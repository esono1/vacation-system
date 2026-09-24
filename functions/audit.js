// 稽核日誌：記錄每次資料修改「誰、何時、改了什麼」、登入紀錄，並標出可疑操作
//
// audit/<id>    {ts, at, uid, who, role, lines[], suspicious, reasons[]} 資料修改紀錄
// logins/<id>   {ts, at, kind, who, ok, reason, ip} 登入紀錄（含失敗）
// alerts/<id>   可疑操作通知的去重（同一帳號每小時最多寄一封）
//
// 紀錄由 Google 伺服器端的資料庫觸發產生，「誰改的」來自 Firebase 的登入身分，不是網頁回報，
// 所以繞過網頁直接改資料也一樣會被記錄；安全規則禁止任何人（包括超級管理員）修改或刪除紀錄。

const { onDocumentWrittenWithAuthContext } = require('firebase-functions/v2/firestore');
const { logger } = require('firebase-functions');
const admin = require('firebase-admin');
const { publicCall, requireSuper, queueMail, twNow, twStamp } = require('./protection').helpers;

const db = admin.firestore();
const KEEP_DAYS = 90;

const FIELD_LABEL = {
  employees: '技師名單', periods: '假期設定', applications: '排假申請', extraLeaves: '額外假',
  makeupLeaves: '補假', longLeaves: '長假', history: '抽籤紀錄', publishedSchedules: '已發布假表',
  counterApplications: '櫃檯排休', counterShiftOverrides: '櫃檯班別調整', counterStaff: '櫃檯人員',
  cleanerSchedules: '清潔排班', cleanerStaff: '清潔人員', admins: '管理員帳號', adminPermissions: '權限設定',
  departments: '班別', deptTimes: '班別時間', dailyLimits: '每日上限', monthlyQuota: '每月排假天數',
  partTimeQuota: '兼職排假天數', empQuotas: '個別排假天數', pendingPromotions: '待升職',
};
const MASS_DELETE = 10;

// 各分頁的網頁功能會改動的資料（依 index.html 掃描＋人工確認，改網頁功能時要一起更新）
const TAB_FIELDS = {
  employees: ['employees', 'departments', 'deptTimes', 'applications'],
  periods: ['periods', 'applications', 'dailyLimits'],
  applications: ['applications', 'history', 'makeupLeaves', 'pendingPromotions', 'extraLeaves', 'longLeaves',
    'monthlyQuota', 'partTimeQuota', 'empQuotas', 'dailyLimits'],
  lottery: ['history', 'applications', 'pendingPromotions', 'makeupLeaves'],
  schedule: ['publishedSchedules', 'makeupLeaves'],
  history: ['history'],
  counter: ['counterApplications', 'counterShiftOverrides', 'counterStaff', 'cleanerStaff', 'cleanerSchedules'],
  accounts: ['admins', 'adminPermissions'],
};
const ALL_TABS = Object.keys(TAB_FIELDS);
// 對應網頁 loginAsAdmin 的分頁顯示邏輯
function visibleTabs(adminRec, perms) {
  if (perms) return new Set(perms);
  const role = adminRec.role || '主管';
  if (role === '負責人') return new Set(ALL_TABS);
  if (role === '櫃檯') return new Set(['schedule', 'history', 'counter']);
  return new Set(['employees', 'periods', 'applications', 'lottery', 'schedule', 'history', 'counter']);
}

// 對應網頁 migrateData：網頁載入時自動補的預設值，不算使用者的修改
function normalize(d) {
  const x = JSON.parse(JSON.stringify(d || {}));
  for (const k of ['employees', 'periods', 'applications', 'extraLeaves', 'makeupLeaves', 'pendingPromotions', 'history',
    'admins', 'longLeaves', 'publishedSchedules', 'counterApplications', 'counterStaff', 'counterShiftOverrides'])
    if (!Array.isArray(x[k])) x[k] = [];
  for (const k of ['deptTimes', 'dailyLimits', 'adminPermissions', 'empQuotas']) if (!x[k]) x[k] = {};
  if (!Array.isArray(x.departments) || !x.departments.length) x.departments = ['09-19', '12-22', '13-23', '14-24', '16-02'];
  if (!x.monthlyQuota) x.monthlyQuota = 8;
  if (!x.partTimeQuota) x.partTimeQuota = 15;
  x.periods.forEach(p => { p.genderRestrict = ''; if (p.allowApplication === undefined) p.allowApplication = true; if (p.allowMakeup === undefined) p.allowMakeup = true; });
  x.employees.forEach(e => { if (!e.store) e.store = '竹北店'; });
  return x;
}

// ══ 網頁的排假規則（對應 index.html 的 getLim / getEmpQuota / isLoserOfPeriod）══
function datesBetween(s, e) {
  const r = [], c = new Date(s + 'T00:00:00Z'), l = new Date(e + 'T00:00:00Z');
  while (c <= l) { r.push(c.toISOString().slice(0, 10)); c.setUTCDate(c.getUTCDate() + 1); }
  return r;
}
function getLim(p, shift, d, gender) {
  if (!p.limits || !p.limits[shift]) return gender ? 1 : 2;
  const v = p.limits[shift][d];
  if (v === undefined) return gender ? 1 : 2;
  if (typeof v === 'object' && v !== null) {
    if (gender === 'male') return v.male ?? 1;
    if (gender === 'female') return v.female ?? 1;
    return (v.male ?? 1) + (v.female ?? 1);
  }
  return gender ? Math.ceil(v / 2) : v;
}
const samePeriod = (h, p) => h.periodId === p.id || (h.periodName === p.name && h.periodStart === p.start);
function empQuota(d, emp, p) {
  const ll = (d.longLeaves || []).find(l => l.empId === emp.id && l.customQuota != null && l.startDate <= p.end && l.endDate >= p.start);
  if (ll) return ll.customQuota;
  if ((emp.empType || '直') === '兼') {
    const [y, m] = p.start.slice(0, 7).split('-').map(Number);
    return Math.max(0, new Date(Date.UTC(y, m, 0)).getUTCDate() - (d.partTimeQuota || 4));
  }
  return d.monthlyQuota || 8;
}
function loserDates(d, emp, p) {
  return (d.history || []).filter(h => samePeriod(h, p) && !h.type && (h.losers || []).some(l => l.name === emp.name && l.dept === emp.dept)).map(h => h.date);
}

// ══ 員工：逐筆比對是否符合網頁的操作規則 ══
function validateEmployee(me, before, after, changes, ctx) {
  const reasons = [];
  const selfId = String(me.empId);
  const emp = (before.employees || []).find(e => String(e.id) === selfId);
  if (!emp) return ['找不到這位員工的資料，卻在修改資料'];
  const gender = emp.gender || 'male';
  const isMine = x => x && String(x.empId) === selfId;
  const periodOf = id => (after.periods || []).find(p => String(p.id) === String(id));
  const newDatesByPeriod = {};
  const byField = Object.fromEntries(changes.map(c => [c.field, c]));
  const ALLOWED = new Set(['applications', 'extraLeaves', 'makeupLeaves', 'history', 'pendingPromotions']);
  for (const c of changes) if (!ALLOWED.has(c.field)) reasons.push(`員工修改了「${FIELD_LABEL[c.field] || c.field}」（員工畫面沒有這個功能）`);

  const others = (c, name) => {
    const touched = [...c.added, ...c.removed, ...c.changed.map(x => x.after)].filter(x => !isMine(x));
    if (touched.length) reasons.push(`員工動到別人的「${name}」：${list(touched, x => itemLabel(x, ctx))}`);
  };

  // 排假申請
  const ap = byField.applications;
  if (ap && !ap.reordered) {
    others(ap, '排假申請');
    const mine = [...ap.added.filter(isMine).map(a => ({ b: null, a })), ...ap.changed.filter(x => isMine(x.after)).map(x => ({ b: x.before, a: x.after }))];
    for (const { b, a } of mine) {
      if (b) {
        const other = Object.keys({ ...a, ...b }).filter(k => k !== 'dates' && J(a[k]) !== J(b[k]));
        if (other.length) reasons.push(`員工改了自己排假申請的「${other.join('/')}」（網頁只會改日期）`);
      } else if (a.empName !== emp.name || a.shift !== emp.dept) {
        reasons.push(`員工新增的排假申請姓名或班別不符（${a.empName} ${a.shift}）`);
      }
      const p = periodOf(a.periodId);
      if (!p) { reasons.push(`排假申請指向不存在的假期（${a.periodId}）`); continue; }
      const added = (a.dates || []).filter(x => !(b && (b.dates || []).includes(x)));
      if (!added.length) continue;
      newDatesByPeriod[p.id] = added;
      const inRange = new Set(datesBetween(p.start, p.end));
      const bad = [];
      if (p.allowApplication === false) bad.push('假期未開放申請');
      if (p.storeRestrict && (emp.store || '竹北店') !== p.storeRestrict) bad.push(`限${p.storeRestrict}`);
      if (p.genderRestrict && gender !== p.genderRestrict) bad.push('職稱不符');
      const out = added.filter(x => !inRange.has(x));
      if (out.length) bad.push(`日期不在假期內（${out.join('、')}）`);
      const closed = added.filter(x => inRange.has(x) && getLim(p, emp.dept, x) === 0);
      if (closed.length) bad.push(`不開放的日期（${closed.join('、')}）`);
      const losers = new Set(loserDates(after, emp, p));
      const count = (a.dates || []).filter(x => !losers.has(x)).length;
      const quota = empQuota(after, emp, p);
      if (count > quota) bad.push(`超過天數上限（${count}/${quota}）`);
      if (bad.length) reasons.push(`員工的排假申請不符合網頁規則（${p.name}）：${bad.join('、')}`);
    }
  }

  // 額外假：只能新增「待審核」、只能取消自己「待審核」的、不能改任何一筆
  const el = byField.extraLeaves;
  if (el && !el.reordered) {
    others(el, '額外假');
    el.added.filter(isMine).forEach(x => { if (x.status !== 'pending' || x.reviewedAt) reasons.push(`員工新增的額外假不是「待審核」（${itemLabel(x, ctx)}）`); });
    el.removed.filter(isMine).forEach(x => { if (x.status !== 'pending') reasons.push(`員工刪除了已審核的額外假（${itemLabel(x, ctx)}）`); });
    el.changed.filter(x => isMine(x.after)).forEach(x => reasons.push(`員工修改了自己的額外假（${itemLabel(x.before, ctx)} → ${itemLabel(x.after, ctx)}），網頁沒有這個功能`));
  }

  // 補假：必須是未中籤者、假期開放補假、日期在假期內
  const mk = byField.makeupLeaves;
  if (mk && !mk.reordered) {
    others(mk, '補假');
    mk.changed.filter(x => isMine(x.after)).forEach(x => reasons.push(`員工修改了自己的補假（${itemLabel(x.after, ctx)}），網頁沒有這個功能`));
    for (const x of mk.added.filter(isMine)) {
      const p = periodOf(x.periodId);
      const bad = [];
      if (!p) bad.push('假期不存在');
      else {
        if (p.allowMakeup === false) bad.push('假期未開放補假');
        if (!datesBetween(p.start, p.end).includes(x.date)) bad.push('日期不在假期內');
        if (!loserDates(after, emp, p).length) bad.push('不是這個假期的未中籤者');
        else if (getLim(p, emp.dept, x.date) <= 0) bad.push('不開放的日期');
      }
      if (bad.length) reasons.push(`員工的補假不符合網頁規則（${itemLabel(x, ctx)}）：${bad.join('、')}`);
    }
  }

  // 抽籤紀錄：只允許「超休確認」刪除自己剛申請日期、同班別、同性別的紀錄
  const hs = byField.history;
  if (hs && !hs.reordered) {
    const okRemove = h => !h.type && h.shift === emp.dept && (h.gender === gender || h.gender === undefined) &&
      Object.entries(newDatesByPeriod).some(([pid, ds]) => { const p = periodOf(pid); return p && samePeriod(h, p) && ds.includes(h.date); });
    if (hs.added.length || hs.changed.length || hs.removed.some(h => !okRemove(h)))
      reasons.push('員工修改了抽籤紀錄（只有「超休確認」會刪除自己當天的紀錄）');
  }

  // 補籤資訊：網頁顯示預覽時會自動清掉項目（renderPendingPromotions），所以只刪除不算；新增或修改才可疑
  const pp = byField.pendingPromotions;
  if (pp && (pp.added.length || pp.changed.length)) reasons.push('員工新增或修改了補籤資訊');
  return reasons;
}

// 比對用：物件欄位先排序（Firestore 存取時欄位順序會變，內容相同不能算修改）；陣列保持原順序
const stable = v => Array.isArray(v) ? v.map(stable)
  : (v && typeof v === 'object') ? Object.keys(v).sort().reduce((o, k) => { o[k] = stable(v[k]); return o; }, {}) : v;
const J = v => JSON.stringify(stable(v));
const keyOf = x => (x && typeof x === 'object') ? String(x.id ?? x.periodId ?? x.adminId ?? J(x)) : J(x);

// ══ 找出兩份資料的差異 ══
function diffData(before, after) {
  const changes = [];
  for (const field of new Set([...Object.keys(before), ...Object.keys(after)])) {
    const b = before[field], a = after[field];
    if (J(b) === J(a)) continue;
    if (Array.isArray(a) || Array.isArray(b)) {
      const bm = new Map((b || []).map(x => [keyOf(x), x]));
      const am = new Map((a || []).map(x => [keyOf(x), x]));
      const added = [...am].filter(([k]) => !bm.has(k)).map(([, x]) => x);
      const removed = [...bm].filter(([k]) => !am.has(k)).map(([, x]) => x);
      const changed = [...am].filter(([k, x]) => bm.has(k) && J(bm.get(k)) !== J(x))
        .map(([k, x]) => ({ before: bm.get(k), after: x }));
      changes.push({ field, added, removed, changed, reordered: !added.length && !removed.length && !changed.length });
    } else {
      changes.push({ field, before: b, after: a });
    }
  }
  return changes;
}

// 身分、角色、權限一律以「修改前」為準（否則自己把自己升級，會被當成本來就有權限）
function makeCtx(before, after) {
  const emp = {}, adm = {};
  for (const d of [after, before]) {
    (d.employees || []).forEach(e => { emp[e.id] = e.name; });
    (d.admins || []).forEach(a => { adm[a.id] = a; });
  }
  const perms = { ...(after.adminPermissions || {}), ...(before.adminPermissions || {}) };
  return { emp, adm, perms, adminExisted: new Set((before.admins || []).map(a => a.id)) };
}
function itemLabel(x, ctx) {
  if (!x || typeof x !== 'object') return String(x);
  const who = x.empName || (x.empId != null && ctx.emp[x.empId]) || x.adminName ||
    (x.adminId && ctx.adm[x.adminId] && ctx.adm[x.adminId].username) || x.username || x.name || x.periodName || '';
  const when = Array.isArray(x.dates)
    ? (x.dates.length > 3 ? `${x.dates[0]} 等 ${x.dates.length} 天` : x.dates.join('、'))
    : x.date || (x.startDate && `${x.startDate}~${x.endDate}`) || (x.start && `${x.start}~${x.end}`) || '';
  const s = [who, x.shift, when].filter(Boolean).join(' ');
  return (s || keyOf(x).slice(0, 40)) + (x.status ? `（${x.status}）` : '');
}
function list(items, fmt) {
  const shown = items.slice(0, 8).map(fmt).join('、');
  return items.length > 8 ? `${shown}…等 ${items.length} 筆` : shown;
}
function shortVal(v) { const s = J(v); return s === undefined ? '（無）' : (s.length > 60 ? s.slice(0, 60) + '…' : s); }
function describe(changes, ctx) {
  return changes.map(c => {
    const name = FIELD_LABEL[c.field] || c.field;
    if (!('added' in c)) return `${name}：${shortVal(c.before)} → ${shortVal(c.after)}`;
    if (c.reordered) return `${name}：調整順序`;
    const parts = [];
    if (c.added.length) parts.push(`新增 ${c.added.length}（${list(c.added, x => itemLabel(x, ctx))}）`);
    if (c.removed.length) parts.push(`刪除 ${c.removed.length}（${list(c.removed, x => itemLabel(x, ctx))}）`);
    if (c.changed.length) parts.push(`修改 ${c.changed.length}（${list(c.changed, ch => {
      const keys = [...new Set([...Object.keys(ch.before), ...Object.keys(ch.after)])].filter(k => J(ch.before[k]) !== J(ch.after[k]));
      return `${itemLabel(ch.after, ctx)}：${keys.join('/')}`;
    })}）`);
    return `${name}：${parts.join('，')}`;
  });
}

// ══ 誰改的 ══
function identify(event, ctx) {
  const uid = event.authId || '';
  if (event.authType === 'service_account') return { uid, role: 'system', who: '系統（伺服器）' };
  if (uid === 'super') return { uid, role: 'superadmin', who: '超級管理員' };
  if (uid.startsWith('admin_')) {
    const a = ctx.adm[uid.slice(6)];
    return { uid, role: 'admin', who: a ? `${a.username}（${a.role || '主管'}）` : `已刪除的管理員 ${uid.slice(6)}`, adminId: uid.slice(6) };
  }
  if (uid.startsWith('emp_')) {
    const id = uid.slice(4);
    return { uid, role: 'employee', who: `${ctx.emp[id] || '未知員工'}（員工）`, empId: id };
  }
  return { uid, role: event.authType || 'unknown', who: `未知身分（${event.authType || '無'}）` };
}

// ══ 可疑判斷 ══
function judge(me, changes, ctx, before, after) {
  const reasons = [];
  if (me.role === 'superadmin' || me.role === 'system') return reasons;
  if (me.role === 'employee') reasons.push(...validateEmployee(me, before, after, changes, ctx));
  if (me.role === 'admin') {
    const a = ctx.adm[me.adminId];
    if (!ctx.adminExisted.has(me.adminId) || !a) reasons.push('已被刪除的管理員帳號仍在修改資料');
    else {
      // 只能改自己看得到的分頁會改的資料（補籤資訊的刪除是顯示預覽時的自動清理，不算）
      const tabs = visibleTabs(a, ctx.perms[me.adminId]);
      const allowed = new Set([...tabs].flatMap(t => TAB_FIELDS[t] || []));
      for (const c of changes) {
        if (allowed.has(c.field) || c.reordered) continue;
        if (c.field === 'pendingPromotions' && !c.added.length && !c.changed.length) continue;
        const where = ALL_TABS.filter(t => (TAB_FIELDS[t] || []).includes(c.field));
        reasons.push(`${a.role || '主管'}「${a.username}」修改了「${FIELD_LABEL[c.field] || c.field}」，` +
          (where.length ? `但他看不到能改這項資料的分頁` : `網頁沒有能改這項資料的功能`));
      }
    }
  }
  if (me.role !== 'admin' && me.role !== 'employee') reasons.push('無法辨識的身分修改了資料');
  const removed = changes.reduce((s, c) => s + ((c.removed || []).length), 0);
  if (removed >= MASS_DELETE) reasons.push(`一次刪除 ${removed} 筆資料`);
  return reasons;
}

// ══ 資料每次被修改就記一筆 ══
exports.auditDataWrite = onDocumentWrittenWithAuthContext('system/data', async event => {
  // 修改前的資料先補上網頁載入時會自動補的預設值，避免把網頁的自動修正算成使用者的修改
  const before = normalize(event.data.before.exists ? event.data.before.data() : {});
  const after = event.data.after.exists ? event.data.after.data() : {};
  const changes = diffData(before, after);
  if (!changes.length) return;
  const ctx = makeCtx(before, after);
  const me = identify(event, ctx);
  const lines = describe(changes, ctx);
  const reasons = judge(me, changes, ctx, before, after);
  const rec = { ts: Date.now(), at: twStamp(), uid: me.uid, who: me.who, role: me.role, lines, suspicious: reasons.length > 0, reasons };
  await db.collection('audit').add(rec);
  if (!reasons.length) return;
  logger.warn('Suspicious write:', me.who, reasons);
  // 同一帳號每小時最多寄一封，避免被灌爆
  const hour = twNow().toISOString().slice(0, 13).replace(/[-T]/g, '');
  try { await db.doc(`alerts/${me.uid || 'unknown'}_${hour}`).create({ ts: Date.now() }); } catch (e) { return; }
  await queueMail(`🚨 假期抽籤系統：可疑操作（${me.who}）`,
    `時間：${rec.at}\n帳號：${me.who}\n\n可疑原因：\n${reasons.map(r => '・' + r).join('\n')}\n\n這次修改的內容：\n${lines.map(l => '・' + l).join('\n')}\n\n` +
    `修改已經生效。可以用超級管理員登入，在「帳號管理 → 系統保護 → 操作紀錄」查看完整紀錄；` +
    `需要復原時，用「自動備份」還原到修改前的版本。\n（同一帳號一小時內只通知一次，其餘可疑操作請到操作紀錄查看）`);
});

// ══ 登入紀錄（由 index.js 的登入功能呼叫）══
exports.logLogin = async (req, { kind, who, ok, reason }) => {
  const h = (req.rawRequest && req.rawRequest.headers) || {};
  const ip = String(h['x-forwarded-for'] || (req.rawRequest && req.rawRequest.ip) || '').split(',')[0].trim();
  try {
    await db.collection('logins').add({ ts: Date.now(), at: twStamp(), kind, who: String(who || '').slice(0, 60), ok, reason: reason || '', ip });
  } catch (e) { logger.error('Login log failed:', e); }
};

// ══ 超級管理員查詢 ══
exports.listAudit = publicCall(async req => {
  requireSuper(req);
  const { suspiciousOnly, limit } = req.data || {};
  let q = db.collection('audit');
  if (suspiciousOnly) q = q.where('suspicious', '==', true);
  const snap = await q.orderBy('ts', 'desc').limit(Math.min(+limit || 100, 300)).get();
  return snap.docs.map(d => d.data());
});
exports.listLogins = publicCall(async req => {
  requireSuper(req);
  const snap = await db.collection('logins').orderBy('ts', 'desc').limit(Math.min(+(req.data || {}).limit || 100, 300)).get();
  return snap.docs.map(d => d.data());
});

exports._test = { diffData, describe, judge, makeCtx, identify, normalize }; // 離線測試用

// ══ 清掉 90 天前的紀錄（每日備份時呼叫）══
exports.pruneOld = async () => {
  const cutoff = Date.now() - KEEP_DAYS * 86400e3;
  for (const col of ['audit', 'logins', 'alerts']) {
    for (;;) {
      const snap = await db.collection(col).where('ts', '<', cutoff).limit(300).get();
      if (snap.empty) break;
      const batch = db.batch();
      snap.docs.forEach(d => batch.delete(d.ref));
      await batch.commit();
    }
  }
};
