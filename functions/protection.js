// 系統保護：異常流量鎖定、自動備份、備份寄信、費用熔斷
//
// system/lock        {locked, reason, at, cutoff} 鎖定狀態（只有伺服器能寫）
// traffic/<小時>      {n} 每小時對外功能的呼叫次數
// backups/<id>       {at, reason, size, gz} 備份（gzip 壓縮的整份資料，只有伺服器能讀）
// mail/<id>          待寄的信（寄出後刪除）

const { onCall, HttpsError } = require('firebase-functions/v2/https');
const { onSchedule } = require('firebase-functions/v2/scheduler');
const { onDocumentCreated } = require('firebase-functions/v2/firestore');
const { onMessagePublished } = require('firebase-functions/v2/pubsub');
const { defineSecret, defineString, defineInt } = require('firebase-functions/params');
const { logger } = require('firebase-functions');
const admin = require('firebase-admin');
const zlib = require('zlib');
const { promisify } = require('util');
const gzip = promisify(zlib.gzip), gunzip = promisify(zlib.gunzip);

const db = admin.firestore();
const FieldValue = admin.firestore.FieldValue;
const DATA = db.doc('system/data');
const LOCK = db.doc('system/lock');

// 寄信用：Gmail 帳號寫在 functions/.env 的 BACKUP_EMAIL，應用程式密碼存在 Secret Manager
const GMAIL_APP_PASSWORD = defineSecret('GMAIL_APP_PASSWORD');
const BACKUP_EMAIL = defineString('BACKUP_EMAIL', { default: '' });
// 每小時公開呼叫上限：開網頁、登入各算 1 次，3000 ≈ 1500 人次「開網頁＋登入」
const TRAFFIC_LIMIT = defineInt('TRAFFIC_LIMIT', { default: 3000 });
// 提醒門檻：以最先用完的免費額度（Firestore 每天 5 萬次讀取）平均到每小時換算
// 每小時約 2080 次讀取 ≈ 700 次「開網頁＋登入」≈ 1400 次呼叫；每天 3 萬次呼叫 ≈ 每日免費讀取的一半
const WARN_LIMIT = defineInt('WARN_LIMIT', { default: 1400 });
const DAILY_WARN = defineInt('DAILY_WARN', { default: 30000 });
const BUDGET_TRIP_RATIO = 0.95;
const KEEP_DAILY = 3;   // 每日備份保留最新 3 份
const KEEP_EVENT = 5;   // 鎖定／熔斷／還原前等事件備份保留最新 5 份

const twNow = () => new Date(Date.now() + 8 * 3600e3); // 台灣時間（用 UTC 欄位讀）
const twStamp = () => twNow().toISOString().slice(0, 16).replace('T', ' ');

// ══ 鎖定狀態（每台伺服器快取 15 秒，減少讀取）══
let lockCache = { at: 0, v: null };
async function getLock() {
  if (Date.now() - lockCache.at < 15000 && lockCache.v) return lockCache.v;
  const s = await LOCK.get();
  lockCache = { at: Date.now(), v: s.exists ? s.data() : { locked: false } };
  return lockCache.v;
}
async function assertNotLocked() {
  const l = await getLock();
  if (l.locked) throw new HttpsError('unavailable', `系統暫停中（${l.reason || '管理員鎖定'}），請聯絡管理員`);
}
async function triggerLock(reason) {
  const first = await db.runTransaction(async tx => {
    const s = await tx.get(LOCK);
    if (s.exists && s.data().locked) return false;
    tx.set(LOCK, { locked: true, reason, at: twStamp() });
    return true;
  });
  lockCache = { at: 0, v: null };
  if (!first) return;
  logger.warn('System locked:', reason);
  const id = await makeBackup('lock');
  await queueMail(`⚠️ 假期抽籤系統已自動鎖定`,
    `原因：${reason}\n時間：${twStamp()}\n\n鎖定期間只有超級管理員能登入。確認沒有問題後，請用超級管理員登入，在「帳號管理 → 系統保護」按「解除鎖定」。\n\n附件是鎖定當下的完整資料備份。`, id);
}

// ══ 流量計數：所有對外功能的每一次呼叫都算（包含鎖定期間）══
// 每台伺服器累積 20 次、且距上次寫入至少 1 秒才寫一次，被灌爆時每台每秒最多寫 1 次
// 超過上限 → 鎖定；鎖定後同一小時再超過一倍 → 判定為攻擊，立即解除付款（不等 Google 帳單統計）
const FLUSH_EVERY = 20;
let counter = { hour: '', pending: 0, lastFlush: 0 };
async function countCall() {
  const hour = twNow().toISOString().slice(0, 13).replace(/[-T]/g, ''); // 例 2026092514
  if (counter.hour !== hour) counter = { hour, pending: 0, lastFlush: 0 };
  if (++counter.pending < FLUSH_EVERY || Date.now() - counter.lastFlush < 1000) return;
  const n = counter.pending;
  counter.pending = 0;
  counter.lastFlush = Date.now();
  const ref = db.doc(`traffic/${hour}`);
  await ref.set({ n: FieldValue.increment(n) }, { merge: true });
  const total = (await ref.get()).data().n;
  const limit = TRAFFIC_LIMIT.value();
  if (total >= limit * 2) await triggerCutoff(`${hour.slice(8)} 點這一小時的呼叫次數達 ${total} 次（鎖定後仍持續湧入，判定為攻擊）`);
  else if (total >= limit) await triggerLock(`${hour.slice(8)} 點這一小時的開網頁／登入次數達 ${total} 次（上限 ${limit}）`);
  else if (total >= WARN_LIMIT.value()) await warnHour(ref, hour, total);
}

// 每小時提醒：同一小時只寄一次，連續幾個小時超過就每小時各寄一封
async function warnHour(ref, hour, total) {
  const first = await db.runTransaction(async tx => {
    const s = await tx.get(ref);
    if (s.data().warned) return false;
    tx.update(ref, { warned: true });
    return true;
  });
  if (!first) return;
  await queueMail(`🔔 假期抽籤系統：${hour.slice(8)} 點流量偏高`,
    `${hour.slice(0, 4)}-${hour.slice(4, 6)}-${hour.slice(6, 8)} ${hour.slice(8)} 點這一小時的呼叫次數已達 ${total} 次，` +
    `超過平均每小時免費額度（${WARN_LIMIT.value()} 次）。\n\n` +
    `系統仍正常運作，這封只是提醒。如果不是開放排假之類的正常尖峰，而且接下來幾個小時持續收到這封信，` +
    `可能有人在長時間操作，可以用超級管理員登入，在「帳號管理 → 系統保護」手動鎖定。\n\n` +
    `自動處理門檻：每小時 ${TRAFFIC_LIMIT.value()} 次鎖定、${TRAFFIC_LIMIT.value() * 2} 次熔斷。`);
}

// 所有對外（網頁可呼叫）的功能都用這個包起來：先計數，再執行
function publicCall(handler) {
  return onCall({ secrets: [GMAIL_APP_PASSWORD] }, async req => {
    await countCall();
    return handler(req);
  });
}

// ══ 備份 ══
async function makeBackup(reason) {
  const snap = await DATA.get();
  if (!snap.exists) return null;
  const json = JSON.stringify(snap.data());
  const gz = await gzip(Buffer.from(json));
  const id = `${twNow().toISOString().slice(0, 19).replace(/[-:T]/g, '')}_${reason}`;
  await db.doc(`backups/${id}`).set({ at: twStamp(), reason, size: json.length, gz });
  await pruneBackups();
  return id;
}
async function pruneBackups() {
  const all = (await db.collection('backups').select('reason').get()).docs
    .sort((a, b) => b.id.localeCompare(a.id)); // id 開頭是時間，新的在前
  const daily = all.filter(d => d.data().reason === 'daily');
  const events = all.filter(d => d.data().reason !== 'daily');
  const extra = [...daily.slice(KEEP_DAILY), ...events.slice(KEEP_EVENT)];
  await Promise.all(extra.map(d => d.ref.delete()));
}
async function backupJson(id) {
  const s = await db.doc(`backups/${id}`).get();
  if (!s.exists) throw new HttpsError('not-found', '找不到此備份');
  return (await gunzip(s.data().gz)).toString();
}

// ══ 寄信 ══
async function queueMail(subject, text, backupId) {
  await db.collection('mail').add({ subject, text, backupId: backupId || null, at: twStamp() });
}
async function sendMail(subject, text, backupId) {
  const user = BACKUP_EMAIL.value();
  if (!user) { logger.warn('BACKUP_EMAIL 未設定，略過寄信：', subject); return; }
  const nodemailer = require('nodemailer');
  const t = nodemailer.createTransport({ service: 'gmail', auth: { user, pass: GMAIL_APP_PASSWORD.value() } });
  const attachments = backupId
    ? [{ filename: `vacLottery_backup_${backupId}.json`, content: await backupJson(backupId), contentType: 'application/json' }]
    : [];
  await t.sendMail({ from: `假期抽籤系統 <${user}>`, to: user, subject, text, attachments });
}
exports.sendQueuedMail = onDocumentCreated({ document: 'mail/{id}', secrets: [GMAIL_APP_PASSWORD] }, async event => {
  const m = event.data.data();
  try {
    await sendMail(m.subject, m.text, m.backupId);
    await event.data.ref.delete();
  } catch (e) {
    logger.error('Send mail failed:', e);
    await event.data.ref.update({ error: String(e.message || e) });
  }
});

// ══ 每日備份（台灣時間 04:00），每週一另外寄到信箱，順便清掉一週前的流量紀錄 ══
exports.dailyBackup = onSchedule({ schedule: '0 4 * * *', timeZone: 'Asia/Taipei' }, async () => {
  const id = await makeBackup('daily');
  if (id && twNow().getUTCDay() === 1) {
    await queueMail(`假期抽籤系統 每週備份 ${twStamp().slice(0, 10)}`,
      '附件是系統的完整資料備份（不含任何密碼）。\n還原方式：超級管理員登入 →「📂 匯入資料」選這個檔案。', id);
  }
  // 前一天總呼叫次數（每小時都沒超標、但整天累積很多的情況）
  const y = twNow(); y.setUTCDate(y.getUTCDate() - 1);
  const yKey = y.toISOString().slice(0, 10).replace(/-/g, ''); // 例 20260924
  const ySnap = await db.collection('traffic')
    .where(admin.firestore.FieldPath.documentId(), '>=', `${yKey}00`)
    .where(admin.firestore.FieldPath.documentId(), '<=', `${yKey}23`).get();
  const yTotal = ySnap.docs.reduce((s, d) => s + (d.data().n || 0), 0);
  if (yTotal >= DAILY_WARN.value()) {
    const byHour = ySnap.docs.map(d => `${d.id.slice(8)} 點：${d.data().n}`).join('\n');
    await queueMail(`🔔 假期抽籤系統：昨天總流量偏高（${yTotal} 次）`,
      `${yKey.slice(0, 4)}-${yKey.slice(4, 6)}-${yKey.slice(6)} 整天的呼叫次數共 ${yTotal} 次，超過提醒門檻 ${DAILY_WARN.value()} 次` +
      `（約每日免費額度的一半）。\n\n各小時次數：\n${byHour}\n\n系統仍正常運作，這封只是提醒。`);
  }

  await require('./audit').pruneOld(); // 稽核／登入紀錄保留 90 天

  const old = twNow(); old.setUTCDate(old.getUTCDate() - 7);
  const oldKey = old.toISOString().slice(0, 13).replace(/[-T]/g, '');
  const stale = await db.collection('traffic').where(admin.firestore.FieldPath.documentId(), '<', oldKey).get();
  await Promise.all(stale.docs.map(d => d.ref.delete()));
});

// ══ 費用熔斷：預算通知（Pub/Sub）達 95% → 備份＋寄信 → 解除專案的付款帳戶 ══
async function disableBilling(projectId) {
  const { GoogleAuth } = require('google-auth-library');
  const client = await new GoogleAuth({ scopes: ['https://www.googleapis.com/auth/cloud-platform'] }).getClient();
  const url = `https://cloudbilling.googleapis.com/v1/projects/${projectId}/billingInfo`;
  const info = (await client.request({ url })).data;
  if (!info.billingEnabled) return false;
  await client.request({ url, method: 'PUT', data: { billingAccountName: '' } });
  return true;
}
// 備份 → 寄信 → 解除付款。解除付款後寄信功能也會停，所以直接寄，不經過 mail 佇列
async function cutoff(kind, title, detail) {
  const projectId = process.env.GCLOUD_PROJECT;
  logger.warn(`Cutoff (${kind}): ${detail}`);
  let id = null;
  try { id = await makeBackup(kind); } catch (e) { logger.error('Backup before billing cutoff failed:', e); }
  try {
    await sendMail(`🛑 假期抽籤系統已停止：${title}`,
      `${detail}\n時間：${twStamp()}\n\n` +
      `為了避免繼續產生費用，專案 ${projectId} 已自動解除付款帳戶，網站已停止，資料仍保留在資料庫。\n` +
      `恢復方式：Firebase 主控台 → 專案 → 左下角「升級」→ 重新選擇付款帳戶（Blaze），約 15～30 分鐘恢復。\n` +
      `恢復後請用超級管理員登入，在「帳號管理 → 系統保護」解除鎖定。\n\n附件是停止前的完整資料備份。`, id);
  } catch (e) { logger.error('Cutoff mail failed:', e); }
  const done = await disableBilling(projectId);
  logger.warn(done ? 'Billing disabled.' : 'Billing was already disabled.');
}
async function triggerCutoff(detail) {
  // 同一波攻擊只處理一次（多台伺服器同時偵測到也一樣）
  const first = await db.runTransaction(async tx => {
    const s = await tx.get(LOCK);
    const cur = s.exists ? s.data() : {};
    if (cur.cutoff) return false;
    tx.set(LOCK, { ...cur, locked: true, reason: cur.reason || detail, cutoff: true, at: cur.at || twStamp() });
    return true;
  });
  lockCache = { at: 0, v: null };
  if (first) await cutoff('attack', '流量異常（疑似攻擊）', detail);
}

exports.budgetGuard = onMessagePublished({ topic: 'budget-alerts', secrets: [GMAIL_APP_PASSWORD] }, async event => {
  const msg = event.data.message.json || {};
  const { costAmount, budgetAmount, currencyCode } = msg;
  if (!budgetAmount || costAmount < budgetAmount * BUDGET_TRIP_RATIO) return;
  await cutoff('budget', `費用達預算 ${Math.round(costAmount / budgetAmount * 100)}%`,
    `費用 ${costAmount} / 預算 ${budgetAmount} ${currencyCode || ''}`);
});

// ══ 超級管理員用：鎖定／解除、備份清單、立即備份、還原、下載 ══
function requireSuper(req) {
  if (!req.auth || req.auth.token.role !== 'superadmin') throw new HttpsError('permission-denied', '只有超級管理員可以使用');
}
exports.setLock = publicCall(async req => {
  requireSuper(req);
  const locked = !!(req.data || {}).locked;
  await LOCK.set(locked ? { locked: true, reason: '超級管理員手動鎖定', at: twStamp() } : { locked: false, at: twStamp() });
  lockCache = { at: 0, v: null };
  if (locked) await makeBackup('lock');
  // 解鎖時把這一小時的計數歸零，否則還在同一小時內會馬上又被鎖住
  else await db.doc(`traffic/${twNow().toISOString().slice(0, 13).replace(/[-T]/g, '')}`).delete();
  return { locked };
});
exports.listBackups = publicCall(async req => {
  requireSuper(req);
  const snap = await db.collection('backups').select('at', 'reason', 'size').get();
  return snap.docs.map(d => ({ id: d.id, ...d.data() })).sort((a, b) => b.id.localeCompare(a.id));
});
exports.backupNow = publicCall(async req => {
  requireSuper(req);
  return { id: await makeBackup('manual') };
});
exports.downloadBackup = publicCall(async req => {
  requireSuper(req);
  return { json: await backupJson((req.data || {}).id) };
});
exports.restoreBackup = publicCall(async req => {
  requireSuper(req);
  const json = await backupJson((req.data || {}).id);
  const before = await makeBackup('before-restore'); // 還原前先備份目前狀態，還原錯了還能救回來
  await DATA.set(JSON.parse(json));
  return { ok: true, before };
});

module.exports.helpers = { publicCall, getLock, assertNotLocked, requireSuper, queueMail, twNow, twStamp };
