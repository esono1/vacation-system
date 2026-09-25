// 假期抽籤系統 — 登入伺服器（Cloud Functions for Firebase）
//
// 密碼一律存在 creds 集合（安全規則禁止網頁讀寫，只有這裡能碰），
// 驗證成功才發 Firebase 通行證（custom token），網頁憑通行證才能讀寫 system/data。
//
// creds/super          超級管理員 {username, hash}
// creds/admin_<id>     管理員     {hash}（帳號名稱、角色仍在 system/data 的 admins）
// creds/emp_<id>       員工 PIN   {hash}
// system/pinStatus     {<empId>: true} 哪些員工已設定 PIN（登入畫面要用，公開可讀）
// 登入畫面用的員工名單與密碼設定狀態由 status 提供（資料庫沒有任何公開可讀的內容）
// attempts/<key>       登入失敗次數（防止猜密碼）
// 鎖定、備份、寄信、費用熔斷見 protection.js

const { HttpsError } = require('firebase-functions/v2/https');
const { setGlobalOptions } = require('firebase-functions/v2');
const admin = require('firebase-admin');
const crypto = require('crypto');
const { promisify } = require('util');

admin.initializeApp();
const db = admin.firestore();
const pbkdf2 = promisify(crypto.pbkdf2);

// 每個功能最多 3 台伺服器：限制被灌請求時的擴張與費用，又不會因為 1 台卡住就整個停擺
setGlobalOptions({ region: 'asia-east1', maxInstances: 3, memory: '256MiB', timeoutSeconds: 30 });

const protection = require('./protection');
const { publicCall, getLock, assertNotLocked } = protection.helpers;
for (const [name, fn] of Object.entries(protection)) if (name !== 'helpers') exports[name] = fn;
const audit = require('./audit');
const { logLogin } = audit;
for (const name of ['auditDataWrite', 'listAudit', 'listLogins']) exports[name] = audit[name];

const DATA = db.doc('system/data');
const PIN_STATUS = db.doc('system/pinStatus');
const LEGACY_AUTH = db.doc('system/auth');
const cred = key => db.doc(`creds/${key}`);

const MAX_FAILS = 5;
const LOCK_MS = 5 * 60 * 1000;

// ══ 密碼雜湊（格式與網頁版相同：pbkdf2$迭代次數$salt$hash）══
const ITER = 100000;
async function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  const hash = await pbkdf2(pw, salt, ITER, 32, 'sha256');
  return `pbkdf2$${ITER}$${salt.toString('base64')}$${hash.toString('base64')}`;
}
function isHashed(s) { return typeof s === 'string' && s.startsWith('pbkdf2$'); }
function safeEqual(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
async function verifyPw(pw, stored) {
  if (!pw || !stored) return false;
  if (!isHashed(stored)) return safeEqual(pw, stored); // 舊版明文
  const [, iter, salt, hash] = stored.split('$');
  const got = await pbkdf2(pw, Buffer.from(salt, 'base64'), +iter, 32, 'sha256');
  return safeEqual(got.toString('base64'), hash);
}

// ══ 登入失敗鎖定 ══
async function checkLock(key) {
  const snap = await db.doc(`attempts/${key}`).get();
  const until = snap.exists ? snap.data().lockedUntil || 0 : 0;
  if (until > Date.now()) {
    const min = Math.ceil((until - Date.now()) / 60000);
    throw new HttpsError('resource-exhausted', `密碼錯誤次數過多，請 ${min} 分鐘後再試`);
  }
}
async function recordFail(key) {
  const ref = db.doc(`attempts/${key}`);
  await db.runTransaction(async tx => {
    const snap = await tx.get(ref);
    const fails = (snap.exists ? snap.data().fails || 0 : 0) + 1;
    tx.set(ref, fails >= MAX_FAILS ? { fails: 0, lockedUntil: Date.now() + LOCK_MS } : { fails, lockedUntil: 0 });
  });
}
async function clearFails(key) { await db.doc(`attempts/${key}`).delete(); }
const attemptKey = s => encodeURIComponent(String(s)).slice(0, 200);

// ══ 舊資料搬移：把 system/auth、data 裡的密碼搬進 creds，並從公開資料刪掉 ══
// 每次登入都會檢查一次；舊版網頁若把密碼寫回 data，也會在這裡被清掉
async function scrubLegacy() {
  const legacy = await LEGACY_AUTH.get();
  if (legacy.exists) {
    const { username, password } = legacy.data();
    const superRef = cred('super');
    if (!(await superRef.get()).exists && username && password) {
      await superRef.set({ username, hash: isHashed(password) ? password : await hashPw(password) });
    }
    await LEGACY_AUTH.delete();
  }

  const snap = await DATA.get();
  if (!snap.exists) return null;
  const d = snap.data();
  const admins = d.admins || [], employees = d.employees || [];
  const dirtyAdmins = admins.filter(a => a.password);
  const dirtyEmps = employees.filter(e => e.pin);
  if (!dirtyAdmins.length && !dirtyEmps.length) return d;

  // creds 已存在的就以 creds 為準（可能是之後改過的新密碼），只清掉 data 裡的欄位
  const pinUpdates = {};
  for (const a of dirtyAdmins) {
    const ref = cred(`admin_${a.id}`);
    if (!(await ref.get()).exists) await ref.set({ hash: isHashed(a.password) ? a.password : await hashPw(a.password) });
  }
  for (const e of dirtyEmps) {
    const ref = cred(`emp_${e.id}`);
    if (!(await ref.get()).exists) await ref.set({ hash: isHashed(e.pin) ? e.pin : await hashPw(e.pin) });
    pinUpdates[String(e.id)] = true;
  }
  if (Object.keys(pinUpdates).length) await PIN_STATUS.set(pinUpdates, { merge: true });

  // 用交易只改 admins / employees 兩個欄位，不覆蓋其他人同時寫入的資料
  return db.runTransaction(async tx => {
    const cur = (await tx.get(DATA)).data();
    const v = await protection.helpers.nextVersion(tx);
    const cleanAdmins = (cur.admins || []).map(a => { const { password, ...rest } = a; return rest; });
    const cleanEmps = (cur.employees || []).map(e => { const { pin, ...rest } = e; return rest; });
    tx.update(DATA, { admins: cleanAdmins, employees: cleanEmps, _v: v });
    tx.set(protection.helpers.META, { v });
    return { ...cur, admins: cleanAdmins, employees: cleanEmps, _v: v };
  });
}


async function superConfigured() {
  return (await cred('super').get()).exists || (await LEGACY_AUTH.get()).exists;
}

async function issueToken(uid, claims) {
  return admin.auth().createCustomToken(uid, claims);
}

// ══ 權限判斷（對應網頁的 _roleRank / _canEditAdmin）══
function roleRank(role) {
  if (role === 'superadmin') return 4;
  if (role === '負責人') return 3;
  if (role === '主管') return 2;
  if (role === '櫃檯' || role === '櫃檶' || role === '清潔') return 1; // 櫃檶：舊版錯字，網頁載入時會改正
  return 0;
}
async function callerInfo(req) {
  const t = req.auth && req.auth.token;
  if (!t || !t.role) throw new HttpsError('unauthenticated', '請先登入');
  if (t.role !== 'superadmin') await assertNotLocked();
  const d = (await DATA.get()).data() || {};
  if (t.role === 'superadmin') return { role: 'superadmin', rank: 4, canManage: true, d };
  if (t.role === 'admin') {
    const me = (d.admins || []).find(a => a.id === t.adminId);
    if (!me) throw new HttpsError('permission-denied', '帳號已不存在');
    const perms = (d.adminPermissions || {})[me.id];
    const canManage = perms ? perms.includes('accounts') : me.role === '負責人';
    return { role: 'admin', rank: roleRank(me.role || '主管'), canManage, adminId: me.id, d };
  }
  return { role: 'employee', empId: t.empId, rank: 0, canManage: false, d };
}
function checkPin(pin) {
  if (typeof pin !== 'string' || pin.length < 2) throw new HttpsError('invalid-argument', '密碼至少需要 2 個字元');
  if (pin.length > 100) throw new HttpsError('invalid-argument', '密碼太長');
}

// ══ 網頁開啟時：登入畫面需要的一切（員工名單、誰已設定密碼、是否鎖定）══
// 每台伺服器快取 30 秒：被大量呼叫時幾乎不讀資料庫，壓低費用
let statusCache = { at: 0, v: null };
exports.status = publicCall(async () => {
  if (Date.now() - statusCache.at < 30000 && statusCache.v) return statusCache.v;
  const lock = await getLock();
  // 先搬移舊資料，登入畫面才拿得到正確的「誰已設定密碼」
  const d = (await scrubLegacy()) || {};
  const pin = await PIN_STATUS.get();
  const v = {
    superConfigured: await superConfigured(),
    locked: !!lock.locked,
    lockReason: lock.reason || '',
    employees: (d.employees || []).map(e => ({ id: e.id, name: e.name, dept: e.dept, store: e.store || '竹北店' })),
    pinStatus: pin.exists ? pin.data() : {},
  };
  statusCache = { at: Date.now(), v };
  return v;
});

// ══ 首次設定超級管理員 ══
exports.setupSuper = publicCall(async req => {
  const { username, password } = req.data || {};
  if (!username || typeof username !== 'string') throw new HttpsError('invalid-argument', '請輸入帳號');
  if (typeof password !== 'string' || password.length < 4) throw new HttpsError('invalid-argument', '密碼至少需要 4 個字元');
  if (await superConfigured()) throw new HttpsError('already-exists', '超級管理員已設定過');
  await cred('super').create({ username: username.trim(), hash: await hashPw(password) });
  return { ok: true };
});

// ══ 超級管理員的信任裝置：陌生裝置要用寄到信箱的驗證碼確認 ══
// superDevices/<id>      {tokenHash, name, ip, createdAt, lastUsedAt}（網頁存 id＋token 在 localStorage）
// superChallenge/current {codeHash, expires, tries, sentAt, ip, ua}
const DEVICES = db.collection('superDevices');
const CHALLENGE = db.doc('superChallenge/current');
const sha = s => crypto.createHash('sha256').update(String(s)).digest('hex');
const reqIp = req => String(((req.rawRequest || {}).headers || {})['x-forwarded-for'] || (req.rawRequest || {}).ip || '').split(',')[0].trim();
function uaName(req) {
  const ua = String(((req.rawRequest || {}).headers || {})['user-agent'] || '');
  const os = /iPhone|iPad/.test(ua) ? 'iPhone/iPad' : /Android/.test(ua) ? 'Android' : /Windows/.test(ua) ? 'Windows' : /Mac OS/.test(ua) ? 'Mac' : '其他系統';
  const br = /Edg\//.test(ua) ? 'Edge' : /Line\//.test(ua) ? 'LINE' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : /Firefox\//.test(ua) ? 'Firefox' : '其他瀏覽器';
  return `${os}・${br}`;
}
async function trustedDevice(req) {
  const { deviceId, deviceToken } = req.data || {};
  if (!deviceId || !deviceToken || typeof deviceId !== 'string' || deviceId.length > 64) return null;
  const ref = DEVICES.doc(deviceId);
  const s = await ref.get();
  if (!s.exists || s.data().tokenHash !== sha(deviceToken)) return null;
  await ref.update({ lastUsedAt: protection.helpers.twStamp(), ip: reqIp(req) });
  return deviceId;
}
async function sendDeviceCode(req) {
  const prev = await CHALLENGE.get();
  if (prev.exists && Date.now() - (prev.data().sentAt || 0) < 60000) return; // 同一分鐘只寄一封
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  await CHALLENGE.set({ codeHash: sha(code), expires: Date.now() + 10 * 60000, tries: 0, sentAt: Date.now(), ip: reqIp(req), ua: uaName(req) });
  await protection.helpers.sendMailNow(`🔐 假期抽籤系統：超級管理員陌生裝置登入驗證碼 ${code}`,
    `有裝置正在登入超級管理員：\n時間：${protection.helpers.twStamp()}\nIP：${reqIp(req)}\n裝置：${uaName(req)}\n\n` +
    `驗證碼：${code}（10 分鐘內有效）\n\n如果不是你本人在登入，代表你的超級管理員密碼可能已外洩，請盡快登入後修改密碼。`);
}
async function newDevice(req) {
  const deviceId = crypto.randomBytes(16).toString('hex');
  const deviceToken = crypto.randomBytes(32).toString('hex');
  const now = protection.helpers.twStamp();
  await DEVICES.doc(deviceId).set({ tokenHash: sha(deviceToken), name: uaName(req), ip: reqIp(req), createdAt: now, lastUsedAt: now });
  return { deviceId, deviceToken };
}

// ══ 管理員登入（含超級管理員）══
exports.adminLogin = publicCall(async req => {
  const { username, password } = req.data || {};
  if (!username || !password) throw new HttpsError('invalid-argument', '請輸入帳號和密碼');
  const key = attemptKey(`admin:${username}`);
  await checkLock(key);
  const lock = await getLock();
  const d = lock.locked ? {} : ((await scrubLegacy()) || {}); // 鎖定中只接受超級管理員，不必讀資料

  const sup = await cred('super').get();
  if (sup.exists && sup.data().username === username && await verifyPw(password, sup.data().hash)) {
    await clearFails(key);
    // 陌生裝置：密碼正確也不發通行證，先寄驗證碼到信箱
    if (!(await trustedDevice(req))) {
      await sendDeviceCode(req);
      await logLogin(req, { kind: 'superadmin', who: `${username}（超級管理員）`, ok: false, reason: '陌生裝置，已寄驗證碼' });
      return { needDeviceVerify: true };
    }
    await logLogin(req, { kind: 'superadmin', who: `${username}（超級管理員）`, ok: true });
    return { token: await issueToken('super', { role: 'superadmin' }), role: 'superadmin', username,
      locked: !!lock.locked, lockReason: lock.reason || '' };
  }
  // 系統鎖定中只有超級管理員能登入
  await assertNotLocked();
  const a = (d.admins || []).find(x => x.username === username);
  const c = a && await cred(`admin_${a.id}`).get();
  if (c && c.exists && await verifyPw(password, c.data().hash)) {
    await clearFails(key);
    await logLogin(req, { kind: 'admin', who: `${username}（${a.role || '主管'}）`, ok: true });
    return { token: await issueToken(`admin_${a.id}`, { role: 'admin', adminId: a.id }), role: 'admin', username };
  }
  await recordFail(key);
  await logLogin(req, { kind: 'admin', who: username, ok: false, reason: a ? '密碼錯誤' : '帳號不存在' });
  throw new HttpsError('permission-denied', '帳號或密碼錯誤');
});

// ══ 超級管理員：輸入信箱驗證碼，信任這台裝置並登入 ══
exports.verifySuperDevice = publicCall(async req => {
  const { username, password, code } = req.data || {};
  const key = attemptKey(`admin:${username}`);
  await checkLock(key);
  const sup = await cred('super').get();
  if (!sup.exists || sup.data().username !== username || !(await verifyPw(password, sup.data().hash))) {
    await recordFail(key);
    throw new HttpsError('permission-denied', '帳號或密碼錯誤');
  }
  const result = await db.runTransaction(async tx => {
    const s = await tx.get(CHALLENGE);
    if (!s.exists) return '驗證碼不存在，請重新登入取得新的驗證碼';
    const c = s.data();
    if (Date.now() > c.expires) { tx.delete(CHALLENGE); return '驗證碼已過期，請重新登入取得新的驗證碼'; }
    if (c.tries >= 5) { tx.delete(CHALLENGE); return '驗證碼錯誤次數過多，請重新登入取得新的驗證碼'; }
    if (sha(String(code || '').trim()) !== c.codeHash) { tx.update(CHALLENGE, { tries: c.tries + 1 }); return `驗證碼錯誤（還可以再試 ${4 - c.tries} 次）`; }
    tx.delete(CHALLENGE);
    return null;
  });
  if (result) {
    await logLogin(req, { kind: 'superadmin', who: `${username}（超級管理員）`, ok: false, reason: '裝置驗證碼錯誤' });
    throw new HttpsError('permission-denied', result);
  }
  await clearFails(key);
  const dev = await newDevice(req);
  await logLogin(req, { kind: 'superadmin', who: `${username}（超級管理員）`, ok: true, reason: `新裝置已驗證：${uaName(req)}` });
  const lock = await getLock();
  return { token: await issueToken('super', { role: 'superadmin' }), role: 'superadmin', username, ...dev,
    locked: !!lock.locked, lockReason: lock.reason || '' };
});

// ══ 超級管理員：信任裝置清單／移除 ══
exports.listSuperDevices = publicCall(async req => {
  protection.helpers.requireSuper(req);
  const snap = await DEVICES.get();
  return snap.docs.map(d => { const { tokenHash, ...rest } = d.data(); return { id: d.id, ...rest }; })
    .sort((a, b) => String(b.lastUsedAt).localeCompare(String(a.lastUsedAt)));
});
exports.removeSuperDevice = publicCall(async req => {
  protection.helpers.requireSuper(req);
  const { deviceId, all } = req.data || {};
  if (all) { const snap = await DEVICES.get(); await Promise.all(snap.docs.map(d => d.ref.delete())); }
  else if (typeof deviceId === 'string') await DEVICES.doc(deviceId).delete();
  return { ok: true };
});

// ══ 超級管理員：修改密碼（要輸入目前密碼；改完移除其他信任裝置並寄信通知）══
exports.changeSuperPassword = publicCall(async req => {
  protection.helpers.requireSuper(req);
  const { oldPassword, newPassword, deviceId } = req.data || {};
  if (typeof newPassword !== 'string' || newPassword.length < 8) throw new HttpsError('invalid-argument', '新密碼至少需要 8 個字元');
  if (newPassword.length > 100) throw new HttpsError('invalid-argument', '密碼太長');
  const sup = await cred('super').get();
  const { username, hash } = sup.data();
  const key = attemptKey(`admin:${username}`);
  await checkLock(key);
  if (!(await verifyPw(oldPassword, hash))) {
    await recordFail(key);
    throw new HttpsError('permission-denied', '目前密碼錯誤');
  }
  if (await verifyPw(newPassword, hash)) throw new HttpsError('invalid-argument', '新密碼不能跟目前密碼相同');
  await cred('super').set({ username, hash: await hashPw(newPassword), changedAt: protection.helpers.twStamp() });
  await clearFails(key);
  const others = (await DEVICES.get()).docs.filter(d => d.id !== deviceId);
  await Promise.all(others.map(d => d.ref.delete()));
  await admin.auth().revokeRefreshTokens('super').catch(() => {});
  await logLogin(req, { kind: 'superadmin', who: `${username}（超級管理員）`, ok: true, reason: '修改密碼' });
  await protection.helpers.sendMailNow('🔑 假期抽籤系統：超級管理員密碼已變更',
    `超級管理員密碼已在 ${protection.helpers.twStamp()} 變更。\nIP：${reqIp(req)}\n裝置：${uaName(req)}\n` +
    `已移除其他 ${others.length} 台信任裝置，其他裝置下次登入需要重新用信箱驗證碼確認。\n\n` +
    `如果不是你本人修改的，請立即到 Firebase 主控台 → Firestore → creds 集合刪除 super 文件，重新設定超級管理員。`);
  return { ok: true, removedDevices: others.length };
});

// ══ 管理員修改自己的密碼（要輸入目前密碼；改完其他裝置的登入失效）══
exports.changeOwnAdminPassword = publicCall(async req => {
  const t = req.auth && req.auth.token;
  if (!t || t.role !== 'admin') throw new HttpsError('permission-denied', '只有管理員可以使用');
  const { oldPassword, newPassword } = req.data || {};
  if (typeof newPassword !== 'string' || !newPassword.trim()) throw new HttpsError('invalid-argument', '請輸入新密碼');
  if (newPassword.length > 100) throw new HttpsError('invalid-argument', '密碼太長');
  const d = (await DATA.get()).data() || {};
  const me = (d.admins || []).find(a => a.id === t.adminId);
  if (!me) throw new HttpsError('permission-denied', '帳號已不存在');
  const key = attemptKey(`admin:${me.username}`);
  await checkLock(key);
  const c = await cred(`admin_${me.id}`).get();
  if (!c.exists || !(await verifyPw(oldPassword, c.data().hash))) {
    await recordFail(key);
    throw new HttpsError('permission-denied', '目前密碼錯誤');
  }
  await cred(`admin_${me.id}`).set({ hash: await hashPw(newPassword.trim()) });
  await clearFails(key);
  await admin.auth().revokeRefreshTokens(`admin_${me.id}`).catch(() => {});
  await logLogin(req, { kind: 'admin', who: `${me.username}（${me.role || '主管'}）`, ok: true, reason: '修改自己的密碼' });
  return { ok: true };
});

// ══ 員工登入 ══
exports.empLogin = publicCall(async req => {
  const { empId, pin } = req.data || {};
  await assertNotLocked();
  const key = attemptKey(`emp:${empId}`);
  await checkLock(key);
  const d = (await scrubLegacy()) || {};
  const emp = (d.employees || []).find(e => e.id === empId);
  if (!emp) throw new HttpsError('not-found', '找不到此員工');
  const c = await cred(`emp_${empId}`).get();
  if (!c.exists) throw new HttpsError('failed-precondition', '此員工尚未設定密碼');
  if (!(await verifyPw(pin, c.data().hash))) {
    await recordFail(key);
    await logLogin(req, { kind: 'employee', who: emp.name, ok: false, reason: '密碼錯誤' });
    throw new HttpsError('permission-denied', '密碼錯誤');
  }
  await clearFails(key);
  await logLogin(req, { kind: 'employee', who: emp.name, ok: true });
  return { token: await issueToken(`emp_${empId}`, { role: 'employee', empId }) };
});

// ══ 員工首次設定密碼（尚未設定過才可以）══
exports.empSetupPin = publicCall(async req => {
  const { empId, pin } = req.data || {};
  checkPin(pin);
  await assertNotLocked();
  const d = (await scrubLegacy()) || {};
  const emp = (d.employees || []).find(e => e.id === empId);
  if (!emp) throw new HttpsError('not-found', '找不到此員工');
  try {
    await cred(`emp_${empId}`).create({ hash: await hashPw(pin) });
  } catch (e) {
    throw new HttpsError('already-exists', '此員工已設定過密碼，請重新整理');
  }
  await logLogin(req, { kind: 'employee', who: emp.name, ok: true, reason: '首次設定密碼' });
  await PIN_STATUS.set({ [String(empId)]: true }, { merge: true });
  return { token: await issueToken(`emp_${empId}`, { role: 'employee', empId }) };
});

// ══ 設定員工密碼：員工改自己的，或有帳號管理權限的管理員設定 ══
exports.setEmployeePin = publicCall(async req => {
  const { empId, pin } = req.data || {};
  checkPin(pin);
  const me = await callerInfo(req);
  if (!(me.role === 'employee' ? me.empId === empId : me.canManage)) throw new HttpsError('permission-denied', '權限不足');
  if (!(me.d.employees || []).some(e => e.id === empId)) throw new HttpsError('not-found', '找不到此員工');
  await cred(`emp_${empId}`).set({ hash: await hashPw(pin) });
  await PIN_STATUS.set({ [String(empId)]: true }, { merge: true });
  return { ok: true };
});

// ══ 重置員工密碼：刪除密碼並讓已登入的裝置失效，員工下次登入重新設定 ══
exports.resetEmployeePin = publicCall(async req => {
  const { empId } = req.data || {};
  const me = await callerInfo(req);
  if (!me.canManage) throw new HttpsError('permission-denied', '權限不足');
  await cred(`emp_${empId}`).delete();
  await PIN_STATUS.update({ [String(empId)]: admin.firestore.FieldValue.delete() }).catch(() => {});
  await admin.auth().revokeRefreshTokens(`emp_${empId}`).catch(() => {});
  return { ok: true };
});

// ══ 設定管理員密碼（新增帳號、改密碼都用這個）══
exports.setAdminPassword = publicCall(async req => {
  const { adminId, password } = req.data || {};
  if (typeof password !== 'string' || !password.trim()) throw new HttpsError('invalid-argument', '請輸入密碼');
  const me = await callerInfo(req);
  const target = (me.d.admins || []).find(a => a.id === adminId);
  if (!target) throw new HttpsError('not-found', '找不到此管理員');
  if (!me.canManage || me.rank <= roleRank(target.role || '主管')) throw new HttpsError('permission-denied', '權限不足，無法修改此帳號密碼');
  await cred(`admin_${adminId}`).set({ hash: await hashPw(password.trim()) });
  await admin.auth().revokeRefreshTokens(`admin_${adminId}`).catch(() => {});
  return { ok: true };
});

// ══ 刪除管理員前呼叫：刪除密碼並讓已登入的裝置失效 ══
exports.deleteAdminCreds = publicCall(async req => {
  const { adminId } = req.data || {};
  const me = await callerInfo(req);
  const target = (me.d.admins || []).find(a => a.id === adminId);
  if (target && (!me.canManage || me.rank <= roleRank(target.role || '主管'))) throw new HttpsError('permission-denied', '權限不足，無法刪除此帳號');
  await cred(`admin_${adminId}`).delete();
  await admin.auth().revokeRefreshTokens(`admin_${adminId}`).catch(() => {});
  return { ok: true };
});
