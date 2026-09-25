// 稽核日誌「是否符合網頁操作規則」的離線測試（假資料，不連線）
// 執行：node tests/audit_rules.test.js（需先在 functions 資料夾 npm install）
// 改了網頁功能或 functions/audit.js 的規則後，都要重跑並補上新功能的測試案例
const path = require('path');
const FN = path.join(__dirname, '..', 'functions');
const admin = require(path.join(FN, 'node_modules/firebase-admin'));
admin.initializeApp({ projectId: 'offline-test' });
const { diffData, describe, judge, makeCtx, identify, normalize } = require(path.join(FN, 'audit.js'))._test;

const P = { id: 100, name: '10月假期', start: '2026-10-01', end: '2026-10-31', allowApplication: true, allowMakeup: true, genderRestrict: '',
  limits: { 早班: { '2026-10-13': 0 } } };
const base = normalize({
  employees: [{ id: 1, name: '小明', dept: '早班', gender: 'male', store: '竹北店' }, { id: 2, name: '小華', dept: '晚班', gender: 'female', store: '竹北店' }],
  admins: [{ id: 'a1', username: 'SU', role: '負責人' }, { id: 'a2', username: 'CC', role: '櫃檯' }, { id: 'a3', username: 'TS', role: '主管' }],
  periods: [P],
  applications: [{ id: 'p1', periodId: 100, empId: 1, empName: '小明', shift: '早班', dates: ['2026-10-01'] },
                 { id: 'p2', periodId: 100, empId: 2, empName: '小華', shift: '晚班', dates: ['2026-10-02'] }],
  extraLeaves: [{ id: 'e1', empId: 1, empName: '小明', shift: '早班', date: '2026-10-05', status: 'rejected' },
                { id: 'e2', empId: 1, empName: '小明', shift: '早班', date: '2026-10-06', status: 'pending' }],
  history: [{ id: 'h1', periodId: 100, shift: '早班', date: '2026-10-03', gender: 'male', limit: 1, winners: [{ name: '小強', dept: '早班' }], losers: [{ name: '小明', dept: '早班' }] },
            { id: 'h2', periodId: 100, shift: '早班', date: '2026-10-20', gender: 'male', limit: 1, winners: [{ name: '小強', dept: '早班' }], losers: [] }],
  makeupLeaves: [], pendingPromotions: [{ periodId: 100, shift: '早班', date: '2026-10-03', gender: 'male' }],
  monthlyQuota: 3, counterApplications: [],
});
const clone = o => JSON.parse(JSON.stringify(o));
let fail = 0;
function run(name, uid, mutate, expectSuspicious) {
  const after = clone(base); mutate(after);
  const ctx = makeCtx(base, after);
  const me = identify({ authType: 'app_user', authId: uid }, ctx);
  const changes = diffData(base, after);
  const reasons = judge(me, changes, ctx, base, after);
  const ok = (reasons.length > 0) === expectSuspicious;
  if (!ok) fail++;
  console.log(`${ok ? '✅' : '❌'} ${expectSuspicious ? '[應可疑]' : '[應正常]'} ${name}${reasons.length ? '\n     → ' + reasons.join('\n     → ') : ''}`);
}
const E = 'emp_1';
console.log('── 員工：網頁做得到的（應正常）');
run('申請 2 天（範圍內、未超額）', E, d => d.applications[0].dates.push('2026-10-08', '2026-10-09'), false);
run('取消自己的日期', E, d => { d.applications = d.applications.filter(a => a.id !== 'p1'); }, false);
run('未中籤日不計入上限：已有 1 天＋未中籤 10/03＋再 2 天 = 4 天但有效 3 天', E, d => d.applications[0].dates.push('2026-10-03', '2026-10-08', '2026-10-09'), false);
run('申請額外假（待審核）', E, d => d.extraLeaves.push({ id: 'e3', empId: 1, empName: '小明', date: '2026-10-07', status: 'pending' }), false);
run('取消自己待審核的額外假', E, d => { d.extraLeaves = d.extraLeaves.filter(x => x.id !== 'e2'); }, false);
run('未中籤者申請補假', E, d => d.makeupLeaves.push({ id: 'm1', periodId: 100, empId: 1, empName: '小明', date: '2026-10-15' }), false);
run('超休確認：刪除自己剛申請那天的抽籤紀錄', E, d => { d.applications[0].dates.push('2026-10-20'); d.history = d.history.filter(h => h.id !== 'h2'); }, false);
run('顯示預覽時清掉補籤資訊', E, d => { d.pendingPromotions = []; }, false);
{ // 資料庫裡的舊資料缺欄位 → 網頁載入時自動補上後存檔（伺服器也先補上再比對）
  const raw = clone(base); delete raw.periods[0].allowApplication; delete raw.employees[0].store; delete raw.makeupLeaves;
  const before = normalize(raw), after = clone(base);
  const ch = diffData(before, after);
  const ok = ch.length === 0; if (!ok) fail++;
  console.log(`${ok ? '✅' : '❌'} [應正常] 網頁載入時自動補預設值（缺欄位的舊資料）${ch.length ? ' → 偵測到 ' + ch.map(c => c.field).join(',') : ''}`);
}

console.log('── 員工：網頁做不到的（應可疑）');
run('申請超過天數上限（3 天）', E, d => d.applications[0].dates.push('2026-10-08', '2026-10-09', '2026-10-10'), true);
run('申請假期範圍外的日期', E, d => d.applications[0].dates.push('2026-11-01'), true);
run('申請不開放的日期（10/13 名額 0）', E, d => d.applications[0].dates.push('2026-10-13'), true);
run('假期未開放時申請', E, d => { d.periods[0].allowApplication = false; d.applications[0].dates.push('2026-10-08'); }, true);
run('把自己被駁回的額外假改成核准', E, d => { d.extraLeaves[0].status = 'approved'; }, true);
run('新增額外假直接設成已核准', E, d => d.extraLeaves.push({ id: 'e3', empId: 1, empName: '小明', date: '2026-10-07', status: 'approved' }), true);
run('刪除自己已審核（駁回）的額外假', E, d => { d.extraLeaves = d.extraLeaves.filter(x => x.id !== 'e1'); }, true);
run('非未中籤者申請補假（小華）', 'emp_2', d => d.makeupLeaves.push({ id: 'm2', periodId: 100, empId: 2, empName: '小華', date: '2026-10-15' }), true);
run('刪除別人的申請', E, d => { d.applications = d.applications.filter(a => a.id !== 'p2'); }, true);
run('刪除與自己申請無關的抽籤紀錄', E, d => { d.history = d.history.filter(h => h.id !== 'h1'); }, true);
run('改自己的抽籤結果（把自己加進中籤）', E, d => { d.history[0].winners.push({ name: '小明', dept: '早班' }); }, true);
run('改申請的班別', E, d => { d.applications[0].shift = '晚班'; }, true);
run('改每月天數', E, d => { d.monthlyQuota = 30; }, true);

console.log('── 管理員');
run('櫃檯改櫃檯排休（看得到的分頁）', 'admin_a2', d => d.counterApplications.push({ id: 'c1', adminId: 'a2', date: '2026-10-01' }), false);
run('櫃檯改排假申請（看不到的分頁）', 'admin_a2', d => { d.applications[1].dates.push('2026-10-09'); }, true);
run('櫃檯把自己升成負責人', 'admin_a2', d => { d.admins[1].role = '負責人'; }, true);
run('主管改排假申請', 'admin_a3', d => { d.applications[1].dates.push('2026-10-09'); }, false);
run('主管改管理員帳號（預設沒有帳號管理）', 'admin_a3', d => { d.admins[1].role = '主管'; }, true);
run('負責人改管理員帳號', 'admin_a1', d => { d.admins[1].role = '主管'; }, false);
run('主管一次刪 12 筆', 'admin_a3', d => { for (let i = 0; i < 12; i++) base.applications.push({ id: 'x' + i, periodId: 100, empId: 1, dates: ['2026-10-0' + (i % 9 + 1)] }); d.applications = []; }, true);
base.applications = base.applications.slice(0, 2);
run('超級管理員任意修改', 'super', d => { d.applications = []; d.monthlyQuota = 1; }, false);
{ // 只有「技師管理」分頁權限的主管幫員工改名（會同步改抽籤紀錄、額外假裡的名字）
  base.adminPermissions = { a3: ['employees'] };
  run('只有技師管理權限的主管改員工姓名（同步改紀錄）', 'admin_a3', d => {
    d.employees[0].name = '小明明'; d.applications[0].empName = '小明明'; d.extraLeaves.forEach(x => { x.empName = '小明明'; });
    d.history[0].losers[0].name = '小明明';
  }, false);
  base.adminPermissions = {};
}
{ // 清潔：只看得到假表、歷史
  base.admins.push({ id: 'a4', username: 'TJ', role: '清潔' });
  run('清潔改排假申請（看不到的分頁）', 'admin_a4', d => { d.applications[1].dates.push('2026-10-09'); }, true);
  run('清潔改櫃檯排休（預設看不到櫃檯分頁）', 'admin_a4', d => d.counterApplications.push({ id: 'c2', adminId: 'a4', date: '2026-10-01' }), true);
  base.admins.pop();
}
{ // 舊錯字「櫃檶」：網頁載入時自動改正成「櫃檯」，任何人存檔帶到這個改正都不算修改；權限照櫃檯
  const raw = clone(base); raw.admins[1].role = '櫃檶';
  const ch = diffData(normalize(raw), clone(base));
  const ok = ch.length === 0; if (!ok) fail++;
  console.log(`${ok ? '✅' : '❌'} [應正常] 載入時把「櫃檶」改正成「櫃檯」不算修改`);
  base.admins.push({ id: 'a5', username: 'GG', role: '櫃檶' });
  run('舊錯字櫃檶的帳號改排假申請（應依櫃檯權限擋下）', 'admin_a5', d => { d.applications[1].dates.push('2026-10-09'); }, true);
  base.admins.pop();
}
console.log('── 伺服器／專案管理權限的寫入');
{
  const { judgeServer } = require(path.join(FN, 'audit.js'))._test;
  const check = (name, mutate, restore, expectSuspicious) => {
    const b = clone(base), a = clone(base);
    b.admins[0].password = 'plain'; b.employees[0].pin = '12'; // 舊格式：密碼還在資料裡
    Object.assign(a, clone(b)); mutate(a);
    const r = judgeServer(diffData(b, a), restore);
    const ok = (r.reasons.length > 0) === expectSuspicious; if (!ok) fail++;
    console.log(`${ok ? '✅' : '❌'} ${expectSuspicious ? '[應可疑]' : '[應正常]'} ${name} → ${r.who}`);
  };
  check('舊資料密碼搬移（只移除 password/pin）', a => { delete a.admins[0].password; delete a.employees[0].pin; }, false, false);
  check('還原備份（2 分鐘內有還原前備份）', a => { a.applications = []; }, true, false);
  check('搬移時順便改了別的欄位', a => { delete a.admins[0].password; a.admins[0].role = '主管'; }, false, true);
  check('沒有還原、也不是搬移的直接修改', a => { a.monthlyQuota = 99; }, false, true);
  // 封存：2 分鐘內有 archive 備份，而且只有「刪除」
  const b = clone(base), onlyRemove = clone(base); onlyRemove.applications = []; onlyRemove.periods = [];
  const r1 = judgeServer(diffData(b, onlyRemove), new Set(['archive']));
  const ok1 = !r1.reasons.length; if (!ok1) fail++;
  console.log(`${ok1 ? '✅' : '❌'} [應正常] 封存舊資料（只刪除） → ${r1.who}`);
  const sneaky = clone(base); sneaky.applications = []; sneaky.monthlyQuota = 99;
  const r2 = judgeServer(diffData(b, sneaky), new Set(['archive']));
  const ok2 = r2.reasons.length > 0; if (!ok2) fail++;
  console.log(`${ok2 ? '✅' : '❌'} [應可疑] 封存時順便改了別的設定 → ${r2.who}`);
}

console.log('── 封存舊資料的挑選規則');
{
  const { splitForArchive } = require(path.join(FN, 'protection.js')).helpers;
  const d = {
    periods: [{ id: 1, name: '舊', start: '2026-01-01', end: '2026-01-31' }, { id: 2, name: '新', start: '2026-09-01', end: '2026-09-30' }],
    applications: [{ id: 'a1', periodId: 1 }, { id: 'a2', periodId: 2 }],
    history: [{ periodId: 1, date: '2026-01-05' }, { periodId: 2, date: '2026-09-05' }, { periodId: 99, date: '2025-12-01' }],
    extraLeaves: [{ id: 'x1', date: '2026-01-10' }, { id: 'x2', date: '2026-09-10' }],
    counterApplications: [{ id: 'c1', date: '2026-01-02' }, { id: 'c2', date: '2026-09-02' }],
    publishedSchedules: [{ periodId: 1, periodEnd: '2026-01-31' }], makeupLeaves: [], longLeaves: [{ endDate: '2026-01-20' }],
    employees: [{ id: 1, name: '小明' }], monthlyQuota: 8,
  };
  const { out, oldPeriods, dropped } = splitForArchive(d, '2026-03-25');
  const ok = oldPeriods.length === 1 && out.periods.length === 1 && out.applications.length === 1 && out.history.length === 1 &&
    out.extraLeaves.length === 1 && out.counterApplications.length === 1 && !out.publishedSchedules.length && !out.longLeaves.length &&
    out.employees.length === 1 && out.monthlyQuota === 8;
  if (!ok) fail++;
  console.log(`${ok ? '✅' : '❌'} 結束滿 6 個月的假期與相關紀錄被移除、其他保留 → 移除 ${JSON.stringify(dropped)}`);
}
console.log(fail ? `\n${fail} 項失敗` : '\n全部通過');
process.exit(fail ? 1 : 0);
