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
console.log(fail ? `\n${fail} 項失敗` : '\n全部通過');
process.exit(fail ? 1 : 0);
