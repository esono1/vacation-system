# CLAUDE.md — 假期抽籤系統

給 Claude Code 的專案說明。使用者 Kooii，**溝通用繁體中文、簡潔直接**。

## 架構

| 部分 | 檔案 | 說明 |
|---|---|---|
| 網頁 | `index.html` | 整個系統（單一檔案），放在 GitHub Pages |
| 登入伺服器 | `functions/index.js` | 密碼驗證、發通行證、帳號密碼管理 |
| 系統保護 | `functions/protection.js` | 流量提醒／鎖定／攻擊熔斷、備份、寄信、費用熔斷 |
| 稽核日誌 | `functions/audit.js` | 資料修改紀錄、可疑判斷（比對「網頁允許的操作」）、登入紀錄 |
| 安全規則 | `firestore.rules` | 沒有任何公開可讀的資料；只有登入者能讀寫 `system/data` |
| 測試 | `tests/audit_rules.test.js` | 稽核規則的離線測試 |

詳細說明、部署步驟、待辦在 `README.md`。

## 環境

- `http://localhost:8765/`：本地模式，不連線（超級管理員 `test`/`test`）
- `http://localhost:8765/?env=test`：連測試專案 `vacation-system-test`
- 正式網站（GitHub Pages）：正式專案 `vacation-system-22655`
- 本機伺服器：`python -m http.server 8765 --bind 127.0.0.1`
- 部署：`firebase deploy --only "functions,firestore" --project test`（正式用 `--project prod`）

## ✅ 每次修改完成前的檢查清單（不可省略）

1. **改了網頁功能（新增／修改／刪除任何會存檔的操作）→ 同步稽核規則**
   - `functions/audit.js`：員工操作改 `validateEmployee`；管理員分頁能改的資料改 `TAB_FIELDS`；新資料欄位加進 `FIELD_LABEL`
   - `tests/audit_rules.test.js`：補上新功能「應正常」和「應可疑」的測試案例
   - 執行 `node tests/audit_rules.test.js`，必須全部通過
   - 沒同步的後果：新功能的正常操作會被誤判成可疑、寄誤報信給使用者
2. **改了 `index.html` 的 `migrateData`（載入時自動補預設值）→ 同步 `audit.js` 的 `normalize`**，否則網頁的自動修正會被當成使用者修改
3. **新增 Cloud Functions 的對外功能（onCall）→ 一律用 `publicCall` 包起來**，才會被流量計數、鎖定與熔斷保護
4. **新增資料欄位或集合 → 檢查 `firestore.rules`**：預設全部拒絕，只開放真正需要的
5. **語法檢查**：`index.html` 的 `<script>` 抽出來 `node --check`；functions 用 `node -e "require('./index.js')"`
6. **測試順序**：本地模式 → 測試專案（`?env=test`，真實連線）→ 才部署正式專案
7. **部署正式專案時**：`index.html` 上傳 GitHub 與 `firestore.rules` 部署要同一時段做（挑沒人用的時間）
8. **更新 `README.md`**（功能說明、待辦）
9. **不上傳 GitHub**：備份檔（`*backup*.json`）、`functions/.env`（`.gitignore` 已排除，提交前再確認）

## 已知限制與踩過的坑

- **不要用 Google 的「強制執行支出上限」**（預覽功能）：觸發後只擋部分功能、頁面顯示正常、不寄信，網站打不開卻看不出原因。改用本系統的流量鎖定＋費用熔斷＋1 台幣警示預算。
- 付款帳戶解除後重新連結，服務要 15～30 分鐘才完全恢復。
- 安全規則部署後約 1 分鐘才生效；新 Firestore 索引建立要幾分鐘。
- 第一次部署 Firestore 觸發的功能常因權限還沒生效失敗，等 1～2 分鐘重試即可。
- **新專案第一次部署常大量建置失敗**，重試時才建立成功的 callable 會漏設「公開呼叫」權限（網頁呼叫得到 403，更新部署也補不回來）。解法：`firebase functions:delete <名稱們> --region asia-east1` 後重新部署。驗證：直接 POST 功能網址，未帶資料時應回 200／400／403（程式的錯誤訊息），不應是空白的 403。
- 部署失敗留下的殘留版本可能類型錯誤（例如 `budgetGuard` 被當成 HTTPS 功能），要先刪除再部署。
- Claude 桌面版有獨立的程式空間：在這裡 `npm install -g` 的工具，使用者自己的命令提示字元看不到。需要使用者輸入的設定（密碼等）改用 Google Cloud 網頁操作。
- 登入伺服器簽發通行證需要 compute 服務帳戶有「服務帳戶憑證建立者」角色＋IAM Credentials API；費用熔斷需要「專案帳單管理員」＋Cloud Billing API。
- 網頁存檔是整份資料覆寫，兩人同時存檔時，後存的會蓋掉先存的；稽核日誌可能因此把「蓋掉別人的修改」標成可疑，需人工判斷。
- `index.html` 的 `renderPendingPromotions` 顯示時會清掉補籤資訊（包含其他假期的），是既有行為，稽核規則已視為正常。
