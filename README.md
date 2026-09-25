# vacation-system

假期抽籤系統。網頁（`index.html`）放在 GitHub，資料與登入放在 Firebase。

## 架構

| 部分 | 位置 | 作用 |
|---|---|---|
| 網頁 | `index.html`（GitHub） | 整個系統的畫面與邏輯 |
| 登入伺服器 | `functions/index.js`（Firebase Cloud Functions） | 驗證密碼、發登入通行證 |
| 安全規則 | `firestore.rules`（Firebase） | 沒登入的人讀寫不了資料 |

- 所有密碼只存在 Firestore 的 `creds` 集合，網頁和任何使用者都讀不到，只有登入伺服器能讀。
- 登入畫面需要的員工名單（姓名／班別／店別）放在 `system/public`，公開可讀。
- 同一帳號連續輸錯 5 次密碼，鎖定 5 分鐘。

## 三種執行環境

網頁會依網址自動切換：

| 網址 | 環境 | 資料 |
|---|---|---|
| 正式網站（GitHub Pages） | 正式 | 正式專案 `vacation-system-22655` |
| `http://localhost:8765/?env=test` | 測試 | 測試專案 `vacation-system-test` |
| `http://localhost:8765/` 或直接開檔案 | 本地 | 只存在瀏覽器，不連線（超級管理員 `test` / `test`） |

本機開伺服器（在這個資料夾執行）：

```
python -m http.server 8765 --bind 127.0.0.1
```

## 部署

需要先安裝 Node.js LTS 與 Firebase CLI（`npm install -g firebase-tools`），並執行 `firebase login`。

```
cd functions
npm install
cd ..
firebase deploy --only "functions,firestore:rules" --project test
```

正式專案把 `--project test` 換成 `--project prod`。**一定要先部署到測試專案並測試過，再部署正式專案。**

網頁（`index.html`）的更新是上傳到 GitHub，跟上面的指令無關。

## 新 Firebase 專案第一次部署前要做的設定

1. 升級 **Blaze 方案**（Cloud Functions 需要）。在 Google Cloud 帳單設定預算：
   - 一個「僅傳送警告」的預算（例如 1 台幣），任何費用都會寄信通知。
   - 一個給費用熔斷用的預算（金額設正常月費的好幾倍），並連結 Pub/Sub 主題 `budget-alerts`（見下方「系統保護」）。
   - **不建議使用 Google 的「強制執行支出上限」（預覽功能）**：2026-09 測試時，它觸發後只擋住部分功能（網頁一開就要用的 `status`），預算頁面仍顯示正常、也沒有再寄信，網站打不開卻看不出原因；改回「僅傳送警告」後才恢復。
2. 部署一次後，到 Google Cloud 主控台 →「IAM 與管理」→「IAM」，找 `專案編號-compute@developer.gserviceaccount.com`，新增角色「**服務帳戶憑證建立者**」（Service Account Token Creator）。沒做這步，登入會出現「連線失敗」，伺服器記錄會寫 `iam.serviceAccounts.signBlob denied`。
3. 啟用 **IAM Service Account Credentials API**：`https://console.cloud.google.com/apis/library/iamcredentials.googleapis.com?project=專案ID`

## 系統保護（`functions/protection.js`）

| 保護 | 觸發 | 動作 | 恢復 |
|---|---|---|---|
| 異常流量鎖定 | 每小時所有對外功能的呼叫超過 `TRAFFIC_LIMIT`（預設 3000 次） | 備份 → 寄信 → 鎖定，只有超級管理員能登入 | 超級管理員在「帳號管理 → 系統保護」按「解除鎖定」 |
| 攻擊熔斷 | 鎖定後同一小時仍持續湧入，達 `TRAFFIC_LIMIT` 兩倍 | 備份 → 寄信 → 立即解除付款（不等 Google 帳單統計） | 同費用熔斷，恢復後再解除鎖定 |
| 費用熔斷 | 預算通知（Pub/Sub `budget-alerts`）費用達 95% | 備份 → 寄信 → 解除專案的付款帳戶 | Firebase 主控台重新升級 Blaze、選原本的付款帳戶；約 15～30 分鐘恢復 |
| 每日備份 | 每天 04:00 | 保留最新 3 份；每週一寄一份到信箱 | 「系統保護」可下載或還原 |

設定：
- 寄信：Gmail 應用程式密碼存在 Secret Manager 的 `GMAIL_APP_PASSWORD`（Google Cloud 主控台 → Secret Manager 建立）；寄件／收件信箱寫在 `functions/.env` 的 `BACKUP_EMAIL`（此檔不上傳 GitHub）。
- 費用熔斷需要：`專案編號-compute@developer.gserviceaccount.com` 加上「專案帳單管理員」角色、啟用 Cloud Billing API、預算連結 Pub/Sub 主題 `budget-alerts`。
- 測試專案的設定在 `functions/.env.vacation-system-test`。

## 其他資料保護

- **同時編輯保護**：`system/meta` 存資料版本號，網頁存檔時在同一筆交易裡比對；有人先存過就拒絕這次存檔、載入最新資料並提示重新操作（不會悄悄蓋掉別人的修改）。
- **舊資料封存**：每天 04:00 檢查，結束滿 `ARCHIVE_MONTHS`（6）個月的假期 → 先寄完整備份到信箱 → 連同相關申請／抽籤／補假／額外假／長假／櫃檯與清潔排班一起移除（避免資料超過 1 MB 上限）。「系統保護」可預覽與手動執行；匯入含舊假期的資料時會提醒。
- **備份信不重複**：每週備份資料沒變就不寄；其他通知信資料沒變就不附檔（`mailState/lastBackup` 記錄上次寄出的雜湊）。
- **管理員自己改密碼**：右上角「🔑 修改密碼」，要輸入目前密碼，改完需重新登入。

## 稽核日誌（`functions/audit.js`）

- **操作紀錄**：`system/data` 每次被修改，伺服器端觸發 `auditDataWrite`，比對修改前後，記錄「誰、何時、改了什麼」到 `audit`。
  「誰」來自 Firebase 登入身分（不是網頁回報），繞過網頁直接改資料也會被記錄；任何人都不能改或刪紀錄。
- **可疑判斷**：任何「網頁本身做不到」的修改都標為可疑（以修改「前」的身分與權限為準）：
  - 員工：逐筆比對網頁規則。排假申請只能動自己的、日期要在開放中的假期內、不超過天數上限；額外假只能新增「待審核」、只能取消自己待審核的、不能改狀態；補假只有未中籤者能申請；抽籤紀錄只允許「超休確認」刪除自己當天的紀錄；其他資料一律不能碰
  - 管理員：只能改自己看得到的分頁會改的資料（`TAB_FIELDS`），權限邏輯同網頁
  - 非超級管理員一次刪除 10 筆以上
  - 網頁載入時自動補的預設值不算修改（`normalize` 對應網頁的 `migrateData`）
  - 可疑操作會寄信通知（同一帳號每小時最多一封）
  - **改網頁功能時必須同步更新這些規則**，見 `CLAUDE.md` 的檢查清單
- **登入紀錄**：成功／失敗、帳號、IP，存在 `logins`。
- 兩種紀錄保留 90 天，在超級管理員的「帳號管理 → 系統保護」查看。
- 限制：這是「抓得到」不是「擋得住」，修改會先生效，需要時用備份還原。網頁端的資料自動修正（`migrateData`）偶爾可能讓員工的第一次存檔被標為可疑，請看紀錄內容判斷。
- 離線測試：`node tests/audit_rules.test.js`（30 項，含網頁做得到／做不到的各種操作）。

## 從舊版（密碼存在資料裡）升級

新版上線後，網頁第一次被打開時，登入伺服器會自動把舊資料裡的密碼（`system/auth`、`admins[].password`、`employees[].pin`）搬進 `creds` 並從公開資料刪除。不需要任何人重設密碼。

## 備份與還原

- **備份**：超級管理員登入 →「💾 匯出資料」。新版的備份**不含任何密碼**。
- **還原**：超級管理員登入 →「📂 匯入資料」。只會還原資料，不會動到密碼。

## 超級管理員安全

- **修改密碼**：超級管理員登入 →「帳號管理 → 系統保護 → 超級管理員安全」→「修改密碼」。要輸入目前密碼，新密碼至少 8 碼；改完寄信通知，並移除本裝置以外的所有信任裝置。
- **陌生裝置驗證**：超級管理員在沒驗證過的裝置（或清除過瀏覽器資料）登入時，密碼正確後還要輸入寄到管理信箱的 6 位數驗證碼（10 分鐘有效、錯 5 次作廢、每分鐘最多寄一封）。信任裝置清單在同一頁，可以移除。
  - 裝置憑證存在瀏覽器的 localStorage，伺服器只存雜湊（`superDevices`）；驗證碼也只存雜湊（`superChallenge`）。

### 忘記超級管理員密碼（或被盜改）

1. Firebase 主控台 → Firestore Database →「資料」→ `creds` 集合 → 刪除 `super` 文件。
2. **立刻**重新打開網站，會出現「首次設定」畫面，重新設定帳號密碼。（刪除到重設之間，任何人打開網站都會看到首次設定畫面，所以動作要快。）
3. 其他管理員與員工的密碼不受影響。

## 待辦

- [x] 費用熔斷（`budgetGuard`）實際觸發測試（2026-09-25 測試專案：停止與恢復皆成功，資料完整）
- [x] 稽核日誌（2026-09-25 完成，測試專案驗證）
- [x] 正式專案上線（2026-09-25 04:55 切換完成，舊密碼已搬移，安全規則已驗證）；剩第 3 步預算、第 7 步換新備份由使用者完成
- 上線步驟（留作紀錄）：
  1. 超級管理員匯出最新備份
  2. 正式專案升級 Blaze（選原本的付款帳戶「我的帳單帳戶」）
  3. 預算：**1 台幣「僅傳送警告」預算，範圍要涵蓋正式專案**（或建一個範圍「所有專案」的）；另建熔斷預算（100～300 台幣）連結 Pub/Sub `budget-alerts`；**不要用 Google 的「強制執行支出上限」**
  4. `firebase deploy --only functions --project prod`
  5. 權限：compute 服務帳戶加「服務帳戶憑證建立者」「專案帳單管理員」；啟用 IAM Credentials API、Cloud Billing API；Secret Manager 建 `GMAIL_APP_PASSWORD`
  6. 挑沒人用的時段：上傳新 `index.html` 到 GitHub，同時 `firebase deploy --only firestore:rules --project prod`
  7. 打開正式網站確認能登入 → 重新匯出備份，刪掉舊的含密碼備份
- [ ] 測試結束後清空測試專案：刪除伺服器功能與映像檔、解除付款帳戶

## 定期維護：Node.js 版本

Google 大約每 2～3 年淘汰一個 Node.js 版本，淘汰前會寄信通知。收到通知時：

1. 把 `functions/package.json` 裡 `"node": "22"` 改成信中建議的新版本（例如 `"24"`）。
2. 照「部署」章節重新部署，先測試專案、再正式專案。
