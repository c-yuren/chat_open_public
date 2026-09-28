# 私人雙人聊天室

這是一個免註冊的雙人聊天室。使用者從瀏覽器建立房間，透過邀請連結讓另一位成員加入；訊息在瀏覽器端加密後才送到伺服器。

## 使用方式

### 建立房間

1. 開啟聊天室首頁。
2. 點擊「建立加密聊天室」。
3. 輸入顯示暱稱，例如「小明」。欄位不會預先填入暱稱。
4. 建立完成後，從「邀請」取得邀請連結。
5. 將邀請連結提供給另一位成員。

### 加入房間

1. 開啟收到的邀請連結。
2. 輸入顯示暱稱。
3. 完成後即可進入聊天室。

聊天室只接受邀請連結加入，不提供直接輸入房間代碼的加入方式。

### 離開房間

從左上角返回首頁，或在設定中選擇「離開房間」。系統會清除瀏覽器中的房間快取、目前房間狀態、訊息畫面與網址中的房間資訊；重新載入後不會自動回到原房間。

## iOS 捷徑

捷徑安裝與使用流程如下：

1. 開啟 [聊天室捷徑](https://www.icloud.com/shortcuts/d3c94c3468554c9b9abf38c9a09e186e)，選擇加入捷徑。
2. 在聊天室設定中複製目前房間連結。
3. 第一次執行捷徑時貼上房間連結，再輸入使用者暱稱。
4. 之後選擇傳送訊息或查看訊息。

捷徑不需要手動設定 API、Token 或加密金鑰。

## 資料與加密

- 加解密在使用者瀏覽器中使用 AES-GCM-256 完成。
- 加密金鑰放在邀請網址的 hash 片段，不會放進 HTTP 請求。
- 伺服器只接收房間驗證資訊、密文、IV 與必要的訊息狀態。
- 每個房間最多保留 50 則訊息，超過後依 FIFO 移除最舊訊息。
- 超過 14 天沒有活動的房間會由後端定期清理。
- 暱稱儲存在瀏覽器 `localStorage`，不作為帳號或登入憑證。

## 系統架構

```
瀏覽器 A ── 加密 ──┐
                    ├──> 前端靜態頁面
瀏覽器 B ── 解密 ──┘          │
                              │ 僅傳送密文與房間驗證資訊
                              ▼
                   Oracle Cloud VM
                   Express + better-sqlite3
                   Port 3001
```

## 專案結構

```text
chat_open/
├── backend/
│   ├── server.js
│   ├── package.json
│   ├── nginx.conf
│   └── setup-vm.sh
├── frontend/
│   ├── index.html
│   └── monitor.html
├── index.html
├── monitor.html
├── vercel.json
├── ORACLE_CONFIG.md
└── README.md
```

`frontend/index.html` 與根目錄 `index.html` 必須保持同步；`frontend/monitor.html` 與根目錄 `monitor.html` 也必須保持同步。

## 本機開發

後端：

```powershell
cd backend
npm install
npm start
```

前端可使用靜態伺服器提供根目錄或 `frontend/` 內容。若直接從檔案系統開啟，部分瀏覽器功能可能受安全來源限制，建議使用 HTTPS 或本機伺服器。

後端語法檢查：

```powershell
node -c backend/server.js
```

## 公開版部署

公開版服務使用：

- 前端：根目錄與 `frontend/` 靜態 HTML
- 後端：Oracle Cloud VM 的 Port `3001`
- 程序：PM2 `chat-open-api`
- 網域：`https://open-shortcut-chat.duckdns.org`

詳細的 SSH、Nginx、PM2、SQLite 與管理員 API 說明請參考 [ORACLE_CONFIG.md](ORACLE_CONFIG.md)。

部署前同步前端檔案：
```powershell
Copy-Item frontend/index.html -Destination index.html -Force
Copy-Item frontend/monitor.html -Destination monitor.html -Force
```

## 注意事項

- 邀請連結包含房間驗證資訊與加密金鑰，請只提供給房間成員。
- 清除瀏覽器網站資料會移除本機房間與暱稱記憶。
- 不要把 VM 私鑰、後端 `.env` 或管理員金鑰提交到 Git 儲存庫。
- 公開版後端使用 Port `3001`。
