#!/bin/bash
# ============================================================
#  Oracle Cloud VM 一鍵快速設定腳本 (公開版 E2EE Chat)
# ============================================================
#  支援全新 VM 初始化，或在現有 VM 上建立 Port 3001 獨立空間
#  適用於 Ubuntu 22.04 / 24.04
#  用法：
#    chmod +x setup-vm.sh
#    sudo ./setup-vm.sh
# ============================================================

set -e

echo "======================================================"
echo "  🚀 Open E2EE Chat「仁 (公開版)」— 伺服器部署腳本"
echo "======================================================"

# --- 1. 系統更新 ---
echo ""
echo "📦 [1/5] 更新系統套件清單..."
apt update -y

# --- 2. 檢查/安裝 Node.js 20 ---
echo ""
echo "📦 [2/5] 檢查 Node.js 執行環境..."
if ! command -v node &> /dev/null; then
  echo "  → 正在安裝 Node.js 20 LTS..."
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt install -y nodejs
else
  echo "  → Node.js 已安裝: $(node -v)"
fi

# --- 3. 檢查/安裝 PM2 與 Nginx ---
echo ""
echo "📦 [3/5] 安裝 PM2 行程守護與 Nginx 反向代理..."
if ! command -v pm2 &> /dev/null; then
  npm install -g pm2
else
  echo "  → PM2 已就緒"
fi

if ! command -v nginx &> /dev/null; then
  apt install -y nginx
else
  echo "  → Nginx 已就緒"
fi

# --- 4. 防火牆規則設定 (80, 443) ---
echo ""
echo "🔥 [4/5] 檢查並開放 HTTP/HTTPS 防火牆 (Port 80/443)..."
if ! iptables -L INPUT -n | grep -q "dpt:80"; then
  iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80 -j ACCEPT
  echo "  → 已開放 Port 80"
fi
if ! iptables -L INPUT -n | grep -q "dpt:443"; then
  iptables -I INPUT 6 -m state --state NEW -p tcp --dport 443 -j ACCEPT
  echo "  → 已開放 Port 443"
fi

apt install -y netfilter-persistent iptables-persistent 2>/dev/null || true
netfilter-persistent save 2>/dev/null || true
echo "  → 防火牆設定完成"

# --- 5. 安裝 Certbot SSL 憑證工具 ---
echo ""
echo "📦 [5/5] 安裝 Certbot 自動 SSL 憑證管理工具..."
apt install -y certbot python3-certbot-nginx

echo ""
echo "======================================================"
echo "  🎉 基礎設施安裝完成！"
echo "======================================================"
echo ""
echo "👉 接下來只需 3 步驟啟動服務："
echo ""
echo "1. 啟動後端服務 (Port 3001)："
echo "   cd /home/ubuntu/chat-open/backend"
echo "   npm install"
echo "   pm2 start server.js --name chat-open-api"
echo "   pm2 save"
echo ""
echo "2. 設定 Nginx 轉發："
echo "   sudo cp nginx.conf /etc/nginx/sites-available/chat-open"
echo "   sudo nano /etc/nginx/sites-available/chat-open   # 把網域名稱換成你的 DuckDNS"
echo "   sudo ln -s /etc/nginx/sites-available/chat-open /etc/nginx/sites-enabled/"
echo "   sudo nginx -t && sudo systemctl reload nginx"
echo ""
echo "3. 取得免付費 HTTPS 證書："
echo "   sudo certbot --nginx -d 你的新網域.duckdns.org"
echo "======================================================"
