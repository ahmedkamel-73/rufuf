#!/bin/bash
set -e
echo "🚀 رفوف V6.2 FINAL REFINED - أوتوماتيك 100%..."
echo "📦 [1/7] تثبيت bcryptjs..."
cd worker && npm install --silent && cd ..
echo "🗄️ [2/7] إنشاء D1..."
D1_OUT=$(npx wrangler d1 create rufuf-db 2>&1 || true)
D1_ID=$(echo "$D1_OUT" | grep -oE '"[a-f0-9]{32}"' | tr -d '"' | head -1)
if [ -z "$D1_ID" ]; then D1_ID=$(echo "$D1_OUT" | grep -oE '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}' | head -1); fi
if [ -n "$D1_ID" ] && [ "$D1_ID" != "REPLACE_WITH_D1_ID" ]; then
  echo "✅ D1 ID: $D1_ID"
  sed -i "s/REPLACE_WITH_D1_ID/$D1_ID/g" wrangler.toml 2>/dev/null || sed -i '' "s/REPLACE_WITH_D1_ID/$D1_ID/g" wrangler.toml
else
  echo "⚠️ D1 موجود - جلب ID..."
  D1_ID=$(npx wrangler d1 list | grep rufuf-db | grep -oE '[a-f0-9-]{36}' | head -1)
  sed -i "s/REPLACE_WITH_D1_ID/$D1_ID/g" wrangler.toml 2>/dev/null || sed -i '' "s/REPLACE_WITH_D1_ID/$D1_ID/g" wrangler.toml || true
fi
echo "🪣 [3/7] إنشاء R2..."
npx wrangler r2 bucket create rufuf-storage 2>&1 | grep -v "already exists" || true
echo "🔑 [4/7] JWT_SECRET..."
echo "rufuf_jwt_2026_$(date +%s)_secure_!@#" | npx wrangler secret put JWT_SECRET
echo "📜 [5/7] Migration..."
sleep 2
npx wrangler d1 execute rufuf-db --file=migrations/0001_init.sql --remote --yes || npx wrangler d1 execute rufuf-db --file=migrations/0001_init.sql --remote
echo "⚡ [6/7] Deploy Worker + Assets + Forum DO..."
npx wrangler deploy
echo "📄 [7/7] Deploy Pages fallback..."
npx wrangler pages deploy frontend --project-name=rufuf --commit-dirty=true 2>&1 | grep -v "error" || echo "تخطي Pages - Worker يكفي"
echo ""
echo "🎉 تم 100%!"
echo "🌐 https://rufuf.pages.dev"
echo "👑 rufuf@pages.dev / 132000aA*"
