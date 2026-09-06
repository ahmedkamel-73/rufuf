# 📚 رفوف - منصة نشر رقمية ذكية

> منصة عربية متكاملة للقراءة والنشر، بتصميم عصري، أداء فائق، وتجربة PWA كاملة.

![Version](https://img.shields.io/badge/version-9.0-orange)
![PWA](https://img.shields.io/badge/PWA-ready-success)
![License](https://img.shields.io/badge/license-MIT-blue)

---

## ✨ الفكرة

**رفوف** هي مكتبة رقمية تربط بين القراء والناشرين العرب في مكان واحد:
- القارئ يجد آلاف الكتب والمقالات المجانية
- الناشر ينشر أعماله ويربح من إعلاناته الخاصة
- المنصة تعمل بسرعة عالية، بدون إنترنت، مع إشعارات فورية

لا يوجد بيع كتب ولا بوابات دفع - التركيز على المحتوى والمجتمع.

---

## 🚀 المميزات الرئيسية

### للقراء
- 📖 قراءة فورية للكتب (PDF/EPUB) والمقالات
- 🔍 بحث وفلترة حسب التصنيف
- 📊 تتبع تقدم القراءة وعدد القراءات
- 💬 منتدى نقاشي مباشر (Durable Objects)
- 📱 يعمل بدون إنترنت (PWA)

### للناشرين
- 📤 رفع الكتب والمقالات من لوحة واحدة
- 💰 نظام إعلانات خاص بكل ناشر (يظهر فقط في كتبه)
- 📈 إحصائيات القراءات
- ✅ طلب انضمام كناشر بموافقة الأدمن

### للإدارة
- 👥 إدارة طلبات الناشرين (قبول/رفض)
- 📢 إدارة إعلانات المنصة
- 📚 إدارة المحتوى والمستخدمين

---

## 🎨 التصميم - V9 Ultimate

### Hero Section جذاب
- خلفية بثلاث طبقات Glow متحركة بتأثير blur
- عنوان كبير 64px بخط 900 و Gradient برتقالي
- 3D Stack - ثلاث كروت فوق بعض بتأثير `rotateY` و `translateZ`
- Live Indicator أخضر ينبض + Floating Badges
- Responsive كامل - يتحول لعمود واحد على الموبايل

### UI Cards احترافية
- `border-radius: 16px` + `hover lift -4px`
- ظلال متعددة الطبقات + border برتقالي عند الـ Hover
- صور بزوايا دائرية و Skeleton Loading

### Mobile First
- الجداول تتحول لـ Cards مع `data-label`
- كل الأزرار `min-height: 44px` (معيار Apple/Google)
- Grid يتكيف: 4 أعمدة → 2 → 1

---

## ⚡ الأداء - Lazy Loading حقيقي

### المشكلة القديمة
كل ملفات JS كانت تتحمل مرة واحدة (~80KB)

### الحل V9
- **Initial Bundle: 3KB فقط** (toast + inline loader)
- **IntersectionObserver** يحمل الأقسام فقط عند الاقتراب 400px
- **Dynamic import()** للكتب والمقالات
- **Images:** `data-src` + `loading="lazy"` + placeholder SVG
- **Modules:** `publisher.js` و `admin.js` لا يتم تحميلهم إلا عند دخول الصفحة

```
Network Tab:
0ms    → index.html + style.css + loader (15KB)
+400px → books.js (lazy)
+400px → articles.js (lazy)
```

---

## 🔔 PushKit & PWA - إشعارات فورية حقيقية

- **Service Worker** كامل: `install`, `activate`, `push`, `notificationclick`
- **API:** `/api/push/subscribe` يحفظ في D1
- **VAPID:** نظام مفاتيح عام/خاص
- **Manifest:** `theme_color #ff6b00`, `display standalone`
- **Offline:** Cache للصفحات مع fallback

---

## 🔒 الأمان

- JWT قوي (HS256) + Secret 32+ حرف
- Rate Limiting: 30 طلب/دقيقة عام، 5 للـ Login
- تحقق من حجم ونوع الملفات (PDF 50MB, صور 5MB)
- تنقية HTML من `<script>` و `javascript:`
- Headers: `X-Content-Type-Options`, `X-Frame-Options`, `CSP`
- منع `..` و `.env` في المسارات

---

## 🗂️ هيكلة المشروع (نظيفة 100%)

```
/
├── frontend/              # الواجهة - 18 ملف فقط، بدون مكررات
│   ├── index.html         # Hero V9 Ultimate + Lazy
│   ├── css/style.css      # تصميم واحد احترافي
│   ├── js/
│   │   ├── toast.js       # بديل alert()
│   │   ├── loader.js      # Lazy Loading Engine
│   │   ├── modules/       # وحدات تحمل عند الطلب
│   │   │   ├── books.js
│   │   │   └── articles.js
│   │   ├── api.js
│   │   ├── auth.js
│   │   └── ads.js
│   ├── manifest.json
│   ├── sw.js
│   └── sitemap.xml
├── worker/
│   └── src/
│       ├── index.js       # Router رئيسي (<400 سطر)
│       ├── middleware/
│       │   └── rateLimit.js
│       └── routes/
│           └── push.js    # منطق الإشعارات
├── migrations/
│   ├── 0001_init.sql
│   └── 0002_pushkit_pwa.sql
├── tests/                 # 32 اختبار - 100% Coverage
│   ├── api.test.js
│   ├── e2e.test.js
│   └── setup.js
├── vitest.config.js
├── wrangler.toml
└── README.md              # هذا الملف
```

**تم حذف:** `index_1.html`, `style_1.css`, `api_1.js` وكل المكررات.

---

## 🧪 الاختبارات - 100%

```bash
npm run test        # كل الاختبارات (32 test)
npm run test:watch  # مراقبة
```

**ما يتم اختباره:**
- API: pagination, limit cap, total, hasMore
- Rate Limit: 30 عام، 5 للـ login، reset بعد 60s
- Push: subscribe, vapid key, sw.js events
- UI: toast يلغي alert
- SEO: sitemap.xml valid, manifest theme_color
- Lazy: loader exists, data-src, dynamic import
- Mobile: media queries, data-label, 44px
- Worker Split: middleware + routes
- E2E: تصفح بدون login, طلب ناشر, عزل الإعلانات
- Security: path traversal, JWT length, sanitize

---

## 🛠️ التثبيت والتشغيل

### المتطلبات
- Node.js 18+
- Cloudflare Wrangler
- D1 Database + R2 Bucket

### الخطوات
```bash
# 1. تثبيت Wrangler
npm install -g wrangler

# 2. تسجيل دخول
wrangler login

# 3. إنشاء قاعدة البيانات
wrangler d1 create rufuf-db
# انسخ الـ ID إلى wrangler.toml

# 4. تطبيق الـ Migrations
wrangler d1 execute rufuf-db --file=migrations/0001_init.sql
wrangler d1 execute rufuf-db --file=migrations/0002_pushkit_pwa.sql

# 5. إنشاء R2
wrangler r2 bucket create rufuf-storage

# 6. ضبط المتغيرات السرية
wrangler secret put JWT_SECRET
wrangler secret put VAPID_PRIVATE_KEY

# 7. تشغيل محلي
wrangler dev

# 8. رفع للإنتاج
wrangler deploy
```

---

## 🌐 SEO

- **Sitemap.xml:** `/sitemap.xml` ديناميكي + ثابت
- **Meta:** description, theme-color, Open Graph
- **Performance:** Lazy Loading, preload CSS, defer JS
- **PWA:** قابل للتثبيت على الموبايل

---

## 📦 التقنيات

- **Frontend:** HTML5, CSS3 (Grid, 3D, Animations), Vanilla JS (ES Modules)
- **Backend:** Cloudflare Workers, Hono
- **DB:** Cloudflare D1 (SQLite)
- **Storage:** Cloudflare R2
- **Realtime:** Durable Objects (Forum)
- **Tests:** Vitest
- **PWA:** Service Worker + Web Push (VAPID)

---

## 📄 الترخيص

MIT - مفتوح للاستخدام والتطوير.

---

## 🤝 المساهمة

مرحب بالمساهمات! افتح Issue أو Pull Request.

---

**رفوف V9 - نظيف، سريع، جذاب. جاهز للإنتاج.** 🚀
