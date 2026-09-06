
# TESTING.md - رفوف V7

## تشغيل الاختبارات
```bash
npm install
npm run test
```

## إصلاحات V7
1. Hero Section: موجود في index.html class hero-new
2. UI Cards: border-radius 16px + hover lift + shadow
3. Alert -> Toast: js/toast.js يلغي alert()
4. Mobile: جداول تتحول كروت + أزرار 44px
5. Worker مقسم: middleware/rateLimit.js + routes/push.js + src/index.js (أقل من 400 سطر منطقي)
6. Sitemap.xml: /sitemap.xml + /frontend/sitemap.xml
7. PushKit حقيقي: /sw.js + /api/push/subscribe + manifest.json
8. Lazy Loading: IntersectionObserver + loading="lazy"
9. API: Rate Limiting 30 req/min + Pagination مع total و hasMore
10. Tests: tests/api.test.js

## اختبار يدوي
- افتح على موبايل: الجدول كروت
- افتح console: لا يوجد alert()
- /sitemap.xml يعمل
- فعل الإشعارات من الكونسول: subscribePush()
