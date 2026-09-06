# رفوف V6.2 FINAL REFINED - 3 تعديلات نهائية

## التعديلات المطلوبة - تم تنفيذها 100%

### 1. رفع المقالات من داخل لوحة الناشر (مش صفحة منفصلة)
- **المطلوب**: زر رفع مقال جوه publisher.html
- **التنفيذ V6.2**: 
  - في publisher.html تمت إضافة section id="article-upload-inline" بعنوان 📝 رفع مقال جديد
  - يحتوي: title, content textarea, cover file, button رفع المقال
  - يستدعي uploadFile -> /api/upload ثم POST /api/articles
  - تم إزالة رابط التنقل المنفصل لـ upload-article.html (لكن الملف موجود fallback)
  - publisher.html الآن فيها رفع كتاب + رفع مقال inline

### 2. طلب انضمام كناشر - admin approval that changes role
- **المطلوب**: الأدمن يشوف الطلبات ويوافق/يرفض ويتحول دور المستخدم
- **التنفيذ V6.2**:
  - admin.html فيها قسم publisher_requests مع عرض user_id, name, reason, samples, status
  - أزرار approve/reject تستدعي PUT /api/publisher-requests/:id
  - في worker/src/index.js:
    ```js
    await DB.prepare("UPDATE publisher_requests SET status=? WHERE id=?").bind(status,id).run()
    if(status==='approved'){
      await DB.prepare("UPDATE users SET role='publisher', is_publisher=1 WHERE id=(SELECT user_id FROM publisher_requests WHERE id=?)").bind(id).run()
    }
    ```
  - join-publisher.html موجود كنموذج تقديم

### 3. إعلانات الناشر تظهر في صفحة القارئ (reader.html)
- **المطلوب**: إعلان المنصة + إعلان الناشر صاحب الكتاب
- **التنفيذ V6.2**:
  - reader.html الآن فيها TWO ad slots: ad-reader-platform و ad-reader-publisher
  - JS: بعد تحميل الكتاب (book.owner_id) يتم:
    - fetch platform ads: /api/ads?placement=reader (بدون owner)
    - fetch publisher ads: /api/ads?placement=reader&owner_id=book.owner_id
  - js/ads.js يدعم owner_id param و renderAd يتعامل مع custom_html و image_link
  - admin-ads.html و publisher-ads.html تدعم placement reader

## التثبيت الأوتوماتيك 7 خطوات
```bash
chmod +x setup.sh
./setup.sh
```

## تسجيل دخول أدمن
rufuf@pages.dev / 132000aA*

## الملفات 28 ملف
- setup.sh, wrangler.toml, migrations, worker, frontend 22 file, README

V6.2 FINAL REFINED جاهز 100%
