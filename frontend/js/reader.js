// V6.2 REFINED - reader.js shows TWO ad slots: platform + publisher owner_id
document.addEventListener('DOMContentLoaded', async ()=>{
  const params=new URLSearchParams(location.search);
  const id=params.get('id');
  if(!id){ document.getElementById('book-title').textContent='لم يتم تحديد كتاب'; return; }
  try{
    const book=await fetch('/api/books/'+id).then(r=>r.json());
    if(book.error){ document.getElementById('book-title').textContent=book.error; return; }
    document.getElementById('book-title').textContent=book.title;
    document.getElementById('book-author').textContent=book.author||'';
    document.getElementById('book-desc').innerHTML='<p>'+(book.description||'').replace(/\n/g,'<br>')+'</p>';
    if(book.cover_url) document.getElementById('book-cover').src=book.cover_url;
    if(book.file_url) document.getElementById('book-file').innerHTML='<a href="'+book.file_url+'" target="_blank" style="background:#ff6b00;color:#fff;padding:10px 20px;border-radius:8px;text-decoration:none;display:inline-block;margin-top:10px">📄 تحميل/قراءة الكتاب</a>';

    // V6.2 REFINED: جلب إعلان المنصة + إعلان الناشر صاحب الكتاب
    // 1. إعلانات المنصة العامة (owner_id null)
    const platformAds=await fetchAds('reader');
    if(platformAds.length>0){ renderAd(platformAds[0],'ad-reader-platform'); if(platformAds[1]) renderAd(platformAds[1],'ad-sidebar-platform'); }
    else { document.getElementById('ad-reader-platform').innerHTML='<div class="ad-label">إعلان المنصة</div><span style="color:#666">لا يوجد إعلان منصة حاليا</span>'; }

    // 2. إعلانات الناشر صاحب الكتاب (owner_id = book.owner_id)
    if(book.owner_id){
      const publisherAds=await fetchAds('reader', book.owner_id);
      if(publisherAds.length>0){
        renderAd(publisherAds[0],'ad-reader-publisher');
        if(publisherAds[1]) renderAd(publisherAds[1],'ad-sidebar-publisher');
      } else {
        document.getElementById('ad-reader-publisher').innerHTML='<div class="ad-label">إعلان الناشر #'+book.owner_id+'</div><span style="color:#666">الناشر لم يضف إعلان reader بعد</span>';
        document.getElementById('ad-sidebar-publisher').innerHTML='<div class="ad-label">إعلان الناشر</div><span style="color:#666">لا يوجد إعلان ناشر</span>';
      }
    } else {
      document.getElementById('ad-reader-publisher').style.display='none';
      document.getElementById('ad-sidebar-publisher').style.display='none';
    }

  }catch(e){
    document.getElementById('book-title').textContent='خطأ: '+e.message;
  }
});
