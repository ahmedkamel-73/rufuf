
export function init(){
  const grid=document.getElementById('books-grid');
  if(!grid) return;
  grid.innerHTML='<p>جاري التحميل...</p>';
  fetch('/api/books?page=1&limit=6').then(r=>r.json()).then(data=>{
    const books = data.books || data.data || [];
    grid.innerHTML=books.slice(0,6).map(b=>{
      const t=(b.title||'').replace(/[<>]/g,'').slice(0,80);
      const cover=b.cover_url||'';
      return `<div class="card"><img data-src="${cover}" src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 200 150'%3E%3Crect width='200' height='150' fill='%23111'/%3E%3C/svg%3E loading="lazy" alt=""><h4>${t}</h4><a href="reader.html?id=${b.id}">قراءة الآن</a></div>`;
    }).join('');
    document.querySelectorAll('img[data-src]').forEach(img=>{
      // trigger imgObserver if exists
      if(img.dataset.src) { img.src = img.dataset.src; }
    });
  }).catch(()=>{ grid.innerHTML='<p>فشل التحميل</p>'; window.toast && toast('فشل تحميل الكتب','error'); });
}
