// V6.2 publisher.js
async function loadMyBooks(){
  try{
    const books=await apiGet('/api/books');
    const user=getUser();
    const myBooks=books.filter(b=>b.owner_id===user.id || user.role==='admin');
    document.getElementById('my-books').innerHTML=myBooks.map(b=>'<div class="card"><h4>'+b.title+'</h4><a href="reader.html?id='+b.id+'">عرض</a></div>').join('')||'<p>لم ترفع كتب بعد</p>';
  }catch(e){ console.error(e); }
}
async function loadMyArticles(){
  try{
    const arts=await apiGet('/api/articles');
    const user=getUser();
    const myArts=arts.filter(a=>a.author_id===user.id || user.role==='admin');
    const el=document.getElementById('my-articles');
    if(el) el.innerHTML=myArts.map(a=>'<div class="card"><h4>'+a.title+'</h4><a href="article.html?id='+a.id+'">عرض</a></div>').join('')||'<p>لم ترفع مقالات بعد - استخدم النموذج أعلاه ☝️</p>';
  }catch(e){ console.error(e); }
}
document.addEventListener('DOMContentLoaded', ()=>{ loadMyBooks(); loadMyArticles(); });
