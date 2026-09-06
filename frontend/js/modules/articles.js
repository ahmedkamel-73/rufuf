
export function init(){
  const grid=document.getElementById('articles-grid');
  if(!grid) return;
  fetch('/api/articles?page=1&limit=6').then(r=>r.json()).then(data=>{
    const arts = data.articles || data.data || [];
    grid.innerHTML=arts.slice(0,6).map(a=>{
      const t=(a.title||'').replace(/[<>]/g,'').slice(0,80);
      return `<div class="card"><h4>${t}</h4><a href="article.html?id=${a.id}">قراءة</a></div>`;
    }).join('');
  });
}
