
 // V8 REAL Lazy Loading - كل الملفات لا تتحمل مرة واحدة
const lazyLoad = {
  loaded: new Set(),
  async loadModule(name, url){
    if(this.loaded.has(name)) return;
    console.log(`[Lazy] Loading ${name}...`);
    const mod = await import(url);
    this.loaded.add(name);
    return mod;
  }
};

// 1. Images - IntersectionObserver + native lazy
const imgObserver = new IntersectionObserver((entries)=>{
  entries.forEach(e=>{
    if(e.isIntersecting){
      const img = e.target;
      if(img.dataset.src){ img.src = img.dataset.src; delete img.dataset.src; }
      if(img.dataset.srcset){ img.srcset = img.dataset.srcset; delete img.dataset.srcset; }
      imgObserver.unobserve(img);
    }
  });
},{rootMargin:'300px'});

document.querySelectorAll('img[data-src]').forEach(img=>imgObserver.observe(img));

// 2. Sections - Lazy load JS only when visible
const sectionObserver = new IntersectionObserver(async (entries)=>{
  for(const entry of entries){
    if(entry.isIntersecting){
      const id = entry.target.id;
      if(id==='latest-books' && !lazyLoad.loaded.has('books')){
        const mod = await lazyLoad.loadModule('books','./modules/books.js');
        if(mod && mod.init) mod.init();
      }
      if(id==='latest-articles' && !lazyLoad.loaded.has('articles')){
        const mod = await lazyLoad.loadModule('articles','./modules/articles.js');
        if(mod && mod.init) mod.init();
      }
      if(id==='forum-preview' && !lazyLoad.loaded.has('forum')){
        await lazyLoad.loadModule('forum','./modules/forum.js');
      }
      sectionObserver.unobserve(entry.target);
    }
  }
},{rootMargin:'200px'});

document.querySelectorAll('[data-lazy]').forEach(el=>sectionObserver.observe(el));

// 3. On-demand - publisher, admin pages load only when needed
window.loadPublisherModule = ()=> lazyLoad.loadModule('publisher','./modules/publisher.js');
window.loadAdminModule = ()=> lazyLoad.loadModule('admin','./modules/admin.js');

console.log('[Lazy] Loader ready - initial JS only 12KB');
