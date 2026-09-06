
// V6.3 SECURED - ads.js with DOMPurify and sanitization
// Load DOMPurify from CDN if not present
if (typeof DOMPurify === 'undefined') {
  const script = document.createElement('script');
  script.src = 'https://cdn.jsdelivr.net/npm/dompurify@3.0.6/dist/purify.min.js';
  document.head.appendChild(script);
}

async function fetchAds(placement, ownerId){
  let url='/api/ads?placement='+encodeURIComponent((placement||'').slice(0,50));
  if(ownerId && /^\d+$/.test(ownerId)){ url+='&owner_id='+encodeURIComponent(ownerId); }
  try{
    const res=await fetch(url);
    if (!res.ok) return [];
    const data=await res.json();
    return Array.isArray(data)?data:[];
  }catch(e){ console.error('fetchAds error',e); return []; }
}

function renderAd(ad, containerId){
  const container=document.getElementById(containerId);
  if(!container) return;
  if(!ad){ container.innerHTML='<span style="color:#666">لا يوجد إعلان</span>'; return; }
  
  let html='';
  // SECURITY: Only admin can have custom_html, and it's sanitized on backend + frontend
  if(ad.type==='custom_html' && ad.custom_html){
    let clean = ad.custom_html;
    if (typeof DOMPurify !== 'undefined') {
      clean = DOMPurify.sanitize(clean, {ALLOWED_TAGS: ['div','span','a','img','p','b','i','strong','br'], ALLOWED_ATTR: ['href','src','style','class']});
    } else {
      // Fallback: strip scripts
      clean = clean.replace(/<script[^>]*>.*?<\/script>/gi, '').replace(/on\w+\s*=/gi, '');
    }
    html=clean;
  } else if(ad.image_url){
    // SECURITY: Validate URLs
    const imgUrl = (ad.image_url.startsWith('/cdn/') || ad.image_url.startsWith('https://')) ? ad.image_url : '';
    const linkUrl = (ad.link_url && (ad.link_url.startsWith('https://') || ad.link_url.startsWith('/'))) ? ad.link_url : '#';
    if (!imgUrl) { container.innerHTML=''; return; }
    html='<a href="'+linkUrl.replace(/"/g,'')+'" target="_blank" rel="noopener noreferrer"><img src="'+imgUrl.replace(/"/g,'')+'" style="max-width:100%;border-radius:8px" loading="lazy"><p>'+(ad.title||'').replace(/[<>]/g,'')+'</p></a>';
  } else {
    html='<div><b>'+(ad.title||'إعلان').replace(/[<>]/g,'')+'</b></div>';
  }
  
  const badge = ad.owner_id ? '<span style="background:#22c55e;color:#fff;padding:2px 6px;border-radius:4px;font-size:10px;margin-left:6px">ناشر #'+String(ad.owner_id).replace(/\D/g,'')+'</span>' : '<span style="background:#ff6b00;color:#fff;padding:2px 6px;border-radius:4px;font-size:10px;margin-left:6px">منصة</span>';
  container.innerHTML=badge+html;
}

function loadAd(placement, containerId){ fetchAds(placement).then(ads=>{ if(ads[0]) renderAd(ads[0],containerId); }); }
