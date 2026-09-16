
// SECURED API - V6.3
const API_BASE = '';

function getToken() { return localStorage.getItem('token'); }

function handleAuthError(res) {
  if (res.status === 401) {
    localStorage.removeItem('token');
    if (!location.pathname.includes('login.html')) {
      alert('انتهت الجلسة - سجل دخول مرة أخرى');
      location.href = 'login.html';
    }
    return true;
  }
  return false;
}

async function apiGet(url){
  const token=getToken();
  const headers = {};
  if (token) headers['Authorization'] = 'Bearer ' + token;
  const res=await fetch(url,{headers});
  if (handleAuthError(res)) throw new Error('Unauthorized');
  const data = await res.json().catch(()=>({error:'Invalid JSON'}));
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}

async function apiPost(url,data){
  const token=getToken();
  const res=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:JSON.stringify(data)});
  if (handleAuthError(res)) throw new Error('Unauthorized');
  const result = await res.json().catch(()=>({error:'Invalid JSON'}));
  if (!res.ok) throw new Error(result.error || 'Request failed');
  return result;
}

async function apiDelete(url){
  const token=getToken();
  const res=await fetch(url,{method:'DELETE',headers:{'Authorization':'Bearer '+token}});
  if (handleAuthError(res)) throw new Error('Unauthorized');
  const result = await res.json().catch(()=>({error:'Invalid JSON'}));
  if (!res.ok) throw new Error(result.error || 'Request failed');
  return result;
}

async function apiPut(url,data){
  const token=getToken();
  const res=await fetch(url,{method:'PUT',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:JSON.stringify(data)});
  if (handleAuthError(res)) throw new Error('Unauthorized');
  const result = await res.json().catch(()=>({error:'Invalid JSON'}));
  if (!res.ok) throw new Error(result.error || 'Request failed');
  return result;
}

async function uploadFile(file){
  const token=getToken();
  if (!token) throw new Error('سجل دخول أولاً');
  
  // SECURITY: Client-side validation
  const MAX_BOOK = 50*1024*1024;
  const MAX_IMAGE = 5*1024*1024;
  const ALLOWED_BOOK = ['application/pdf','application/epub+zip'];
  const ALLOWED_IMG = ['image/jpeg','image/png','image/webp','image/jpg'];
  
  const isImage = ALLOWED_IMG.includes(file.type);
  const maxSize = isImage ? MAX_IMAGE : MAX_BOOK;
  if (file.size > maxSize) throw new Error(`الملف كبير جداً - الحد ${maxSize/1024/1024}MB`);
  if (file.size === 0) throw new Error('ملف فارغ');
  if (![...ALLOWED_BOOK, ...ALLOWED_IMG].includes(file.type)) {
    throw new Error(`نوع غير مسموح: ${file.type}`);
  }

  const fd=new FormData();
  fd.append('file',file);
  const res=await fetch('/api/upload',{method:'POST',headers:{'Authorization':'Bearer '+token},body:fd});
  if (handleAuthError(res)) throw new Error('Unauthorized');
  const data = await res.json().catch(()=>({error:'Upload failed'}));
  if (!res.ok) throw new Error(data.error || 'فشل الرفع');
  return data;
}

function sanitizeHTML(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[<>]/g, '').slice(0,5000);
}
