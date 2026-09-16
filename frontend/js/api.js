// SECURED API - V10.1 FIXED - images fix
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
  
  // FIXED V10.1: Accept any image/* (jpeg, png, webp, gif, avif, heic) + pdf/epub
  const MAX_BOOK = 50*1024*1024;
  const MAX_IMAGE = 5*1024*1024;
  
  const fileType = (file.type || '').toLowerCase();
  const fileName = (file.name || '').toLowerCase();
  
  const isImage = fileType.startsWith('image/') || /\.(jpg|jpeg|png|webp|gif|avif|heic|heif)$/.test(fileName);
  const isBook = fileType.includes('pdf') || fileType.includes('epub') || /\.(pdf|epub)$/.test(fileName) || fileType === 'application/octet-stream';
  
  const maxSize = isImage ? MAX_IMAGE : MAX_BOOK;
  if (file.size > maxSize) throw new Error(`الملف كبير جداً - الحد ${maxSize/1024/1024}MB - حجم ملفك ${(file.size/1024/1024).toFixed(1)}MB`);
  if (file.size === 0) throw new Error('ملف فارغ');
  
  if (!isImage && !isBook) {
    throw new Error(`نوع غير مسموح: ${file.type || file.name} - المسموح: صور و PDF/EPUB فقط`);
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
