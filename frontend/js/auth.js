function checkAuth(){ const token=localStorage.getItem('token'); if(!token) { if(!location.pathname.includes('login') && !location.pathname.includes('register') && !location.pathname.includes('index')) location.href='login.html'; } }
function getUser(){ try{ return JSON.parse(localStorage.getItem('user')||'{}'); }catch(e){ return {}; } }
function isAdmin(){ const u=getUser(); return u.role==='admin'; }
function isPublisher(){ const u=getUser(); return u.role==='publisher' || u.role==='admin'; }
checkAuth();
