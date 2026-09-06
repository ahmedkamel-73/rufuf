function getToken(){ return localStorage.getItem('token'); }
function getUser(){ try{ return JSON.parse(localStorage.getItem('user')||'null'); }catch(e){ return null; } }
function isLoggedIn(){ return !!getToken() && !!getUser(); }
function isAdmin(){ const u=getUser(); return u && u.role==='admin'; }
function isPublisher(){ const u=getUser(); return u && (u.role==='publisher' || u.role==='admin'); }

function logout(){
  localStorage.removeItem('token');
  localStorage.removeItem('user');
  location.href='login.html';
}

function updateHeader(){
  const user = getUser();
  const nav = document.querySelector('header nav');
  if(!nav) return;
  
  if(user && user.email){
    // User is logged in - show profile and logout
    nav.innerHTML = `
      <a href="books.html">الكتب</a>
      <a href="articles.html">المقالات</a>
      <a href="profile.html" style="background:#ff6b00;color:#fff;padding:6px 12px;border-radius:20px;">👤 ${user.email.split('@')[0]}</a>
      <a href="#" onclick="logout();return false;" style="color:#ff4444;">خروج</a>
      ${user.role==='admin' ? '<a href="admin.html" style="background:#7c3aed;color:#fff;padding:6px 12px;border-radius:20px;">لوحة الأدمن</a>' : ''}
      ${user.role==='publisher' ? '<a href="publisher.html" style="background:#059669;color:#fff;padding:6px 12px;border-radius:20px;">لوحة الناشر</a>' : ''}
    `;
  } else {
    // Not logged in
    nav.innerHTML = `
      <a href="books.html">الكتب</a>
      <a href="articles.html">المقالات</a>
      <a href="login.html">دخول</a>
      <a href="register.html" style="background:#ff6b00;color:#fff;padding:6px 12px;border-radius:20px;">سجل مجاناً</a>
    `;
  }
}

function checkAuth(){
  // Only protect pages that require login
  const protectedPages = ['admin.html', 'publisher.html', 'upload-book.html', 'upload-article.html', 'profile.html'];
  const currentPage = location.pathname.split('/').pop() || 'index.html';
  
  if(protectedPages.includes(currentPage) && !isLoggedIn()){
    location.href='login.html';
  }
}

// Run on every page
document.addEventListener('DOMContentLoaded', ()=>{
  updateHeader();
  checkAuth();
  
  // Show welcome toast if just logged in
  const user = getUser();
  if(user && document.getElementById('toast-container')){
    const urlParams = new URLSearchParams(location.search);
    if(urlParams.get('login')==='success'){
      if(typeof showToast==='function'){
        showToast(`أهلاً ${user.email} - تم تسجيل الدخول بنجاح!`, 'success');
      }
      // Remove param from URL
      history.replaceState({}, '', location.pathname);
    }
  }
});
