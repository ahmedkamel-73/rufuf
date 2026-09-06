
// toast.js - بديل alert()
window.toast = function(msg, type='error'){
  let c = document.getElementById('toast-container');
  if(!c){ c=document.createElement('div'); c.id='toast-container'; document.body.appendChild(c); }
  const el=document.createElement('div');
  el.className='toast toast-'+type;
  el.textContent=msg;
  c.appendChild(el);
  setTimeout(()=>{ el.style.opacity='0'; el.style.transform='translateY(10px)'; setTimeout(()=>el.remove(),300); },3500);
};
// override alert
window._oldAlert = window.alert;
window.alert = function(m){ window.toast(m,'error'); };
