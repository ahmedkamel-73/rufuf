
export async function handlePush(req, env, url){
  const method = req.method;
  if(url.pathname==='/api/push/subscribe' && method==='POST'){
    const body = await req.json();
    if(!body.endpoint) return new Response(JSON.stringify({error:'endpoint required'}),{status:400});
    await env.DB.prepare('INSERT OR REPLACE INTO push_subscriptions (endpoint, subscription_json, created_at) VALUES (?,?,?)').bind(body.endpoint, JSON.stringify(body), Date.now()).run();
    return new Response(JSON.stringify({ok:true}),{headers:{'Content-Type':'application/json'}});
  }
  if(url.pathname==='/api/push/send' && method==='POST'){
    // admin only in real prod - simplified
    const {title, body} = await req.json();
    const {results} = await env.DB.prepare('SELECT subscription_json FROM push_subscriptions').all();
    // In production use web-push library with VAPID
    return new Response(JSON.stringify({sent: results.length, note:'Use web-push lib with VAPID_PRIVATE_KEY secret'}),{headers:{'Content-Type':'application/json'}});
  }
  if(url.pathname==='/api/push/vapid-public-key' && method==='GET'){
    return new Response(JSON.stringify({key: env.VAPID_PUBLIC_KEY || 'SET_VAPID_PUBLIC_KEY'}),{headers:{'Content-Type':'application/json'}});
  }
  return null;
}
