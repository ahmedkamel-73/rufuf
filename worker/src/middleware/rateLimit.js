
export async function checkRateLimit(ip, env, max=30){
  const now = Date.now();
  const windowStart = now - 60000;
  try{
    const row = await env.DB.prepare('SELECT count, window_start FROM rate_limits WHERE ip=?').bind(ip).first();
    if(!row){ await env.DB.prepare('INSERT INTO rate_limits (ip,count,window_start) VALUES (?,?,?)').bind(ip,1,now).run(); return true; }
    if(row.window_start < windowStart){ await env.DB.prepare('UPDATE rate_limits SET count=1, window_start=? WHERE ip=?').bind(now,ip).run(); return true; }
    if(row.count >= max) return false;
    await env.DB.prepare('UPDATE rate_limits SET count=count+1 WHERE ip=?').bind(ip).run();
    return true;
  }catch{ return true; }
}
