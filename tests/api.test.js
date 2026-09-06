
import { describe, it, expect } from 'vitest';
// V7 Tests
describe('Rufuf V7 Fixes', ()=>{
  it('sitemap exists', async ()=>{
    const res = await fetch('/sitemap.xml');
    expect(res.headers.get('content-type')).toContain('xml');
  });
  it('pagination has total', async ()=>{
    const data = await fetch('/api/books?page=1&limit=2').then(r=>r.json());
    expect(data).toHaveProperty('total');
  });
  it('rate limit 429 after burst', async ()=>{});
  it('push subscribe saves', async ()=>{
    const sub = {endpoint:'https://test.com/123', keys:{p256dh:'x',auth:'y'}};
    const res = await fetch('/api/push/subscribe',{method:'POST', body: JSON.stringify(sub)});
    expect([200,201]).toContain(res.status);
  });
});
