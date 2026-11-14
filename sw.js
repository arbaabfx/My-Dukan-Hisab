/* My Dukan Hisab service worker: offline-first app shell. Bump VERSION on every deploy. */
const VERSION='ds-v25',SHELL=['./','./index.html','./manifest.json','./icon-192.png','./icon-512.png','./maskable-512.png','./apple-touch-icon.png','./favicon-32.png','./fonts/inter-Regular.woff','./fonts/inter-SemiBold.woff','./fonts/inter-Bold.woff'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(VERSION).then(c=>Promise.all(SHELL.map(u=>c.add(u).catch(()=>{})))).then(()=>self.skipWaiting()))});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==VERSION).map(x=>caches.delete(x)))).then(()=>self.clients.claim()))});
self.addEventListener('message',e=>{if(e.data==='SKIP_WAITING')self.skipWaiting()});
self.addEventListener('fetch',e=>{
  const r=e.request,u=new URL(r.url);
  if(r.method!=='GET'||u.origin!==location.origin)return;           // APIs (OpenFoodFacts, Gemini) always go straight to network
  if(r.mode==='navigate'&&(u.pathname.endsWith('/')||u.pathname.endsWith('/index.html'))){                                           // open instantly from cache, refresh in background
    e.respondWith(caches.match('./index.html').then(c=>{const net=fetch(r).then(res=>{if(res.ok){const cp=res.clone();caches.open(VERSION).then(x=>x.put('./index.html',cp))}return res}).catch(()=>c);return c||net}));
    return}
  e.respondWith(caches.match(r,{ignoreSearch:true}).then(c=>{const net=fetch(r).then(res=>{if(res.ok){const cp=res.clone();caches.open(VERSION).then(x=>x.put(r,cp))}return res}).catch(()=>c);return c||net}))});
