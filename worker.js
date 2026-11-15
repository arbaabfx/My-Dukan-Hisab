/* My Dukan Hisab: login + plan server (Cloudflare Worker + D1).
   Stores only: email, trial start date, plan and plan expiry. No shop, bill or customer data. */
const DAY=864e5, TRIAL_DAYS=14;
const b64u=b=>{let s='';new Uint8Array(b).forEach(x=>s+=String.fromCharCode(x));return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')};
const enc=s=>new TextEncoder().encode(s);
const J=(o,s=200,h={})=>new Response(JSON.stringify(o),{status:s,headers:{'content-type':'application/json','cache-control':'no-store',...h}});
const EMAIL=/^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,24}$/;
let ready=false,keyCache=null;

async function init(env){
  if(ready)return;
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS users(email TEXT PRIMARY KEY, created INTEGER, trial_start INTEGER, plan TEXT DEFAULT '', plan_exp INTEGER DEFAULT 0, last_login INTEGER, logins INTEGER DEFAULT 0)`).run();
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT)').run();
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS rl(k TEXT PRIMARY KEY, n INTEGER, w INTEGER)').run();
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS gone(h TEXT PRIMARY KEY, trial_start INTEGER)').run();
  ready=true;
}
/* The signing key is created once, on first use, and lives only in your own D1 database. */
async function keys(env){
  if(keyCache)return keyCache;
  let j=null;
  if(env.SIGN_JWK){try{const t=JSON.parse(env.SIGN_JWK);if(t&&t.priv&&t.pub)j=t}catch{}}   /* preferred: private key lives in a Cloudflare secret */
  let row=j?null:await env.DB.prepare("SELECT v FROM kv WHERE k='sign'").first();
  if(j){}
  else if(row)j=JSON.parse(row.v);
  else{
    const kp=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
    j={priv:await crypto.subtle.exportKey('jwk',kp.privateKey),pub:await crypto.subtle.exportKey('jwk',kp.publicKey)};
    await env.DB.prepare("INSERT OR IGNORE INTO kv(k,v) VALUES('sign',?)").bind(JSON.stringify(j)).run();
    row=await env.DB.prepare("SELECT v FROM kv WHERE k='sign'").first();j=JSON.parse(row.v);
  }
  keyCache={pub:j.pub,priv:await crypto.subtle.importKey('jwk',j.priv,{name:'ECDSA',namedCurve:'P-256'},false,['sign'])};
  return keyCache;
}
/* Deleted accounts keep ONLY a salted hash + the original trial start, so delete-and-login can not give a new free trial. The plain email is never stored here. */
async function emailHash(env,email){const d=await crypto.subtle.digest('SHA-256',enc((env.PEPPER||'')+'|'+email));return b64u(new Uint8Array(d))}
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function sign(env,u){
  const k=await keys(env),now=Date.now();
  const p=b64u(enc(JSON.stringify({pr:'dukan',em:u.email,pl:u.plan||'',ts:u.trial_start,ex:u.plan_exp||0,iat:now,exp:now+90*DAY})));
  const s=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},k.priv,enc(p));
  return{tok:'DS1.'+p+'.'+b64u(s),pub:k.pub};
}
function cors(req,env){
  const o=req.headers.get('Origin')||'',ok=String(env.ORIGINS||'').split(',').map(x=>x.trim()).filter(Boolean);
  return ok.includes(o)?{'access-control-allow-origin':o,'vary':'Origin','access-control-allow-headers':'content-type,x-admin','access-control-allow-methods':'GET,POST,OPTIONS','access-control-max-age':'86400'}:{};
}
function same(a,b){a=String(a||'');b=String(b||'');if(!b||a.length!==b.length)return false;let r=0;for(let i=0;i<a.length;i++)r|=a.charCodeAt(i)^b.charCodeAt(i);return r===0}
/* simple per-IP rate limit kept in D1: max `lim` calls per `win` ms per bucket */
async function limited(req,env,bucket,lim,win){
  const ip=req.headers.get('CF-Connecting-IP')||'x',k=bucket+':'+ip,now=Date.now();
  if(Math.random()<0.02)await env.DB.prepare('DELETE FROM rl WHERE w<?').bind(now-DAY).run();   /* tidy: drop rate-limit rows older than 1 day (about once per 50 calls) */
  const r=await env.DB.prepare('SELECT n,w FROM rl WHERE k=?').bind(k).first();
  if(!r||now-r.w>win){await env.DB.prepare('INSERT OR REPLACE INTO rl(k,n,w) VALUES(?,?,?)').bind(k,1,now).run();return false}
  if(r.n>=lim)return true;
  await env.DB.prepare('UPDATE rl SET n=n+1 WHERE k=?').bind(k).run();return false;
}
/* verify a Google access token for THIS app and return the verified email (or an error Response) */
async function googleEmail(env,t){
  let g;try{const r=await fetch('https://oauth2.googleapis.com/tokeninfo?access_token='+encodeURIComponent(t));if(!r.ok)return{err:J({error:'google_rejected'},401)};g=await r.json()}catch{return{err:J({error:'google_unreachable'},502)}}
  if(!env.GCID||(g.aud!==env.GCID&&g.azp!==env.GCID))return{err:J({error:'wrong_client'},401)};
  if(!(+g.expires_in>0))return{err:J({error:'token_expired'},401)};
  const email=String(g.email||'').toLowerCase();
  if(!(g.email_verified===true||g.email_verified==='true')||!EMAIL.test(email))return{err:J({error:'email_not_verified'},401)};
  return{email};
}
const pub=u=>({email:u.email,plan:u.plan||'',plan_exp:u.plan_exp||0,trial_start:u.trial_start,created:u.created,last_login:u.last_login,logins:u.logins});

async function auth(req,env){
  if(await limited(req,env,'auth',30,10*60e3))return J({error:'too_many'},429);
  let b;try{b=await req.json()}catch{return J({error:'bad_json'},400)}
  const t=String(b&&b.token||'');if(t.length<20||t.length>4096)return J({error:'bad_token'},400);
  const g=await googleEmail(env,t);if(g.err)return g.err;const email=g.email;
  const now=Date.now();
  let u=await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(email).first();
  if(!u){const g0=await env.DB.prepare('SELECT trial_start FROM gone WHERE h=?').bind(await emailHash(env,email)).first(),ts=g0&&g0.trial_start?g0.trial_start:now;await env.DB.prepare('INSERT OR IGNORE INTO users(email,created,trial_start,last_login,logins) VALUES(?,?,?,?,1)').bind(email,now,ts,now).run();u=await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(email).first()}
  else{await env.DB.prepare('UPDATE users SET last_login=?,logins=logins+1 WHERE email=?').bind(now,email).run();u.last_login=now;u.logins=(u.logins||0)+1}
  const s=await sign(env,u);
  return J({tok:s.tok,pub:s.pub,now,trial_days:TRIAL_DAYS,user:pub(u)});
}
/* Play Store account-deletion: user re-authenticates with Google, then ALL server data for that email is erased */
async function delAccount(req,env){
  if(await limited(req,env,'del',10,10*60e3))return J({error:'too_many'},429);
  let b;try{b=await req.json()}catch{return J({error:'bad_json'},400)}
  const t=String(b&&b.token||'');if(t.length<20||t.length>4096)return J({error:'bad_token'},400);
  const g=await googleEmail(env,t);if(g.err)return g.err;
  const old=await env.DB.prepare('SELECT trial_start FROM users WHERE email=?').bind(g.email).first();
  if(old&&old.trial_start)await env.DB.prepare('INSERT OR REPLACE INTO gone(h,trial_start) VALUES(?,?)').bind(await emailHash(env,g.email),old.trial_start).run();
  await env.DB.prepare('DELETE FROM users WHERE email=?').bind(g.email).run();
  return J({ok:true});
}
async function admin(req,env,path){
  if(await limited(req,env,'adm',30,10*60e3))return J({error:'too_many'},429);
  if(!same(req.headers.get('x-admin'),env.ADMIN_KEY)){await sleep(700);return J({error:'forbidden'},403)}
  const now0=Date.now(),paidSql="(plan='l' OR (plan!='' AND plan_exp>"+now0+"))";
  if(path==='/admin/stats'){
    const c=async q=>(await env.DB.prepare(q).first()).c,ex=await env.DB.prepare("SELECT * FROM users WHERE plan IN ('m','y') AND plan_exp>? AND plan_exp<? ORDER BY plan_exp LIMIT 100").bind(now0,now0+7*DAY).all();
    return J({total:await c('SELECT COUNT(*) c FROM users'),paid:await c('SELECT COUNT(*) c FROM users WHERE '+paidSql),trials_today:await c('SELECT COUNT(*) c FROM users WHERE created>'+(now0-DAY)),expiring7:(ex.results||[]).map(pub)});
  }
  if(path==='/admin/search'){
    const q=String(new URL(req.url).searchParams.get('q')||'').trim().toLowerCase().replace(/[%_\\]/g,'');if(q.length<2||q.length>64)return J({error:'bad_query'},400);
    const r=await env.DB.prepare('SELECT * FROM users WHERE email LIKE ? ORDER BY last_login DESC LIMIT 20').bind('%'+q+'%').all();return J({users:(r.results||[]).map(pub)});
  }
  if(path==='/admin/recent'){const r=await env.DB.prepare('SELECT * FROM users ORDER BY last_login DESC LIMIT 50').all();return J({users:(r.results||[]).map(pub),total:(await env.DB.prepare('SELECT COUNT(*) c FROM users').first()).c})}
  let b={};if(req.method==='POST'){try{b=await req.json()}catch{return J({error:'bad_json'},400)}}
  const url=new URL(req.url),email=String(b.email||url.searchParams.get('email')||'').trim().toLowerCase();
  if(!EMAIL.test(email))return J({error:'bad_email'},400);
  const now=Date.now();
  let u=await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(email).first();
  if(path==='/admin/user')return u?J({user:pub(u)}):J({error:'not_found'},404);
  if(path==='/admin/revoke'){if(!u)return J({error:'not_found'},404);await env.DB.prepare("UPDATE users SET plan='',plan_exp=0 WHERE email=?").bind(email).run();return J({ok:true})}
  if(path==='/admin/grant'){
    const pl=String(b.plan||'');if(!['m','y','l'].includes(pl))return J({error:'bad_plan'},400);
    if(!u){await env.DB.prepare('INSERT INTO users(email,created,trial_start,last_login,logins) VALUES(?,?,?,?,0)').bind(email,now,now,0).run();u={email,plan:'',plan_exp:0}}
    let exp=0,plan=pl;
    if(pl!=='l'){const keep=u.plan&&u.plan!=='l'&&u.plan_exp>now?u.plan_exp:now;let days=pl==='m'?30:365;const cd=Math.floor(+b.days);if(cd>=1&&cd<=3650)days=cd;exp=keep+days*DAY}
    await env.DB.prepare('UPDATE users SET plan=?,plan_exp=? WHERE email=?').bind(plan,exp,email).run();
    return J({ok:true,email,plan,plan_exp:exp});
  }
  return J({error:'not_found'},404);
}
const PAGE=`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Dukan Hisab Admin</title><style>body{font:16px system-ui;background:#f6f8fa;margin:0;padding:16px;color:#1b2430}main{max-width:560px;margin:auto}h1{font-size:22px;margin:0 0 8px}h2{font-size:15px;margin:16px 0 6px;color:#44566c}input,button{font:inherit;padding:12px;border-radius:10px;border:1.5px solid #cfd7e0;width:100%;box-sizing:border-box;margin:6px 0}button{background:#0e7c7b;color:#fff;border:0;font-weight:700}button.o{background:#fff;color:#0e7c7b;border:1.5px solid #0e7c7b}.r{display:flex;gap:8px}.r>*{flex:1;min-width:0}.st{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}.st div{background:#fff;border:1px solid #dde4ea;border-radius:10px;padding:10px;text-align:center}.st b{display:block;font-size:22px}.u{background:#fff;border:1px solid #dde4ea;border-radius:10px;padding:10px;margin:6px 0;word-break:break-all;font-size:14px}.u button{margin:6px 0 0;padding:8px}pre{background:#fff;border:1px solid #dde4ea;border-radius:10px;padding:12px;white-space:pre-wrap;word-break:break-word;font-size:14px}</style></head><body><main><h1>Dukan Hisab Admin</h1><input id=k type=password placeholder="Admin key" autocomplete=off><div class=st><div><b id=s1>-</b>Users</div><div><b id=s2>-</b>Paid</div><div><b id=s3>-</b>Naye (24h)</div></div><button class=o id=st>Counters + 7 din mein khatam hone wale</button><h2>Plan do</h2><input id=e type=email placeholder="Customer Gmail" autocapitalize=none><div class=r><button data-p=m>Monthly 30d</button><button data-p=y>Yearly 365d</button><button data-p=l>Lifetime</button></div><div class=r><input id=d type=number min=1 max=3650 placeholder="Custom din (jaise 45)"><button id=cd>Custom din do</button></div><button class=o id=u>Is user ko dekho</button><button class=o id=x>Plan hatao</button><h2>Search</h2><div class=r><input id=q placeholder="email ka hissa"><button id=sq>Search</button></div><button class=o id=n>Recent users</button><div id=l></div><pre id=o>Ready.</pre></main><script>
const $=s=>document.querySelector(s),o=$('#o'),PN={m:'Monthly',y:'Yearly',l:'Lifetime'};
async function call(p,b,m){try{const r=await fetch(p,{method:m||'POST',headers:{'content-type':'application/json','x-admin':$('#k').value},body:m==='GET'?undefined:JSON.stringify(b||{})});const j=await r.json();if(r.status===429)o.textContent='Bahut zyada koshish. 10 minute baad try karo.';else if(!r.ok)o.textContent='Error: '+(j.error||r.status);else o.textContent='OK';return r.ok?j:null}catch(e){o.textContent='Network error';return null}}
const fd=t=>t?new Date(t).toLocaleDateString('en-IN',{day:'2-digit',month:'short',year:'numeric'}):'-';
function msg(u){return 'Namaste! Aapka My Dukan Hisab '+(PN[u.plan]||'')+' plan active ho gaya hai. '+(u.plan==='l'?'Ye Lifetime plan hai.':'Expiry: '+fd(u.plan_exp))+' Dhanyavaad!'}
function show(us){const L=$('#l');L.textContent='';us.forEach(u=>{const d=document.createElement('div');d.className='u';d.textContent=u.email+' · '+(u.plan?(PN[u.plan]+(u.plan==='l'?'':' till '+fd(u.plan_exp))):'trial '+fd(u.trial_start));const b=document.createElement('button');b.className='o';b.textContent='WhatsApp message copy';b.onclick=()=>{navigator.clipboard.writeText(msg(u)).then(()=>o.textContent='Copy ho gaya',()=>o.textContent=msg(u))};d.appendChild(b);const c=document.createElement('button');c.className='o';c.textContent='Is email ko chuno';c.onclick=()=>{$('#e').value=u.email;scrollTo(0,0)};d.appendChild(c);L.appendChild(d)})}
async function grant(b){const j=await call('/admin/grant',b);if(j){o.textContent='Plan ho gaya. Neeche se message copy karo.';show([{email:j.email,plan:j.plan,plan_exp:j.plan_exp}])}}
document.querySelectorAll('[data-p]').forEach(b=>b.onclick=()=>grant({email:$('#e').value,plan:b.dataset.p}));
$('#cd').onclick=()=>grant({email:$('#e').value,plan:'m',days:+$('#d').value});
$('#u').onclick=async()=>{const j=await call('/admin/user?email='+encodeURIComponent($('#e').value),null,'GET');if(j)show([j.user])};
$('#x').onclick=()=>call('/admin/revoke',{email:$('#e').value});
$('#n').onclick=async()=>{const j=await call('/admin/recent',null,'GET');if(j)show(j.users)};
$('#sq').onclick=async()=>{const j=await call('/admin/search?q='+encodeURIComponent($('#q').value),null,'GET');if(j)show(j.users)};
$('#st').onclick=async()=>{const j=await call('/admin/stats',null,'GET');if(j){$('#s1').textContent=j.total;$('#s2').textContent=j.paid;$('#s3').textContent=j.trials_today;show(j.expiring7);o.textContent='7 din mein khatam hone wale: '+j.expiring7.length}};
</script></body></html>`;

export default{
  async fetch(req,env){
    const url=new URL(req.url),path=url.pathname,h=cors(req,env);
    if(req.method==='OPTIONS')return new Response(null,{status:204,headers:h});
    try{
      if(path==='/'||path==='/health')return J({ok:true,app:'dukan-hisab-api'},200,h);
      if(path==='/admin'&&req.method==='GET')return new Response(PAGE,{headers:{'content-type':'text/html;charset=utf-8','cache-control':'no-store','content-security-policy':"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'"}});
      if(!env.DB||!env.GCID||!env.ADMIN_KEY)return J({error:'server_not_configured'},500,h);
      await init(env);
      let r;
      if(path==='/auth'&&req.method==='POST')r=await auth(req,env);
      else if(path==='/delete-account'&&req.method==='POST')r=await delAccount(req,env);
      else if(path==='/pubkey'&&req.method==='GET')r=J({pub:(await keys(env)).pub});
      else if(path.startsWith('/admin/'))r=await admin(req,env,path);
      else r=J({error:'not_found'},404);
      Object.entries(h).forEach(([k,v])=>r.headers.set(k,v));
      return r;
    }catch(e){return J({error:'server_error'},500,h)}
  }
};
