const COOKIE = 'mossio_session';
const encoder = new TextEncoder();
const json = (data, status=200, headers={}) => new Response(JSON.stringify(data), {status, headers:{'content-type':'application/json; charset=utf-8', ...headers}});
const secureHeaders = {
  'X-Content-Type-Options':'nosniff', 'X-Frame-Options':'DENY', 'Referrer-Policy':'strict-origin-when-cross-origin',
  'Permissions-Policy':'camera=(), microphone=(), geolocation=()',
  'Content-Security-Policy':"default-src 'self'; img-src 'self' data: https:; media-src 'self' blob:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; script-src 'self'; connect-src 'self'; font-src 'self' data: https://fonts.gstatic.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
};
function withSecurity(response){ const h=new Headers(response.headers); for(const [k,v] of Object.entries(secureHeaders)) h.set(k,v); return new Response(response.body,{status:response.status,statusText:response.statusText,headers:h}); }
const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const random = n => crypto.getRandomValues(new Uint8Array(n));
async function sha(value){ return b64(await crypto.subtle.digest('SHA-256', encoder.encode(value))); }
async function passwordHash(password,salt){ const key=await crypto.subtle.importKey('raw',encoder.encode(password),'PBKDF2',false,['deriveBits']); const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt:encoder.encode(salt),iterations:210000,hash:'SHA-256'},key,256); return b64(bits); }
function cookieValue(request,name){ const raw=request.headers.get('Cookie')||''; const item=raw.split(';').map(x=>x.trim()).find(x=>x.startsWith(name+'=')); return item?decodeURIComponent(item.slice(name.length+1)):''; }
async function auth(request,env){ const token=cookieValue(request,COOKIE); if(!token) return null; const row=await env.DB.prepare('SELECT admins.id, admins.username FROM sessions JOIN admins ON admins.id=sessions.admin_id WHERE sessions.token_hash=? AND sessions.expires_at>?').bind(await sha(token),Math.floor(Date.now()/1000)).first(); return row||null; }
function setCookie(token,days){ return `${COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${days*86400}`; }
const clearCookie=()=>`${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
async function bodyJSON(req){ try{return await req.json()}catch{return null} }
const allowedTypes=new Set(['projects','gallery','tools','skills','timeline','news','social']);
async function handle(request,env){
 const url=new URL(request.url), path=url.pathname, method=request.method;
 if(path==='/api/health'&&method==='GET') return json({ok:true,service:'MOSSIO API',time:new Date().toISOString()});
 if(path==='/api/site'&&method==='GET'){ const rows=await env.DB.prepare('SELECT type,title,subtitle,body,media_url,link_url,sort_order FROM content WHERE published=1 ORDER BY type,sort_order').all(); const settings=await env.DB.prepare('SELECT key,value FROM settings').all(); return json({items:rows.results||[],settings:Object.fromEntries((settings.results||[]).map(x=>[x.key,x.value]))}); }
 if(path==='/api/setup'&&method==='POST'){
   const count=await env.DB.prepare('SELECT COUNT(*) AS n FROM admins').first(); if(count.n>0) return json({error:'Initial setup is already complete.'},409);
   const data=await bodyJSON(request); if(!data||!env.ADMIN_SETUP_KEY||data.setupKey!==env.ADMIN_SETUP_KEY) return json({error:'Invalid setup key.'},403);
   const username=String(data.username||'').trim().toLowerCase(), password=String(data.password||'');
   if(!/^[a-z0-9_-]{3,32}$/.test(username)||password.length<12||password.length>128) return json({error:'Use a 3–32 character username and a 12–128 character password.'},400);
   const salt=b64(random(16)), hash=await passwordHash(password,salt), id=crypto.randomUUID();
   await env.DB.prepare('INSERT INTO admins(id,username,password_hash,password_salt) VALUES(?,?,?,?)').bind(id,username,hash,salt).run();
   return json({ok:true,message:'Admin account created. You can now sign in.'},201);
 }
 if(path==='/api/admin/login'&&method==='POST'){
   const data=await bodyJSON(request); const ip=request.headers.get('CF-Connecting-IP')||'unknown'; const now=Math.floor(Date.now()/1000);
   let attempt=await env.DB.prepare('SELECT attempts,window_started FROM login_attempts WHERE ip=?').bind(ip).first();
   if(attempt&&now-attempt.window_started<900&&attempt.attempts>=8) return json({error:'Too many attempts. Try again in 15 minutes.'},429);
   if(!attempt||now-attempt.window_started>=900){await env.DB.prepare('INSERT OR REPLACE INTO login_attempts(ip,attempts,window_started) VALUES(?,0,?)').bind(ip,now).run(); attempt={attempts:0,window_started:now};}
   const user=String(data?.username||'').trim().toLowerCase(), pass=String(data?.password||'');
   const admin=await env.DB.prepare('SELECT * FROM admins WHERE username=?').bind(user).first();
   const valid=admin&&await passwordHash(pass,admin.password_salt)===admin.password_hash;
   if(!valid){await env.DB.prepare('UPDATE login_attempts SET attempts=attempts+1 WHERE ip=?').bind(ip).run(); return json({error:'Invalid username or password.'},401);}
   await env.DB.prepare('DELETE FROM login_attempts WHERE ip=?').bind(ip).run();
   const token=b64(random(32)), days=Math.min(30,Math.max(1,Number(env.SESSION_TTL_DAYS||7)));
   await env.DB.prepare('INSERT INTO sessions(token_hash,admin_id,expires_at) VALUES(?,?,?)').bind(await sha(token),admin.id,now+days*86400).run();
   return json({ok:true,username:admin.username},200,{'Set-Cookie':setCookie(token,days)});
 }
 if(path==='/api/admin/logout'&&method==='POST'){
   const token=cookieValue(request,COOKIE); if(token) await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sha(token)).run();
   return json({ok:true},200,{'Set-Cookie':clearCookie()});
 }
 if(path==='/api/admin/me'&&method==='GET'){const admin=await auth(request,env); return admin?json({ok:true,username:admin.username}):json({error:'Unauthorized'},401);}
 if(path.startsWith('/api/admin/')){
   const admin=await auth(request,env); if(!admin) return json({error:'Unauthorized'},401);
   if(path==='/api/admin/content'&&method==='GET'){
     const rows=await env.DB.prepare('SELECT * FROM content ORDER BY type,sort_order,updated_at DESC').all();
     const settings=await env.DB.prepare('SELECT key,value FROM settings').all(); return json({items:rows.results||[],settings:Object.fromEntries((settings.results||[]).map(x=>[x.key,x.value]))});
   }
   if(path==='/api/admin/settings'&&method==='PUT'){
     const data=await bodyJSON(request); if(!data||typeof data!=='object'||Array.isArray(data)) return json({error:'Invalid settings.'},400);
     const allowed=new Set(['hero_title','hero_subtitle','about_title','about_body','status_label','contact_email','social_links']);
     for(const [key,value] of Object.entries(data)){if(!allowed.has(key)) continue; const val=String(value).slice(0,5000); await env.DB.prepare('INSERT INTO settings(key,value,updated_at) VALUES(?,?,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP').bind(key,val).run();}
     return json({ok:true});
   }
   if(path==='/api/admin/content'&&method==='POST'){
     const d=await bodyJSON(request); if(!d||!allowedTypes.has(d.type)||!String(d.title||'').trim()) return json({error:'Type and title are required.'},400);
     const id=String(d.id||crypto.randomUUID()).slice(0,80);
     await env.DB.prepare(`INSERT INTO content(id,type,title,subtitle,body,media_url,link_url,sort_order,published,updated_at) VALUES(?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(id) DO UPDATE SET type=excluded.type,title=excluded.title,subtitle=excluded.subtitle,body=excluded.body,media_url=excluded.media_url,link_url=excluded.link_url,sort_order=excluded.sort_order,published=excluded.published,updated_at=CURRENT_TIMESTAMP`).bind(id,d.type,String(d.title).slice(0,180),String(d.subtitle||'').slice(0,240),String(d.body||'').slice(0,8000),String(d.media_url||'').slice(0,1000),String(d.link_url||'').slice(0,1000),Math.max(0,Math.min(10000,Number(d.sort_order)||0)),d.published?1:0).run();
     return json({ok:true,id});
   }
   const del=path.match(/^\/api\/admin\/content\/([\w-]+)$/); if(del&&method==='DELETE'){await env.DB.prepare('DELETE FROM content WHERE id=?').bind(del[1]).run();return json({ok:true});}
   if(path==='/api/admin/upload'&&method==='POST'){
     const form=await request.formData(), file=form.get('file'); if(!(file instanceof File)) return json({error:'Choose a file.'},400);
     const max=Number(env.MAX_UPLOAD_MB||25)*1024*1024; if(file.size<1||file.size>max) return json({error:`File must be smaller than ${env.MAX_UPLOAD_MB||25} MB.`},413);
     const mime=file.type.toLowerCase(); const allowed=/^(image\/(png|jpeg|webp|gif)|video\/(mp4|webm)|audio\/(mpeg|mp3|wav|ogg|mp4|aac))$/.test(mime);
     if(!allowed) return json({error:'Unsupported file type.'},415);
     const ext=(file.name.split('.').pop()||'bin').toLowerCase().replace(/[^a-z0-9]/g,'').slice(0,8)||'bin';
     const key=`uploads/${new Date().toISOString().slice(0,10)}/${crypto.randomUUID()}.${ext}`;
     await env.MEDIA.put(key,await file.arrayBuffer(),{httpMetadata:{contentType:mime,cacheControl:'public, max-age=31536000, immutable'},customMetadata:{originalName:file.name.slice(0,120)}});
     return json({ok:true,key,url:`/media/${key}`},201);
   }
   return json({error:'Not found'},404);
 }
 if(path.startsWith('/media/')){
   const key=decodeURIComponent(path.slice('/media/'.length)); if(key.includes('..')) return json({error:'Invalid key'},400);
   const object=await env.MEDIA.get(key); if(!object) return json({error:'Not found'},404);
   const h=new Headers(); object.writeHttpMetadata(h); h.set('etag',object.httpEtag); h.set('X-Content-Type-Options','nosniff'); return new Response(object.body,{headers:h});
 }
 return env.ASSETS.fetch(request);
}
export default {async fetch(request,env){try{return withSecurity(await handle(request,env));}catch(err){return withSecurity(json({error:'Internal server error'},500));}}};
