const json=(data,status=200,headers={})=>Response.json(data,{status,headers:{"Cache-Control":"no-store",...headers}});
const enc=new TextEncoder();
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("");
const b64u=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
const unb64u=s=>Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")),c=>c.charCodeAt(0));
const digest=async s=>hex(await crypto.subtle.digest("SHA-256",enc.encode(s)));
async function passHash(p,s){const k=await crypto.subtle.importKey("raw",enc.encode(p),"PBKDF2",false,["deriveBits"]);return hex(await crypto.subtle.deriveBits({name:"PBKDF2",salt:unb64u(s),iterations:210000,hash:"SHA-256"},k,256));}
function tokenFrom(r){const p=(r.headers.get("Cookie")||"").split(";").map(x=>x.trim()).find(x=>x.startsWith("cl_session="));return p?decodeURIComponent(p.slice(11)):null;}
async function userFor(r,e){const t=tokenFrom(r);if(!t)return null;return await e.DB.prepare("SELECT u.id,u.name,u.email FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?").bind(await digest(t),Math.floor(Date.now()/1000)).first();}
async function session(e,id){const t=b64u(crypto.getRandomValues(new Uint8Array(32)));await e.DB.prepare("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)").bind(await digest(t),id,Math.floor(Date.now()/1000)+1209600).run();return "cl_session="+encodeURIComponent(t)+"; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=1209600";}
async function api(r,e){
 if(!e.DB)return json({error:"База данных не подключена."},503);
 const p=new URL(r.url).pathname;
 try{
  if(p==="/api/auth/register"&&r.method==="POST"){const b=await r.json(),name=String(b.name||"").trim().slice(0,80),email=String(b.email||"").trim().toLowerCase(),pw=String(b.password||"");if(name.length<2||!/^\S+@\S+\.\S+$/.test(email)||pw.length<10||pw.length>128)return json({error:"Укажите имя, корректную почту и пароль от 10 до 128 символов."},400);const salt=b64u(crypto.getRandomValues(new Uint8Array(16))),hash=await passHash(pw,salt),id=crypto.randomUUID();try{await e.DB.prepare("INSERT INTO users(id,name,email,password_hash,password_salt) VALUES(?,?,?,?,?)").bind(id,name,email,hash,salt).run();}catch{return json({error:"Аккаунт с такой почтой уже существует."},409);}return json({user:{id,name,email}},201,{"Set-Cookie":await session(e,id)});}
  if(p==="/api/auth/login"&&r.method==="POST"){const b=await r.json(),email=String(b.email||"").trim().toLowerCase(),pw=String(b.password||""),u=await e.DB.prepare("SELECT * FROM users WHERE email=?").bind(email).first();if(!u||await passHash(pw,u.password_salt)!==u.password_hash)return json({error:"Неверная почта или пароль."},401);return json({user:{id:u.id,name:u.name,email:u.email}},200,{"Set-Cookie":await session(e,u.id)});}
  if(p==="/api/auth/logout"&&r.method==="POST"){const t=tokenFrom(r);if(t)await e.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await digest(t)).run();return json({ok:true},200,{"Set-Cookie":"cl_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"});}
  if(p==="/api/auth/me"&&r.method==="GET")return json({user:await userFor(r,e)});
  if(p==="/api/history"&&r.method==="GET"){const u=await userFor(r,e);if(!u)return json({error:"Требуется вход."},401);const {results=[]}=await e.DB.prepare("SELECT id,message,reply,created_at FROM conversations WHERE user_id=? ORDER BY created_at DESC LIMIT 100").bind(u.id).all();return json({items:results});}
  if(p==="/api/history"&&r.method==="POST"){const u=await userFor(r,e);if(!u)return json({error:"Требуется вход."},401);const b=await r.json(),m=String(b.message||"").trim(),a=String(b.reply||"").trim();if(!m||m.length>5000||!a||a.length>12000)return json({error:"Некорректная запись."},400);const id=crypto.randomUUID();await e.DB.prepare("INSERT INTO conversations(id,user_id,message,reply) VALUES(?,?,?,?)").bind(id,u.id,m,a).run();return json({id},201);}
  if(p==="/api/chat"&&r.method==="POST"){const b=await r.json(),m=String(b.message||"").trim();if(!m||m.length>5000)return json({error:"Сообщение пустое или слишком длинное."},400);if(!e.ai)return json({error:"Workers AI binding не подключён."},503);const out=await e.ai.run("@cf/meta/llama-3.1-8b-instruct",{messages:[{role:"system",content:"Ты Cat Lawyer — юридический информационный помощник по законодательству РФ. Отвечай по-русски, естественно, учитывай детали. Если фактов мало, задай до трёх конкретных вопросов. Не выдумывай статьи, сроки, судебную практику и адреса. Отделяй факты от предположений и рекомендуй проверять актуальную редакцию норм по официальным источникам. Объясняй возможные права, следующие шаги и куда обратиться. Не проси лишние персональные данные. Это не юридическое заключение."},{role:"user",content:m}],max_tokens:900,temperature:.65});const reply=out.response||"Не удалось сформировать ответ.";const u=await userFor(r,e);if(u)await e.DB.prepare("INSERT INTO conversations(id,user_id,message,reply) VALUES(?,?,?,?)").bind(crypto.randomUUID(),u.id,m,reply).run();return json({reply});}
  return json({error:"Не найдено."},404);
 }catch{return json({error:"Ошибка обработки запроса."},500);}
}
let schemaReady;
async function ensureSchema(db){
 if(!schemaReady)schemaReady=(async()=>{
  await db.prepare("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY,name TEXT NOT NULL,email TEXT NOT NULL UNIQUE COLLATE NOCASE,password_hash TEXT NOT NULL,password_salt TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires_at INTEGER NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id)").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS conversations (id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,message TEXT NOT NULL,reply TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS conversations_user_created_idx ON conversations(user_id,created_at DESC)").run();
 })();
 return schemaReady;
}
export default {async fetch(request,env){
 const url=new URL(request.url);
 if(url.pathname.startsWith("/api/")){
  if(env.DB)await ensureSchema(env.DB);
  const origin=request.headers.get("Origin")||"";
  const ok=origin==="https://cat-lawyer.pages.dev"||/^https:\/\/[a-z0-9-]+\.cat-lawyer\.pages\.dev$/.test(origin);
  const headers={"Access-Control-Allow-Origin":ok?origin:"https://cat-lawyer.pages.dev","Access-Control-Allow-Credentials":"true","Access-Control-Allow-Methods":"GET,POST,OPTIONS","Access-Control-Allow-Headers":"Content-Type","Vary":"Origin"};
  if(request.method==="OPTIONS")return new Response(null,{status:204,headers});
  const response=await api(request,env);const out=new Headers(response.headers);
  for(const [k,v] of Object.entries(headers))out.set(k,v);
  return new Response(response.body,{status:response.status,headers:out});
 }
 return env.ASSETS.fetch(request);
}};