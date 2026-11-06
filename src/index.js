// Cat Lawyer production API
const json=(data,status=200,headers={})=>Response.json(data,{status,headers:{"Cache-Control":"no-store",...headers}});
const enc=new TextEncoder();
const rate=new Map();
function limited(request,key,limit=20,windowMs=60000){const now=Date.now(),v=rate.get(key)||{n:0,t:now};if(now-v.t>windowMs){v.n=0;v.t=now}v.n++;rate.set(key,v);return v.n>limit}
function adminKey(request,env){const key=request.headers.get("X-Admin-Key")||"";return !!env.ADMIN_KEY&&key===env.ADMIN_KEY}
function requestIP(request){return request.headers.get("CF-Connecting-IP")||"unknown"}
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("");
const b64u=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
const unb64u=s=>Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")),c=>c.charCodeAt(0));
const digest=async s=>hex(await crypto.subtle.digest("SHA-256",enc.encode(s)));
async function passHash(p,s){const k=await crypto.subtle.importKey("raw",enc.encode(p),"PBKDF2",false,["deriveBits"]);return hex(await crypto.subtle.deriveBits({name:"PBKDF2",salt:unb64u(s),iterations:210000,hash:"SHA-256"},k,256));}
function tokenFrom(r){const p=(r.headers.get("Cookie")||"").split(";").map(x=>x.trim()).find(x=>x.startsWith("cl_session="));return p?decodeURIComponent(p.slice(11)):null;}
async function userFor(r,e){const t=tokenFrom(r);if(!t)return null;return await e.DB.prepare("SELECT u.id,u.name,u.email FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?").bind(await digest(t),Math.floor(Date.now()/1000)).first();}
async function session(e,id){const t=b64u(crypto.getRandomValues(new Uint8Array(32)));await e.DB.prepare("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)").bind(await digest(t),id,Math.floor(Date.now()/1000)+1209600).run();return "cl_session="+encodeURIComponent(t)+"; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=1209600";}
async function api(r,e){
 if(new URL(r.url).pathname==="/api/health"&&r.method==="GET")return json({ok:true,db:!!e.DB,ai:!!e.ai});
 if(!e.DB)return json({error:"База данных не подключена."},503);
 const p=new URL(r.url).pathname;
 try{
  if(p==="/api/auth/register"&&r.method==="POST"){if(limited(r,"register:"+requestIP(r),5,600000))return json({error:"Слишком много попыток регистрации. Попробуйте позже."},429);const b=await r.json(),name=String(b.name||"").trim().slice(0,80),email=String(b.email||"").trim().toLowerCase(),pw=String(b.password||"");if(name.length<2||!/^\S+@\S+\.\S+$/.test(email)||pw.length<10||pw.length>128)return json({error:"Укажите имя, корректную почту и пароль от 10 до 128 символов."},400);const salt=b64u(crypto.getRandomValues(new Uint8Array(16))),hash=await passHash(pw,salt),id=crypto.randomUUID();try{await e.DB.prepare("INSERT INTO users(id,name,email,password_hash,password_salt) VALUES(?,?,?,?,?)").bind(id,name,email,hash,salt).run();}catch(err){console.error("register insert failed",err);const msg=String(err?.message||"");if(/unique|constraint/i.test(msg))return json({error:"Аккаунт с такой почтой уже существует."},409);return json({error:"Не удалось создать аккаунт. Попробуйте ещё раз через несколько секунд."},500);}return json({user:{id,name,email}},201,{"Set-Cookie":await session(e,id)});}
  if(p==="/api/auth/login"&&r.method==="POST"){if(limited(r,"login:"+requestIP(r),10,60000))return json({error:"Слишком много попыток входа. Попробуйте через минуту."},429);const b=await r.json(),email=String(b.email||"").trim().toLowerCase(),pw=String(b.password||""),u=await e.DB.prepare("SELECT * FROM users WHERE email=?").bind(email).first();if(!u||await passHash(pw,u.password_salt)!==u.password_hash)return json({error:"Неверная почта или пароль."},401);return json({user:{id:u.id,name:u.name,email:u.email}},200,{"Set-Cookie":await session(e,u.id)});}
  if(p==="/api/auth/delete"&&r.method==="POST"){const u=await userFor(r,e);if(!u)return json({error:"Требуется вход."},401);await e.DB.prepare("DELETE FROM users WHERE id=?").bind(u.id).run();return json({ok:true},200,{"Set-Cookie":"cl_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"});}\n  if(p==="/api/auth/logout"&&r.method==="POST"){const t=tokenFrom(r);if(t)await e.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await digest(t)).run();return json({ok:true},200,{"Set-Cookie":"cl_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"});}
  if(p==="/api/auth/me"&&r.method==="GET")return json({user:await userFor(r,e)});
  if(p==="/api/plan"&&r.method==="GET"){const u=await userFor(r,e);if(!u)return json({error:"Требуется вход."},401);const row=await e.DB.prepare("SELECT plan FROM users WHERE id=?").bind(u.id).first();return json({plan:row?.plan||null});}
  if(p==="/api/plan"&&r.method==="POST"){const u=await userFor(r,e);if(!u)return json({error:"Требуется вход."},401);const b=await r.json(),plan=String(b.plan||"").trim();const allowed=["Базовый","Расширенный","Максимальный"];if(!allowed.includes(plan))return json({error:"Неизвестный тариф."},400);await e.DB.prepare("UPDATE users SET plan=? WHERE id=?").bind(plan,u.id).run();return json({plan});}
  if(p==="/api/reviews"&&r.method==="GET"){const {results=[]}=await e.DB.prepare("SELECT id,name,text,rating,created_at FROM reviews WHERE approved=1 ORDER BY created_at DESC LIMIT 50").all();return json({items:results});}
  if(p==="/api/reviews"&&r.method==="POST"){const b=await r.json(),u=await userFor(r,e),name=String(b.name||u?.name||"Пользователь Cat Lawyer").trim().slice(0,80),text=String(b.text||"").trim(),rating=Math.max(1,Math.min(5,Number(b.rating)||5);if(text.length<3||text.length>1000)return json({error:"Отзыв должен содержать от 3 до 1000 символов."},400);const id=crypto.randomUUID();await e.DB.prepare("INSERT INTO reviews(id,name,text,rating,approved) VALUES(?,?,?,?,1)").bind(id,name||"Пользователь Cat Lawyer",text,rating).run();return json({id},201);}
  if(p==="/api/history"&&r.method==="GET"){const u=await userFor(r,e);if(!u)return json({error:"Требуется вход."},401);const {results=[]}=await e.DB.prepare("SELECT id,message,reply,created_at FROM conversations WHERE user_id=? ORDER BY created_at DESC LIMIT 100").bind(u.id).all();return json({items:results});}
  if(p==="/api/history"&&r.method==="POST"){const u=await userFor(r,e);if(!u)return json({error:"Требуется вход."},401);const b=await r.json(),m=String(b.message||"").trim(),a=String(b.reply||"").trim();if(!m||m.length>5000||!a||a.length>12000)return json({error:"Некорректная запись."},400);const id=crypto.randomUUID();await e.DB.prepare("INSERT INTO conversations(id,user_id,message,reply) VALUES(?,?,?,?)").bind(id,u.id,m,a).run();return json({id},201);}
  if(p==="/api/chat"&&r.method==="POST"){const ip=requestIP(r);if(limited(r,"chat:"+ip,20,60000))return json({error:"Слишком много запросов. Подожди немного и попробуй снова."},429);const b=await r.json(),m=String(b.message||"").trim();if(!m||m.length>5000)return json({error:"Сообщение пустое или слишком длинное."},400);if(!e.ai)return json({error:"Workers AI binding не подключён."},503);const out=await e.ai.run("@cf/meta/llama-3.1-8b-instruct-fp8",{messages:[{role:"system",content:"Ты Cat Lawyer — юридический информационный помощник по законодательству РФ. Отвечай по-русски, естественно и понятными словами. Если фактов мало, сначала задай до трёх конкретных уточняющих вопросов и не делай преждевременных выводов. Не выдумывай статьи, сроки, судебную практику, реквизиты органов или адреса. Отделяй установленные факты от предположений. Когда даёшь правовую норму, по возможности указывай кодекс/закон и статью, но только если уверен в её применимости; актуальность нормы советуй проверять по официальному источнику. Если информации достаточно для первичного ответа, оформляй ответ строго в таком порядке: 1) «Коротко» — суть ситуации в 1–3 предложениях; 2) «Что может быть нарушено» — возможные права и нормы с оговоркой, если нужна проверка; 3) «Что делать» — пошаговый план; 4) «Куда обращаться» — конкретный орган/организацию и зачем; 5) «Что подготовить» — документы и доказательства; 6) «Важно» — риски, сроки или ограничения. Не проси лишние персональные данные. В конце каждого содержательного ответа обязательно добавляй отдельный блок «Дисклеймер»: «Ответ Cat Lawyer носит исключительно информационно-консультационный характер, не является юридическим заключением, не имеет юридической силы для реального обращения в государственные органы, суд, организации или иные учреждения и не заменяет помощь квалифицированного юриста. Перед реальным обращением рекомендуем проконсультироваться с юристом.»"},{role:"user",content:m}],max_tokens:900,temperature:.65});const reply=out.response||"Не удалось сформировать ответ.";const u=await userFor(r,e);if(u)await e.DB.prepare("INSERT INTO conversations(id,user_id,message,reply) VALUES(?,?,?,?)").bind(crypto.randomUUID(),u.id,m,reply).run();return json({reply});}
  return json({error:"Не найдено."},404);
 }catch(err){console.error("Cat Lawyer API error",err);return json({error:"Временная ошибка сервера. Попробуйте ещё раз через несколько секунд."},500);}
}
let schemaReady;
async function ensureSchema(db){
 if(!schemaReady)schemaReady=(async()=>{
  const tableInfo=async table=>{const r=await db.prepare("PRAGMA table_info("+table+")").all();return r.results||[]};
  const has=async(table,cols)=>{const rows=await tableInfo(table);return cols.every(c=>rows.some(x=>x.name===c))};
  const usersOk=await has("users",["id","name","email","password_hash","password_salt","created_at"]);
  const sessionsOk=await has("sessions",["token_hash","user_id","expires_at","created_at"]);
  const convOk=await has("conversations",["id","user_id","message","reply","created_at"]);
  const learnOk=await has("learn_progress",["user_id","completed","score"]);
  if(!usersOk&& (await tableInfo("users")).length) await db.prepare("ALTER TABLE users RENAME TO users_legacy").run();
  if(!sessionsOk&& (await tableInfo("sessions")).length) await db.prepare("ALTER TABLE sessions RENAME TO sessions_legacy").run();
  if(!convOk&& (await tableInfo("conversations")).length) await db.prepare("ALTER TABLE conversations RENAME TO conversations_legacy").run();
  if(!learnOk&& (await tableInfo("learn_progress")).length) await db.prepare("ALTER TABLE learn_progress RENAME TO learn_progress_legacy").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY,name TEXT NOT NULL,email TEXT NOT NULL UNIQUE COLLATE NOCASE,password_hash TEXT NOT NULL,password_salt TEXT NOT NULL,plan TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)").run();
  const userCols=await tableInfo("users");if(!userCols.some(x=>x.name==="plan"))await db.prepare("ALTER TABLE users ADD COLUMN plan TEXT").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires_at INTEGER NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id)").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS conversations (id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,message TEXT NOT NULL,reply TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS conversations_user_created_idx ON conversations(user_id,created_at DESC)").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS learn_progress (user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,completed INTEGER NOT NULL DEFAULT 0,score INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS reviews (id TEXT PRIMARY KEY,name TEXT NOT NULL,text TEXT NOT NULL,rating INTEGER NOT NULL DEFAULT 5,approved INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)").run();
  const reviewCols=await tableInfo("reviews");if(!reviewCols.some(x=>x.name==="rating"))await db.prepare("ALTER TABLE reviews ADD COLUMN rating INTEGER NOT NULL DEFAULT 5").run();\n  await db.prepare("CREATE INDEX IF NOT EXISTS reviews_created_idx ON reviews(approved,created_at DESC)").run();
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
 return new Response("Cat Lawyer API online",{status:200,headers:{"content-type":"text/plain; charset=utf-8"}});
}};