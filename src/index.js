// Cat Lawyer production API
const json=(data,status=200,headers={})=>Response.json(data,{status,headers:{"Cache-Control":"no-store",...headers}});
const enc=new TextEncoder();
const rate=new Map();
let schemaPromise=null;

function limited(request,key,limit=20,windowMs=60000){
  const now=Date.now(),v=rate.get(key)||{n:0,t:now};
  if(now-v.t>windowMs){v.n=0;v.t=now}
  v.n++;
  rate.set(key,v);
  return v.n>limit;
}
function requestIP(request){return request.headers.get("CF-Connecting-IP")||"unknown"}
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("");
const b64u=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
const unb64u=s=>Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")),c=>c.charCodeAt(0));
const digest=async s=>hex(await crypto.subtle.digest("SHA-256",enc.encode(s)));
async function passHash(p,s){
  const k=await crypto.subtle.importKey("raw",enc.encode(p),"PBKDF2",false,["deriveBits"]);
  return hex(await crypto.subtle.deriveBits({name:"PBKDF2",salt:unb64u(s),iterations:210000,hash:"SHA-256"},k,256));
}
function tokenFrom(r){
  const p=(r.headers.get("Cookie")||"").split(";").map(x=>x.trim()).find(x=>x.startsWith("cl_session="));
  return p?decodeURIComponent(p.slice(11)):null;
}
async function userFor(r,e){
  const t=tokenFrom(r); if(!t)return null;
  return await e.DB.prepare("SELECT u.id,u.name,u.email FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?").bind(await digest(t),Math.floor(Date.now()/1000)).first();
}
async function session(e,id){
  const t=b64u(crypto.getRandomValues(new Uint8Array(32)));
  await e.DB.prepare("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)").bind(await digest(t),id,Math.floor(Date.now()/1000)+1209600).run();
  return "cl_session="+encodeURIComponent(t)+"; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=1209600";
}
function clearCookie(name="cl_session"){return name+"=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"}
async function adminAuth(request,env){
  const cookie=request.headers.get("Cookie")||"";
  const m=cookie.match(/(?:^|;\s*)cl_admin=([^;]+)/);
  if(m&&env.ADMIN_PASSWORD){
    const raw=decodeURIComponent(m[1]),parts=raw.split(".");
    if(parts.length===2){
      const ts=Number(parts[0]);
      if(Number.isFinite(ts)&&Date.now()-ts<86400000){
        const sig=await digest(ts+"."+env.ADMIN_PASSWORD);
        if(sig===parts[1])return true;
      }
    }
  }
  const key=request.headers.get("X-Admin-Key")||"";
  return !!env.ADMIN_KEY&&key===env.ADMIN_KEY;
}
async function adminCookie(env){
  const ts=Date.now().toString();
  return "cl_admin="+encodeURIComponent(ts+"."+await digest(ts+"."+env.ADMIN_PASSWORD))+"; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400";
}
async function aiText(e,messages,max_tokens=900){
  if(!e.ai)throw new Error("AI binding missing");
  const out=await e.ai.run("@cf/meta/llama-3.1-8b-instruct-fp8",{messages,max_tokens,temperature:.65});
  return out.response||"Не удалось сформировать ответ.";
}
async function ensureAuthSchema(db){
  await db.prepare("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY,name TEXT,email TEXT UNIQUE COLLATE NOCASE,password_hash TEXT,password_salt TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP,plan TEXT)").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY,user_id TEXT,expires_at INTEGER,created_at TEXT DEFAULT CURRENT_TIMESTAMP)").run();
  const info=async t=>(await db.prepare("PRAGMA table_info("+t+")").all()).results||[];
  const add=async(t,n,d)=>{if(!(await info(t)).some(x=>x.name===n))await db.prepare("ALTER TABLE "+t+" ADD COLUMN "+n+" "+d).run()};
  await add("users","name","TEXT DEFAULT ''"); await add("users","email","TEXT DEFAULT ''");
  await add("users","password_hash","TEXT DEFAULT ''"); await add("users","password_salt","TEXT DEFAULT ''");
  await add("users","created_at","TEXT DEFAULT ''"); await add("users","plan","TEXT");
  await add("sessions","token_hash","TEXT DEFAULT ''"); await add("sessions","user_id","TEXT"); await add("sessions","expires_at","INTEGER DEFAULT 0"); await add("sessions","created_at","TEXT DEFAULT ''");
  try{await db.prepare("CREATE UNIQUE INDEX IF NOT EXISTS users_email_idx ON users(email COLLATE NOCASE)").run()}catch{}
  try{await db.prepare("CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id)").run()}catch{} try{await db.prepare("CREATE UNIQUE INDEX IF NOT EXISTS sessions_token_hash_idx ON sessions(token_hash)").run()}catch{}
}

async function ensureSchemaOnce(db){
  if(schemaPromise)return schemaPromise;
  schemaPromise=ensureSchema(db).catch(err=>{schemaPromise=null;throw err});
  return schemaPromise;
}
async function ensureSchema(db){
  const tableInfo=async table=>(await db.prepare("PRAGMA table_info("+table+")").all()).results||[];
  const has=async(table,name)=>{const rows=await tableInfo(table);return rows.some(x=>x.name===name)};
  const add=async(table,name,definition)=>{if(!(await has(table,name)))await db.prepare("ALTER TABLE "+table+" ADD COLUMN "+name+" "+definition).run()};
  const safeIndex=async(sql)=>{try{await db.prepare(sql).run()}catch(err){console.error("Cat Lawyer index migration:",err)}};

  await db.prepare("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY,name TEXT,email TEXT UNIQUE COLLATE NOCASE,password_hash TEXT,password_salt TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP,plan TEXT)").run();
  await add("users","name","TEXT DEFAULT ''");
  await add("users","email","TEXT DEFAULT ''");
  await add("users","password_hash","TEXT DEFAULT ''");
  await add("users","password_salt","TEXT DEFAULT ''");
  await add("users","created_at","TEXT DEFAULT ''");
  await add("users","plan","TEXT");
  await safeIndex("CREATE UNIQUE INDEX IF NOT EXISTS users_email_idx ON users(email COLLATE NOCASE)");

  await db.prepare("CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY,user_id TEXT,expires_at INTEGER,created_at TEXT DEFAULT CURRENT_TIMESTAMP)").run();
  await add("sessions","user_id","TEXT");
  await add("sessions","expires_at","INTEGER DEFAULT 0");
  await add("sessions","created_at","TEXT DEFAULT ''");
  await safeIndex("CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id)");

  await db.prepare("CREATE TABLE IF NOT EXISTS conversations (id TEXT PRIMARY KEY,user_id TEXT,message TEXT,reply TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP)").run();
  await add("conversations","user_id","TEXT");
  await add("conversations","message","TEXT DEFAULT ''");
  await add("conversations","reply","TEXT DEFAULT ''");
  await add("conversations","created_at","TEXT DEFAULT ''");
  await safeIndex("CREATE INDEX IF NOT EXISTS conversations_user_created_idx ON conversations(user_id,created_at DESC)");

  await db.prepare("CREATE TABLE IF NOT EXISTS learn_progress (user_id TEXT PRIMARY KEY,completed INTEGER DEFAULT 0,score INTEGER DEFAULT 0,created_at TEXT DEFAULT CURRENT_TIMESTAMP,updated_at TEXT DEFAULT CURRENT_TIMESTAMP)").run();
  await add("learn_progress","completed","INTEGER DEFAULT 0");
  await add("learn_progress","score","INTEGER DEFAULT 0");
  await add("learn_progress","created_at","TEXT DEFAULT ''");
  await add("learn_progress","updated_at","TEXT DEFAULT ''");

  await db.prepare("CREATE TABLE IF NOT EXISTS reviews (id TEXT PRIMARY KEY,name TEXT,text TEXT,rating INTEGER DEFAULT 5,approved INTEGER DEFAULT 0,created_at TEXT DEFAULT CURRENT_TIMESTAMP)").run();
  await add("reviews","name","TEXT DEFAULT 'Пользователь Cat Lawyer'");
  await add("reviews","text","TEXT DEFAULT ''");
  await add("reviews","rating","INTEGER DEFAULT 5");
  await add("reviews","approved","INTEGER DEFAULT 0");
  await add("reviews","created_at","TEXT DEFAULT ''");
  await safeIndex("CREATE INDEX IF NOT EXISTS reviews_created_idx ON reviews(approved,created_at DESC)");
}
async function api(r,e){
  const url=new URL(r.url),p=url.pathname;
  if(p==="/api/health"&&r.method==="GET"){\n    if(new URL(r.url).searchParams.get("debug")==="1"&&e.DB){\n      const tables={};\n      for(const t of ["users","sessions"]){\n        try{tables[t]=(await e.DB.prepare("PRAGMA table_info("+t+")").all()).results||[]}catch(err){tables[t]={error:String(err?.message||err)}}\n      }\n      return json({ok:true,db:true,ai:!!e.ai,tables});\n    }\n    return json({ok:true,db:!!e.DB,ai:!!e.ai});\n  }
  if(!e.DB)return json({error:"База данных не подключена."},503);
  try{
    if(p==="/api/auth/register"&&r.method==="POST"){
      if(limited(r,"register:"+requestIP(r),5,600000))return json({error:"Слишком много попыток регистрации. Попробуйте позже."},429);
      const b=await r.json(),name=String(b.name||"").trim().slice(0,80),email=String(b.email||"").trim().toLowerCase(),pw=String(b.password||"");
      if(name.length<2||!/^\S+@\S+\.\S+$/.test(email)||pw.length<10||pw.length>128)return json({error:"Укажите имя, корректную почту и пароль от 10 до 128 символов."},400);
      let salt,hash,id;
      try {
        salt=b64u(crypto.getRandomValues(new Uint8Array(16)));
        hash=await passHash(pw,salt);
        id=crypto.randomUUID();
        const cols=(await e.DB.prepare("PRAGMA table_info(users)").all()).results||[];
        const valuesByName={
          id, name, email, password_hash:hash, password_salt:salt, plan:"Базовый",
          username:email, login:email, full_name:name, display_name:name,
          password:hash, role:"user", created_at:new Date().toISOString(), created:new Date().toISOString()
        };
        const insertCols=[],insertVals=[];
        for(const col of cols){
          const n=String(col.name||"");
          if(!n)continue;
          const isIntegerId=(n==="id"&&String(col.type||"").toUpperCase().includes("INT")&&Number(col.pk)===1);
          if(isIntegerId)continue;
          if(Object.prototype.hasOwnProperty.call(valuesByName,n)){
            insertCols.push(n); insertVals.push(valuesByName[n]); continue;
          }
          if(Number(col.notnull)===1&&col.dflt_value==null){
            const type=String(col.type||"").toUpperCase();
            insertCols.push(n);
            if(type.includes("INT")||type.includes("REAL")||type.includes("NUM"))insertVals.push(0);
            else insertVals.push("");
          }
        }
        if(!insertCols.length)throw new Error("users table has no writable columns");
        const marks=insertCols.map(()=>"?").join(",");
        await e.DB.prepare("INSERT INTO users("+insertCols.join(",")+") VALUES("+marks+")").bind(...insertVals).run();
      } catch(err) {
        console.error("Cat Lawyer registration insert error",err);
        const msg=String(err?.message||"");
        if(/unique|constraint/i.test(msg))return json({error:"Аккаунт с такой почтой уже существует."},409);
        return json({error:"Не удалось создать аккаунт. Проверьте подключение базы данных и попробуйте ещё раз."},500);
      }
      try {
        const cookie=await session(e,id);
        return json({user:{id,name,email}},201,{"Set-Cookie":cookie});
      } catch(err) {
        console.error("Cat Lawyer session creation error",err);
        return json({error:"Аккаунт создан, но не удалось открыть сессию. Попробуйте войти ещё раз."},500);
      }
    }
    if(p==="/api/auth/login"&&r.method==="POST"){
      if(limited(r,"login:"+requestIP(r),10,60000))return json({error:"Слишком много попыток входа. Попробуйте через минуту."},429);
      const b=await r.json(),email=String(b.email||"").trim().toLowerCase(),pw=String(b.password||""),u=await e.DB.prepare("SELECT * FROM users WHERE email=?").bind(email).first();
      if(!u||!u.password_salt||await passHash(pw,u.password_salt)!==u.password_hash)return json({error:"Неверная почта или пароль."},401);
      return json({user:{id:u.id,name:u.name,email:u.email}},200,{"Set-Cookie":await session(e,u.id)});
    }
    if(p==="/api/auth/delete"&&r.method==="POST"){
      const u=await userFor(r,e);if(!u)return json({error:"Требуется вход."},401);
      await e.DB.batch([e.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(u.id),e.DB.prepare("DELETE FROM conversations WHERE user_id=?").bind(u.id),e.DB.prepare("DELETE FROM learn_progress WHERE user_id=?").bind(u.id),e.DB.prepare("DELETE FROM users WHERE id=?").bind(u.id)]);
      return json({ok:true},200,{"Set-Cookie":clearCookie()});
    }
    if(p==="/api/auth/logout"&&r.method==="POST"){
      const t=tokenFrom(r);if(t)await e.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await digest(t)).run();
      return json({ok:true},200,{"Set-Cookie":clearCookie()});
    }
    if(p==="/api/auth/me"&&r.method==="GET")return json({user:await userFor(r,e)});
    if(p==="/api/plan"&&r.method==="GET"){
      const u=await userFor(r,e);if(!u)return json({error:"Требуется вход."},401);
      const row=await e.DB.prepare("SELECT plan FROM users WHERE id=?").bind(u.id).first();return json({plan:row?.plan||null});
    }
    if(p==="/api/plan"&&r.method==="POST"){
      const u=await userFor(r,e);if(!u)return json({error:"Требуется вход."},401);
      const plan=String((await r.json()).plan||"").trim(),allowed=["Базовый","Расширенный","Максимальный"];
      if(!allowed.includes(plan))return json({error:"Неизвестный тариф."},400);
      await e.DB.prepare("UPDATE users SET plan=? WHERE id=?").bind(plan,u.id).run();return json({plan});
    }
    if(p==="/api/reviews"&&r.method==="GET"){
      const {results=[]}=await e.DB.prepare("SELECT id,name,text,rating,created_at FROM reviews WHERE approved=1 ORDER BY created_at DESC LIMIT 50").all();return json({items:results});
    }
    if(p==="/api/reviews"&&r.method==="POST"){
      const b=await r.json(),u=await userFor(r,e),name=String(b.name||u?.name||"Пользователь Cat Lawyer").trim().slice(0,80),text=String(b.text||"").trim(),rating=Math.max(1,Math.min(5,Number(b.rating)||5));
      if(text.length<3||text.length>1000)return json({error:"Отзыв должен содержать от 3 до 1000 символов."},400);
      const id=crypto.randomUUID();await e.DB.prepare("INSERT INTO reviews(id,name,text,rating,approved) VALUES(?,?,?,?,0)").bind(id,name||"Пользователь Cat Lawyer",text,rating).run();return json({id,pending:true},201);
    }
    if(p==="/api/history"&&r.method==="GET"){
      const u=await userFor(r,e);if(!u)return json({error:"Требуется вход."},401);
      const {results=[]}=await e.DB.prepare("SELECT id,message,reply,created_at FROM conversations WHERE user_id=? ORDER BY created_at DESC LIMIT 100").bind(u.id).all();return json({items:results});
    }
    if(p==="/api/chat"&&r.method==="POST"){
      if(limited(r,"chat:"+requestIP(r),20,60000))return json({error:"Слишком много запросов. Подожди немного и попробуй снова."},429);
      const m=String((await r.json()).message||"").trim();if(!m||m.length>5000)return json({error:"Сообщение пустое или слишком длинное."},400);
      const reply=await aiText(e,[{role:"system",content:"Ты Cat Lawyer — юридический информационный помощник по законодательству РФ. Отвечай по-русски, естественно и понятными словами. Если фактов мало, сначала задай до трёх конкретных уточняющих вопросов. Не выдумывай статьи, сроки, судебную практику, реквизиты органов или адреса. Если информации достаточно, используй строго: 1) «Коротко»; 2) «Что может быть нарушено»; 3) «Что делать»; 4) «Куда обращаться»; 5) «Что подготовить»; 6) «Важно». Не проси лишние персональные данные. В конце содержательного ответа добавляй блок «Дисклеймер»: «Ответ Cat Lawyer носит исключительно информационно-консультационный характер, не является юридическим заключением, не имеет юридической силы для реального обращения в государственные органы, суд, организации или иные учреждения и не заменяет помощь квалифицированного юриста. Перед реальным обращением рекомендуем проконсультироваться с юристом.»"},{role:"user",content:m}],900);
      const u=await userFor(r,e);if(u)await e.DB.prepare("INSERT INTO conversations(id,user_id,message,reply) VALUES(?,?,?,?)").bind(crypto.randomUUID(),u.id,m,reply).run();
      return json({reply});
    }
    if(p==="/api/documents"&&r.method==="POST"){
      if(limited(r,"documents:"+requestIP(r),10,60000))return json({error:"Слишком много запросов. Попробуйте позже."},429);
      const b=await r.json(),type=String(b.type||"Обращение").trim(),situation=String(b.situation||"").trim();
      if(!["Претензия","Жалоба","Заявление","Обращение"].includes(type)||situation.length<10||situation.length>10000)return json({error:"Проверь тип документа и описание ситуации."},400);
      const document=await aiText(e,[{role:"system",content:"Ты помощник Cat Lawyer. Составляй только информационный черновик документа по законодательству РФ. Тип документа: "+type+". Не выдумывай ФИО, адреса, номера, даты, организации, статьи или факты. Недостающие сведения обозначай квадратными скобками: [указать]. Структура должна быть пригодна для дальнейшей проверки человеком. В конце добавь короткую пометку, что документ нужно проверить перед отправкой."},{role:"user",content:situation}],1200);
      return json({type,document});
    }
    if(p==="/api/learn/progress"&&r.method==="GET"){
      const u=await userFor(r,e);if(!u)return json({error:"Требуется вход."},401);
      const row=await e.DB.prepare("SELECT completed,score FROM learn_progress WHERE user_id=?").bind(u.id).first();return json({completed:row?.completed||0,score:row?.score||0});
    }
    if(p==="/api/learn/progress"&&r.method==="POST"){
      const u=await userFor(r,e);if(!u)return json({error:"Требуется вход."},401);
      const b=await r.json(),completed=Math.max(0,Math.min(6,Number(b.completed)||0)),score=Math.max(0,Math.min(6,Number(b.score)||0));
      await e.DB.prepare("INSERT INTO learn_progress(user_id,completed,score) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET completed=excluded.completed,score=excluded.score,updated_at=CURRENT_TIMESTAMP").bind(u.id,completed,score).run();
      return json({completed,score});
    }
    if(p==="/api/admin/login"&&r.method==="POST"){
      if(limited(r,"admin-login:"+requestIP(r),10,60000))return json({error:"Слишком много попыток входа."},429);
      if(!e.ADMIN_LOGIN||!e.ADMIN_PASSWORD)return json({error:"Админ-доступ ещё не настроен на сервере."},503);
      const b=await r.json();if(String(b.login||"")!==e.ADMIN_LOGIN||String(b.password||"")!==e.ADMIN_PASSWORD)return json({error:"Неверные данные администратора."},401);
      return json({ok:true},200,{"Set-Cookie":await adminCookie(e)});
    }
    if(p==="/api/admin/logout"&&r.method==="POST")return json({ok:true},200,{"Set-Cookie":clearCookie("cl_admin")});
    if(p.startsWith("/api/admin/")){
      if(!(await adminAuth(r,e)))return json({error:"Доступ запрещён."},401);
      if(p==="/api/admin/stats"&&r.method==="GET"){
        const [u,c,v]=await Promise.all([e.DB.prepare("SELECT COUNT(*) n FROM users").first(),e.DB.prepare("SELECT COUNT(*) n FROM conversations").first(),e.DB.prepare("SELECT COUNT(*) n FROM reviews").first()]);
        return json({users:u?.n||0,conversations:c?.n||0,reviews:v?.n||0});
      }
      if(p==="/api/admin/reviews"&&r.method==="GET"){
        const {results=[]}=await e.DB.prepare("SELECT id,name,text,rating,approved,created_at FROM reviews ORDER BY created_at DESC LIMIT 100").all();return json({items:results});
      }
      if(p==="/api/admin/reviews"&&r.method==="POST"){
        const b=await r.json(),id=String(b.id||""),approved=Number(b.approved)?1:0;if(!id)return json({error:"Не указан отзыв."},400);
        await e.DB.prepare("UPDATE reviews SET approved=? WHERE id=?").bind(approved,id).run();return json({ok:true});
      }
      if(p==="/api/admin/reviews/delete"&&r.method==="POST"){
        const id=String((await r.json()).id||"");if(!id)return json({error:"Не указан отзыв."},400);
        await e.DB.prepare("DELETE FROM reviews WHERE id=?").bind(id).run();return json({ok:true});
      }
    }
    return json({error:"Не найдено."},404);
  }catch(err){
    console.error("Cat Lawyer API error",err);
    if(String(err?.message||"").includes("AI"))return json({error:"Не удалось получить ответ от AI. Попробуйте ещё раз."},502);
    return json({error:"Временная ошибка сервера. Попробуйте ещё раз через несколько секунд."},500);
  }
}
export default {async fetch(request,env){
  const url=new URL(request.url);
  if(url.pathname.startsWith("/api/")){
    if(url.pathname==="/api/health"&&request.method==="GET")return new Response(JSON.stringify({ok:true,db:!!env.DB,ai:!!env.ai}),{headers:{"content-type":"application/json"}});
    if(env.DB){
      try{
        const authPath=/^\/api\/auth\/(register|login|me|logout)$/.test(url.pathname);
        if(authPath) await ensureAuthSchema(env.DB); else await ensureSchemaOnce(env.DB);
      }catch(err){
        console.error("Cat Lawyer schema error",err);
        const origin=request.headers.get("Origin")||"";
        const ok=origin==="https://cat-lawyer.pages.dev"||/^https:\/\/[a-z0-9-]+\.cat-lawyer\.pages\.dev$/.test(origin);
        const headers={"Access-Control-Allow-Origin":ok?origin:"https://cat-lawyer.pages.dev","Access-Control-Allow-Credentials":"true","Access-Control-Allow-Methods":"GET,POST,OPTIONS","Access-Control-Allow-Headers":"Content-Type,X-Admin-Key","Vary":"Origin"};
        return new Response(JSON.stringify({error:"База данных временно недоступна. Попробуйте ещё раз через несколько секунд."}),{status:503,headers:{"content-type":"application/json; charset=utf-8",...headers}});
      }
    }
    const origin=request.headers.get("Origin")||"";
    const ok=origin==="https://cat-lawyer.pages.dev"||/^https:\/\/[a-z0-9-]+\.cat-lawyer\.pages\.dev$/.test(origin);
    const headers={"Access-Control-Allow-Origin":ok?origin:"https://cat-lawyer.pages.dev","Access-Control-Allow-Credentials":"true","Access-Control-Allow-Methods":"GET,POST,OPTIONS","Access-Control-Allow-Headers":"Content-Type,X-Admin-Key","Vary":"Origin"};
    if(request.method==="OPTIONS")return new Response(null,{status:204,headers});
    const response=await api(request,env),out=new Headers(response.headers);for(const [k,v] of Object.entries(headers))out.set(k,v);
    return new Response(response.body,{status:response.status,headers:out});
  }
  return new Response("Cat Lawyer API online",{status:200,headers:{"content-type":"text/plain; charset=utf-8"}});
}};
