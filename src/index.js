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
  return hex(await crypto.subtle.deriveBits({name:"PBKDF2",salt:unb64u(s),iterations:100000,hash:"SHA-256"},k,256));
}
function tokenFrom(r){
  const p=(r.headers.get("Cookie")||"").split(";").map(x=>x.trim()).find(x=>x.startsWith("cl_session="));
  return p?decodeURIComponent(p.slice(11)):null;
}
async function userFor(r,e){
  const t=tokenFrom(r); if(!t)return null;
  return await e.DB.prepare("SELECT u.id,u.name,u.email FROM cl_auth_sessions s JOIN cl_auth_users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?").bind(await digest(t),Math.floor(Date.now()/1000)).first();
}
async function session(e,id){
  const t=b64u(crypto.getRandomValues(new Uint8Array(32)));
  await e.DB.prepare("INSERT INTO cl_auth_sessions(token_hash,user_id,expires_at) VALUES(?,?,?)").bind(await digest(t),id,Math.floor(Date.now()/1000)+1209600).run();
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
async function aiText(e,messages,max_tokens=420){
  if(!e.ai)throw new Error("AI binding missing");
  const models=[
    "@cf/meta/llama-3.1-8b-instruct-fast",
    "@cf/meta/llama-3.1-8b-instruct-fp8",
    "@cf/meta/llama-3.2-3b-instruct"
  ];
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),18000);
  try{
    let lastErr;
    const prompt=messages.map(x=>String(x?.content||"")).filter(Boolean).join("\n\n");
    for(const model of models){
      for(const input of [
        {messages,max_tokens,temperature:.45},
        {prompt,max_tokens,temperature:.45}
      ]){
        try{
          const out=await e.ai.run(model,input);
          const response=typeof out==="string"?out:(out?.response||out?.result?.response||"");
          if(response&&String(response).trim())return String(response).trim();
          lastErr=new Error(model+" returned an empty response");
        }catch(err){lastErr=err}
      }
    }
    throw lastErr||new Error("Workers AI returned an empty response");
  }catch(err){
    if(err?.name==="AbortError")throw new Error("Workers AI request timed out");
    throw err;
  }finally{
    clearTimeout(timer);
  }
}
function validateAiReply(question,reply){
  const q=String(question||"").toLowerCase(),r=String(reply||"").toLowerCase();
  const consumerReturn=/(вернуть|возврат|обмен).*(товар|покуп|магазин)|((товар|покуп|магазин).*(вернуть|возврат|обмен))/.test(q);
  if(consumerReturn && /(?:вернуть|возврат|обмен)[^\n]{0,160}7\s*дн|7\s*дн[^\n]{0,160}(?:вернуть|возврат|обмен)/.test(r))return false;
  if(/федеральн(?:ый|ого) закон[^\n]{0,100}329-фз/.test(r))return false;
  if(/8-800-100-100-8/.test(r))return false;
  if(/\bфас\b|федеральн(ая|ую) антимонопольн/.test(r))return false;
  if(/гражданск(ий|ого) кодекс[^\n]{0,80}стать\s*1\b/.test(r))return false;
  if(/чек[^\n]{0,80}(обязател|необходим)|обязателен[^\n]{0,80}чек/.test(r))return false;
  if(/право потребителя на возврат товара в течение срока, указанного выше/.test(r))return false;
  return r.length>=40;
}
function fallbackLegalReply(m){
  const q=String(m||"").toLowerCase();
  if(/вернуть|возврат|обмен|магазин|товар/.test(q)){
    if(/брак|дефект|неисправ|недостат/.test(q))return "Коротко\\nНужно уточнить обстоятельства, но если товар с недостатком, правила отличаются от обычного возврата товара надлежащего качества.\\n\\nУточни, пожалуйста: 1) когда купил товар; 2) в чём именно недостаток; 3) покупка была в обычном магазине или дистанционно.\\n\\nПосле этого можно определить требование к продавцу и порядок обращения.\\n\\nДисклеймер: Ответ Cat Lawyer носит исключительно информационно-консультационный характер, не является юридическим заключением, не имеет юридической силы для реального обращения в государственные органы, суд, организации или иные учреждения и не заменяет помощь квалифицированного юриста. Перед реальным обращением рекомендуем проконсультироваться с юристом.";
    return "Коротко\\nЕсли это обычная покупка в магазине и товар надлежащего качества, обычно применяется статья 25 Закона РФ «О защите прав потребителей»: непродовольственный товар можно требовать обменять в течение 14 дней, не считая дня покупки, при соблюдении установленных условий. Если подходящего аналогичного товара нет, в предусмотренных законом случаях можно потребовать возврат денег. Если у товара есть недостаток, действует другой порядок, в частности правила статьи 18 этого закона.\\n\\nУточни, пожалуйста: 1) когда была покупка; 2) товар исправен или есть недостаток; 3) покупка была в обычном магазине или через интернет.\\n\\nЕсли продавец уже отказал, сохрани переписку/ответ продавца и документы о покупке. Отсутствие кассового чека само по себе не лишает потребителя возможности доказывать покупку другими способами.\\n\\nДисклеймер: Ответ Cat Lawyer носит исключительно информационно-консультационный характер, не является юридическим заключением, не имеет юридической силы для реального обращения в государственные органы, суд, организации или иные учреждения и не заменяет помощь квалифицированного юриста. Перед реальным обращением рекомендуем проконсультироваться с юристом.";
  }
  if(/уволь|работ|зарплат|начальник|отпуск/.test(q))return "Коротко\\nЧтобы не дать неверный совет, нужны детали трудовой ситуации.\\n\\nУточни: что произошло, когда это произошло и что именно работодатель требует или отказался сделать. Если есть приказ или письменный отказ, его содержание тоже пригодится.\\n\\nДисклеймер: Ответ Cat Lawyer носит исключительно информационно-консультационный характер, не является юридическим заключением, не имеет юридической силы для реального обращения в государственные органы, суд, организации или иные учреждения и не заменяет помощь квалифицированного юриста. Перед реальным обращением рекомендуем проконсультироваться с юристом.";
  if(/штраф|полици|гибдд|дпс|административ/.test(q))return "Коротко\\nДля административной ситуации важны конкретное событие, дата, составленный документ и орган, который его вынес.\\n\\nПришли своими словами: что произошло, какой документ получил и когда. Персональные данные можно удалить.\\n\\nДисклеймер: Ответ Cat Lawyer носит исключительно информационно-консультационный характер, не является юридическим заключением, не имеет юридической силы для реального обращения в государственные органы, суд, организации или иные учреждения и не заменяет помощь квалифицированного юриста. Перед реальным обращением рекомендуем проконсультироваться с юристом.";
  return "Коротко\\nЯ могу разобрать ситуацию, но для точного юридического ответа нужны факты.\\n\\nОпиши: что произошло, когда это было, с кем возник спор и чего ты хочешь добиться. Не отправляй паспортные данные, банковские реквизиты и другие чувствительные сведения.\\n\\nПосле этого определим возможные права, порядок действий и подходящий способ обращения.\\n\\nДисклеймер: Ответ Cat Lawyer носит исключительно информационно-консультационный характер, не является юридическим заключением, не имеет юридической силы для реального обращения в государственные органы, суд, организации или иные учреждения и не заменяет помощь квалифицированного юриста. Перед реальным обращением рекомендуем проконсультироваться с юристом.";
}
async function ensureAuthSchema(db){
  await db.prepare("CREATE TABLE IF NOT EXISTS cl_auth_users (id TEXT PRIMARY KEY,name TEXT NOT NULL,email TEXT NOT NULL UNIQUE COLLATE NOCASE,password_hash TEXT NOT NULL,password_salt TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,plan TEXT NOT NULL DEFAULT 'Базовый')").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS cl_auth_sessions (token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL,expires_at INTEGER NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)").run();
  const info=async t=>(await db.prepare("PRAGMA table_info("+t+")").all()).results||[];
  const add=async(t,n,d)=>{if(!(await info(t)).some(x=>x.name===n))await db.prepare("ALTER TABLE "+t+" ADD COLUMN "+n+" "+d).run()};
  await add("cl_auth_users","name","TEXT DEFAULT ''");
  await add("cl_auth_users","email","TEXT DEFAULT ''");
  await add("cl_auth_users","password_hash","TEXT DEFAULT ''");
  await add("cl_auth_users","password_salt","TEXT DEFAULT ''");
  await add("cl_auth_users","created_at","TEXT DEFAULT ''");
  await add("cl_auth_users","plan","TEXT DEFAULT 'Базовый'");
  await add("cl_auth_sessions","token_hash","TEXT DEFAULT ''");
  await add("cl_auth_sessions","user_id","TEXT DEFAULT ''");
  await add("cl_auth_sessions","expires_at","INTEGER DEFAULT 0");
  await add("cl_auth_sessions","created_at","TEXT DEFAULT ''");
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

  await db.prepare("CREATE TABLE IF NOT EXISTS learn_progress (user_id TEXT PRIMARY KEY,completed INTEGER DEFAULT 0,score INTEGER DEFAULT 0,lesson_no INTEGER DEFAULT 0,xp INTEGER DEFAULT 0,state_json TEXT DEFAULT '',plan_json TEXT DEFAULT '',created_at TEXT DEFAULT CURRENT_TIMESTAMP,updated_at TEXT DEFAULT CURRENT_TIMESTAMP)").run();
  await add("learn_progress","completed","INTEGER DEFAULT 0");
  await add("learn_progress","score","INTEGER DEFAULT 0");
  await add("learn_progress","lesson_no","INTEGER DEFAULT 0");
  await add("learn_progress","xp","INTEGER DEFAULT 0");
  await add("learn_progress","state_json","TEXT DEFAULT ''");
  await add("learn_progress","plan_json","TEXT DEFAULT ''");
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
  if(p==="/api/health"&&r.method==="GET"){
    return json({ok:true,db:!!e.DB,ai:!!e.ai});
  }
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
        await e.DB.prepare("INSERT INTO cl_auth_users(id,name,email,password_hash,password_salt,plan) VALUES(?,?,?,?,?,?)").bind(id,name,email,hash,salt,"Базовый").run();
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
      const b=await r.json(),email=String(b.email||"").trim().toLowerCase(),pw=String(b.password||""),u=await e.DB.prepare("SELECT * FROM cl_auth_users WHERE email=?").bind(email).first();
      if(!u||!u.password_salt||await passHash(pw,u.password_salt)!==u.password_hash)return json({error:"Неверная почта или пароль."},401);
      return json({user:{id:u.id,name:u.name,email:u.email}},200,{"Set-Cookie":await session(e,u.id)});
    }
    if(p==="/api/auth/delete"&&r.method==="POST"){
      const u=await userFor(r,e);if(!u)return json({error:"Требуется вход."},401);
      await e.DB.batch([e.DB.prepare("DELETE FROM cl_auth_sessions WHERE user_id=?").bind(u.id),e.DB.prepare("DELETE FROM conversations WHERE user_id=?").bind(u.id),e.DB.prepare("DELETE FROM learn_progress WHERE user_id=?").bind(u.id),e.DB.prepare("DELETE FROM cl_auth_users WHERE id=?").bind(u.id)]);
      return json({ok:true},200,{"Set-Cookie":clearCookie()});
    }
    if(p==="/api/auth/logout"&&r.method==="POST"){
      const t=tokenFrom(r);if(t)await e.DB.prepare("DELETE FROM cl_auth_sessions WHERE token_hash=?").bind(await digest(t)).run();
      return json({ok:true},200,{"Set-Cookie":clearCookie()});
    }
    if(p==="/api/auth/me"&&r.method==="GET")return json({user:await userFor(r,e)});
    if(p==="/api/plan"&&r.method==="GET"){
      const u=await userFor(r,e);if(!u)return json({error:"Требуется вход."},401);
      const row=await e.DB.prepare("SELECT plan FROM cl_auth_users WHERE id=?").bind(u.id).first();return json({plan:row?.plan||null});
    }
    if(p==="/api/plan"&&r.method==="POST"){
      const u=await userFor(r,e);if(!u)return json({error:"Требуется вход."},401);
      const plan=String((await r.json()).plan||"").trim(),allowed=["Базовый","Расширенный","Максимальный"];
      if(!allowed.includes(plan))return json({error:"Неизвестный тариф."},400);
      await e.DB.prepare("UPDATE cl_auth_users SET plan=? WHERE id=?").bind(plan,u.id).run();return json({plan});
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
      let reply,aiAvailable=true;
      try{
        reply=await aiText(e,[{role:"system",content:"Ты Cat Lawyer — юридический информационный помощник по действующему законодательству Российской Федерации на дату запроса. Главный приоритет — юридическая точность, а не уверенный тон. Не выдумывай статьи, сроки, судебную практику или факты. Различай товар надлежащего качества, недостаток товара и дистанционную покупку. Если фактов недостаточно — задай до трёх уточняющих вопросов. Не называй конкретную статью, если не уверен в её номере и содержании. Отвечай естественно и по-русски. Если данных достаточно, используй разделы: Коротко; Что может быть нарушено; Что делать; Куда обращаться; Что подготовить; Важно. В конце добавь дисклеймер о том, что ответ носит информационно-консультационный характер и не заменяет квалифицированного юриста."},{role:"user",content:m}],420);
        if(!validateAiReply(m,reply))throw new Error("AI response failed legal safety validation");
      }catch(aiErr){
        console.error("Cat Lawyer Workers AI unavailable, using safe fallback",aiErr);
        aiAvailable=false;
        reply=fallbackLegalReply(m);
      }
      try{const u=await userFor(r,e);if(u)await e.DB.prepare("INSERT INTO conversations(id,user_id,message,reply) VALUES(?,?,?,?)").bind(crypto.randomUUID(),u.id,m,reply).run()}catch(historyErr){console.error("Cat Lawyer history save failed",historyErr)}
      return json({reply,ai:aiAvailable});
    }
    if(p==="/api/documents"&&r.method==="POST"){
      if(limited(r,"documents:"+requestIP(r),10,60000))return json({error:"Слишком много запросов. Попробуйте позже."},429);
      const b=await r.json(),type=String(b.type||"Обращение").trim(),situation=String(b.situation||"").trim();
      if(!["Претензия","Жалоба","Заявление","Обращение"].includes(type)||situation.length<10||situation.length>10000)return json({error:"Проверь тип документа и описание ситуации."},400);
      let document;
      try{
        document=await aiText(e,[{role:"system",content:"Ты помощник Cat Lawyer. Составляй только информационный черновик документа по законодательству РФ. Тип документа: "+type+". Не выдумывай ФИО, адреса, номера, даты, организации, статьи, сроки или факты. Если норма или срок не подтверждены исходными данными, не утверждай их как факт. Недостающие сведения обозначай квадратными скобками: [указать]. Структура должна быть пригодна для дальнейшей проверки человеком. В конце добавь короткую пометку, что документ нужно проверить перед отправкой."},{role:"user",content:situation}],1200);
        if(!validateAiReply(situation,document))throw new Error("Generated document failed legal safety validation");
      }catch(err){
        console.error("Cat Lawyer document generation failed validation",err);
        document="ЧЕРНОВИК ДОКУМЕНТА\n\nТип: "+type+"\n\nОписание ситуации:\n"+situation+"\n\nТребования:\n[указать, чего именно вы просите]\n\nПриложения:\n[указать документы и доказательства]\n\nВажно: этот шаблон требует заполнения и проверки по актуальному законодательству РФ перед отправкой.";
      }
      return json({type,document});
    }
    if(p==="/api/learn/calibrate"&&r.method==="POST"){
      if(limited(r,"learn-calibrate:"+requestIP(r),20,60000))return json({error:"Слишком много диагностических запросов."},429);
      const b=await r.json(),question=String(b.question||"").slice(0,3000),context=String(b.context||"").slice(0,3000),answer=String(b.answer||"").slice(0,10000),expected=String(b.expected||"").slice(0,3000);
      if(answer.length<30||!question)return json({error:"Недостаточно данных для анализа."},400);
      let analysis;
      try{
        const raw=await aiText(e,[{role:"system",content:"Ты диагностический методист юридической академии РФ. Оцени ответ студента по юридическому мышлению: выделение юридически значимых фактов, квалификация, последовательность анализа, понимание нормы, доказательства и осторожность вывода. Не требуй дословного совпадения с эталоном. Верни только JSON: {score:0-100,level:'начальный'|'базовый'|'средний'|'продвинутый',strengths:string[],weaknesses:string[],skills:string[],feedback:string,nextFocus:string}."},{role:"user",content:"Вопрос: "+question+"\nКонтекст: "+context+"\nЭталонная логика: "+expected+"\nОтвет студента: "+answer}],650);
        analysis=JSON.parse(raw.replace(/^\s*```json\s*/,"").replace(/\s*```\s*$/,"") );analysis.score=Math.max(0,Math.min(100,Number(analysis.score)||0));
        if(!Array.isArray(analysis.weaknesses))analysis.weaknesses=[];if(!Array.isArray(analysis.strengths))analysis.strengths=[];if(!Array.isArray(analysis.skills))analysis.skills=[];
      }catch(err){analysis={score:50,level:"средний",strengths:[],weaknesses:["AI-анализ временно недоступен"],skills:[question],feedback:expected,nextFocus:"Повторить ключевую логику темы."}}
      return json({analysis});
    }
    if(p==="/api/learn/profile"&&r.method==="POST"){
      if(limited(r,"learn-profile:"+requestIP(r),6,60000))return json({error:"Слишком много анализов профиля. Подожди немного."},429);
      const u=await userFor(r,e);
      const b=await r.json(),profile=b.profile||{},results=Array.isArray(b.results)?b.results.slice(0,30):[];
      if(!results.length)return json({error:"Нет результатов диагностики."},400);
      const education=String(profile.type||"").slice(0,40),course=Math.max(1,Math.min(6,Number(profile.course)||1));
      const prompt="Построй индивидуальную карту юридических знаний студента. Профиль: "+education+", курс "+course+", самооценка "+String(profile.level||"")+" . Результаты диагностики: "+JSON.stringify(results)+". Проанализируй фактический уровень, освоенные навыки, пробелы, повторяющиеся ошибки, нужную глубину и уверенность вывода. Не делай уровень только по номеру курса. Для письменных ответов учитывай качество юридического рассуждения; для MCQ — паттерн правильных и неправильных ответов. Верни только JSON: {level,confidence,summary,mastery,weakSkills,strongSkills,errorPatterns,nextFocus,difficultyCeiling,lessonMix}. "
      let out;
      try{
        const raw=await aiText(e,[{role:"system",content:"Ты методист юридической академии. Анализируй реальные ответы, а не самооценку. Возвращай только JSON."},{role:"user",content:prompt}],1000);
        out=JSON.parse(raw.replace(/^\s*```json\s*/,"").replace(/\s*```\s*$/,""));
      }catch(err){
        out={level:"средний",confidence:35,summary:"AI-анализ профиля временно неполный.",mastery:{},weakSkills:results.flatMap(x=>x.weaknesses||[]).slice(0,10),strongSkills:results.flatMap(x=>x.strengths||[]).slice(0,10),errorPatterns:[],nextFocus:"Повторить навыки, где были ошибки.",difficultyCeiling:"средняя",lessonMix:{mcq:8,free:6,case:6}};
      }
      out.updatedAt=new Date().toISOString();
      if(u){try{await e.DB.prepare("CREATE TABLE IF NOT EXISTS learn_profiles (user_id TEXT PRIMARY KEY,profile_json TEXT NOT NULL,updated_at TEXT DEFAULT CURRENT_TIMESTAMP)").run();await e.DB.prepare("INSERT INTO learn_profiles(user_id,profile_json) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET profile_json=excluded.profile_json,updated_at=CURRENT_TIMESTAMP").bind(u.id,JSON.stringify(out)).run()}catch(err){console.error("Learn profile save failed",err)}}
      return json({profile:out});
    }
    if(p==="/api/learn/evaluate"&&r.method==="POST"){
      if(limited(r,"learn-evaluate:"+requestIP(r),20,60000))return json({error:"Слишком много проверок."},429);
      const b=await r.json(),lesson=b.lesson||{},answer=String(b.answer||"").slice(0,10000),subject=String(b.subject||lesson.subject||"").slice(0,120);
      if(answer.length<30||!lesson.question)return json({error:"Недостаточно данных для проверки."},400);
      let analysis;
      try{
        const raw=await aiText(e,[{role:"system",content:"Ты сильный преподаватель юридической академии РФ и внимательный проверяющий. Твоя задача — реально оценить мышление студента, а не просто похвалить его. Сначала мысленно выдели: 1) что именно требовалось установить, 2) какие юридически значимые факты нужны, 3) какое правило/правоотношение применимо, 4) к какому выводу ведут факты. Затем сравни с ответом студента. Не требуй дословного совпадения с эталоном и засчитывай юридически эквивалентные формулировки. Одновременно не засчитывай пустые общие фразы, уверенный ответ без нужных фактов или случайно угаданный вывод. Если ответ частично правильный, дай промежуточную оценку, а не 0 или 100. Если студент ошибся, спокойно и конкретно объясни, где именно ошибка и как рассуждать правильно. Не выдумывай нормы и не называй статью, если её нет в задании или ты не уверен. Обратная связь должна звучать естественно, по-русски, как комментарий преподавателя: 2–5 предложений, без шаблонного «хороший ответ». Верни только JSON: {score:0-100,correct:boolean,feedback:string,strengths:string[],weaknesses:string[],nextSkill:string}."},{role:"user",content:"Предмет: "+subject+"\nЗадание: "+JSON.stringify(lesson)+"\nОтвет студента: "+answer}],650);
        analysis=JSON.parse(raw.replace(/^\s*```json\s*/,"").replace(/\s*```\s*$/,"") );analysis.score=Math.max(0,Math.min(100,Number(analysis.score)||0));analysis.correct=analysis.score>=60;
      }catch(err){analysis={score:50,correct:false,feedback:"Не удалось автоматически оценить ответ. Сверь его с эталонной логикой задания.",strengths:[],weaknesses:["Автоматическая проверка недоступна"],nextSkill:"Повторить тему задания."}}
      return json({analysis});
    }
    if(p==="/api/learn/plan"&&r.method==="POST"){
      if(limited(r,"learn-plan:"+requestIP(r),8,60000))return json({error:"Слишком много запросов. Подожди немного и попробуй снова."},429);
      const u=await userFor(r,e);
      const b=await r.json(),profile=b.profile||{},subjects=Array.isArray(b.subjects)?b.subjects.map(x=>String(x).slice(0,80)).slice(0,12):[];
      if(!subjects.length)return json({error:"Выбери хотя бы один предмет."},400);
      let sourceStatus={officialPortal:"https://pravo.gov.ru/",checkedAt:new Date().toISOString(),reachable:false};
      try{
        const sr=await fetch("https://www.pravo.gov.ru/",{method:"GET",headers:{"User-Agent":"Cat-Lawyer-Legal-Source-Check/1.0"}});
        sourceStatus.reachable=sr.ok;
        sourceStatus.status=sr.status;
      }catch(err){sourceStatus.error="Портал не ответил при этой проверке";}
      const prompt="Составь персональный учебный план Cat Lawyer по действующему законодательству РФ. Профиль: "+JSON.stringify(profile)+"; диагностические ответы: "+JSON.stringify(profile.diagnostics||[])+"; выбранные предметы: "+subjects.join(", ")+". Официальный контрольный источник: https://pravo.gov.ru/ . Сегодня: "+new Date().toISOString().slice(0,10)+". Не выдумывай нормы. Если номер статьи или содержание нормы не уверенны, не указывай их как факт и пометь тему для проверки. План должен быть адаптивным: не повторяй освоенные навыки без причины; слабые навыки из диагностики получают больше практики и повторений, сильные переводятся на более сложные кейсы. Каждый следующий день должен учитывать предыдущие ошибки. 5 учебных дней, каждый день 2-3 шага, чередовать теорию, тест, свободный ответ и практический кейс с клиентом. Для каждого шага укажи subject,title,type(mcq/free/case),skill,difficulty. Верни только JSON: {summary,days:[{day,focus,lessons:[...]}],sources:[{name,url,why}]}";
      let plan;
      try{
        const raw=await aiText(e,[{role:"system",content:"Ты методист юридической академии. Генерируй только валидный JSON без markdown. Юридическая точность важнее полноты."},{role:"user",content:prompt}],1400);
        plan=JSON.parse(raw.replace(/^\s*\`\`\`json\s*/,"").replace(/\s*\`\`\`\s*$/,""));
      }catch(err){
        console.error("Learn plan generation failed",err);
        plan={summary:"Базовый адаптивный маршрут",days:subjects.slice(0,5).map((s,n)=>({day:n+1,focus:s,lessons:[{subject:s,title:"Теория и ключевые понятия",type:"mcq",skill:"понимание нормы",difficulty:"средняя"},{subject:s,title:"Практический кейс",type:"case",skill:"квалификация ситуации",difficulty:"средняя"},{subject:s,title:"Ответ своими словами",type:"free",skill:"юридическая формулировка",difficulty:"средняя"}]})),sources:[{name:"Официальный интернет-портал правовой информации",url:"https://pravo.gov.ru/",why:"официальный источник опубликованных правовых актов и текстов с изменениями"}]};
      }
      plan.sourceCheck=sourceStatus;
      plan.generatedAt=new Date().toISOString();
      if(u){try{await e.DB.prepare("CREATE TABLE IF NOT EXISTS learn_plans (user_id TEXT PRIMARY KEY,plan_json TEXT NOT NULL,updated_at TEXT DEFAULT CURRENT_TIMESTAMP)").run();await e.DB.prepare("INSERT INTO learn_plans(user_id,plan_json) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET plan_json=excluded.plan_json,updated_at=CURRENT_TIMESTAMP").bind(u.id,JSON.stringify(plan)).run()}catch(err){console.error("Learn plan save failed",err)}}
      return json({plan});
    }
    if(p==="/api/learn/lesson"&&r.method==="POST"){
      if(limited(r,"learn-lesson:"+requestIP(r),15,60000))return json({error:"Слишком много запросов. Подожди немного и попробуй снова."},429);
      const u=await userFor(r,e);
      const b=await r.json(),subject=String(b.subject||"").slice(0,100),skill=String(b.skill||"").slice(0,180),difficulty=String(b.difficulty||"средняя").slice(0,40),type=String(b.type||"mcq").slice(0,20);
      if(!subject)return json({error:"Не указан предмет."},400);
      const profile=b.profile||{},education=String(profile.type||"").slice(0,40),course=Math.max(1,Math.min(6,Number(profile.course)||1)),level=String(profile.level||difficulty).slice(0,40),recent=Array.isArray(b.recentQuestions)?b.recentQuestions.slice(-18):[],aiProfile=profile.aiProfile&&typeof profile.aiProfile==="object"?profile.aiProfile:null;
      const uni=education==="Университет";
      const stage=uni?(course>=5?"старшие курсы: углублённый анализ, конкуренция норм, аргументация, доказательства и сложные кейсы":course>=3?"средние курсы: системное применение норм, квалификация, доказательства и процедура":"младшие курсы: базовые институты, понятия и их применение"):(course>=3?"старшие курсы СПО: практическая квалификация, документы, процедуры и кейсы":"младшие курсы СПО: фундаментальные понятия и простое применение");
      const prompt="Создай ОДНО НОВОЕ задание для обучения праву РФ по предмету «"+subject+"». Профиль: "+education+", курс "+course+", самооценка "+level+". AI-карта знаний: "+JSON.stringify(aiProfile||{})+". Уровень программы: "+stage+". Навык текущего урока: "+skill+", сложность: "+difficulty+", тип: "+type+", урок №"+String(b.lessonNo||0)+". Диагностика: "+JSON.stringify(b.diagnostics||[])+". Последние вопросы: "+JSON.stringify(recent)+". НИКОГДА не повторяй последние вопросы, их фабулу, ключевую формулировку или тот же набор ответов. Если AI-карта показывает слабый навык — дай больше практики именно по нему; если навык устойчиво освоен — подними сложность и измени тип рассуждения. Не делай уровень только по номеру курса. Для 2 курса СПО используй прикладные документы, типовые процедуры и понятные ситуации; для 5–6 курса университета — сложные квалификации, конкуренцию норм, доказательственные риски, процессуальную стратегию и контраргументы, но только если карта знаний это подтверждает. Меняй юридическую проблему, факты, субъектов, документы и способ проверки. Не используй снова шаблон «клиент спросил статью». Используй только нормы и принципы, в которых уверен; если номер статьи сомнителен, не выдумывай его. Официальный контрольный источник: https://pravo.gov.ru/. Для mcq создай ровно 4 варианта одинаковой длины и детализации; правильный вариант не должен выделяться. Для free дай вопрос, эталонную логику и критерии проверки. Для case создай реальную сцену клиента: имя клиента, описание входа в кабинет, юридический вопрос, конкретные документы по делу и текст каждого документа. Документы должны соответствовать уровню студента: младшие курсы — простые документы с понятными реквизитами; старшие — договоры, претензии, постановления, переписка или процессуальные документы с юридически значимыми деталями. Не вставляй в документы готовый ответ на задачу. Для case верни client:{name,entry,task,documents:[{name,type,text}]}. Верни только JSON с полями type,subject,question,context,answers,correct,explanation,trap,sourceNote,client.";      let item;
      try{
        const raw=await aiText(e,[{role:"system",content:"Ты преподаватель права и редактор юридических учебных материалов. Верни только валидный JSON."},{role:"user",content:prompt}],900);
        item=JSON.parse(raw.replace(/^\s*\`\`\`json\s*/,"").replace(/\s*\`\`\`\s*$/,""));
        const audit=await aiText(e,[{role:"system",content:"Проверь учебное задание как строгий редактор юридического экзамена. Верни только JSON: {ok:boolean,issues:string[],fix:string}. Считай ошибкой выдуманную статью, неверное правило, слишком однозначный вывод без фактов, повторяющуюся подсказку в вариантах или вариант ответа, который заметно длиннее/детальнее остальных и поэтому выдаёт правильный ответ. Для mcq сравни длину и структуру всех вариантов. Для case проверь наличие конкретного клиента и хотя бы одного содержательного документа, соответствующего фабуле и уровню студента; документ не должен содержать готовый ответ."},{role:"user",content:JSON.stringify(item)}],500);
        const a=JSON.parse(audit.replace(/^\s*\`\`\`json\s*/,"").replace(/\s*\`\`\`\s*$/,""));
        if(!a.ok){throw new Error("AI legal audit failed: "+(a.issues||[]).join("; "))}
        item.audit={ok:true,checkedAt:new Date().toISOString()};
      }catch(err){
        console.error("Learn lesson generation failed",err);
        item={type,subject,question:"Разбери ситуацию по юридической цепочке: факты → юридически значимые признаки → применимое правило → последствие.",context:"Сформулируй, каких фактов тебе не хватает и почему без них нельзя делать окончательный вывод.",answers:[],correct:"Сначала установить факты и применимость нормы; не делать категоричный вывод без проверки актуального источника.",explanation:"Юрист не угадывает статью по одному слову: он проверяет обстоятельства и источник.",trap:"Не путай правдоподобную бытовую логику с юридическим выводом.",sourceNote:"Проверь актуальную редакцию нормы на https://pravo.gov.ru/.",client:type==="case"?{name:"Антон Сергеевич",entry:"Клиент заходит в кабинет и передаёт папку с материалами.",task:"Определи юридически значимые факты и порядок дальнейшей проверки.",documents:[{name:"Письмо клиента",type:"Письмо",text:"Прошу оценить мою ситуацию и указать, какие документы и обстоятельства нужно проверить перед выводом."}]}:null,audit:{ok:false,checkedAt:new Date().toISOString()}};
      }
      return json({lesson:item});
    }
    if(p==="/api/learn/progress"&&r.method==="GET"){
      const u=await userFor(r,e);if(!u)return json({error:"Требуется вход."},401);
      const row=await e.DB.prepare("SELECT completed,score,lesson_no,xp,state_json,plan_json,updated_at FROM learn_progress WHERE user_id=?").bind(u.id).first();
      return json({
        completed:row?.completed||0,
        score:row?.score||0,
        lessonNo:row?.lesson_no||0,
        xp:row?.xp||0,
        state:row?.state_json?JSON.parse(row.state_json):null,
        plan:row?.plan_json?JSON.parse(row.plan_json):null,
        updatedAt:row?.updated_at||null
      });
    }
    if(p==="/api/learn/progress"&&r.method==="POST"){
      const u=await userFor(r,e);if(!u)return json({error:"Требуется вход."},401);
      const b=await r.json();
      const completed=Math.max(0,Math.min(100,Number(b.completed)||0));
      const score=Math.max(0,Math.min(100,Number(b.score)||0));
      const lessonNo=Math.max(0,Math.min(10000,Number(b.lessonNo)||0));
      const xp=Math.max(0,Math.min(1000000,Number(b.xp)||0));
      const stateJson=JSON.stringify(b.state&&typeof b.state==="object"?b.state:{});
      const planJson=JSON.stringify(b.plan&&typeof b.plan==="object"?b.plan:null);
      await e.DB.prepare("INSERT INTO learn_progress(user_id,completed,score,lesson_no,xp,state_json,plan_json) VALUES(?,?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET completed=excluded.completed,score=excluded.score,lesson_no=excluded.lesson_no,xp=excluded.xp,state_json=excluded.state_json,plan_json=excluded.plan_json,updated_at=CURRENT_TIMESTAMP").bind(u.id,completed,score,lessonNo,xp,stateJson,planJson).run();
      return json({completed,score,lessonNo,xp});
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
        const [u,c,v]=await Promise.all([e.DB.prepare("SELECT COUNT(*) n FROM cl_auth_users").first(),e.DB.prepare("SELECT COUNT(*) n FROM conversations").first(),e.DB.prepare("SELECT COUNT(*) n FROM reviews").first()]);
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
