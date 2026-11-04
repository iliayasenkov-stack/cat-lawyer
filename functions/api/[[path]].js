import {json,hashPassword,makeSession,whoami,endSession,to64} from "../_shared/auth.js";
async function ensureSchema(db){
 await db.prepare("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY,name TEXT NOT NULL,email TEXT NOT NULL UNIQUE COLLATE NOCASE,password_hash TEXT NOT NULL,password_salt TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)").run();
 await db.prepare("CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires_at INTEGER NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)").run();
 await db.prepare("CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id)").run();
 await db.prepare("CREATE TABLE IF NOT EXISTS conversations (id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,message TEXT NOT NULL,reply TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)").run();
 await db.prepare("CREATE INDEX IF NOT EXISTS conversations_user_created_idx ON conversations(user_id,created_at DESC)").run();
}
export async function onRequest({request,env}){
 if(!env.DB)return json({error:"Серверная база данных пока не подключена."},503);
 try{
  await ensureSchema(env.DB);
  const path=new URL(request.url).pathname;
  if(path==="/api/auth/register"&&request.method==="POST"){
   const b=await request.json(),name=String(b.name||"").trim().slice(0,80),email=String(b.email||"").trim().toLowerCase(),password=String(b.password||"");
   if(name.length<2||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||password.length<10||password.length>128)return json({error:"Укажите имя, корректную почту и пароль от 10 до 128 символов."},400);
   const salt=to64(crypto.getRandomValues(new Uint8Array(16))),password_hash=await hashPassword(password,salt),id=crypto.randomUUID();
   try{await env.DB.prepare("INSERT INTO users(id,name,email,password_hash,password_salt) VALUES(?,?,?,?,?)").bind(id,name,email,password_hash,salt).run();}catch{return json({error:"Аккаунт с такой почтой уже существует."},409);}
   return json({user:{id,name,email}},201,{"Set-Cookie":await makeSession(env.DB,id)});
  }
  if(path==="/api/auth/login"&&request.method==="POST"){
   const b=await request.json(),email=String(b.email||"").trim().toLowerCase(),password=String(b.password||""),u=await env.DB.prepare("SELECT * FROM users WHERE email=?").bind(email).first();
   if(!u||await hashPassword(password,u.password_salt)!==u.password_hash)return json({error:"Неверная почта или пароль."},401);
   return json({user:{id:u.id,name:u.name,email:u.email}},200,{"Set-Cookie":await makeSession(env.DB,u.id)});
  }
  if(path==="/api/auth/me"&&request.method==="GET")return json({user:await whoami(request,env.DB)});
  if(path==="/api/auth/logout"&&request.method==="POST")return json({ok:true},200,{"Set-Cookie":await endSession(request,env.DB)});
  if(path==="/api/history"){
   const u=await whoami(request,env.DB);if(!u)return json({error:"Требуется вход."},401);
   if(request.method==="GET"){const {results=[]}=await env.DB.prepare("SELECT id,message,reply,created_at FROM conversations WHERE user_id=? ORDER BY created_at DESC LIMIT 100").bind(u.id).all();return json({items:results});}
   if(request.method==="POST"){const b=await request.json(),message=String(b.message||"").trim(),reply=String(b.reply||"").trim();if(!message||message.length>5000||!reply||reply.length>12000)return json({error:"Некорректная запись."},400);const id=crypto.randomUUID();await env.DB.prepare("INSERT INTO conversations(id,user_id,message,reply) VALUES(?,?,?,?)").bind(id,u.id,message,reply).run();return json({id},201);}
  }
  return json({error:"Не найдено."},404);
 }catch{return json({error:"Не удалось обработать запрос."},500);}
}