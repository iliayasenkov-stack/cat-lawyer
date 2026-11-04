import {json,whoami} from "../_shared/auth.js";
export async function onRequestPost({request,env}){
 try{
  const b=await request.json(),message=String(b.message||"").trim();
  if(!message||message.length>5000)return json({error:"Сообщение пустое или слишком длинное."},400);
  if(!env.ai)return json({error:"Workers AI не подключён к Pages."},503);
  const result=await env.ai.run("@cf/meta/llama-3.1-8b-instruct",{
   messages:[
    {role:"system",content:"Ты — Cat Lawyer, юридический информационный помощник по праву Российской Федерации. Отвечай на русском, естественно и профессионально, но доступно. Не используй одинаковый шаблон в каждом ответе. Учитывай уже сообщённые детали и не спрашивай их повторно. Если данных недостаточно, задай 1–3 конкретных уточняющих вопроса. Называй точные нормы только если уверен в их существовании и применимости; не выдумывай статьи, сроки, практику или адреса. Отделяй факты от предположений. Если актуальность нормы не подтверждена, укажи, что её нужно проверить по официальному источнику. Объясняй возможные права, следующие шаги и куда обратиться. Не выдавай ответ за юридическое заключение и не проси лишние персональные данные."},
    {role:"user",content:message}
   ],max_tokens:900,temperature:0.65
  });
  const reply=result.response||"Не удалось подготовить ответ.";
  if(env.DB){try{const user=await whoami(request,env.DB);if(user)await env.DB.prepare("INSERT INTO conversations(id,user_id,message,reply) VALUES(?,?,?,?)").bind(crypto.randomUUID(),user.id,message,reply).run();}catch{}}
  return json({reply});
 }catch{return json({error:"Не удалось обработать запрос. Попробуйте ещё раз."},500);}
}