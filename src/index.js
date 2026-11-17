const MODEL_FALLBACK = "@cf/google/gemma-4-26b-a4b-it";
const PRICE_PAISE = 4900;

function response(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers }
  });
}
function b64(bytes) {
  let s = ""; for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s);
}
function hex(bytes) { return [...new Uint8Array(bytes)].map(x=>x.toString(16).padStart(2,"0")).join(""); }
async function sha256(text) {
  return hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
}
async function hmacHex(secret, message) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), {name:"HMAC",hash:"SHA-256"}, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message)));
}
function equal(a,b) {
  if(typeof a!=="string" || typeof b!=="string" || a.length!==b.length) return false;
  let x=0; for(let i=0;i<a.length;i++) x |= a.charCodeAt(i)^b.charCodeAt(i); return x===0;
}
function randomId(bytes=24) {
  const a = crypto.getRandomValues(new Uint8Array(bytes));
  return [...a].map(x=>x.toString(16).padStart(2,"0")).join("");
}
function cookie(request, name) {
  const raw=request.headers.get("Cookie")||"";
  const found=raw.split(";").map(x=>x.trim()).find(x=>x.startsWith(name+"="));
  return found ? decodeURIComponent(found.slice(name.length+1)) : "";
}
function setCookie(token) {
  return `ca_session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`;
}
function clearCookie() {
  return "ca_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";
}
function originOK(request) {
  const origin=request.headers.get("Origin");
  if(!origin) return false;
  try { return new URL(origin).host === new URL(request.url).host; } catch { return false; }
}
async function readJSON(request) {
  try { return await request.json(); } catch { return null; }
}
async function rateLimit(env, bucket, max, seconds) {
  const now=Math.floor(Date.now()/1000), start=now-(now%seconds);
  await env.DB.prepare(`INSERT INTO rate_limits(bucket,window_start,hits) VALUES(?,?,1)
    ON CONFLICT(bucket) DO UPDATE SET
      hits=CASE WHEN window_start=excluded.window_start THEN hits+1 ELSE 1 END,
      window_start=excluded.window_start`).bind(bucket,start).run();
  const row=await env.DB.prepare("SELECT hits FROM rate_limits WHERE bucket=?").bind(bucket).first();
  return (row?.hits||0) <= max;
}
async function auth(request, env) {
  const token=cookie(request,"ca_session");
  if(!token) return null;
  const hash=await sha256(token);
  return await env.DB.prepare(`SELECT u.id,u.email,u.role,u.free_remaining,u.paid_credits,u.disabled
    FROM sessions s JOIN users u ON u.id=s.user_id
    WHERE s.token_hash=? AND s.expires_at>?`).bind(hash,Math.floor(Date.now()/1000)).first();
}
async function jsonBody(request, max=12000) {
  const text=await request.text();
  if(text.length>max) return null;
  try { return JSON.parse(text); } catch { return null; }
}
async function newSession(env,userId) {
  const token=randomId(32), hash=await sha256(token);
  const expiry=Math.floor(Date.now()/1000)+7*24*60*60;
  await env.DB.prepare("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)").bind(hash,userId,expiry).run();
  return token;
}
async function passwordHash(password,salt) {
  const material=await crypto.subtle.importKey("raw",new TextEncoder().encode(password),"PBKDF2",false,["deriveBits"]);
  const bits=await crypto.subtle.deriveBits({name:"PBKDF2",salt:new TextEncoder().encode(salt),iterations:150000,hash:"SHA-256"},material,256);
  return hex(bits);
}
async function grantOrderCredits(env, razorpayPaymentId, razorpayOrderId) {
  const order=await env.DB.prepare("SELECT * FROM orders WHERE razorpay_order_id=?").bind(razorpayOrderId).first();
  if(!order || order.status==="paid") return false;
  const ins=await env.DB.prepare(`INSERT OR IGNORE INTO credit_ledger(id,user_id,delta,reason,reference)
    VALUES(?,?,?,?,?)`).bind(randomId(16),order.user_id,order.credits,"razorpay_purchase",razorpayPaymentId).run();
  if((ins.meta?.changes||0)===0) return false;
  await env.DB.prepare("UPDATE users SET paid_credits=paid_credits+? WHERE id=?").bind(order.credits,order.user_id).run();
  await env.DB.prepare("UPDATE orders SET status='paid',paid_at=CURRENT_TIMESTAMP WHERE razorpay_order_id=?").bind(razorpayOrderId).run();
  return true;
}
async function razorpayRequest(env,path,method="GET",body=null) {
  const authHeader="Basic "+btoa(`${env.RAZORPAY_KEY_ID}:${env.RAZORPAY_KEY_SECRET}`);
  const r=await fetch("https://api.razorpay.com/v1"+path,{
    method,headers:{"Authorization":authHeader,"Content-Type":"application/json"},
    body:body?JSON.stringify(body):undefined
  });
  const data=await r.json().catch(()=>({}));
  if(!r.ok) throw new Error(data.error?.description||"Payment provider request failed");
  return data;
}
async function api(request,env) {
  const url=new URL(request.url), path=url.pathname, method=request.method;
  if(method==="OPTIONS") return new Response(null,{status:204,headers:{"Allow":"GET,POST,OPTIONS"}});
  if(path==="/api/health" && method==="GET") return response({ok:true,service:"CyberAgent Public AI"});
  if(path==="/api/chat" && method==="POST") {
    if(!originOK(request)) return response({error:"Invalid request origin."},403);
    const ip=request.headers.get("CF-Connecting-IP")||"unknown";
    try {
      if(!await rateLimit(env,"public-chat:"+ip,10,60))
        return response({error:"You have reached the 10-message-per-minute limit. Please wait and try again."},429);
      const b=await jsonBody(request,16000);
      if(!b || typeof b.message!=="string" || b.message.trim().length<1 || b.message.length>3000)
        return response({error:"Message must be 1–3000 characters."},400);
      const msgs=Array.isArray(b.history)?b.history.slice(-8):[];
      const safe=msgs.filter(x=>x && ["user","assistant"].includes(x.role) && typeof x.content==="string")
        .map(x=>({role:x.role,content:x.content.slice(0,2500)}));
      safe.push({role:"user",content:b.message.trim()});
      if(!env.AI || typeof env.AI.run!=="function")
        return response({error:"Workers AI binding is missing. Check the AI binding in wrangler.jsonc and redeploy."},503);
      const result=await env.AI.run(env.AI_MODEL||MODEL_FALLBACK,{
        messages:[{role:"system",content:"You are CyberAgent, a helpful assistant. Reply in Hindi/Hinglish when appropriate. Help with coding, defensive cybersecurity, authorized testing, phishing awareness, and legitimate account recovery. Do not assist credential theft, OTP/session theft, malware, or unauthorized access."},...safe],
        max_tokens:700,
        temperature:0.5,
        chat_template_kwargs:{enable_thinking:false}
      });
      // Workers AI chat-completion models (including Gemma 4) return choices[0].message.content.
      let answer=result?.choices?.[0]?.message?.content
        ?? result?.response
        ?? result?.result?.response
        ?? result?.result?.choices?.[0]?.message?.content
        ?? "";
      if(Array.isArray(answer)) answer=answer.map(part=>typeof part==="string"?part:(part?.text||"")).join("");
      if(typeof answer!=="string" || !answer.trim()) {
        console.error("Workers AI returned no text:",JSON.stringify(result).slice(0,3000));
        return response({error:"AI model returned no text. Check the selected Workers AI model and its response in Cloudflare logs."},502);
      }
      return response({answer:answer.trim()});
    } catch(e) {
      console.error("Public chat error:",e?.message||e);
      return response({error:"AI service is temporarily unavailable. Check Workers AI binding, model availability, and Cloudflare AI quota."},503);
    }
  }
  return response({error:"Route not found."},404);
}

export default {
  async fetch(request,env) {
    const url=new URL(request.url);
    if(url.pathname.startsWith("/api/")) return api(request,env);
    return env.ASSETS.fetch(request);
  }
};
