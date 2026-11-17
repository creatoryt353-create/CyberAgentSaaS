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
  if(path==="/api/health" && method==="GET") return response({ok:true,service:"CyberAgent SaaS"});
  if(path==="/api/config" && method==="GET") return response({razorpayKeyId:env.RAZORPAY_KEY_ID||"",pricePaise:PRICE_PAISE,paidCredits:Number(env.PAID_CREDITS||50)});
  if(path==="/api/register" && method==="POST") {
    if(!originOK(request)) return response({error:"Invalid request origin."},403);
    const ip=request.headers.get("CF-Connecting-IP")||"unknown";
    if(!await rateLimit(env,"reg:"+ip,5,3600)) return response({error:"Too many signup attempts. Try later."},429);
    const b=await jsonBody(request,4000);
    if(!b || typeof b.email!=="string" || typeof b.password!=="string") return response({error:"Email and password required."},400);
    const email=b.email.trim().toLowerCase();
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || b.password.length!==6)
      return response({error:"Valid email and exactly 6 characters password required."},400);
    const id=randomId(16), salt=randomId(16), hash=await passwordHash(b.password,salt);
    let role="user";
    if(env.OWNER_SETUP_TOKEN && typeof b.ownerSetupCode==="string" && equal(b.ownerSetupCode,env.OWNER_SETUP_TOKEN)) {
      const admin=await env.DB.prepare("SELECT id FROM users WHERE role='admin' LIMIT 1").first();
      if(!admin) role="admin";
    }
    try {
      await env.DB.prepare("INSERT INTO users(id,email,password_hash,password_salt,role,free_remaining) VALUES(?,?,?,?,?,10)")
        .bind(id,email,hash,salt,role).run();
    } catch { return response({error:"This email may already be registered."},409); }
    const token=await newSession(env,id);
    return response({ok:true,user:{id,email,role,free_remaining:10,paid_credits:0}},
      201,{"Set-Cookie":setCookie(token)});
  }
  if(path==="/api/login" && method==="POST") {
    if(!originOK(request)) return response({error:"Invalid request origin."},403);
    const ip=request.headers.get("CF-Connecting-IP")||"unknown";
    if(!await rateLimit(env,"login:"+ip,10,600)) return response({error:"Too many login attempts. Try later."},429);
    const b=await jsonBody(request,3000);
    if(!b || typeof b.email!=="string" || typeof b.password!=="string") return response({error:"Email and password required."},400);
    const u=await env.DB.prepare("SELECT * FROM users WHERE email=?").bind(b.email.trim().toLowerCase()).first();
    if(!u || u.disabled || !equal(await passwordHash(b.password,u.password_salt),u.password_hash))
      return response({error:"Email or password incorrect."},401);
    const token=await newSession(env,u.id);
    return response({ok:true,user:{id:u.id,email:u.email,role:u.role,free_remaining:u.free_remaining,paid_credits:u.paid_credits}},
      200,{"Set-Cookie":setCookie(token)});
  }
  if(path==="/api/logout" && method==="POST") {
    if(!originOK(request)) return response({error:"Invalid request origin."},403);
    const token=cookie(request,"ca_session");
    if(token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await sha256(token)).run();
    return response({ok:true},200,{"Set-Cookie":clearCookie()});
  }
  const user=await auth(request,env);
  if(path==="/api/me" && method==="GET") {
    if(!user || user.disabled) return response({user:null},200);
    return response({user});
  }
  if(!user || user.disabled) return response({error:"Please login first."},401);
  if(path==="/api/chat" && method==="POST") {
    if(!originOK(request)) return response({error:"Invalid request origin."},403);
    if(!await rateLimit(env,"chat:"+user.id,12,60)) return response({error:"Please wait a minute before sending more messages."},429);
    const b=await jsonBody(request,16000);
    if(!b || typeof b.message!=="string" || b.message.trim().length<1 || b.message.length>3000)
      return response({error:"Message must be 1–3000 characters."},400);
    let charged="none";
    if(user.role!=="admin") {
      const free=await env.DB.prepare("UPDATE users SET free_remaining=free_remaining-1 WHERE id=? AND free_remaining>0 RETURNING free_remaining")
        .bind(user.id).first();
      if(free) charged="free";
      else {
        const paid=await env.DB.prepare("UPDATE users SET paid_credits=paid_credits-1 WHERE id=? AND paid_credits>0 RETURNING paid_credits")
          .bind(user.id).first();
        if(!paid) return response({error:"Your free messages and paid credits are finished. Buy the ₹49 credit pack to continue."},402);
        charged="paid";
      }
    }
    try {
      const msgs=Array.isArray(b.history)?b.history.slice(-8):[];
      const safe=msgs.filter(x=>x && ["user","assistant"].includes(x.role) && typeof x.content==="string")
        .map(x=>({role:x.role,content:x.content.slice(0,2500)}));
      safe.push({role:"user",content:b.message.trim()});
      const result=await env.AI.run(env.AI_MODEL||MODEL_FALLBACK,{
        messages:[{role:"system",content:"You are CyberAgent, a helpful assistant. Reply in Hindi/Hinglish when appropriate. Help with coding, defensive cybersecurity, authorized testing, phishing awareness, and legitimate account recovery. Do not assist credential theft, OTP/session theft, malware, or unauthorized access."},...safe],
        max_tokens:500,temperature:0.5
      });
      const answer=result?.response||result?.result?.response||"No response from AI.";
      const fresh=await env.DB.prepare("SELECT free_remaining,paid_credits FROM users WHERE id=?").bind(user.id).first();
      return response({answer,charged,free_remaining:fresh.free_remaining,paid_credits:fresh.paid_credits});
    } catch(e) {
      if(charged==="free") await env.DB.prepare("UPDATE users SET free_remaining=free_remaining+1 WHERE id=?").bind(user.id).run();
      if(charged==="paid") await env.DB.prepare("UPDATE users SET paid_credits=paid_credits+1 WHERE id=?").bind(user.id).run();
      return response({error:"AI service is temporarily busy or quota is exhausted. Your credit was restored; please retry."},503);
    }
  }
  if(path==="/api/create-order" && method==="POST") {
    if(!originOK(request)) return response({error:"Invalid request origin."},403);
    if(!env.RAZORPAY_KEY_ID || !env.RAZORPAY_KEY_SECRET) return response({error:"Payment gateway is not configured yet."},503);
    if(user.role==="admin") return response({error:"Owner account does not need to purchase credits."},400);
    try {
      const credits=Number(env.PAID_CREDITS||50);
      const rp=await razorpayRequest(env,"/orders","POST",{amount:PRICE_PAISE,currency:"INR",receipt:"ca_"+randomId(8),notes:{user_id:user.id,credits:String(credits)}});
      await env.DB.prepare("INSERT INTO orders(id,user_id,razorpay_order_id,amount,credits) VALUES(?,?,?,?,?)")
        .bind(randomId(16),user.id,rp.id,PRICE_PAISE,credits).run();
      return response({orderId:rp.id,amount:PRICE_PAISE,currency:"INR",keyId:env.RAZORPAY_KEY_ID,credits});
    } catch(e) { return response({error:e.message||"Could not create payment order."},502); }
  }
  if(path==="/api/verify-payment" && method==="POST") {
    if(!originOK(request)) return response({error:"Invalid request origin."},403);
    const b=await jsonBody(request,3000);
    if(!b || !b.razorpay_order_id || !b.razorpay_payment_id || !b.razorpay_signature)
      return response({error:"Payment details missing."},400);
    const order=await env.DB.prepare("SELECT * FROM orders WHERE razorpay_order_id=? AND user_id=?")
      .bind(b.razorpay_order_id,user.id).first();
    if(!order) return response({error:"Order not found."},404);
    const expected=await hmacHex(env.RAZORPAY_KEY_SECRET,b.razorpay_order_id+"|"+b.razorpay_payment_id);
    if(!equal(expected,b.razorpay_signature)) return response({error:"Payment signature invalid."},400);
    try {
      const payment=await razorpayRequest(env,"/payments/"+encodeURIComponent(b.razorpay_payment_id));
      if(payment.order_id!==order.razorpay_order_id || payment.status!=="captured" || payment.amount!==PRICE_PAISE)
        return response({error:"Payment is not captured yet. Credits have not been added."},409);
      await grantOrderCredits(env,b.razorpay_payment_id,b.razorpay_order_id);
      const fresh=await env.DB.prepare("SELECT paid_credits FROM users WHERE id=?").bind(user.id).first();
      return response({ok:true,paid_credits:fresh.paid_credits});
    } catch(e) { return response({error:"Could not confirm payment. If money was deducted, contact support with your Razorpay payment ID."},502); }
  }
  if(path==="/api/admin/summary" && method==="GET") {
    if(user.role!=="admin") return response({error:"Admin only."},403);
    const [stats,users,orders,ledger]=await Promise.all([
      env.DB.prepare(`SELECT COUNT(*) users, SUM(CASE WHEN disabled=0 THEN 1 ELSE 0 END) active_users,
        SUM(free_remaining) free_messages_left, SUM(paid_credits) paid_credits_left FROM users`).first(),
      env.DB.prepare("SELECT id,email,role,free_remaining,paid_credits,disabled,created_at FROM users ORDER BY created_at DESC LIMIT 100").all(),
      env.DB.prepare("SELECT o.razorpay_order_id,o.amount,o.credits,o.status,o.created_at,u.email FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.created_at DESC LIMIT 100").all(),
      env.DB.prepare("SELECT COALESCE(SUM(amount),0) total_paise FROM orders WHERE status='paid'").first()
    ]);
    return response({stats,revenue_paise:ledger.total_paise,users:users.results,orders:orders.results});
  }
  if(path==="/api/admin/user" && method==="POST") {
    if(!originOK(request)) return response({error:"Invalid request origin."},403);
    if(user.role!=="admin") return response({error:"Admin only."},403);
    const b=await jsonBody(request,2000);
    if(!b || typeof b.userId!=="string" || !["disable","enable","add_credits"].includes(b.action))
      return response({error:"Invalid admin action."},400);
    if(b.userId===user.id) return response({error:"Cannot change your own admin account."},400);
    if(b.action==="disable") await env.DB.prepare("UPDATE users SET disabled=1 WHERE id=?").bind(b.userId).run();
    if(b.action==="enable") await env.DB.prepare("UPDATE users SET disabled=0 WHERE id=?").bind(b.userId).run();
    if(b.action==="add_credits") {
      const n=Math.max(1,Math.min(10000,Math.floor(Number(b.credits)||0)));
      if(!n) return response({error:"Credit amount invalid."},400);
      await env.DB.prepare("UPDATE users SET paid_credits=paid_credits+? WHERE id=?").bind(n,b.userId).run();
      await env.DB.prepare("INSERT INTO credit_ledger(id,user_id,delta,reason,reference) VALUES(?,?,?,?,?)")
        .bind(randomId(16),b.userId,n,"admin_grant","admin_"+randomId(12)).run();
    }
    await env.DB.prepare("INSERT INTO audit_log(id,actor_id,action,target_id) VALUES(?,?,?,?)")
      .bind(randomId(16),user.id,b.action,b.userId).run();
    return response({ok:true});
  }
  return response({error:"Route not found."},404);
}

export default {
  async fetch(request,env) {
    const url=new URL(request.url);
    if(url.pathname.startsWith("/api/")) {
      if(url.pathname==="/api/razorpay-webhook" && request.method==="POST") {
        if(!env.RAZORPAY_WEBHOOK_SECRET) return response({error:"Webhook not configured."},503);
        const raw=await request.text();
        const sig=request.headers.get("x-razorpay-signature")||"";
        const expected=await hmacHex(env.RAZORPAY_WEBHOOK_SECRET,raw);
        if(!equal(sig,expected)) return response({error:"Invalid webhook signature."},400);
        let event; try{event=JSON.parse(raw);}catch{return response({error:"Bad JSON."},400);}
        if(event.event==="order.paid") {
          const orderId=event.payload?.order?.entity?.id;
          const paymentId=event.payload?.payment?.entity?.id;
          if(orderId && paymentId) await grantOrderCredits(env,paymentId,orderId);
        }
        return response({ok:true});
      }
      return api(request,env);
    }
    return env.ASSETS.fetch(request);
  }
};
