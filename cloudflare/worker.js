
const cors = {
  "Access-Control-Allow-Origin": "https://tiocucho.github.io",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type"
};

function b64(s) {
  const a = new TextEncoder().encode(s);
  let b = "";
  for (const x of a) b += String.fromCharCode(x);
  return btoa(b).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
}

async function sign(p, secret) {
  const h = b64(JSON.stringify({alg:"HS256",typ:"JWT"}));
  const body = b64(JSON.stringify(p));
  const input = h+"."+body;
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    {name:"HMAC",hash:"SHA-256"}, false, ["sign"]
  );
  const sig = new Uint8Array(await crypto.subtle.sign(
    "HMAC",key,new TextEncoder().encode(input)
  ));
  let bin = "";
  for (const x of sig) bin += String.fromCharCode(x);
  return input+"."+btoa(bin).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
}

export default {
 async fetch(request,env) {
  if(request.method==="OPTIONS")
   return new Response(null,{status:204,headers:cors});

  const url=new URL(request.url);
  if(request.method!=="POST"||url.pathname!=="/token")
   return new Response("Not found",{status:404,headers:cors});

  try {
   const d=await request.json();
   const room=String(d.room||"").trim();
   const name=String(d.name||"").trim().slice(0,32);
   const host=d.role==="host";

   if(!env.LIVEKIT_URL||!env.LIVEKIT_API_KEY||
      !env.LIVEKIT_API_SECRET||!env.HOST_ACCESS_CODE)
    return Response.json({error:"Faltan secretos."},
      {status:503,headers:cors});

   if(!/^[a-zA-Z0-9_-]{3,48}$/.test(room)||!name)
    return Response.json({error:"Sala o nombre inválido."},
      {status:400,headers:cors});

   if(host&&d.hostCode!==env.HOST_ACCESS_CODE)
    return Response.json({error:"Código incorrecto."},
      {status:403,headers:cors});

   const now=Math.floor(Date.now()/1000);
   const identity=(host?"host-":"p-")+crypto.randomUUID();

   const token=await sign({
    iss:env.LIVEKIT_API_KEY,
    sub:identity,
    nbf:now-5,
    exp:now+10800,
    name,
    video:{
     room,
     roomJoin:true,
     canSubscribe:true,
     canPublish:true,
     canPublishData:true,
     canPublishSources:host?
      ["camera","microphone"]:["microphone"]
    }
   },env.LIVEKIT_API_SECRET);

   return Response.json({
    token,
    serverUrl:env.LIVEKIT_URL,
    identity,
    role:host?"host":"participant",
    room
   },{headers:cors});

  } catch {
   return Response.json({error:"No se pudo crear el acceso."},
    {status:500,headers:cors});
  }
 }
};
