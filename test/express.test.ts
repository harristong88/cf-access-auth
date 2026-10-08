import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { request } from 'node:http';
import { readFileSync } from 'node:fs';
import { cfAccessMiddleware } from '../src/express.js';
import { AccessError } from '../src/index.js';
const f=JSON.parse(readFileSync(new URL('../fixtures/tokens.json',import.meta.url),'utf8'));
test('Express guards handlers, resolves separately, rejects raw duplicate headers, masks errors',async()=>{
  let denied=false;
  const app=express();
  app.use(cfAccessMiddleware({teamDomain:f.issuer,audience:f.audience,fetch:(async()=>new Response(JSON.stringify(f.jwks))) as typeof fetch,
    resolveUser: identity=>{if(denied)throw new AccessError('ACCOUNT_DISABLED',403);return {email:identity.email,role:'user'};}}));
  app.get('/',(req,res)=>res.json({identity:req.cfAccessIdentity,user:req.cfAccessUser}));
  const server=app.listen(0,'127.0.0.1'); await new Promise<void>(r=>server.once('listening',r));
  const port=(server.address() as {port:number}).port;
  const get=(headers:Record<string,string|string[]>={})=>new Promise<{status:number;body:any}>((resolve,reject)=>{
    request({hostname:'127.0.0.1',port,headers},res=>{let data='';res.on('data',c=>data+=c);res.on('end',()=>resolve({status:res.statusCode!,body:JSON.parse(data)}));}).on('error',reject).end();
  });
  try {
    assert.equal((await get()).status,401);
    const success=await get({'Cf-Access-Jwt-Assertion':f.cases.valid.token}); assert.equal(success.status,200);assert.equal(success.body.user.role,'user');
    assert.equal((await get({'Cf-Access-Jwt-Assertion':[f.cases.valid.token,f.cases.valid.token]})).status,401);
    denied=true; const rejection=await get({'Cf-Access-Jwt-Assertion':f.cases.valid.token});assert.equal(rejection.status,403);assert.deepEqual(rejection.body,{error:'Forbidden'});
  } finally { await new Promise<void>(r=>server.close(()=>r())); }
});
