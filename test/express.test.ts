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
for (const mode of ['noResolver','emptyResolver','falseResolver','unexpectedError','unavailableKeys','throwingDiagnostic'] as const) {
  test(`Express boundary: ${mode}`, async () => {
    const app=express(); let handled=0; let observed:express.Request|undefined;
    const events:{code:string,status:number}[]=[]; let forwarded:unknown;
    app.use((req,_res,next)=>{observed=req;next();});
    app.use(cfAccessMiddleware<unknown>({teamDomain:f.issuer,audience:f.audience,
      fetch:(async()=>{if(mode==='unavailableKeys')throw new Error('network detail');return new Response(JSON.stringify(f.jwks));}) as typeof fetch,
      ...(mode==='emptyResolver'?{resolveUser:()=>undefined}:{}),
      ...(mode==='falseResolver'?{resolveUser:()=>false}:{}),
      ...(mode==='unexpectedError'?{resolveUser:async()=>{throw new Error('private application detail');}}:{}),
      onDiagnostic:event=>{events.push(event);throw new Error('logger detail');},
    }));
    app.get('/',(req,res)=>{handled++;res.json({identity:req.cfAccessIdentity});});
    app.use((error:unknown,_req:express.Request,res:express.Response,_next:express.NextFunction)=>{forwarded=error;res.status(500).json({error:'Application failed'});});
    const server=app.listen(0,'127.0.0.1');
    await new Promise<void>((resolve,reject)=>{server.once('listening',resolve);server.once('error',reject);});
    try {
      const headers=mode==='throwingDiagnostic'?{}:{'Cf-Access-Jwt-Assertion':f.cases.valid.token};
      const result=await new Promise<{status:number,body:unknown,cache:string|undefined}>((resolve,reject)=>{
        request({hostname:'127.0.0.1',port:(server.address() as {port:number}).port,headers},res=>{
          let data='';res.on('data',chunk=>data+=chunk);res.on('end',()=>resolve({status:res.statusCode!,body:JSON.parse(data),cache:res.headers['cache-control']}));
        }).on('error',reject).end();
      });
      const status=mode==='noResolver'?200:mode==='unexpectedError'?500:mode==='unavailableKeys'?503:mode==='throwingDiagnostic'?401:403;
      assert.equal(result.status,status); assert.equal(handled,status===200?1:0);
      assert.equal(result.cache,mode==='unexpectedError'?undefined:'no-store');
      if(status===200) {
        assert.deepEqual(result.body,{identity:f.cases.valid.identity}); assert.equal(observed!.cfAccessUser,undefined); assert.deepEqual(events,[]);
      } else {
        assert.equal(observed!.cfAccessIdentity,undefined); assert.equal(observed!.cfAccessUser,undefined);
        assert.deepEqual(result.body,{error:status===403?'Forbidden':status===503?'Authentication unavailable':status===401?'Unauthorized':'Application failed'});
        assert.equal(events.length,mode==='unexpectedError'?0:1);
      }
      if(mode==='unexpectedError') assert.equal((forwarded as Error).message,'private application detail');
    } finally {await new Promise<void>(resolve=>server.close(()=>resolve()));}
  });
}
