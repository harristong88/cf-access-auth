import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { AccessError, createAccessVerifier, assertionFromHeaders } from '../src/index.js';
const f = JSON.parse(readFileSync(new URL('../fixtures/tokens.json', import.meta.url), 'utf8'));
const mock = (jwks = f.jwks) => (async () => new Response(JSON.stringify(jwks))) as typeof fetch;
const config = {teamDomain:f.issuer,audience:f.audience};
interface FixtureCase {token:string;status:number;statuses?:{node?:number};identity?:unknown;keyFetches:number;keySet?:string}
for (const [name, scenario] of Object.entries(f.cases) as [string, FixtureCase][]) {
  test(`shared fixture: ${name}`, async () => {
    let calls=0;
    const verifier = createAccessVerifier({...config, fetch:(async()=>{calls++;return new Response(JSON.stringify(f[scenario.keySet??'jwks']));}) as typeof fetch});
    const status=scenario.statuses?.node??scenario.status;
    if (status === 200) {
      const identity = await verifier.verifyToken(scenario.token);
      assert.deepEqual(identity,scenario.identity);
      assert.deepEqual(Object.keys(identity),['issuer','subject','email','expiresAt']);
    } else await assert.rejects(verifier.verifyToken(scenario.token), (e:AccessError) => e.status === status);
    assert.equal(calls,scenario.keyFetches);
  });
}
test('headers: case, duplicate, arrays, comma merging, cookie-only, email-only', async () => {
  const token=f.cases.valid.token;
  assert.equal(assertionFromHeaders({'Cf-Access-Jwt-Assertion':token}),token);
  assert.equal(assertionFromHeaders(new Headers({'cf-access-jwt-assertion':token})),token);
  for (const headers of [{}, {'cookie':`CF_Authorization=${token}`},{'Cf-Access-Authenticated-User-Email':'alice@example.com'},
    {'cf-access-jwt-assertion':[token]}, {'cf-access-jwt-assertion':token,'Cf-Access-Jwt-Assertion':token},
    {'cf-access-jwt-assertion':`${token}, ${token}`}]) assert.throws(()=>assertionFromHeaders(headers), AccessError);
});
test('configuration boundaries preserve Node normalization and zero timings', () => {
  assert.doesNotThrow(()=>createAccessVerifier({...config,teamDomain:'https://FIXTURE.cloudflareaccess.com/'}));
  assert.doesNotThrow(()=>createAccessVerifier({...config,cacheMaxAge:0,cooldownDuration:0,timeoutDuration:0}));
  for(const audience of ['', ' ', ' aud', [], ['aud',' ']]) assert.throws(()=>createAccessVerifier({...config,audience}));
  for(const key of ['cacheMaxAge','cooldownDuration','timeoutDuration']) {
    for(const value of [-1,NaN,Infinity]) assert.throws(()=>createAccessVerifier({...config,[key]:value}));
  }
});
test('Node ignores unsupported keys alongside a matching RSA key', async () => {
  const jwks={keys:[...f.jwks.keys,{kty:'EC',kid:'unused',crv:'P-256',x:'AA',y:'AA'}]};
  assert.deepEqual(await createAccessVerifier({...config,fetch:mock(jwks)}).verifyToken(f.cases.valid.token),f.cases.valid.identity);
});
test('fresh keys work during a stalled unknown-key refresh', async () => {
  let calls=0; let started!:()=>void; let release!:()=>void;
  const fetching=new Promise<void>(resolve=>{started=resolve;});
  const finish=new Promise<void>(resolve=>{release=resolve;});
  const verifier=createAccessVerifier({...config,cooldownDuration:0,fetch:(async()=>{
    if(++calls===1) return new Response(JSON.stringify(f.jwks));
    started(); await finish; throw new TypeError('offline');
  }) as typeof fetch});
  await verifier.verifyToken(f.cases.valid.token);
  const refresh=assert.rejects(verifier.verifyToken(f.cases.rotated.token),(e:AccessError)=>e.status===503);
  try {
    await fetching;
    assert.deepEqual(await verifier.verifyToken(f.cases.valid.token),f.cases.valid.identity);
  } finally {release();await refresh;}
  assert.equal(calls,2);
});
test('coalesces requests, caches keys, rotates only on unknown kid', async () => {
  let count=0; let jwks=f.jwks;
  const verifier=createAccessVerifier({...config,cooldownDuration:0,fetch:(async () => {count++; await new Promise(r=>setTimeout(r,10)); return new Response(JSON.stringify(jwks));}) as typeof fetch});
  await Promise.all(Array.from({length:20},()=>verifier.verifyToken(f.cases.valid.token)));
  assert.equal(count,1);
  await assert.rejects(verifier.verifyToken(f.cases.tampered.token)); assert.equal(count,1);
  jwks=f.rotatedJwks; await verifier.verifyToken(f.cases.rotated.token); assert.equal(count,2);
});
test('cooldown limits random key probes; warm keys work offline, expired keys do not', async () => {
  let count=0; let offline=false;
  const verifier=createAccessVerifier({...config,cacheMaxAge:30,cooldownDuration:30000,fetch:(async()=>{count++; if(offline) throw new TypeError('offline'); return new Response(JSON.stringify(f.jwks));}) as typeof fetch});
  await verifier.verifyToken(f.cases.valid.token);
  await assert.rejects(verifier.verifyToken(f.cases.rotated.token),(e:AccessError)=>e.status===401); assert.equal(count,1);
  offline=true; await verifier.verifyToken(f.cases.valid.token); assert.equal(count,1);
  await new Promise(r=>setTimeout(r,40));
  await assert.rejects(verifier.verifyToken(f.cases.valid.token),(e:AccessError)=>e.status===503);
});
test('config validation, explicit audience transitions and safe diagnostics', async () => {
  for (const teamDomain of ['http://fixture.cloudflareaccess.com','https://evil.test','https://fixture.cloudflareaccess.com/path','https://fixture.cloudflareaccess.com?x=y']) assert.throws(()=>createAccessVerifier({...config,teamDomain}));
  assert.throws(()=>createAccessVerifier({...config,audience:[]}));
  await createAccessVerifier({...config,audience:['old',f.audience],fetch:mock()}).verifyToken(f.cases.valid.token);
  const events:unknown[]=[];
  const verifier=createAccessVerifier({...config,fetch:(async()=>{throw new Error('network');}) as typeof fetch,onDiagnostic:event=>{events.push(event);throw new Error('logger failed');}});
  await assert.rejects(verifier.verifyToken(f.cases.valid.token),(e:AccessError)=>e.status===503);
  assert.deepEqual(events,[{code:'JWKS_UNAVAILABLE',status:503}]);
});
test('a trailing token newline is rejected before any remote lookup', async () => {
  let calls=0;
  const verifier=createAccessVerifier({...config,fetch:(async()=>{calls++;return new Response(JSON.stringify(f.jwks));}) as typeof fetch});
  await assert.rejects(verifier.verifyToken(f.cases.valid.token+'\n'),(e:AccessError)=>e.status===401);
  assert.equal(calls,0);
});
test('cold and expired-cache failures share backoff and retry after it expires', async () => {
  let calls=0; let available=false;
  const verifier=createAccessVerifier({...config,cacheMaxAge:10,cooldownDuration:30,fetch:(async()=>{
    calls++; await new Promise(r=>setTimeout(r,2));
    if(!available) throw new TypeError('offline');
    return new Response(JSON.stringify(f.jwks));
  }) as typeof fetch});
  await Promise.all(Array.from({length:10},()=>assert.rejects(verifier.verifyToken(f.cases.valid.token),(e:AccessError)=>e.status===503)));
  for(let i=0;i<10;i++) await assert.rejects(verifier.verifyToken(f.cases.valid.token),(e:AccessError)=>e.status===503);
  assert.equal(calls,1);
  await new Promise(r=>setTimeout(r,40)); available=true;
  await verifier.verifyToken(f.cases.valid.token); assert.equal(calls,2);
  await new Promise(r=>setTimeout(r,15)); available=false;
  for(let i=0;i<10;i++) await assert.rejects(verifier.verifyToken(f.cases.valid.token),(e:AccessError)=>e.status===503);
  assert.equal(calls,3);
});
test('unknown-key outage probes back off while fresh matching keys work', async () => {
  let calls=0; let available=true;
  const verifier=createAccessVerifier({...config,cooldownDuration:30,fetch:(async()=>{
    calls++; if(!available) throw new TypeError('offline'); return new Response(JSON.stringify(f.jwks));
  }) as typeof fetch});
  await verifier.verifyToken(f.cases.valid.token);
  await new Promise(r=>setTimeout(r,40)); available=false;
  const forged=Buffer.from(JSON.stringify({alg:'RS256',kid:'unknown'})).toString('base64url')+'.e30.AA';
  for(let i=0;i<10;i++) await assert.rejects(verifier.verifyToken(forged),(e:AccessError)=>e.status===503);
  assert.equal(calls,2);
  await verifier.verifyToken(f.cases.valid.token); assert.equal(calls,2);
});
test('HTTP, invalid JSON and malformed JWKS failures also back off', async () => {
  for(const response of [()=>new Response('unavailable',{status:503}),()=>new Response('{'),()=>new Response('{"keys":42}')]) {
    let calls=0;
    const verifier=createAccessVerifier({...config,fetch:(async()=>{calls++;return response();}) as typeof fetch});
    for(let i=0;i<5;i++) await assert.rejects(verifier.verifyToken(f.cases.valid.token),(e:AccessError)=>e.status===503);
    assert.equal(calls,1);
  }
});
