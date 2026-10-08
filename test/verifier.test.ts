import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { AccessError, createAccessVerifier, assertionFromHeaders } from '../src/index.js';
const f = JSON.parse(readFileSync(new URL('../fixtures/tokens.json', import.meta.url), 'utf8'));
const mock = (jwks = f.jwks) => (async () => new Response(JSON.stringify(jwks))) as typeof fetch;
const config = {teamDomain:f.issuer,audience:f.audience};
for (const [name, scenario] of Object.entries(f.cases) as [string, {token:string,status:number}][]) {
  if (name === 'rotated') continue;
  test(`shared fixture: ${name}`, async () => {
    const verifier = createAccessVerifier({...config, fetch:mock()});
    if (scenario.status === 200) {
      const identity = await verifier.verifyToken(scenario.token);
      assert.equal(identity.issuer,f.issuer); assert.equal(identity.expiresAt,4102444800);
      assert.deepEqual(Object.keys(identity),['issuer','subject','email','expiresAt']);
    } else await assert.rejects(verifier.verifyToken(scenario.token), (e:AccessError) => e.status === 401);
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
