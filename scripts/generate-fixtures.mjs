import { generateKeyPairSync, createSign, createHmac } from 'node:crypto';
import { writeFileSync } from 'node:fs';
const pair = () => generateKeyPairSync('rsa', {modulusLength: 2048});
const a = pair(), b = pair();
const enc = value => Buffer.from(JSON.stringify(value)).toString('base64url');
const base = {iss:'https://fixture.cloudflareaccess.com', aud:['test-audience'], exp:4102444800, iat:1, nbf:1, sub:'user-1', email:'Alice@example.com', type:'app'};
function token(claims, kid = 'key-a', key = a.privateKey, alg = 'RS256') {
  const unsigned = enc({alg, kid, typ:'JWT'}) + '.' + enc(claims);
  const signature = alg === 'HS256' ? createHmac('sha256','test-only').update(unsigned).digest() : createSign('RSA-SHA256').update(unsigned).sign(key);
  return unsigned + '.' + signature.toString('base64url');
}
const valid = token(base);
const cases = {valid:{token:valid,status:200}};
for (const [name, change] of Object.entries({wrongIssuer:{iss:'https://other.cloudflareaccess.com'},wrongAudience:{aud:['other']},expired:{exp:2},futureNbf:{nbf:4102444799},futureIat:{iat:4102444799},service:{sub:'',email:undefined},organization:{type:'org'},emptyEmail:{email:' '},numericSubject:{sub:1},fractionalExpiry:{exp:4102444800.5},invalidLifetime:{exp:1},badAudience:{aud:[42]},bob:{sub:'user-2',email:'bob@example.com'}})) {
  cases[name] = {token:token({...base,...change}),status:name==='bob'?200:401};
}
for (const field of ['iss','aud','exp','iat','nbf','sub','email','type']) {
  const claims = {...base}; delete claims[field]; cases['missing_'+field] = {token:token(claims),status:401};
}
cases.wrongAlgorithm = {token:token(base,'key-a',a.privateKey,'HS256'),status:401};
cases.tampered = {token:valid.slice(0,-8)+'AAAAAAAA',status:401};
cases.malformed = {token:'not.a.jwt',status:401};
cases.oversized = {token:'a'.repeat(16385),status:401};
cases.rotated = {token:token(base,'key-b',b.privateKey),status:200};
const jwk = (key,kid) => ({...key.export({format:'jwk'}),kid,alg:'RS256',use:'sig'});
writeFileSync('fixtures/tokens.json', JSON.stringify({issuer:base.iss,audience:'test-audience',jwks:{keys:[jwk(a.publicKey,'key-a')]},rotatedJwks:{keys:[jwk(b.publicKey,'key-b')]},cases},null,2)+'\n');
