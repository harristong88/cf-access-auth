import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root=fileURLToPath(new URL('../',import.meta.url));
const directory=mkdtempSync(join(tmpdir(),'cf-access-npm-consumer-'));
const run=(args,cwd=directory)=>execFileSync('npm',args,{cwd,encoding:'utf8'});
try {
  const [artifact]=JSON.parse(run(['pack','--ignore-scripts','--json','--pack-destination',directory],root));
  for(const path of ['dist/index.js','dist/index.d.ts','dist/express.js','dist/express.d.ts']) {
    assert.ok(artifact.files.some(file=>file.path===path),`Missing packaged ${path}`);
  }
  writeFileSync(join(directory,'package.json'),JSON.stringify({name:'isolated-consumer',private:true,type:'module'}));
  copyFileSync(join(root,'fixtures/tokens.json'),join(directory,'fixtures.json'));
  const lock=JSON.parse(readFileSync(join(root,'package-lock.json'),'utf8'));
  run(['install','--ignore-scripts','--no-audit','--no-fund',join(directory,artifact.filename),`jose@${lock.packages['node_modules/jose'].version}`]);
  writeFileSync(join(directory,'core.mjs'),`
    import assert from 'node:assert/strict';
    import { createRequire } from 'node:module';
    import { readFileSync } from 'node:fs';
    import { AccessError, createAccessVerifier, normalizeEmail } from 'cf-access-auth';
    assert.throws(()=>createRequire(import.meta.url).resolve('express'),{code:'MODULE_NOT_FOUND'});
    const f=JSON.parse(readFileSync(new URL('./fixtures.json',import.meta.url)));
    const v=createAccessVerifier({teamDomain:f.issuer,audience:f.audience,fetch:async()=>new Response(JSON.stringify(f.jwks))});
    assert.deepEqual(await v.verifyToken(f.cases.valid.token),f.cases.valid.identity);
    await assert.rejects(v.authenticateRequest({}),AccessError);
    assert.equal(normalizeEmail(' Alice@Example.com '),'alice@example.com');
  `);
  execFileSync(process.execPath,['core.mjs'],{cwd:directory});
  writeFileSync(join(directory,'express.mjs'),`
    import assert from 'node:assert/strict';
    import { readFileSync } from 'node:fs';
    import express from 'express';
    import { cfAccessMiddleware } from 'cf-access-auth/express';
    const f=JSON.parse(readFileSync(new URL('./fixtures.json',import.meta.url)));
    const app=express();
    app.use(cfAccessMiddleware({teamDomain:f.issuer,audience:f.audience,fetch:async()=>new Response(JSON.stringify(f.jwks))}));
    app.get('/',(req,res)=>res.json(req.cfAccessIdentity));
    const server=app.listen(0,'127.0.0.1');
    await new Promise((resolve,reject)=>{server.once('listening',resolve);server.once('error',reject);});
    try {
      const url='http://127.0.0.1:'+server.address().port;
      assert.equal((await fetch(url,{signal:AbortSignal.timeout(5000)})).status,401);
      const response=await fetch(url,{headers:{'Cf-Access-Jwt-Assertion':f.cases.valid.token},signal:AbortSignal.timeout(5000)});
      assert.equal(response.headers.get('cache-control'),'no-store');
      assert.deepEqual(await response.json(),f.cases.valid.identity);
    } finally {await new Promise(resolve=>server.close(resolve));}
  `);
  for(const version of ['4',lock.packages['node_modules/express'].version]) {
    run(['install','--ignore-scripts','--no-audit','--no-fund',`express@${version}`]);
    execFileSync(process.execPath,['express.mjs'],{cwd:directory});
  }
  console.log('Packaged npm core and Express 4/5 consumers passed');
} finally {rmSync(directory,{recursive:true,force:true});}
