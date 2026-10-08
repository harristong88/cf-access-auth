import { chromium, request } from '@playwright/test';
import assert from 'node:assert/strict';
import { readFileSync, mkdirSync } from 'node:fs';
const f=JSON.parse(readFileSync(new URL('../fixtures/tokens.json',import.meta.url),'utf8'));
const base=process.env.FILEGATOR_URL ?? 'http://127.0.0.1:8088/';
const alice=f.cases.valid.token,bob=f.cases.bob.token;
const browser=await chromium.launch();
const context=await browser.newContext({extraHTTPHeaders:{'Cf-Access-Jwt-Assertion':alice}});
let csrf;
const endpoint=route=>base+'?r=/'+route;
const headers=()=>({'X-CSRF-Token':csrf});
const getUser=async()=>{
  const response=await context.request.get(endpoint('getuser'));assert.equal(response.status(),200,await response.text());
  csrf=response.headers()['x-csrf-token'];assert.ok(csrf);return (await response.json()).data;
};
try {
  const unauthorized=await request.newContext();
  assert.equal((await unauthorized.get(base)).status(),401);
  assert.equal((await unauthorized.get(endpoint('getuser'))).status(),401);
  await unauthorized.dispose();
  const user=await getUser();assert.equal(user.username,'alice@example.com');assert.equal(user.role,'admin');assert.match(user.homedir,/^\/users\/[a-f0-9]+\/$/);
  for(const route of ['login','changepassword']) assert.equal((await context.request.post(endpoint(route),{headers:headers(),data:{username:'alice',password:'anything'}})).status(), route==='login'?404:403);
  // Login route isn't registered for an already authenticated user; 404 also rejects it.
  const upload=await context.request.post(endpoint('upload'),{headers:headers(),multipart:{
    resumableFilename:'hello.txt',resumableRelativePath:'/',resumableChunkNumber:'1',resumableTotalChunks:'1',resumableTotalSize:'12',resumableIdentifier:'fixture',
    file:{name:'hello.txt',mimeType:'text/plain',buffer:Buffer.from('private data')}}});
  assert.equal(upload.status(),200,await upload.text());assert.equal((await upload.json()).data,'Stored');
  const path=Buffer.from('/hello.txt').toString('base64');
  const download=await context.request.get(endpoint('download')+'&path='+encodeURIComponent(path));assert.equal(download.status(),200);assert.equal(await download.text(),'private data');
  const listing=await context.request.post(endpoint('getdir'),{headers:headers(),data:{dir:'/'}});assert.equal(listing.status(),200);
  // The admin UI must support creating users without passwords.
  const added=await context.request.post(endpoint('storeuser'),{headers:headers(),data:{name:'Carol',username:`carol-${Date.now()}@example.com`,homedir:'/carol/',role:'user',permissions:['read','download']}});
  assert.equal(added.status(),200,await added.text());
  const archive=await context.request.post(endpoint('batchdownload'),{headers:headers(),data:{items:[{path:'/hello.txt',type:'file'}]}});
  assert.equal(archive.status(),200,await archive.text());
  const archiveData=(await archive.json()).data;
  const incomplete=await context.request.post(endpoint('upload'),{headers:headers(),multipart:{resumableFilename:'partial.txt',resumableRelativePath:'/',resumableChunkNumber:'1',resumableTotalChunks:'2',resumableTotalSize:'24',resumableIdentifier:'partial',file:{name:'partial.txt',mimeType:'text/plain',buffer:Buffer.from('private data')}}});
  assert.equal((await incomplete.json()).data,'Uploaded');
  const aliceCookie=(await context.cookies()).find(c=>c.name==='filegator')?.value;
  await context.setExtraHTTPHeaders({'Cf-Access-Jwt-Assertion':bob});
  const switchedPost=await context.request.post(endpoint('getdir'),{headers:headers(),data:{dir:'/'}});assert.equal(switchedPost.status(),403);
  const second=await getUser();assert.notEqual(second.homedir,user.homedir);assert.equal(second.role,'user');
  const bobCookie=(await context.cookies()).find(c=>c.name==='filegator')?.value;assert.notEqual(aliceCookie,bobCookie);
  const bobDownload=await context.request.get(endpoint('download')+'&path='+encodeURIComponent(path),{maxRedirects:0});assert.equal(bobDownload.status(),302);
  assert.equal((await context.request.get(endpoint('batchdownload')+'&uniqid='+archiveData.uniqid,{maxRedirects:0})).status(),302);
  assert.equal((await context.request.get(endpoint('upload')+'&resumableFilename=partial.txt&resumableIdentifier=partial&resumableChunkNumber=1')).status(),204);
  const bobListing=await context.request.post(endpoint('getdir'),{headers:headers(),data:{dir:'/'}});assert.equal(bobListing.status(),200);assert.ok(!(await bobListing.text()).includes('hello.txt'));
  assert.equal((await context.request.get(endpoint('listusers'))).status(),404);
  // Verify the browser opens directly into FileGator and hides password controls.
  await context.setExtraHTTPHeaders({'Cf-Access-Jwt-Assertion':alice});
  const page=await context.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto(base);await page.locator('.navbar .logout').waitFor();
  assert.equal(await page.locator('input[type=password]').count(),0);
  await page.locator('.navbar .profile').click();await page.getByText('Sign-in is managed by Cloudflare Access.').waitFor();assert.equal(await page.locator('input[type=password]').count(),0);
  await page.getByRole('button',{name:'Close',exact:true}).click();
  await page.goto(base+'#/login');assert.equal(await page.locator('input[type=password]').count(),0);
  // Simulate the edge logout endpoint only; no live Cloudflare session is involved.
  await page.route('**/cdn-cgi/access/logout',route=>route.fulfill({status:200,contentType:'text/plain',body:'Cloudflare logout reached'}));
  await page.locator('.navbar .logout').click();await page.waitForURL('**/cdn-cgi/access/logout');assert.ok((await page.textContent('body')).includes('Cloudflare logout reached'));
  assert.deepEqual(errors,[]);
  mkdirSync('.artifacts',{recursive:true});await page.screenshot({path:'.artifacts/filegator-logout.png'});
  console.log('FileGator HTTP and Chromium checks passed: startup, upload/download, homes, admin creation, CSRF/session switch, password rejection, and logout.');
} finally {await context.close();await browser.close();}
