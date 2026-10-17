// Sign the complete recovered public release with the EXISTING production key.
// Usage: BRY_SITE_SIGNER_KEY_PATH=<private path> node scripts/sign-public-site.cjs
// Never create or rotate a key as part of a content release.
const fs=require('fs'),path=require('path'),crypto=require('crypto'),assert=require('assert/strict');
const root=path.resolve(__dirname,'../public-site');
const canonical=v=>v===null||typeof v!=='object'?JSON.stringify(v):Array.isArray(v)?'['+v.map(canonical).join(',')+']':'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}';
function walk(dir){return fs.readdirSync(dir,{withFileTypes:true}).flatMap(d=>d.isDirectory()?walk(path.join(dir,d.name)):[path.join(dir,d.name)]);}
const pinned=fs.readFileSync(path.join(root,'site-signer.ed25519.pub'),'utf8').trim();
const files={};
for(const file of walk(root).sort()){
 const rel=path.relative(root,file).replaceAll('\\','/');
 if(rel==='site-integrity.json'||rel==='_headers')continue;
 assert(!/(?:\.key$|\.pem$|\.env|node_modules|^\.git)/i.test(rel),'Private/build file in public release: '+rel);
 files[rel]=crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
 if(file.endsWith('.html')){
  for(const tag of fs.readFileSync(file,'utf8').matchAll(/<(?:script|link)\b[^>]+>/g)){
   const src=tag[0].match(/(?:src|href)="([^"]+)"/),sri=tag[0].match(/integrity="(sha(?:256|384|512))-([^" ]+)"/);
   if(!src||!sri||/^https?:/.test(src[1]))continue;
   const url=new URL(src[1],'https://secure.imagineqira.com/'+rel),target=path.resolve(root,'.'+decodeURIComponent(url.pathname));
   assert(target.startsWith(root+path.sep));
   assert.equal(crypto.createHash(sri[1]).update(fs.readFileSync(target)).digest('base64'),sri[2],'SRI mismatch '+rel);
  }
 }
}
if(process.argv.includes('--verify')){
 const {signature,...unsigned}=JSON.parse(fs.readFileSync(path.join(root,'site-integrity.json'),'utf8'));
 const publicKey=crypto.createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(pinned,'hex')]),format:'der',type:'spki'});
 assert.deepEqual(unsigned.files,files,'Manifest file hashes differ from release');
 assert.equal(unsigned.signer.public_key_hex,pinned);
 assert(crypto.verify(null,Buffer.from(unsigned.signer.domain+canonical(unsigned)),publicKey,Buffer.from(signature.signature_hex,'hex')),'Signature invalid');
 console.log('Verified pinned signature, all '+Object.keys(files).length+' file hashes, and local SRI.');
}else{
 assert(process.env.BRY_SITE_SIGNER_KEY_PATH,'Existing private signer path required');
 const key=crypto.createPrivateKey(fs.readFileSync(process.env.BRY_SITE_SIGNER_KEY_PATH));
 assert.equal(crypto.createPublicKey(key).export({format:'jwk'}).x,Buffer.from(pinned,'hex').toString('base64url'),'Existing private key does not match pinned signer');
 const domain='BRY-NFET-SX|SITE-INTEGRITY|V2';
 const unsigned={schema:'BRY-NFET-SX-SITE-INTEGRITY-V2',site:'secure.imagineqira.com',signed_at:new Date().toISOString(),file_count:Object.keys(files).length,files,signer:{scheme:'ed25519',public_key_hex:pinned,public_key_url:'https://secure.imagineqira.com/site-signer.ed25519.pub',domain}};
 const bytes=Buffer.from(domain+canonical(unsigned)),sig=crypto.sign(null,bytes,key);
 assert(crypto.verify(null,bytes,crypto.createPublicKey(key),sig));
 fs.writeFileSync(path.join(root,'site-integrity.json'),JSON.stringify({...unsigned,signature:{algorithm:'ed25519',domain,public_key_hex:pinned,signature_hex:sig.toString('hex'),canonical_json_note:'Domain separator followed by recursively key-sorted compact JSON of the manifest without signature.'}},null,2)+'\n');
 console.log('Signed '+Object.keys(files).length+' public files with unchanged production signer.');
}
