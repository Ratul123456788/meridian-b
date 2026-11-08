require('dotenv').config();
const fs=require('fs'),path=require('path'),crypto=require('crypto');
const express=require('express'),helmet=require('helmet'),rateLimit=require('express-rate-limit'),cookie=require('cookie-parser'),jwt=require('jsonwebtoken'),Database=require('better-sqlite3');
const E=process.env,PORT=E.PORT||3000,BASE=(E.BASE_URL||`http://localhost:${PORT}`).replace(/\/$/,'');
if(!E.JWT_SECRET||!E.ADMIN_PASSWORD){console.error('Set JWT_SECRET and ADMIN_PASSWORD in .env');process.exit(1)}
const dbFile=E.DB_PATH||'./data/meridian.db';fs.mkdirSync(path.dirname(dbFile),{recursive:true});
const db=new Database(dbFile);db.pragma('journal_mode=WAL');
db.exec(`CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,brand TEXT,category TEXT,price INTEGER NOT NULL,stock INTEGER NOT NULL DEFAULT 0,description TEXT,image TEXT);
CREATE TABLE IF NOT EXISTS orders(id TEXT PRIMARY KEY,created TEXT,name TEXT,phone TEXT,email TEXT,division TEXT,district TEXT,address TEXT,subtotal INTEGER,delivery INTEGER,total INTEGER,method TEXT,pay_status TEXT,pay_ref TEXT,status TEXT,items TEXT);`);
const app=express();app.set('trust proxy',1);
app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'self'"],scriptSrc:["'self'"],styleSrc:["'self'","'unsafe-inline'","https://fonts.googleapis.com"],fontSrc:["https://fonts.gstatic.com"],imgSrc:["'self'","data:","https:"],connectSrc:["'self'"],formAction:["'self'"]}}}));
app.use(express.json({limit:'100kb'}),cookie());
const bad=(res,m,c=400)=>res.status(c).json({error:m});
const DIV=['Dhaka','Chattogram','Rajshahi','Khulna','Barishal','Sylhet','Rangpur','Mymensingh'];
const PHONE=/^(?:\+?88)?01[3-9]\d{8}$/;
const safeEq=(a,b)=>{const x=crypto.createHash('sha256').update(String(a)).digest(),y=crypto.createHash('sha256').update(String(b)).digest();return crypto.timingSafeEqual(x,y)};
/* ---------- Admin auth (HttpOnly signed cookie) ---------- */
const admin=(req,res,next)=>{try{jwt.verify(req.cookies.adm,E.JWT_SECRET);next()}catch{bad(res,'Please sign in.',401)}};
app.post('/api/admin/login',rateLimit({windowMs:15*60e3,max:10}),(req,res)=>{const{user,password}=req.body||{};
 if(safeEq(user,E.ADMIN_USER||'admin')&&safeEq(password,E.ADMIN_PASSWORD)){res.cookie('adm',jwt.sign({a:1},E.JWT_SECRET,{expiresIn:'8h'}),{httpOnly:true,secure:BASE.startsWith('https'),sameSite:'strict',maxAge:8*3600e3});return res.json({ok:true})}
 bad(res,'Incorrect username or password.',401)});
app.post('/api/admin/logout',(req,res)=>{res.clearCookie('adm');res.json({ok:true})});
app.get('/api/admin/me',admin,(req,res)=>res.json({ok:true}));
/* ---------- Products ---------- */
const P=b=>{const n=String(b.name||'').trim(),pr=Math.round(+b.price),st=Math.round(+b.stock);if(!n||!(pr>=0)||!(st>=0))return null;
 return[n,String(b.brand||'').trim(),String(b.category||'Other').trim(),pr,st,String(b.description||'').trim(),String(b.image||'').trim()]};
app.get('/api/products',(q,r)=>r.json(db.prepare('SELECT * FROM products ORDER BY id DESC').all()));
app.post('/api/admin/products',admin,(q,r)=>{const v=P(q.body);if(!v)return bad(r,'Name, price and stock are required.');
 r.json({id:db.prepare('INSERT INTO products(name,brand,category,price,stock,description,image) VALUES(?,?,?,?,?,?,?)').run(...v).lastInsertRowid})});
app.put('/api/admin/products/:id',admin,(q,r)=>{const v=P(q.body);if(!v)return bad(r,'Name, price and stock are required.');
 db.prepare('UPDATE products SET name=?,brand=?,category=?,price=?,stock=?,description=?,image=? WHERE id=?').run(...v,q.params.id);r.json({ok:true})});
app.delete('/api/admin/products/:id',admin,(q,r)=>{db.prepare('DELETE FROM products WHERE id=?').run(q.params.id);r.json({ok:true})});
/* ---------- Orders ---------- */
const restock=o=>{JSON.parse(o.items).forEach(i=>db.prepare('UPDATE products SET stock=stock+? WHERE id=?').run(i.qty,i.id))};
const settle=(id,ok,ref)=>{const o=db.prepare('SELECT * FROM orders WHERE id=?').get(id);if(!o||o.pay_status!=='Awaiting payment')return;
 if(ok)db.prepare("UPDATE orders SET pay_status='Paid',pay_ref=? WHERE id=?").run(ref,id);
 else{db.transaction(()=>{restock(o);db.prepare("UPDATE orders SET pay_status='Failed',status='Cancelled' WHERE id=?").run(id)})()}};
app.post('/api/orders',rateLimit({windowMs:60e3,max:20}),async(req,res)=>{
 const b=req.body||{},name=String(b.name||'').trim(),phone=String(b.phone||'').replace(/[\s-]/g,''),division=b.division,district=String(b.district||'').trim(),address=String(b.address||'').trim();
 if(name.length<2)return bad(res,'Enter your full name.');
 if(!PHONE.test(phone))return bad(res,'Enter a valid Bangladeshi mobile number, like 01712345678.');
 if(!DIV.includes(division)||!district||address.length<8)return bad(res,'Enter your division, district and full delivery address.');
 if(!['cod','bkash','nagad'].includes(b.method))return bad(res,'Choose a payment method.');
 if(!Array.isArray(b.items)||!b.items.length)return bad(res,'Your cart is empty.');
 const id='MEL'+Date.now().toString(36).toUpperCase();let result;
 try{result=db.transaction(()=>{let sub=0;const items=[];
  for(const it of b.items){const p=db.prepare('SELECT * FROM products WHERE id=?').get(it.id),q=Math.floor(+it.qty);
   if(!p||!(q>0))throw new Error('A product in your cart is no longer available.');
   if(p.stock<q)throw new Error(`Only ${p.stock} left of ${p.name}.`);
   db.prepare('UPDATE products SET stock=stock-? WHERE id=?').run(q,p.id);sub+=p.price*q;items.push({id:p.id,name:p.name,price:p.price,qty:q})}
  const free=+E.FREE_DELIVERY_OVER>0&&sub>=+E.FREE_DELIVERY_OVER,del=free?0:(division==='Dhaka'?+(E.DELIVERY_DHAKA||70):+(E.DELIVERY_OUTSIDE||130)),total=sub+del;
  db.prepare('INSERT INTO orders VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(id,new Date().toISOString(),name,phone,String(b.email||'').trim(),division,district,address,sub,del,total,b.method,b.method==='cod'?'Cash on delivery':'Awaiting payment','','Pending',JSON.stringify(items));
  return{total}})()}catch(e){return bad(res,e.message)}
 try{
  if(b.method==='cod')return res.json({id,total:result.total});
  const url=b.method==='bkash'?await bkash.create(id,result.total):await nagad.create(id,result.total);
  res.json({id,total:result.total,redirect:url});
 }catch(e){console.error(e);settle(id,false);bad(res,'Could not start the payment. Please try again or choose Cash on delivery.',502)}});
app.get('/api/admin/orders',admin,(q,r)=>r.json(db.prepare('SELECT * FROM orders ORDER BY created DESC').all().map(o=>({...o,items:JSON.parse(o.items)}))));
app.patch('/api/admin/orders/:id',admin,(q,r)=>{const o=db.prepare('SELECT * FROM orders WHERE id=?').get(q.params.id);if(!o)return bad(r,'Order not found.',404);
 const s=q.body.status;if(!['Pending','Confirmed','Shipped','Delivered','Cancelled'].includes(s))return bad(r,'Invalid status.');
 db.transaction(()=>{if(s==='Cancelled'&&o.status!=='Cancelled')restock(o);
  if(s==='Delivered'&&o.method==='cod')db.prepare("UPDATE orders SET pay_status='Paid (cash)' WHERE id=?").run(o.id);
  db.prepare('UPDATE orders SET status=? WHERE id=?').run(s,o.id)})();r.json({ok:true})});
/* ---------- bKash Tokenized Checkout ---------- */
const bkash={async token(){const r=await fetch(E.BKASH_BASE_URL+'/tokenized/checkout/token/grant',{method:'POST',headers:{'Content-Type':'application/json',username:E.BKASH_USERNAME,password:E.BKASH_PASSWORD},body:JSON.stringify({app_key:E.BKASH_APP_KEY,app_secret:E.BKASH_APP_SECRET})});const j=await r.json();if(!j.id_token)throw new Error('bKash token: '+JSON.stringify(j));return j.id_token},
 async call(p,body){const t=await this.token(),r=await fetch(E.BKASH_BASE_URL+p,{method:'POST',headers:{'Content-Type':'application/json',Authorization:t,'X-APP-Key':E.BKASH_APP_KEY},body:JSON.stringify(body)});return r.json()},
 async create(id,amount){const j=await this.call('/tokenized/checkout/create',{mode:'0011',payerReference:id,callbackURL:`${BASE}/api/pay/bkash/callback?order=${id}`,amount:String(amount),currency:'BDT',intent:'sale',merchantInvoiceNumber:id});if(!j.bkashURL)throw new Error('bKash create: '+JSON.stringify(j));return j.bkashURL}};
app.get('/api/pay/bkash/callback',async(q,r)=>{const{order,paymentID,status}=q.query;let ok=false,ref='';
 try{if(status==='success'){const j=await bkash.call('/tokenized/checkout/execute',{paymentID});ok=j.transactionStatus==='Completed';ref=j.trxID||''}}catch(e){console.error(e)}
 settle(order,ok,ref);r.redirect(`/?${ok?'status=success':'status=failed'}&order=${encodeURIComponent(order)}`)});
/* ---------- Nagad (RSA-encrypted checkout; verify against your sandbox credentials) ---------- */
const pem=k=>(k||'').replace(/\\n/g,'\n'),pk=k=>k.includes('BEGIN')?k:`-----BEGIN PUBLIC KEY-----\n${k}\n-----END PUBLIC KEY-----`,sk=k=>k.includes('BEGIN')?k:`-----BEGIN PRIVATE KEY-----\n${k}\n-----END PRIVATE KEY-----`;
const nagad={enc:d=>crypto.publicEncrypt({key:pk(pem(E.NAGAD_PG_PUBLIC_KEY)),padding:crypto.constants.RSA_PKCS1_PADDING},Buffer.from(JSON.stringify(d))).toString('base64'),
 sign:d=>crypto.sign('sha256',Buffer.from(JSON.stringify(d)),sk(pem(E.NAGAD_MERCHANT_PRIVATE_KEY))).toString('base64'),
 dec:s=>JSON.parse(crypto.privateDecrypt({key:sk(pem(E.NAGAD_MERCHANT_PRIVATE_KEY)),padding:crypto.constants.RSA_PKCS1_PADDING},Buffer.from(s,'base64')).toString()),
 hdr:{'Content-Type':'application/json','X-KM-Api-Version':'v-0.2.0','X-KM-IP-V4':'127.0.0.1','X-KM-Client-Type':'PC_WEB'},
 async create(id,amount){const m=E.NAGAD_MERCHANT_ID,dt=new Date(Date.now()+6*3600e3).toISOString().replace(/\D/g,'').slice(0,14);
  const s1={merchantId:m,datetime:dt,orderId:id,challenge:crypto.randomBytes(20).toString('hex')};
  const i=await(await fetch(`${E.NAGAD_BASE_URL}/check-out/initialize/${m}/${id}`,{method:'POST',headers:this.hdr,body:JSON.stringify({dateTime:dt,sensitiveData:this.enc(s1),signature:this.sign(s1)})})).json();
  if(!i.sensitiveData)throw new Error('Nagad init: '+JSON.stringify(i));const d=this.dec(i.sensitiveData);
  const s2={merchantId:m,orderId:id,currencyCode:'050',amount:String(amount),challenge:d.challenge};
  const c=await(await fetch(`${E.NAGAD_BASE_URL}/check-out/complete/${d.paymentReferenceId}`,{method:'POST',headers:this.hdr,body:JSON.stringify({sensitiveData:this.enc(s2),signature:this.sign(s2),merchantCallbackURL:`${BASE}/api/pay/nagad/callback?order=${id}`,additionalMerchantInfo:{}})})).json();
  if(!c.callBackUrl)throw new Error('Nagad complete: '+JSON.stringify(c));return c.callBackUrl}};
app.get('/api/pay/nagad/callback',async(q,r)=>{const{order,payment_ref_id}=q.query;let ok=false;
 try{const v=await(await fetch(`${E.NAGAD_BASE_URL}/verify/payment/${payment_ref_id}`,{headers:nagad.hdr})).json();ok=v.status==='Success'&&String(v.orderId)===String(order)}catch(e){console.error(e)}
 settle(order,ok,payment_ref_id||'');r.redirect(`/?${ok?'status=success':'status=failed'}&order=${encodeURIComponent(order)}`)});
app.get('/healthz',(q,r)=>r.send('ok'));
app.use(express.static(path.join(__dirname,'public')));
app.listen(PORT,()=>console.log('Meridian running on '+BASE));
