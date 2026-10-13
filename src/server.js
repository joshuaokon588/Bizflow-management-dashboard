'use strict';
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');

const required = ['JWT_SECRET','DB_HOST','DB_NAME','DB_USER','DB_PASSWORD'];
for (const key of required) if (!process.env[key] || process.env[key].startsWith('REPLACE_')) {
  console.error(`Missing or placeholder environment variable: ${key}`); process.exit(1);
}
if (process.env.NODE_ENV === 'production' && process.env.JWT_SECRET.length < 48) {
  console.error('JWT_SECRET must be at least 48 characters in production.'); process.exit(1);
}

const app = express();
const PORT = Number(process.env.PORT || 4000);
const pool = mysql.createPool({
  host: process.env.DB_HOST, port: Number(process.env.DB_PORT || 3306),
  database: process.env.DB_NAME, user: process.env.DB_USER, password: process.env.DB_PASSWORD,
  waitForConnections: true, connectionLimit: Number(process.env.DB_CONNECTION_LIMIT || 10),
  queueLimit: 0, enableKeepAlive: true, decimalNumbers: true, charset: 'utf8mb4'
});
const allowedOrigins = (process.env.APP_ORIGIN || `http://localhost:${PORT}`).split(',').map(x => x.trim());
app.disable('x-powered-by');
app.set('trust proxy', process.env.TRUST_PROXY === 'true' ? 1 : false);
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"],
  imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"], objectSrc: ["'none'"],
  upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null
}}}));
app.use(cors({ origin(origin, cb) { if (!origin || allowedOrigins.includes(origin)) return cb(null, true); return cb(new Error('Origin not allowed')); }, methods: ['GET','POST','PATCH','DELETE'], allowedHeaders: ['Content-Type','Authorization'], maxAge: 600 }));
app.use(express.json({ limit: '100kb', strict: true }));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));
app.use((req,res,next) => {
  req.requestId = crypto.randomUUID(); res.setHeader('X-Request-Id', req.requestId);
  const start = Date.now(); res.on('finish', () => console.log(JSON.stringify({ level:'info', requestId:req.requestId, method:req.method, path:req.path, status:res.statusCode, durationMs:Date.now()-start, ip:req.ip })));
  next();
});
const loginLimiter = rateLimit({ windowMs: 15*60*1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false, message: { error:'Too many login attempts. Try again in 15 minutes.' } });
const apiLimiter = rateLimit({ windowMs: 60*1000, limit: 120, standardHeaders: 'draft-7', legacyHeaders: false, message: { error:'Too many requests. Please slow down.' } });
app.use('/api', apiLimiter);
const asyncRoute = fn => (req,res,next) => Promise.resolve(fn(req,res,next)).catch(next);
const fail = (res,status,error) => res.status(status).json({ error });
const clean = v => typeof v === 'string' ? v.trim() : v;
const validEmail = v => typeof v === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) && v.length <= 190;
const positiveInt = v => Number.isInteger(Number(v)) && Number(v) > 0;
const nonnegativeMoney = v => Number.isFinite(Number(v)) && Number(v) >= 0 && Number(v) <= 999999999999;
const money = n => Math.round((Number(n) + Number.EPSILON) * 100) / 100;
async function audit(userId, action, entityType, entityId, req, metadata={}) {
  try { await pool.execute('INSERT INTO audit_logs (user_id,action,entity_type,entity_id,ip_address,metadata) VALUES (?,?,?,?,?,?)', [userId || null, action, entityType, entityId == null ? null : String(entityId), req.ip, JSON.stringify(metadata)]); }
  catch (e) { console.error(JSON.stringify({level:'error',message:'audit_write_failed',requestId:req.requestId,error:e.message})); }
}
function auth(req,res,next) {
  const header = req.headers.authorization || ''; const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) return fail(res,401,'Authentication required.');
  try { req.user = jwt.verify(token, process.env.JWT_SECRET, { algorithms:['HS256'], issuer:'bizflow-api', audience:'bizflow-client' }); next(); }
  catch { return fail(res,401,'Session is invalid or expired. Please sign in again.'); }
}
const roles = (...allowed) => (req,res,next) => allowed.includes(req.user.role) ? next() : fail(res,403,'You do not have permission to perform this action.');
app.get('/api/health', asyncRoute(async (req,res) => {
  try { await pool.query('SELECT 1'); res.json({ status:'ok', database:'connected', timestamp:new Date().toISOString(), requestId:req.requestId }); }
  catch { res.status(503).json({ status:'degraded', database:'unavailable', requestId:req.requestId }); }
}));
app.post('/api/auth/login', loginLimiter, asyncRoute(async (req,res) => {
  const email = String(req.body.email || '').trim().toLowerCase(); const password = req.body.password;
  if (!validEmail(email) || typeof password !== 'string' || password.length < 1 || password.length > 200) return fail(res,400,'Enter a valid email and password.');
  const [rows] = await pool.execute('SELECT id,name,email,password_hash,role,is_active FROM users WHERE email=? LIMIT 1',[email]);
  const user = rows[0]; const matches = user ? await bcrypt.compare(password,user.password_hash) : await bcrypt.compare(password,'$2a$10$abcdefghijklmnopqrstuuD6F6zqv4X6F0KQ5bJ2m1oW');
  if (!user || !matches || !user.is_active) { await audit(user?.id,'login_failed','user',user?.id,req,{email}); return fail(res,401,'Email or password is incorrect.'); }
  const token = jwt.sign({ sub:String(user.id), name:user.name, email:user.email, role:user.role }, process.env.JWT_SECRET, { algorithm:'HS256', expiresIn:process.env.JWT_EXPIRES_IN || '30m', issuer:'bizflow-api', audience:'bizflow-client' });
  await pool.execute('UPDATE users SET last_login_at=NOW() WHERE id=?',[user.id]); await audit(user.id,'login_success','user',user.id,req);
  res.json({ token, expiresIn:process.env.JWT_EXPIRES_IN || '30m', user:{id:user.id,name:user.name,email:user.email,role:user.role} });
}));
app.get('/api/auth/me', auth, asyncRoute(async (req,res) => {
  const [rows] = await pool.execute('SELECT id,name,email,role,is_active FROM users WHERE id=?',[req.user.sub]);
  if (!rows[0] || !rows[0].is_active) return fail(res,401,'Account is unavailable.');
  res.json({ user:rows[0] });
}));
app.post('/api/auth/logout', auth, asyncRoute(async (req,res) => { await audit(req.user.sub,'logout','user',req.user.sub,req); res.json({message:'Signed out. Discard the token on this device.'}); }));
app.get('/api/dashboard', auth, asyncRoute(async (req,res) => {
  const [[p]] = await pool.query('SELECT COUNT(*) totalProducts, COALESCE(SUM(stock),0) unitsInStock, SUM(stock <= low_stock_threshold) lowStock FROM products WHERE is_active=1');
  const [[c]] = await pool.query('SELECT COUNT(*) totalCustomers FROM customers');
  const [[s]] = await pool.query("SELECT COUNT(*) salesCount, COALESCE(SUM(total),0) salesTotal FROM sales WHERE status='completed' AND created_at >= DATE_FORMAT(CURRENT_DATE,'%Y-%m-01')");
  const [[e]] = await pool.query('SELECT COALESCE(SUM(amount),0) expensesTotal FROM expenses WHERE expense_date >= DATE_FORMAT(CURRENT_DATE,\'%Y-%m-01\') AND expense_date < DATE_ADD(CURRENT_DATE, INTERVAL 1 DAY)');
  const [recentSales] = await pool.query('SELECT s.id,s.sale_number,s.total,s.payment_method,s.created_at,c.name customer_name FROM sales s LEFT JOIN customers c ON c.id=s.customer_id ORDER BY s.created_at DESC LIMIT 6');
  res.json({ metrics:{...p,...c,...s,...e, netBeforeOtherCosts:money(s.salesTotal-e.expensesTotal)}, recentSales });
}));
app.get('/api/customers', auth, asyncRoute(async (req,res) => { const q = String(req.query.q || '').trim().slice(0,100); const [rows] = q ? await pool.execute('SELECT id,name,email,phone,company,notes,created_at FROM customers WHERE name LIKE ? OR email LIKE ? OR company LIKE ? ORDER BY created_at DESC LIMIT 200',[`%${q}%`,`%${q}%`,`%${q}%`]) : await pool.query('SELECT id,name,email,phone,company,notes,created_at FROM customers ORDER BY created_at DESC LIMIT 200'); res.json({customers:rows}); }));
app.post('/api/customers', auth, roles('admin','manager','staff'), asyncRoute(async (req,res) => {
  const name=clean(req.body.name), email=clean(req.body.email||'')||null, phone=clean(req.body.phone||'')||null, company=clean(req.body.company||'')||null, notes=clean(req.body.notes||'')||null;
  if (typeof name!=='string'||name.length<2||name.length>160) return fail(res,400,'Customer name must be 2–160 characters.');
  if (email && !validEmail(email)) return fail(res,400,'Enter a valid email address.');
  if ([phone,company].some(v=>v && (typeof v!=='string'||v.length>160)) || (notes && (typeof notes!=='string'||notes.length>2000))) return fail(res,400,'One or more fields are too long.');
  const [r]=await pool.execute('INSERT INTO customers(name,email,phone,company,notes,created_by) VALUES(?,?,?,?,?,?)',[name,email,phone,company,notes,req.user.sub]); await audit(req.user.sub,'customer_created','customer',r.insertId,req); res.status(201).json({id:r.insertId,message:'Customer created.'});
}));
app.patch('/api/customers/:id', auth, roles('admin','manager'), asyncRoute(async (req,res) => {
  if(!positiveInt(req.params.id)) return fail(res,400,'Invalid customer ID.');
  const fields=['name','email','phone','company','notes']; const sets=[], vals=[];
  for(const f of fields) if(Object.prototype.hasOwnProperty.call(req.body,f)){ let v=clean(req.body[f]); if(f==='email'){v=v||null;if(v&&!validEmail(v))return fail(res,400,'Invalid email.');} if(f==='name'&&(typeof v!=='string'||v.length<2||v.length>160))return fail(res,400,'Invalid name.'); if(v!==null&&typeof v!=='string')return fail(res,400,`Invalid ${f}.`); if(typeof v==='string'&&v.length>(f==='notes'?2000:160))return fail(res,400,`${f} is too long.`); sets.push(`${f}=?`);vals.push(v||null); }
  if(!sets.length)return fail(res,400,'No valid fields provided.'); vals.push(req.params.id); const [r]=await pool.execute(`UPDATE customers SET ${sets.join(',')} WHERE id=?`,vals); if(!r.affectedRows)return fail(res,404,'Customer not found.'); await audit(req.user.sub,'customer_updated','customer',req.params.id,req); res.json({message:'Customer updated.'});
}));
app.delete('/api/customers/:id', auth, roles('admin','manager'), asyncRoute(async (req,res) => { if(!positiveInt(req.params.id))return fail(res,400,'Invalid customer ID.'); const [r]=await pool.execute('DELETE FROM customers WHERE id=?',[req.params.id]); if(!r.affectedRows)return fail(res,404,'Customer not found.'); await audit(req.user.sub,'customer_deleted','customer',req.params.id,req); res.json({message:'Customer deleted.'}); }));
app.get('/api/products', auth, asyncRoute(async (req,res) => { const q=String(req.query.q||'').trim().slice(0,100); const [rows]=q?await pool.execute('SELECT id,sku,name,description,price,stock,low_stock_threshold,is_active,created_at FROM products WHERE is_active=1 AND (name LIKE ? OR sku LIKE ?) ORDER BY name LIMIT 300',[`%${q}%`,`%${q}%`]):await pool.query('SELECT id,sku,name,description,price,stock,low_stock_threshold,is_active,created_at FROM products WHERE is_active=1 ORDER BY name LIMIT 300');res.json({products:rows}); }));
app.post('/api/products', auth, roles('admin','manager'), asyncRoute(async (req,res) => {
  const sku=clean(req.body.sku),name=clean(req.body.name),description=clean(req.body.description||'')||null,price=Number(req.body.price),stock=Number(req.body.stock),threshold=Number(req.body.low_stock_threshold??5);
  if(typeof sku!=='string'||sku.length<1||sku.length>80||typeof name!=='string'||name.length<2||name.length>160)return fail(res,400,'SKU and product name are required.');
  if(!nonnegativeMoney(price)||!Number.isInteger(stock)||stock<0||stock>100000000||!Number.isInteger(threshold)||threshold<0||threshold>1000000)return fail(res,400,'Enter valid price, stock and low-stock threshold.');
  const [r]=await pool.execute('INSERT INTO products(sku,name,description,price,stock,low_stock_threshold,created_by) VALUES(?,?,?,?,?,?,?)',[sku,name,description,price,stock,threshold,req.user.sub]);await audit(req.user.sub,'product_created','product',r.insertId,req);res.status(201).json({id:r.insertId,message:'Product created.'});
}));
app.patch('/api/products/:id', auth, roles('admin','manager'), asyncRoute(async (req,res) => {
  if(!positiveInt(req.params.id))return fail(res,400,'Invalid product ID.');const fields=['sku','name','description','price','stock','low_stock_threshold','is_active'];const sets=[],vals=[];
  for(const f of fields)if(Object.prototype.hasOwnProperty.call(req.body,f)){let v=req.body[f];if(['sku','name','description'].includes(f)){v=clean(v);if(typeof v!=='string'||v.length>(f==='description'?3000:f==='sku'?80:160))return fail(res,400,`Invalid ${f}.`);}if(f==='price'&&(!nonnegativeMoney(v)))return fail(res,400,'Invalid price.');if(['stock','low_stock_threshold'].includes(f)&&(!Number.isInteger(Number(v))||Number(v)<0))return fail(res,400,`Invalid ${f}.`);if(f==='is_active'&&typeof v!=='boolean')return fail(res,400,'is_active must be true or false.');sets.push(`${f}=?`);vals.push(v);}
  if(!sets.length)return fail(res,400,'No valid fields provided.');vals.push(req.params.id);const [r]=await pool.execute(`UPDATE products SET ${sets.join(',')} WHERE id=?`,vals);if(!r.affectedRows)return fail(res,404,'Product not found.');await audit(req.user.sub,'product_updated','product',req.params.id,req);res.json({message:'Product updated.'});
}));
app.delete('/api/products/:id', auth, roles('admin'), asyncRoute(async (req,res) => {if(!positiveInt(req.params.id))return fail(res,400,'Invalid product ID.');const [r]=await pool.execute('UPDATE products SET is_active=0 WHERE id=?',[req.params.id]);if(!r.affectedRows)return fail(res,404,'Product not found.');await audit(req.user.sub,'product_archived','product',req.params.id,req);res.json({message:'Product archived.'});}));
app.get('/api/sales', auth, asyncRoute(async (req,res) => {const [rows]=await pool.query('SELECT s.id,s.sale_number,s.total,s.payment_method,s.status,s.created_at,c.name customer_name,u.name created_by_name FROM sales s LEFT JOIN customers c ON c.id=s.customer_id LEFT JOIN users u ON u.id=s.created_by ORDER BY s.created_at DESC LIMIT 200');res.json({sales:rows});}));
app.post('/api/sales', auth, roles('admin','manager','staff'), asyncRoute(async (req,res) => {
  const items=req.body.items,customerId=req.body.customer_id||null,payment=req.body.payment_method||'transfer',notes=clean(req.body.notes||'')||null;
  if(!Array.isArray(items)||items.length<1||items.length>50)return fail(res,400,'A sale must contain between 1 and 50 line items.');if(!['cash','transfer','card','other'].includes(payment))return fail(res,400,'Invalid payment method.');if(customerId&&!positiveInt(customerId))return fail(res,400,'Invalid customer.');
  const conn=await pool.getConnection();try{await conn.beginTransaction();if(customerId){const [c]=await conn.execute('SELECT id FROM customers WHERE id=?',[customerId]);if(!c.length)throw Object.assign(new Error('Customer not found.'),{status:400});}
    let subtotal=0;const lines=[];
    for(const item of items){if(!positiveInt(item.product_id)||!positiveInt(item.quantity)||Number(item.quantity)>100000)throw Object.assign(new Error('Each item requires a valid product and quantity.'),{status:400});const [pr]=await conn.execute('SELECT id,sku,name,price,stock FROM products WHERE id=? AND is_active=1 FOR UPDATE',[item.product_id]);if(!pr.length)throw Object.assign(new Error('A selected product is unavailable.'),{status:400});const p=pr[0],qty=Number(item.quantity);if(p.stock<qty)throw Object.assign(new Error(`Insufficient stock for ${p.name}.`),{status:409});const line=money(p.price*qty);subtotal=money(subtotal+line);lines.push({p,qty,line});}
    const saleNo=`BF-${Date.now()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;const [sr]=await conn.execute('INSERT INTO sales(sale_number,customer_id,subtotal,total,payment_method,notes,created_by) VALUES(?,?,?,?,?,?,?)',[saleNo,customerId,subtotal,subtotal,payment,notes,req.user.sub]);
    for(const l of lines){await conn.execute('INSERT INTO sale_items(sale_id,product_id,product_name,sku,quantity,unit_price,line_total) VALUES(?,?,?,?,?,?,?)',[sr.insertId,l.p.id,l.p.name,l.p.sku,l.qty,l.p.price,l.line]);const [ur]=await conn.execute('UPDATE products SET stock=stock-? WHERE id=? AND stock>=?',[l.qty,l.p.id,l.qty]);if(!ur.affectedRows)throw Object.assign(new Error('Stock changed while processing the sale. Please retry.'),{status:409});}
    await conn.commit();await audit(req.user.sub,'sale_created','sale',sr.insertId,req,{sale_number:saleNo,total:subtotal});res.status(201).json({id:sr.insertId,sale_number:saleNo,total:subtotal,message:'Sale recorded and inventory updated.'});
  }catch(e){await conn.rollback();throw e;}finally{conn.release();}
}));
app.get('/api/sales/:id/items', auth, asyncRoute(async (req,res)=>{if(!positiveInt(req.params.id))return fail(res,400,'Invalid sale ID.');const [rows]=await pool.execute('SELECT product_name,sku,quantity,unit_price,line_total FROM sale_items WHERE sale_id=?',[req.params.id]);res.json({items:rows});}));
app.get('/api/expenses', auth, asyncRoute(async (req,res)=>{const [rows]=await pool.query('SELECT e.id,e.category,e.description,e.amount,e.expense_date,e.created_at,u.name created_by_name FROM expenses e LEFT JOIN users u ON u.id=e.created_by ORDER BY e.expense_date DESC,e.id DESC LIMIT 200');res.json({expenses:rows});}));
app.post('/api/expenses', auth, roles('admin','manager'), asyncRoute(async (req,res)=>{const category=clean(req.body.category),description=clean(req.body.description),amount=Number(req.body.amount),date=String(req.body.expense_date||new Date().toISOString().slice(0,10));if(typeof category!=='string'||!category||category.length>100||typeof description!=='string'||description.length<2||description.length>255)return fail(res,400,'Enter a category and description.');if(!Number.isFinite(amount)||amount<=0||amount>999999999999)return fail(res,400,'Expense amount must be greater than zero.');if(!/^\d{4}-\d{2}-\d{2}$/.test(date)||Number.isNaN(Date.parse(`${date}T00:00:00Z`)))return fail(res,400,'Use a valid expense date (YYYY-MM-DD).');const [r]=await pool.execute('INSERT INTO expenses(category,description,amount,expense_date,created_by) VALUES(?,?,?,?,?)',[category,description,amount,date,req.user.sub]);await audit(req.user.sub,'expense_created','expense',r.insertId,req,{amount});res.status(201).json({id:r.insertId,message:'Expense recorded.'});}));
app.get('/api/audit-logs', auth, roles('admin'), asyncRoute(async (req,res)=>{const [rows]=await pool.query('SELECT a.id,a.action,a.entity_type,a.entity_id,a.ip_address,a.metadata,a.created_at,u.name user_name,u.email user_email FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.created_at DESC LIMIT 200');res.json({logs:rows});}));
app.use('/api', (req,res)=>fail(res,404,'API endpoint not found.'));
app.use(express.static(path.join(__dirname,'..','public'), { extensions:['html'], maxAge:process.env.NODE_ENV==='production'?'1h':0, etag:true }));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'..','public','index.html')));
app.use((err,req,res,next)=>{console.error(JSON.stringify({level:'error',requestId:req.requestId,message:err.message,stack:process.env.NODE_ENV==='production'?undefined:err.stack}));if(res.headersSent)return next(err);const status=err.status|| (err.code==='ER_DUP_ENTRY'?409:err.message==='Origin not allowed'?403:500);res.status(status).json({error:status>=500?'An unexpected server error occurred.':err.message,requestId:req.requestId});});
const server=app.listen(PORT,()=>console.log(JSON.stringify({level:'info',message:'BizFlow API started',port:PORT,env:process.env.NODE_ENV||'development'})));
async function shutdown(signal){console.log(`${signal} received; shutting down`);server.close(async()=>{await pool.end();process.exit(0);});setTimeout(()=>process.exit(1),10000).unref();}
process.on('SIGINT',()=>shutdown('SIGINT'));process.on('SIGTERM',()=>shutdown('SIGTERM'));
