const express=require("express");
const session=require("express-session");
const Database=require("better-sqlite3");
const bcrypt=require("bcryptjs");
const path=require("path");
const app=express();
const db=new Database("didno.db");
app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(session({secret:process.env.SESSION_SECRET||"change-this-secret",resave:false,saveUninitialized:false,cookie:{httpOnly:true,maxAge:86400000}}));
app.use(express.static(path.join(__dirname,"public")));

db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,password TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'user',created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS services(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,description TEXT NOT NULL,price TEXT NOT NULL,icon TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,name TEXT NOT NULL,phone TEXT NOT NULL,service TEXT NOT NULL,details TEXT, status TEXT DEFAULT 'در انتظار بررسی',created_at TEXT DEFAULT CURRENT_TIMESTAMP);
`);
if(!db.prepare("SELECT 1 FROM users WHERE email=?").get("admin@didno.ir")){
  db.prepare("INSERT INTO users(name,email,password,role) VALUES(?,?,?,?)").run("مدیر دیدنو","admin@didno.ir",bcrypt.hashSync("Admin12345!",10),"admin");
}
if(db.prepare("SELECT COUNT(*) c FROM services").get().c===0){
  const ins=db.prepare("INSERT INTO services(title,description,price,icon) VALUES(?,?,?,?)");
  [
    ["طراحی گرافیک","طراحی پوستر، کارت ویزیت، بنر و محتوای تبلیغاتی","تماس بگیرید","🎨"],
    ["چاپ و استیکر","چاپ استیکر، شبرنگ، روزرنگ و تبلیغات شیشه","تماس بگیرید","🖨️"],
    ["فنرزنی کتاب","فنرزنی ساده، طلق‌دار و جلد پرس‌شده","از ۱۰۸٬۰۰۰ تومان","📚"],
    ["تابلو و تبلیغات محیطی","طراحی و اجرای تبلیغات برای فروشگاه‌ها و کسب‌وکارها","استعلام قیمت","🏪"],
    ["تولید محتوای تبلیغاتی","طراحی محتوای شبکه‌های اجتماعی و ویدئوی کوتاه","استعلام قیمت","🎬"],
    ["سفارش اختصاصی","ایده‌پردازی و اجرای پروژه‌های خاص تبلیغاتی","توافقی","✨"]
  ].forEach(x=>ins.run(...x));
}

function auth(req,res,next){if(!req.session.user)return res.status(401).json({error:"ابتدا وارد حساب شوید"});next()}
function admin(req,res,next){if(!req.session.user||req.session.user.role!=="admin")return res.status(403).json({error:"دسترسی مدیر لازم است"});next()}

app.get("/api/services",(req,res)=>res.json(db.prepare("SELECT * FROM services ORDER BY id").all()));
app.post("/api/register",(req,res)=>{
  const {name,email,password}=req.body;
  if(!name||!email||!password||password.length<6)return res.status(400).json({error:"نام، ایمیل و رمز حداقل ۶ کاراکتر الزامی است"});
  try{
    const info=db.prepare("INSERT INTO users(name,email,password) VALUES(?,?,?)").run(name,email,bcrypt.hashSync(password,10));
    req.session.user={id:info.lastInsertRowid,name,email,role:"user"};
    res.json({user:req.session.user});
  }catch(e){res.status(400).json({error:"این ایمیل قبلاً ثبت شده است"})}
});
app.post("/api/login",(req,res)=>{
  const u=db.prepare("SELECT * FROM users WHERE email=?").get(req.body.email);
  if(!u||!bcrypt.compareSync(req.body.password,u.password))return res.status(401).json({error:"ایمیل یا رمز عبور اشتباه است"});
  req.session.user={id:u.id,name:u.name,email:u.email,role:u.role};res.json({user:req.session.user});
});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me",(req,res)=>res.json({user:req.session.user||null}));
app.post("/api/orders",auth,(req,res)=>{
  const {name,phone,service,details}=req.body;
  if(!name||!phone||!service)return res.status(400).json({error:"نام، شماره و خدمت الزامی است"});
  const x=db.prepare("INSERT INTO orders(user_id,name,phone,service,details) VALUES(?,?,?,?,?)").run(req.session.user.id,name,phone,service,details||"");
  res.json({id:x.lastInsertRowid});
});
app.get("/api/orders",admin,(req,res)=>res.json(db.prepare("SELECT * FROM orders ORDER BY id DESC").all()));
app.patch("/api/orders/:id",admin,(req,res)=>{
  db.prepare("UPDATE orders SET status=? WHERE id=?").run(req.body.status,req.params.id);res.json({ok:true});
});
app.post("/api/services",admin,(req,res)=>{
  const {title,description,price,icon}=req.body;
  db.prepare("INSERT INTO services(title,description,price,icon) VALUES(?,?,?,?)").run(title,description,price,icon||"✨");res.json({ok:true});
});
app.delete("/api/services/:id",admin,(req,res)=>{db.prepare("DELETE FROM services WHERE id=?").run(req.params.id);res.json({ok:true})});
app.get("/api/stats",admin,(req,res)=>res.json({
  users:db.prepare("SELECT COUNT(*) c FROM users WHERE role='user'").get().c,
  orders:db.prepare("SELECT COUNT(*) c FROM orders").get().c,
  pending:db.prepare("SELECT COUNT(*) c FROM orders WHERE status='در انتظار بررسی'").get().c,
  services:db.prepare("SELECT COUNT(*) c FROM services").get().c
}));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(process.env.PORT||3000,()=>console.log("Didno running on http://localhost:3000"));