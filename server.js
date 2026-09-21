
const express = require("express");
const cookieParser = require("cookie-parser");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const DATA = path.join(__dirname, "data.json");
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@didno.ir";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "Admin12345!";
const SECRET = process.env.AUTH_SECRET || "didno-change-this-secret-in-render";

app.use(express.json({limit:"2mb"}));
app.use(cookieParser());
app.use(express.static(path.join(__dirname,"public")));

function readDB(){
  try { return JSON.parse(fs.readFileSync(DATA,"utf8")); }
  catch(e){ return {products:[],users:[],orders:[]}; }
}
function writeDB(db){ fs.writeFileSync(DATA, JSON.stringify(db,null,2), "utf8"); }
function id(prefix){ return prefix+"_"+crypto.randomBytes(6).toString("hex"); }
function hash(p){ return crypto.createHash("sha256").update(p).digest("hex"); }
function sign(payload){
  const raw = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256",SECRET).update(raw).digest("base64url");
  return raw+"."+sig;
}
function verify(token){
  try{
    const [raw,sig]=token.split(".");
    const expected=crypto.createHmac("sha256",SECRET).update(raw).digest("base64url");
    if(!sig || !crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(expected))) return null;
    const p=JSON.parse(Buffer.from(raw,"base64url").toString());
    if(p.exp && p.exp<Date.now()) return null;
    return p;
  }catch(e){return null}
}
function setAuth(res,payload){
  res.cookie("didno_auth", sign({...payload,exp:Date.now()+1000*60*60*24*7}), {
    httpOnly:true, sameSite:"lax", secure:process.env.NODE_ENV==="production", maxAge:1000*60*60*24*7
  });
}
function auth(req){
  return verify(req.cookies.didno_auth || "");
}
function adminOnly(req,res,next){
  const a=auth(req);
  if(!a || a.role!=="admin") return res.status(401).json({error:"دسترسی مدیر مورد نیاز است"});
  next();
}

app.get("/api/health",(req,res)=>res.json({ok:true,service:"didno",time:new Date().toISOString()}));
app.get("/api/products",(req,res)=>res.json(readDB().products.filter(p=>p.active!==false)));
app.get("/api/me",(req,res)=>res.json({user:auth(req)}));

app.post("/api/register",(req,res)=>{
  const {name,email,password}=req.body||{};
  if(!name || !email || !password || password.length<6) return res.status(400).json({error:"نام، ایمیل و رمز عبور حداقل ۶ کاراکتری را وارد کنید."});
  const db=readDB();
  email=email.trim().toLowerCase();
  if(db.users.some(u=>u.email===email)) return res.status(409).json({error:"این ایمیل قبلاً ثبت شده است."});
  const user={id:id("u"),name:name.trim(),email,password:hash(password),createdAt:new Date().toISOString()};
  db.users.push(user); writeDB(db);
  setAuth(res,{id:user.id,name:user.name,email:user.email,role:"user"});
  res.json({ok:true,user:{id:user.id,name:user.name,email:user.email,role:"user"}});
});

app.post("/api/login",(req,res)=>{
  const {email,password}=req.body||{};
  const e=(email||"").trim().toLowerCase();
  if(e===ADMIN_EMAIL && password===ADMIN_PASSWORD){
    setAuth(res,{id:"admin",name:"مدیر دیدنو",email:ADMIN_EMAIL,role:"admin"});
    return res.json({ok:true,role:"admin"});
  }
  const db=readDB();
  const u=db.users.find(x=>x.email===e && x.password===hash(password||""));
  if(!u) return res.status(401).json({error:"ایمیل یا رمز عبور اشتباه است."});
  setAuth(res,{id:u.id,name:u.name,email:u.email,role:"user"});
  res.json({ok:true,role:"user"});
});
app.post("/api/logout",(req,res)=>{res.clearCookie("didno_auth");res.json({ok:true});});

app.post("/api/orders",(req,res)=>{
  const a=auth(req);
  const {items,customer,message}=req.body||{};
  if(!Array.isArray(items)||!items.length) return res.status(400).json({error:"سبد خرید خالی است."});
  const db=readDB();
  const cleanItems=items.map(x=>({
    productId:x.productId,name:x.name,qty:Math.max(1,Number(x.qty)||1),
    unit:x.unit,price:Number(x.price)||0,contact:!!x.contact
  }));
  const order={id:id("ORD"),userId:a?.id||null,customer:customer||{},items:cleanItems,message:message||"",status:"در انتظار بررسی",createdAt:new Date().toISOString()};
  db.orders.unshift(order); writeDB(db);
  res.json({ok:true,orderId:order.id});
});

app.get("/api/orders",adminOnly,(req,res)=>res.json(readDB().orders));
app.patch("/api/orders/:id",adminOnly,(req,res)=>{
  const db=readDB(), o=db.orders.find(x=>x.id===req.params.id);
  if(!o) return res.status(404).json({error:"سفارش پیدا نشد."});
  o.status=req.body.status||o.status; writeDB(db); res.json({ok:true,order:o});
});

app.get("/api/admin/stats",adminOnly,(req,res)=>{
  const db=readDB();
  res.json({
    products:db.products.length,
    activeProducts:db.products.filter(p=>p.active!==false).length,
    users:db.users.length,
    orders:db.orders.length,
    pending:db.orders.filter(o=>o.status==="در انتظار بررسی").length
  });
});
app.get("/api/admin/products",adminOnly,(req,res)=>res.json(readDB().products));
app.post("/api/admin/products",adminOnly,(req,res)=>{
  const db=readDB(), b=req.body||{};
  const p={id:id("p"),cat:b.cat||"سایر",icon:b.icon||"✦",name:(b.name||"محصول جدید").trim(),desc:b.desc||"",unit:b.unit||"استعلام",price:Number(b.price)||0,contact:!!b.contact,active:b.active!==false};
  db.products.push(p); writeDB(db); res.json({ok:true,product:p});
});
app.put("/api/admin/products/:id",adminOnly,(req,res)=>{
  const db=readDB(), p=db.products.find(x=>x.id===req.params.id);
  if(!p) return res.status(404).json({error:"محصول پیدا نشد."});
  Object.assign(p,{
    cat:req.body.cat??p.cat,icon:req.body.icon??p.icon,name:req.body.name??p.name,
    desc:req.body.desc??p.desc,unit:req.body.unit??p.unit,
    price:Number(req.body.price)||0,contact:!!req.body.contact,active:req.body.active!==false
  });
  writeDB(db); res.json({ok:true,product:p});
});
app.delete("/api/admin/products/:id",adminOnly,(req,res)=>{
  const db=readDB(); db.products=db.products.filter(x=>x.id!==req.params.id); writeDB(db); res.json({ok:true});
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,"0.0.0.0",()=>console.log(`Didno Pro running on port ${PORT}`));
