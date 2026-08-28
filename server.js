const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA = path.join(ROOT, "data");
const UPLOADS = path.join(DATA, "uploads");
fs.mkdirSync(UPLOADS, { recursive: true });

const db = new Database(path.join(DATA, "satyam.db"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  quota_bytes INTEGER NOT NULL DEFAULT 5368709120,
  used_bytes INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS pending_otps (
  email TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS password_resets (
  email TEXT PRIMARY KEY,
  code_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS folders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  original_name TEXT NOT NULL,
  stored_name TEXT NOT NULL UNIQUE,
  mime_type TEXT,
  size_bytes INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);
try { db.exec("ALTER TABLE users ADD COLUMN profile_photo TEXT"); } catch(e) {}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || "CHANGE_THIS_SECRET_BEFORE_PRODUCTION",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));
app.use(express.static(path.join(ROOT, "public")));

function currentUser(req) {
  if (!req.session.userId) return null;
  return db.prepare("SELECT id,name,email,quota_bytes,used_bytes,created_at FROM users WHERE id=?").get(req.session.userId);
}
function auth(req, res, next) {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "लॉगिन जरूरी है।" });
  req.user = user;
  next();
}
function gb(n) { return (n / (1024 ** 3)).toFixed(2); }

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).slice(0, 20);
    cb(null, crypto.randomUUID() + ext);
  }
});
const photoStorage = multer.diskStorage({
  destination: (req,file,cb)=>cb(null, UPLOADS),
  filename: (req,file,cb)=>cb(null, "profile-"+crypto.randomUUID()+path.extname(file.originalname))
});
const photoUpload = multer({ storage: photoStorage, limits:{fileSize:5*1024*1024}, fileFilter:(req,file,cb)=>cb(null, file.mimetype.startsWith("image/")) });

const upload = multer({
  storage,
  limits: { fileSize: 1024 * 1024 * 1024 } // 1 GB per file
});

app.get("/api/me", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.json({ loggedIn: false });
  res.json({ loggedIn: true, user, quotaGB: gb(user.quota_bytes), usedGB: gb(user.used_bytes) });
});

async function sendOtpEmail(email, code) {
  const host = process.env.SMTP_HOST;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  if (!host || !user || !pass) {
    console.log(`OTP for ${email}: ${code}`);
    return { configured: false };
  }
  const transporter = nodemailer.createTransport({
    host,
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE || "false") === "true",
    auth: { user, pass }
  });
  await transporter.sendMail({
    from: process.env.SMTP_FROM || user,
    to: email,
    subject: "Satyam With Me OTP Verification",
    text: `Your Satyam With Me verification code is ${code}. It expires in 10 minutes.`
  });
  return { configured: true };
}

app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: "नाम, ईमेल और पासवर्ड जरूरी हैं।" });
  if (password.length < 6) return res.status(400).json({ error: "पासवर्ड कम से कम 6 अक्षर का रखें।" });
  const cleanEmail = String(email).trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) return res.status(400).json({ error: "सही ईमेल डालें।" });
  if (db.prepare("SELECT id FROM users WHERE email=?").get(cleanEmail)) return res.status(409).json({ error: "यह ईमेल पहले से रजिस्टर है।" });

  try {
    const hash = await bcrypt.hash(password, 12);
    const code = String(Math.floor(100000 + Math.random() * 900000));
    const codeHash = await bcrypt.hash(code, 10);
    const expires = Date.now() + 10 * 60 * 1000;
    db.prepare(`INSERT INTO pending_otps(email,name,password_hash,code_hash,expires_at,attempts)
      VALUES(?,?,?,?,?,0)
      ON CONFLICT(email) DO UPDATE SET name=excluded.name,password_hash=excluded.password_hash,code_hash=excluded.code_hash,expires_at=excluded.expires_at,attempts=0`
    ).run(cleanEmail, String(name).trim(), hash, codeHash, expires);
    const mail = await sendOtpEmail(cleanEmail, code);
    const out = { ok: true, otpRequired: true, message: "OTP भेज दिया गया है।" };
    if (!mail.configured) out.devOtp = code;
    res.json(out);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "OTP भेजा नहीं जा सका।" });
  }
});

app.post("/api/verify-otp", async (req, res) => {
  const email = String((req.body || {}).email || "").trim().toLowerCase();
  const code = String((req.body || {}).code || "").trim();
  const pending = db.prepare("SELECT * FROM pending_otps WHERE email=?").get(email);
  if (!pending) return res.status(400).json({ error: "OTP request नहीं मिली। फिर से registration करें।" });
  if (pending.expires_at < Date.now()) { db.prepare("DELETE FROM pending_otps WHERE email=?").run(email); return res.status(400).json({ error: "OTP expire हो गया। फिर से registration करें।" }); }
  if (pending.attempts >= 5) return res.status(429).json({ error: "बहुत ज्यादा गलत कोशिश। फिर से OTP लें।" });
  const ok = await bcrypt.compare(code, pending.code_hash);
  if (!ok) { db.prepare("UPDATE pending_otps SET attempts=attempts+1 WHERE email=?").run(email); return res.status(400).json({ error: "OTP गलत है।" }); }
  try {
    const tx = db.transaction(() => {
      const info = db.prepare("INSERT INTO users(name,email,password_hash) VALUES(?,?,?)").run(pending.name, pending.email, pending.password_hash);
      db.prepare("DELETE FROM pending_otps WHERE email=?").run(email);
      return info.lastInsertRowid;
    });
    req.session.userId = tx();
    res.json({ ok: true });
  } catch (e) {
    if (String(e.message).includes("UNIQUE")) return res.status(409).json({ error: "यह ईमेल पहले से रजिस्टर है।" });
    console.error(e); res.status(500).json({ error: "अकाउंट नहीं बन पाया।" });
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body || {};
  const user = db.prepare("SELECT * FROM users WHERE email=?").get(String(email || "").trim().toLowerCase());
  if (!user || !(await bcrypt.compare(password || "", user.password_hash))) {
    return res.status(401).json({ error: "ईमेल या पासवर्ड गलत है।" });
  }
  req.session.userId = user.id;
  res.json({ ok: true });
});


app.post("/api/forgot-password", async (req,res)=>{
  const email=String((req.body||{}).email||"").trim().toLowerCase();
  const user=db.prepare("SELECT id FROM users WHERE email=?").get(email);
  if(!user) return res.status(404).json({error:"इस ईमेल का अकाउंट नहीं मिला।"});
  const code=String(Math.floor(100000+Math.random()*900000));
  const codeHash=await bcrypt.hash(code,10);
  db.prepare(`INSERT INTO password_resets(email,code_hash,expires_at,attempts) VALUES(?,?,?,0)
    ON CONFLICT(email) DO UPDATE SET code_hash=excluded.code_hash,expires_at=excluded.expires_at,attempts=0`).run(email,codeHash,Date.now()+10*60*1000);
  try { const mail=await sendOtpEmail(email,code); const out={ok:true,message:"Reset OTP भेज दिया गया।"}; if(!mail.configured) out.devOtp=code; res.json(out); }
  catch(e){res.status(500).json({error:"OTP नहीं भेजा जा सका।"});}
});

app.post("/api/reset-password", async (req,res)=>{
  const {email,code,password}=req.body||{}; const clean=String(email||"").trim().toLowerCase();
  if(!password || String(password).length<6) return res.status(400).json({error:"पासवर्ड कम से कम 6 अक्षर का रखें।"});
  const row=db.prepare("SELECT * FROM password_resets WHERE email=?").get(clean);
  if(!row || row.expires_at<Date.now()) return res.status(400).json({error:"OTP expire या invalid है।"});
  if(row.attempts>=5) return res.status(429).json({error:"बहुत ज्यादा गलत कोशिश।"});
  if(!(await bcrypt.compare(String(code||""),row.code_hash))){db.prepare("UPDATE password_resets SET attempts=attempts+1 WHERE email=?").run(clean);return res.status(400).json({error:"OTP गलत है।"});}
  db.prepare("UPDATE users SET password_hash=? WHERE email=?").run(await bcrypt.hash(password,12),clean);
  db.prepare("DELETE FROM password_resets WHERE email=?").run(clean); res.json({ok:true});
});

app.get("/api/profile",auth,(req,res)=>res.json({user:currentUser(req),quotaGB:gb(req.user.quota_bytes),usedGB:gb(req.user.used_bytes)}));
app.post("/api/profile/photo",auth,photoUpload.single("photo"),(req,res)=>{
  if(!req.file) return res.status(400).json({error:"सही image चुनें।"});
  db.prepare("UPDATE users SET profile_photo=? WHERE id=?").run(req.file.filename,req.user.id);
  res.json({ok:true,url:"/api/profile/photo"});
});
app.get("/api/profile/photo",auth,(req,res)=>{
  const u=db.prepare("SELECT profile_photo FROM users WHERE id=?").get(req.user.id);
  if(!u?.profile_photo) return res.status(404).end();
  const f=path.join(UPLOADS,u.profile_photo); if(!fs.existsSync(f)) return res.status(404).end(); res.sendFile(f);
});

app.get("/api/folders",auth,(req,res)=>res.json(db.prepare("SELECT * FROM folders WHERE user_id=? ORDER BY name").all(req.user.id)));
app.post("/api/folders",auth,(req,res)=>{const name=String((req.body||{}).name||"").trim().slice(0,100);if(!name)return res.status(400).json({error:"Folder नाम जरूरी है।"});const x=db.prepare("INSERT INTO folders(user_id,name) VALUES(?,?)").run(req.user.id,name);res.json({ok:true,id:x.lastInsertRowid});});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/files", auth, (req, res) => {
  const q=String(req.query.q||"").trim();
  const rows = q ? db.prepare(`SELECT id,original_name,mime_type,size_bytes,created_at FROM files WHERE user_id=? AND original_name LIKE ? ORDER BY id DESC`).all(req.user.id,"%"+q+"%") : db.prepare(`
    SELECT id, original_name, mime_type, size_bytes, created_at
    FROM files WHERE user_id=? ORDER BY id DESC
  `).all(req.user.id);
  res.json(rows);
});

app.post("/api/upload", auth, upload.array("files", 20), (req, res) => {
  const files = req.files || [];
  const total = files.reduce((sum, f) => sum + f.size, 0);
  const freshUser = currentUser(req);

  if (freshUser.used_bytes + total > freshUser.quota_bytes) {
    for (const f of files) fs.rmSync(f.path, { force: true });
    return res.status(413).json({ error: "आपका storage quota पूरा हो गया है।" });
  }

  const insert = db.prepare(`
    INSERT INTO files(user_id,original_name,stored_name,mime_type,size_bytes)
    VALUES(?,?,?,?,?)
  `);
  const update = db.prepare("UPDATE users SET used_bytes=used_bytes+? WHERE id=?");
  const tx = db.transaction(() => {
    for (const f of files) insert.run(req.user.id, f.originalname, f.filename, f.mimetype, f.size);
    update.run(total, req.user.id);
  });
  tx();

  res.json({ ok: true, uploaded: files.length });
});

app.get("/api/download/:id", auth, (req, res) => {
  const file = db.prepare("SELECT * FROM files WHERE id=? AND user_id=?").get(req.params.id, req.user.id);
  if (!file) return res.status(404).send("File नहीं मिली।");
  const full = path.join(UPLOADS, file.stored_name);
  if (!fs.existsSync(full)) return res.status(404).send("File server पर नहीं मिली।");
  res.download(full, file.original_name);
});

app.delete("/api/files/:id", auth, (req, res) => {
  const file = db.prepare("SELECT * FROM files WHERE id=? AND user_id=?").get(req.params.id, req.user.id);
  if (!file) return res.status(404).json({ error: "File नहीं मिली।" });
  const full = path.join(UPLOADS, file.stored_name);
  fs.rmSync(full, { force: true });
  const tx = db.transaction(() => {
    db.prepare("DELETE FROM files WHERE id=?").run(file.id);
    db.prepare("UPDATE users SET used_bytes=MAX(used_bytes-?,0) WHERE id=?").run(file.size_bytes, req.user.id);
  });
  tx();
  res.json({ ok: true });
});

app.get("*splat", (req, res) => {
  res.sendFile(path.join(ROOT, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`Satyam With Me चल रहा है: http://localhost:${PORT}`);
});
