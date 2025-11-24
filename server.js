// server.js (final, drop-in)
require('dotenv').config();

const path        = require('path');
const fs          = require('fs');
const express     = require('express');
const mongoose    = require('mongoose');
const cors        = require('cors');
const bcrypt      = require('bcrypt');
const jwt         = require('jsonwebtoken');
const helmet      = require('helmet');
const compression = require('compression');
const morgan      = require('morgan');
const rateLimit   = require('express-rate-limit');
const multer      = require('multer');

// ─────────────────────────────────────────────────────────────
// ENV & 기본 체크
// ─────────────────────────────────────────────────────────────
const MONGODB_URI = process.env.MONGODB_URI;
const PORT        = process.env.PORT || 4000;
const JWT_SECRET  = process.env.JWT_SECRET;

if (!MONGODB_URI) { console.error('❌ MONGODB_URI is required'); process.exit(1); }
if (!JWT_SECRET)  { console.error('❌ JWT_SECRET is required');  process.exit(1); }

const app = express();
app.set('trust proxy', 1);

// ─────────────────────────────────────────────────────────────
// 보안/성능 미들웨어
// ─────────────────────────────────────────────────────────────
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(compression());
app.use(morgan('dev'));
app.use(express.json({ limit: '2mb' }));

// CORS
const allowOrigins = (process.env.CORS_ORIGINS || '')
  .split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin(origin, cb) {
    if (!origin || allowOrigins.length === 0) return cb(null, true);
    cb(null, allowOrigins.includes(origin));
  },
  credentials: true,
}));

// ─────────────────────────────────────────────────────────────
// 업로드 경로 & 정적 서빙
// ─────────────────────────────────────────────────────────────
const UPLOAD_ROOT = process.env.UPLOAD_DIR || path.join(process.cwd(), 'uploads');
const PETCARE_DIR = path.join(UPLOAD_ROOT, 'pet-care');
fs.mkdirSync(PETCARE_DIR, { recursive: true });

app.use('/uploads', express.static(UPLOAD_ROOT, {
  setHeaders(res) { res.setHeader('Cache-Control', 'public, max-age=86400'); },
  index: false,
}));

// Multer (이미지)
const ALLOWED_EXTS  = new Set(['.jpg','.jpeg','.png','.gif','.webp','.heic','.heif']);
const ALLOWED_MIMES = new Set([
  'image/jpeg','image/jpg','image/png','image/gif','image/webp','image/heic','image/heif',
  'application/octet-stream' // iOS HEIC
]);
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, PETCARE_DIR),
  filename: (_req, file, cb) => {
    const ext = (path.extname(file.originalname || '') || '').toLowerCase();
    const safe = ALLOWED_EXTS.has(ext) ? ext : '';
    cb(null, `${Date.now()}-${Math.round(Math.random()*1e9)}${safe}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024, files: 10 },
  fileFilter: (_req, file, cb) => {
    if (!ALLOWED_MIMES.has(file.mimetype)) return cb(new Error('Invalid file type'));
    cb(null, true);
  }
});

// ─────────────────────────────────────────────────────────────
// 유틸
// ─────────────────────────────────────────────────────────────
function oid(v) {
  try { return new mongoose.Types.ObjectId(String(v)); } catch { return null; }
}
function issueToken(doc) {
  return jwt.sign({ uid: doc._id, role: doc.role }, JWT_SECRET, { expiresIn: '7d' });
}
function auth(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : '';
    if (!token) return res.status(401).json({ message: 'no token' });
    req.jwt = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: 'invalid token' });
  }
}
const onlyUser = (req, res, next) =>
  req.jwt?.role === 'USER' ? next() : res.status(403).json({ message: 'for USER' });
const onlyHospitalAdmin = (req, res, next) =>
  req.jwt?.role === 'HOSPITAL_ADMIN' ? next() : res.status(403).json({ message: 'for HOSPITAL_ADMIN' });

function buildBaseUrl(req) {
  if (process.env.PUBLIC_BASE_URL) return process.env.PUBLIC_BASE_URL.replace(/\/+$/, '');
  const proto = req.get('x-forwarded-proto') || req.protocol;
  const host  = req.get('x-forwarded-host') || req.get('host');
  return `${proto}://${host}`;
}
function publicUrl(req, relativePath) {
  const base = buildBaseUrl(req);
  return `${base}${relativePath.startsWith('/') ? '' : '/'}${relativePath}`;
}
function filePathFromPublicUrl(publicUrl) {
  try {
    const u = new URL(publicUrl);
    if (!u.pathname.startsWith('/uploads/')) return null;
    const fp = path.join(UPLOAD_ROOT, u.pathname.replace(/^\/uploads\//, ''));
    const normalized = path.normalize(fp);
    if (!normalized.startsWith(path.normalize(UPLOAD_ROOT))) return null;
    return normalized;
  } catch { return null; }
}
async function deleteFilesByUrls(urls = []) {
  for (const u of urls) {
    const fp = filePathFromPublicUrl(u);
    if (!fp) continue;
    try { await fs.promises.unlink(fp); }
    catch (e) { if (e.code !== 'ENOENT') console.warn('unlink error:', fp, e.message); }
  }
}

// ─────────────────────────────────────────────────────────────
// 레이트 리밋
// ─────────────────────────────────────────────────────────────
const authLimiter = rateLimit({ windowMs: 10*60*1000, max: 100, standardHeaders: true, legacyHeaders: false });
const uploadLimiter = rateLimit({ windowMs: 10*60*1000, max: 60, standardHeaders: true, legacyHeaders: false });

// ─────────────────────────────────────────────────────────────
// Mongo 연결 (역할별 DB 분리)
// user_db: 일반 사용자/건강/알림/주문
// hospital_db: 병원 관리자/예약/공지/채팅/진료내역/케어일지
// admin_db: 상품(Product) 등 관리자 전용 데이터
// ─────────────────────────────────────────────────────────────
mongoose.set('strictQuery', true);
const userConn     = mongoose.createConnection(MONGODB_URI, { dbName: 'user_db' });
const hospitalConn = mongoose.createConnection(MONGODB_URI, { dbName: 'hospital_db' });
const adminConn    = mongoose.createConnection(MONGODB_URI, { dbName: 'admin_db' });

userConn.on('connected',     () => console.log('✅ userConn -> user_db'));
hospitalConn.on('connected', () => console.log('✅ hospitalConn -> hospital_db'));
adminConn.on('connected',    () => console.log('✅ adminConn -> admin_db'));
[userConn, hospitalConn, adminConn].forEach(c =>
  c.on('error', (e) => console.error('Mongo error:', e?.message || e))
);

// ─────────────────────────────────────────────────────────────
// 스키마/모델
// ─────────────────────────────────────────────────────────────
// 건강 기록(차트용 서브도큐먼트)
const HealthWeightSchema = new mongoose.Schema({ date: Date, bodyWeight: Number, muscleMass: Number, bodyFatMass: Number }, { _id:false });
const HealthActivitySchema = new mongoose.Schema({ date: Date, time: Number, calories: Number }, { _id:false });
const HealthIntakeSchema = new mongoose.Schema({ date: Date, food: Number, water: Number }, { _id:false });

const DiarySchema = new mongoose.Schema({ title:String, content:String, date:{type:Date, default:Date.now}, imagePath:String });
const AlarmSchema = new mongoose.Schema({
  time:String, label:String, isActive:{type:Boolean, default:true}, repeatDays:[Number], snoozeMinutes:{type:Number, default:null}
});
const PetProfileSchema = new mongoose.Schema({
  name:String, age:Number, gender:String, species:String, avatarUrl:String,
  healthChart: {
    weight:   { type:[HealthWeightSchema], default:[] },
    activity: { type:[HealthActivitySchema], default:[] },
    intake:   { type:[HealthIntakeSchema], default:[] },
  },
  diaries: { type:[DiarySchema], default:[] },
  alarms:  { type:[AlarmSchema], default:[] },
}, { _id:false });

const userSchema = new mongoose.Schema({
  email: { type:String, unique:true, index:true, required:true },
  passwordHash: { type:String, required:true },
  name: { type:String, default:'' },
  role: { type:String, enum:['USER'], default:'USER', index:true },
  birthDate: { type:String, default:'' },
  petProfile: { type: PetProfileSchema, default:{} },
  favorites: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Product' }],
  cart: [{ productId:{ type:mongoose.Schema.Types.ObjectId, ref:'Product' }, count:{ type:Number, default:1 } }],
  linkedHospitals: [{
    hospitalId: { type: mongoose.Schema.Types.ObjectId, index:true },
    hospitalName: String,
    status: { type:String, enum:['PENDING','APPROVED','REJECTED'], default:'PENDING', index:true },
    requestedAt: Date, linkedAt: Date
  }],
}, { timestamps:true });

const hospitalUserSchema = new mongoose.Schema({
  email:{type:String, unique:true, index:true, required:true},
  passwordHash:{type:String, required:true},
  name:{type:String, default:''},
  role:{type:String, enum:['HOSPITAL_ADMIN'], default:'HOSPITAL_ADMIN', index:true},
  hospitalName:{type:String, default:''},
  hospitalProfile:{ photoUrl:String, intro:String, address:String, hours:String, phone:String },
  approveStatus:{ type:String, enum:['PENDING','APPROVED','REJECTED'], default:'PENDING', index:true },
}, { timestamps:true });

const hospitalLinkRequestSchema = new mongoose.Schema({
  userId:{type:mongoose.Schema.Types.ObjectId, index:true, required:true},
  userName:String, petName:String,
  hospitalId:{type:mongoose.Schema.Types.ObjectId, index:true, required:true},
  hospitalName:String,
  status:{type:String, enum:['PENDING','APPROVED','REJECTED'], default:'PENDING', index:true},
  createdAt:{type:Date, default:Date.now, index:true}, decidedAt:Date
});

const hospitalMetaSchema = new mongoose.Schema({
  hospitalId:{type:mongoose.Schema.Types.ObjectId, unique:true, index:true, required:true},
  hospitalName:String, notice:String,
  services:[String], doctors:[{ id:String, name:String }],
}, { timestamps:true });

const appointmentSchema = new mongoose.Schema({
  hospitalId:{type:mongoose.Schema.Types.ObjectId, index:true, required:true},
  hospitalName:String,
  userId:{type:mongoose.Schema.Types.ObjectId, index:true, required:true},
  userName:String, petName:String,
  service:String, doctorName:String, date:String, time:String,
  visitDateTime:{type:Date, index:true},
  status:{ type:String, enum:['PENDING','APPROVED','REJECTED','CANCELED'], default:'PENDING', index:true },
  createdAt:{ type:Date, default:Date.now, index:true }, decidedAt:Date, decidedBy:mongoose.Schema.Types.ObjectId
}, { timestamps:true });

const userAppointmentSchema = new mongoose.Schema({
  userId:{type:mongoose.Schema.Types.ObjectId, index:true, required:true},
  originAppointmentId:{type:mongoose.Schema.Types.ObjectId, index:true, required:true},
  hospitalId:{type:mongoose.Schema.Types.ObjectId, index:true, required:true},
  hospitalName:String, userName:String, petName:String,
  service:String, doctorName:String, date:String, time:String,
  visitDateTime:{type:Date, index:true}, status:{type:String, default:'PENDING', index:true}
}, { timestamps:true });

const medicalHistorySchema = new mongoose.Schema({
  hospitalId:{type:mongoose.Schema.Types.ObjectId, index:true, required:true},
  hospitalName:String,
  userId:{type:mongoose.Schema.Types.ObjectId, index:true, required:true},
  userName:String, petName:String,
  date:{type:Date, index:true, required:true},
  category:String, content:String, prescription:String, howToTake:String, cost:String
}, { timestamps:true });

const petCareSchema = new mongoose.Schema({
  hospitalId:{type:mongoose.Schema.Types.ObjectId, index:true, required:true},
  hospitalName:String,
  createdBy:{type:mongoose.Schema.Types.ObjectId, index:true, required:true},
  patientId:{type:mongoose.Schema.Types.ObjectId, index:true, required:true}, // == User._id
  userId:{type:mongoose.Schema.Types.ObjectId, index:true},                  // = patientId
  date:String, time:String, dateTime:{type:Date, index:true},
  memo:String, images:[String]
}, { timestamps:true });

const sosLogSchema = new mongoose.Schema({
  hospitalId:{type:mongoose.Schema.Types.ObjectId, index:true},
  hospitalName:String,
  userId:{type:mongoose.Schema.Types.ObjectId, index:true},
  userName:String, petName:String, message:String
}, { timestamps:true });

const chatMessageSchema = new mongoose.Schema({
  hospitalId:{type:mongoose.Schema.Types.ObjectId, index:true, required:true},
  userId:{type:mongoose.Schema.Types.ObjectId, index:true, required:true},
  senderRole:{type:String, enum:['USER','ADMIN'], index:true, required:true},
  senderId:{type:mongoose.Schema.Types.ObjectId, index:true, required:true},
  senderName:String, text:{type:String, required:true},
  createdAt:{type:Date, default:Date.now, index:true},
  readByUser:{type:Boolean, default:false, index:true},
  readByAdmin:{type:Boolean, default:false, index:true},
}, { versionKey:false });
chatMessageSchema.index({ hospitalId:1, userId:1, createdAt:-1 });

const notificationSchema = new mongoose.Schema({
  userId:{type:mongoose.Schema.Types.ObjectId, index:true, required:true},
  hospitalId:{type:mongoose.Schema.Types.ObjectId, index:true, required:true},
  hospitalName:String, type:{type:String, default:'SYSTEM', index:true},
  title:String, message:String, read:{type:Boolean, default:false, index:true},
  meta:{ type:mongoose.Schema.Types.Mixed, default:{} },
  createdAt:{type:Date, default:Date.now, index:true}
}, { versionKey:false });

const hospitalNoticeSchema = new mongoose.Schema({
  hospitalId:{type:mongoose.Schema.Types.ObjectId, index:true, required:true},
  hospitalName:String, title:{type:String, required:true}, content:{type:String, required:true},
  createdBy:{type:mongoose.Schema.Types.ObjectId, index:true, required:true},
}, { timestamps:true });

const healthRecordSchema = new mongoose.Schema({
  userId:{type:mongoose.Schema.Types.ObjectId, index:true, required:true},
  date:{type:String, index:true, required:true}, time:String, dateTime:{type:Date, index:true},
  weight:Number, height:Number, temperature:Number, systolic:Number, diastolic:Number, heartRate:Number, glucose:Number, memo:String
}, { timestamps:true });
healthRecordSchema.index({ userId:1, dateTime:-1 });

// 쇼핑: Product(admin_db), Order(user_db)
const productSchema = new mongoose.Schema({
  name:{type:String, required:true},
  category:{type:String, required:true},
  description:{type:String, required:true},
  quantity:{type:Number, required:true},
  price:{type:Number, required:true},
  images:[String],
  reviews:[{ userName:String, rating:Number, comment:String, createdAt:{type:Date, default:Date.now} }],
  averageRating:{type:Number, default:0}
}, { timestamps:true });

const orderSchema = new mongoose.Schema({
  userId:{type:mongoose.Schema.Types.ObjectId, ref:'User', required:true},
  userName:String, address:String, phone:String,
  products:[{ productId:{type:mongoose.Schema.Types.ObjectId, ref:'Product', required:true}, name:String, category:String, price:Number, quantity:{type:Number, default:1}, image:String }],
  payment:{ method:{type:String, default:'카드결제'}, totalAmount:{type:Number, required:true} },
  status:{ type:String, enum:['주문접수','결제완료','배송중','배송완료','주문취소'], default:'주문접수' }
}, { timestamps:true });

// 모델 등록
const User                = userConn.model('User', userSchema, 'users');
const HealthRecord        = userConn.model('HealthRecord', healthRecordSchema, 'health_records');
const Notification        = userConn.model('Notification', notificationSchema, 'notifications');
const UserAppointment     = userConn.model('UserAppointment', userAppointmentSchema, 'user_appointments');
const Order               = userConn.model('Order', orderSchema, 'orders');

const HospitalUser        = hospitalConn.model('HospitalUser', hospitalUserSchema, 'hospital_user');
const HospitalLinkRequest = hospitalConn.model('HospitalLinkRequest', hospitalLinkRequestSchema, 'hospital_link_requests');
const HospitalMeta        = hospitalConn.model('HospitalMeta', hospitalMetaSchema, 'hospital_meta');
const Appointment         = hospitalConn.model('Appointment', appointmentSchema, 'appointments');
const MedicalHistory      = hospitalConn.model('MedicalHistory', medicalHistorySchema, 'medical_histories');
const PetCare             = hospitalConn.model('PetCare', petCareSchema, 'pet_care');
const SosLog              = hospitalConn.model('SosLog', sosLogSchema, 'sos_logs');
const HospitalNotice      = hospitalConn.model('HospitalNotice', hospitalNoticeSchema, 'hospital_notices');
const ChatMessage         = hospitalConn.model('ChatMessage', chatMessageSchema, 'chat_messages');

const Product             = adminConn.model('Product', productSchema, 'products');

// ─────────────────────────────────────────────────────────────
// 알림 유틸
// ─────────────────────────────────────────────────────────────
async function pushNotificationOne({ userId, hospitalId, hospitalName = '', type, title, message, meta = {} }) {
  try {
    if (!userId || !hospitalId) return;
    await Notification.create({ userId: oid(userId), hospitalId: oid(hospitalId), hospitalName, type: String(type||'SYSTEM'), title:String(title||''), message:String(message||''), meta });
  } catch (e) { console.error('pushNotificationOne error:', e?.message || e); }
}
async function pushNotificationMany({ userIds = [], hospitalId, hospitalName = '', type, title, message, meta = {} }) {
  try {
    const docs = (userIds||[]).filter(Boolean).map(u => ({
      userId: oid(u), hospitalId: oid(hospitalId), hospitalName, type:String(type||'SYSTEM'),
      title:String(title||''), message:String(message||''), meta, createdAt:new Date()
    }));
    if (docs.length) await Notification.insertMany(docs, { ordered:false });
  } catch (e) { console.error('pushNotificationMany error:', e?.message || e); }
}
function hospitalAdminProfileDto(admin) {
  return {
    hospitalName: admin.hospitalName || '',
    intro: admin.hospitalProfile?.intro || '',
    photoUrl: admin.hospitalProfile?.photoUrl || '',
    address:  admin.hospitalProfile?.address  || '',
    hours:    admin.hospitalProfile?.hours    || '',
    phone:    admin.hospitalProfile?.phone    || '',
    approveStatus: admin.approveStatus || 'PENDING',
  };
}

// ─────────────────────────────────────────────────────────────
// 기본 라우트
// ─────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => res.json({ ok:true, ts:Date.now() }));
app.get('/', (_req, res) => res.json({ message:'🚀 Animal API running', env: process.env.NODE_ENV || 'dev' }));

// 전역 ID 중복 체크
app.get('/auth/check-id', async (req, res) => {
  try {
    const key = (req.query.email || req.query.username || req.query.key || '').toString().trim();
    if (!key) return res.status(400).json({ message:'email/username required' });
    const [u, h] = await Promise.all([User.exists({ email:key }), HospitalUser.exists({ email:key })]);
    res.json({ available: !(u || h) });
  } catch (e) { console.error('check-id error:', e); res.status(500).json({ message:'server error' }); }
});

// 회원가입/로그인
app.post('/auth/signup', authLimiter, async (req, res) => {
  try {
    const { email, username, password, name, birthDate } = req.body || {};
    const finalEmail = (email || username || '').trim();
    if (!finalEmail || !password) return res.status(400).json({ message:'email/password required' });
    const exists = await Promise.all([User.findOne({ email:finalEmail }), HospitalUser.findOne({ email:finalEmail })]);
    if (exists[0] || exists[1]) return res.status(409).json({ message:'email already used' });
    const passwordHash = await bcrypt.hash(password, 12);
    const user = await User.create({ email:finalEmail, passwordHash, name:name||'', birthDate:(birthDate||'').trim(), role:'USER' });
    res.status(201).json({ token:issueToken(user), user:{ id:user._id, email:user.email, name:user.name, role:user.role, birthDate:user.birthDate } });
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});
app.post('/auth/signup-with-invite', authLimiter, async (req, res) => {
  try {
    const { email, password, name, inviteCode } = req.body || {};
    if (!email || !password || !inviteCode) return res.status(400).json({ message:'missing fields' });
    const codes = (process.env.INVITE_ADMIN_CODES || '').split(',').map(s=>s.trim()).filter(Boolean);
    if (!codes.includes(inviteCode)) return res.status(400).json({ message:'invalid invite code' });
    const exists = await Promise.all([HospitalUser.findOne({ email }), User.findOne({ email })]);
    if (exists[0] || exists[1]) return res.status(409).json({ message:'email already used' });
    const passwordHash = await bcrypt.hash(password, 12);
    const admin = await HospitalUser.create({ email, passwordHash, name:name||'', role:'HOSPITAL_ADMIN', hospitalName:'' });
    res.status(201).json({ token:issueToken(admin), user:{ id:admin._id, email:admin.email, name:admin.name, role:admin.role, hospitalName:admin.hospitalName, hospitalProfile:admin.hospitalProfile, approveStatus:admin.approveStatus } });
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});
app.post('/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ message:'email/password required' });

    let doc = await HospitalUser.findOne({ email });
    if (doc) {
      const ok = await bcrypt.compare(password, doc.passwordHash);
      if (!ok) return res.status(401).json({ message:'invalid credentials' });
      return res.json({ token:issueToken(doc), user:{ id:doc._id, email:doc.email, name:doc.name, role:doc.role, hospitalName:doc.hospitalName, hospitalProfile:doc.hospitalProfile, approveStatus:doc.approveStatus } });
    }
    doc = await User.findOne({ email });
    if (!doc) return res.status(401).json({ message:'invalid credentials' });
    const ok = await bcrypt.compare(password, doc.passwordHash);
    if (!ok) return res.status(401).json({ message:'invalid credentials' });
    return res.json({ token:issueToken(doc), user:{ id:doc._id, email:doc.email, name:doc.name, role:doc.role, birthDate:doc.birthDate, petProfile:doc.petProfile } });
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});

// 프로필
app.get('/users/me', auth, onlyUser, async (req, res) => {
  const user = await User.findById(oid(req.jwt.uid)).lean();
  if (!user) return res.status(404).json({ message:'not found' });
  delete user.passwordHash;
  res.json({ user, id:user._id, email:user.email, name:user.name, role:user.role, birthDate:user.birthDate, petProfile:user.petProfile });
});
app.get('/hospital/me', auth, onlyHospitalAdmin, async (req, res) => {
  const admin = await HospitalUser.findById(oid(req.jwt.uid)).lean();
  if (!admin) return res.status(404).json({ message:'not found' });
  delete admin.passwordHash;
  res.json({ user:admin });
});
app.put('/users/me/pet', auth, onlyUser, async (req, res) => {
  try {
    const { name, age, gender, species, avatarUrl } = req.body || {};
    const update = {
      'petProfile.name': (name||'').trim(),
      'petProfile.age': Number.isFinite(Number(age)) ? Number(age) : 0,
      'petProfile.gender': (gender||'').trim(),
      'petProfile.species': (species||'').trim(),
      'petProfile.avatarUrl': (avatarUrl||'').trim(),
    };
    const user = await User.findByIdAndUpdate(oid(req.jwt.uid), { $set:update }, { new:true, lean:true });
    if (!user) return res.status(404).json({ message:'not found' });
    delete user.passwordHash;
    res.json({ user });
  } catch (e) { console.error('PUT /users/me/pet error:', e); res.status(500).json({ message:'server error' }); }
});
app.put('/hospital/profile', auth, onlyHospitalAdmin, async (req, res) => {
  const { hospitalName, photoUrl, intro, address, hours, phone } = req.body || {};
  const update = {
    ...(typeof hospitalName === 'string' ? { hospitalName:hospitalName.trim() } : {}),
    'hospitalProfile.photoUrl': (photoUrl||'').trim(),
    'hospitalProfile.intro':    (intro||'').trim(),
    'hospitalProfile.address':  (address||'').trim(),
    'hospitalProfile.hours':    (hours||'').trim(),
    'hospitalProfile.phone':    (phone||'').trim(),
    approveStatus:'PENDING',
  };
  const admin = await HospitalUser.findByIdAndUpdate(oid(req.jwt.uid), { $set:update }, { new:true, lean:true });
  if (!admin) return res.status(404).json({ message:'not found' });
  delete admin.passwordHash;
  res.json({ user:admin });
});

// ─────────────────────────────────────────────────────────────
// 병원(관리) API
// ─────────────────────────────────────────────────────────────
app.post('/api/hospital-admin/sos', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const { userId, hospitalId, message } = req.body || {};
    if (!userId) return res.status(400).json({ message:'userId required' });
    const user = await User.findById(oid(userId)).lean();
    if (!user) return res.status(404).json({ message:'user not found' });

    const hid = oid(hospitalId || req.jwt.uid);
    let hospitalName = '';
    const approved = (user.linkedHospitals || []).find(h => String(h.hospitalId) === String(hid) && h.status === 'APPROVED');
    if (approved) hospitalName = approved.hospitalName || '';

    const log = await SosLog.create({
      hospitalId: hid,
      hospitalName,
      userId: user._id,
      userName: user.name || '',
      petName:  user.petProfile?.name || '',
      message:  (message||'').toString(),
    });

    await pushNotificationOne({
      userId: user._id,
      hospitalId: hid,
      hospitalName,
      type: 'SOS_ALERT',
      title: '병원 긴급 알림',
      message: (message||'').toString(),
      meta: { sosId: log._id }
    });

    res.status(201).json({ ok:true, id:log._id });
  } catch (e) {
    console.error('POST /api/hospital-admin/sos error:', e);
    res.status(500).json({ message:'server error' });
  }
});

app.get('/api/hospital-admin/profile', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const admin = await HospitalUser.findById(oid(req.jwt.uid)).lean();
    if (!admin) return res.status(404).json({ message:'not found' });
    res.json({ data: hospitalAdminProfileDto(admin) });
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});
app.patch('/api/hospital-admin/profile', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const { name, hospitalName, intro, photoUrl, address, hours, phone } = req.body || {};
    const update = {
      ...(typeof (hospitalName ?? name) === 'string' ? { hospitalName:(hospitalName ?? name).trim() } : {}),
      'hospitalProfile.photoUrl': typeof photoUrl === 'string' ? photoUrl.trim() : undefined,
      'hospitalProfile.intro':    typeof intro    === 'string' ? intro.trim()    : undefined,
      'hospitalProfile.address':  typeof address  === 'string' ? address.trim()  : undefined,
      'hospitalProfile.hours':    typeof hours    === 'string' ? hours.trim()    : undefined,
      'hospitalProfile.phone':    typeof phone    === 'string' ? phone.trim()    : undefined,
      approveStatus:'PENDING',
    };
    Object.keys(update).forEach(k => update[k] === undefined && delete update[k]);

    const admin = await HospitalUser.findByIdAndUpdate(oid(req.jwt.uid), { $set:update }, { new:true, lean:true });
    if (!admin) return res.status(404).json({ message:'not found' });
    res.json({ data: hospitalAdminProfileDto(admin) });
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});

// 공지 배너(최신 1건)
app.get('/api/hospitals/:hospitalId/notice', async (req, res) => {
  try {
    const hid = oid(req.params.hospitalId);
    const last = await HospitalNotice.findOne({ hospitalId: hid }).sort({ createdAt:-1 }).lean();
    const title = (last?.title || '').trim();
    const content = (last?.content || '').trim();
    const firstLine = content.split('\n').map(s=>s.trim()).filter(Boolean)[0] || '';
    const notice = title || firstLine ? `[공지] ${title}${firstLine ? ' · ' + firstLine : ''}` : '';
    res.json({ notice });
  } catch (e) { console.error(e); res.json({ notice:'' }); }
});

// 병원 목록
app.get('/api/hospitals', async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
  const page  = Math.max(parseInt(req.query.page || '1', 10), 1);
  const skip  = (page - 1) * limit;
  const [items, total] = await Promise.all([
    HospitalUser.find({}, { passwordHash:0 }).sort({ createdAt:-1 }).skip(skip).limit(limit).lean(),
    HospitalUser.countDocuments({})
  ]);
  const data = items.map(h => ({
    _id:h._id, hospitalName:h.hospitalName || '', approveStatus:h.approveStatus || 'PENDING',
    imageUrl:h.hospitalProfile?.photoUrl || '', createdAt:h.createdAt
  }));
  res.json({ data, paging:{ total, page, limit } });
});

// 병원 연동
app.get('/api/hospital-links/available', auth, onlyUser, async (req, res) => {
  const [hospitals, me] = await Promise.all([
    HospitalUser.find({}, { passwordHash:0 }).sort({ createdAt:-1 }).lean(),
    User.findById(oid(req.jwt.uid), { linkedHospitals:1 }).lean(),
  ]);
  const statusMap = new Map();
  (me?.linkedHospitals || []).forEach(x => statusMap.set(String(x.hospitalId), x.status));
  const data = hospitals.map(h => ({
    hospitalId:String(h._id),
    hospitalName:h.hospitalName || '',
    myStatus: statusMap.get(String(h._id)) || 'NONE',
    imageUrl: h.hospitalProfile?.photoUrl || '',
    createdAt:h.createdAt
  }));
  res.json({ data });
});
async function upsertUserLink(userId, hospital) {
  const user = await User.findById(oid(userId));
  if (!user) throw new Error('user not found');
  const has = (user.linkedHospitals || []).find(h => String(h.hospitalId) === String(hospital._id));
  if (has) { has.status = 'PENDING'; has.requestedAt = new Date(); }
  else {
    user.linkedHospitals.push({ hospitalId:hospital._id, hospitalName:hospital.hospitalName || '', status:'PENDING', requestedAt:new Date() });
  }
  await user.save();

  const existing = await HospitalLinkRequest.findOne({ userId:oid(userId), hospitalId:oid(hospital._id), status:'PENDING' });
  if (!existing) {
    await HospitalLinkRequest.create({
      userId:oid(userId),
      userName:user.name || '',
      petName:user.petProfile?.name || '',
      hospitalId:hospital._id,
      hospitalName:hospital.hospitalName || '',
    });
  }
}
app.post('/api/hospital-links/request', auth, onlyUser, async (req, res) => {
  try {
    const { hospitalId } = req.body || {};
    if (!hospitalId) return res.status(400).json({ message:'hospitalId required' });
    const hospital = await HospitalUser.findById(oid(hospitalId)).lean();
    if (!hospital) return res.status(404).json({ message:'hospital not found' });
    await upsertUserLink(req.jwt.uid, hospital);
    res.json({ ok:true });
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});
app.post('/api/hospitals/:id/connect', auth, onlyUser, async (req, res) => {
  try {
    const hospital = await HospitalUser.findById(oid(req.params.id)).lean();
    if (!hospital) return res.status(404).json({ message:'hospital not found' });
    await upsertUserLink(req.jwt.uid, hospital);
    res.json({ ok:true });
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});

// 예약함/승인/거절
app.get('/api/hospital-admin/appointments', auth, onlyHospitalAdmin, async (req, res) => {
  const status = (req.query.status || '').toString().toUpperCase();
  const order  = (req.query.order || 'desc').toString().toLowerCase();
  const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
  const page  = Math.max(parseInt(req.query.page  || '1', 10), 1);
  const skip  = (page - 1) * limit;
  const q = { hospitalId: oid(req.jwt.uid) };
  if (['PENDING','APPROVED','REJECTED','CANCELED'].includes(status)) q.status = status;
  const sort = order === 'asc' ? 1 : -1;
  const [items, total] = await Promise.all([
    Appointment.find(q).sort({ createdAt:sort }).skip(skip).limit(limit).lean(),
    Appointment.countDocuments(q),
  ]);
  res.json({ data:items, paging:{ total, page, limit } });
});
app.post('/api/hospital-admin/appointments/:id/approve', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const appt = await Appointment.findById(oid(req.params.id));
    if (!appt) return res.status(404).json({ message:'not found' });
    if (String(appt.hospitalId) !== String(req.jwt.uid)) return res.status(403).json({ message:'forbidden' });
    if (appt.status !== 'PENDING') return res.status(409).json({ message:'already decided' });
    appt.status = 'APPROVED'; appt.decidedAt = new Date(); appt.decidedBy = oid(req.jwt.uid);
    await appt.save();
    await UserAppointment.updateOne({ originAppointmentId: appt._id }, { $set:{ status:'APPROVED' } });
    await pushNotificationOne({
      userId: appt.userId, hospitalId: appt.hospitalId, hospitalName: appt.hospitalName || '',
      type:'APPOINTMENT_APPROVED', title:'진료 예약 승인',
      message:`${appt.date} ${appt.time} · ${appt.service} (${appt.doctorName || '담당의'})`,
      meta:{ appointmentId: appt._id }
    });
    res.json({ ok:true });
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});
app.post('/api/hospital-admin/appointments/:id/reject', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const appt = await Appointment.findById(oid(req.params.id));
    if (!appt) return res.status(404).json({ message:'not found' });
    if (String(appt.hospitalId) !== String(req.jwt.uid)) return res.status(403).json({ message:'forbidden' });
    if (appt.status !== 'PENDING') return res.status(409).json({ message:'already decided' });
    appt.status = 'REJECTED'; appt.decidedAt = new Date(); appt.decidedBy = oid(req.jwt.uid);
    await appt.save();
    await UserAppointment.updateOne({ originAppointmentId: appt._id }, { $set:{ status:'REJECTED' } });
    await pushNotificationOne({
      userId: appt.userId, hospitalId: appt.hospitalId, hospitalName: appt.hospitalName || '',
      type:'APPOINTMENT_REJECTED', title:'진료 예약 거절', message:`${appt.date} ${appt.time} · ${appt.service}`, meta:{ appointmentId: appt._id }
    });
    res.json({ ok:true });
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});

// 관리자 채팅: 스레드/메시지/읽음
app.get('/api/hospital-admin/chat/threads', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const hid = oid(req.jwt.uid);
    const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
    const latest = await ChatMessage.aggregate([
      { $match:{ hospitalId:hid } },
      { $sort:{ createdAt:-1 } },
      { $group:{ _id:'$userId', lastMessage:{ $first:'$__ROOT__' } } },
      { $limit:limit }
    ]);
    const userIds = latest.map(x => x._id);
    const unreadAgg = await ChatMessage.aggregate([
      { $match:{ hospitalId:hid, userId:{ $in:userIds }, senderRole:'USER', readByAdmin:false } },
      { $group:{ _id:'$userId', cnt:{ $sum:1 } } }
    ]);
    const unreadMap = new Map(unreadAgg.map(a => [String(a._id), a.cnt]));
    const users = await User.find({ _id:{ $in:userIds } }).select('name petProfile').lean();
    const nameMap = new Map(users.map(u => [String(u._id), u.name || '사용자']));
    const data = latest.map(x => ({
      userId:String(x._id),
      userName:nameMap.get(String(x._id)) || '사용자',
      lastText:x.lastMessage.text,
      lastAt:x.lastMessage.createdAt,
      unread:unreadMap.get(String(x._id)) || 0,
    }));
    res.json({ data });
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});
async function createAdminChatMessage(req, res) {
  try {
    const { userId, text } = req.body || {};
    if (!userId || !text || !String(text).trim()) return res.status(400).json({ message:'userId/text required' });

    const admin = await HospitalUser.findById(oid(req.jwt.uid)).lean();
    if (!admin) return res.status(404).json({ message:'hospital not found' });

    const user = await User.findById(oid(userId), { name:1, linkedHospitals:1 }).lean();
    if (!user) return res.status(404).json({ message:'user not found' });

    const ok = (user.linkedHospitals || []).some(h => String(h.hospitalId) === String(admin._id) && h.status === 'APPROVED');
    if (!ok) return res.status(403).json({ message:'link to user required (APPROVED)' });

    const doc = await ChatMessage.create({
      hospitalId: oid(req.jwt.uid),
      userId: oid(userId),
      senderRole: 'ADMIN',
      senderId: oid(req.jwt.uid),
      senderName: (admin.name || admin.hospitalName || '병원').trim(),
      text: String(text),
      readByUser: false, readByAdmin: true,
    });
    await pushNotificationOne({
      userId: user._id, hospitalId: oid(req.jwt.uid), hospitalName: admin.hospitalName || '',
      type:'CHAT_ADMIN_TO_USER', title:`${admin.hospitalName || '병원'} 메시지`,
      message:String(text).slice(0, 80), meta:{ chatMessageId: doc._id }
    });
    res.status(201).json({ _id:doc._id, senderRole:doc.senderRole, senderId:doc.senderId, senderName:doc.senderName, text:doc.text, createdAt:doc.createdAt });
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
}
app.get('/api/hospital-admin/chat/messages', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const { userId } = req.query || {};
    if (!userId) return res.status(400).json({ message:'userId required' });
    const hid = oid(req.jwt.uid), uid = oid(userId);
    const user = await User.findById(uid, { linkedHospitals:1, name:1 }).lean();
    if (!user) return res.status(404).json({ message:'user not found' });
    const linked = (user.linkedHospitals||[]).some(h => String(h.hospitalId) === String(hid) && h.status === 'APPROVED');
    if (!linked) return res.status(403).json({ message:'link to user required (APPROVED)' });

    const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
    const since = req.query.since ? new Date(String(req.query.since)) : null;
    const q = { hospitalId:hid, userId:uid }; if (since && !isNaN(since.getTime())) q.createdAt = { $gt: since };
    const list = await ChatMessage.find(q).sort({ createdAt:1 }).limit(limit).lean();
    res.json(list.map(m => ({ _id:m._id, senderRole:m.senderRole, senderId:m.senderId, senderName:m.senderName, text:m.text, createdAt:m.createdAt })));
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});
app.post('/api/hospital-admin/chat/messages', auth, onlyHospitalAdmin, createAdminChatMessage);
app.post('/api/hospital-admin/chat/send',    auth, onlyHospitalAdmin, createAdminChatMessage);
app.post('/api/hospital-admin/chat/read-all', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const { userId } = req.body || {};
    if (!userId) return res.status(400).json({ message:'userId required' });
    await ChatMessage.updateMany({ hospitalId: oid(req.jwt.uid), userId: oid(userId), senderRole:'USER', readByAdmin:false }, { $set:{ readByAdmin:true } });
    res.status(204).send();
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});

// 사용자 채팅
app.get('/api/hospitals/:hospitalId/chat/messages', auth, onlyUser, async (req, res) => {
  try {
    const hid = oid(req.params.hospitalId);
    const me  = await User.findById(oid(req.jwt.uid), { linkedHospitals:1, name:1 }).lean();
    if (!me) return res.status(404).json({ message:'user not found' });
    const linked = (me.linkedHospitals||[]).find(x => String(x.hospitalId) === String(hid) && x.status === 'APPROVED');
    if (!linked) return res.status(403).json({ message:'link to hospital required (APPROVED)' });
    const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
    const since = req.query.since ? new Date(String(req.query.since)) : null;
    const q = { hospitalId:hid, userId:oid(req.jwt.uid) }; if (since && !isNaN(since.getTime())) q.createdAt = { $gt: since };
    const list = await ChatMessage.find(q).sort({ createdAt:1 }).limit(limit).lean();
    res.json(list.map(m => ({ _id:m._id, senderRole:m.senderRole, senderId:m.senderId, senderName:m.senderName, text:m.text, createdAt:m.createdAt })));
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});
app.post('/api/hospitals/:hospitalId/chat/send', auth, onlyUser, async (req, res) => {
  try {
    const hid = oid(req.params.hospitalId);
    const { text } = req.body || {};
    if (!text || !String(text).trim()) return res.status(400).json({ message:'text required' });
    const me = await User.findById(oid(req.jwt.uid), { name:1, linkedHospitals:1 }).lean();
    if (!me) return res.status(404).json({ message:'user not found' });
    const linked = (me.linkedHospitals||[]).find(x => String(x.hospitalId) === String(hid) && x.status === 'APPROVED');
    if (!linked) return res.status(403).json({ message:'link to hospital required (APPROVED)' });
    const admin = await HospitalUser.findById(hid).lean(); if (!admin) return res.status(404).json({ message:'hospital not found' });
    const doc = await ChatMessage.create({
      hospitalId: hid, userId: oid(req.jwt.uid),
      senderRole:'USER', senderId: oid(req.jwt.uid), senderName:(me.name||'').trim() || '사용자',
      text:String(text), readByUser:true, readByAdmin:false
    });
    // 관리자 알림 저장이 필요하면 별도 구현(관리자 알림 DB)
    res.status(201).json({ _id:doc._id, senderRole:doc.senderRole, senderId:doc.senderId, senderName:doc.senderName, text:doc.text, createdAt:doc.createdAt });
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});
app.post('/api/hospitals/:hospitalId/chat/read-all', auth, onlyUser, async (req, res) => {
  try {
    const hid = oid(req.params.hospitalId);
    await ChatMessage.updateMany({ hospitalId:hid, userId: oid(req.jwt.uid), senderRole:'ADMIN', readByUser:false }, { $set:{ readByUser:true } });
    res.status(204).send();
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});

// 환자/진료/케어일지(관리)
app.get('/api/hospital-admin/patients', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit || '200', 10), 500);
    const page  = Math.max(parseInt(req.query.page  || '1', 10), 1);
    const skip  = (page - 1) * limit;
    const pipeline = [
      { $unwind:'$linkedHospitals' },
      { $match:{ 'linkedHospitals.hospitalId': oid(req.jwt.uid), 'linkedHospitals.status':'APPROVED' } },
      { $project:{ _id:'$_id', userId:'$_id', userName:'$name', petName:'$petProfile.name' } },
      { $skip:skip }, { $limit:limit }
    ];
    const [items, totalAgg] = await Promise.all([
      User.aggregate(pipeline),
      User.aggregate([
        { $unwind:'$linkedHospitals' },
        { $match:{ 'linkedHospitals.hospitalId': oid(req.jwt.uid), 'linkedHospitals.status':'APPROVED' } },
        { $count:'total' }
      ]),
    ]);
    const total = totalAgg[0]?.total || 0;
    res.json({ data:items, paging:{ total, page, limit } });
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});
app.get('/api/hospital-admin/medical-histories', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) return res.status(400).json({ message:'userId is required' });
    const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
    const page  = Math.max(parseInt(req.query.page  || '1', 10), 1);
    const skip  = (page - 1) * limit;
    const hid  = oid(req.query.hospitalId || req.jwt.uid);
    const list = await MedicalHistory.find({ userId: oid(userId), hospitalId: hid }).sort({ date:-1, createdAt:-1 }).skip(skip).limit(limit).lean();
    const total = await MedicalHistory.countDocuments({ userId: oid(userId), hospitalId: hid });
    const data  = list.map(m => ({ ...m, id:m._id }));
    res.json({ data, paging:{ total, page, limit } });
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});
app.post('/api/hospital-admin/medical-histories', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const { userId, hospitalId, date, content, prescription, howToTake, cost, petName, userName, category, hospitalName } = req.body || {};
    if (!userId || !date) return res.status(400).json({ message:'userId and date are required' });
    const hid = oid(hospitalId || req.jwt.uid);
    let hName = (hospitalName || '').trim();
    if (!hName) {
      const h = await HospitalUser.findById(hid).lean();
      hName = h?.hospitalName || '';
    }
    const doc = await MedicalHistory.create({
      userId: oid(userId), hospitalId: hid, hospitalName: hName,
      userName:(userName||'').trim(), petName:(petName||'').trim(),
      date:new Date(date), category:(category||'').trim(), content:(content||'').trim(),
      prescription:(prescription||'').trim(), howToTake:(howToTake||'').trim(), cost:(cost||'').trim(),
    });
    await pushNotificationOne({
      userId, hospitalId:hid, hospitalName:hName, type:'MEDICAL_HISTORY_ADDED',
      title:'새 진료 내역 등록', message:`${(category||'진료')} · ${new Date(date).toLocaleDateString()}`,
      meta:{ medicalHistoryId: doc._id }
    });
    res.status(201).json({ data:{ ...doc.toJSON(), id:doc._id } });
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});

// 케어일지(관리자 목록/등록/삭제)
app.get('/api/hospital-admin/pet-care', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const { patientId } = req.query;
    const keyword = (req.query.keyword || '').toString().trim();
    const sortKey = (req.query.sort || 'dateDesc').toString();
    if (!patientId) return res.status(400).json({ message:'patientId required' });

    // 병원-사용자 APPROVED 검증
    const approvedUser = await User.findOne({
      _id: oid(patientId),
      linkedHospitals: { $elemMatch: { hospitalId: oid(req.jwt.uid), status: 'APPROVED' } },
    }).select('_id').lean();
    if (!approvedUser) return res.status(404).json({ message:'patient not found in this hospital' });

    const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
    const page  = Math.max(parseInt(req.query.page  || '1', 10), 1);
    const skip  = (page - 1) * limit;
    const sort  = (sortKey === 'dateAsc') ? 1 : -1;

    const q = { hospitalId: oid(req.jwt.uid), patientId: oid(patientId) };
    if (keyword) { const rx = new RegExp(keyword, 'i'); q.$or = [{ memo: rx }]; }

    const [items, total] = await Promise.all([
      PetCare.find(q).sort({ dateTime:sort, createdAt:sort }).skip(skip).limit(limit).lean(),
      PetCare.countDocuments(q),
    ]);
    const data = items.map(d => ({
      _id:d._id, date:d.date||'', time:d.time||'', dateTime:d.dateTime, memo:d.memo||'',
      imageUrl:(d.images&&d.images.length)? d.images[0] : '', images:d.images||[], patientId:d.patientId
    }));
    res.json({ data, paging:{ total, page, limit } });
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});
app.post('/api/hospital-admin/pet-care', auth, onlyHospitalAdmin, uploadLimiter, upload.array('images', 10), async (req, res) => {
  try {
    const { patientId } = req.body;
    const date = (req.body.date || '').toString().trim();
    const time = (req.body.time || '').toString().trim();
    const memo = (req.body.memo || '').toString().trim();
    if (!patientId) return res.status(400).json({ message:'patientId required' });
    if (!date || !time) return res.status(400).json({ message:'date/time required' });

    // 병원-사용자 APPROVED 검증
    const patientUser = await User.findOne({
      _id: oid(patientId),
      linkedHospitals: { $elemMatch: { hospitalId: oid(req.jwt.uid), status: 'APPROVED' } },
    }).select('_id name petProfile').lean();
    if (!patientUser) return res.status(404).json({ message:'patient not found in this hospital' });

    const urls = (req.files||[]).map(f => publicUrl(req, `/uploads/pet-care/${path.basename(f.path)}`));
    const dt = new Date(`${date}T${time}:00`);
    const hospitalName = (await HospitalUser.findById(oid(req.jwt.uid)).select('hospitalName').lean())?.hospitalName || '';

    const doc = await PetCare.create({
      hospitalId: oid(req.jwt.uid), hospitalName,
      createdBy: oid(req.jwt.uid), patientId: oid(patientId), userId: oid(patientId),
      date, time, dateTime: isNaN(dt.getTime()) ? new Date() : dt, memo, images: urls
    });

    await pushNotificationMany({
      userIds:[oid(patientId)], hospitalId: oid(req.jwt.uid), hospitalName,
      type:'PET_CARE_POSTED', title:'새 반려 일지가 올라왔어요',
      message: memo ? memo.slice(0,80) : '이미지/메모가 등록되었습니다.',
      meta:{ petCareId: doc._id, imageUrl: urls[0] || '' }
    });

    res.status(201).json({
      data:{
        _id:doc._id, date:doc.date, time:doc.time, dateTime:doc.dateTime, memo:doc.memo,
        imageUrl:(doc.images&&doc.images.length)? doc.images[0] : '', images:doc.images||[], patientId:doc.patientId
      }
    });
  } catch (e) { console.error(e); res.status(500).json({ message:e?.message || 'server error' }); }
});
app.delete('/api/hospital-admin/pet-care/:id', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const care = await PetCare.findById(id).lean();
    if (!care) return res.status(404).json({ message:'care not found' });
    if (String(care.hospitalId) !== String(req.jwt.uid)) return res.status(403).json({ message:'forbidden' });
    const urls = Array.isArray(care.images) ? care.images.filter(Boolean) : [];
    await deleteFilesByUrls(urls);
    await PetCare.deleteOne({ _id:id });
    return res.json({ ok:true });
  } catch (e) { console.error(e); return res.status(500).json({ message:'internal error' }); }
});

// 병원 예약 메타/신청
app.get('/api/hospitals/:hospitalId/appointment-meta', async (req, res) => {
  const { hospitalId } = req.params;
  const meta = await HospitalMeta.findOne({ hospitalId: oid(hospitalId) }).lean();
  const servicesDefault = ['일반진료','건강검진','종합백신','심장사상충','치석제거'];
  const doctorsDefault  = [{ id:'default', name:'김철수 원장' }];
  if (!meta) {
    const h = await HospitalUser.findById(oid(hospitalId)).lean();
    return res.json({ hospitalId, hospitalName:h?.hospitalName || '', notice:'', services:servicesDefault, doctors:doctorsDefault });
  }
  res.json({
    hospitalId, hospitalName: meta.hospitalName || '', notice: meta.notice || '',
    services: (meta.services?.length ? meta.services : servicesDefault),
    doctors:  (meta.doctors?.length  ? meta.doctors  : doctorsDefault)
  });
});
app.put('/api/hospitals/:hospitalId/appointment-meta', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    if (String(req.params.hospitalId) !== String(req.jwt.uid)) return res.status(403).json({ message:'forbidden' });
    const { services, doctors, notice } = req.body || {};
    const h = await HospitalUser.findById(oid(req.jwt.uid)).lean();
    const doc = await HospitalMeta.findOneAndUpdate(
      { hospitalId: oid(req.jwt.uid) },
      { $set:{
        hospitalId: oid(req.jwt.uid), hospitalName: h?.hospitalName || '',
        notice: (notice||'').toString(),
        services: Array.isArray(services) ? services : undefined,
        doctors:  Array.isArray(doctors)  ? doctors  : undefined,
      }},
      { new:true, upsert:true }
    ).lean();
    res.json({ ok:true, meta:doc });
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});
app.post('/api/hospitals/:hospitalId/appointments/request', auth, onlyUser, async (req, res) => {
  try {
    const { hospitalId } = req.params;
    const { hospitalName, service, doctorName, date, time, visitDateTime, userName, petName } = req.body || {};
    if (!service || !doctorName || !date || !time) return res.status(400).json({ message:'missing fields' });

    const me = await User.findById(oid(req.jwt.uid)).lean();
    const link = (me?.linkedHospitals||[]).find(h => String(h.hospitalId) === String(hospitalId));
    if (!link || link.status !== 'APPROVED') return res.status(403).json({ message:'link to hospital required (APPROVED)' });

    const h = await HospitalUser.findById(oid(hospitalId)).lean(); if (!h) return res.status(404).json({ message:'hospital not found' });

    const vdt = visitDateTime ? new Date(visitDateTime) : new Date(`${date}T${time}:00`);
    const finalUserName = (userName||'').trim() && (userName||'').trim() !== '사용자' ? (userName||'').trim() : (me?.name || '');
    const finalPetName  = (petName||'').trim() && (petName||'').trim() !== '(미입력)' ? (petName||'').trim() : (me?.petProfile?.name || '');

    const appt = await Appointment.create({
      hospitalId: oid(hospitalId), hospitalName: hospitalName || h.hospitalName || '',
      userId: oid(req.jwt.uid), userName: finalUserName, petName: finalPetName,
      service, doctorName, date, time, visitDateTime:vdt, status:'PENDING'
    });
    await UserAppointment.create({
      userId: oid(req.jwt.uid), originAppointmentId: appt._id,
      hospitalId: oid(hospitalId), hospitalName: hospitalName || h.hospitalName || '',
      userName: finalUserName, petName: finalPetName,
      service, doctorName, date, time, visitDateTime:vdt, status:'PENDING'
    });
    res.status(201).json({ ok:true, appointmentId: appt._id });
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});

// 공지 목록/등록
app.get('/api/hospital-admin/notices', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const hid = oid(req.query.hospitalId || req.jwt.uid);
    const list = await HospitalNotice.find({ hospitalId: hid }).sort({ createdAt:-1 }).select('_id title content createdAt').lean();
    res.json({ data: list.map(n => ({ id:n._id, _id:n._id, title:n.title, content:n.content, createdAt:n.createdAt })) });
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});
app.post('/api/hospital-admin/notices', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const { title, content } = req.body || {};
    const hid = oid(req.body?.hospitalId || req.jwt.uid);
    if (!title || !content) return res.status(400).json({ message:'title/content required' });
    const h = await HospitalUser.findById(hid).lean();
    const hospitalName = h?.hospitalName || '';
    const doc = await HospitalNotice.create({
      hospitalId: hid, hospitalName, title:String(title).trim(), content:String(content).trim(), createdBy: oid(req.jwt.uid),
    });
    const approvedUsers = await User.find({ linkedHospitals: { $elemMatch:{ hospitalId:hid, status:'APPROVED' } } }).select('_id').lean();
    await pushNotificationMany({
      userIds: approvedUsers.map(u => u._id), hospitalId:hid, hospitalName,
      type:'HOSPITAL_NOTICE', title:`[공지] ${doc.title}`.slice(0,40), message: doc.content.slice(0,120), meta:{ noticeId: doc._id }
    });
    res.status(201).json({ data:{ id:doc._id, _id:doc._id, title:doc.title, content:doc.content, createdAt:doc.createdAt } });
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});

// 관리자 요약
app.get('/api/hospitals/:hospitalId/admin/summary', async (req, res) => {
  try {
    const h = await HospitalUser.findById(oid(req.params.hospitalId)).lean();
    if (!h) return res.status(404).json({ message:'hospital not found' });
    const doctorName = (h.hospitalProfile?.doctorName || h.name || '').trim() || '김철수 원장';
    res.json({ doctorName });
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});

// ─────────────────────────────────────────────────────────────
// 쇼핑 API (/api/shop/...)
// ─────────────────────────────────────────────────────────────

// 상품 등록(관리자 전용이 필요하면 미들웨어 추가)
app.post('/api/shop/products', async (req, res) => {
  try { const p = await Product.create(req.body); res.json({ message:'상품 등록 성공', product:p }); }
  catch (err) { res.status(500).json({ error:err.message }); }
});
// 상품 목록/단일
app.get('/api/shop/products', async (_req, res) => {
  try { const list = await Product.find().sort({ createdAt:-1 }); res.json(list); }
  catch (err) { res.status(500).json({ error:err.message }); }
});
app.get('/api/shop/products/:id', async (req, res) => {
  try { const p = await Product.findById(req.params.id); if (!p) return res.status(404).json({ message:'상품 없음' }); res.json(p); }
  catch (err) { res.status(500).json({ error:err.message }); }
});

// 리뷰 등록/삭제
app.post('/api/shop/products/:id/reviews', async (req, res) => {
  try {
    const { userName, rating, comment } = req.body;
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message:'상품 없음' });
    product.reviews.push({ userName, rating, comment, createdAt:new Date() });
    const total = product.reviews.reduce((s, r) => s + (r.rating||0), 0);
    product.averageRating = product.reviews.length ? total / product.reviews.length : 0;
    await product.save();
    res.json({ message:'리뷰 등록 성공', product });
  } catch (err) { res.status(500).json({ error:err.message }); }
});
app.delete('/api/shop/products/:productId/reviews/:reviewId', async (req, res) => {
  try {
    const product = await Product.findById(req.params.productId);
    if (!product) return res.status(404).json({ message:'상품 없음' });
    product.reviews = product.reviews.filter(r => String(r._id) !== String(req.params.reviewId));
    const total = product.reviews.reduce((s, r) => s + (r.rating||0), 0);
    product.averageRating = product.reviews.length ? total / product.reviews.length : 0;
    await product.save();
    res.json({ message:'✅ 리뷰 삭제 완료' });
  } catch (err) { res.status(500).json({ error:err.message }); }
});

// 찜/장바구니
app.post('/api/shop/users/:userId/favorites/:productId', async (req, res) => {
  try {
    const { userId, productId } = req.params;
    const user = await User.findById(userId); if (!user) return res.status(404).json({ message:'유저 없음' });
    if (!user.favorites.map(String).includes(String(productId))) {
      user.favorites.push(productId); await user.save();
    }
    res.json({ message:'찜 완료', favorites:user.favorites });
  } catch (err) { res.status(500).json({ error:err.message }); }
});
app.post('/api/shop/users/:userId/cart/:productId', async (req, res) => {
  try {
    const { userId, productId } = req.params; const { count } = req.body || {};
    const user = await User.findById(userId); if (!user) return res.status(404).json({ message:'유저 없음' });
    const existing = user.cart.find(i => String(i.productId) === String(productId));
    if (existing) existing.count += (count || 1);
    else user.cart.push({ productId, count: count || 1 });
    await user.save();
    res.json({ message:'장바구니 추가 완료', cart:user.cart });
  } catch (err) { res.status(500).json({ error:err.message }); }
});

// 주문(생성/목록/상태/삭제)
app.post('/api/shop/orders', async (req, res) => {
  try { const order = await Order.create(req.body); res.json({ message:'주문 생성 성공', order }); }
  catch (err) { res.status(500).json({ error:err.message }); }
});
app.get('/api/shop/orders', async (_req, res) => {
  try { const orders = await Order.find().sort({ createdAt:-1 }); res.json(orders); }
  catch (err) { res.status(500).json({ error:err.message }); }
});
app.patch('/api/shop/orders/:orderId', async (req, res) => {
  try {
    const { status } = req.body;
    const order = await Order.findByIdAndUpdate(req.params.orderId, { status }, { new:true });
    if (!order) return res.status(404).json({ message:'주문 없음' });
    res.json({ success:true, updatedOrder:order });
  } catch (err) { res.status(500).json({ error:err.message }); }
});
app.delete('/api/shop/orders/:orderId', async (req, res) => {
  try {
    const order = await Order.findByIdAndDelete(req.params.orderId);
    if (!order) return res.status(404).json({ message:'주문 없음' });
    res.json({ success:true, message:'주문이 취소되었습니다' });
  } catch (err) { res.status(500).json({ error:err.message }); }
});

// ─────────────────────────────────────────────────────────────
// 건강 관리(Chart), 일기, 알람
// ─────────────────────────────────────────────────────────────
app.post('/users/me/health-record', auth, onlyUser, async (req, res) => {
  try {
    const userId = req.jwt.uid;
    const { date, weight, activity, intake } = req.body;
    if (!date) return res.status(400).json({ message:'날짜는 필수입니다.' });

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message:'사용자를 찾을 수 없습니다.' });

    if (!user.petProfile) user.petProfile = {};
    if (!user.petProfile.healthChart) user.petProfile.healthChart = { weight:[], activity:[], intake:[] };

    const d = new Date(date);
    if (weight && typeof weight.bodyWeight === 'number') {
      user.petProfile.healthChart.weight.push({
        date:d, bodyWeight:weight.bodyWeight,
        ...(typeof weight.muscleMass === 'number' && { muscleMass:weight.muscleMass }),
        ...(typeof weight.bodyFatMass === 'number' && { bodyFatMass:weight.bodyFatMass }),
      });
    }
    if (activity && typeof activity.time === 'number') {
      user.petProfile.healthChart.activity.push({
        date:d, time:activity.time, ...(typeof activity.calories === 'number' && { calories:activity.calories }),
      });
    }
    if (intake && typeof intake.food === 'number') {
      user.petProfile.healthChart.intake.push({
        date:d, food:intake.food, ...(typeof intake.water === 'number' && { water:intake.water }),
      });
    }
    await user.save();
    return res.status(200).json({ petProfile:user.petProfile });
  } catch (e) { console.error(e); res.status(500).json({ message:'서버 오류가 발생했습니다.' }); }
});
app.delete('/users/health-record', auth, onlyUser, async (req, res) => {
  try {
    const userId = req.jwt.uid;
    const { date } = req.body;
    if (!date) return res.status(400).json({ message:'삭제할 날짜(시간) 정보가 필요합니다.' });
    const targetDate = new Date(date);
    await User.updateOne(
      { _id:userId },
      { $pull:{
        'petProfile.healthChart.weight':   { date: targetDate },
        'petProfile.healthChart.activity': { date: targetDate },
        'petProfile.healthChart.intake':   { date: targetDate },
      }}
    );
    return res.status(204).send();
  } catch (e) { console.error(e); res.status(500).json({ message:'서버 오류가 발생했습니다.' }); }
});

// 일기
app.get('/diaries', auth, onlyUser, async (req, res) => {
  try {
    const user = await User.findById(req.jwt.uid, { 'petProfile.diaries':1 }).lean();
    if (!user || !user.petProfile) return res.json([]);
    const sorted = [...(user.petProfile.diaries || [])].sort((a,b)=> new Date(b.date) - new Date(a.date));
    res.json(sorted);
  } catch (e) { console.error(e); res.status(500).json({ message:'Server error' }); }
});
app.post('/diaries', auth, onlyUser, upload.single('image'), async (req, res) => {
  try {
    const user = await User.findById(req.jwt.uid);
    if (!user) return res.status(404).json({ message:'User not found' });
    const { title, content, date } = req.body;
    const imagePath = req.file ? `/uploads/pet-care/${path.basename(req.file.path)}` : '';
    if (!user.petProfile) user.petProfile = {};
    if (!user.petProfile.diaries) user.petProfile.diaries = [];
    const newDiary = { title:String(title||''), content:String(content||''), date:new Date(date), imagePath };
    user.petProfile.diaries.push(newDiary);
    await user.save();
    const saved = user.petProfile.diaries[user.petProfile.diaries.length - 1];
    res.status(201).json(saved);
  } catch (e) { console.error(e); res.status(500).json({ message:'Server error' }); }
});
app.put('/diaries/:id', auth, onlyUser, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, content, date, imagePath } = req.body;
    const user = await User.findById(req.jwt.uid);
    if (!user?.petProfile?.diaries) return res.status(404).json({ message:'Diary not found' });
    const diary = user.petProfile.diaries.id(id);
    if (!diary) return res.status(404).json({ message:'Diary not found' });
    diary.set({
      ...(title !== undefined ? { title } : {}),
      ...(content !== undefined ? { content } : {}),
      ...(date !== undefined ? { date:new Date(date) } : {}),
      ...(imagePath !== undefined ? { imagePath } : {}),
    });
    await user.save();
    res.json(diary);
  } catch (e) { console.error(e); res.status(500).json({ message:'Server error' }); }
});
app.delete('/diaries/:id', auth, onlyUser, async (req, res) => {
  try { await User.updateOne({ _id:req.jwt.uid }, { $pull:{ 'petProfile.diaries': { _id:req.params.id } } }); res.status(204).send(); }
  catch (e) { console.error(e); res.status(500).json({ message:'Server error' }); }
});

// 알람
app.get('/users/me/alarms', auth, onlyUser, async (req, res) => {
  try { const user = await User.findById(req.jwt.uid, { 'petProfile.alarms':1 }).lean(); res.json(user?.petProfile?.alarms || []); }
  catch (e) { console.error(e); res.status(500).json({ message:'Server error' }); }
});
app.post('/users/me/alarms', auth, onlyUser, async (req, res) => {
  try {
    const { time, label, isActive, repeatDays, snoozeMinutes } = req.body || {};
    if (!time || !label) return res.status(400).json({ message:'Time and label are required.' });
    const user = await User.findById(req.jwt.uid); if (!user) return res.status(404).json({ message:'User not found' });
    if (!user.petProfile) user.petProfile = {}; if (!user.petProfile.alarms) user.petProfile.alarms = [];
    const newAlarm = { time, label, isActive: isActive !== false, repeatDays: Array.isArray(repeatDays)? repeatDays : [] };
    if (Object.prototype.hasOwnProperty.call(req.body,'snoozeMinutes')) newAlarm.snoozeMinutes = snoozeMinutes;
    user.petProfile.alarms.push(newAlarm); await user.save();
    res.status(201).json(user.petProfile.alarms[user.petProfile.alarms.length - 1]);
  } catch (e) { console.error(e); res.status(500).json({ message:'Server error' }); }
});
app.put('/users/me/alarms/:id', auth, onlyUser, async (req, res) => {
  try {
    const { id } = req.params; const { time, label, isActive, repeatDays, snoozeMinutes } = req.body || {};
    const user = await User.findById(req.jwt.uid);
    if (!user?.petProfile?.alarms) return res.status(404).json({ message:'Alarm not found' });
    const alarm = user.petProfile.alarms.id(id); if (!alarm) return res.status(404).json({ message:'Alarm not found' });
    if (time !== undefined) alarm.time = time;
    if (label !== undefined) alarm.label = label;
    if (isActive !== undefined) alarm.isActive = isActive;
    if (repeatDays !== undefined) alarm.repeatDays = repeatDays;
    if (Object.prototype.hasOwnProperty.call(req.body,'snoozeMinutes')) alarm.snoozeMinutes = snoozeMinutes;
    await user.save(); res.json(alarm);
  } catch (e) { console.error(e); res.status(500).json({ message:'Server error' }); }
});
app.delete('/users/me/alarms/:id', auth, onlyUser, async (req, res) => {
  try { await User.updateOne({ _id:req.jwt.uid }, { $pull:{ 'petProfile.alarms': { _id:req.params.id } } }); res.status(204).send(); }
  catch (e) { console.error(e); res.status(500).json({ message:'Server error' }); }
});

// 사용자: 예약/케어일지/진료내역/알림
app.get('/api/users/me/appointments', auth, onlyUser, async (req, res) => {
  try {
    const me = await User.findById(oid(req.jwt.uid), { name:1, petProfile:1 }).lean();
    const q = { userId: oid(req.jwt.uid) };
    if (req.query.hospitalId) q.hospitalId = oid(req.query.hospitalId);
    if (req.query.month) {
      const [yy, mm] = String(req.query.month).split('-').map(Number);
      if (yy && mm) {
        const start = new Date(yy, mm - 1, 1, 0, 0, 0);
        const end   = new Date(yy, mm, 1, 0, 0, 0);
        q.visitDateTime = { $gte:start, $lt:end };
      }
    }
    const limit = Math.min(parseInt(req.query.limit || '100', 10), 300);
    const page  = Math.max(parseInt(req.query.page || '1', 10), 1);
    const skip  = (page - 1) * limit;
    let list = await UserAppointment.find(q).sort({ visitDateTime:1 }).skip(skip).limit(limit).lean();
    const total = await UserAppointment.countDocuments(q);
    list = list.map(a => ({ ...a, userName: a.userName || me?.name || '', petName: a.petName || me?.petProfile?.name || '' }));
    if (!list.length) {
      const hospitalList = await Appointment.find({ userId: oid(req.jwt.uid) }).sort({ visitDateTime:1 }).skip(skip).limit(limit).lean();
      const mapped = hospitalList.map(a => ({
        userId:a.userId, hospitalId:a.hospitalId, hospitalName:a.hospitalName,
        userName:a.userName || me?.name || '', petName:a.petName || me?.petProfile?.name || '',
        service:a.service, doctorName:a.doctorName, date:a.date, time:a.time, visitDateTime:a.visitDateTime, status:a.status,
      }));
      return res.json({ data:mapped, paging:{ total: await Appointment.countDocuments({ userId: oid(req.jwt.uid) }), page, limit } });
    }
    res.json({ data:list, paging:{ total, page, limit } });
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});
app.delete('/api/users/me/appointments/:id', auth, onlyUser, async (req, res) => {
  try {
    const ua = await UserAppointment.findOne({ _id: oid(req.params.id), userId: oid(req.jwt.uid) });
    if (!ua) return res.status(404).json({ message:'not found' });
    await UserAppointment.deleteOne({ _id: ua._id });
    await Appointment.deleteOne({ _id: ua.originAppointmentId, userId: oid(req.jwt.uid) });
    res.status(204).send();
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});
app.get('/api/users/me/appointments/monthly', auth, onlyUser, async (req, res) => {
  try {
    const { hospitalId, month } = req.query;
    if (!month) return res.status(400).json({ message:'month required (YYYY-MM)' });
    const [yy, mm] = String(month).split('-').map(Number);
    if (!yy || !mm) return res.status(400).json({ message:'invalid month' });
    const q = { userId: oid(req.jwt.uid) };
    if (hospitalId) q.hospitalId = oid(hospitalId);
    const start = new Date(yy, mm - 1, 1, 0, 0, 0), end = new Date(yy, mm, 1, 0, 0, 0);
    q.visitDateTime = { $gte:start, $lt:end };
    const list = await UserAppointment.find(q).sort({ visitDateTime:1 }).lean();
    res.json(list);
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});
app.get('/api/users/me/pet-care', auth, onlyUser, async (req, res) => {
  try {
    const { hospitalId, keyword = '', sort = 'dateDesc' } = req.query;
    if (!hospitalId) return res.status(400).json({ message:'hospitalId required' });
    const me = await User.findById(oid(req.jwt.uid), { linkedHospitals:1 }).lean();
    const link = (me?.linkedHospitals||[]).find(h => String(h.hospitalId) === String(hospitalId) && h.status === 'APPROVED');
    if (!link) return res.status(403).json({ message:'link to hospital required (APPROVED)' });
    const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
    const page  = Math.max(parseInt(req.query.page  || '1', 10), 1);
    const skip  = (page - 1) * limit;
    const s = (String(sort) === 'dateAsc') ? 1 : -1;
    const q = { hospitalId: oid(hospitalId), patientId: oid(req.jwt.uid) };
    if (String(keyword).trim()) { const rx = new RegExp(String(keyword).trim(), 'i'); q.$or = [{ memo: rx }]; }
    const [items, total] = await Promise.all([
      PetCare.find(q).sort({ dateTime:s, createdAt:s }).skip(skip).limit(limit).lean(),
      PetCare.countDocuments(q),
    ]);
    const data = items.map(d => ({ _id:d._id, date:d.date||'', time:d.time||'', dateTime:d.dateTime, memo:d.memo||'', imageUrl:(d.images&&d.images.length)? d.images[0] : '', images:d.images||[], patientId:d.patientId }));
    res.json({ data, paging:{ total, page, limit } });
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});
app.get('/api/users/me/medical-histories', auth, onlyUser, async (req, res) => {
  try {
    const { hospitalId, month, q } = req.query;
    const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
    const page  = Math.max(parseInt(req.query.page  || '1', 10), 1);
    const skip  = (page - 1) * limit;
    const find = { userId: oid(req.jwt.uid) };
    if (hospitalId) find.hospitalId = oid(hospitalId);
    if (month) {
      const [yy, mm] = String(month).split('-').map(Number);
      if (!yy || !mm) return res.status(400).json({ message:'invalid month' });
      const start = new Date(yy, mm - 1, 1, 0, 0, 0), end = new Date(yy, mm, 1, 0, 0, 0);
      find.date = { $gte:start, $lt:end };
    }
    if (q && String(q).trim()) {
      const rx = new RegExp(String(q).trim(), 'i');
      find.$or = [{ category:rx }, { content:rx }, { prescription:rx }, { howToTake:rx }, { hospitalName:rx }, { cost:rx }];
    }
    const [items, total] = await Promise.all([
      MedicalHistory.find(find).sort({ date:-1, createdAt:-1 }).skip(skip).limit(limit).lean(),
      MedicalHistory.countDocuments(find),
    ]);
    const data = items.map(m => ({ ...m, id:m._id }));
    res.json({ data, paging:{ total, page, limit } });
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});

// 사용자 알림
app.get('/api/users/me/notifications/unread-count', auth, onlyUser, async (req, res) => {
  try {
    const q = { userId: oid(req.jwt.uid), read:false };
    if (req.query.hospitalId) q.hospitalId = oid(req.query.hospitalId);
    const count = await Notification.countDocuments(q);
    res.json({ count });
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});
app.get('/api/users/me/notifications', auth, onlyUser, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit || '20', 10), 100);
    const q = { userId: oid(req.jwt.uid) };
    if (req.query.hospitalId) q.hospitalId = oid(req.query.hospitalId);
    if (req.query.cursor) q._id = { $lt: oid(req.query.cursor) };
    const items = await Notification.find(q).sort({ _id:-1 }).limit(limit).lean();
    const nextCursor = items.length === limit ? String(items[items.length - 1]._id) : null;
    const data = items.map(n => ({ id:n._id, type:n.type, title:n.title||'', message:n.message||'', createdAt:n.createdAt, read:!!n.read, hospitalId:n.hospitalId, hospitalName:n.hospitalName||'', meta:n.meta||{} }));
    res.json({ data, nextCursor });
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});
app.patch('/api/users/me/notifications/:id/read', auth, onlyUser, async (req, res) => {
  try { await Notification.updateOne({ _id:oid(req.params.id), userId: oid(req.jwt.uid) }, { $set:{ read:true } }); res.status(204).send(); }
  catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});
app.post('/api/users/me/notifications/mark-all-read', auth, onlyUser, async (req, res) => {
  try {
    const q = { userId: oid(req.jwt.uid), read:false };
    if (req.query.hospitalId) q.hospitalId = oid(req.query.hospitalId);
    await Notification.updateMany(q, { $set:{ read:true } });
    res.status(204).send();
  } catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});
app.delete('/api/users/me/notifications/:id', auth, onlyUser, async (req, res) => {
  try { await Notification.deleteOne({ _id:oid(req.params.id), userId: oid(req.jwt.uid) }); res.status(204).send(); }
  catch (e) { console.error(e); res.status(500).json({ message:'server error' }); }
});

// ─────────────────────────────────────────────────────────────
// 404 & 에러 핸들러
// ─────────────────────────────────────────────────────────────
app.use((req, res) => {
  if (req.path === '/favicon.ico') return res.status(204).send();
  return res.status(404).json({ message:'not found' });
});
app.use((err, _req, res, _next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ message:'server error' });
});

// ─────────────────────────────────────────────────────────────
const server = app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
process.on('SIGTERM', () => server.close(() => process.exit(0)));
process.on('SIGINT',  () => server.close(() => process.exit(0)));
