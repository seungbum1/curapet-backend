// server.js
require('dotenv').config();
const path   = require('path');
const fs     = require('fs');
const multer = require('multer');

const express    = require('express');
const mongoose   = require('mongoose');
const cors       = require('cors');
const bcrypt     = require('bcrypt');
const jwt        = require('jsonwebtoken');
const helmet     = require('helmet');
const compression= require('compression');
const morgan     = require('morgan');
const rateLimit  = require('express-rate-limit');

const MONGODB_URI = process.env.MONGODB_URI;
const PORT        = process.env.PORT || 4000;
const JWT_SECRET  = process.env.JWT_SECRET;

// ─────────────── 환경변수 필수 체크 ───────────────
if (!MONGODB_URI) {
  console.error('❌ MONGODB_URI is required');
  process.exit(1);
}
if (!JWT_SECRET) {
  console.error('❌ JWT_SECRET is required');
  process.exit(1);
}

const app = express();

// 프록시 환경(Cloudflare, Nginx 등)에서 X-Forwarded-* 신뢰
app.set('trust proxy', 1);

// ─────────────── 보안/성능 미들웨어 ───────────────
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
}));
app.use(compression());
app.use(morgan('dev'));

// CORS: 화이트리스트 → 없으면 전체 허용(개발편의)
const allowOrigins = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || allowOrigins.length === 0) return cb(null, true);
    return cb(null, allowOrigins.includes(origin));
  },
  credentials: true,
}));
app.use(express.json({ limit: '2mb' }));

// ───────────────── 업로드 폴더 & 정적 서빙 ─────────────────
const UP_ROOT = path.join(__dirname, 'uploads');
const UP_DIR  = path.join(UP_ROOT, 'pet-care');
fs.mkdirSync(UP_DIR, { recursive: true });

// 정적 파일 캐시(1d) + 기본 보안 옵션
app.use('/uploads', express.static(UP_ROOT, {
  setHeaders: (res) => {
    res.setHeader('Cache-Control', 'public, max-age=86400');
  },
  fallthrough: true,
  index: false,
}));

// ─────────────── Multer(업로드) 설정 ───────────────
const ALLOWED_EXTS  = new Set(['.jpg', '.jpeg', '.png', '.gif', '.webp']);
const ALLOWED_MIMES = new Set(['image/jpeg','image/png','image/gif','image/webp']);

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UP_DIR),
  filename: (_req, file, cb) => {
    const ext = (path.extname(file.originalname || '') || '').toLowerCase();
    const safeExt = ALLOWED_EXTS.has(ext) ? ext : '';
    cb(null, `${Date.now()}-${Math.round(Math.random()*1e9)}${safeExt}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024, files: 10 }, // 10MB, 최대 10장
  fileFilter: (_req, file, cb) => {
    if (!ALLOWED_MIMES.has(file.mimetype)) return cb(new Error('Invalid file type'));
    cb(null, true);
  }
});

// ─────────────── 레이트리밋(로그인/회원가입/업로드) ───────────────
const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10분
  max: 100,                  // 10분에 100회
  standardHeaders: true,
  legacyHeaders: false,
});
const uploadLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
});

// ─────────────── 공통 유틸 ───────────────
function issueToken(doc) {
  return jwt.sign({ uid: doc._id, role: doc.role }, JWT_SECRET, { expiresIn: '7d' });
}

function buildBaseUrl(req) {
  // PUBLIC_BASE_URL 우선, 없으면 프록시 헤더 고려
  if (process.env.PUBLIC_BASE_URL) return process.env.PUBLIC_BASE_URL.replace(/\/+$/, '');
  const proto = req.get('x-forwarded-proto') || req.protocol;
  const host  = req.get('x-forwarded-host') || req.get('host');
  return `${proto}://${host}`;
}

function publicUrl(req, relativePath) {
  const base = buildBaseUrl(req);
  return `${base}${relativePath.startsWith('/') ? '' : '/'}${relativePath}`;
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

function hospitalAdminProfileDto(admin) {
  return {
    // Flutter는 name/hospitalName/title 중 먼저 오는 값을 쓰니
    // 병원명이 덮어쓰이도록 name은 보내지 않습니다.
    hospitalName: admin.hospitalName || '',
    intro: admin.hospitalProfile?.intro || '',
    // 필요 시 확장 필드
    photoUrl: admin.hospitalProfile?.photoUrl || '',
    address:  admin.hospitalProfile?.address  || '',
    hours:    admin.hospitalProfile?.hours    || '',
    phone:    admin.hospitalProfile?.phone    || '',
    approveStatus: admin.approveStatus || 'PENDING',
  };
}

// ─────────────── 알림 유틸 ───────────────
async function pushNotificationOne({ userId, hospitalId, hospitalName = '', type, title, message, meta = {} }) {
  try {
    if (!userId || !hospitalId) return;
    await Notification.create({
      userId: oid(userId),
      hospitalId: oid(hospitalId),
      hospitalName: hospitalName || '',
      type: (type || 'SYSTEM').toString(),
      title: (title || '').toString(),
      message: (message || '').toString(),
      meta,
    });
  } catch (e) {
    console.error('pushNotificationOne error:', e?.message || e);
  }
}

async function pushNotificationMany({ userIds = [], hospitalId, hospitalName = '', type, title, message, meta = {} }) {
  try {
    const docs = (userIds || []).filter(Boolean).map(u => ({
      userId: oid(u),
      hospitalId: oid(hospitalId),
      hospitalName: hospitalName || '',
      type: (type || 'SYSTEM').toString(),
      title: (title || '').toString(),
      message: (message || '').toString(),
      meta,
      createdAt: new Date(),
    }));
    if (docs.length) await Notification.insertMany(docs, { ordered: false });
  } catch (e) {
    console.error('pushNotificationMany error:', e?.message || e);
  }
}



const onlyUser = (req, res, next) =>
  req.jwt?.role === 'USER' ? next() : res.status(403).json({ message: 'for USER' });
const onlyHospitalAdmin = (req, res, next) =>
  req.jwt?.role === 'HOSPITAL_ADMIN' ? next() : res.status(403).json({ message: 'for HOSPITAL_ADMIN' });

const oid = (v) => {
  if (v instanceof mongoose.Types.ObjectId) return v;
  try { return new mongoose.Types.ObjectId(String(v)); } catch { return null; }
};

// ─────────────── Mongoose ───────────────
mongoose.set('strictQuery', true);

// 커넥션
const userConn     = mongoose.createConnection(MONGODB_URI, { dbName: 'user_db' });
const hospitalConn = mongoose.createConnection(MONGODB_URI, { dbName: 'hospital_db' });
const adminConn    = mongoose.createConnection(MONGODB_URI, { dbName: 'admin_db' });

userConn.on('connected',     () => console.log('✅ userConn -> user_db'));
hospitalConn.on('connected', () => console.log('✅ hospitalConn -> hospital_db'));
adminConn.on('connected',    () => console.log('✅ adminConn -> admin_db'));

// 에러 로깅
[userConn, hospitalConn, adminConn].forEach(c =>
  c.on('error', (e) => console.error('Mongo error:', e?.message || e))
);

// ─────────────── 스키마 ───────────────
const userSchema = new mongoose.Schema({
  email:        { type: String, required: true, unique: true, index: true },
  passwordHash: { type: String, required: true },
  name:         { type: String, default: '' },
  role:         { type: String, enum: ['USER'], default: 'USER', index: true },
  birthDate:    { type: String, default: '' },
  petProfile: {
    name:      { type: String, default: '' },
    age:       { type: Number, default: 0 },
    gender:    { type: String, default: '' },
    species:   { type: String, default: '' },
    avatarUrl: { type: String, default: '' },
  },
  linkedHospitals: [{
    hospitalId:   { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
    hospitalName: { type: String, default: '' },
    status:       { type: String, enum: ['PENDING','APPROVED','REJECTED'], default: 'PENDING', index: true },
    requestedAt:  { type: Date },
    linkedAt:     { type: Date }
  }],
}, { timestamps: true });

const hospitalUserSchema = new mongoose.Schema({
  email:        { type: String, required: true, unique: true, index: true },
  passwordHash: { type: String, required: true },
  name:         { type: String, default: '' },
  role:         { type: String, enum: ['HOSPITAL_ADMIN'], default: 'HOSPITAL_ADMIN', index: true },
  hospitalName: { type: String, default: '' },
  hospitalProfile: {
    photoUrl: { type: String, default: '' },
    intro:    { type: String, default: '' },
    address:  { type: String, default: '' },
    hours:    { type: String, default: '' },
    phone:    { type: String, default: '' },
  },
  approveStatus: { type: String, enum: ['PENDING','APPROVED','REJECTED'], default: 'PENDING', index: true },
}, { timestamps: true });

const hospitalLinkRequestSchema = new mongoose.Schema({
  userId:       { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  userName:     { type: String, default: '' },
  petName:      { type: String, default: '' },
  hospitalId:   { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  hospitalName: { type: String, default: '' },
  status:       { type: String, enum: ['PENDING','APPROVED','REJECTED'], default: 'PENDING', index: true },
  createdAt:    { type: Date, default: Date.now, index: true },
  decidedAt:    { type: Date, default: null }
});

const hospitalMetaSchema = new mongoose.Schema({
  hospitalId:   { type: mongoose.Schema.Types.ObjectId, required: true, unique: true, index: true },
  hospitalName: { type: String, default: '' },
  notice:       { type: String, default: '' },
  services:     [{ type: String }],
  doctors:      [{ id: String, name: String }],
}, { timestamps: true });

const appointmentSchema = new mongoose.Schema({
  hospitalId:   { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  hospitalName: { type: String, default: '' },
  userId:       { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  userName:     { type: String, default: '' },
  petName:      { type: String, default: '' },
  service:      { type: String, default: '' },
  doctorName:   { type: String, default: '' },
  date:         { type: String, default: '' },
  time:         { type: String, default: '' },
  visitDateTime:{ type: Date, index: true },
  status:       { type: String, enum: ['PENDING','APPROVED','REJECTED','CANCELED'], default: 'PENDING', index: true },
  createdAt:    { type: Date, default: Date.now, index: true },
  decidedAt:    { type: Date, default: null },
  decidedBy:    { type: mongoose.Schema.Types.ObjectId, default: null },
}, { timestamps: true });

const medicalHistorySchema = new mongoose.Schema({
  hospitalId:   { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  hospitalName: { type: String, default: '' },
  userId:       { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  userName:     { type: String, default: '' },
  petName:      { type: String, default: '' },
  date:         { type: Date, required: true, index: true },
  category:     { type: String, default: '' },
  content:      { type: String, default: '' },
  prescription: { type: String, default: '' },
  howToTake:    { type: String, default: '' },
  cost:         { type: String, default: '' },
}, { timestamps: true });

const userAppointmentSchema = new mongoose.Schema({
  userId:             { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  originAppointmentId:{ type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  hospitalId:         { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  hospitalName:       { type: String, default: '' },
  userName:           { type: String, default: '' },
  petName:            { type: String, default: '' },
  service:            { type: String, default: '' },
  doctorName:         { type: String, default: '' },
  date:               { type: String, default: '' },    // YYYY-MM-DD
  time:               { type: String, default: '' },    // HH:mm
  visitDateTime:      { type: Date, index: true },
  status:             { type: String, default: 'PENDING', index: true },
}, { timestamps: true });

const petCareSchema = new mongoose.Schema({
  hospitalId:   { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  hospitalName: { type: String, default: '' },
  createdBy:    { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  date:         { type: String, default: '' },  // 'YYYY-MM-DD'
  time:         { type: String, default: '' },  // 'HH:mm'
  dateTime:     { type: Date,   index: true },
  memo:         { type: String, default: '' },
  images:       [{ type: String }],
}, { timestamps: true });

const sosLogSchema = new mongoose.Schema({
  hospitalId:   { type: mongoose.Schema.Types.ObjectId, index: true },
  hospitalName: { type: String, default: '' },
  userId:       { type: mongoose.Schema.Types.ObjectId, index: true },
  userName:     { type: String, default: '' },
  petName:      { type: String, default: '' },
  message:      { type: String, default: '' },
}, { timestamps: true });

// ─────────────── 알림 스키마 ───────────────
const notificationSchema = new mongoose.Schema({
  userId:       { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  hospitalId:   { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  hospitalName: { type: String, default: '' },

  // 유형: APPOINTMENT_APPROVED, APPOINTMENT_REJECTED, PET_CARE_POSTED,
  //       MEDICAL_HISTORY_ADDED, SOS_ALERT, SYSTEM 등
  type:         { type: String, default: 'SYSTEM', index: true },
  title:        { type: String, default: '' },
  message:      { type: String, default: '' },

  read:         { type: Boolean, default: false, index: true },
  meta:         { type: mongoose.Schema.Types.Mixed, default: {} }, // 필요하면 상세정보

  createdAt:    { type: Date, default: Date.now, index: true },
}, { versionKey: false });

// ─────────────── 모델 등록 ───────────────
const User                = userConn.model('User', userSchema, 'users');
const HospitalUser        = hospitalConn.model('HospitalUser', hospitalUserSchema, 'hospital_user');
const HospitalLinkRequest = hospitalConn.model('HospitalLinkRequest', hospitalLinkRequestSchema, 'hospital_link_requests');
const HospitalMeta        = hospitalConn.model('HospitalMeta', hospitalMetaSchema, 'hospital_meta');
const Appointment         = hospitalConn.model('Appointment', appointmentSchema, 'appointments');
const MedicalHistory      = hospitalConn.model('MedicalHistory', medicalHistorySchema, 'medical_histories');
const UserAppointment     = userConn.model('UserAppointment', userAppointmentSchema, 'user_appointments');
const PetCare             = hospitalConn.model('PetCare', petCareSchema, 'pet_care');
const SosLog = hospitalConn.model('SosLog', sosLogSchema, 'sos_logs');
const Notification = userConn.model('Notification', notificationSchema, 'notifications');



// ─────────────── 헬스 & 루트 ───────────────
app.get('/health', (_req, res) => res.json({ ok: true, ts: Date.now() }));
app.get('/', (_req, res) => res.json({ message: '🚀 Animal API running', env: process.env.NODE_ENV || 'dev' }));

// ─────────────── 전역 아이디 중복 확인 ───────────────
app.get('/auth/check-id', async (req, res) => {
  try {
    const key = (req.query.email || req.query.username || req.query.key || '').toString().trim();
    if (!key) return res.status(400).json({ message: 'email/username required' });
    const [u, h] = await Promise.all([User.exists({ email: key }), HospitalUser.exists({ email: key })]);
    res.json({ available: !(u || h) });
  } catch (e) { console.error('check-id error:', e); res.status(500).json({ message: 'server error' }); }
});

// ─────────────── 회원가입/로그인 ───────────────
app.post('/auth/signup', authLimiter, async (req, res) => {
  try {
    const { email, username, password, name, birthDate } = req.body || {};
    const finalEmail = (email || username || '').trim();
    if (!finalEmail || !password) return res.status(400).json({ message: 'email/password required' });
    const existsAnywhere = await Promise.all([User.findOne({ email: finalEmail }), HospitalUser.findOne({ email: finalEmail })]);
    if (existsAnywhere[0] || existsAnywhere[1]) return res.status(409).json({ message: 'email already used' });
    const passwordHash = await bcrypt.hash(password, 12);
    const user = await User.create({ email: finalEmail, passwordHash, name: name || '', birthDate: (birthDate || '').trim(), role: 'USER' });
    res.status(201).json({
      token: issueToken(user),
      user: { id: user._id, email: user.email, name: user.name, role: user.role, birthDate: user.birthDate },
    });
  } catch (e) { console.error(e); res.status(500).json({ message: 'server error' }); }
});

app.post('/auth/signup-with-invite', authLimiter, async (req, res) => {
  try {
    const { email, password, name, inviteCode } = req.body || {};
    if (!email || !password || !inviteCode) return res.status(400).json({ message: 'missing fields' });
    const codes = (process.env.INVITE_ADMIN_CODES || '').split(',').map(s => s.trim()).filter(Boolean);
    if (!codes.includes(inviteCode)) return res.status(400).json({ message: 'invalid invite code' });
    const existsAnywhere = await Promise.all([HospitalUser.findOne({ email }), User.findOne({ email })]);
    if (existsAnywhere[0] || existsAnywhere[1]) return res.status(409).json({ message: 'email already used' });
    const passwordHash = await bcrypt.hash(password, 12);
    const admin = await HospitalUser.create({ email, passwordHash, name: name || '', role: 'HOSPITAL_ADMIN', hospitalName: '' });
    res.status(201).json({
      token: issueToken(admin),
      user: {
        id: admin._id, email: admin.email, name: admin.name, role: admin.role,
        hospitalName: admin.hospitalName, hospitalProfile: admin.hospitalProfile, approveStatus: admin.approveStatus,
      },
    });
  } catch (e) { console.error(e); res.status(500).json({ message: 'server error' }); }
});

app.post('/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ message: 'email/password required' });
    let doc = await HospitalUser.findOne({ email });
    if (doc) {
      const ok = await bcrypt.compare(password, doc.passwordHash);
      if (!ok) return res.status(401).json({ message: 'invalid credentials' });
      return res.json({
        token: issueToken(doc),
        user: {
          id: doc._id, email: doc.email, name: doc.name, role: doc.role,
          hospitalName: doc.hospitalName, hospitalProfile: doc.hospitalProfile, approveStatus: doc.approveStatus,
        },
      });
    }
    doc = await User.findOne({ email });
    if (!doc) return res.status(401).json({ message: 'invalid credentials' });
    const ok = await bcrypt.compare(password, doc.passwordHash);
    if (!ok) return res.status(401).json({ message: 'invalid credentials' });
    return res.json({
      token: issueToken(doc),
      user: { id: doc._id, email: doc.email, name: doc.name, role: doc.role, birthDate: doc.birthDate, petProfile: doc.petProfile },
    });
  } catch (e) { console.error(e); res.status(500).json({ message: 'server error' }); }
});

// ─────────────── 프로필 ───────────────
app.get('/users/me', auth, onlyUser, async (req, res) => {
  const user = await User.findById(oid(req.jwt.uid)).lean();
  if (!user) return res.status(404).json({ message: 'not found' });
  delete user.passwordHash;
  res.json({ user, id: user._id, email: user.email, name: user.name, role: user.role, birthDate: user.birthDate, petProfile: user.petProfile });
});

app.get('/hospital/me', auth, onlyHospitalAdmin, async (req, res) => {
  const admin = await HospitalUser.findById(oid(req.jwt.uid)).lean();
  if (!admin) return res.status(404).json({ message: 'not found' });
  delete admin.passwordHash;
  res.json({ user: admin });
});

app.put('/users/me/pet', auth, onlyUser, async (req, res) => {
  try {
    const { name, age, gender, species, avatarUrl } = req.body || {};
    const update = {
      'petProfile.name': (name || '').trim(),
      'petProfile.age':  Number.isFinite(Number(age)) ? Number(age) : 0,
      'petProfile.gender': (gender || '').trim(),
      'petProfile.species': (species || '').trim(),
      'petProfile.avatarUrl': (avatarUrl || '').trim(),
    };
    const user = await User.findByIdAndUpdate(oid(req.jwt.uid), { $set: update }, { new: true, lean: true });
    if (!user) return res.status(404).json({ message: 'not found' });
    delete user.passwordHash;
    return res.json({ user });
  } catch (e) { console.error('PUT /users/me/pet error:', e); return res.status(500).json({ message: 'server error' }); }
});

app.put('/hospital/profile', auth, onlyHospitalAdmin, async (req, res) => {
  const { hospitalName, photoUrl, intro, address, hours, phone } = req.body || {};
  const update = {
    ...(typeof hospitalName === 'string' ? { hospitalName: hospitalName.trim() } : {}),
    'hospitalProfile.photoUrl': (photoUrl || '').trim(),
    'hospitalProfile.intro':    (intro || '').trim(),
    'hospitalProfile.address':  (address || '').trim(),
    'hospitalProfile.hours':    (hours || '').trim(),
    'hospitalProfile.phone':    (phone || '').trim(),
    approveStatus: 'PENDING',
  };
  const admin = await HospitalUser.findByIdAndUpdate(oid(req.jwt.uid), { $set: update }, { new: true, lean: true });
  if (!admin) return res.status(404).json({ message: 'not found' });
  delete admin.passwordHash;
  res.json({ user: admin });
});

// ─────────────── 병원 목록 ───────────────
app.get('/api/hospitals', async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
  const page  = Math.max(parseInt(req.query.page  || '1', 10), 1);
  const skip  = (page - 1) * limit;

  const [items, total] = await Promise.all([
    HospitalUser.find({}, { passwordHash: 0 }).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
    HospitalUser.countDocuments({}),
  ]);
  const data = items.map(h => ({
    _id: h._id,
    hospitalName: h.hospitalName || '',
    approveStatus: h.approveStatus || 'PENDING',
    imageUrl: h.hospitalProfile?.photoUrl || '',
    createdAt: h.createdAt,
  }));
  res.json({ data, paging: { total, page, limit } });
});

// ─────────────── 병원 연동 ───────────────
app.get('/api/hospital-links/available', auth, onlyUser, async (req, res) => {
  const [hospitals, me] = await Promise.all([
    HospitalUser.find({}, { passwordHash: 0 }).sort({ createdAt: -1 }).lean(),
    User.findById(oid(req.jwt.uid), { linkedHospitals: 1 }).lean(),
  ]);
  const statusMap = new Map();
  (me?.linkedHospitals || []).forEach(x => statusMap.set(String(x.hospitalId), x.status));
  const data = hospitals.map(h => ({
    hospitalId: String(h._id),
    hospitalName: h.hospitalName || '',
    myStatus: statusMap.get(String(h._id)) || 'NONE',
    imageUrl: h.hospitalProfile?.photoUrl || '',
    createdAt: h.createdAt,
  }));
  res.json({ data });
});

async function upsertUserLink(userId, hospital) {
  const user = await User.findById(oid(userId));
  if (!user) throw new Error('user not found');
  const has = (user.linkedHospitals || []).find(h => String(h.hospitalId) === String(hospital._id));
  if (has) {
    has.status = 'PENDING';
    has.requestedAt = new Date();
  } else {
    user.linkedHospitals.push({
      hospitalId: hospital._id,
      hospitalName: hospital.hospitalName || '',
      status: 'PENDING',
      requestedAt: new Date(),
    });
  }
  await user.save();

  const existing = await HospitalLinkRequest.findOne({
    userId: oid(userId), hospitalId: oid(hospital._id), status: 'PENDING',
  });
  if (!existing) {
    await HospitalLinkRequest.create({
      userId: oid(userId),
      userName: user.name || '',
      petName: user.petProfile?.name || '',
      hospitalId: hospital._id,
      hospitalName: hospital.hospitalName || '',
    });
  }
}
app.post('/api/hospital-links/request', auth, onlyUser, async (req, res) => {
  try {
    const { hospitalId } = req.body || {};
    if (!hospitalId) return res.status(400).json({ message: 'hospitalId required' });
    const hospital = await HospitalUser.findById(oid(hospitalId)).lean();
    if (!hospital) return res.status(404).json({ message: 'hospital not found' });
    await upsertUserLink(req.jwt.uid, hospital);
    res.json({ ok: true });
  } catch (e) { console.error('request link error:', e); res.status(500).json({ message: 'server error' }); }
});
app.post('/api/hospitals/:id/connect', auth, onlyUser, async (req, res) => {
  try {
    const hospital = await HospitalUser.findById(oid(req.params.id)).lean();
    if (!hospital) return res.status(404).json({ message: 'hospital not found' });
    await upsertUserLink(req.jwt.uid, hospital);
    res.json({ ok: true });
  } catch (e) { console.error('compat connect error:', e); res.status(500).json({ message: 'server error' }); }
});

// ─────────────── 병원관리자: 요청/승인/거절 ───────────────
app.get('/api/hospital-admin/requests', auth, onlyHospitalAdmin, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
  const page  = Math.max(parseInt(req.query.page  || '1', 10), 1);
  const skip  = (page - 1) * limit;

  const q = { hospitalId: oid(req.jwt.uid), status: 'PENDING' };
  const [items, total] = await Promise.all([
    HospitalLinkRequest.find(q).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
    HospitalLinkRequest.countDocuments(q),
  ]);
  res.json({ data: items, paging: { total, page, limit } });
});

app.post('/api/hospital-admin/requests/:id/approve', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const r = await HospitalLinkRequest.findById(oid(req.params.id));
    if (!r) return res.status(404).json({ message: 'not found' });
    if (String(r.hospitalId) !== String(req.jwt.uid)) return res.status(403).json({ message: 'forbidden' });
    r.status = 'APPROVED';
    r.decidedAt = new Date();
    await r.save();
    await User.updateOne(
      { _id: r.userId, 'linkedHospitals.hospitalId': r.hospitalId },
      { $set: { 'linkedHospitals.$.status': 'APPROVED', 'linkedHospitals.$.linkedAt': new Date() } }
    );
    res.json({ ok: true });
  } catch (e) { console.error('approve error:', e); res.status(500).json({ message: 'server error' }); }
});

app.post('/api/hospital-admin/requests/:id/reject', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const r = await HospitalLinkRequest.findById(oid(req.params.id));
    if (!r) return res.status(404).json({ message: 'not found' });
    if (String(r.hospitalId) !== String(req.jwt.uid)) return res.status(403).json({ message: 'forbidden' });
    r.status = 'REJECTED';
    r.decidedAt = new Date();
    await r.save();
    await User.updateOne(
      { _id: r.userId, 'linkedHospitals.hospitalId': r.hospitalId },
      { $set: { 'linkedHospitals.$.status': 'REJECTED' } }
    );
    res.json({ ok: true });
  } catch (e) { console.error('reject error:', e); res.status(500).json({ message: 'server error' }); }
});

// ─────────────── 병원관리자: 연동된 사용자 목록 (SOS용) ───────────────
app.get('/api/hospital-admin/linked-users', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const hid = oid(req.jwt.uid);

    // linkedHospitals 중 status=APPROVED 인 사용자만
    const users = await User.find({
      linkedHospitals: { $elemMatch: { hospitalId: hid, status: 'APPROVED' } },
    })
      .select('email name birthDate petProfile')
      .lean();

    const list = users.map(u => ({
      _id: u._id,
      email: u.email,
      userName: u.name || '',
      birthDate: u.birthDate || '',
      petProfile: u.petProfile || {},
    }));

    res.json(list);
  } catch (e) {
    console.error('GET /api/hospital-admin/linked-users error:', e);
    res.status(500).json({ message: 'server error' });
  }
});


// ─────────────── 병원관리자: 환자/진료내역 ───────────────
app.get('/api/hospital-admin/patients', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit || '200', 10), 500);
    const page  = Math.max(parseInt(req.query.page  || '1', 10), 1);
    const skip  = (page - 1) * limit;

    const pipeline = [
      { $unwind: '$linkedHospitals' },
      { $match: { 'linkedHospitals.hospitalId': oid(req.jwt.uid), 'linkedHospitals.status': 'APPROVED' } },
      { $project: { _id: 0, userId: '$_id', userName: '$name', petName: '$petProfile.name' } },
      { $skip: skip },
      { $limit: limit },
    ];
    const [items, totalAgg] = await Promise.all([
      User.aggregate(pipeline),
      User.aggregate([
        { $unwind: '$linkedHospitals' },
        { $match: { 'linkedHospitals.hospitalId': oid(req.jwt.uid), 'linkedHospitals.status': 'APPROVED' } },
        { $count: 'total' },
      ]),
    ]);
    const total = totalAgg[0]?.total || 0;
    res.json({ data: items, paging: { total, page, limit } });
  } catch (e) { console.error('GET /api/hospital-admin/patients error:', e); res.status(500).json({ message: 'server error' }); }
});

app.get('/api/hospital-admin/medical-histories', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) return res.status(400).json({ message: 'userId is required' });

    const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
    const page  = Math.max(parseInt(req.query.page  || '1', 10), 1);
    const skip  = (page - 1) * limit;

    const hid  = oid(req.query.hospitalId || req.jwt.uid);
    const list = await MedicalHistory.find({ userId: oid(userId), hospitalId: hid })
      .sort({ date: -1, createdAt: -1 })
      .skip(skip).limit(limit).lean();
    const total = await MedicalHistory.countDocuments({ userId: oid(userId), hospitalId: hid });
    const data  = list.map(m => ({ ...m, id: m._id }));
    return res.json({ data, paging: { total, page, limit } });
  } catch (e) { console.error('GET histories error:', e); return res.status(500).json({ message: 'server error' }); }
});

app.post('/api/hospital-admin/medical-histories', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const { userId, hospitalId, date, content, prescription, howToTake, cost, petName, userName, category, hospitalName } = req.body || {};
    if (!userId || !date) return res.status(400).json({ message: 'userId and date are required' });
    const hid = oid(hospitalId || req.jwt.uid);
    let hName = (hospitalName || '').trim();
    if (!hName) {
      const h = await HospitalUser.findById(hid).lean();
      hName = h?.hospitalName || '';
    }
    const doc = await MedicalHistory.create({
      userId: oid(userId),
      hospitalId: hid,
      hospitalName: hName,
      userName: (userName || '').trim(),
      petName: (petName || '').trim(),
      date: new Date(date),
      category: (category || '').trim(),
      content: (content || '').trim(),
      prescription: (prescription || '').trim(),
      howToTake: (howToTake || '').trim(),
      cost: (cost || '').trim(),
    });

    await pushNotificationOne({
      userId: userId,
      hospitalId: hid,
      hospitalName: hName,
      type: 'MEDICAL_HISTORY_ADDED',
      title: '새 진료 내역 등록',
      message: `${(category || '진료')} · ${new Date(date).toLocaleDateString()}`,
      meta: { medicalHistoryId: doc._id }
    });

    const created = doc.toJSON();
    return res.status(201).json({ data: { ...created, id: created._id } });
  } catch (e) { console.error('POST histories error:', e); return res.status(500).json({ message: 'server error' }); }
});

// ─────────────── 사용자: 병원 목록/예약/케어일지 ───────────────
app.get('/api/users/me/hospitals', auth, onlyUser, async (req, res) => {
  const user = await User.findById(oid(req.jwt.uid)).lean();
  if (!user) return res.status(404).json({ message: 'not found' });
  let list = user.linkedHospitals || [];
  if (!req.query.all) list = list.filter(h => h.status === 'APPROVED');
  list.sort((a, b) => {
    const aa = a.linkedAt || a.requestedAt || new Date(0);
    const bb = b.linkedAt || b.requestedAt || new Date(0);
    return new Date(bb) - new Date(aa);
  });
  const data = list.map(x => ({
    hospitalId: String(x.hospitalId ?? ''),
    hospitalName: x.hospitalName || '',
    linkedAt: x.linkedAt || x.requestedAt || user.updatedAt,
  }));
  return res.json({ data });
});

// ─────────────── 병원관리자: 케어일지 목록/등록 ───────────────
app.get('/api/hospital-admin/pet-care', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const keyword = (req.query.keyword || '').toString().trim();
    const sortKey = (req.query.sort || 'dateDesc').toString();
    const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
    const page  = Math.max(parseInt(req.query.page  || '1', 10), 1);
    const skip  = (page - 1) * limit;

    const q = { hospitalId: oid(req.jwt.uid) };
    if (keyword) {
      const rx = new RegExp(keyword, 'i');
      q.$or = [{ memo: rx }];
    }
    const sort = sortKey === 'dateAsc' ? 1 : -1;

    const [items, total] = await Promise.all([
      PetCare.find(q).sort({ dateTime: sort, createdAt: sort }).skip(skip).limit(limit).lean(),
      PetCare.countDocuments(q),
    ]);
    const data = items.map(d => ({
      _id: d._id,
      date: d.date || '',
      time: d.time || '',
      dateTime: d.dateTime,
      memo: d.memo || '',
      imageUrl: (d.images && d.images.length) ? d.images[0] : '',
      images: d.images || [],
    }));
    return res.json({ data, paging: { total, page, limit } });
  } catch (e) { console.error('GET pet-care error:', e); return res.status(500).json({ message: 'server error' }); }
});

app.post('/api/hospital-admin/pet-care', auth, onlyHospitalAdmin, uploadLimiter, upload.array('images', 10), async (req, res) => {
  try {
    const admin = await HospitalUser.findById(oid(req.jwt.uid)).lean();
    if (!admin) return res.status(404).json({ message: 'hospital not found' });
    const date = (req.body.date || '').toString().trim();
    const time = (req.body.time || '').toString().trim();
    const memo = (req.body.memo || '').toString().trim();
    if (!date || !time) return res.status(400).json({ message: 'date/time required' });

    const urls = (req.files || []).map(f => publicUrl(req, `/uploads/pet-care/${path.basename(f.path)}`));

    // 서울 타임존을 고려한 날짜 파싱은 클라이언트에서 ISO로 보내는 것이 제일 안전
    const dt = new Date(`${date}T${time}:00`);
    const doc = await PetCare.create({
      hospitalId: oid(req.jwt.uid),
      hospitalName: admin.hospitalName || '',
      createdBy: oid(req.jwt.uid),
      date, time, dateTime: isNaN(dt.getTime()) ? new Date() : dt,
      memo,
      images: urls,
    });
    const created = doc.toJSON();

    // 이 병원과 연동(APPROVED)된 모든 사용자에게 알림
    const approvedUsers = await User.find({
      linkedHospitals: { $elemMatch: { hospitalId: oid(req.jwt.uid), status: 'APPROVED' } }
    }).select('_id').lean();

    await pushNotificationMany({
      userIds: approvedUsers.map(u => u._id),
      hospitalId: oid(req.jwt.uid),
      hospitalName: admin.hospitalName || '',
      type: 'PET_CARE_POSTED',
      title: '새 반려 일지가 올라왔어요',
      message: memo ? memo.slice(0, 80) : '이미지/메모가 등록되었습니다.',
      meta: { petCareId: doc._id, imageUrl: urls[0] || '' }
    });

    return res.status(201).json({
      data: {
        _id: created._id,
        date: created.date,
        time: created.time,
        dateTime: created.dateTime,
        memo: created.memo,
        imageUrl: (created.images && created.images.length) ? created.images[0] : '',
        images: created.images || [],
      }
    });
  } catch (e) {
    console.error('POST pet-care error:', e);
    return res.status(500).json({ message: e?.message || 'server error' });
  }
});

// ─────────────── 예약 메타/신청 ───────────────
app.get('/api/hospitals/:hospitalId/appointment-meta', async (req, res) => {
  const { hospitalId } = req.params;
  const meta = await HospitalMeta.findOne({ hospitalId: oid(hospitalId) }).lean();
  const servicesDefault = ['일반진료','건강검진','종합백신','심장사상충','치석제거'];
  const doctorsDefault  = [{ id: 'default', name: '김철수 원장' }];
  if (!meta) {
    const h = await HospitalUser.findById(oid(hospitalId)).lean();
    return res.json({
      hospitalId,
      hospitalName: h?.hospitalName || '',
      notice: '',
      services: servicesDefault,
      doctors: doctorsDefault
    });
  }
  res.json({
    hospitalId,
    hospitalName: meta.hospitalName || '',
    notice: meta.notice || '',
    services: (meta.services && meta.services.length) ? meta.services : servicesDefault,
    doctors:  (meta.doctors && meta.doctors.length)   ? meta.doctors  : doctorsDefault
  });
});

app.put('/api/hospitals/:hospitalId/appointment-meta', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    if (String(req.params.hospitalId) !== String(req.jwt.uid)) return res.status(403).json({ message: 'forbidden' });
    const { services, doctors, notice } = req.body || {};
    const h = await HospitalUser.findById(oid(req.jwt.uid)).lean();
    const doc = await HospitalMeta.findOneAndUpdate(
      { hospitalId: oid(req.jwt.uid) },
      {
        $set: {
          hospitalId: oid(req.jwt.uid),
          hospitalName: h?.hospitalName || '',
          notice: (notice || '').toString(),
          services: Array.isArray(services) ? services : undefined,
          doctors:  Array.isArray(doctors)  ? doctors  : undefined,
        }
      },
      { new: true, upsert: true }
    ).lean();
    res.json({ ok: true, meta: doc });
  } catch (e) { console.error('PUT meta error:', e); res.status(500).json({ message: 'server error' }); }
});

app.post('/api/hospitals/:hospitalId/appointments/request', auth, onlyUser, async (req, res) => {
  try {
    const { hospitalId } = req.params;
    const { hospitalName, service, doctorName, date, time, visitDateTime, userName, petName } = req.body || {};
    if (!service || !doctorName || !date || !time) return res.status(400).json({ message: 'missing fields' });

    const me = await User.findById(oid(req.jwt.uid)).lean();
    const link = (me?.linkedHospitals || []).find(h => String(h.hospitalId) === String(hospitalId));
    if (!link || link.status !== 'APPROVED') return res.status(403).json({ message: 'link to hospital required (APPROVED)' });

    const h = await HospitalUser.findById(oid(hospitalId)).lean();
    if (!h) return res.status(404).json({ message: 'hospital not found' });

    const vdt = visitDateTime ? new Date(visitDateTime) : new Date(`${date}T${time}:00`);
    const cleanedUserName = (userName || '').trim();
    const finalUserName = cleanedUserName && cleanedUserName !== '사용자' ? cleanedUserName : (me?.name || '');
    const cleanedPetName = (petName || '').trim();
    const finalPetName = cleanedPetName && cleanedPetName !== '(미입력)' ? cleanedPetName : (me?.petProfile?.name || '');

    const appt = await Appointment.create({
      hospitalId: oid(hospitalId),
      hospitalName: hospitalName || h.hospitalName || '',
      userId: oid(req.jwt.uid),
      userName: finalUserName,
      petName:  finalPetName,
      service, doctorName, date, time,
      visitDateTime: vdt,
      status: 'PENDING'
    });

    await UserAppointment.create({
      userId: oid(req.jwt.uid),
      originAppointmentId: appt._id,
      hospitalId: oid(hospitalId),
      hospitalName: hospitalName || h.hospitalName || '',
      userName: finalUserName,
      petName:  finalPetName,
      service, doctorName, date, time,
      visitDateTime: vdt,
      status: 'PENDING'
    });

    res.status(201).json({ ok: true, appointmentId: appt._id });
  } catch (e) { console.error('appointment request error:', e); res.status(500).json({ message: 'server error' }); }
});

// ─────────────── 사용자 예약 조회/삭제/월간 ───────────────
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
        q.visitDateTime = { $gte: start, $lt: end };
      }
    }

    const limit = Math.min(parseInt(req.query.limit || '100', 10), 300);
    const page  = Math.max(parseInt(req.query.page  || '1', 10), 1);
    const skip  = (page - 1) * limit;

    let list = await UserAppointment.find(q).sort({ visitDateTime: 1 }).skip(skip).limit(limit).lean();
    const total = await UserAppointment.countDocuments(q);

    list = list.map(a => ({ ...a, userName: a.userName || me?.name || '', petName: a.petName || me?.petProfile?.name || '' }));

    // 과거 호환
    if (!list.length) {
      const hospitalList = await Appointment.find({ userId: oid(req.jwt.uid) }).sort({ visitDateTime: 1 }).skip(skip).limit(limit).lean();
      const mapped = hospitalList.map(a => ({
        userId: a.userId, hospitalId: a.hospitalId, hospitalName: a.hospitalName,
        userName: a.userName || me?.name || '', petName: a.petName || me?.petProfile?.name || '',
        service: a.service, doctorName: a.doctorName, date: a.date, time: a.time,
        visitDateTime: a.visitDateTime, status: a.status,
      }));
      return res.json({ data: mapped, paging: { total: await Appointment.countDocuments({ userId: oid(req.jwt.uid) }), page, limit } });
    }

    res.json({ data: list, paging: { total, page, limit } });
  } catch (e) { console.error('get user appointments error:', e); res.status(500).json({ message: 'server error' }); }
});

app.delete('/api/users/me/appointments/:id', auth, onlyUser, async (req, res) => {
  try {
    const ua = await UserAppointment.findOne({ _id: oid(req.params.id), userId: oid(req.jwt.uid) });
    if (!ua) return res.status(404).json({ message: 'not found' });
    await UserAppointment.deleteOne({ _id: ua._id });
    await Appointment.deleteOne({ _id: ua.originAppointmentId, userId: oid(req.jwt.uid) });
    return res.status(204).send();
  } catch (e) { console.error('delete my appt error:', e); return res.status(500).json({ message: 'server error' }); }
});

app.get('/api/users/me/appointments/monthly', auth, onlyUser, async (req, res) => {
  try {
    const { hospitalId, month } = req.query;
    if (!month) return res.status(400).json({ message: 'month required (YYYY-MM)' });
    const [yy, mm] = String(month).split('-').map(Number);
    if (!yy || !mm) return res.status(400).json({ message: 'invalid month' });
    const q = { userId: oid(req.jwt.uid) };
    if (hospitalId) q.hospitalId = oid(hospitalId);
    const start = new Date(yy, mm - 1, 1, 0, 0, 0);
    const end   = new Date(yy, mm, 1, 0, 0, 0);
    q.visitDateTime = { $gte: start, $lt: end };
    const list = await UserAppointment.find(q).sort({ visitDateTime: 1 }).lean();
    res.json(list);
  } catch (e) { console.error('monthly user appts error:', e); res.status(500).json({ message: 'server error' }); }
});

// ─────────────── 사용자: 케어일지 보기 ───────────────
app.get('/api/users/me/pet-care', auth, onlyUser, async (req, res) => {
  try {
    const { hospitalId, keyword = '', sort = 'dateDesc' } = req.query;
    if (!hospitalId) return res.status(400).json({ message: 'hospitalId required' });

    const me = await User.findById(oid(req.jwt.uid), { linkedHospitals: 1 }).lean();
    const link = (me?.linkedHospitals || []).find(h => String(h.hospitalId) === String(hospitalId) && h.status === 'APPROVED');
    if (!link) return res.status(403).json({ message: 'link to hospital required (APPROVED)' });

    const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
    const page  = Math.max(parseInt(req.query.page  || '1', 10), 1);
    const skip  = (page - 1) * limit;

    const q = { hospitalId: oid(hospitalId) };
    if (String(keyword).trim()) {
      const rx = new RegExp(String(keyword).trim(), 'i');
      q.$or = [{ memo: rx }];
    }
    const s = sort === 'dateAsc' ? 1 : -1;

    const [items, total] = await Promise.all([
      PetCare.find(q).sort({ dateTime: s, createdAt: s }).skip(skip).limit(limit).lean(),
      PetCare.countDocuments(q),
    ]);

    const data = items.map(d => ({
      _id: d._id, date: d.date || '', time: d.time || '', dateTime: d.dateTime, memo: d.memo || '',
      imageUrl: (d.images && d.images.length) ? d.images[0] : '', images: d.images || [],
    }));
    res.json({ data, paging: { total, page, limit } });
  } catch (e) { console.error('GET /api/users/me/pet-care error:', e); res.status(500).json({ message: 'server error' }); }
});

// ─────────────── 병원관리자: 예약함/승인/거절 ───────────────
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
    Appointment.find(q).sort({ createdAt: sort }).skip(skip).limit(limit).lean(),
    Appointment.countDocuments(q),
  ]);
  res.json({ data: items, paging: { total, page, limit } });
});

app.post('/api/hospital-admin/appointments/:id/approve', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const appt = await Appointment.findById(oid(req.params.id));
    if (!appt) return res.status(404).json({ message: 'not found' });
    if (String(appt.hospitalId) !== String(req.jwt.uid)) return res.status(403).json({ message: 'forbidden' });
    if (appt.status !== 'PENDING') return res.status(409).json({ message: 'already decided' });
    appt.status = 'APPROVED';
    appt.decidedAt = new Date();
    appt.decidedBy = oid(req.jwt.uid);
    await appt.save();
    await UserAppointment.updateOne({ originAppointmentId: appt._id }, { $set: { status: 'APPROVED' } });

// ✅ pushNotificationOne 추가 (return 전에)
await pushNotificationOne({
  userId: appt.userId,
  hospitalId: appt.hospitalId,
  hospitalName: appt.hospitalName || '',
  type: 'APPOINTMENT_APPROVED',
  title: '진료 예약 승인',
  message: `${appt.date} ${appt.time} · ${appt.service} (${appt.doctorName || '담당의'})`,
  meta: { appointmentId: appt._id }
});

    res.json({ ok: true });
  } catch (e) { console.error('approve appt error:', e); res.status(500).json({ message: 'server error' }); }
});

app.post('/api/hospital-admin/appointments/:id/reject', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const appt = await Appointment.findById(oid(req.params.id));
    if (!appt) return res.status(404).json({ message: 'not found' });
    if (String(appt.hospitalId) !== String(req.jwt.uid)) return res.status(403).json({ message: 'forbidden' });
    if (appt.status !== 'PENDING') return res.status(409).json({ message: 'already decided' });
    appt.status = 'REJECTED';
    appt.decidedAt = new Date();
    appt.decidedBy = oid(req.jwt.uid);
    await appt.save();
    await UserAppointment.updateOne({ originAppointmentId: appt._id }, { $set: { status: 'REJECTED' } });
// 거절 처리 부분도 동일하게 res.json 전에
await pushNotificationOne({
  userId: appt.userId,
  hospitalId: appt.hospitalId,
  hospitalName: appt.hospitalName || '',
  type: 'APPOINTMENT_REJECTED',
  title: '진료 예약 거절',
  message: `${appt.date} ${appt.time} · ${appt.service}`,
  meta: { appointmentId: appt._id }
});


    res.json({ ok: true });
  } catch (e) { console.error('reject appt error:', e); res.status(500).json({ message: 'server error' }); }
});

// ─────────────── 사용자: 내 진료내역 ───────────────
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
      if (!yy || !mm) return res.status(400).json({ message: 'invalid month' });
      const start = new Date(yy, mm - 1, 1, 0, 0, 0);
      const end   = new Date(yy, mm,     1, 0, 0, 0);
      find.date = { $gte: start, $lt: end };
    }
    if (q && String(q).trim()) {
      const rx = new RegExp(String(q).trim(), 'i');
      find.$or = [
        { category: rx }, { content: rx }, { prescription: rx },
        { howToTake: rx }, { hospitalName: rx }, { cost: rx },
      ];
    }
    const [items, total] = await Promise.all([
      MedicalHistory.find(find).sort({ date: -1, createdAt: -1 }).skip(skip).limit(limit).lean(),
      MedicalHistory.countDocuments(find),
    ]);
    const data = items.map(m => ({ ...m, id: m._id }));
    return res.json({ data, paging: { total, page, limit } });
  } catch (e) { console.error('GET /api/users/me/medical-histories error:', e); return res.status(500).json({ message: 'server error' }); }
});

// SOS 전송(로그 저장; 추후 문자/푸시 연동 지점)
app.post('/api/hospital-admin/sos', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const { userId, hospitalId, message } = req.body || {};
    if (!userId) return res.status(400).json({ message: 'userId required' });

    const user = await User.findById(oid(userId)).lean();
    if (!user) return res.status(404).json({ message: 'user not found' });

    // 병원 ID/이름 확정
    const hid = oid(hospitalId || req.jwt.uid);
    let hospitalName = '';
    const approved = (user.linkedHospitals || []).find(h =>
      String(h.hospitalId) === String(hid) && h.status === 'APPROVED'
    );
    if (approved) hospitalName = approved.hospitalName || '';

    const log = await SosLog.create({
      hospitalId: hid,
      hospitalName,
      userId: user._id,
      userName: user.name || '',
      petName: user.petProfile?.name || '',
      message: (message || '').toString(),
    });

await pushNotificationOne({
  userId: user._id,
  hospitalId: hid,
  hospitalName,
  type: 'SOS_ALERT',
  title: '병원 긴급 알림',
  message: (message || '').toString(),
  meta: { sosId: log._id }
});


    // TODO: 문자/알림 연동 (Twilio/알리고/FCM 등)
    return res.status(201).json({ ok: true, id: log._id });
  } catch (e) {
    console.error('POST /api/hospital-admin/sos error:', e);
    return res.status(500).json({ message: 'server error' });
  }
});

app.get('/api/hospital-admin/profile', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const admin = await HospitalUser.findById(oid(req.jwt.uid)).lean();
    if (!admin) return res.status(404).json({ message: 'not found' });
    return res.json({ data: hospitalAdminProfileDto(admin) });
  } catch (e) {
    console.error('GET /api/hospital-admin/profile error:', e);
    return res.status(500).json({ message: 'server error' });
  }
});

// PATCH /api/hospital-admin/profile  → 마이페이지 우상단 편집 저장에서 사용
app.patch('/api/hospital-admin/profile', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    // Flutter가 보내는 바디: { name, intro } (name = 병원명)
    // 추가 호환: { hospitalName, photoUrl, address, hours, phone }
    const {
      name,
      hospitalName,
      intro,
      photoUrl,
      address,
      hours,
      phone,
    } = req.body || {};

    const update = {
      ...(typeof (hospitalName ?? name) === 'string'
        ? { hospitalName: (hospitalName ?? name).trim() }
        : {}),
      'hospitalProfile.photoUrl': typeof photoUrl === 'string' ? photoUrl.trim() : undefined,
      'hospitalProfile.intro':    typeof intro    === 'string' ? intro.trim()    : undefined,
      'hospitalProfile.address':  typeof address  === 'string' ? address.trim()  : undefined,
      'hospitalProfile.hours':    typeof hours    === 'string' ? hours.trim()    : undefined,
      'hospitalProfile.phone':    typeof phone    === 'string' ? phone.trim()    : undefined,
      // 프로필 변경 시 다시 승인 필요하도록 기존 로직 유지
      approveStatus: 'PENDING',
    };

    // undefined 값은 $unset 되지 않으므로, 정의된 키만 세팅
    Object.keys(update).forEach((k) => update[k] === undefined && delete update[k]);

    const admin = await HospitalUser.findByIdAndUpdate(
      oid(req.jwt.uid),// server.js
                       require('dotenv').config();
                       const path   = require('path');
                       const fs     = require('fs');
                       const multer = require('multer');

                       const express    = require('express');
                       const mongoose   = require('mongoose');
                       const cors       = require('cors');
                       const bcrypt     = require('bcrypt');
                       const jwt        = require('jsonwebtoken');
                       const helmet     = require('helmet');
                       const compression= require('compression');
                       const morgan     = require('morgan');
                       const rateLimit  = require('express-rate-limit');

                       const MONGODB_URI = process.env.MONGODB_URI;
                       const PORT        = process.env.PORT || 4000;
                       const JWT_SECRET  = process.env.JWT_SECRET;

                       // ─────────────── 환경변수 필수 체크 ───────────────
                       if (!MONGODB_URI) {
                         console.error('❌ MONGODB_URI is required');
                         process.exit(1);
                       }
                       if (!JWT_SECRET) {
                         console.error('❌ JWT_SECRET is required');
                         process.exit(1);
                       }

                       const app = express();

                       // 프록시 환경(Cloudflare, Nginx 등)에서 X-Forwarded-* 신뢰
                       app.set('trust proxy', 1);

                       // ─────────────── 보안/성능 미들웨어 ───────────────
                       app.use(helmet({
                         crossOriginResourcePolicy: { policy: 'cross-origin' },
                       }));
                       app.use(compression());
                       app.use(morgan('dev'));

                       // CORS: 화이트리스트 → 없으면 전체 허용(개발편의)
                       const allowOrigins = (process.env.CORS_ORIGINS || '')
                         .split(',')
                         .map(s => s.trim())
                         .filter(Boolean);
                       app.use(cors({
                         origin: (origin, cb) => {
                           if (!origin || allowOrigins.length === 0) return cb(null, true);
                           return cb(null, allowOrigins.includes(origin));
                         },
                         credentials: true,
                       }));
                       app.use(express.json({ limit: '2mb' }));

                       // ───────────────── 업로드 폴더 & 정적 서빙 ─────────────────
                       const UP_ROOT = path.join(__dirname, 'uploads');
                       const UP_DIR  = path.join(UP_ROOT, 'pet-care');
                       fs.mkdirSync(UP_DIR, { recursive: true });

                       // 정적 파일 캐시(1d) + 기본 보안 옵션
                       app.use('/uploads', express.static(UP_ROOT, {
                         setHeaders: (res) => {
                           res.setHeader('Cache-Control', 'public, max-age=86400');
                         },
                         fallthrough: true,
                         index: false,
                       }));

                       // ─────────────── Multer(업로드) 설정 ───────────────
                       const ALLOWED_EXTS  = new Set(['.jpg', '.jpeg', '.png', '.gif', '.webp']);
                       const ALLOWED_MIMES = new Set(['image/jpeg','image/png','image/gif','image/webp']);

                       const storage = multer.diskStorage({
                         destination: (_req, _file, cb) => cb(null, UP_DIR),
                         filename: (_req, file, cb) => {
                           const ext = (path.extname(file.originalname || '') || '').toLowerCase();
                           const safeExt = ALLOWED_EXTS.has(ext) ? ext : '';
                           cb(null, `${Date.now()}-${Math.round(Math.random()*1e9)}${safeExt}`);
                         }
                       });
                       const upload = multer({
                         storage,
                         limits: { fileSize: 10 * 1024 * 1024, files: 10 }, // 10MB, 최대 10장
                         fileFilter: (_req, file, cb) => {
                           if (!ALLOWED_MIMES.has(file.mimetype)) return cb(new Error('Invalid file type'));
                           cb(null, true);
                         }
                       });

                       // ─────────────── 레이트리밋(로그인/회원가입/업로드) ───────────────
                       const authLimiter = rateLimit({
                         windowMs: 10 * 60 * 1000, // 10분
                         max: 100,                  // 10분에 100회
                         standardHeaders: true,
                         legacyHeaders: false,
                       });
                       const uploadLimiter = rateLimit({
                         windowMs: 10 * 60 * 1000,
                         max: 60,
                         standardHeaders: true,
                         legacyHeaders: false,
                       });

                       // ─────────────── 공통 유틸 ───────────────
                       function issueToken(doc) {
                         return jwt.sign({ uid: doc._id, role: doc.role }, JWT_SECRET, { expiresIn: '7d' });
                       }

                       function buildBaseUrl(req) {
                         // PUBLIC_BASE_URL 우선, 없으면 프록시 헤더 고려
                         if (process.env.PUBLIC_BASE_URL) return process.env.PUBLIC_BASE_URL.replace(/\/+$/, '');
                         const proto = req.get('x-forwarded-proto') || req.protocol;
                         const host  = req.get('x-forwarded-host') || req.get('host');
                         return `${proto}://${host}`;
                       }

                       function publicUrl(req, relativePath) {
                         const base = buildBaseUrl(req);
                         return `${base}${relativePath.startsWith('/') ? '' : '/'}${relativePath}`;
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

                       function hospitalAdminProfileDto(admin) {
                         return {
                           // Flutter는 name/hospitalName/title 중 먼저 오는 값을 쓰니
                           // 병원명이 덮어쓰이도록 name은 보내지 않습니다.
                           hospitalName: admin.hospitalName || '',
                           intro: admin.hospitalProfile?.intro || '',
                           // 필요 시 확장 필드
                           photoUrl: admin.hospitalProfile?.photoUrl || '',
                           address:  admin.hospitalProfile?.address  || '',
                           hours:    admin.hospitalProfile?.hours    || '',
                           phone:    admin.hospitalProfile?.phone    || '',
                           approveStatus: admin.approveStatus || 'PENDING',
                         };
                       }

                       // ─────────────── 알림 유틸 ───────────────
                       async function pushNotificationOne({ userId, hospitalId, hospitalName = '', type, title, message, meta = {} }) {
                         try {
                           if (!userId || !hospitalId) return;
                           await Notification.create({
                             userId: oid(userId),
                             hospitalId: oid(hospitalId),
                             hospitalName: hospitalName || '',
                             type: (type || 'SYSTEM').toString(),
                             title: (title || '').toString(),
                             message: (message || '').toString(),
                             meta,
                           });
                         } catch (e) {
                           console.error('pushNotificationOne error:', e?.message || e);
                         }
                       }

                       async function pushNotificationMany({ userIds = [], hospitalId, hospitalName = '', type, title, message, meta = {} }) {
                         try {
                           const docs = (userIds || []).filter(Boolean).map(u => ({
                             userId: oid(u),
                             hospitalId: oid(hospitalId),
                             hospitalName: hospitalName || '',
                             type: (type || 'SYSTEM').toString(),
                             title: (title || '').toString(),
                             message: (message || '').toString(),
                             meta,
                             createdAt: new Date(),
                           }));
                           if (docs.length) await Notification.insertMany(docs, { ordered: false });
                         } catch (e) {
                           console.error('pushNotificationMany error:', e?.message || e);
                         }
                       }



                       const onlyUser = (req, res, next) =>
                         req.jwt?.role === 'USER' ? next() : res.status(403).json({ message: 'for USER' });
                       const onlyHospitalAdmin = (req, res, next) =>
                         req.jwt?.role === 'HOSPITAL_ADMIN' ? next() : res.status(403).json({ message: 'for HOSPITAL_ADMIN' });

                       const oid = (v) => {
                         if (v instanceof mongoose.Types.ObjectId) return v;
                         try { return new mongoose.Types.ObjectId(String(v)); } catch { return null; }
                       };

                       // ─────────────── Mongoose ───────────────
                       mongoose.set('strictQuery', true);

                       // 커넥션
                       const userConn     = mongoose.createConnection(MONGODB_URI, { dbName: 'user_db' });
                       const hospitalConn = mongoose.createConnection(MONGODB_URI, { dbName: 'hospital_db' });
                       const adminConn    = mongoose.createConnection(MONGODB_URI, { dbName: 'admin_db' });

                       userConn.on('connected',     () => console.log('✅ userConn -> user_db'));
                       hospitalConn.on('connected', () => console.log('✅ hospitalConn -> hospital_db'));
                       adminConn.on('connected',    () => console.log('✅ adminConn -> admin_db'));

                       // 에러 로깅
                       [userConn, hospitalConn, adminConn].forEach(c =>
                         c.on('error', (e) => console.error('Mongo error:', e?.message || e))
                       );

                       // ─────────────── 스키마 ───────────────
                       const userSchema = new mongoose.Schema({
                         email:        { type: String, required: true, unique: true, index: true },
                         passwordHash: { type: String, required: true },
                         name:         { type: String, default: '' },
                         role:         { type: String, enum: ['USER'], default: 'USER', index: true },
                         birthDate:    { type: String, default: '' },
                         petProfile: {
                           name:      { type: String, default: '' },
                           age:       { type: Number, default: 0 },
                           gender:    { type: String, default: '' },
                           species:   { type: String, default: '' },
                           avatarUrl: { type: String, default: '' },
                         },
                         linkedHospitals: [{
                           hospitalId:   { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
                           hospitalName: { type: String, default: '' },
                           status:       { type: String, enum: ['PENDING','APPROVED','REJECTED'], default: 'PENDING', index: true },
                           requestedAt:  { type: Date },
                           linkedAt:     { type: Date }
                         }],
                       }, { timestamps: true });

                       const hospitalUserSchema = new mongoose.Schema({
                         email:        { type: String, required: true, unique: true, index: true },
                         passwordHash: { type: String, required: true },
                         name:         { type: String, default: '' },
                         role:         { type: String, enum: ['HOSPITAL_ADMIN'], default: 'HOSPITAL_ADMIN', index: true },
                         hospitalName: { type: String, default: '' },
                         hospitalProfile: {
                           photoUrl: { type: String, default: '' },
                           intro:    { type: String, default: '' },
                           address:  { type: String, default: '' },
                           hours:    { type: String, default: '' },
                           phone:    { type: String, default: '' },
                         },
                         approveStatus: { type: String, enum: ['PENDING','APPROVED','REJECTED'], default: 'PENDING', index: true },
                       }, { timestamps: true });

                       const hospitalLinkRequestSchema = new mongoose.Schema({
                         userId:       { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
                         userName:     { type: String, default: '' },
                         petName:      { type: String, default: '' },
                         hospitalId:   { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
                         hospitalName: { type: String, default: '' },
                         status:       { type: String, enum: ['PENDING','APPROVED','REJECTED'], default: 'PENDING', index: true },
                         createdAt:    { type: Date, default: Date.now, index: true },
                         decidedAt:    { type: Date, default: null }
                       });

                       const hospitalMetaSchema = new mongoose.Schema({
                         hospitalId:   { type: mongoose.Schema.Types.ObjectId, required: true, unique: true, index: true },
                         hospitalName: { type: String, default: '' },
                         notice:       { type: String, default: '' },
                         services:     [{ type: String }],
                         doctors:      [{ id: String, name: String }],
                       }, { timestamps: true });

                       const appointmentSchema = new mongoose.Schema({
                         hospitalId:   { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
                         hospitalName: { type: String, default: '' },
                         userId:       { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
                         userName:     { type: String, default: '' },
                         petName:      { type: String, default: '' },
                         service:      { type: String, default: '' },
                         doctorName:   { type: String, default: '' },
                         date:         { type: String, default: '' },
                         time:         { type: String, default: '' },
                         visitDateTime:{ type: Date, index: true },
                         status:       { type: String, enum: ['PENDING','APPROVED','REJECTED','CANCELED'], default: 'PENDING', index: true },
                         createdAt:    { type: Date, default: Date.now, index: true },
                         decidedAt:    { type: Date, default: null },
                         decidedBy:    { type: mongoose.Schema.Types.ObjectId, default: null },
                       }, { timestamps: true });

                       const medicalHistorySchema = new mongoose.Schema({
                         hospitalId:   { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
                         hospitalName: { type: String, default: '' },
                         userId:       { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
                         userName:     { type: String, default: '' },
                         petName:      { type: String, default: '' },
                         date:         { type: Date, required: true, index: true },
                         category:     { type: String, default: '' },
                         content:      { type: String, default: '' },
                         prescription: { type: String, default: '' },
                         howToTake:    { type: String, default: '' },
                         cost:         { type: String, default: '' },
                       }, { timestamps: true });

                       const userAppointmentSchema = new mongoose.Schema({
                         userId:             { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
                         originAppointmentId:{ type: mongoose.Schema.Types.ObjectId, required: true, index: true },
                         hospitalId:         { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
                         hospitalName:       { type: String, default: '' },
                         userName:           { type: String, default: '' },
                         petName:            { type: String, default: '' },
                         service:            { type: String, default: '' },
                         doctorName:         { type: String, default: '' },
                         date:               { type: String, default: '' },    // YYYY-MM-DD
                         time:               { type: String, default: '' },    // HH:mm
                         visitDateTime:      { type: Date, index: true },
                         status:             { type: String, default: 'PENDING', index: true },
                       }, { timestamps: true });

                       const petCareSchema = new mongoose.Schema({
                         hospitalId:   { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
                         hospitalName: { type: String, default: '' },
                         createdBy:    { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
                         date:         { type: String, default: '' },  // 'YYYY-MM-DD'
                         time:         { type: String, default: '' },  // 'HH:mm'
                         dateTime:     { type: Date,   index: true },
                         memo:         { type: String, default: '' },
                         images:       [{ type: String }],
                       }, { timestamps: true });

                       const sosLogSchema = new mongoose.Schema({
                         hospitalId:   { type: mongoose.Schema.Types.ObjectId, index: true },
                         hospitalName: { type: String, default: '' },
                         userId:       { type: mongoose.Schema.Types.ObjectId, index: true },
                         userName:     { type: String, default: '' },
                         petName:      { type: String, default: '' },
                         message:      { type: String, default: '' },
                       }, { timestamps: true });

                       // ─────────────── 알림 스키마 ───────────────
                       const notificationSchema = new mongoose.Schema({
                         userId:       { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
                         hospitalId:   { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
                         hospitalName: { type: String, default: '' },

                         // 유형: APPOINTMENT_APPROVED, APPOINTMENT_REJECTED, PET_CARE_POSTED,
                         //       MEDICAL_HISTORY_ADDED, SOS_ALERT, SYSTEM 등
                         type:         { type: String, default: 'SYSTEM', index: true },
                         title:        { type: String, default: '' },
                         message:      { type: String, default: '' },

                         read:         { type: Boolean, default: false, index: true },
                         meta:         { type: mongoose.Schema.Types.Mixed, default: {} }, // 필요하면 상세정보

                         createdAt:    { type: Date, default: Date.now, index: true },
                       }, { versionKey: false });

                       // ─────────────── 모델 등록 ───────────────
                       const User                = userConn.model('User', userSchema, 'users');
                       const HospitalUser        = hospitalConn.model('HospitalUser', hospitalUserSchema, 'hospital_user');
                       const HospitalLinkRequest = hospitalConn.model('HospitalLinkRequest', hospitalLinkRequestSchema, 'hospital_link_requests');
                       const HospitalMeta        = hospitalConn.model('HospitalMeta', hospitalMetaSchema, 'hospital_meta');
                       const Appointment         = hospitalConn.model('Appointment', appointmentSchema, 'appointments');
                       const MedicalHistory      = hospitalConn.model('MedicalHistory', medicalHistorySchema, 'medical_histories');
                       const UserAppointment     = userConn.model('UserAppointment', userAppointmentSchema, 'user_appointments');
                       const PetCare             = hospitalConn.model('PetCare', petCareSchema, 'pet_care');
                       const SosLog = hospitalConn.model('SosLog', sosLogSchema, 'sos_logs');
                       const Notification = userConn.model('Notification', notificationSchema, 'notifications');



                       // ─────────────── 헬스 & 루트 ───────────────
                       app.get('/health', (_req, res) => res.json({ ok: true, ts: Date.now() }));
                       app.get('/', (_req, res) => res.json({ message: '🚀 Animal API running', env: process.env.NODE_ENV || 'dev' }));

                       // ─────────────── 전역 아이디 중복 확인 ───────────────
                       app.get('/auth/check-id', async (req, res) => {
                         try {
                           const key = (req.query.email || req.query.username || req.query.key || '').toString().trim();
                           if (!key) return res.status(400).json({ message: 'email/username required' });
                           const [u, h] = await Promise.all([User.exists({ email: key }), HospitalUser.exists({ email: key })]);
                           res.json({ available: !(u || h) });
                         } catch (e) { console.error('check-id error:', e); res.status(500).json({ message: 'server error' }); }
                       });

                       // ─────────────── 회원가입/로그인 ───────────────
                       app.post('/auth/signup', authLimiter, async (req, res) => {
                         try {
                           const { email, username, password, name, birthDate } = req.body || {};
                           const finalEmail = (email || username || '').trim();
                           if (!finalEmail || !password) return res.status(400).json({ message: 'email/password required' });
                           const existsAnywhere = await Promise.all([User.findOne({ email: finalEmail }), HospitalUser.findOne({ email: finalEmail })]);
                           if (existsAnywhere[0] || existsAnywhere[1]) return res.status(409).json({ message: 'email already used' });
                           const passwordHash = await bcrypt.hash(password, 12);
                           const user = await User.create({ email: finalEmail, passwordHash, name: name || '', birthDate: (birthDate || '').trim(), role: 'USER' });
                           res.status(201).json({
                             token: issueToken(user),
                             user: { id: user._id, email: user.email, name: user.name, role: user.role, birthDate: user.birthDate },
                           });
                         } catch (e) { console.error(e); res.status(500).json({ message: 'server error' }); }
                       });

                       app.post('/auth/signup-with-invite', authLimiter, async (req, res) => {
                         try {
                           const { email, password, name, inviteCode } = req.body || {};
                           if (!email || !password || !inviteCode) return res.status(400).json({ message: 'missing fields' });
                           const codes = (process.env.INVITE_ADMIN_CODES || '').split(',').map(s => s.trim()).filter(Boolean);
                           if (!codes.includes(inviteCode)) return res.status(400).json({ message: 'invalid invite code' });
                           const existsAnywhere = await Promise.all([HospitalUser.findOne({ email }), User.findOne({ email })]);
                           if (existsAnywhere[0] || existsAnywhere[1]) return res.status(409).json({ message: 'email already used' });
                           const passwordHash = await bcrypt.hash(password, 12);
                           const admin = await HospitalUser.create({ email, passwordHash, name: name || '', role: 'HOSPITAL_ADMIN', hospitalName: '' });
                           res.status(201).json({
                             token: issueToken(admin),
                             user: {
                               id: admin._id, email: admin.email, name: admin.name, role: admin.role,
                               hospitalName: admin.hospitalName, hospitalProfile: admin.hospitalProfile, approveStatus: admin.approveStatus,
                             },
                           });
                         } catch (e) { console.error(e); res.status(500).json({ message: 'server error' }); }
                       });

                       app.post('/auth/login', authLimiter, async (req, res) => {
                         try {
                           const { email, password } = req.body || {};
                           if (!email || !password) return res.status(400).json({ message: 'email/password required' });
                           let doc = await HospitalUser.findOne({ email });
                           if (doc) {
                             const ok = await bcrypt.compare(password, doc.passwordHash);
                             if (!ok) return res.status(401).json({ message: 'invalid credentials' });
                             return res.json({
                               token: issueToken(doc),
                               user: {
                                 id: doc._id, email: doc.email, name: doc.name, role: doc.role,
                                 hospitalName: doc.hospitalName, hospitalProfile: doc.hospitalProfile, approveStatus: doc.approveStatus,
                               },
                             });
                           }
                           doc = await User.findOne({ email });
                           if (!doc) return res.status(401).json({ message: 'invalid credentials' });
                           const ok = await bcrypt.compare(password, doc.passwordHash);
                           if (!ok) return res.status(401).json({ message: 'invalid credentials' });
                           return res.json({
                             token: issueToken(doc),
                             user: { id: doc._id, email: doc.email, name: doc.name, role: doc.role, birthDate: doc.birthDate, petProfile: doc.petProfile },
                           });
                         } catch (e) { console.error(e); res.status(500).json({ message: 'server error' }); }
                       });

                       // ─────────────── 프로필 ───────────────
                       app.get('/users/me', auth, onlyUser, async (req, res) => {
                         const user = await User.findById(oid(req.jwt.uid)).lean();
                         if (!user) return res.status(404).json({ message: 'not found' });
                         delete user.passwordHash;
                         res.json({ user, id: user._id, email: user.email, name: user.name, role: user.role, birthDate: user.birthDate, petProfile: user.petProfile });
                       });

                       app.get('/hospital/me', auth, onlyHospitalAdmin, async (req, res) => {
                         const admin = await HospitalUser.findById(oid(req.jwt.uid)).lean();
                         if (!admin) return res.status(404).json({ message: 'not found' });
                         delete admin.passwordHash;
                         res.json({ user: admin });
                       });

                       app.put('/users/me/pet', auth, onlyUser, async (req, res) => {
                         try {
                           const { name, age, gender, species, avatarUrl } = req.body || {};
                           const update = {
                             'petProfile.name': (name || '').trim(),
                             'petProfile.age':  Number.isFinite(Number(age)) ? Number(age) : 0,
                             'petProfile.gender': (gender || '').trim(),
                             'petProfile.species': (species || '').trim(),
                             'petProfile.avatarUrl': (avatarUrl || '').trim(),
                           };
                           const user = await User.findByIdAndUpdate(oid(req.jwt.uid), { $set: update }, { new: true, lean: true });
                           if (!user) return res.status(404).json({ message: 'not found' });
                           delete user.passwordHash;
                           return res.json({ user });
                         } catch (e) { console.error('PUT /users/me/pet error:', e); return res.status(500).json({ message: 'server error' }); }
                       });

                       app.put('/hospital/profile', auth, onlyHospitalAdmin, async (req, res) => {
                         const { hospitalName, photoUrl, intro, address, hours, phone } = req.body || {};
                         const update = {
                           ...(typeof hospitalName === 'string' ? { hospitalName: hospitalName.trim() } : {}),
                           'hospitalProfile.photoUrl': (photoUrl || '').trim(),
                           'hospitalProfile.intro':    (intro || '').trim(),
                           'hospitalProfile.address':  (address || '').trim(),
                           'hospitalProfile.hours':    (hours || '').trim(),
                           'hospitalProfile.phone':    (phone || '').trim(),
                           approveStatus: 'PENDING',
                         };
                         const admin = await HospitalUser.findByIdAndUpdate(oid(req.jwt.uid), { $set: update }, { new: true, lean: true });
                         if (!admin) return res.status(404).json({ message: 'not found' });
                         delete admin.passwordHash;
                         res.json({ user: admin });
                       });

                       // ─────────────── 병원 목록 ───────────────
                       app.get('/api/hospitals', async (req, res) => {
                         const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
                         const page  = Math.max(parseInt(req.query.page  || '1', 10), 1);
                         const skip  = (page - 1) * limit;

                         const [items, total] = await Promise.all([
                           HospitalUser.find({}, { passwordHash: 0 }).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
                           HospitalUser.countDocuments({}),
                         ]);
                         const data = items.map(h => ({
                           _id: h._id,
                           hospitalName: h.hospitalName || '',
                           approveStatus: h.approveStatus || 'PENDING',
                           imageUrl: h.hospitalProfile?.photoUrl || '',
                           createdAt: h.createdAt,
                         }));
                         res.json({ data, paging: { total, page, limit } });
                       });

                       // ─────────────── 병원 연동 ───────────────
                       app.get('/api/hospital-links/available', auth, onlyUser, async (req, res) => {
                         const [hospitals, me] = await Promise.all([
                           HospitalUser.find({}, { passwordHash: 0 }).sort({ createdAt: -1 }).lean(),
                           User.findById(oid(req.jwt.uid), { linkedHospitals: 1 }).lean(),
                         ]);
                         const statusMap = new Map();
                         (me?.linkedHospitals || []).forEach(x => statusMap.set(String(x.hospitalId), x.status));
                         const data = hospitals.map(h => ({
                           hospitalId: String(h._id),
                           hospitalName: h.hospitalName || '',
                           myStatus: statusMap.get(String(h._id)) || 'NONE',
                           imageUrl: h.hospitalProfile?.photoUrl || '',
                           createdAt: h.createdAt,
                         }));
                         res.json({ data });
                       });

                       async function upsertUserLink(userId, hospital) {
                         const user = await User.findById(oid(userId));
                         if (!user) throw new Error('user not found');
                         const has = (user.linkedHospitals || []).find(h => String(h.hospitalId) === String(hospital._id));
                         if (has) {
                           has.status = 'PENDING';
                           has.requestedAt = new Date();
                         } else {
                           user.linkedHospitals.push({
                             hospitalId: hospital._id,
                             hospitalName: hospital.hospitalName || '',
                             status: 'PENDING',
                             requestedAt: new Date(),
                           });
                         }
                         await user.save();

                         const existing = await HospitalLinkRequest.findOne({
                           userId: oid(userId), hospitalId: oid(hospital._id), status: 'PENDING',
                         });
                         if (!existing) {
                           await HospitalLinkRequest.create({
                             userId: oid(userId),
                             userName: user.name || '',
                             petName: user.petProfile?.name || '',
                             hospitalId: hospital._id,
                             hospitalName: hospital.hospitalName || '',
                           });
                         }
                       }
                       app.post('/api/hospital-links/request', auth, onlyUser, async (req, res) => {
                         try {
                           const { hospitalId } = req.body || {};
                           if (!hospitalId) return res.status(400).json({ message: 'hospitalId required' });
                           const hospital = await HospitalUser.findById(oid(hospitalId)).lean();
                           if (!hospital) return res.status(404).json({ message: 'hospital not found' });
                           await upsertUserLink(req.jwt.uid, hospital);
                           res.json({ ok: true });
                         } catch (e) { console.error('request link error:', e); res.status(500).json({ message: 'server error' }); }
                       });
                       app.post('/api/hospitals/:id/connect', auth, onlyUser, async (req, res) => {
                         try {
                           const hospital = await HospitalUser.findById(oid(req.params.id)).lean();
                           if (!hospital) return res.status(404).json({ message: 'hospital not found' });
                           await upsertUserLink(req.jwt.uid, hospital);
                           res.json({ ok: true });
                         } catch (e) { console.error('compat connect error:', e); res.status(500).json({ message: 'server error' }); }
                       });

                       // ─────────────── 병원관리자: 요청/승인/거절 ───────────────
                       app.get('/api/hospital-admin/requests', auth, onlyHospitalAdmin, async (req, res) => {
                         const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
                         const page  = Math.max(parseInt(req.query.page  || '1', 10), 1);
                         const skip  = (page - 1) * limit;

                         const q = { hospitalId: oid(req.jwt.uid), status: 'PENDING' };
                         const [items, total] = await Promise.all([
                           HospitalLinkRequest.find(q).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
                           HospitalLinkRequest.countDocuments(q),
                         ]);
                         res.json({ data: items, paging: { total, page, limit } });
                       });

                       app.post('/api/hospital-admin/requests/:id/approve', auth, onlyHospitalAdmin, async (req, res) => {
                         try {
                           const r = await HospitalLinkRequest.findById(oid(req.params.id));
                           if (!r) return res.status(404).json({ message: 'not found' });
                           if (String(r.hospitalId) !== String(req.jwt.uid)) return res.status(403).json({ message: 'forbidden' });
                           r.status = 'APPROVED';
                           r.decidedAt = new Date();
                           await r.save();
                           await User.updateOne(
                             { _id: r.userId, 'linkedHospitals.hospitalId': r.hospitalId },
                             { $set: { 'linkedHospitals.$.status': 'APPROVED', 'linkedHospitals.$.linkedAt': new Date() } }
                           );
                           res.json({ ok: true });
                         } catch (e) { console.error('approve error:', e); res.status(500).json({ message: 'server error' }); }
                       });

                       app.post('/api/hospital-admin/requests/:id/reject', auth, onlyHospitalAdmin, async (req, res) => {
                         try {
                           const r = await HospitalLinkRequest.findById(oid(req.params.id));
                           if (!r) return res.status(404).json({ message: 'not found' });
                           if (String(r.hospitalId) !== String(req.jwt.uid)) return res.status(403).json({ message: 'forbidden' });
                           r.status = 'REJECTED';
                           r.decidedAt = new Date();
                           await r.save();
                           await User.updateOne(
                             { _id: r.userId, 'linkedHospitals.hospitalId': r.hospitalId },
                             { $set: { 'linkedHospitals.$.status': 'REJECTED' } }
                           );
                           res.json({ ok: true });
                         } catch (e) { console.error('reject error:', e); res.status(500).json({ message: 'server error' }); }
                       });

                       // ─────────────── 병원관리자: 연동된 사용자 목록 (SOS용) ───────────────
                       app.get('/api/hospital-admin/linked-users', auth, onlyHospitalAdmin, async (req, res) => {
                         try {
                           const hid = oid(req.jwt.uid);

                           // linkedHospitals 중 status=APPROVED 인 사용자만
                           const users = await User.find({
                             linkedHospitals: { $elemMatch: { hospitalId: hid, status: 'APPROVED' } },
                           })
                             .select('email name birthDate petProfile')
                             .lean();

                           const list = users.map(u => ({
                             _id: u._id,
                             email: u.email,
                             userName: u.name || '',
                             birthDate: u.birthDate || '',
                             petProfile: u.petProfile || {},
                           }));

                           res.json(list);
                         } catch (e) {
                           console.error('GET /api/hospital-admin/linked-users error:', e);
                           res.status(500).json({ message: 'server error' });
                         }
                       });


                       // ─────────────── 병원관리자: 환자/진료내역 ───────────────
                       app.get('/api/hospital-admin/patients', auth, onlyHospitalAdmin, async (req, res) => {
                         try {
                           const limit = Math.min(parseInt(req.query.limit || '200', 10), 500);
                           const page  = Math.max(parseInt(req.query.page  || '1', 10), 1);
                           const skip  = (page - 1) * limit;

                           const pipeline = [
                             { $unwind: '$linkedHospitals' },
                             { $match: { 'linkedHospitals.hospitalId': oid(req.jwt.uid), 'linkedHospitals.status': 'APPROVED' } },
                             { $project: { _id: 0, userId: '$_id', userName: '$name', petName: '$petProfile.name' } },
                             { $skip: skip },
                             { $limit: limit },
                           ];
                           const [items, totalAgg] = await Promise.all([
                             User.aggregate(pipeline),
                             User.aggregate([
                               { $unwind: '$linkedHospitals' },
                               { $match: { 'linkedHospitals.hospitalId': oid(req.jwt.uid), 'linkedHospitals.status': 'APPROVED' } },
                               { $count: 'total' },
                             ]),
                           ]);
                           const total = totalAgg[0]?.total || 0;
                           res.json({ data: items, paging: { total, page, limit } });
                         } catch (e) { console.error('GET /api/hospital-admin/patients error:', e); res.status(500).json({ message: 'server error' }); }
                       });

                       app.get('/api/hospital-admin/medical-histories', auth, onlyHospitalAdmin, async (req, res) => {
                         try {
                           const { userId } = req.query;
                           if (!userId) return res.status(400).json({ message: 'userId is required' });

                           const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
                           const page  = Math.max(parseInt(req.query.page  || '1', 10), 1);
                           const skip  = (page - 1) * limit;

                           const hid  = oid(req.query.hospitalId || req.jwt.uid);
                           const list = await MedicalHistory.find({ userId: oid(userId), hospitalId: hid })
                             .sort({ date: -1, createdAt: -1 })
                             .skip(skip).limit(limit).lean();
                           const total = await MedicalHistory.countDocuments({ userId: oid(userId), hospitalId: hid });
                           const data  = list.map(m => ({ ...m, id: m._id }));
                           return res.json({ data, paging: { total, page, limit } });
                         } catch (e) { console.error('GET histories error:', e); return res.status(500).json({ message: 'server error' }); }
                       });

                       app.post('/api/hospital-admin/medical-histories', auth, onlyHospitalAdmin, async (req, res) => {
                         try {
                           const { userId, hospitalId, date, content, prescription, howToTake, cost, petName, userName, category, hospitalName } = req.body || {};
                           if (!userId || !date) return res.status(400).json({ message: 'userId and date are required' });
                           const hid = oid(hospitalId || req.jwt.uid);
                           let hName = (hospitalName || '').trim();
                           if (!hName) {
                             const h = await HospitalUser.findById(hid).lean();
                             hName = h?.hospitalName || '';
                           }
                           const doc = await MedicalHistory.create({
                             userId: oid(userId),
                             hospitalId: hid,
                             hospitalName: hName,
                             userName: (userName || '').trim(),
                             petName: (petName || '').trim(),
                             date: new Date(date),
                             category: (category || '').trim(),
                             content: (content || '').trim(),
                             prescription: (prescription || '').trim(),
                             howToTake: (howToTake || '').trim(),
                             cost: (cost || '').trim(),
                           });

                           await pushNotificationOne({
                             userId: userId,
                             hospitalId: hid,
                             hospitalName: hName,
                             type: 'MEDICAL_HISTORY_ADDED',
                             title: '새 진료 내역 등록',
                             message: `${(category || '진료')} · ${new Date(date).toLocaleDateString()}`,
                             meta: { medicalHistoryId: doc._id }
                           });

                           const created = doc.toJSON();
                           return res.status(201).json({ data: { ...created, id: created._id } });
                         } catch (e) { console.error('POST histories error:', e); return res.status(500).json({ message: 'server error' }); }
                       });

                       // ─────────────── 사용자: 병원 목록/예약/케어일지 ───────────────
                       app.get('/api/users/me/hospitals', auth, onlyUser, async (req, res) => {
                         const user = await User.findById(oid(req.jwt.uid)).lean();
                         if (!user) return res.status(404).json({ message: 'not found' });
                         let list = user.linkedHospitals || [];
                         if (!req.query.all) list = list.filter(h => h.status === 'APPROVED');
                         list.sort((a, b) => {
                           const aa = a.linkedAt || a.requestedAt || new Date(0);
                           const bb = b.linkedAt || b.requestedAt || new Date(0);
                           return new Date(bb) - new Date(aa);
                         });
                         const data = list.map(x => ({
                           hospitalId: String(x.hospitalId ?? ''),
                           hospitalName: x.hospitalName || '',
                           linkedAt: x.linkedAt || x.requestedAt || user.updatedAt,
                         }));
                         return res.json({ data });
                       });

                       // ─────────────── 병원관리자: 케어일지 목록/등록 ───────────────
                       app.get('/api/hospital-admin/pet-care', auth, onlyHospitalAdmin, async (req, res) => {
                         try {
                           const keyword = (req.query.keyword || '').toString().trim();
                           const sortKey = (req.query.sort || 'dateDesc').toString();
                           const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
                           const page  = Math.max(parseInt(req.query.page  || '1', 10), 1);
                           const skip  = (page - 1) * limit;

                           const q = { hospitalId: oid(req.jwt.uid) };
                           if (keyword) {
                             const rx = new RegExp(keyword, 'i');
                             q.$or = [{ memo: rx }];
                           }
                           const sort = sortKey === 'dateAsc' ? 1 : -1;

                           const [items, total] = await Promise.all([
                             PetCare.find(q).sort({ dateTime: sort, createdAt: sort }).skip(skip).limit(limit).lean(),
                             PetCare.countDocuments(q),
                           ]);
                           const data = items.map(d => ({
                             _id: d._id,
                             date: d.date || '',
                             time: d.time || '',
                             dateTime: d.dateTime,
                             memo: d.memo || '',
                             imageUrl: (d.images && d.images.length) ? d.images[0] : '',
                             images: d.images || [],
                           }));
                           return res.json({ data, paging: { total, page, limit } });
                         } catch (e) { console.error('GET pet-care error:', e); return res.status(500).json({ message: 'server error' }); }
                       });

                       app.post('/api/hospital-admin/pet-care', auth, onlyHospitalAdmin, uploadLimiter, upload.array('images', 10), async (req, res) => {
                         try {
                           const admin = await HospitalUser.findById(oid(req.jwt.uid)).lean();
                           if (!admin) return res.status(404).json({ message: 'hospital not found' });
                           const date = (req.body.date || '').toString().trim();
                           const time = (req.body.time || '').toString().trim();
                           const memo = (req.body.memo || '').toString().trim();
                           if (!date || !time) return res.status(400).json({ message: 'date/time required' });

                           const urls = (req.files || []).map(f => publicUrl(req, `/uploads/pet-care/${path.basename(f.path)}`));

                           // 서울 타임존을 고려한 날짜 파싱은 클라이언트에서 ISO로 보내는 것이 제일 안전
                           const dt = new Date(`${date}T${time}:00`);
                           const doc = await PetCare.create({
                             hospitalId: oid(req.jwt.uid),
                             hospitalName: admin.hospitalName || '',
                             createdBy: oid(req.jwt.uid),
                             date, time, dateTime: isNaN(dt.getTime()) ? new Date() : dt,
                             memo,
                             images: urls,
                           });
                           const created = doc.toJSON();

                           // 이 병원과 연동(APPROVED)된 모든 사용자에게 알림
                           const approvedUsers = await User.find({
                             linkedHospitals: { $elemMatch: { hospitalId: oid(req.jwt.uid), status: 'APPROVED' } }
                           }).select('_id').lean();

                           await pushNotificationMany({
                             userIds: approvedUsers.map(u => u._id),
                             hospitalId: oid(req.jwt.uid),
                             hospitalName: admin.hospitalName || '',
                             type: 'PET_CARE_POSTED',
                             title: '새 반려 일지가 올라왔어요',
                             message: memo ? memo.slice(0, 80) : '이미지/메모가 등록되었습니다.',
                             meta: { petCareId: doc._id, imageUrl: urls[0] || '' }
                           });

                           return res.status(201).json({
                             data: {
                               _id: created._id,
                               date: created.date,
                               time: created.time,
                               dateTime: created.dateTime,
                               memo: created.memo,
                               imageUrl: (created.images && created.images.length) ? created.images[0] : '',
                               images: created.images || [],
                             }
                           });
                         } catch (e) {
                           console.error('POST pet-care error:', e);
                           return res.status(500).json({ message: e?.message || 'server error' });
                         }
                       });

                       // ─────────────── 예약 메타/신청 ───────────────
                       app.get('/api/hospitals/:hospitalId/appointment-meta', async (req, res) => {
                         const { hospitalId } = req.params;
                         const meta = await HospitalMeta.findOne({ hospitalId: oid(hospitalId) }).lean();
                         const servicesDefault = ['일반진료','건강검진','종합백신','심장사상충','치석제거'];
                         const doctorsDefault  = [{ id: 'default', name: '김철수 원장' }];
                         if (!meta) {
                           const h = await HospitalUser.findById(oid(hospitalId)).lean();
                           return res.json({
                             hospitalId,
                             hospitalName: h?.hospitalName || '',
                             notice: '',
                             services: servicesDefault,
                             doctors: doctorsDefault
                           });
                         }
                         res.json({
                           hospitalId,
                           hospitalName: meta.hospitalName || '',
                           notice: meta.notice || '',
                           services: (meta.services && meta.services.length) ? meta.services : servicesDefault,
                           doctors:  (meta.doctors && meta.doctors.length)   ? meta.doctors  : doctorsDefault
                         });
                       });

                       app.put('/api/hospitals/:hospitalId/appointment-meta', auth, onlyHospitalAdmin, async (req, res) => {
                         try {
                           if (String(req.params.hospitalId) !== String(req.jwt.uid)) return res.status(403).json({ message: 'forbidden' });
                           const { services, doctors, notice } = req.body || {};
                           const h = await HospitalUser.findById(oid(req.jwt.uid)).lean();
                           const doc = await HospitalMeta.findOneAndUpdate(
                             { hospitalId: oid(req.jwt.uid) },
                             {
                               $set: {
                                 hospitalId: oid(req.jwt.uid),
                                 hospitalName: h?.hospitalName || '',
                                 notice: (notice || '').toString(),
                                 services: Array.isArray(services) ? services : undefined,
                                 doctors:  Array.isArray(doctors)  ? doctors  : undefined,
                               }
                             },
                             { new: true, upsert: true }
                           ).lean();
                           res.json({ ok: true, meta: doc });
                         } catch (e) { console.error('PUT meta error:', e); res.status(500).json({ message: 'server error' }); }
                       });

                       app.post('/api/hospitals/:hospitalId/appointments/request', auth, onlyUser, async (req, res) => {
                         try {
                           const { hospitalId } = req.params;
                           const { hospitalName, service, doctorName, date, time, visitDateTime, userName, petName } = req.body || {};
                           if (!service || !doctorName || !date || !time) return res.status(400).json({ message: 'missing fields' });

                           const me = await User.findById(oid(req.jwt.uid)).lean();
                           const link = (me?.linkedHospitals || []).find(h => String(h.hospitalId) === String(hospitalId));
                           if (!link || link.status !== 'APPROVED') return res.status(403).json({ message: 'link to hospital required (APPROVED)' });

                           const h = await HospitalUser.findById(oid(hospitalId)).lean();
                           if (!h) return res.status(404).json({ message: 'hospital not found' });

                           const vdt = visitDateTime ? new Date(visitDateTime) : new Date(`${date}T${time}:00`);
                           const cleanedUserName = (userName || '').trim();
                           const finalUserName = cleanedUserName && cleanedUserName !== '사용자' ? cleanedUserName : (me?.name || '');
                           const cleanedPetName = (petName || '').trim();
                           const finalPetName = cleanedPetName && cleanedPetName !== '(미입력)' ? cleanedPetName : (me?.petProfile?.name || '');

                           const appt = await Appointment.create({
                             hospitalId: oid(hospitalId),
                             hospitalName: hospitalName || h.hospitalName || '',
                             userId: oid(req.jwt.uid),
                             userName: finalUserName,
                             petName:  finalPetName,
                             service, doctorName, date, time,
                             visitDateTime: vdt,
                             status: 'PENDING'
                           });

                           await UserAppointment.create({
                             userId: oid(req.jwt.uid),
                             originAppointmentId: appt._id,
                             hospitalId: oid(hospitalId),
                             hospitalName: hospitalName || h.hospitalName || '',
                             userName: finalUserName,
                             petName:  finalPetName,
                             service, doctorName, date, time,
                             visitDateTime: vdt,
                             status: 'PENDING'
                           });

                           res.status(201).json({ ok: true, appointmentId: appt._id });
                         } catch (e) { console.error('appointment request error:', e); res.status(500).json({ message: 'server error' }); }
                       });

                       // ─────────────── 사용자 예약 조회/삭제/월간 ───────────────
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
                               q.visitDateTime = { $gte: start, $lt: end };
                             }
                           }

                           const limit = Math.min(parseInt(req.query.limit || '100', 10), 300);
                           const page  = Math.max(parseInt(req.query.page  || '1', 10), 1);
                           const skip  = (page - 1) * limit;

                           let list = await UserAppointment.find(q).sort({ visitDateTime: 1 }).skip(skip).limit(limit).lean();
                           const total = await UserAppointment.countDocuments(q);

                           list = list.map(a => ({ ...a, userName: a.userName || me?.name || '', petName: a.petName || me?.petProfile?.name || '' }));

                           // 과거 호환
                           if (!list.length) {
                             const hospitalList = await Appointment.find({ userId: oid(req.jwt.uid) }).sort({ visitDateTime: 1 }).skip(skip).limit(limit).lean();
                             const mapped = hospitalList.map(a => ({
                               userId: a.userId, hospitalId: a.hospitalId, hospitalName: a.hospitalName,
                               userName: a.userName || me?.name || '', petName: a.petName || me?.petProfile?.name || '',
                               service: a.service, doctorName: a.doctorName, date: a.date, time: a.time,
                               visitDateTime: a.visitDateTime, status: a.status,
                             }));
                             return res.json({ data: mapped, paging: { total: await Appointment.countDocuments({ userId: oid(req.jwt.uid) }), page, limit } });
                           }

                           res.json({ data: list, paging: { total, page, limit } });
                         } catch (e) { console.error('get user appointments error:', e); res.status(500).json({ message: 'server error' }); }
                       });

                       app.delete('/api/users/me/appointments/:id', auth, onlyUser, async (req, res) => {
                         try {
                           const ua = await UserAppointment.findOne({ _id: oid(req.params.id), userId: oid(req.jwt.uid) });
                           if (!ua) return res.status(404).json({ message: 'not found' });
                           await UserAppointment.deleteOne({ _id: ua._id });
                           await Appointment.deleteOne({ _id: ua.originAppointmentId, userId: oid(req.jwt.uid) });
                           return res.status(204).send();
                         } catch (e) { console.error('delete my appt error:', e); return res.status(500).json({ message: 'server error' }); }
                       });

                       app.get('/api/users/me/appointments/monthly', auth, onlyUser, async (req, res) => {
                         try {
                           const { hospitalId, month } = req.query;
                           if (!month) return res.status(400).json({ message: 'month required (YYYY-MM)' });
                           const [yy, mm] = String(month).split('-').map(Number);
                           if (!yy || !mm) return res.status(400).json({ message: 'invalid month' });
                           const q = { userId: oid(req.jwt.uid) };
                           if (hospitalId) q.hospitalId = oid(hospitalId);
                           const start = new Date(yy, mm - 1, 1, 0, 0, 0);
                           const end   = new Date(yy, mm, 1, 0, 0, 0);
                           q.visitDateTime = { $gte: start, $lt: end };
                           const list = await UserAppointment.find(q).sort({ visitDateTime: 1 }).lean();
                           res.json(list);
                         } catch (e) { console.error('monthly user appts error:', e); res.status(500).json({ message: 'server error' }); }
                       });

                       // ─────────────── 사용자: 케어일지 보기 ───────────────
                       app.get('/api/users/me/pet-care', auth, onlyUser, async (req, res) => {
                         try {
                           const { hospitalId, keyword = '', sort = 'dateDesc' } = req.query;
                           if (!hospitalId) return res.status(400).json({ message: 'hospitalId required' });

                           const me = await User.findById(oid(req.jwt.uid), { linkedHospitals: 1 }).lean();
                           const link = (me?.linkedHospitals || []).find(h => String(h.hospitalId) === String(hospitalId) && h.status === 'APPROVED');
                           if (!link) return res.status(403).json({ message: 'link to hospital required (APPROVED)' });

                           const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
                           const page  = Math.max(parseInt(req.query.page  || '1', 10), 1);
                           const skip  = (page - 1) * limit;

                           const q = { hospitalId: oid(hospitalId) };
                           if (String(keyword).trim()) {
                             const rx = new RegExp(String(keyword).trim(), 'i');
                             q.$or = [{ memo: rx }];
                           }
                           const s = sort === 'dateAsc' ? 1 : -1;

                           const [items, total] = await Promise.all([
                             PetCare.find(q).sort({ dateTime: s, createdAt: s }).skip(skip).limit(limit).lean(),
                             PetCare.countDocuments(q),
                           ]);

                           const data = items.map(d => ({
                             _id: d._id, date: d.date || '', time: d.time || '', dateTime: d.dateTime, memo: d.memo || '',
                             imageUrl: (d.images && d.images.length) ? d.images[0] : '', images: d.images || [],
                           }));
                           res.json({ data, paging: { total, page, limit } });
                         } catch (e) { console.error('GET /api/users/me/pet-care error:', e); res.status(500).json({ message: 'server error' }); }
                       });

                       // ─────────────── 병원관리자: 예약함/승인/거절 ───────────────
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
                           Appointment.find(q).sort({ createdAt: sort }).skip(skip).limit(limit).lean(),
                           Appointment.countDocuments(q),
                         ]);
                         res.json({ data: items, paging: { total, page, limit } });
                       });

                       app.post('/api/hospital-admin/appointments/:id/approve', auth, onlyHospitalAdmin, async (req, res) => {
                         try {
                           const appt = await Appointment.findById(oid(req.params.id));
                           if (!appt) return res.status(404).json({ message: 'not found' });
                           if (String(appt.hospitalId) !== String(req.jwt.uid)) return res.status(403).json({ message: 'forbidden' });
                           if (appt.status !== 'PENDING') return res.status(409).json({ message: 'already decided' });
                           appt.status = 'APPROVED';
                           appt.decidedAt = new Date();
                           appt.decidedBy = oid(req.jwt.uid);
                           await appt.save();
                           await UserAppointment.updateOne({ originAppointmentId: appt._id }, { $set: { status: 'APPROVED' } });

                       // ✅ pushNotificationOne 추가 (return 전에)
                       await pushNotificationOne({
                         userId: appt.userId,
                         hospitalId: appt.hospitalId,
                         hospitalName: appt.hospitalName || '',
                         type: 'APPOINTMENT_APPROVED',
                         title: '진료 예약 승인',
                         message: `${appt.date} ${appt.time} · ${appt.service} (${appt.doctorName || '담당의'})`,
                         meta: { appointmentId: appt._id }
                       });

                           res.json({ ok: true });
                         } catch (e) { console.error('approve appt error:', e); res.status(500).json({ message: 'server error' }); }
                       });

                       app.post('/api/hospital-admin/appointments/:id/reject', auth, onlyHospitalAdmin, async (req, res) => {
                         try {
                           const appt = await Appointment.findById(oid(req.params.id));
                           if (!appt) return res.status(404).json({ message: 'not found' });
                           if (String(appt.hospitalId) !== String(req.jwt.uid)) return res.status(403).json({ message: 'forbidden' });
                           if (appt.status !== 'PENDING') return res.status(409).json({ message: 'already decided' });
                           appt.status = 'REJECTED';
                           appt.decidedAt = new Date();
                           appt.decidedBy = oid(req.jwt.uid);
                           await appt.save();
                           await UserAppointment.updateOne({ originAppointmentId: appt._id }, { $set: { status: 'REJECTED' } });
                       // 거절 처리 부분도 동일하게 res.json 전에
                       await pushNotificationOne({
                         userId: appt.userId,
                         hospitalId: appt.hospitalId,
                         hospitalName: appt.hospitalName || '',
                         type: 'APPOINTMENT_REJECTED',
                         title: '진료 예약 거절',
                         message: `${appt.date} ${appt.time} · ${appt.service}`,
                         meta: { appointmentId: appt._id }
                       });


                           res.json({ ok: true });
                         } catch (e) { console.error('reject appt error:', e); res.status(500).json({ message: 'server error' }); }
                       });

                       // ─────────────── 사용자: 내 진료내역 ───────────────
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
                             if (!yy || !mm) return res.status(400).json({ message: 'invalid month' });
                             const start = new Date(yy, mm - 1, 1, 0, 0, 0);
                             const end   = new Date(yy, mm,     1, 0, 0, 0);
                             find.date = { $gte: start, $lt: end };
                           }
                           if (q && String(q).trim()) {
                             const rx = new RegExp(String(q).trim(), 'i');
                             find.$or = [
                               { category: rx }, { content: rx }, { prescription: rx },
                               { howToTake: rx }, { hospitalName: rx }, { cost: rx },
                             ];
                           }
                           const [items, total] = await Promise.all([
                             MedicalHistory.find(find).sort({ date: -1, createdAt: -1 }).skip(skip).limit(limit).lean(),
                             MedicalHistory.countDocuments(find),
                           ]);
                           const data = items.map(m => ({ ...m, id: m._id }));
                           return res.json({ data, paging: { total, page, limit } });
                         } catch (e) { console.error('GET /api/users/me/medical-histories error:', e); return res.status(500).json({ message: 'server error' }); }
                       });

                       // SOS 전송(로그 저장; 추후 문자/푸시 연동 지점)
                       app.post('/api/hospital-admin/sos', auth, onlyHospitalAdmin, async (req, res) => {
                         try {
                           const { userId, hospitalId, message } = req.body || {};
                           if (!userId) return res.status(400).json({ message: 'userId required' });

                           const user = await User.findById(oid(userId)).lean();
                           if (!user) return res.status(404).json({ message: 'user not found' });

                           // 병원 ID/이름 확정
                           const hid = oid(hospitalId || req.jwt.uid);
                           let hospitalName = '';
                           const approved = (user.linkedHospitals || []).find(h =>
                             String(h.hospitalId) === String(hid) && h.status === 'APPROVED'
                           );
                           if (approved) hospitalName = approved.hospitalName || '';

                           const log = await SosLog.create({
                             hospitalId: hid,
                             hospitalName,
                             userId: user._id,
                             userName: user.name || '',
                             petName: user.petProfile?.name || '',
                             message: (message || '').toString(),
                           });

                       await pushNotificationOne({
                         userId: user._id,
                         hospitalId: hid,
                         hospitalName,
                         type: 'SOS_ALERT',
                         title: '병원 긴급 알림',
                         message: (message || '').toString(),
                         meta: { sosId: log._id }
                       });


                           // TODO: 문자/알림 연동 (Twilio/알리고/FCM 등)
                           return res.status(201).json({ ok: true, id: log._id });
                         } catch (e) {
                           console.error('POST /api/hospital-admin/sos error:', e);
                           return res.status(500).json({ message: 'server error' });
                         }
                       });

                       app.get('/api/hospital-admin/profile', auth, onlyHospitalAdmin, async (req, res) => {
                         try {
                           const admin = await HospitalUser.findById(oid(req.jwt.uid)).lean();
                           if (!admin) return res.status(404).json({ message: 'not found' });
                           return res.json({ data: hospitalAdminProfileDto(admin) });
                         } catch (e) {
                           console.error('GET /api/hospital-admin/profile error:', e);
                           return res.status(500).json({ message: 'server error' });
                         }
                       });

                       // PATCH /api/hospital-admin/profile  → 마이페이지 우상단 편집 저장에서 사용
                       app.patch('/api/hospital-admin/profile', auth, onlyHospitalAdmin, async (req, res) => {
                         try {
                           // Flutter가 보내는 바디: { name, intro } (name = 병원명)
                           // 추가 호환: { hospitalName, photoUrl, address, hours, phone }
                           const {
                             name,
                             hospitalName,
                             intro,
                             photoUrl,
                             address,
                             hours,
                             phone,
                           } = req.body || {};

                           const update = {
                             ...(typeof (hospitalName ?? name) === 'string'
                               ? { hospitalName: (hospitalName ?? name).trim() }
                               : {}),
                             'hospitalProfile.photoUrl': typeof photoUrl === 'string' ? photoUrl.trim() : undefined,
                             'hospitalProfile.intro':    typeof intro    === 'string' ? intro.trim()    : undefined,
                             'hospitalProfile.address':  typeof address  === 'string' ? address.trim()  : undefined,
                             'hospitalProfile.hours':    typeof hours    === 'string' ? hours.trim()    : undefined,
                             'hospitalProfile.phone':    typeof phone    === 'string' ? phone.trim()    : undefined,
                             // 프로필 변경 시 다시 승인 필요하도록 기존 로직 유지
                             approveStatus: 'PENDING',
                           };

                           // undefined 값은 $unset 되지 않으므로, 정의된 키만 세팅
                           Object.keys(update).forEach((k) => update[k] === undefined && delete update[k]);

                           const admin = await HospitalUser.findByIdAndUpdate(
                             oid(req.jwt.uid),
                             { $set: update },
                             { new: true, lean: true }
                           );
                           if (!admin) return res.status(404).json({ message: 'not found' });

                           return res.json({ data: hospitalAdminProfileDto(admin) });
                         } catch (e) {
                           console.error('PATCH /api/hospital-admin/profile error:', e);
                           return res.status(500).json({ message: 'server error' });
                         }
                       });

                       // ─────────────── 사용자 알림 API ───────────────

                       // 미확인 개수
                       app.get('/api/users/me/notifications/unread-count', auth, onlyUser, async (req, res) => {
                         try {
                           const q = { userId: oid(req.jwt.uid), read: false };
                           if (req.query.hospitalId) q.hospitalId = oid(req.query.hospitalId);
                           const count = await Notification.countDocuments(q);
                           res.json({ count });
                         } catch (e) { console.error('unread-count error:', e); res.status(500).json({ message: 'server error' }); }
                       });

                       // 목록 (커서 기반: _id 기준 내림차순)
                       app.get('/api/users/me/notifications', auth, onlyUser, async (req, res) => {
                         try {
                           const limit = Math.min(parseInt(req.query.limit || '20', 10), 100);
                           const q = { userId: oid(req.jwt.uid) };
                           if (req.query.hospitalId) q.hospitalId = oid(req.query.hospitalId);
                           if (req.query.cursor) q._id = { $lt: oid(req.query.cursor) };

                           const items = await Notification.find(q).sort({ _id: -1 }).limit(limit).lean();
                           const nextCursor = items.length === limit ? String(items[items.length - 1]._id) : null;

                           const data = items.map(n => ({
                             id: n._id,
                             type: n.type,
                             title: n.title || '',
                             message: n.message || '',
                             createdAt: n.createdAt,
                             read: !!n.read,
                             hospitalId: n.hospitalId,
                             hospitalName: n.hospitalName || '',
                             meta: n.meta || {},
                           }));
                           res.json({ data, nextCursor });
                         } catch (e) { console.error('list notifications error:', e); res.status(500).json({ message: 'server error' }); }
                       });

                       // 읽음 처리
                       app.patch('/api/users/me/notifications/:id/read', auth, onlyUser, async (req, res) => {
                         try {
                           await Notification.updateOne({ _id: oid(req.params.id), userId: oid(req.jwt.uid) }, { $set: { read: true } });
                           res.status(204).send();
                         } catch (e) { console.error('read notif error:', e); res.status(500).json({ message: 'server error' }); }
                       });

                       // 모두 읽음
                       app.post('/api/users/me/notifications/mark-all-read', auth, onlyUser, async (req, res) => {
                         try {
                           const q = { userId: oid(req.jwt.uid), read: false };
                           if (req.query.hospitalId) q.hospitalId = oid(req.query.hospitalId);
                           await Notification.updateMany(q, { $set: { read: true } });
                           res.status(204).send();
                         } catch (e) { console.error('mark-all-read error:', e); res.status(500).json({ message: 'server error' }); }
                       });

                       // 삭제(선택)
                       app.delete('/api/users/me/notifications/:id', auth, onlyUser, async (req, res) => {
                         try {
                           await Notification.deleteOne({ _id: oid(req.params.id), userId: oid(req.jwt.uid) });
                           res.status(204).send();
                         } catch (e) { console.error('delete notif error:', e); res.status(500).json({ message: 'server error' }); }
                       });


                       // ─────────────── 404 핸들러 ───────────────
                       app.use((req, res, next) => {
                         if (req.path === '/favicon.ico') return res.status(204).send();
                         return res.status(404).json({ message: 'not found' });
                       });

                       // ─────────────── 공통 에러 핸들러 ───────────────
                       app.use((err, _req, res, _next) => {
                         console.error('Unhandled error:', err);
                         res.status(500).json({ message: 'server error' });
                       });

                       // ─────────────── 서버 실행(Graceful) ───────────────
                       const server = app.listen(PORT, () => {
                         console.log(`🚀 Server running on port ${PORT}`);
                       });
                       process.on('SIGTERM', () => server.close(() => process.exit(0)));
                       process.on('SIGINT',  () => server.close(() => process.exit(0)));

      { $set: update },
      { new: true, lean: true }
    );
    if (!admin) return res.status(404).json({ message: 'not found' });

    return res.json({ data: hospitalAdminProfileDto(admin) });
  } catch (e) {
    console.error('PATCH /api/hospital-admin/profile error:', e);
    return res.status(500).json({ message: 'server error' });
  }
});

// ─────────────── 사용자 알림 API ───────────────

// 미확인 개수
app.get('/api/users/me/notifications/unread-count', auth, onlyUser, async (req, res) => {
  try {
    const q = { userId: oid(req.jwt.uid), read: false };
    if (req.query.hospitalId) q.hospitalId = oid(req.query.hospitalId);
    const count = await Notification.countDocuments(q);
    res.json({ count });
  } catch (e) { console.error('unread-count error:', e); res.status(500).json({ message: 'server error' }); }
});

// 목록 (커서 기반: _id 기준 내림차순)
app.get('/api/users/me/notifications', auth, onlyUser, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit || '20', 10), 100);
    const q = { userId: oid(req.jwt.uid) };
    if (req.query.hospitalId) q.hospitalId = oid(req.query.hospitalId);
    if (req.query.cursor) q._id = { $lt: oid(req.query.cursor) };

    const items = await Notification.find(q).sort({ _id: -1 }).limit(limit).lean();
    const nextCursor = items.length === limit ? String(items[items.length - 1]._id) : null;

    const data = items.map(n => ({
      id: n._id,
      type: n.type,
      title: n.title || '',
      message: n.message || '',
      createdAt: n.createdAt,
      read: !!n.read,
      hospitalId: n.hospitalId,
      hospitalName: n.hospitalName || '',
      meta: n.meta || {},
    }));
    res.json({ data, nextCursor });
  } catch (e) { console.error('list notifications error:', e); res.status(500).json({ message: 'server error' }); }
});

// 읽음 처리
app.patch('/api/users/me/notifications/:id/read', auth, onlyUser, async (req, res) => {
  try {
    await Notification.updateOne({ _id: oid(req.params.id), userId: oid(req.jwt.uid) }, { $set: { read: true } });
    res.status(204).send();
  } catch (e) { console.error('read notif error:', e); res.status(500).json({ message: 'server error' }); }
});

// 모두 읽음
app.post('/api/users/me/notifications/mark-all-read', auth, onlyUser, async (req, res) => {
  try {
    const q = { userId: oid(req.jwt.uid), read: false };
    if (req.query.hospitalId) q.hospitalId = oid(req.query.hospitalId);
    await Notification.updateMany(q, { $set: { read: true } });
    res.status(204).send();
  } catch (e) { console.error('mark-all-read error:', e); res.status(500).json({ message: 'server error' }); }
});

// 삭제(선택)
app.delete('/api/users/me/notifications/:id', auth, onlyUser, async (req, res) => {
  try {
    await Notification.deleteOne({ _id: oid(req.params.id), userId: oid(req.jwt.uid) });
    res.status(204).send();
  } catch (e) { console.error('delete notif error:', e); res.status(500).json({ message: 'server error' }); }
});


// ─────────────── 404 핸들러 ───────────────
app.use((req, res, next) => {
  if (req.path === '/favicon.ico') return res.status(204).send();
  return res.status(404).json({ message: 'not found' });
});

// ─────────────── 공통 에러 핸들러 ───────────────
app.use((err, _req, res, _next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ message: 'server error' });
});

// ─────────────── 서버 실행(Graceful) ───────────────
const server = app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
process.on('SIGTERM', () => server.close(() => process.exit(0)));
process.on('SIGINT',  () => server.close(() => process.exit(0)));
