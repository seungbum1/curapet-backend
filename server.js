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

// const 부분
// ────────────────────────────────────────────────────────────

// 업로드 폴더 생성
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(process.cwd(), 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

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
const UP_ROOT = path.join(process.cwd(), 'uploads');   // ✅ 수정: __dirname → process.cwd()
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
const ALLOWED_EXTS  = new Set(['.jpg', '.jpeg', '.png', '.gif', '.webp', '.heic', '.heif']);
const ALLOWED_MIMES = new Set([
  'image/jpeg',
  'image/jpg',           // ✅ 추가
  'image/png',
  'image/gif',
  'image/webp',
  'image/heic',
  'image/heif',
  'application/octet-stream' // ✅ iOS가 가끔 HEIC를 이렇게 보냄
]);

const EXT_BY_MIME = {
  'image/jpeg': '.jpg',
  'image/jpg':  '.jpg',
  'image/png':  '.png',
  'image/gif':  '.gif',
  'image/webp': '.webp',
  'image/heic': '.heic',
  'image/heif': '.heif',
  'application/octet-stream': '.heic', // ✅ iOS HEIC 추정치 (원하면 '.jpg'로 바꿔도 됨)
};


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

// 업로드 URL -> 실제 파일 경로로 안전 변환
function filePathFromPublicUrl(publicUrl) {
  try {
    const u = new URL(publicUrl);
    // 우리 서버의 /uploads/... 만 허용
    if (!u.pathname.startsWith('/uploads/')) return null;
    const fp = path.join(UPLOAD_DIR, u.pathname.replace(/^\/uploads\//, ''));
    // 디렉터리 이스케이프 방지
    const normalized = path.normalize(fp);
    if (!normalized.startsWith(path.normalize(UPLOAD_DIR))) return null;
    return normalized;
  } catch {
    return null;
  }
}

async function deleteFilesByUrls(urls = []) {
  for (const u of urls) {
    const fp = filePathFromPublicUrl(u);
    if (!fp) continue;
    try {
      await fs.promises.unlink(fp);
    } catch (e) {
      // 이미 없는 경우 등은 무시
      if (e.code !== 'ENOENT') console.warn('unlink error:', fp, e.message);
    }
  }
}

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

function issueToken(doc) {
  return jwt.sign({ uid: doc._id, role: doc.role }, JWT_SECRET, { expiresIn: '7d' });
}

function buildBaseUrl(req) {
  if (process.env.PUBLIC_BASE_URL) return process.env.PUBLIC_BASE_URL.replace(/\/+$/, '');
  const proto = req.get('x-forwarded-proto') || req.protocol;
  const host  = req.get('x-forwarded-host') || req.get('host');
  return `${proto}://${host}`;
}

function publicUrl(req, relativePath) {
  const base = buildBaseUrl(req);  // ✅ 여기로 변경
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

// 공통 함수로 분리 (기존 /send 로직을 이 함수로 옮기면 재사용 쉬움)
async function createAdminChatMessage(req, res) {
  try {
    const { userId, text } = req.body || {};
    if (!userId || !text || !String(text).trim()) {
      return res.status(400).json({ message: 'userId/text required' });
    }

    const admin = await HospitalUser.findById(oid(req.jwt.uid)).lean();
    if (!admin) return res.status(404).json({ message: 'hospital not found' });

    const user = await User.findById(oid(userId), { name:1, linkedHospitals:1 }).lean();
    if (!user) return res.status(404).json({ message: 'user not found' });

    const ok = (user.linkedHospitals || []).some(h =>
      String(h.hospitalId) === String(admin._id) && h.status === 'APPROVED'
    );
    if (!ok) return res.status(403).json({ message: 'link to user required (APPROVED)' });

    const doc = await ChatMessage.create({
      hospitalId: oid(req.jwt.uid),
      userId: oid(userId),
      senderRole: 'ADMIN',
      senderId: oid(req.jwt.uid),
      senderName: (admin.name || admin.hospitalName || '병원').trim(),
      text: String(text),
      readByUser: false,
      readByAdmin: true,
    });

    await pushNotificationOne({
      userId: user._id,
      hospitalId: oid(req.jwt.uid),
      hospitalName: admin.hospitalName || '',
      type: 'CHAT_ADMIN_TO_USER',
      title: `${admin.hospitalName || '병원'} 메시지`,
      message: String(text).slice(0, 80),
      meta: { chatMessageId: doc._id }
    });

    return res.status(201).json({
      _id: doc._id,
      senderRole: doc.senderRole,
      senderId: doc.senderId,
      senderName: doc.senderName,
      text: doc.text,
      createdAt: doc.createdAt,
    });
  } catch (e) {
    console.error('createAdminChatMessage error:', e);
    return res.status(500).json({ message: 'server error' });
  }
}

// ────────────────────────────────────────────────────────────
const onlyUser = (req, res, next) =>
  req.jwt?.role === 'USER' ? next() : res.status(403).json({ message: 'for USER' });
const onlyHospitalAdmin = (req, res, next) =>
  req.jwt?.role === 'HOSPITAL_ADMIN' ? next() : res.status(403).json({ message: 'for HOSPITAL_ADMIN' });

const oid = (v) => {
  if (v instanceof mongoose.Types.ObjectId) return v;
  try { return new mongoose.Types.ObjectId(String(v)); } catch { return null; }
};






// ────────────────────────────────────────────────────────────
// ─────────────── Mongoose server───────────────
// ────────────────────────────────────────────────────────────
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

// ─────────────── 스키마 server───────────────

// 체중/체성분 기록 (배열 원소에 개별 _id 불필요 → _id:false)
const HealthWeightSchema = new mongoose.Schema(
  {
    date:        { type: Date, required: true, index: true },
    bodyWeight:  { type: Number, default: null }, // kg
    muscleMass:  { type: Number, default: null }, // kg
    bodyFatMass: { type: Number, default: null }, // kg
  },
  { _id: false }
);

// 활동량 기록
const HealthActivitySchema = new mongoose.Schema(
  {
    date:     { type: Date, required: true, index: true },
    time:     { type: Number, default: null }, // 분
    calories: { type: Number, default: null }, // kcal
  },
  { _id: false }
);

// 섭취 기록
const HealthIntakeSchema = new mongoose.Schema(
  {
    date:  { type: Date, required: true, index: true },
    food:  { type: Number, default: null }, // g 또는 kcal (클라이언트 규약에 맞춰 사용)
    water: { type: Number, default: null }, // ml
  },
  { _id: false }
);

// 일기(Diary) — 배열 원소에 _id 필요(.id()로 접근) → 기본값 사용
const DiarySchema = new mongoose.Schema(
  {
    title:     { type: String, default: '' },
    content:   { type: String, default: '' },
    date:      { type: Date,   default: Date.now, index: true },
    imagePath: { type: String, default: '' }, // 업로드 경로 또는 URL
  },
  { _id: true }
);

// 복약 알람(Alarm) — 배열 원소에 _id 필요(.id()로 접근)
const AlarmSchema = new mongoose.Schema(
  {
    time:          { type: String,  required: true },         // 'HH:mm' 등 클라 규약
    label:         { type: String,  required: true },
    isActive:      { type: Boolean, default: true },
    // 요일: 0(일)~6(토) 같은 정수 배열. (클라가 문자열 사용 시 문자열 배열로 바꿔도 OK)
    repeatDays:    [{ type: Number }],                        // 예: [1,4] → 월/목
    // 다시 울림 분. null 허용 → undefined과 구분하려면 클라에서 필드 자체를 보내기
    snoozeMinutes: { type: Number, default: null },
  },
  { _id: true }
);

// PetProfile 전체
const PetProfileSchema = new mongoose.Schema(
  {
    // 기본 프로필
    name:      { type: String, default: '' },
    age:       { type: Number, default: 0 },
    gender:    { type: String, default: '' },
    species:   { type: String, default: '' },
    avatarUrl: { type: String, default: '' },

    // 건강 기록
    healthChart: {
      weight:   { type: [HealthWeightSchema],   default: [] },
      activity: { type: [HealthActivitySchema], default: [] },
      intake:   { type: [HealthIntakeSchema],   default: [] },
    },

    // 일기 & 알람
    diaries: { type: [DiarySchema],  default: [] },
    alarms:  { type: [AlarmSchema],  default: [] },
  },
  { _id: false }
);

const userSchema = new mongoose.Schema({
  email:        { type: String, required: true, unique: true, index: true },
  passwordHash: { type: String, required: true },
  name:         { type: String, default: '' },
  role:         { type: String, enum: ['USER'], default: 'USER', index: true },
  birthDate:    { type: String, default: '' },

  petProfile:   { type: PetProfileSchema, default: {} },

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

// 연동 요청
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

// 병원 메타
const hospitalMetaSchema = new mongoose.Schema({
  hospitalId:   { type: mongoose.Schema.Types.ObjectId, required: true, unique: true, index: true },
  hospitalName: { type: String, default: '' },
  notice:       { type: String, default: '' },
  services:     [{ type: String }],
  doctors:      [{ id: String, name: String }],
}, { timestamps: true });

// 병원 예약 (기존)
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

// 사용자 예약 복제 스키마
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
  patientId:    { type: mongoose.Schema.Types.ObjectId, required: true, index: true }, // 🔴 추가
  userId:       { type: mongoose.Schema.Types.ObjectId, index: true },
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

// ─────────────── Chat 스키마 ───────────────
const chatMessageSchema = new mongoose.Schema({
  hospitalId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  userId:     { type: mongoose.Schema.Types.ObjectId, required: true, index: true },

  // USER | ADMIN
  senderRole: { type: String, enum: ['USER','ADMIN'], required: true, index: true },
  senderId:   { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  senderName: { type: String, default: '' },

  text:       { type: String, required: true },
  createdAt:  { type: Date, default: Date.now, index: true },

  // 읽음표시: 수신자 기준으로 관리
  readByUser:  { type: Boolean, default: false, index: true },   // 사용자가 읽음
  readByAdmin: { type: Boolean, default: false, index: true },   // 관리자가 읽음
}, { versionKey: false });
chatMessageSchema.index({ hospitalId: 1, userId: 1, createdAt: -1 });

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

/* 병원 공지 스키마 */
const hospitalNoticeSchema = new mongoose.Schema({
  hospitalId:   { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  hospitalName: { type: String, default: '' },
  title:        { type: String, required: true },
  content:      { type: String, required: true },
  createdBy:    { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
}, { timestamps: true });

// 건강관리(헬스) 스키마 — user_db에 둔다
const healthRecordSchema = new mongoose.Schema({
  userId:     { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  date:       { type: String, required: true, index: true }, // 'YYYY-MM-DD'
  time:       { type: String, default: '' },                  // 'HH:mm' (옵션)
  dateTime:   { type: Date, index: true },
  // 측정/기록 항목 (원하는 것만 사용)
  weight:     { type: Number, default: null },
  height:     { type: Number, default: null },
  temperature:{ type: Number, default: null },
  systolic:   { type: Number, default: null }, // 수축
  diastolic:  { type: Number, default: null }, // 이완
  heartRate:  { type: Number, default: null },
  glucose:    { type: Number, default: null }, // 혈당
  memo:       { type: String,  default: '' },
}, { timestamps: true });
healthRecordSchema.index({ userId: 1, dateTime: -1 });

const HealthRecord = userConn.model('HealthRecord', healthRecordSchema, 'health_records');

// 3) Product 스키마 & 모델
// =====================================================
const productSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    category: { type: String, default: "간식" },
    description: { type: String, default: "" },
    price: { type: Number, required: true },
    quantity: { type: Number, default: 1 },

    // 이미지 배열
    images: { type: [String], default: [] },

    // 리뷰 기능
    reviews: [
      {
        userName: String,
        rating: Number,
        comment: String,
        createdAt: { type: Date, default: Date.now },
      },
    ],
    averageRating: { type: Number, default: 0 },
  },
  { timestamps: true }
);

const cartSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  productId: String,
  count: Number,
}, { timestamps: true });

const Cart = userConn.model("Cart", cartSchema, "carts");

// user_db에 저장할 Order 스키마
const orderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  userName: String,
  address: String,
  phone: String,

  product: {
    _id: String,
    name: String,
    category: String,
    price: Number,
    quantity: Number,
    image: String,
  },

  payment: {
    method: String,
    totalAmount: Number,
  },

  status: { type: String, default: "결제완료" },
}, { timestamps: true });

const Order = userConn.model("Order", orderSchema, "orders");

// ─────────────── 모델 server ───────────────

const User                = userConn.model('User', userSchema, 'users');
const HospitalUser        = hospitalConn.model('HospitalUser', hospitalUserSchema, 'hospital_user');
const Product = hospitalConn.model("Product", productSchema, "products");
const HospitalLinkRequest = hospitalConn.model('HospitalLinkRequest', hospitalLinkRequestSchema, 'hospital_link_requests');
const HospitalMeta        = hospitalConn.model('HospitalMeta', hospitalMetaSchema, 'hospital_meta');
const Appointment         = hospitalConn.model('Appointment', appointmentSchema, 'appointments');
const MedicalHistory      = hospitalConn.model('MedicalHistory', medicalHistorySchema, 'medical_histories');
const UserAppointment     = userConn.model('UserAppointment', userAppointmentSchema, 'user_appointments');
const PetCare             = hospitalConn.model('PetCare', petCareSchema, 'pet_care');
const SosLog = hospitalConn.model('SosLog', sosLogSchema, 'sos_logs');
const Notification = userConn.model('Notification', notificationSchema, 'notifications');
const HospitalNotice = hospitalConn.model('HospitalNotice', hospitalNoticeSchema, 'hospital_notices');
const ChatMessage = hospitalConn.model('ChatMessage', chatMessageSchema, 'chat_messages');

// ─────────────── 헬스 & 루트 ───────────────
// ────────────────────────────────────────────────────────────

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





// ────────────────────────────────────────────────────────────
// 병원 server
// ────────────────────────────────────────────────────────────

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

// ✅ 병원 공지사항 단일 조회 (최신 공지 1건, 항상 200 반환)
app.get('/api/hospitals/:hospitalId/notice', async (req, res) => {
  try {
    const { hospitalId } = req.params;

    // 🔴 ObjectId로 조회
    const hid = oid(hospitalId);

    // 🔴 HospitalNotice에서 최신 1건
    const last = await HospitalNotice
      .findOne({ hospitalId: hid })
      .sort({ createdAt: -1 })
      .lean();

    // 🔴 보여줄 문자열 구성 (원하면 형식 조절 가능)
    const title = (last?.title || '').toString().trim();
    const content = (last?.content || '').toString().trim();

    // 예) [공지] 타이틀 · 첫줄
    const firstLine = content.split('\n').map(s => s.trim()).filter(Boolean)[0] || '';
    const notice = title || firstLine
      ? `[공지] ${title}${firstLine ? ' · ' + firstLine : ''}`
      : '';

    // 🔴 항상 200으로 반환 (비어 있으면 빈 문자열)
    return res.json({ notice });
  } catch (err) {
    console.error('GET /api/hospitals/:hospitalId/notice error:', err);
    // 🔴 에러 상황에서도 배너 깨지지 않게 200 + 빈 문자열
    return res.json({ notice: '' });
  }
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

// 관리자: 특정 사용자와의 채팅 메시지 목록(증분)
app.get('/api/hospital-admin/chat/messages', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const { userId } = req.query || {};
    if (!userId) return res.status(400).json({ message: 'userId required' });

    const hid = oid(req.jwt.uid);
    const uid = oid(userId);
    if (!hid || !uid) return res.status(400).json({ message: 'invalid id' });

    // 사용자 존재/연동 확인
    const user = await User.findById(uid, { linkedHospitals: 1, name: 1 }).lean();
    if (!user) return res.status(404).json({ message: 'user not found' });
    const linked = (user.linkedHospitals || []).some(h =>
      String(h.hospitalId) === String(hid) && h.status === 'APPROVED'
    );
    if (!linked) return res.status(403).json({ message: 'link to user required (APPROVED)' });

    const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
    const since = req.query.since ? new Date(String(req.query.since)) : null;

    const q = { hospitalId: hid, userId: uid };
    if (since && !isNaN(since.getTime())) q.createdAt = { $gt: since };

    const list = await ChatMessage.find(q).sort({ createdAt: 1 }).limit(limit).lean();

    // 응답 포맷은 사용자측과 동일하게
    return res.json(list.map(m => ({
      _id: m._id,
      senderRole: m.senderRole,
      senderId: m.senderId,
      senderName: m.senderName,
      text: m.text,
      createdAt: m.createdAt,
    })));
  } catch (e) {
    console.error('GET admin chat messages error:', e);
    return res.status(500).json({ message: 'server error' });
  }
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
      { $project: { _id: '$_id', userId: '$_id', userName: '$name', petName: '$petProfile.name' } },
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

// ======================================================================
// ─────────────── 병원관리자: 케어일지 목록/등록 ───────────────
// ======================================================================

app.get('/api/hospital-admin/pet-care', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const { patientId } = req.query;
    const keyword = (req.query.keyword || '').toString().trim();
    const sortKey = (req.query.sort || 'dateDesc').toString();

    if (!patientId) {
      return res.status(400).json({ message: 'patientId required' });
    }

    // ✅ 이 유저가 이 병원과 APPROVED 연동인지 검증
    const patientUser = await User.findOne({
      _id: oid(patientId),
      linkedHospitals: { $elemMatch: { hospitalId: oid(req.jwt.uid), status: 'APPROVED' } },
    }).select('_id').lean();
    if (!patientUser) {
      return res.status(404).json({ message: 'patient not found in this hospital' });
    }

    const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
    const page  = Math.max(parseInt(req.query.page  || '1', 10), 1);
    const skip  = (page - 1) * limit;
    const sort  = (sortKey === 'dateAsc') ? 1 : -1;

    // ✅ hospitalId + patientId(User._id) 로 조회
    const q = {
      hospitalId: oid(req.jwt.uid),
      patientId : oid(patientId),
    };
    if (keyword) {
      const rx = new RegExp(keyword, 'i');
      q.$or = [{ memo: rx }];
    }

    const [items, total] = await Promise.all([
      PetCare.find(q)
        .sort({ dateTime: sort, createdAt: sort })
        .skip(skip)
        .limit(limit)
        .lean(),
      PetCare.countDocuments(q),
    ]);

    const data = items.map(d => ({
      _id      : d._id,
      date     : d.date || '',
      time     : d.time || '',
      dateTime : d.dateTime,
      memo     : d.memo || '',
      imageUrl : (d.images && d.images.length) ? d.images[0] : '',
      images   : d.images || [],
      patientId: d.patientId, // == User._id
    }));

    return res.json({ data, paging: { total, page, limit } });
  } catch (e) {
    console.error('GET /api/hospital-admin/pet-care error:', e);
    return res.status(500).json({ message: 'server error' });
  }
});

app.post(
  '/api/hospital-admin/pet-care',
  auth,
  onlyHospitalAdmin,
  uploadLimiter,
  upload.array('images', 10),
  async (req, res) => {
    try {
      const { patientId } = req.body;
      const date = (req.body.date || '').toString().trim();
      const time = (req.body.time || '').toString().trim();
      const memo = (req.body.memo || '').toString().trim();

      if (!patientId) return res.status(400).json({ message: 'patientId required' });
      if (!date || !time) return res.status(400).json({ message: 'date/time required' });

      // ✅ 이 유저가 이 병원과 APPROVED 연동인지 검증
      const patientUser = await User.findOne({
        _id: oid(patientId),
        linkedHospitals: { $elemMatch: { hospitalId: oid(req.jwt.uid), status: 'APPROVED' } },
      }).select('_id name petProfile').lean();
      if (!patientUser) {
        return res.status(404).json({ message: 'patient not found in this hospital' });
      }

      const urls = (req.files || []).map(f =>
        publicUrl(req, `/uploads/pet-care/${path.basename(f.path)}`)
      );

      const dt = new Date(`${date}T${time}:00`);

      const hospitalName =
        (await HospitalUser.findById(oid(req.jwt.uid)).select('hospitalName').lean())
          ?.hospitalName || '';

      const doc = await PetCare.create({
        hospitalId  : oid(req.jwt.uid),
        hospitalName,
        createdBy   : oid(req.jwt.uid),

        // ✅ 통일: patientId = User._id, userId도 동일하게
        patientId   : oid(patientId),
        userId      : oid(patientId),

        date,
        time,
        dateTime    : isNaN(dt.getTime()) ? new Date() : dt,
        memo,
        images      : urls,
      });

      const created = doc.toJSON();

      await pushNotificationMany({
        userIds     : [oid(patientId)],
        hospitalId  : oid(req.jwt.uid),
        hospitalName,
        type        : 'PET_CARE_POSTED',
        title       : '새 반려 일지가 올라왔어요',
        message     : memo ? memo.slice(0, 80) : '이미지/메모가 등록되었습니다.',
        meta        : { petCareId: created._id, imageUrl: urls[0] || '' },
      });

      return res.status(201).json({
        data: {
          _id      : created._id,
          date     : created.date,
          time     : created.time,
          dateTime : created.dateTime,
          memo     : created.memo,
          imageUrl : (created.images && created.images.length) ? created.images[0] : '',
          images   : created.images || [],
          patientId: created.patientId, // == User._id
        }
      });
    } catch (e) {
      console.error('POST /api/hospital-admin/pet-care error:', e);
      return res.status(500).json({ message: e?.message || 'server error' });
    }
  }
);


// ───────────────병원 예약 메타/신청 ───────────────

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

// ─────────────── 병원관리자: 공지 목록/등록 ───────────────

app.get('/api/hospital-admin/notices', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const hid = oid(req.query.hospitalId || req.jwt.uid);
    const list = await HospitalNotice.find({ hospitalId: hid })
      .sort({ createdAt: -1 })
      .select('_id title content createdAt')  // 필요한 필드만
      .lean();

    // 플러터 파서가 배열/객체 둘 다 처리하므로 객체로 통일
    return res.json({ data: list.map(n => ({
      id: n._id,
      _id: n._id,
      title: n.title,
      content: n.content,
      createdAt: n.createdAt,
    })) });
  } catch (e) {
    console.error('GET /api/hospital-admin/notices error:', e);
    return res.status(500).json({ message: 'server error' });
  }
});

app.post('/api/hospital-admin/notices', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const { title, content } = req.body || {};
    const hid = oid(req.body?.hospitalId || req.jwt.uid);
    if (!title || !content) return res.status(400).json({ message: 'title/content required' });

    const h = await HospitalUser.findById(hid).lean();
    const hospitalName = h?.hospitalName || '';

    const doc = await HospitalNotice.create({
      hospitalId: hid,
      hospitalName,
      title: String(title).trim(),
      content: String(content).trim(),
      createdBy: oid(req.jwt.uid),
    });


    const approvedUsers = await User.find({
      linkedHospitals: { $elemMatch: { hospitalId: hid, status: 'APPROVED' } }
    }).select('_id').lean();

    await pushNotificationMany({
      userIds: approvedUsers.map(u => u._id),
      hospitalId: hid,
      hospitalName,
      type: 'HOSPITAL_NOTICE',
      title: `[공지] ${doc.title}`.slice(0, 40),
      message: doc.content.slice(0, 120),
      meta: { noticeId: doc._id }
    });

    return res.status(201).json({
      data: {
        id: doc._id,
        _id: doc._id,
        title: doc.title,
        content: doc.content,
        createdAt: doc.createdAt,
      }
    });
  } catch (e) {
    console.error('POST /api/hospital-admin/notices error:', e);
    return res.status(500).json({ message: 'server error' });
  }
});

app.get('/api/hospitals/:hospitalId/admin/summary', async (req, res) => {
  try {
    const h = await HospitalUser.findById(oid(req.params.hospitalId)).lean();
    if (!h) return res.status(404).json({ message: 'hospital not found' });
    const doctorName = (h.hospitalProfile?.doctorName || h.name || '').trim() || '김철수 원장';
    res.json({ doctorName });
  } catch (e) {
    console.error('admin summary error:', e);
    res.status(500).json({ message: 'server error' });
  }
});





// ======================================================================
// ─────────────── 건강관리 server───────────────
// ======================================================================

app.post('/users/me/health-record', auth, onlyUser, async (req, res) => {
  try {
    const userId = req.jwt.uid;
    const { date, weight, activity, intake } = req.body;

    if (!date) {
      return res.status(400).json({ message: '날짜는 필수입니다.' });
    }
    console.log(`✅ 건강 기록 추가 요청 (사용자: ${userId}):`, req.body);

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: '사용자를 찾을 수 없습니다.' });
    }

    if (!user.petProfile) user.petProfile = {};
    if (!user.petProfile.healthChart) {
      user.petProfile.healthChart = { weight: [], activity: [], intake: [] };
    }

    const recordDate = new Date(date);

    // 1. 체중 데이터 처리
    if (weight && typeof weight.bodyWeight === 'number') {
      const weightRecord = {
        date: recordDate,
        bodyWeight: weight.bodyWeight,
        // ✅ 나머지 상세 데이터도 null/undefined가 아닐 경우에만 추가
        ...(typeof weight.muscleMass === 'number' && { muscleMass: weight.muscleMass }),
        ...(typeof weight.bodyFatMass === 'number' && { bodyFatMass: weight.bodyFatMass }),
      };
      user.petProfile.healthChart.weight.push(weightRecord);
    }

    // 2. 활동량 데이터 처리
    if (activity && typeof activity.time === 'number') {
      const activityRecord = {
        date: recordDate,
        time: activity.time,
        ...(typeof activity.calories === 'number' && { calories: activity.calories }),
      };
      user.petProfile.healthChart.activity.push(activityRecord);
    }

    // 3. 섭취량 데이터 처리
    if (intake && typeof intake.food === 'number') {
      const intakeRecord = {
        date: recordDate,
        food: intake.food,
        ...(typeof intake.water === 'number' && { water: intake.water }),
      };
      user.petProfile.healthChart.intake.push(intakeRecord);
    }

    await user.save();

    console.log('💾 건강 기록이 DB에 저장되었습니다.');
    return res.status(200).json({ petProfile: user.petProfile });

  } catch (error) {
    console.error('❌ 건강 기록 저장 중 오류:', error);
    return res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});


app.delete('/users/health-record', auth, onlyUser, async (req, res) => {
  try {
    const userId = req.jwt.uid;
    const { date } = req.body; // ex) '2025-10-20T15:05:58.000Z'

    console.log('--- 🎯 특정 시간 기록 동시 삭제 요청 수신 ---');
    console.log('요청 Body:', { date });

    if (!date) {
      return res.status(400).json({ message: '삭제할 날짜(시간) 정보가 필요합니다.' });
    }

    // 프론트에서 받은 ISO 시간 문자열을 Date로 변환해 정확 일치 삭제
    const targetDate = new Date(date);

    await User.updateOne(
      { _id: userId },
      {
        $pull: {
          'petProfile.healthChart.weight':   { date: targetDate },
          'petProfile.healthChart.activity': { date: targetDate },
          'petProfile.healthChart.intake':   { date: targetDate },
        }
      }
    );

    console.log(`✅ 성공: '${targetDate.toISOString()}' 시간의 기록을 모두 삭제했습니다.`);
    return res.status(204).send();
  } catch (error) {
    console.error('❌ 특정 시간 기록 삭제 중 오류:', error);
    return res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// ✅✅✅ 일기(Diary) CRUD API
// [GET] 내 모든 일기 목록 조회
app.get('/diaries', auth, onlyUser, async (req, res) => {
  try {
    const user = await User.findById(req.jwt.uid, { 'petProfile.diaries': 1 }).lean();
    if (!user || !user.petProfile) return res.json([]);

    // 날짜 내림차순 정렬
    const sorted = [...(user.petProfile.diaries || [])]
      .sort((a, b) => new Date(b.date) - new Date(a.date));

    return res.json(sorted);
  } catch (e) {
    console.error('GET /diaries error:', e);
    return res.status(500).json({ message: 'Server error' });
  }
});

// [POST] 새 일기 작성 (이미지 업로드는 multipart/form-data, 키: image)
app.post('/diaries', auth, onlyUser, upload.single('image'), async (req, res) => {
  try {
    const user = await User.findById(req.jwt.uid);
    if (!user) return res.status(404).json({ message: 'User not found' });

    const { title, content, date } = req.body;
    const imagePath = req.file ? req.file.path : '';

    if (!user.petProfile) user.petProfile = {};
    if (!user.petProfile.diaries) user.petProfile.diaries = [];

    const newDiary = {
      title: (title || '').toString(),
      content: (content || '').toString(),
      date: new Date(date),
      imagePath,
    };

    user.petProfile.diaries.push(newDiary);
    await user.save();

    const saved = user.petProfile.diaries[user.petProfile.diaries.length - 1];
    return res.status(201).json(saved);
  } catch (e) {
    console.error('POST /diaries error:', e);
    return res.status(500).json({ message: 'Server error' });
  }
});

// [PUT] 특정 일기 수정
app.put('/diaries/:id', auth, onlyUser, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, content, date, imagePath } = req.body;

    const user = await User.findById(req.jwt.uid);
    if (!user?.petProfile?.diaries) return res.status(404).json({ message: 'Diary not found' });

    const diary = user.petProfile.diaries.id(id);
    if (!diary) return res.status(404).json({ message: 'Diary not found' });

    diary.set({
      ...(title !== undefined ? { title } : {}),
      ...(content !== undefined ? { content } : {}),
      ...(date !== undefined ? { date: new Date(date) } : {}),
      ...(imagePath !== undefined ? { imagePath } : {}),
    });

    await user.save();
    return res.json(diary);
  } catch (e) {
    console.error('PUT /diaries/:id error:', e);
    return res.status(500).json({ message: 'Server error' });
  }
});

// [DELETE] 특정 일기 삭제
app.delete('/diaries/:id', auth, onlyUser, async (req, res) => {
  try {
    const { id } = req.params;
    await User.updateOne(
      { _id: req.jwt.uid },
      { $pull: { 'petProfile.diaries': { _id: id } } }
    );
    return res.status(204).send();
  } catch (e) {
    console.error('DELETE /diaries/:id error:', e);
    return res.status(500).json({ message: 'Server error' });
  }
});

// ✅✅✅ 복약 알림(Alarms) CRUD API
// [GET] 내 모든 알림 목록 조회
app.get('/users/me/alarms', auth, onlyUser, async (req, res) => {
  try {
    const user = await User.findById(req.jwt.uid, { 'petProfile.alarms': 1 }).lean();
    if (!user || !user.petProfile) return res.json([]);
    return res.json(user.petProfile.alarms || []);
  } catch (e) {
    console.error('GET /users/me/alarms error:', e);
    return res.status(500).json({ message: 'Server error' });
  }
});

// [POST] 새 알림 추가 (확장 필드 포함)
app.post('/users/me/alarms', auth, onlyUser, async (req, res) => {
  try {
    const { time, label, isActive, repeatDays, snoozeMinutes } = req.body;
    if (!time || !label) {
      return res.status(400).json({ message: 'Time and label are required.' });
    }

    const user = await User.findById(req.jwt.uid);
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (!user.petProfile) user.petProfile = {};
    if (!user.petProfile.alarms) user.petProfile.alarms = [];

    const newAlarm = {
      time,
      label,
      isActive: isActive !== false,
      repeatDays: Array.isArray(repeatDays) ? repeatDays : [],
      // null 허용 → hasOwnProperty 로 구분해 저장
      ...(req.body.hasOwnProperty('snoozeMinutes') ? { snoozeMinutes } : {}),
    };

    user.petProfile.alarms.push(newAlarm);
    await user.save();

    const saved = user.petProfile.alarms[user.petProfile.alarms.length - 1];
    return res.status(201).json(saved);
  } catch (e) {
    console.error('POST /users/me/alarms error:', e);
    return res.status(500).json({ message: 'Server error' });
  }
});

// [PUT] 특정 알림 수정 (부분 업데이트 허용)
app.put('/users/me/alarms/:id', auth, onlyUser, async (req, res) => {
  try {
    const { id } = req.params;
    const { time, label, isActive, repeatDays, snoozeMinutes } = req.body;

    const user = await User.findById(req.jwt.uid);
    if (!user?.petProfile?.alarms) return res.status(404).json({ message: 'Alarm not found' });

    const alarm = user.petProfile.alarms.id(id);
    if (!alarm) return res.status(404).json({ message: 'Alarm not found' });

    if (time !== undefined) alarm.time = time;
    if (label !== undefined) alarm.label = label;
    if (isActive !== undefined) alarm.isActive = isActive;
    if (repeatDays !== undefined) alarm.repeatDays = repeatDays;
    if (req.body.hasOwnProperty('snoozeMinutes')) alarm.snoozeMinutes = snoozeMinutes;

    await user.save();
    return res.json(alarm);
  } catch (e) {
    console.error('PUT /users/me/alarms/:id error:', e);
    return res.status(500).json({ message: 'Server error' });
  }
});

// [DELETE] 특정 알림 삭제
app.delete('/users/me/alarms/:id', auth, onlyUser, async (req, res) => {
  try {
    const { id } = req.params;
    await User.updateOne(
      { _id: req.jwt.uid },
      { $pull: { 'petProfile.alarms': { _id: id } } }
    );
    return res.status(204).send();
  } catch (e) {
    console.error('DELETE /users/me/alarms/:id error:', e);
    return res.status(500).json({ message: 'Server error' });
  }
});








// ======================================================================
// ─────────────── 사용자 server ───────────────
// ======================================================================

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

// ─────────────── USER ↔ ADMIN 1:1 채팅 (Admin 측) ───────────────

// 스레드 목록: 최근 메시지 기준으로 사용자별 요약 + 안읽음 수
app.get('/api/hospital-admin/chat/threads', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const hid = oid(req.jwt.uid);
    const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);

    // 최근 메시지 1건씩 뽑기
    const latest = await ChatMessage.aggregate([
      { $match: { hospitalId: hid } },
      { $sort: { createdAt: -1 } },
      { $group: {
          _id: '$userId',
          lastMessage: { $first: '$$ROOT' }
      }},
      { $limit: limit }
    ]);

    // 안읽음 수 계산
    const userIds = latest.map(x => x._id);
    const unreadAgg = await ChatMessage.aggregate([
      { $match: { hospitalId: hid, userId: { $in: userIds }, senderRole: 'USER', readByAdmin: false } },
      { $group: { _id: '$userId', cnt: { $sum: 1 } } }
    ]);
    const unreadMap = new Map(unreadAgg.map(a => [String(a._id), a.cnt]));

    // 사용자 이름 붙이기
    const users = await User.find({ _id: { $in: userIds } }).select('name petProfile').lean();
    const nameMap = new Map(users.map(u => [String(u._id), u.name || '사용자']));

    const data = latest.map(x => ({
      userId: String(x._id),
      userName: nameMap.get(String(x._id)) || '사용자',
      lastText: x.lastMessage.text,
      lastAt:   x.lastMessage.createdAt,
      unread:   unreadMap.get(String(x._id)) || 0,
    }));

    res.json({ data });
  } catch (e) {
    console.error('GET admin chat threads error:', e);
    res.status(500).json({ message: 'server error' });
  }
});

app.post(
  '/api/hospital-admin/chat/messages',
  auth, onlyHospitalAdmin,
  createAdminChatMessage
);

app.post(
  '/api/hospital-admin/chat/send',
  auth, onlyHospitalAdmin,
  createAdminChatMessage
);

// 읽음 처리(관리자가 해당 유저 채팅방 열었을 때)
app.post('/api/hospital-admin/chat/read-all', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const { userId } = req.body || {};
    if (!userId) return res.status(400).json({ message: 'userId required' });

    await ChatMessage.updateMany(
      { hospitalId: oid(req.jwt.uid), userId: oid(userId), senderRole: 'USER', readByAdmin: false },
      { $set: { readByAdmin: true } }
    );
    res.status(204).send();
  } catch (e) {
    console.error('POST admin chat read-all error:', e);
    res.status(500).json({ message: 'server error' });
  }
});

// ─────────────── USER ↔ ADMIN 1:1 채팅 (User 측) ───────────────

// 메시지 목록(증분)
app.get('/api/hospitals/:hospitalId/chat/messages', auth, onlyUser, async (req, res) => {
  try {
    const hid = oid(req.params.hospitalId);
    const me  = await User.findById(oid(req.jwt.uid), { linkedHospitals:1, name:1 }).lean();
    if (!me) return res.status(404).json({ message: 'user not found' });

    const linked = (me.linkedHospitals || []).find(x =>
      String(x.hospitalId) === String(hid) && x.status === 'APPROVED'
    );
    if (!linked) return res.status(403).json({ message: 'link to hospital required (APPROVED)' });

    const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
    const since = req.query.since ? new Date(String(req.query.since)) : null;

    const q = { hospitalId: hid, userId: oid(req.jwt.uid) };
    if (since && !isNaN(since.getTime())) q.createdAt = { $gt: since };

    const list = await ChatMessage.find(q).sort({ createdAt: 1 }).limit(limit).lean();
    res.json(list.map(m => ({
      _id: m._id,
      senderRole: m.senderRole,
      senderId: m.senderId,
      senderName: m.senderName,
      text: m.text,
      createdAt: m.createdAt,
    })));
  } catch (e) {
    console.error('GET user chat messages error:', e);
    res.status(500).json({ message: 'server error' });
  }
});

// 전송
app.post('/api/hospitals/:hospitalId/chat/send', auth, onlyUser, async (req, res) => {
  try {
    const hid = oid(req.params.hospitalId);
    const { text } = req.body || {};
    if (!text || !String(text).trim()) return res.status(400).json({ message: 'text required' });

    const me = await User.findById(oid(req.jwt.uid), { name:1, linkedHospitals:1 }).lean();
    if (!me) return res.status(404).json({ message: 'user not found' });

    const linked = (me.linkedHospitals || []).find(x =>
      String(x.hospitalId) === String(hid) && x.status === 'APPROVED'
    );
    if (!linked) return res.status(403).json({ message: 'link to hospital required (APPROVED)' });

    const admin = await HospitalUser.findById(hid).lean();
    if (!admin) return res.status(404).json({ message: 'hospital not found' });

    const doc = await ChatMessage.create({
      hospitalId: hid,
      userId: oid(req.jwt.uid),
      senderRole: 'USER',
      senderId: oid(req.jwt.uid),
      senderName: (me.name || '').trim() || '사용자',
      text: String(text),
      readByUser: true,      // 내가 보냈으니 사용자 읽음 true
      readByAdmin: false,    // 상대(관리자)는 아직 안 읽음
    });

    // (선택) 관리자 알림 저장
    await pushNotificationOne({
      userId: null, // 관리자는 유저DB가 아니라 알림DB 분리 시 스킵
      hospitalId: hid,
      hospitalName: admin.hospitalName || '',
      type: 'CHAT_USER_TO_ADMIN',
      title: '새 채팅 도착',
      message: String(text).slice(0, 80),
      meta: { userId: req.jwt.uid, chatMessageId: doc._id, healthRecordId: doc._id }
    });

    res.status(201).json({
      _id: doc._id,
      senderRole: doc.senderRole,
      senderId: doc.senderId,
      senderName: doc.senderName,
      text: doc.text,
      createdAt: doc.createdAt,
    });
  } catch (e) {
    console.error('POST user chat send error:', e);
    res.status(500).json({ message: 'server error' });
  }
});

// 읽음 처리(사용자가 채팅방 열었을 때)
app.post('/api/hospitals/:hospitalId/chat/read-all', auth, onlyUser, async (req, res) => {
  try {
    const hid = oid(req.params.hospitalId);
    await ChatMessage.updateMany(
      { hospitalId: hid, userId: oid(req.jwt.uid), senderRole: 'ADMIN', readByUser: false },
      { $set: { readByUser: true } }
    );
    res.status(204).send();
  } catch (e) {
    console.error('POST user chat read-all error:', e);
    res.status(500).json({ message: 'server error' });
  }
});

app.delete('/api/hospital-admin/pet-care/:id', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    // 1) 삭제 대상 가져오기 + 병원 소속 검증
    //    patient 테이블 join 없이, care 문서에 patientId가 있고 Patient에 hospitalId가 매칭되는 구조라면 아래처럼 확인:
    const care = await PetCareAdmin.findById(id).lean();
    if (!care) return res.status(404).json({ message: 'care not found' });

    // 필수: 이 케어의 환자가 이 병원 소속인지 확인
    const patient = await AdminConn.model('Patient')
      .findOne({ _id: care.patientId, hospitalId: req.jwt.uid })
      .select('_id')
      .lean();
    if (!patient) return res.status(403).json({ message: 'forbidden: not your patient' });

    // 2) 파일 삭제 (images 배열/단일 imageUrl 모두 대응)
    const urls = [];
    if (Array.isArray(care.images)) urls.push(...care.images.filter(Boolean));
    if (care.imageUrl) urls.push(care.imageUrl);
    await deleteFilesByUrls(urls);

    // 3) admin_db에서 문서 삭제
    await PetCareAdmin.deleteOne({ _id: id });

    // 4) user_db 미러 삭제 (최대한 동일 _id 사용 가정)
    try {
      await PetCareUser.deleteOne({ _id: id });
      // 만약 다른 키로 매핑했다면 예: await PetCareUser.deleteOne({ hospitalCareId: id });
    } catch (e) {
      console.warn('user_db mirror delete failed:', e.message);
      // 실패해도 200은 보냄(최선 수행). 필요 시 보상 큐 구성 가능.
    }

    return res.json({ ok: true });
  } catch (e) {
    console.error('delete care error:', e);
    return res.status(500).json({ message: 'internal error' });
  }
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

// ─────────────── 사용자 알림 API ───────────────

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

// ─────────────── 사용자: 케어일지 보기 ───────────────

app.get('/api/users/me/pet-care', auth, onlyUser, async (req, res) => {
  try {
    const { hospitalId, keyword = '', sort = 'dateDesc' } = req.query;
    if (!hospitalId) return res.status(400).json({ message: 'hospitalId required' });

    // ✅ 병원-사용자 링크(APPROVED) 확인
    const me = await User.findById(oid(req.jwt.uid), { linkedHospitals: 1 }).lean();
    const link = (me?.linkedHospitals || []).find(
      h => String(h.hospitalId) === String(hospitalId) && h.status === 'APPROVED'
    );
    if (!link) {
      return res.status(403).json({ message: 'link to hospital required (APPROVED)' });
    }

    const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
    const page  = Math.max(parseInt(req.query.page  || '1', 10), 1);
    const skip  = (page - 1) * limit;
    const s = (String(sort) === 'dateAsc') ? 1 : -1;

    // ✅ 그냥 나의 userId(=patientId)로 조회
    const q = {
      hospitalId: oid(hospitalId),
      patientId : oid(req.jwt.uid), // == User._id
    };
    if (String(keyword).trim()) {
      const rx = new RegExp(String(keyword).trim(), 'i');
      q.$or = [{ memo: rx }];
    }

    const [items, total] = await Promise.all([
      PetCare.find(q)
        .sort({ dateTime: s, createdAt: s })
        .skip(skip)
        .limit(limit)
        .lean(),
      PetCare.countDocuments(q),
    ]);

    const data = items.map(d => ({
      _id     : d._id,
      date    : d.date || '',
      time    : d.time || '',
      dateTime: d.dateTime,
      memo    : d.memo || '',
      imageUrl: (d.images && d.images.length) ? d.images[0] : '',
      images  : d.images || [],
      patientId: d.patientId, // == User._id
    }));

    res.json({ data, paging: { total, page, limit } });
  } catch (e) {
    console.error('GET /api/users/me/pet-care error:', e);
    res.status(500).json({ message: 'server error' });
  }
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

// 🔐 관리자(admin) 로그인
// ===============================
app.post('/auth/admin-login', (req, res) => {
  const { id, password } = req.body;

  // ✔ 기본 관리자 계정 (원하면 DB로도 바꿀 수 있음)
  const adminId = "admin";
  const adminPw = "admin";

  if (id === adminId && password === adminPw) {
    const token = jwt.sign(
      { admin: true, role: "MASTER_ADMIN" },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    return res.json({
      message: "관리자 로그인 성공",
      token,
    });
  }

  return res.status(401).json({ message: "아이디 또는 비밀번호가 틀렸습니다." });
});

// 1) 이미지 업로드
//------------------------------------------------------

app.post("/upload", upload.single("image"), (req, res) => {
  if (!req.file) return res.status(400).json({ message: "이미지 없음" });

  const fileUrl = `/uploads/pet-care/${req.file.filename}`;
  res.json({ imageUrl: fileUrl });
});

//------------------------------------------------------
// 2) 상품 CRUD API
//------------------------------------------------------

// ⭐ 상품 등록 (POST /products)
app.post("/products", async (req, res) => {
  try {
    const product = new Product(req.body);
    await product.save();

    res.json({ message: "상품 등록 성공", product });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ⭐ 상품 목록 조회 (GET /products)
app.get("/products", async (req, res) => {
  try {
    const items = await Product.find().sort({ createdAt: -1 }).lean();
    res.json(items);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ⭐ 상품 단일 조회 (GET /products/:id)
app.get("/products/:id", async (req, res) => {
  try {
    const item = await Product.findById(req.params.id).lean();
    if (!item) return res.status(404).json({ message: "상품 없음" });
    res.json(item);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ⭐ 상품 수정 (PUT /products/:id)
app.put("/products/:id", async (req, res) => {
  try {
    const updated = await Product.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );

    if (!updated) return res.status(404).json({ message: "상품 없음" });
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ⭐ 수량 변경 (PATCH /products/:id/quantity)
app.patch("/products/:id/quantity", async (req, res) => {
  try {
    const { quantity } = req.body;

    const updated = await Product.findByIdAndUpdate(
      req.params.id,
      { quantity },
      { new: true }
    );

    if (!updated) return res.status(404).json({ message: "상품 없음" });

    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ⭐ 상품 삭제 (DELETE /products/:id)
app.delete("/products/:id", async (req, res) => {
  try {
    const deleted = await Product.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ message: "상품 없음" });

    // 이미지 파일 삭제
    if (deleted.images?.length > 0) {
      deleted.images.forEach((url) => {
        const filePath = "." + url;
        fs.unlink(filePath, (err) => {
          if (err) console.log("이미지 삭제 실패:", err.message);
        });
      });
    }

    res.json({ message: "상품 삭제 성공", deleted });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

//------------------------------------------------------
// 3) 리뷰 기능
//------------------------------------------------------

// ⭐ 리뷰 등록 (POST /products/:id/reviews)
app.post("/products/:id/reviews", async (req, res) => {
  try {
    const { userName, rating, comment } = req.body;

    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: "상품 없음" });

    product.reviews.push({ userName, rating, comment });

    // ⭐ 평균 평점 계산
    const total = product.reviews.reduce((sum, r) => sum + r.rating, 0);
    product.averageRating = total / product.reviews.length;

    await product.save();
    res.json({ message: "리뷰 등록 성공", product });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ⭐ 리뷰 삭제
app.delete("/products/:productId/reviews/:reviewId", async (req, res) => {
  try {
    const { productId, reviewId } = req.params;

    const product = await Product.findById(productId);
    if (!product) return res.status(404).json({ message: "상품 없음" });

    product.reviews = product.reviews.filter(
      (r) => r._id.toString() !== reviewId
    );

    // ⭐ 평균 평점 재계산
    if (product.reviews.length > 0) {
      const total = product.reviews.reduce((sum, r) => sum + r.rating, 0);
      product.averageRating = total / product.reviews.length;
    } else {
      product.averageRating = 0;
    }

    product.markModified("reviews");
    await product.save();

    res.json({ message: "리뷰 삭제 성공" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ⭐ 주문 생성 API
app.post("/users/:userId/orders", async (req, res) => {
  try {
    const userId = req.params.userId;

    const newOrder = await Order.create({
      userId,
      ...req.body,
    });

    res.status(201).json(newOrder);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/users/:userId/orders", async (req, res) => {
  try {
    const userId = req.params.userId;

    const list = await Order.find({ userId })
      .sort({ createdAt: -1 })
      .lean();

    res.json(list);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/users/:userId/cart", async (req, res) => {
  try {
    const list = await Cart.find({ userId: req.params.userId }).lean();
    res.json(list);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post("/users/:userId/cart", async (req, res) => {
  try {
    const cart = await Cart.create({
      userId: req.params.userId,
      productId: req.body.productId,
      count: req.body.count,
    });
    res.json(cart);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.delete("/users/:userId/cart/:productId", async (req, res) => {
  try {
    await Cart.deleteOne({
      userId: req.params.userId,
      productId: req.params.productId
    });
    res.json({ message: "장바구니 삭제 완료" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
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
