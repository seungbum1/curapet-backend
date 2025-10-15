// server.js
require('dotenv').config();
const path   = require('path');
const fs     = require('fs');
const multer = require('multer');

const express  = require('express');
const mongoose = require('mongoose');
const cors     = require('cors');
const bcrypt   = require('bcrypt');
const jwt      = require('jsonwebtoken');

const MONGODB_URI = process.env.MONGODB_URI;
const PORT        = process.env.PORT || 4000;

const app = express();

// CORS: 초기엔 전부 허용(배포 후 프런트 도메인으로 제한 권장)
app.use(cors());
app.use(express.json());

// ───────────────── 업로드 폴더 & 정적 서빙 ─────────────────
const UP_DIR = path.join(__dirname, 'uploads', 'pet-care');
fs.mkdirSync(UP_DIR, { recursive: true });
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// 파일명: 타임스탬프-랜덤.ext
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UP_DIR),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname || '');
    cb(null, `${Date.now()}-${Math.round(Math.random()*1e9)}${ext}`);
  }
});
const upload = multer({ storage });

mongoose.set('strictQuery', true);

// ─────────────── DB 연결 (유저/병원/관리 분리) ───────────────
const userConn     = mongoose.createConnection(MONGODB_URI, { dbName: 'user_db' });
const hospitalConn = mongoose.createConnection(MONGODB_URI, { dbName: 'hospital_db' });
const adminConn    = mongoose.createConnection(MONGODB_URI, { dbName: 'admin_db' });

userConn.on('connected',     () => console.log('✅ userConn -> user_db'));
hospitalConn.on('connected', () => console.log('✅ hospitalConn -> hospital_db'));
adminConn.on('connected',    () => console.log('✅ adminConn -> admin_db'));

// ─────────────── 스키마 ───────────────
const userSchema = new mongoose.Schema({
  email:        { type: String, required: true, unique: true, index: true },
  passwordHash: { type: String, required: true },
  name:         { type: String, default: '' },
  role:         { type: String, enum: ['USER'], default: 'USER' },
  birthDate:    { type: String, default: '' },
  petProfile: {
    name:      { type: String, default: '' },
    age:       { type: Number, default: 0 },
    gender:    { type: String, default: '' },
    species:   { type: String, default: '' },
    avatarUrl: { type: String, default: '' },
  },
  linkedHospitals: [{
    hospitalId:   { type: mongoose.Schema.Types.ObjectId, required: true },
    hospitalName: { type: String, default: '' },
    status:       { type: String, enum: ['PENDING','APPROVED','REJECTED'], default: 'PENDING' },
    requestedAt:  { type: Date },
    linkedAt:     { type: Date }
  }],
}, { timestamps: true });

const hospitalUserSchema = new mongoose.Schema({
  email:        { type: String, required: true, unique: true, index: true },
  passwordHash: { type: String, required: true },
  name:         { type: String, default: '' },
  role:         { type: String, enum: ['HOSPITAL_ADMIN'], default: 'HOSPITAL_ADMIN' },
  hospitalName: { type: String, default: '' },
  hospitalProfile: {
    photoUrl: { type: String, default: '' },
    intro:    { type: String, default: '' },
    address:  { type: String, default: '' },
    hours:    { type: String, default: '' },
    phone:    { type: String, default: '' },
  },
  approveStatus: { type: String, enum: ['PENDING','APPROVED','REJECTED'], default: 'PENDING' },
}, { timestamps: true });

const hospitalLinkRequestSchema = new mongoose.Schema({
  userId:       { type: mongoose.Schema.Types.ObjectId, required: true },
  userName:     { type: String, default: '' },
  petName:      { type: String, default: '' },
  hospitalId:   { type: mongoose.Schema.Types.ObjectId, required: true },
  hospitalName: { type: String, default: '' },
  status:       { type: String, enum: ['PENDING','APPROVED','REJECTED'], default: 'PENDING' },
  createdAt:    { type: Date, default: Date.now },
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
  visitDateTime:{ type: Date },
  status:       { type: String, enum: ['PENDING','APPROVED','REJECTED','CANCELED'], default: 'PENDING', index: true },
  createdAt:    { type: Date, default: Date.now },
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

// ─────────────── 모델 등록 ───────────────
const User                = userConn.model('User', userSchema, 'users');
const HospitalUser        = hospitalConn.model('HospitalUser', hospitalUserSchema, 'hospital_user');
const HospitalLinkRequest = hospitalConn.model('HospitalLinkRequest', hospitalLinkRequestSchema, 'hospital_link_requests');
const HospitalMeta        = hospitalConn.model('HospitalMeta', hospitalMetaSchema, 'hospital_meta');
const Appointment         = hospitalConn.model('Appointment', appointmentSchema, 'appointments');
const MedicalHistory      = hospitalConn.model('MedicalHistory', medicalHistorySchema, 'medical_histories');
const UserAppointment     = userConn.model('UserAppointment', userAppointmentSchema, 'user_appointments');
const PetCare             = hospitalConn.model('PetCare', petCareSchema, 'pet_care');

// ─────────────── 유틸/미들웨어 ───────────────
function issueToken(doc) {
  return jwt.sign({ uid: doc._id, role: doc.role }, process.env.JWT_SECRET, { expiresIn: '7d' });
}
function publicUrl(req, relativePath) {
  const base = process.env.PUBLIC_BASE_URL || `${req.protocol}://${req.get('host')}`;
  return `${base}${relativePath.startsWith('/') ? '' : '/'}${relativePath}`;
}
function auth(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : '';
    if (!token) return res.status(401).json({ message: 'no token' });
    req.jwt = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: 'invalid token' });
  }
}
const onlyUser = (req, res, next) =>
  req.jwt?.role === 'USER' ? next() : res.status(403).json({ message: 'for USER' });
const onlyHospitalAdmin = (req, res, next) =>
  req.jwt?.role === 'HOSPITAL_ADMIN' ? next() : res.status(403).json({ message: 'for HOSPITAL_ADMIN' });

// ─────────────── 헬스 & 루트 ───────────────
app.get('/health', (_req, res) => res.json({ ok: true, ts: Date.now() }));
app.get('/', (_req, res) => res.json({ message: '🚀 Animal API running', env: process.env.NODE_ENV || 'dev' }));

// ─────────────── (이하 API 전부 기존 그대로) ───────────────

// 전역 아이디 중복 확인
app.get('/auth/check-id', async (req, res) => {
  try {
    const key = (req.query.email || req.query.username || req.query.key || '').toString().trim();
    if (!key) return res.status(400).json({ message: 'email/username required' });
    const [u, h] = await Promise.all([User.exists({ email: key }), HospitalUser.exists({ email: key })]);
    res.json({ available: !(u || h) });
  } catch (e) { console.error('check-id error:', e); res.status(500).json({ message: 'server error' }); }
});

// 회원가입/로그인
app.post('/auth/signup', async (req, res) => {
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

app.post('/auth/signup-with-invite', async (req, res) => {
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

app.post('/auth/login', async (req, res) => {
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

// 프로필
app.get('/users/me', auth, onlyUser, async (req, res) => {
  const user = await User.findById(req.jwt.uid).lean();
  if (!user) return res.status(404).json({ message: 'not found' });
  delete user.passwordHash;
  res.json({ user, id: user._id, email: user.email, name: user.name, role: user.role, birthDate: user.birthDate, petProfile: user.petProfile });
});
app.get('/hospital/me', auth, onlyHospitalAdmin, async (req, res) => {
  const admin = await HospitalUser.findById(req.jwt.uid).lean();
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
    const user = await User.findByIdAndUpdate(req.jwt.uid, { $set: update }, { new: true, lean: true });
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
  const admin = await HospitalUser.findByIdAndUpdate(req.jwt.uid, { $set: update }, { new: true, lean: true });
  if (!admin) return res.status(404).json({ message: 'not found' });
  delete admin.passwordHash;
  res.json({ user: admin });
});

// 병원 목록
app.get('/api/hospitals', async (_req, res) => {
  const list = await HospitalUser.find({}, { passwordHash: 0 }).sort({ createdAt: -1 }).lean();
  res.json(list.map(h => ({
    _id: h._id,
    hospitalName: h.hospitalName || '',
    approveStatus: h.approveStatus || 'PENDING',
    imageUrl: h.hospitalProfile?.photoUrl || '',
    createdAt: h.createdAt,
  })));
});

// 병원 연동
app.get('/api/hospital-links/available', auth, onlyUser, async (req, res) => {
  const [hospitals, me] = await Promise.all([
    HospitalUser.find({}, { passwordHash: 0 }).sort({ createdAt: -1 }).lean(),
    User.findById(req.jwt.uid, { linkedHospitals: 1 }).lean(),
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
  const user = await User.findById(userId);
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
    userId: userId, hospitalId: hospital._id, status: 'PENDING',
  });
  if (!existing) {
    await HospitalLinkRequest.create({
      userId,
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
    const hospital = await HospitalUser.findById(hospitalId).lean();
    if (!hospital) return res.status(404).json({ message: 'hospital not found' });
    await upsertUserLink(req.jwt.uid, hospital);
    res.json({ ok: true });
  } catch (e) { console.error('request link error:', e); res.status(500).json({ message: 'server error' }); }
});
app.post('/api/hospitals/:id/connect', auth, onlyUser, async (req, res) => {
  try {
    const hospital = await HospitalUser.findById(req.params.id).lean();
    if (!hospital) return res.status(404).json({ message: 'hospital not found' });
    await upsertUserLink(req.jwt.uid, hospital);
    res.json({ ok: true });
  } catch (e) { console.error('compat connect error:', e); res.status(500).json({ message: 'server error' }); }
});

// 병원관리자: 요청/승인/거절
app.get('/api/hospital-admin/requests', auth, onlyHospitalAdmin, async (req, res) => {
  const hospitalId = req.jwt.uid;
  const list = await HospitalLinkRequest.find({ hospitalId, status: 'PENDING' }).sort({ createdAt: -1 }).lean();
  res.json(list);
});
app.post('/api/hospital-admin/requests/:id/approve', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const r = await HospitalLinkRequest.findById(req.params.id);
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
    const r = await HospitalLinkRequest.findById(req.params.id);
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

// 병원관리자: 환자/진료내역
app.get('/api/hospital-admin/patients', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const hospitalId = req.jwt.uid;
    const list = await User.aggregate([
      { $unwind: '$linkedHospitals' },
      { $match: { 'linkedHospitals.hospitalId': new mongoose.Types.ObjectId(hospitalId), 'linkedHospitals.status': 'APPROVED' } },
      { $project: { _id: 0, userId: '$_id', userName: '$name', petName: '$petProfile.name' } }
    ]);
    res.json(list);
  } catch (e) { console.error('GET /api/hospital-admin/patients error:', e); res.status(500).json({ message: 'server error' }); }
});
app.get('/api/hospital-admin/medical-histories', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const { userId, hospitalId } = req.query;
    if (!userId) return res.status(400).json({ message: 'userId is required' });
    const hid = hospitalId || req.jwt.uid;
    const list = await MedicalHistory.find({ userId, hospitalId: hid }).sort({ date: -1, createdAt: -1 }).lean();
    const data = list.map(m => ({ ...m, id: m._id }));
    return res.json({ data });
  } catch (e) { console.error('GET histories error:', e); return res.status(500).json({ message: 'server error' }); }
});
app.post('/api/hospital-admin/medical-histories', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const { userId, hospitalId, date, content, prescription, howToTake, cost, petName, userName, category, hospitalName } = req.body || {};
    if (!userId || !date) return res.status(400).json({ message: 'userId and date are required' });
    const hid = hospitalId || req.jwt.uid;
    let hName = (hospitalName || '').trim();
    if (!hName) {
      const h = await HospitalUser.findById(hid).lean();
      hName = h?.hospitalName || '';
    }
    const doc = await MedicalHistory.create({
      userId,
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
    const created = doc.toJSON();
    return res.status(201).json({ data: { ...created, id: created._id } });
  } catch (e) { console.error('POST histories error:', e); return res.status(500).json({ message: 'server error' }); }
});

// 사용자: 병원 목록/예약/케어일지
app.get('/api/users/me/hospitals', auth, onlyUser, async (req, res) => {
  const user = await User.findById(req.jwt.uid).lean();
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

app.get('/api/hospital-admin/pet-care', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const hospitalId = req.jwt.uid;
    const keyword = (req.query.keyword || '').toString().trim();
    const sortKey = (req.query.sort || 'dateDesc').toString();
    const q = { hospitalId };
    if (keyword) {
      const rx = new RegExp(keyword, 'i');
      q.$or = [{ memo: rx }];
    }
    const sort = sortKey === 'dateAsc' ? 1 : -1;
    const list = await PetCare.find(q).sort({ dateTime: sort, createdAt: sort }).lean();
    const data = list.map(d => ({
      _id: d._id,
      date: d.date || '',
      time: d.time || '',
      dateTime: d.dateTime,
      memo: d.memo || '',
      imageUrl: (d.images && d.images.length) ? d.images[0] : '',
      images: d.images || [],
    }));
    return res.json({ data });
  } catch (e) { console.error('GET pet-care error:', e); return res.status(500).json({ message: 'server error' }); }
});

app.post('/api/hospital-admin/pet-care', auth, onlyHospitalAdmin, upload.array('images', 10), async (req, res) => {
  try {
    const hospitalId = req.jwt.uid;
    const admin = await HospitalUser.findById(hospitalId).lean();
    if (!admin) return res.status(404).json({ message: 'hospital not found' });
    const date = (req.body.date || '').toString().trim();
    const time = (req.body.time || '').toString().trim();
    const memo = (req.body.memo || '').toString().trim();
    if (!date || !time) return res.status(400).json({ message: 'date/time required' });
    const urls = (req.files || []).map(f => publicUrl(req, `/uploads/pet-care/${path.basename(f.path)}`));
    const dt = new Date(`${date}T${time}:00`);
    const doc = await PetCare.create({
      hospitalId,
      hospitalName: admin.hospitalName || '',
      createdBy: req.jwt.uid,
      date, time, dateTime: isNaN(dt.getTime()) ? new Date() : dt,
      memo,
      images: urls,
    });
    const created = doc.toJSON();
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
  } catch (e) { console.error('POST pet-care error:', e); return res.status(500).json({ message: 'server error' }); }
});

// 예약 메타/신청
app.get('/api/hospitals/:hospitalId/appointment-meta', async (req, res) => {
  const { hospitalId } = req.params;
  const meta = await HospitalMeta.findOne({ hospitalId }).lean();
  const servicesDefault = ['일반진료','건강검진','종합백신','심장사상충','치석제거'];
  const doctorsDefault  = [{ id: 'default', name: '김철수 원장' }];
  if (!meta) {
    const h = await HospitalUser.findById(hospitalId).lean();
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
    const h = await HospitalUser.findById(req.jwt.uid).lean();
    const doc = await HospitalMeta.findOneAndUpdate(
      { hospitalId: req.jwt.uid },
      {
        $set: {
          hospitalId: req.jwt.uid,
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
    const me = await User.findById(req.jwt.uid).lean();
    const link = (me?.linkedHospitals || []).find(h => String(h.hospitalId) === String(hospitalId));
    if (!link || link.status !== 'APPROVED') return res.status(403).json({ message: 'link to hospital required (APPROVED)' });
    const h = await HospitalUser.findById(hospitalId).lean();
    if (!h) return res.status(404).json({ message: 'hospital not found' });
    const vdt = visitDateTime ? new Date(visitDateTime) : undefined;
    const cleanedUserName = (userName || '').trim();
    const finalUserName = cleanedUserName && cleanedUserName !== '사용자' ? cleanedUserName : (me?.name || '');
    const cleanedPetName = (petName || '').trim();
    const finalPetName = cleanedPetName && cleanedPetName !== '(미입력)' ? cleanedPetName : (me?.petProfile?.name || '');
    const appt = await Appointment.create({
      hospitalId,
      hospitalName: hospitalName || h.hospitalName || '',
      userId: req.jwt.uid,
      userName: finalUserName,
      petName:  finalPetName,
      service, doctorName, date, time,
      visitDateTime: vdt,
      status: 'PENDING'
    });
    await UserAppointment.create({
      userId: req.jwt.uid,
      originAppointmentId: appt._id,
      hospitalId,
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

// 사용자 예약 조회/삭제/월간
app.get('/api/users/me/appointments', auth, onlyUser, async (req, res) => {
  try {
    const me = await User.findById(req.jwt.uid, { name:1, petProfile:1 }).lean();
    const q = { userId: req.jwt.uid };
    if (req.query.hospitalId) q.hospitalId = req.query.hospitalId;
    if (req.query.month) {
      const [yy, mm] = String(req.query.month).split('-').map(Number);
      if (yy && mm) {
        const start = new Date(yy, mm - 1, 1, 0, 0, 0);
        const end   = new Date(yy, mm, 1, 0, 0, 0);
        q.visitDateTime = { $gte: start, $lt: end };
      }
    }
    let list = await UserAppointment.find(q).sort({ visitDateTime: 1 }).lean();
    list = list.map(a => ({ ...a, userName: a.userName || me?.name || '', petName: a.petName || me?.petProfile?.name || '' }));
    if (!list.length) {
      const hospitalList = await Appointment.find({ userId: req.jwt.uid }).sort({ visitDateTime: 1 }).lean();
      list = hospitalList.map(a => ({
        userId: a.userId, hospitalId: a.hospitalId, hospitalName: a.hospitalName,
        userName: a.userName || me?.name || '', petName: a.petName || me?.petProfile?.name || '',
        service: a.service, doctorName: a.doctorName, date: a.date, time: a.time,
        visitDateTime: a.visitDateTime, status: a.status,
      }));
    }
    res.json({ data: list });
  } catch (e) { console.error('get user appointments error:', e); res.status(500).json({ message: 'server error' }); }
});
app.delete('/api/users/me/appointments/:id', auth, onlyUser, async (req, res) => {
  try {
    const ua = await UserAppointment.findOne({ _id: req.params.id, userId: req.jwt.uid });
    if (!ua) return res.status(404).json({ message: 'not found' });
    await UserAppointment.deleteOne({ _id: ua._id });
    await Appointment.deleteOne({ _id: ua.originAppointmentId, userId: req.jwt.uid });
    return res.status(204).send();
  } catch (e) { console.error('delete my appt error:', e); return res.status(500).json({ message: 'server error' }); }
});
app.get('/api/users/me/appointments/monthly', auth, onlyUser, async (req, res) => {
  try {
    const { hospitalId, month } = req.query;
    if (!month) return res.status(400).json({ message: 'month required (YYYY-MM)' });
    const [yy, mm] = String(month).split('-').map(Number);
    if (!yy || !mm) return res.status(400).json({ message: 'invalid month' });
    const q = { userId: req.jwt.uid };
    if (hospitalId) q.hospitalId = hospitalId;
    const start = new Date(yy, mm - 1, 1, 0, 0, 0);
    const end   = new Date(yy, mm, 1, 0, 0, 0);
    q.visitDateTime = { $gte: start, $lt: end };
    const list = await UserAppointment.find(q).sort({ visitDateTime: 1 }).lean();
    res.json(list);
  } catch (e) { console.error('monthly user appts error:', e); res.status(500).json({ message: 'server error' }); }
});

// 사용자: 케어일지 보기
app.get('/api/users/me/pet-care', auth, onlyUser, async (req, res) => {
  try {
    const { hospitalId, keyword = '', sort = 'dateDesc' } = req.query;
    if (!hospitalId) return res.status(400).json({ message: 'hospitalId required' });
    const me = await User.findById(req.jwt.uid, { linkedHospitals: 1 }).lean();
    const link = (me?.linkedHospitals || []).find(h => String(h.hospitalId) === String(hospitalId) && h.status === 'APPROVED');
    if (!link) return res.status(403).json({ message: 'link to hospital required (APPROVED)' });
    const q = { hospitalId };
    if (String(keyword).trim()) {
      const rx = new RegExp(String(keyword).trim(), 'i');
      q.$or = [{ memo: rx }];
    }
    const s = sort === 'dateAsc' ? 1 : -1;
    const list = await PetCare.find(q).sort({ dateTime: s, createdAt: s }).lean();
    const data = list.map(d => ({
      _id: d._id, date: d.date || '', time: d.time || '', dateTime: d.dateTime, memo: d.memo || '',
      imageUrl: (d.images && d.images.length) ? d.images[0] : '', images: d.images || [],
    }));
    res.json({ data });
  } catch (e) { console.error('GET /api/users/me/pet-care error:', e); res.status(500).json({ message: 'server error' }); }
});

// 병원관리자: 예약 수신함/승인/거절
app.get('/api/hospital-admin/appointments', auth, onlyHospitalAdmin, async (req, res) => {
  const status = (req.query.status || '').toString().toUpperCase();
  const order  = (req.query.order || 'desc').toString().toLowerCase();
  const q = { hospitalId: req.jwt.uid };
  if (['PENDING','APPROVED','REJECTED','CANCELED'].includes(status)) q.status = status;
  const sort = order === 'asc' ? 1 : -1;
  const list = await Appointment.find(q).sort({ createdAt: sort }).lean();
  res.json({ data: list });
});
app.post('/api/hospital-admin/appointments/:id/approve', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const appt = await Appointment.findById(req.params.id);
    if (!appt) return res.status(404).json({ message: 'not found' });
    if (String(appt.hospitalId) !== String(req.jwt.uid)) return res.status(403).json({ message: 'forbidden' });
    if (appt.status !== 'PENDING') return res.status(409).json({ message: 'already decided' });
    appt.status = 'APPROVED';
    appt.decidedAt = new Date();
    appt.decidedBy = req.jwt.uid;
    await appt.save();
    await UserAppointment.updateOne({ originAppointmentId: appt._id }, { $set: { status: 'APPROVED' } });
    res.json({ ok: true });
  } catch (e) { console.error('approve appt error:', e); res.status(500).json({ message: 'server error' }); }
});
app.post('/api/hospital-admin/appointments/:id/reject', auth, onlyHospitalAdmin, async (req, res) => {
  try {
    const appt = await Appointment.findById(req.params.id);
    if (!appt) return res.status(404).json({ message: 'not found' });
    if (String(appt.hospitalId) !== String(req.jwt.uid)) return res.status(403).json({ message: 'forbidden' });
    if (appt.status !== 'PENDING') return res.status(409).json({ message: 'already decided' });
    appt.status = 'REJECTED';
    appt.decidedAt = new Date();
    appt.decidedBy = req.jwt.uid;
    await appt.save();
    await UserAppointment.updateOne({ originAppointmentId: appt._id }, { $set: { status: 'REJECTED' } });
    res.json({ ok: true });
  } catch (e) { console.error('reject appt error:', e); res.status(500).json({ message: 'server error' }); }
});

// 사용자 화면용 대시보드
app.get('/api/hospitals/:hospitalId/user-dashboard', auth, onlyUser, async (req, res) => {
  try {
    const { hospitalId } = req.params;
    const meta = await HospitalMeta.findOne({ hospitalId }).lean();
    const notice = meta?.notice || '';
    const upcoming = await Appointment.findOne({
      hospitalId, userId: req.jwt.uid, status: 'APPROVED', visitDateTime: { $gte: new Date() }
    }).sort({ visitDateTime: 1 }).lean();
    let nextAppointment = '';
    if (upcoming) {
      const dt = new Date(upcoming.visitDateTime);
      const y = dt.getFullYear(), m = `${dt.getMonth()+1}`.padStart(2,'0'), d = `${dt.getDate()}`.padStart(2,'0');
      const hh = `${dt.getHours()}`.padStart(2,'0'), mm = `${dt.getMinutes()}`.padStart(2,'0');
      nextAppointment = `${y}/${m}/${d} ${hh}:${mm} · ${upcoming.service} (${upcoming.doctorName})`;
    }
    res.json({ notice, nextAppointment });
  } catch (e) { console.error('user-dashboard error:', e); res.status(500).json({ message: 'server error' }); }
});

// 사용자: 내 진료내역
app.get('/api/users/me/medical-histories', auth, onlyUser, async (req, res) => {
  try {
    const { hospitalId, month, q } = req.query;
    const find = { userId: req.jwt.uid };
    if (hospitalId) find.hospitalId = hospitalId;
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
    const list = await MedicalHistory.find(find).sort({ date: -1, createdAt: -1 }).lean();
    const data = list.map(m => ({ ...m, id: m._id }));
    return res.json({ data });
  } catch (e) { console.error('GET /api/users/me/medical-histories error:', e); return res.status(500).json({ message: 'server error' }); }
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
