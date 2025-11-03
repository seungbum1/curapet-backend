// server.js
require('dotenv').config();
const path = require('path');
const fs = require('fs');
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');

const clean = (v) => (v ?? '')
    .trim()
    .replace(/^['"]|['"]$/g, '');

// ── 환경변수
const PORT = process.env.PORT || 4000;                  // Render가 PORT를 주입함
const CORS_ORIGINS = (process.env.CORS_ORIGINS || '')
    .split(',').map(s => s.trim()).filter(Boolean);

const MONGODB_URI_ADMIN = strip(process.env.MONGODB_URI_ADMIN);
const MONGODB_URI_USER  = strip(process.env.MONGODB_URI_USER);
const UPLOAD_DIR        = process.env.UPLOAD_DIR || path.join(process.cwd(), 'uploads');

if (!MONGODB_URI_ADMIN || !MONGODB_URI_USER) {
console.error('❌ MONGODB_URI_ADMIN / MONGODB_URI_USER 가 필요합니다.');
process.exit(1);
}

const app = express();
app.set('trust proxy', 1);

// ── 보안/성능 미들웨어
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(compression());
app.use(morgan('dev'));

// ── CORS (Render 프론트/로컬 개발 둘다 커버)
app.use(cors({
origin: (origin, cb) => {
if (!origin || CORS_ORIGINS.length === 0) return cb(null, true);
cb(null, CORS_ORIGINS.includes(origin));
},
credentials: true,
}));

app.use(express.json({ limit: '2mb' }));

// ── 업로드 디렉토리 보장 (Render Persistent Disk 권장)
if (!fs.existsSync(UPLOAD_DIR)) {
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
console.log(`📁 uploads 폴더 생성: ${UPLOAD_DIR}`);
}
app.use('/uploads', express.static(UPLOAD_DIR));

// ── DB 연결 (멀티 커넥션)
const mongooseOpts = {
maxPoolSize: 10,
serverSelectionTimeoutMS: 20000,
};
const adminDB = mongoose.createConnection(MONGODB_URI_ADMIN, mongooseOpts);
const userDB  = mongoose.createConnection(MONGODB_URI_USER,  mongooseOpts);

adminDB.on('connected', () => console.log('✅ adminDB connected'));
userDB.on('connected',  () => console.log('✅ userDB connected'));
adminDB.on('error', err => console.error('❌ adminDB error:', err?.message || err));
userDB.on('error',  err => console.error('❌ userDB error:', err?.message || err));

// ── 모델 주입
const Product = adminDB.model('Product', require('./models/Product'));
const User    = userDB.model('User', require('./models/user'));

// ── 라우터 주입
const productRoutes = require('./routes/productRoutes')(Product);
const userRoutes    = require('./routes/userRoutes')(User, adminDB, userDB);
const orderRoutes   = require('./routes/orderRoutes')(userDB);

app.use('/products', productRoutes);
app.use('/users', userRoutes);
app.use('/orders', orderRoutes);

// ── 관리자 로그인 (데모: 평문 확인 방식 유지 / 추후 bcrypt로 교체 권장)
app.post('/admin/login', async (req, res) => {
const { id, password } = req.body;
try {
const collection = adminDB.collection('admin_user');
const admin = await collection.findOne({ id, password }); // TODO: bcrypt로 교체 권장
if (admin) return res.json({ success: true, message: '관리자 로그인 성공' });
return res.status(401).json({ success: false, message: '아이디/비밀번호가 틀렸습니다.' });
} catch (e) {
console.error('❌ 관리자 로그인 오류:', e);
return res.status(500).json({ success: false, message: '서버 오류' });
}
});

// ── 기본 관리자 계정 자동 생성 (최초 1회)
(async () => {
try {
const collection = adminDB.collection('admin_user');
const exists = await collection.findOne({ id: 'admin' });
if (!exists) {
await collection.insertOne({ id: 'admin', password: 'admin', name: '관리자', role: 'ADMIN' });
console.log('✅ 기본 관리자 계정 생성됨 (id: admin / pw: admin)');
} else {
console.log('ℹ️ 관리자 계정 이미 존재');
}
} catch (e) {
console.error('❌ 관리자 계정 생성 오류:', e);
}
})();

// ── Multer 업로드
const storage = multer.diskStorage({
destination: (req, file, cb) => cb(null, UPLOAD_DIR),
filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`),
});
const upload = multer({ storage });

app.post('/upload', upload.single('image'), (req, res) => {
if (!req.file) return res.status(400).json({ error: '파일이 없습니다.' });
const imageUrl = `/uploads/${req.file.filename}`;
res.json({ message: '이미지 업로드 성공', imageUrl });
});

// ── 헬스체크 (Render Auto health check 대응)
app.get('/healthz', (_req, res) => res.status(200).send('ok'));

// ── 서버 시작
app.listen(PORT, '0.0.0.0', () => {
console.log(`🚀 Server running on port ${PORT}`);
});

// ── 종료 시그널 핸들링
const graceful = async () => {
console.log('👋 Shutting down...');
await Promise.allSettled([adminDB.close(), userDB.close()]);
process.exit(0);
};
process.on('SIGINT', graceful);
process.on('SIGTERM', graceful);
