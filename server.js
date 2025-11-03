const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const path = require("path");
const multer = require("multer");
const fs = require("fs");

const app = express();
app.use(cors());
app.use(express.json());

// ✅ uploads 폴더 자동 생성 (없을 경우)
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
  console.log("📁 uploads 폴더가 없어서 새로 생성했습니다.");
}

// ✅ 업로드 폴더 static 설정
app.use("/uploads", express.static(uploadDir));

// ✅ DB 연결
const adminDB = mongoose.createConnection(
  "mongodb+srv://qhdudrjsgml_db_user:1234@animal-cluster.bm3p7bu.mongodb.net/admin_db"
);
const userDB = mongoose.createConnection(
  "mongodb+srv://qhdudrjsgml_db_user:1234@animal-cluster.bm3p7bu.mongodb.net/user_db"
);

// ✅ 모델
const Product = adminDB.model("Product", require("./models/Product"));
const User = userDB.model("User", require("./models/user"));

// ✅ 라우터
const productRoutes = require("./routes/productRoutes")(Product);
const userRoutes = require("./routes/userRoutes")(User, adminDB, userDB);
// ✅ 주문 라우터 추가 (관리자 주문 관리용)
const orderRoutes = require("./routes/orderRoutes")(userDB);

app.use("/products", productRoutes);
app.use("/users", userRoutes);
app.use("/orders", orderRoutes); // ✅ 이 줄 추가

// ✅ 관리자 로그인 API
app.post("/admin/login", async (req, res) => {
  const { id, password } = req.body;

  try {
    const collection = adminDB.collection("admin_user");
    const admin = await collection.findOne({ id, password });

    if (admin) {
      res.json({ success: true, message: "관리자 로그인 성공" });
    } else {
      res.status(401).json({ success: false, message: "아이디 또는 비밀번호가 틀렸습니다." });
    }
  } catch (error) {
    console.error("❌ 관리자 로그인 오류:", error);
    res.status(500).json({ success: false, message: "서버 오류" });
  }
});

// ✅ 기본 관리자 계정 자동 생성
(async () => {
  try {
    const collection = adminDB.collection("admin_user");
    const exists = await collection.findOne({ id: "admin" });
    if (!exists) {
      await collection.insertOne({
        id: "admin",
        password: "admin",
        name: "관리자",
        role: "ADMIN",
      });
      console.log("✅ 기본 관리자 계정 생성됨 (id: admin / pw: admin)");
    } else {
      console.log("ℹ️ 관리자 계정 이미 존재함");
    }
  } catch (e) {
    console.error("❌ 관리자 계정 생성 오류:", e);
  }
})();

// ✅ 이미지 업로드 설정
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, "uploads");
    console.log("📂 저장 경로:", uploadPath);
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + "-" + file.originalname;
    console.log("📸 저장 파일명:", uniqueName);
    cb(null, uniqueName);
  },
});

const upload = multer({ storage });

// ✅ 업로드 API
app.post("/upload", upload.single("image"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "파일이 없습니다." });
  }

  const imageUrl = `/uploads/${req.file.filename}`;
  res.json({ message: "이미지 업로드 성공", imageUrl });
});

// ✅ 서버 실행
const PORT = 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
