const mongoose = require("mongoose");

const petProfileSchema = new mongoose.Schema({
  name: String,
  age: Number,
  gender: String,
  species: String,
  avatarUrl: String
}, { _id: false });

const linkedHospitalSchema = new mongoose.Schema({
  hospitalId: mongoose.Schema.Types.ObjectId,
  hospitalName: String,
  status: String,
  requestedAt: Date,
  linkedAt: Date
}, { _id: false });

// ✅ 장바구니 항목 구조 (상품 + 수량)
const cartItemSchema = new mongoose.Schema({
  productId: { type: mongoose.Schema.Types.ObjectId, ref: "Product" },
  count: { type: Number, default: 1 },
}, { _id: false });

// ✅ 결제내역 구조 추가 (이 부분 새로 추가)
const orderSchema = new mongoose.Schema({
  productId: { type: mongoose.Schema.Types.ObjectId, ref: "Product" },
  name: String,
  category: String,
  price: Number,
  quantity: Number,
  image: String,
  userName: String,         // ✅ 사용자 이름
  address: String,          // ✅ 주소
  phone: String,            // ✅ 전화번호
  paymentMethod: String, 
  totalAmount: Number,    // ✅ 결제 수단
  orderedAt: { type: Date, default: Date.now }
}, { _id: false });

const userSchema = new mongoose.Schema({
  email: { type: String, required: true },
  passwordHash: { type: String, required: true },
  name: { type: String, required: true },
  role: { type: String, default: "USER" },
  birthDate: { type: Date },
  petProfile: petProfileSchema,
  linkedHospitals: [linkedHospitalSchema],
// ✅ [추가] 찜한 상품 목록
  favorites: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Product", // admin_db의 Product 모델 참조
    },
  ],
  // ✅ 장바구니 (상품 + 수량)
  cart: [cartItemSchema],

  // ✅ [추가] 결제내역
  orders: [orderSchema],


}, { timestamps: true });

module.exports = userSchema;   // 🔥 반드시 Schema만 export
