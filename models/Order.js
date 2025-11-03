const mongoose = require("mongoose");

// ✅ 주문 스키마 정의
const orderSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    userName: String,
    address: String,
    phone: String,
    product: {
      _id: mongoose.Schema.Types.ObjectId,
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
  },
  { timestamps: true }
);

module.exports = orderSchema;
