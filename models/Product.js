const mongoose = require("mongoose");

// ✅ 상품 스키마 정의
const productSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },      // 상품명
    category: { type: String, required: true },  // 카테고리
    description: { type: String, required: true },// 설명
    quantity: { type: Number, required: true },  // 수량
    price: { type: Number, required: true },     // 가격
    images: [{ type: String }],                  // 이미지 경로 배열
    
    // ✅ 리뷰 필드 추가
    reviews: [
      {
        userName: { type: String, required: true },  // 작성자 이름
        rating: { type: Number, required: true },    // 별점
        comment: { type: String, required: true },   // 리뷰 내용
        createdAt: { type: Date, default: Date.now } // 작성일
      }
    ],
    // ⭐ 평균 평점 필드 추가
    averageRating: { type: Number, default: 0 }, // ✅ 리뷰 평균값 저장용
  },
  { timestamps: true }
);

// ✅ 스키마만 export (모델 아님)
module.exports = productSchema;
