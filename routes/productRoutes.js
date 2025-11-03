const express = require("express");
const fs = require("fs"); // ✅ 파일 삭제용 모듈

module.exports = (Product) => {
  const router = express.Router();

  // 상품 등록
  router.post("/", async (req, res) => {
    try {
      const product = new Product(req.body);
      await product.save();
      res.json({ message: "상품 등록 성공", product });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });
  // ✅ 상품 수량 변경 (관리자 or 결제 시)
router.patch("/:id/quantity", async (req, res) => {
  try {
    const { id } = req.params;
    const { quantity } = req.body;

    if (quantity < 0)
      return res.status(400).json({ message: "수량은 0 미만일 수 없습니다." });

    const product = await Product.findByIdAndUpdate(
      id,
      { quantity },
      { new: true }
    );

    if (!product)
      return res.status(404).json({ message: "상품을 찾을 수 없습니다." });

    res.json(product);
  } catch (error) {
    res.status(500).json({ message: "수량 업데이트 실패", error });
  }
});

  // 상품 목록 조회
  router.get("/", async (req, res) => {
    try {
      const products = await Product.find();
      res.json(products);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ✅ 상품 단일 조회 (User 상세페이지용)
  router.get("/:id", async (req, res) => {
    try {
      const product = await Product.findById(req.params.id);
      if (!product)
        return res.status(404).json({ message: "상품을 찾을 수 없습니다." });
      res.json(product);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // 상품 수정
  router.put("/:id", async (req, res) => {
    try {
      const product = await Product.findByIdAndUpdate(req.params.id, req.body, { new: true });
      if (!product) return res.status(404).json({ message: "상품 없음" });
      res.json(product);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ✅ 상품 삭제 (이미지 파일 포함)
  router.delete("/:id", async (req, res) => {
    try {
      const deleted = await Product.findByIdAndDelete(req.params.id);
      if (!deleted) return res.status(404).json({ message: "상품을 찾을 수 없습니다." });

      // ✅ 업로드된 이미지 파일도 같이 삭제
      if (deleted.images && deleted.images.length > 0) {
        deleted.images.forEach((imgUrl) => {
          // 예: http://127.0.0.1:5000/uploads/abc.jpg → ./uploads/abc.jpg
          const filePath = imgUrl.replace("http://127.0.0.1:5000", ".");
          fs.unlink(filePath, (err) => {
            if (err) console.log("⚠️ 이미지 삭제 실패:", err.message);
          });
        });
      }

      res.json({ message: "✅ 상품 삭제 성공", deleted });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

 // ✅ [리뷰 등록] POST /products/:id/reviews
router.post("/:id/reviews", async (req, res) => {
  try {
    const { userName, rating, comment } = req.body;
    const productId = req.params.id;

    const product = await Product.findById(productId);
    if (!product) return res.status(404).json({ message: "상품을 찾을 수 없습니다." });

    // ✅ 새 리뷰 추가
    product.reviews.push({ userName, rating, comment, createdAt: new Date() });

    // ⭐ 평균 평점 재계산
    const total = product.reviews.reduce((sum, r) => sum + r.rating, 0);
    product.averageRating = total / product.reviews.length;

    await product.save();

    res.json({
      message: "리뷰 등록 성공",
      averageRating: product.averageRating, // ⭐ 새 평점 반환
      product,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// 🧩 리뷰 삭제 (관리자 전용)
router.delete("/:productId/reviews/:reviewId", async (req, res) => {
  const { productId, reviewId } = req.params;

  try {
    const product = await Product.findById(productId);
    if (!product) return res.status(404).json({ message: "상품을 찾을 수 없습니다." });

    // 리뷰 필터링 (삭제)
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
    res.json({ message: "✅ 리뷰가 삭제되었습니다." });
  } catch (err) {
    console.error("❌ 리뷰 삭제 오류:", err);
    res.status(500).json({ message: "서버 오류" });
  }
});

  return router;
};
