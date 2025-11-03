const express = require("express");
const mongoose = require("mongoose");

module.exports = (userDB) => {
  const router = express.Router();

  const Order = userDB.model("Order", require("../models/Order"));

  // ✅ [1] 전체 주문 조회 (관리자용)
  router.get("/", async (req, res) => {
    try {
      const orders = await Order.find().sort({ createdAt: -1 }).lean();
      res.json(orders);
    } catch (err) {
      console.error("❌ 주문 전체 조회 오류:", err);
      res.status(500).json({ error: err.message });
    }
  });

  // ✅ [2] 주문 상태 업데이트 (배송하기 → 배송중 → 배송완료)
  router.patch("/:orderId", async (req, res) => {
    try {
      const { status } = req.body;
      const order = await Order.findByIdAndUpdate(
        req.params.orderId,
        { status },
        { new: true }
      );
      if (!order) return res.status(404).json({ message: "주문 없음" });
      res.json({ success: true, updatedOrder: order });
    } catch (err) {
      console.error("❌ 주문 상태 변경 오류:", err);
      res.status(500).json({ error: err.message });
    }
  });

  // ✅ [3] 주문 삭제 (취소)
  router.delete("/:orderId", async (req, res) => {
    try {
      const order = await Order.findByIdAndDelete(req.params.orderId);
      if (!order) return res.status(404).json({ message: "주문 없음" });
      res.json({ success: true, message: "주문이 취소되었습니다" });
    } catch (err) {
      console.error("❌ 주문 삭제 오류:", err);
      res.status(500).json({ error: err.message });
    }
  });

  return router;
};
