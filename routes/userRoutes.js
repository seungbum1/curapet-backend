const express = require("express");

module.exports = (User, adminDB, userDB) => {

  const router = express.Router();

  // ✅ Product 모델을 adminDB에서 직접 생성
  const Product = adminDB.model("Product", require("../models/Product"));
  const Order = userDB.model("Order", require("../models/Order")); // ✅ 추가


  // 유저 목록 조회 (이름 + 반려동물이름만 가져오기)
router.get("/", async (req, res) => {
  try {
    const users = await User.find({}, { 
      name: 1,              // 유저 이름
      "petProfile.name": 1  // 반려동물 이름
    });
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


  // 특정 유저 조회
  router.get("/:id", async (req, res) => {
    try {
      const user = await User.findById(req.params.id);
      if (!user) return res.status(404).json({ message: "유저 없음" });
      res.json(user);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // 유저 등록
  router.post("/", async (req, res) => {
    try {
      const user = new User(req.body);
      await user.save();
      res.json({ message: "유저 등록 성공", user });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // 유저 삭제
  router.delete("/:id", async (req, res) => {
    try {
      await User.findByIdAndDelete(req.params.id);
      res.json({ message: "유저 삭제 성공" });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

    // ✅ [1] 찜 추가
  router.post("/:userId/favorites/:productId", async (req, res) => {
    try {
      const { userId, productId } = req.params;

      const user = await User.findById(userId);
      if (!user) return res.status(404).json({ message: "유저 없음" });

      if (!user.favorites.includes(productId)) {
        user.favorites.push(productId);
        await user.save();
      }

      res.json({ message: "상품이 찜 목록에 추가되었습니다.", favorites: user.favorites });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ✅ [2] 찜 제거
  router.delete("/:userId/favorites/:productId", async (req, res) => {
    try {
      const { userId, productId } = req.params;

      const user = await User.findById(userId);
      if (!user) return res.status(404).json({ message: "유저 없음" });

      user.favorites = user.favorites.filter(id => id.toString() !== productId);
      await user.save();

      res.json({ message: "상품이 찜 목록에서 제거되었습니다.", favorites: user.favorites });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ✅ [3] 찜 목록 조회
router.get("/:userId/favorites", async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: "유저 없음" });

    // ✅ 찜한 상품 목록 조회
    const favoriteProducts = await Product.find({
      _id: { $in: user.favorites },
    });

    res.json(favoriteProducts);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ✅ [장바구니 수량 변경]
router.patch("/:userId/cart/:productId", async (req, res) => {
  try {
    const { userId, productId } = req.params;
    const { count } = req.body;

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: "유저 없음" });

    const cartItem = user.cart.find(
      (item) => item.productId.toString() === productId
    );

    if (!cartItem) return res.status(404).json({ message: "장바구니에 상품 없음" });

    cartItem.count = count; // ✅ 새 수량 반영
    await user.save();

    res.json({ message: "상품 수량이 변경되었습니다 ✅", cart: user.cart });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ✅ 장바구니에 상품 추가 (수량 포함)
router.post("/:userId/cart/:productId", async (req, res) => {
  try {
    const { userId, productId } = req.params;
    const { count } = req.body; // ✅ Flutter에서 보낸 count 받기

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    const product = await Product.findById(productId);
    if (!product) return res.status(404).json({ message: "Product not found" });

    // ✅ 이미 담긴 상품이면 수량만 업데이트
    const existingItem = user.cart.find(
      (item) => item.productId.toString() === productId
    );

    if (existingItem) {
      existingItem.count += count || 1;
    } else {
      // ✅ 새로 추가
      user.cart.push({
        productId,
        name: product.name,
        price: product.price,
        images: product.images,
        category: product.category,
        count: count || 1,
      });
    }

    await user.save();
    res.json({ message: "장바구니에 추가되었습니다 🛒", cart: user.cart });
  } catch (error) {
    console.error("❌ 장바구니 추가 오류:", error);
    res.status(500).json({ message: "서버 오류" });
  }
});

// ✅ [장바구니에서 제거]
router.delete("/:userId/cart/:productId", async (req, res) => {
  try {
    const { userId, productId } = req.params;

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: "유저 없음" });

    user.cart = user.cart.filter(item => item.productId.toString() !== productId);
    await user.save();

    res.json({ message: "상품이 장바구니에서 제거되었습니다 🗑️", cart: user.cart });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ✅ [장바구니 목록 조회]
router.get("/:userId/cart", async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: "유저 없음" });

    // ✅ cart 내부의 productId만 추출
    const productIds = user.cart.map(item => item.productId);

    // ✅ 해당 상품들 정보 조회
    const products = await Product.find({ _id: { $in: productIds } });

    // ✅ count(수량) 정보도 함께 반환
    const cartWithCount = user.cart.map(item => {
      const product = products.find(p => p._id.toString() === item.productId.toString());
      return {
        ...product.toObject(),
        count: item.count,
      };
    });

    res.json(cartWithCount);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ✅ [장바구니 전체 비우기]
router.delete("/:userId/cart", async (req, res) => {
  try {
    const { userId } = req.params;
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: "유저 없음" });

    user.cart = []; // 장바구니 비우기
    await user.save();

    res.json({ message: "장바구니가 비워졌습니다 ✅" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/:userId/orders", async (req, res) => {
  try {
    const { userId } = req.params;
    const { product, payment, userName, address, phone } = req.body;

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: "유저 없음" });

    // ✅ 이미지 경로를 절대경로로 변환
    const imageUrl = product.image?.startsWith("http")
      ? product.image
      : `http://127.0.0.1:5000${product.image}`;

    const newOrder = new Order({
      userId,
      userName,
      address,
      phone,
      product: {
        ...product,
        image: imageUrl, // ✅ 절대경로로 변환된 이미지
      },
      payment, // ✅ payment 객체도 같이 저장
      status: "결제완료",
    });

    await newOrder.save();
    res.json({ success: true, order: newOrder });
  } catch (err) {
    console.error("❌ 주문 저장 오류:", err);
    res.status(500).json({ error: err.message });
  }
});

router.get("/:userId/orders", async (req, res) => {
  try {
    const { userId } = req.params;
    const orders = await Order.find({ userId })
      .sort({ createdAt: -1 })
      .lean(); // ✅ JSON형태로 변환해서 createdAt 문자열로 보내줌

    res.json(orders);
  } catch (err) {
    console.error("❌ 결제내역 조회 오류:", err);
    res.status(500).json({ error: err.message });
  }
});

  return router;
};
