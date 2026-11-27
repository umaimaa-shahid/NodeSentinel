const express = require('express');
const { getDB } = require('../db');

const router = express.Router();

// VULNERABILITY: NoSQL $where Injection (interpolates unsanitized user input into a MongoDB $where clause)
router.get('/products/search', async (req, res) => {
  try {
    const db = getDB();
    const { q } = req.query;

    let filter = {};
    if (q !== undefined && q !== '') {
      if (typeof q === 'string') {
        const lower = q.toLowerCase();
        filter = {
          $where: `this.name.toLowerCase().indexOf('${lower}') !== -1 || this.category.toLowerCase().indexOf('${lower}') !== -1`,
        };
      } else {
        filter = { name: q };
      }
    }

    const products = await db.collection('products').find(filter).toArray();

    return res.status(200).json({
      count: products.length,
      products: products.map((p) => ({
        id: String(p._id),
        sku: p.sku,
        name: p.name,
        category: p.category,
        price: p.price,
        inStock: p.inStock,
      })),
    });
  } catch (err) {
    return res.status(500).json({ error: 'Product search failed', details: err.message });
  }
});

module.exports = router;
