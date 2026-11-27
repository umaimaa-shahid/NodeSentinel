const express = require('express');
const Joi = require('joi');
const { getDB } = require('../db');

const router = express.Router();

const productSearchSchema = Joi.object({
  q: Joi.string().trim().max(100).optional(),
});

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

router.get('/products/search', async (req, res) => {
  try {
    const { error, value } = productSearchSchema.validate(req.query, {
      convert: false,
      stripUnknown: true,
    });

    if (error) {
      return res.status(400).json({ error: 'Invalid product search query' });
    }

    const db = getDB();
    let filter = {};

    if (value.q) {
      const safePattern = escapeRegex(value.q);
      filter = {
        $or: [
          { name: { $regex: safePattern, $options: 'i' } },
          { category: { $regex: safePattern, $options: 'i' } },
        ],
      };
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
  } catch (_) {
    return res.status(500).json({ error: 'Product search failed' });
  }
});

module.exports = router;
