const express = require('express');
const router = express.Router();
const inventoryController = require('../controllers/inventoryController');
const { authenticate, requireAdmin } = require('../middleware/auth');

// Protected routes
router.get('/', authenticate, inventoryController.getUserInventory);
router.post('/use', authenticate, inventoryController.useItem);
router.post('/spin', authenticate, inventoryController.spinWheel);

// Admin routes
router.post('/admin/add', authenticate, requireAdmin, inventoryController.addItemToInventory);

module.exports = router;
