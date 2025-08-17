const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminController');
const { authenticate, requireAdmin } = require('../middleware/auth');

// Apply authentication and admin middleware to all routes
router.use(authenticate);
router.use(requireAdmin);

// User management
router.get('/users', adminController.getAllUsers);
router.put('/users/:userId', adminController.updateUser);
router.post('/users/:userId/coins', adminController.manageUserCoins);

// System management
router.get('/stats', adminController.getSystemStats);
router.post('/reset', adminController.resetAllData);

module.exports = router;
