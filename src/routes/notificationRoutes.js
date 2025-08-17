const express = require('express');
const router = express.Router();
const notificationController = require('../controllers/notificationController');
const { authenticate, requireAdmin } = require('../middleware/auth');

// Protected routes
router.get('/', authenticate, notificationController.getUserNotifications);
router.get('/unread-count', authenticate, notificationController.getUnreadCount);
router.post('/:notificationId/read', authenticate, notificationController.markAsRead);
router.post('/mark-all-read', authenticate, notificationController.markAllAsRead);
// Add alias for frontend compatibility
router.post('/read-all', authenticate, notificationController.markAllAsRead);

// Admin routes
router.post('/admin/global', authenticate, requireAdmin, notificationController.sendGlobalNotification);
router.get('/admin/all', authenticate, requireAdmin, notificationController.getAllNotifications);

module.exports = router;
