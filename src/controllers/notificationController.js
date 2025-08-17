const Notification = require('../models/Notification');

// Get all notifications for the current user
exports.getUserNotifications = async (req, res) => {
  try {
    const notifications = await Notification.getUserNotifications(req.user.id);
    res.json(notifications);
  } catch (error) {
    console.error('Get notifications error:', error);
    res.status(500).json({ error: 'Failed to get notifications' });
  }
};

// Get unread notifications count
exports.getUnreadCount = async (req, res) => {
  try {
    const count = await Notification.getUnreadCount(req.user.id);
    res.json({ count });
  } catch (error) {
    console.error('Get unread count error:', error);
    res.status(500).json({ error: 'Failed to get unread count' });
  }
};

// Mark notification as read
exports.markAsRead = async (req, res) => {
  try {
    const { notificationId } = req.params;
    await Notification.markAsRead(notificationId, req.user.id);
    res.json({ success: true });
  } catch (error) {
    console.error('Mark as read error:', error);
    res.status(500).json({ error: 'Failed to mark notification as read' });
  }
};

// Mark all notifications as read
exports.markAllAsRead = async (req, res) => {
  try {
    await Notification.markAllAsRead(req.user.id);
    res.json({ success: true });
  } catch (error) {
    console.error('Mark all as read error:', error);
    res.status(500).json({ error: 'Failed to mark all notifications as read' });
  }
};

// Admin: Send global notification
exports.sendGlobalNotification = async (req, res) => {
  try {
    const { message } = req.body;
    
    if (!message) {
      return res.status(400).json({ error: 'Message is required' });
    }

    const notification = await Notification.create({
      type: 'global',
      message,
      read: false
    });

    // Emit socket event
    if (req.io) {
      req.io.emit('newNotification', notification);
    }

    res.json({ success: true, notification });
  } catch (error) {
    console.error('Send global notification error:', error);
    res.status(500).json({ error: 'Failed to send global notification' });
  }
};

// Admin: Get all notifications (for admin panel)
exports.getAllNotifications = async (req, res) => {
  try {
    const notifications = await Notification.find().sort({ timestamp: -1 });
    res.json(notifications);
  } catch (error) {
    console.error('Get all notifications error:', error);
    res.status(500).json({ error: 'Failed to get all notifications' });
  }
};
