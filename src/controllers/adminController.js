const User = require('../models/User');
const Country = require('../models/Country');
const Notification = require('../models/Notification');
const Inventory = require('../models/Inventory');

// Get all users (for admin panel)
exports.getAllUsers = async (req, res) => {
  try {
    const users = await User.find({}, { password: 0 }); // Exclude passwords
    res.json(users);
  } catch (error) {
    console.error('Get all users error:', error);
    res.status(500).json({ error: 'Failed to get users' });
  }
};

// Update user (admin only)
exports.updateUser = async (req, res) => {
  try {
    const { userId } = req.params;
    const updates = req.body;

    // Don't allow updating sensitive fields
    const { password, role, ...safeUpdates } = updates;

    const updatedUser = await User.updateUser(userId, safeUpdates);
    if (!updatedUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Emit socket event
    if (req.io) {
      req.io.emit('userUpdated', { userId });
    }

    res.json(updatedUser);
  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({ error: 'Failed to update user' });
  }
};

// Add or remove coins from user
exports.manageUserCoins = async (req, res) => {
  try {
    const { userId } = req.params;
    const { amount, reason } = req.body;

    if (typeof amount !== 'number') {
      return res.status(400).json({ error: 'Invalid amount' });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const newCoins = Math.max(0, (user.coins || 0) + amount);
    await User.updateUser(userId, { coins: newCoins });

    // Create notification
    await Notification.create({
      userId,
      type: 'admin-action',
      message: `Admin ${req.user.username} ${amount >= 0 ? 'added' : 'removed'} ${Math.abs(amount)} coins${reason ? ` (${reason})` : ''}`,
      read: false
    });

    // Emit socket event
    if (req.io) {
      req.io.emit('userUpdated', { userId });
    }

    res.json({ success: true, coins: newCoins });
  } catch (error) {
    console.error('Manage user coins error:', error);
    res.status(500).json({ error: 'Failed to update user coins' });
  }
};

// Reset all data (use with caution!)
exports.resetAllData = async (req, res) => {
  try {
    const { confirm } = req.body;
    
    if (confirm !== 'I am sure') {
      return res.status(400).json({ 
        error: 'Confirmation required. This will delete all data!',
        confirmationRequired: true
      });
    }

    // Reset all collections
    await Promise.all([
      User.collection.deleteMany({}),
      Country.collection.deleteMany({}),
      Notification.collection.deleteMany({}),
      Inventory.collection.deleteMany({})
    ]);

    // Recreate indexes
    await Promise.all([
      User.createIndexes(),
      Country.createIndexes(),
      Notification.createIndexes(),
      Inventory.createIndexes()
    ]);

    // Emit socket event
    if (req.io) {
      req.io.emit('systemReset', { timestamp: new Date() });
    }

    res.json({ success: true, message: 'All data has been reset' });
  } catch (error) {
    console.error('Reset all data error:', error);
    res.status(500).json({ error: 'Failed to reset data' });
  }
};

// Get system stats
exports.getSystemStats = async (req, res) => {
  try {
    const [
      userCount,
      countryCount,
      ownedCountries,
      notificationsCount,
      totalCoins,
      totalScore
    ] = await Promise.all([
      User.collection.countDocuments(),
      Country.collection.countDocuments(),
      Country.collection.countDocuments({ owner: { $exists: true, $ne: null } }),
      Notification.collection.countDocuments(),
      User.collection.aggregate([
        { $group: { _id: null, total: { $sum: '$coins' } } }
      ]).toArray(),
      User.collection.aggregate([
        { $group: { _id: null, total: { $sum: '$score' } } }
      ]).toArray()
    ]);

    res.json({
      users: userCount,
      countries: countryCount,
      ownedCountries,
      availableCountries: countryCount - ownedCountries,
      notifications: notificationsCount,
      totalCoins: totalCoins[0]?.total || 0,
      totalScore: totalScore[0]?.total || 0,
      lastUpdated: new Date()
    });
  } catch (error) {
    console.error('Get system stats error:', error);
    res.status(500).json({ error: 'Failed to get system stats' });
  }
};
