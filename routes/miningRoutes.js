const express = require('express');
const auth = require('../middleware/auth');
const MiningService = require('../services/miningService');
const router = express.Router();

// @route   POST /api/mining/start
// @desc    Start a mining session
// @access  Private
router.post('/start', auth, async (req, res) => {
  try {
    const { countryId } = req.body;
    if (!countryId) {
      return res.status(400).json({ msg: 'Country ID is required' });
    }

    // Process any pending offline mining first
    await MiningService.processOfflineMining(req.user.id);

    // Start new mining session
    const session = await MiningService.startMining(req.user.id, countryId);
    
    res.json({ 
      msg: 'Mining started successfully',
      sessionId: session._id
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// @route   GET /api/mining/stats
// @desc    Get current mining statistics
// @access  Private
router.get('/stats', auth, async (req, res) => {
  try {
    // Process any pending offline mining
    const offlineResult = await MiningService.processOfflineMining(req.user.id);
    
    // Get current mining stats
    const stats = await MiningService.getMiningStats(req.user.id);
    
    res.json({
      stats,
      offlineMining: offlineResult.mined > 0 ? offlineResult : null
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// @route   POST /api/mining/stop
// @desc    Stop the current mining session
// @access  Private
router.post('/stop', auth, async (req, res) => {
  try {
    // Process any pending mining
    await MiningService.processOfflineMining(req.user.id);
    
    // End active sessions
    await MiningService.endActiveSessions(req.user.id);
    
    res.json({ msg: 'Mining stopped successfully' });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// @route   GET /api/mining/notifications
// @desc    Get user's mining notifications
// @access  Private
router.get('/notifications', auth, async (req, res) => {
  try {
    const notifications = await Notification.find({
      user: req.user.id,
      isRead: false
    }).sort({ createdAt: -1 }).limit(50);
    
    res.json(notifications);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// @route   PUT /api/mining/notifications/read/:id
// @desc    Mark a notification as read
// @access  Private
router.put('/notifications/read/:id', auth, async (req, res) => {
  try {
    const notification = await Notification.findOneAndUpdate(
      { _id: req.params.id, user: req.user.id },
      { isRead: true },
      { new: true }
    );
    
    if (!notification) {
      return res.status(404).json({ msg: 'Notification not found' });
    }
    
    res.json(notification);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

module.exports = router;
