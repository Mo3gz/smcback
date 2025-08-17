const MiningSession = require('../models/miningSession');
const Notification = require('../models/notification');
const User = require('../models/user');
const { calculateOfflineMining } = require('../utils/miningUtils');

class MiningService {
  // Start a new mining session
  static async startMining(userId, countryId) {
    // End any existing active sessions
    await this.endActiveSessions(userId);

    // Create new mining session
    const session = new MiningSession({
      user: userId,
      country: countryId,
      startTime: new Date(),
      lastActive: new Date()
    });

    await session.save();
    return session;
  }

  // Calculate and process offline mining
  static async processOfflineMining(userId) {
    const activeSession = await MiningSession.findOne({
      user: userId,
      isActive: true
    }).populate('country');

    if (!activeSession) return { mined: 0 };

    const now = new Date();
    const lastActive = activeSession.lastActive;
    const timeDiffHours = (now - lastActive) / (1000 * 60 * 60); // Convert ms to hours

    if (timeDiffHours <= 0) return { mined: 0 };

    // Calculate mined amount based on country's mining rate and time passed
    const minedAmount = calculateOfflineMining(
      timeDiffHours,
      activeSession.country.miningRate
    );

    // Update user's balance
    await User.findByIdAndUpdate(userId, {
      $inc: { balance: minedAmount }
    });

    // Update session
    activeSession.lastActive = now;
    activeSession.totalMined += minedAmount;
    await activeSession.save();

    // Create notification
    await Notification.create({
      user: userId,
      type: 'mining_complete',
      title: 'Mining Complete',
      message: `You've mined ${minedAmount.toFixed(6)} coins while offline!`,
      data: {
        amount: minedAmount,
        duration: timeDiffHours,
        country: activeSession.country.name
      }
    });

    // Notify admin
    await this.notifyAdmin(userId, minedAmount, timeDiffHours);

    return { mined: minedAmount };
  }

  // End all active mining sessions for a user
  static async endActiveSessions(userId) {
    await MiningSession.updateMany(
      { user: userId, isActive: true },
      { isActive: false, endTime: new Date() }
    );
  }

  // Get current mining stats for a user
  static async getMiningStats(userId) {
    const activeSession = await MiningSession.findOne({
      user: userId,
      isActive: true
    }).populate('country', 'name code miningRate');

    if (!activeSession) return null;

    const now = new Date();
    const hoursElapsed = (now - activeSession.lastActive) / (1000 * 60 * 60);
    
    return {
      country: activeSession.country,
      startTime: activeSession.startTime,
      lastActive: activeSession.lastActive,
      totalMined: activeSession.totalMined,
      estimatedHourlyRate: activeSession.country.miningRate,
      estimatedMinedSinceLastActive: hoursElapsed * activeSession.country.miningRate
    };
  }

  // Notify admin about significant mining activity
  static async notifyAdmin(userId, amount, duration) {
    const user = await User.findById(userId);
    if (!user) return;

    await Notification.create({
      user: process.env.ADMIN_USER_ID, // Set admin user ID in environment
      type: 'admin_alert',
      title: 'Mining Activity',
      message: `User ${user.username} mined ${amount.toFixed(6)} coins after being offline for ${duration.toFixed(2)} hours`,
      data: {
        userId: user._id,
        username: user.username,
        amount,
        duration
      }
    });
  }
}

module.exports = MiningService;
