const BaseModel = require('./BaseModel');

class Notification extends BaseModel {
  constructor() {
    super('notifications');
  }

  async createIndexes() {
    await this.collection.createIndex({ timestamp: -1 });
    await this.collection.createIndex({ userId: 1 });
    await this.collection.createIndex({ userId: 1, read: 1 });
    await this.collection.createIndex({ type: 1 });
  }

  async create(notification) {
    const newNotification = {
      ...notification,
      timestamp: new Date(),
      read: false
    };
    
    const result = await this.collection.insertOne(newNotification);
    return { ...newNotification, _id: result.insertedId };
  }

  async getUserNotifications(userId) {
    return this.collection.find({
      $or: [
        { userId },
        { type: 'global' },
        { type: 'scoreboard-update' }
      ]
    }).sort({ timestamp: -1 }).toArray();
  }

  async getUnreadCount(userId) {
    return this.collection.countDocuments({
      $or: [
        { userId, read: { $ne: true } },
        { type: 'global', read: { $ne: true } },
        { type: 'scoreboard-update', read: { $ne: true } }
      ]
    });
  }

  async markAsRead(notificationId, userId) {
    return this.updateOne(
      { _id: notificationId, userId },
      { 
        read: true,
        readAt: new Date()
      }
    );
  }

  async markAllAsRead(userId) {
    return this.collection.updateMany(
      { 
        userId,
        read: { $ne: true }
      },
      { 
        $set: { 
          read: true,
          readAt: new Date()
        } 
      }
    );
  }

  async deleteOldNotifications(days = 30) {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - days);
    
    return this.collection.deleteMany({
      timestamp: { $lt: cutoffDate }
    });
  }
}

module.exports = new Notification();
