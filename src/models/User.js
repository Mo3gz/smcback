const BaseModel = require('./BaseModel');
const bcrypt = require('bcryptjs');

class User extends BaseModel {
  constructor() {
    super('users');
  }

  async createIndexes() {
    await this.collection.createIndex({ username: 1 }, { unique: true });
    await this.collection.createIndex({ id: 1 });
  }

  async findByUsername(username) {
    return this.findOne({ username });
  }

  async findById(id) {
    return this.findOne({ id });
  }

  async create(userData) {
    const hashedPassword = await bcrypt.hash(userData.password, 10);
    const user = {
      ...userData,
      password: hashedPassword,
      role: 'user',
      coins: 500,
      score: 0,
      createdAt: new Date(),
      updatedAt: new Date()
    };
    
    const result = await this.collection.insertOne(user);
    return { ...user, _id: result.insertedId };
  }

  async updateUser(id, updateData) {
    if (updateData.password) {
      updateData.password = await bcrypt.hash(updateData.password, 10);
    }
    updateData.updatedAt = new Date();
    
    await this.updateOne({ id }, updateData);
    return this.findById(id);
  }

  async validatePassword(user, password) {
    return bcrypt.compare(password, user.password);
  }

  async getLeaderboard(limit = 10) {
    return this.collection
      .find({}, { projection: { password: 0 } })
      .sort({ score: -1 })
      .limit(limit)
      .toArray();
  }
}

module.exports = new User();
