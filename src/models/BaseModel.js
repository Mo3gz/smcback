const { getDB } = require('../database/connection');

class BaseModel {
  constructor(collectionName) {
    this.collectionName = collectionName;
    this.collection = getDB().collection(collectionName);
  }

  async createIndexes() {
    // To be implemented by child classes
  }

  async findOne(query) {
    return this.collection.findOne(query);
  }

  async find(query = {}, options = {}) {
    return this.collection.find(query, options).toArray();
  }

  async insertOne(doc) {
    return this.collection.insertOne(doc);
  }

  async updateOne(filter, update, options = {}) {
    return this.collection.updateOne(filter, { $set: update }, options);
  }

  async deleteOne(filter) {
    return this.collection.deleteOne(filter);
  }

  async countDocuments(query = {}) {
    return this.collection.countDocuments(query);
  }
}

module.exports = BaseModel;
