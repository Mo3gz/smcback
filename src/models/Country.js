const BaseModel = require('./BaseModel');

class Country extends BaseModel {
  constructor() {
    super('countries');
  }

  async createIndexes() {
    await this.collection.createIndex({ id: 1 });
    await this.collection.createIndex({ owner: 1 });
  }

  async findById(id) {
    return this.findOne({ id });
  }

  async findByOwner(ownerId) {
    return this.find({ owner: ownerId });
  }

  async updateOwner(countryId, ownerId) {
    return this.updateOne(
      { id: countryId },
      { 
        owner: ownerId,
        ownedAt: new Date()
      }
    );
  }

  async getAvailableCountries() {
    return this.find({ owner: null });
  }

  async getCountriesByScore(limit = 10) {
    return this.collection
      .find({})
      .sort({ score: -1 })
      .limit(limit)
      .toArray();
  }
}

module.exports = new Country();
