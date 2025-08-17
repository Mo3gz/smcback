const BaseModel = require('./BaseModel');

class Inventory extends BaseModel {
  constructor() {
    super('inventories');
  }

  async createIndexes() {
    await this.collection.createIndex({ userId: 1 });
  }

  async getUserInventory(userId) {
    const inventory = await this.findOne({ userId });
    return inventory ? inventory.items : [];
  }

  async addItem(userId, item) {
    return this.collection.updateOne(
      { userId },
      { 
        $push: { items: item },
        $setOnInsert: { 
          userId, 
          createdAt: new Date(),
          updatedAt: new Date()
        }
      },
      { upsert: true }
    );
  }

  async removeItem(userId, itemId) {
    return this.updateOne(
      { userId },
      { 
        $pull: { items: { id: itemId } },
        $set: { updatedAt: new Date() }
      }
    );
  }

  async updateItem(userId, itemId, update) {
    const setObj = {};
    Object.entries(update).forEach(([key, value]) => {
      setObj[`items.$.${key}`] = value;
    });
    
    return this.collection.updateOne(
      { 
        userId,
        'items.id': itemId
      },
      { 
        $set: {
          ...setObj,
          updatedAt: new Date()
        }
      }
    );
  }
}

module.exports = new Inventory();
