const { ObjectId } = require('mongodb');

class Country {
    constructor(data) {
        this._id = data._id ? new ObjectId(data._id) : new ObjectId();
        this.id = data.id || this._id.toString();
        this.name = data.name || '';
        this.code = data.code || '';
        this.flag = data.flag || '';
        this.teamId = data.teamId || null;
        this.ownerId = data.ownerId || null;
        this.miningRate = data.miningRate || 1.0; // Coins per hour
        this.lastMined = data.lastMined || new Date();
        this.createdAt = data.createdAt || new Date();
        this.updatedAt = new Date();
    }

    static get collectionName() {
        return 'countries';
    }

    toJSON() {
        return {
            _id: this._id,
            id: this.id,
            name: this.name,
            code: this.code,
            flag: this.flag,
            teamId: this.teamId,
            ownerId: this.ownerId,
            miningRate: this.miningRate,
            lastMined: this.lastMined,
            createdAt: this.createdAt,
            updatedAt: this.updatedAt
        };
    }

    static async createIndexes(db) {
        await db.collection(this.collectionName).createIndex({ id: 1 }, { unique: true });
        await db.collection(this.collectionName).createIndex({ teamId: 1 });
        await db.collection(this.collectionName).createIndex({ ownerId: 1 });
        await db.collection(this.collectionName).createIndex({ miningRate: 1 });
    }
}

module.exports = Country;
