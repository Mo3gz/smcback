const { MongoClient } = require('mongodb');
const config = require('../config');

let mongoClient = null;
let db = null;

async function connectToMongoDB() {
  try {
    mongoClient = new MongoClient(config.mongo.uri, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    
    await mongoClient.connect();
    db = mongoClient.db(config.mongo.dbName);
    
    console.log('✅ Connected to MongoDB');
    return db;
  } catch (err) {
    console.error('❌ MongoDB connection error:', err);
    throw err;
  }
}

function getDB() {
  if (!db) {
    throw new Error('Database not initialized. Call connectToMongoDB first.');
  }
  return db;
}

async function closeConnection() {
  if (mongoClient) {
    await mongoClient.close();
    db = null;
    mongoClient = null;
    console.log('MongoDB connection closed');
  }
}

module.exports = {
  connectToMongoDB,
  getDB,
  closeConnection,
  isConnected: () => !!db
};
