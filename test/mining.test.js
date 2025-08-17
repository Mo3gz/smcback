const request = require('supertest');
const { MongoClient } = require('mongodb');
const app = require('../app');
const { ObjectId } = require('mongodb');
require('dotenv').config();

describe('Mining Feature Tests', () => {
  let connection;
  let db;
  let testUserId;
  let testCountryId;
  let authToken;

  beforeAll(async () => {
    // Connect to the test database
    connection = await MongoClient.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    db = connection.db(process.env.MONGO_DB_NAME || 'scoring-system-test');
    
    // Set up test data
    const testUser = {
      username: 'testminer',
      password: 'testpass123',
      role: 'user',
      teamName: 'Test Miner',
      coins: 100,
      score: 0
    };
    
    // Insert test user
    const users = db.collection('users');
    await users.deleteMany({ username: 'testminer' });
    const result = await users.insertOne(testUser);
    testUserId = result.insertedId;
    
    // Create a test country
    const countries = db.collection('countries');
    const testCountry = {
      name: 'Test Country',
      cost: 100,
      ownerId: testUserId,
      score: 200,
      miningRate: 5, // 5 coins per hour
      lastMined: new Date(Date.now() - 2 * 60 * 60 * 1000), // 2 hours ago
      updatedAt: new Date()
    };
    
    await countries.deleteMany({ name: 'Test Country' });
    const countryResult = await countries.insertOne(testCountry);
    testCountryId = countryResult.insertedId;
    
    // Get auth token (simplified for testing)
    authToken = 'test-token';
  });

  afterAll(async () => {
    // Clean up test data
    await db.collection('users').deleteMany({ username: 'testminer' });
    await db.collection('countries').deleteMany({ name: 'Test Country' });
    await connection.close();
  });

  test('GET /api/mining/stats returns mining stats', async () => {
    const response = await request(app)
      .get('/api/mining/stats')
      .set('Authorization', `Bearer ${authToken}`);
    
    expect(response.statusCode).toBe(200);
    expect(response.body.success).toBe(true);
    expect(Array.isArray(response.body.data)).toBe(true);
  });

  test('POST /api/mining/mine/:countryId mines coins', async () => {
    // First, get the current user balance
    const userBefore = await db.collection('users').findOne({ _id: testUserId });
    const initialBalance = userBefore.coins;
    
    // Mine the country
    const response = await request(app)
      .post(`/api/mining/mine/${testCountryId}`)
      .set('Authorization', `Bearer ${authToken}`);
    
    expect(response.statusCode).toBe(200);
    expect(response.body.success).toBe(true);
    expect(response.body.coinsMined).toBeGreaterThan(0);
    
    // Verify user balance was updated
    const userAfter = await db.collection('users').findOne({ _id: testUserId });
    expect(userAfter.coins).toBe(initialBalance + response.body.coinsMined);
    
    // Verify lastMined was updated
    const countryAfter = await db.collection('countries').findOne({ _id: testCountryId });
    expect(new Date(countryAfter.lastMined).getTime()).toBeGreaterThan(
      Date.now() - 1000 * 60 // Within the last minute
    );
  });

  test('Mining returns 0 coins if not enough time has passed', async () => {
    // Mine immediately after the previous test should return 0 coins
    const response = await request(app)
      .post(`/api/mining/mine/${testCountryId}`)
      .set('Authorization', `Bearer ${authToken}`);
    
    expect(response.statusCode).toBe(200);
    expect(response.body.coinsMined).toBe(0);
  });
});
