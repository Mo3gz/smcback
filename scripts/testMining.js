const { MongoClient } = require('mongodb');
const { ObjectId } = require('mongodb');
require('dotenv').config();

async function testMining() {
  const client = new MongoClient(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });

  try {
    await client.connect();
    const db = client.db(process.env.MONGO_DB_NAME || 'scoring-system');
    
    // Get a test user and country
    const user = await db.collection('users').findOne({ username: 'team1' });
    const country = await db.collection('countries').findOne({});
    
    if (!user || !country) {
      console.error('Test user or country not found');
      return;
    }

    // Update country to be owned by the test user
    await db.collection('countries').updateOne(
      { _id: country._id },
      { 
        $set: { 
          ownerId: user._id,
          lastMined: new Date(Date.now() - 2 * 60 * 60 * 1000) // 2 hours ago
        } 
      }
    );

    console.log('Test setup complete. Country assigned to user.');
    console.log('User ID:', user._id);
    console.log('Country ID:', country._id);
    console.log('Mining rate:', country.miningRate, 'coins/hour');
    console.log('Last mined:', new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString());
    
    // Now you can test the mining endpoint using curl or Postman:
    console.log('\nTest the mining endpoint with:');
    console.log(`POST http://localhost:5000/api/mining/mine/${country._id}`);
    console.log('Headers:', {
      'Content-Type': 'application/json',
      'Authorization': `Bearer <user_jwt_token>`
    });
    
  } catch (error) {
    console.error('Error setting up test:', error);
  } finally {
    await client.close();
  }
}

testMining();
