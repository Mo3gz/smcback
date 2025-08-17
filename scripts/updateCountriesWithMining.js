const { MongoClient } = require('mongodb');
require('dotenv').config();

async function updateCountriesWithMining() {
  const client = new MongoClient(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });

  try {
    await client.connect();
    const db = client.db(process.env.MONGO_DB_NAME || 'scoring-system');
    const countriesCollection = db.collection('countries');

    // Get all countries
    const countries = await countriesCollection.find({}).toArray();
    
    // Update each country with mining rate (1 coin per 100 score points per hour)
    const bulkOps = countries.map(country => ({
      updateOne: {
        filter: { _id: country._id },
        update: { 
          $set: { 
            miningRate: Math.max(1, Math.floor(country.score / 100)),
            lastMined: new Date(),
            updatedAt: new Date()
          } 
        }
      }
    }));

    // Execute bulk update
    if (bulkOps.length > 0) {
      const result = await countriesCollection.bulkWrite(bulkOps);
      console.log(`✅ Successfully updated ${result.modifiedCount} countries with mining rates`);
    } else {
      console.log('No countries found to update');
    }
  } catch (error) {
    console.error('Error updating countries:', error);
  } finally {
    await client.close();
  }
}

updateCountriesWithMining();
