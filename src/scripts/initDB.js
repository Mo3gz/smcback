require('dotenv').config();
const { connectToMongoDB, getDB } = require('../database/connection');
const config = require('../config');

// Sample data
const defaultUsers = [
  {
    id: '1',
    username: 'ayman',
    password: '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password
    role: 'admin',
    teamName: 'Ayman',
    coins: 1000,
    score: 0,
    createdAt: new Date(),
    updatedAt: new Date()
  },
  {
    id: '2',
    username: 'team1',
    password: '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password
    role: 'user',
    teamName: 'Team Alpha',
    coins: 500,
    score: 0,
    createdAt: new Date(),
    updatedAt: new Date()
  }
];

const defaultCountries = [
  { id: '1', name: 'Egypt', cost: 200, score: 150 },
  { id: '2', name: 'Morocco', cost: 180, score: 140 },
  { id: '3', name: 'Algeria', cost: 160, score: 130 },
  // Add more countries as needed
];

async function initializeDatabase() {
  try {
    console.log('🚀 Starting database initialization...');
    
    // Connect to MongoDB
    await connectToMongoDB();
    const db = getDB();
    
    // Initialize users
    const usersCollection = db.collection('users');
    const userCount = await usersCollection.countDocuments();
    
    if (userCount === 0) {
      console.log('👥 Inserting default users...');
      await usersCollection.insertMany(defaultUsers);
      console.log('✅ Default users inserted');
    } else {
      console.log('ℹ️  Users already exist, skipping...');
    }
    
    // Initialize countries
    const countriesCollection = db.collection('countries');
    const countryCount = await countriesCollection.countDocuments();
    
    if (countryCount === 0) {
      console.log('🌍 Inserting default countries...');
      await countriesCollection.insertMany(defaultCountries);
      console.log('✅ Default countries inserted');
    } else {
      console.log('ℹ️  Countries already exist, skipping...');
    }
    
    // Create indexes
    console.log('🔨 Creating indexes...');
    await Promise.all([
      usersCollection.createIndex({ username: 1 }, { unique: true }),
      usersCollection.createIndex({ id: 1 }),
      countriesCollection.createIndex({ id: 1 }),
      countriesCollection.createIndex({ owner: 1 })
    ]);
    
    console.log('✅ Database initialization completed successfully!');
    process.exit(0);
  } catch (error) {
    console.error('❌ Database initialization failed:', error);
    process.exit(1);
  }
}

// Run the initialization
initializeDatabase();
