const { createServer } = require('http');
const express = require('express');
const serverless = require('serverless-http');
const cors = require('cors');
const bodyParser = require('body-parser');

// Import your Express app
const app = express();

// Apply middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Import routes
const authRoutes = require('../routes/auth');
const miningRoutes = require('../routes/miningRoutes')(null); // Will be initialized in the handler

// Use routes
app.use('/.netlify/functions/server/api/auth', authRoutes);
app.use('/.netlify/functions/server/api/mining', miningRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Create serverless handler
exports.handler = async (event, context) => {
  // Initialize database connection
  const { MongoClient } = require('mongodb');
  const client = new MongoClient(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });

  try {
    await client.connect();
    const db = client.db(process.env.MONGO_DB_NAME || 'scoring-system');
    
    // Attach db to request object
    app.set('db', db);
    
    // Initialize the mining routes with the database
    require('../routes/miningRoutes')(db);
    
    // Handle the request
    const handler = serverless(app);
    return await handler(event, context);
  } catch (error) {
    console.error('Error in serverless function:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Internal Server Error' })
    };
  } finally {
    await client.close();
  }
};
