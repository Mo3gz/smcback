const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const path = require('path');
const { connectToMongoDB, isConnected } = require('./database/connection');
const config = require('./config');

// Initialize Express app
const app = express();
const server = http.createServer(app);

// Initialize database connection first
async function initializeApp() {
  try {
    // Connect to MongoDB
    await connectToMongoDB();
    console.log('✅ Connected to MongoDB');

    // Now import models and routes after DB connection is established
    const { initializeSocket } = require('./sockets');
    const authRoutes = require('./routes/authRoutes');
    const authController = require('./controllers/authController');
    const countryRoutes = require('./routes/countryRoutes');
    const notificationRoutes = require('./routes/notificationRoutes');
    const inventoryRoutes = require('./routes/inventoryRoutes');
    const adminRoutes = require('./routes/adminRoutes');

    // Initialize Socket.IO with CORS configuration
    const io = socketIo(server, {
      cors: {
        origin: config.cors.allowedOrigins,
        methods: config.cors.methods,
        credentials: true
      }
    });

        // Initialize Socket.IO
    initializeSocket(io);
    app.set('io', io);

    // Middleware
    app.use(cors({
      origin: (origin, callback) => {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        
        if (config.cors.allowedOrigins.includes(origin) || 
            config.app.nodeEnv === 'development') {
          callback(null, true);
        } else {
          callback(new Error('Not allowed by CORS'));
        }
      },
      credentials: config.cors.credentials,
      methods: config.cors.methods,
      allowedHeaders: config.cors.allowedHeaders
    }));

    app.use(express.json());
    app.use(cookieParser());

    // Health check endpoint
    app.get('/health', (req, res) => {
      res.json({
        status: 'ok',
        timestamp: new Date(),
        mongo: isConnected() ? 'connected' : 'disconnected',
        environment: config.app.nodeEnv
      });
    });

    // API Routes
    app.use('/api/auth', authRoutes);
    app.use('/api/countries', countryRoutes);
    app.use('/api/notifications', notificationRoutes);
    app.use('/api/inventory', inventoryRoutes);
    app.use('/api/admin', adminRoutes);
    
    // Scoreboard shortcut route - redirect to auth controller
    app.get('/api/scoreboard', authController.getScoreboard);

    // Error handling middleware
    app.use((err, req, res, next) => {
      console.error('Error:', err);
      res.status(500).json({
        error: 'Internal Server Error',
        message: err.message || 'Something went wrong',
        ...(config.app.nodeEnv === 'development' && { stack: err.stack })
      });
    });

    // 404 handler
    app.use((req, res) => {
      res.status(404).json({ error: 'Not Found' });
    });

    const PORT = config.app.port;
    server.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`🌐 Environment: ${config.app.nodeEnv}`);
      console.log(`🔗 CORS allowed origins: ${config.cors.allowedOrigins.join(', ')}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Start the application
initializeApp();

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
  console.error('Unhandled Rejection:', err);
  // Close server & exit process
  server.close(() => process.exit(1));
});

module.exports = { app, server };
