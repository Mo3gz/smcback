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

// CORS middleware - MUST be applied before any routes
app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    // Check if origin is in allowed list (exact match)
    if (config.cors.allowedOrigins.includes(origin)) {
      console.log(`✅ CORS allowed: ${origin}`);
      return callback(null, true);
    }
    
    // Check for development environment
    if (config.app.nodeEnv === 'development') {
      console.log(`✅ CORS allowed (dev): ${origin}`);
      return callback(null, true);
    }
    
    // Check for exact domain match (remove trailing slash for comparison)
    const cleanOrigin = origin.replace(/\/$/, '');
    const isExactMatch = config.cors.allowedOrigins.some(allowedOrigin => {
      const cleanAllowed = allowedOrigin.replace(/\/$/, '');
      return cleanOrigin === cleanAllowed;
    });
    
    if (isExactMatch) {
      console.log(`✅ CORS allowed (exact match): ${origin}`);
      return callback(null, true);
    }
    
    // Check for subdomains (e.g., any.netlify.app)
    const isAllowedSubdomain = config.cors.allowedOrigins.some(allowedOrigin => {
      if (allowedOrigin.includes('netlify.app') && origin.endsWith('.netlify.app')) {
        return true;
      }
      if (allowedOrigin.includes('railway.app') && origin.endsWith('.railway.app')) {
        return true;
      }
      return false;
    });
    
    if (isAllowedSubdomain) {
      console.log(`✅ CORS allowed (subdomain): ${origin}`);
      return callback(null, true);
    }
    
    console.log(`❌ CORS blocked origin: ${origin}`);
    console.log(`Allowed origins: ${config.cors.allowedOrigins.join(', ')}`);
    callback(new Error('Not allowed by CORS'));
  },
  credentials: config.cors.credentials,
  methods: config.cors.methods,
  allowedHeaders: config.cors.allowedHeaders,
  preflightContinue: false,
  optionsSuccessStatus: 204
}));

// Handle preflight requests
app.options('*', cors());

// Additional CORS headers middleware
app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  // Log all CORS requests for debugging
  console.log(`🌐 CORS Request: ${req.method} ${req.path} from ${origin}`);
  console.log(`🔍 CORS Headers:`, {
    'Access-Control-Allow-Origin': res.getHeader('Access-Control-Allow-Origin'),
    'Access-Control-Allow-Credentials': res.getHeader('Access-Control-Allow-Credentials'),
    'Access-Control-Allow-Methods': res.getHeader('Access-Control-Allow-Methods'),
    'Access-Control-Allow-Headers': res.getHeader('Access-Control-Allow-Headers')
  });
  
  if (origin && config.cors.allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
  }
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', config.cors.methods.join(', '));
  res.header('Access-Control-Allow-Headers', config.cors.allowedHeaders.join(', '));
  
  next();
});

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
        origin: (origin, callback) => {
          // Allow requests with no origin
          if (!origin) return callback(null, true);
          
          // Check if origin is in allowed list
          if (config.cors.allowedOrigins.includes(origin)) {
            return callback(null, true);
          }
          
          // Check for exact domain match (remove trailing slash)
          const cleanOrigin = origin.replace(/\/$/, '');
          const isExactMatch = config.cors.allowedOrigins.some(allowedOrigin => {
            const cleanAllowed = allowedOrigin.replace(/\/$/, '');
            return cleanOrigin === cleanAllowed;
          });
          
          if (isExactMatch) {
            return callback(null, true);
          }
          
          // Check for subdomains
          const isAllowedSubdomain = config.cors.allowedOrigins.some(allowedOrigin => {
            if (allowedOrigin.includes('netlify.app') && origin.endsWith('.netlify.app')) {
              return true;
            }
            if (allowedOrigin.includes('railway.app') && origin.endsWith('.railway.app')) {
              return true;
            }
            return false;
          });
          
          if (isAllowedSubdomain) {
            return callback(null, true);
          }
          
          console.log(`❌ Socket.io CORS blocked origin: ${origin}`);
          callback(new Error('Socket.io CORS not allowed'));
        },
        methods: config.cors.methods,
        credentials: true,
        allowedHeaders: config.cors.allowedHeaders
      }
    });

    // Initialize Socket.IO
    initializeSocket(io);
    app.set('io', io);

    // Other middleware
    app.use(express.json());
    app.use(cookieParser());
    
    // Add socket.io to request object for use in controllers
    app.use((req, res, next) => {
      req.io = io;
      next();
    });

    // Health check endpoint
    app.get('/health', (req, res) => {
      res.json({
        status: 'ok',
        timestamp: new Date(),
        mongo: isConnected() ? 'connected' : 'disconnected',
        environment: config.app.nodeEnv
      });
    });

    // CORS test endpoint
    app.get('/api/cors-test', (req, res) => {
      res.json({
        message: 'CORS is working!',
        origin: req.headers.origin,
        timestamp: new Date(),
        cors: {
          allowedOrigins: config.cors.allowedOrigins,
          credentials: config.cors.credentials,
          methods: config.cors.methods
        }
      });
    });

    // Public test endpoint (no auth required)
    app.get('/api/public-test', (req, res) => {
      res.json({
        message: 'Public endpoint working!',
        origin: req.headers.origin,
        timestamp: new Date(),
        cors: {
          allowedOrigins: config.cors.allowedOrigins,
          credentials: config.cors.credentials,
          methods: config.cors.methods
        }
      });
    });

    // Netlify specific CORS test
    app.get('/api/netlify-test', (req, res) => {
      const origin = req.headers.origin;
      const isAllowed = config.cors.allowedOrigins.includes(origin) || 
                       config.cors.allowedOrigins.includes(origin.replace(/\/$/, ''));
      
      res.json({
        message: isAllowed ? 'Netlify CORS is working!' : 'Netlify CORS issue detected',
        origin: origin,
        isAllowed: isAllowed,
        allowedOrigins: config.cors.allowedOrigins,
        timestamp: new Date()
      });
    });

    // Comprehensive CORS debug endpoint
    app.get('/api/cors-debug', (req, res) => {
      const origin = req.headers.origin;
      const isAllowed = config.cors.allowedOrigins.includes(origin) || 
                       config.cors.allowedOrigins.includes(origin.replace(/\/$/, ''));
      
      res.json({
        message: 'CORS Debug Information',
        request: {
          origin: origin,
          method: req.method,
          path: req.path,
          headers: req.headers
        },
        cors: {
          isAllowed: isAllowed,
          allowedOrigins: config.cors.allowedOrigins,
          credentials: config.cors.credentials,
          methods: config.cors.methods,
          allowedHeaders: config.cors.allowedHeaders
        },
        environment: {
          nodeEnv: config.app.nodeEnv,
          timestamp: new Date()
        }
      });
    });

    // Auth test endpoint
    app.get('/api/auth-test', (req, res) => {
      const origin = req.headers.origin;
      const cookies = req.cookies;
      const authToken = cookies[config.jwt.cookieName];
      
      res.json({
        message: 'Auth Test Information',
        request: {
          origin: origin,
          method: req.method,
          path: req.path,
          hasCookies: !!Object.keys(cookies).length,
          cookieNames: Object.keys(cookies),
          hasAuthCookie: !!authToken,
          authTokenLength: authToken ? authToken.length : 0
        },
        auth: {
          cookieName: config.jwt.cookieName,
          hasToken: !!authToken,
          tokenPreview: authToken ? authToken.substring(0, 20) + '...' : 'No token'
        },
        timestamp: new Date()
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
