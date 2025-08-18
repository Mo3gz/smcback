const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const path = require('path');
require('dotenv').config();
const { MongoClient, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'Aymaan';

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: (origin, callback) => callback(null, true), // Allow all origins dynamically
    methods: ['GET', 'POST'],
    credentials: true
  }
});


// MongoDB connection variables
let mongoClient = null;
let db = null;
let mongoConnected = false;

// MongoDB connection
async function connectToMongoDB() {
  console.log(process.env.MONGODB_URI);
  try {
    mongoClient = new MongoClient(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    
    await mongoClient.connect();
    db = mongoClient.db(process.env.MONGO_DB_NAME || 'scoring-system');
    mongoConnected = true;
    
    console.log('✅ Connected to MongoDB');
    
    // Initialize default data after successful connection
    await initializeDefaultData();
    
  } catch (err) {
    console.error('❌ MongoDB connection error:', err);
    console.log('📝 Falling back to in-memory storage');
    mongoConnected = false;
  }
}

// Initialize MongoDB connection
connectToMongoDB();

// Middleware
// CORS for deployment: allow multiple origins and better mobile support
const allowedOrigins = [
  'https://smcscout.netlify.app',
  'http://localhost:3000',
  'http://localhost:3001',
  'https://localhost:3000',
  'https://localhost:3001'
];

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or Postman)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      // For development, allow all origins
      if (process.env.NODE_ENV === 'development') {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Cache-Control', 'Pragma', 'Accept', 'Origin', 'x-auth-token']
}));

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Origin', req.headers.origin);
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Cache-Control, Pragma, Accept, Origin, x-auth-token');
  next();
});

app.use(express.json());
app.use(cookieParser());

// Handle preflight requests
app.options('*', (req, res) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin);
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Cache-Control, Pragma, Accept, Origin, x-auth-token');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.status(200).end();
});

// In-memory data storage (fallback when MongoDB is not available)
let users = [
  {
    id: '1',
    username: 'ayman',
    password: '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password
    role: 'admin',
    teamName: 'Ayman',
    coins: 1000,
    score: 0,
    totalMined: 0,
    lastMined: null
  },
  {
    id: '2',
    username: 'team1',
    password: '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password
    role: 'user',
    teamName: 'Team Alpha',
    coins: 500,
    score: 0,
    totalMined: 0,
    lastMined: null
  },
  {
    id: '3',
    username: 'team2',
    password: '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password
    role: 'user',
    teamName: 'Team Beta',
    coins: 500,
    score: 0,
    totalMined: 0,
    lastMined: null
  }
];

let countries = [
  { id: '1', name: 'Egypt', cost: 200, owner: null, score: 150, miningRate: 100000 },
  { id: '2', name: 'Morocco', cost: 180, owner: null, score: 140, miningRate: 90000 },
  { id: '3', name: 'Algeria', cost: 160, owner: null, score: 130, miningRate: 80000 },
  { id: '4', name: 'Tunisia', cost: 140, owner: null, score: 120, miningRate: 70000 },
  { id: '5', name: 'Libya', cost: 120, owner: null, score: 110, miningRate: 60000 },
  { id: '6', name: 'Sudan', cost: 100, owner: null, score: 100, miningRate: 50000 },
  { id: '7', name: 'Ethiopia', cost: 90, owner: null, score: 90, miningRate: 45000 },
  { id: '8', name: 'Kenya', cost: 80, owner: null, score: 80, miningRate: 40000 },
  { id: '9', name: 'Nigeria', cost: 70, owner: null, score: 70, miningRate: 35000 },
  { id: '10', name: 'Ghana', cost: 60, owner: null, score: 60, miningRate: 30000 },
  { id: '11', name: 'South Africa', cost: 210, owner: null, score: 160, miningRate: 110000 },
  { id: '12', name: 'Senegal', cost: 75, owner: null, score: 65, miningRate: 37500 },
  { id: '13', name: 'Ivory Coast', cost: 85, owner: null, score: 75, miningRate: 42500 },
  { id: '14', name: 'Cameroon', cost: 95, owner: null, score: 85, miningRate: 47500 },
  { id: '15', name: 'Uganda', cost: 70, owner: null, score: 60, miningRate: 35000 },
  { id: '16', name: 'Saudi Arabia', cost: 220, owner: null, score: 170, miningRate: 120000 },
  { id: '17', name: 'United Arab Emirates', cost: 200, owner: null, score: 160, miningRate: 110000 },
  { id: '18', name: 'Qatar', cost: 180, owner: null, score: 150, miningRate: 100000 },
  { id: '19', name: 'Jordan', cost: 110, owner: null, score: 90, miningRate: 55000 },
  { id: '20', name: 'Lebanon', cost: 100, owner: null, score: 80, miningRate: 50000 },
  { id: '21', name: 'Turkey', cost: 230, owner: null, score: 180, miningRate: 130000 },
  { id: '22', name: 'Greece', cost: 150, owner: null, score: 120, miningRate: 75000 },
  { id: '23', name: 'Italy', cost: 250, owner: null, score: 200, miningRate: 150000 },
  { id: '24', name: 'France', cost: 270, owner: null, score: 220, miningRate: 170000 },
  { id: '25', name: 'Spain', cost: 260, owner: null, score: 210, miningRate: 160000 },
  { id: '26', name: 'Germany', cost: 280, owner: null, score: 230, miningRate: 180000 },
  { id: '27', name: 'United Kingdom', cost: 290, owner: null, score: 240, miningRate: 190000 },
  { id: '28', name: 'Portugal', cost: 140, owner: null, score: 110, miningRate: 70000 },
  { id: '29', name: 'Netherlands', cost: 200, owner: null, score: 160, miningRate: 110000 },
  { id: '30', name: 'Belgium', cost: 190, owner: null, score: 150, miningRate: 100000 }
];

let userInventories = {};
let notifications = [];
let promoCodes = [];

// Initialize default data in MongoDB
async function initializeDefaultData() {
  if (!mongoConnected || !db) return;

  try {
    // Initialize users if collection is empty
    const userCount = await db.collection('users').countDocuments();
    if (userCount === 0) {
      await db.collection('users').insertMany(users);
      console.log('✅ Default users initialized in MongoDB');
    }

    // Initialize countries if collection is empty
    const countryCount = await db.collection('countries').countDocuments();
    if (countryCount === 0) {
      await db.collection('countries').insertMany(countries);
      console.log('✅ Default countries initialized in MongoDB');
    }

    // Create indexes for better performance
    await db.collection('users').createIndex({ username: 1 }, { unique: true });
    await db.collection('users').createIndex({ id: 1 });
    await db.collection('countries').createIndex({ id: 1 });
    await db.collection('inventories').createIndex({ userId: 1 });
    await db.collection('notifications').createIndex({ timestamp: -1 });
    await db.collection('notifications').createIndex({ userId: 1 });
    await db.collection('notifications').createIndex({ userId: 1, read: 1 });
    await db.collection('notifications').createIndex({ type: 1 });
    await db.collection('promoCodes').createIndex({ code: 1, teamId: 1 });

    console.log('✅ Database indexes created successfully');

    // Load game settings from database
    await loadGameSettings();

    // Migrate existing notifications to ensure they have read field
    await migrateNotifications();

  } catch (error) {
    console.error('❌ Error initializing default data:', error);
  }
}

// Helper functions for users (MongoDB or fallback)
async function findUserByUsername(username) {
  if (mongoConnected && db) {
    return await db.collection('users').findOne({ username });
  } else {
    return users.find(u => u.username === username);
  }
}

async function findUserById(id) {
  if (mongoConnected && db) {
    // Try both string and ObjectId
    let user = await db.collection('users').findOne({ id });
    if (!user) {
      try {
        user = await db.collection('users').findOne({ _id: new ObjectId(id) });
      } catch (e) {
        // Invalid ObjectId format, ignore
      }
    }
    return user;
  } else {
    return users.find(u => u.id === id);
  }
}

async function updateUserById(id, update) {
  if (mongoConnected && db) {
    await db.collection('users').updateOne(
      { id },
      { $set: update }
    );
  } else {
    const idx = users.findIndex(u => u.id === id);
    if (idx !== -1) {
      users[idx] = { ...users[idx], ...update };
    }
  }
}

async function getAllUsers() {
  if (mongoConnected && db) {
    return await db.collection('users').find({}).toArray();
  } else {
    return users;
  }
}

// Helper functions for countries (MongoDB or fallback)
async function getAllCountries() {
  if (mongoConnected && db) {
    return await db.collection('countries').find({}).toArray();
  } else {
    return countries;
  }
}

async function findCountryById(id) {
  if (mongoConnected && db) {
    return await db.collection('countries').findOne({ id });
  } else {
    return countries.find(c => c.id === id);
  }
}

async function updateCountryById(id, update) {
  if (mongoConnected && db) {
    await db.collection('countries').updateOne(
      { id },
      { $set: update }
    );
  } else {
    const idx = countries.findIndex(c => c.id === id);
    if (idx !== -1) {
      countries[idx] = { ...countries[idx], ...update };
    }
  }
}

// Helper functions for inventories (MongoDB or fallback)
async function getUserInventory(userId) {
  if (mongoConnected && db) {
    const inventory = await db.collection('inventories').findOne({ userId });
    return inventory ? inventory.items : [];
  } else {
    return userInventories[userId] || [];
  }
}

async function addToUserInventory(userId, item) {
  if (mongoConnected && db) {
    await db.collection('inventories').updateOne(
      { userId },
      { 
        $push: { items: item },
        $setOnInsert: { userId, createdAt: new Date() }
      },
      { upsert: true }
    );
  } else {
    if (!userInventories[userId]) {
      userInventories[userId] = [];
    }
    userInventories[userId].push(item);
  }
}

async function removeFromUserInventory(userId, itemId) {
  if (mongoConnected && db) {
    await db.collection('inventories').updateOne(
      { userId },
      { $pull: { items: { id: itemId } } }
    );
  } else {
    if (userInventories[userId]) {
      const index = userInventories[userId].findIndex(item => item.id === itemId);
      if (index !== -1) {
        userInventories[userId].splice(index, 1);
      }
    }
  }
}

// Helper functions for notifications (MongoDB or fallback)
async function addNotification(notification) {
  // Ensure notification has default read status
  const notificationWithDefaults = {
    ...notification,
    read: notification.read !== undefined ? notification.read : false
  };
  
  if (mongoConnected && db) {
    await db.collection('notifications').insertOne(notificationWithDefaults);
  } else {
    notifications.push(notificationWithDefaults);
  }
}

async function getAllNotifications() {
  if (mongoConnected && db) {
    return await db.collection('notifications').find({}).sort({ timestamp: -1 }).toArray();
  } else {
    return notifications.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  }
}

// Get notifications for a specific user
async function getUserNotifications(userId) {
  if (mongoConnected && db) {
    return await db.collection('notifications').find({
      $or: [
        { userId: userId },
        { type: 'global' },
        { type: 'scoreboard-update' }
      ]
    }).sort({ timestamp: -1 }).toArray();
  } else {
    return notifications.filter(notification => 
      notification.userId === userId || 
      notification.type === 'global' ||
      notification.type === 'scoreboard-update'
    ).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  }
}

// Get unread notifications count for a user
async function getUnreadNotificationsCount(userId) {
  if (mongoConnected && db) {
    return await db.collection('notifications').countDocuments({
      $or: [
        { userId: userId, $or: [{ read: { $ne: true } }, { read: { $exists: false } }] },
        { type: 'global', $or: [{ read: { $ne: true } }, { read: { $exists: false } }] },
        { type: 'scoreboard-update', $or: [{ read: { $ne: true } }, { read: { $exists: false } }] }
      ]
    });
  } else {
    return notifications.filter(notification => 
      (notification.userId === userId || 
       notification.type === 'global' ||
       notification.type === 'scoreboard-update') && 
      !notification.read
    ).length;
  }
}

// Mark notification as read
async function markNotificationAsRead(notificationId, userId) {
  if (mongoConnected && db) {
    await db.collection('notifications').updateOne(
      { id: notificationId, userId: userId },
      { $set: { read: true, readAt: new Date() } }
    );
  } else {
    const notification = notifications.find(n => n.id === notificationId && n.userId === userId);
    if (notification) {
      notification.read = true;
      notification.readAt = new Date();
    }
  }
}

// Mark all notifications as read for a user
async function markAllNotificationsAsRead(userId) {
  if (mongoConnected && db) {
    await db.collection('notifications').updateMany(
      {
        $or: [
          { userId: userId, $or: [{ read: { $ne: true } }, { read: { $exists: false } }] },
          { type: 'global', $or: [{ read: { $ne: true } }, { read: { $exists: false } }] },
          { type: 'scoreboard-update', $or: [{ read: { $ne: true } }, { read: { $exists: false } }] }
        ]
      },
      { $set: { read: true, readAt: new Date() } }
    );
  } else {
    notifications.forEach(notification => {
      if ((notification.userId === userId || 
           notification.type === 'global' ||
           notification.type === 'scoreboard-update') && 
          !notification.read) {
        notification.read = true;
        notification.readAt = new Date();
      }
    });
  }
}

// Delete old notifications (cleanup function)
async function deleteOldNotifications(daysOld = 30) {
  if (mongoConnected && db) {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - daysOld);
    
    await db.collection('notifications').deleteMany({
      timestamp: { $lt: cutoffDate.toISOString() }
    });
  } else {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - daysOld);
    
    const filteredNotifications = notifications.filter(notification => 
      new Date(notification.timestamp) >= cutoffDate
    );
    notifications.length = 0;
    notifications.push(...filteredNotifications);
  }
}

// Helper functions for promo codes (MongoDB or fallback)
async function addPromoCode(promoCode) {
  if (mongoConnected && db) {
    await db.collection('promoCodes').insertOne(promoCode);
  } else {
    promoCodes.push(promoCode);
  }
}

async function findPromoCode(code, teamId) {
  if (mongoConnected && db) {
    return await db.collection('promoCodes').findOne({ code, teamId, used: false });
  } else {
    return promoCodes.find(p => p.code === code && p.teamId === teamId && !p.used);
  }
}

async function markPromoCodeAsUsed(code, teamId) {
  if (mongoConnected && db) {
    await db.collection('promoCodes').updateOne(
      { code, teamId },
      { $set: { used: true, usedAt: new Date() } }
    );
  } else {
    const promo = promoCodes.find(p => p.code === code && p.teamId === teamId);
    if (promo) {
      promo.used = true;
      promo.usedAt = new Date();
    }
  }
}

// Helper to get user id from body or query
function getUserId(req) {
  return req.body.id || req.query.id;
}

// Enhanced Authentication middleware with better debugging
function authenticateToken(req, res, next) {
  console.log('🔐 === AUTHENTICATION START ===');
  console.log('🔐 Request URL:', req.url);
  console.log('🔐 Request method:', req.method);
  console.log('🔐 Headers:', JSON.stringify({
    authorization: req.headers.authorization,
    'x-auth-token': req.headers['x-auth-token'],
    cookie: req.headers.cookie,
    origin: req.headers.origin
  }, null, 2));
  console.log('🔐 Cookies:', JSON.stringify(req.cookies, null, 2));
  const token = req.cookies.token || 
                (req.headers.authorization && req.headers.authorization.split(' ')[1]) ||
                req.headers['x-auth-token'] ||
                req.body.token;
  console.log('🔐 Token found:', token ? 'Yes' : 'No');
  console.log('🔐 Token source:', 
    req.cookies.token ? 'cookie' : 
    req.headers.authorization ? 'authorization header' :
    req.headers['x-auth-token'] ? 'x-auth-token header' :
    req.body.token ? 'request body' : 'none'
  );
  if (!token) {
    console.log('❌ No token provided');
    console.log('🔐 === AUTHENTICATION END (NO TOKEN) ===');
    return res.status(401).json({ 
      error: 'Access token required',
      debug: {
        cookies: req.cookies,
        authHeader: req.headers.authorization,
        xAuthToken: req.headers['x-auth-token']
      }
    });
  }
  console.log('🔐 Verifying token with JWT_SECRET...');
  console.log('🔐 JWT_SECRET exists:', JWT_SECRET ? 'Yes' : 'No');
  console.log('🔐 Token preview:', token.substring(0, 20) + '...');
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      console.log('❌ Token verification failed:', err.message);
      console.log('❌ Error details:', err);
      console.log('🔐 === AUTHENTICATION END (TOKEN INVALID) ===');
      return res.status(401).json({ 
        error: 'Invalid token',
        debug: {
          tokenError: err.message,
          tokenPreview: token.substring(0, 20) + '...'
        }
      });
    }
    console.log('✅ Token verified successfully');
    console.log('✅ Decoded user:', JSON.stringify(decoded, null, 2));
    console.log('🔐 === AUTHENTICATION END (SUCCESS) ===');
    req.user = decoded;
    next();
  });
}

// Enhanced Admin middleware with better debugging
function requireAdmin(req, res, next) {
  console.log('🔐 === ADMIN CHECK START ===');
  console.log('🔐 Request URL:', req.url);
  console.log('🔐 User from token:', JSON.stringify(req.user, null, 2));
  if (!req.user) {
    console.log('❌ Admin check failed: No user found in request');
    console.log('🔐 === ADMIN CHECK END (NO USER) ===');
    return res.status(401).json({ 
      error: 'Authentication required',
      debug: 'No user found in request object'
    });
  }
  console.log('🔐 User details:');
  console.log('🔐   - ID:', req.user.id);
  console.log('🔐   - Username:', req.user.username);
  console.log('🔐   - Role:', req.user.role);
  console.log('🔐   - Role type:', typeof req.user.role);
  if (req.user.username === 'ayman') {
    console.log('✅ Admin check BYPASS: username is ayman');
    console.log('🔐 === ADMIN CHECK END (BYPASS) ===');
    return next();
  }
  const userRole = req.user.role;
  const isAdmin = userRole === 'admin' || userRole === 'ADMIN' || userRole === 'Admin';
  console.log('🔐 Role check details:');
  console.log('🔐   - User role:', userRole);
  console.log('🔐   - Is admin (strict):', userRole === 'admin');
  console.log('🔐   - Is admin (case insensitive):', isAdmin);
  if (!isAdmin) {
    console.log('❌ Admin check failed: User role is not admin');
    console.log('🔐 === ADMIN CHECK END (FAILED) ===');
    return res.status(403).json({ 
      error: 'Admin access required',
      debug: {
        userRole: userRole,
        userId: req.user.id,
        username: req.user.username,
        requiredRole: 'admin',
        isAdminCheck: isAdmin
      }
    });
  }
  console.log('✅ Admin check passed for user:', req.user.username);
  console.log('🔐 === ADMIN CHECK END (SUCCESS) ===');
  next();
}

// Enhanced admin check endpoint with more debugging
app.get('/api/admin/check', authenticateToken, requireAdmin, async (req, res) => {
  try {
    console.log('🔐 Admin check endpoint reached successfully');
    console.log('🔐 Final user object:', JSON.stringify(req.user, null, 2));
    res.json({ 
      message: 'Admin access confirmed',
      user: {
        id: req.user.id,
        username: req.user.username,
        role: req.user.role,
        teamName: req.user.teamName
      },
      debug: {
        timestamp: new Date().toISOString(),
        authMethod: 'token verified',
        adminBypass: req.user.username === 'ayman'
      }
    });
  } catch (error) {
    console.error('❌ Admin check endpoint error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      debug: error.message
    });
  }
});

// Additional debug endpoint to test authentication without admin requirement
app.get('/api/debug/token-test', authenticateToken, async (req, res) => {
  try {
    console.log('🔍 Token test endpoint - User:', JSON.stringify(req.user, null, 2));
    res.json({
      message: 'Token authentication successful',
      user: req.user,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('❌ Token test error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Debug endpoint to check current authentication state
app.get('/api/debug/auth-state', (req, res) => {
  console.log('🔍 Auth state check');
  console.log('🔍 Cookies:', req.cookies);
  console.log('🔍 Headers:', req.headers);
  res.json({
    cookies: req.cookies,
    headers: {
      authorization: req.headers.authorization,
      'x-auth-token': req.headers['x-auth-token'],
      'user-agent': req.headers['user-agent'],
      'origin': req.headers.origin
    },
    hasToken: !!(req.cookies.token || req.headers.authorization || req.headers['x-auth-token']),
    timestamp: new Date().toISOString()
  });
});

// Helper to get cookie options based on environment
function getCookieOptions() {
  const isProduction = process.env.NODE_ENV === 'production';
  return {
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: isProduction ? 'none' : 'lax',
    secure: isProduction ? true : false,
    path: '/',
  };
}

app.post('/api/logout', (req, res) => {
  try {
    console.log('🚪 === LOGOUT START ===');
    console.log('🚪 Logout request received');
    const cookieOptions = getCookieOptions();
    res.clearCookie('token', cookieOptions);
    res.clearCookie('authToken', cookieOptions);
    res.clearCookie('session', cookieOptions);
    console.log('✅ Logout successful - cookies cleared');
    console.log('🚪 === LOGOUT END ===');
    res.json({ 
      message: 'Logged out successfully',
      success: true 
    });
  } catch (error) {
    console.error('❌ Logout error:', error);
    res.status(500).json({ 
      error: 'Logout failed',
      success: false 
    });
  }
});

// Removed duplicate requireAdmin function - using the enhanced version above

app.get('/api/debug/auth-state', (req, res) => {
  res.json({
    cookies: req.cookies,
    headers: {
      authorization: req.headers.authorization,
      'x-auth-token': req.headers['x-auth-token']
    },
    hasToken: !!(req.cookies.token || req.headers.authorization || req.headers['x-auth-token']),
    timestamp: new Date().toISOString()
  });
});

app.post('/api/login', async (req, res) => {
  try {
    console.log('🔑 === LOGIN START ===');
    console.log('🔑 Login attempt:', { username: req.body.username });
    console.log('🔑 Request headers:', JSON.stringify({
      origin: req.headers.origin,
      'user-agent': req.headers['user-agent'],
      'content-type': req.headers['content-type']
    }, null, 2));
    const { username, password } = req.body;
    if (!username || !password) {
      console.log('❌ Missing credentials');
      return res.status(400).json({ error: 'Username and password are required' });
    }
    const user = await findUserByUsername(username);
    if (!user) {
      console.log('❌ User not found:', username);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    console.log('✅ User found:', { 
      username: user.username, 
      role: user.role,
      id: user.id || user._id 
    });
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      console.log('❌ Invalid password for user:', username);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    console.log('✅ Password verified for user:', username);
    const tokenPayload = { 
      id: user.id || user._id, 
      username: user.username, 
      role: user.role, 
      teamName: user.teamName 
    };
    console.log('🔑 Creating token with payload:', tokenPayload);
    const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '24h' });
    const cookieOptions = getCookieOptions();
    res.cookie('token', token, cookieOptions);
    console.log('✅ Login successful for user:', username);
    const responseData = {
      user: {
        id: user.id || user._id,
        username: user.username,
        role: user.role,
        teamName: user.teamName,
        coins: user.coins,
        score: user.score
      },
      token: token // Include token for localStorage fallback
    };
    console.log('🔑 Sending response:', responseData);
    console.log('🔑 === LOGIN END (SUCCESS) ===');
    res.json(responseData);
  } catch (error) {
    console.error('❌ Login error:', error);
    console.log('🔑 === LOGIN END (ERROR) ===');
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/scoreboard', async (req, res) => {
  try {
    const users = await getAllUsers();
    const scoreboard = users
      .filter(user => user.role === 'user')
      .map(user => ({
        id: user.id || user._id,
        teamName: user.teamName,
        score: user.score,
        coins: user.coins
      }))
      .sort((a, b) => b.score - a.score);
    
    res.json(scoreboard);
  } catch (error) {
    console.error('Get scoreboard error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/countries', async (req, res) => {
  try {
    const countries = await getAllCountries();
    // Include mining rate in the response
    const countriesWithMining = countries.map(country => ({
      ...country,
      miningRate: country.miningRate || 0
    }));
    res.json(countriesWithMining);
  } catch (error) {
    console.error('Get countries error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/countries/buy', authenticateToken, async (req, res) => {
  try {
    const { countryId } = req.body;
    const user = await findUserById(req.user.id);
    const country = await findCountryById(countryId);

    if (!country) {
      return res.status(404).json({ error: 'Country not found' });
    }

    if (country.owner) {
      return res.status(400).json({ error: 'Country already owned' });
    }

    if (user.coins < country.cost) {
      return res.status(400).json({ error: 'Insufficient coins' });
    }

    const newCoins = user.coins - country.cost;
    const newScore = user.score + country.score;
    const userId = user.id || user._id;

    // Calculate new mining rate after buying the country
    const currentCountries = await getAllCountries();
    const ownedCountries = currentCountries.filter(c => c.owner === userId);
    const newMiningRate = ownedCountries.reduce((sum, c) => sum + (c.miningRate || 0), 0) + (country.miningRate || 0);

    // Update user with new coins, score, and mining rate
    await updateUserById(req.user.id, { 
      coins: newCoins, 
      score: newScore,
      miningRate: newMiningRate
    });
    
    // Emit user-update for this user with mining rate
    io.to(userId).emit('user-update', {
      id: userId,
      teamName: user.teamName,
      coins: newCoins,
      score: newScore,
      miningRate: newMiningRate
    });

    // Update country with ownership and mining start time
    await updateCountryById(countryId, { 
      owner: userId,
      lastMined: new Date().toISOString()
    });

    // Check if user has active Speed Buy challenge
    const speedBuyTimers = global.speedBuyTimers || {};
    if (speedBuyTimers[userId]) {
      const timer = speedBuyTimers[userId];
      const currentTime = Date.now();
      
      // Check if timer is still active
      if (currentTime < (timer.startTime + timer.duration)) {
        // Give Speed Buy reward instantly
        const speedBuyReward = timer.reward;
        const newCoinsWithReward = newCoins + speedBuyReward;
        
        await updateUserById(req.user.id, { 
          coins: newCoinsWithReward, 
          score: newScore,
          miningRate: newMiningRate
        });
        
        // Emit updated user data with Speed Buy reward
        io.to(userId).emit('user-update', {
          id: userId,
          teamName: user.teamName,
          coins: newCoinsWithReward,
          score: newScore,
          miningRate: newMiningRate
        });
        
        // Notify user about Speed Buy completion
        const speedBuyNotification = {
          id: Date.now().toString(),
          userId: userId,
          type: 'speedbuy-completed',
          message: `Speed Buy Challenge completed! You earned an additional ${speedBuyReward} coins for buying ${country.name}!`,
          timestamp: new Date().toISOString(),
          read: false,
          recipientType: 'user'
        };
        await addNotification(speedBuyNotification);
        io.to(userId).emit('notification', speedBuyNotification);
        
        // Clear the timer
        delete speedBuyTimers[userId];
        
        // Update final coins for response
        newCoins = newCoinsWithReward;
      }
    }

    // Create notification for the country purchase
    const notification = {
      id: Date.now().toString(),
      userId: userId,
      type: 'country-purchased',
      message: `You purchased ${country.name} for ${country.cost} coins!`,
      timestamp: new Date().toISOString(),
      read: false,
      recipientType: 'user'
    };

    await addNotification(notification);
    io.to(userId).emit('notification', notification);

    // Notify all clients about the update
    const updatedUsers = await getAllUsers();
    const updatedCountries = await getAllCountries();
    
    io.emit('scoreboard-update', updatedUsers);
    io.emit('countries-update', updatedCountries);

    // Admin notification for country purchase
    const adminCountryNotification = {
      id: Date.now().toString(),
      type: 'country-bought',
      teamId: userId,
      teamName: user.teamName,
      message: `${user.teamName} bought ${country.name} for ${country.cost} coins`,
      countryName: country.name,
      countryId: country.id,
      cost: country.cost,
      timestamp: new Date().toISOString(),
      read: false,
      recipientType: 'admin'
    };
    await addNotification(adminCountryNotification);
    io.emit('admin-notification', adminCountryNotification);

    res.json({ 
      message: `Successfully bought ${country.name}`,
      user: {
        coins: newCoins,
        score: newScore,
        miningRate: newMiningRate
      }
    });
  } catch (error) {
    console.error('Buy country error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/inventory', authenticateToken, async (req, res) => {
  try {
    const inventory = await getUserInventory(req.user.id);
    res.json(inventory);
  } catch (error) {
    console.error('Get inventory error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/cards/use', authenticateToken, async (req, res) => {
  try {
    const { cardId, selectedTeam, selectedGame, description } = req.body;
    const user = await findUserById(req.user.id);
    const inventory = await getUserInventory(req.user.id);
    
    const card = inventory.find(card => card.id === cardId);
    if (!card) {
      return res.status(404).json({ error: 'Card not found in inventory' });
    }

    // Special handling for borrow card
    if (card.name === "Borrow coins to buy a country") {
      // Check if user balance is negative - if so, they can't use the card
      if (user.coins < 0) {
        return res.status(400).json({ error: 'Cannot use borrow card when balance is already negative' });
      }
      
      // Check if balance would go below -200
      if (user.coins < -200) {
        return res.status(400).json({ error: 'Cannot borrow - balance limit is -200' });
      }
    }

    // Special handling for Secret Info card
    if (card.name === "Secret Info" && selectedGame) {
      try {
        const fs = require('fs');
        const gameInfo = JSON.parse(fs.readFileSync('./game-info.json', 'utf8'));
        const userTeamKey = user.id.startsWith('team') ? user.id : `team${user.id}`;
        
        if (gameInfo.teams[userTeamKey] && gameInfo.teams[userTeamKey].games[selectedGame]) {
          const gameData = gameInfo.teams[userTeamKey].games[selectedGame];
          
          // Remove card from inventory
          await removeFromUserInventory(req.user.id, cardId);
          
          // Send secret info directly to user
          const secretInfoNotification = {
            id: Date.now().toString(),
            userId: req.user.id,
            type: 'secret-info',
            message: `Secret Info for Game ${selectedGame}: ${gameData.details}`,
            timestamp: new Date().toISOString(),
            read: false,
            recipientType: 'user',
            metadata: {
              game: selectedGame,
              opponent: gameData.opponent,
              details: gameData.details
            }
          };
          await addNotification(secretInfoNotification);
          io.to(req.user.id).emit('notification', secretInfoNotification);
          
          return res.json({ 
            success: true, 
            message: 'Secret info revealed!',
            gameData 
          });
        }
      } catch (error) {
        console.error('Secret info error:', error);
        return res.status(500).json({ error: 'Failed to get secret info' });
      }
    }

    // Remove card from inventory for other cards
    await removeFromUserInventory(req.user.id, cardId);

    // Get target team name if selectedTeam is provided
    let targetTeamName = '';
    if (selectedTeam) {
      const targetTeam = await findUserById(selectedTeam);
      targetTeamName = targetTeam ? targetTeam.teamName : 'Unknown Team';
    }

    // Create notification for admin only
    let adminMessage = `Team ${user.teamName} used: ${card.name}`;
    if (selectedGame) {
      adminMessage += ` | Game: ${selectedGame}`;
    }
    if (targetTeamName && targetTeamName !== 'Unknown Team') {
      adminMessage += ` | Target: ${targetTeamName}`;
    }
    if (description) {
      adminMessage += ` | Note: ${description}`;
    }
    
    const notification = {
      id: Date.now().toString(),
      type: 'card-used',
      message: adminMessage,
      teamId: req.user.id,
      teamName: user.teamName,
      cardName: card.name,
      cardType: card.type,
      selectedGame: selectedGame,
      selectedTeam: targetTeamName, // Store team name instead of ID
      description,
      timestamp: new Date().toISOString(),
      read: false,
      recipientType: 'admin'
    };
    await addNotification(notification);
    io.emit('admin-notification', notification);

    // Create notification for the user
    let userMessage = `You used: ${card.name}`;
    if (targetTeamName && targetTeamName !== 'Unknown Team') {
      userMessage += ` | Target: ${targetTeamName}`;
    }
    const userNotification = {
      id: (Date.now() + 1).toString(),
      userId: req.user.id,
      type: 'card-used',
      message: userMessage,
      timestamp: new Date().toISOString(),
      read: false,
      recipientType: 'user'
    };
    await addNotification(userNotification);
    io.to(req.user.id).emit('notification', userNotification);

    // Notify user that inventory has been updated
    io.to(req.user.id).emit('inventory-update');
    // Notify all admins (and listeners) that any inventory has changed
    io.emit('inventory-update');

    res.json({ message: 'Card used successfully' });
  } catch (error) {
    console.error('Use card error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/spin', authenticateToken, async (req, res) => {
  try {
    const { spinType, promoCode } = req.body;
    const user = await findUserById(req.user.id);
    
    // Set costs for new spin types
    let cost = 50;
    switch(spinType) {
      case 'lucky': cost = 50; break;
      case 'gamehelper': cost = 75; break;
      case 'challenge': cost = 100; break;
      case 'hightier': cost = 150; break;
      case 'lowtier': cost = 25; break;
      case 'random': cost = 30; break;
      default: cost = 50;
    }

    // Check promo code
    if (promoCode) {
      const promo = await findPromoCode(promoCode, req.user.id);
      if (promo) {
        cost = Math.floor(cost * (1 - promo.discount / 100));
        await markPromoCodeAsUsed(promoCode, req.user.id);
      }
    }

    if (user.coins < cost) {
      return res.status(400).json({ error: 'Insufficient coins' });
    }

    const newCoins = user.coins - cost;
    await updateUserById(req.user.id, { coins: newCoins });

    // Generate random card based on spin type
    const cards = getCardsByType(spinType);
    const randomCard = cards[Math.floor(Math.random() * cards.length)];

    let finalCoins = newCoins;
    let isInstantAction = false;
    let additionalData = {};

    // Handle different action types
    switch(randomCard.actionType) {
      case 'instant':
        // Instant coin changes
        finalCoins = newCoins + (randomCard.coinChange || 0);
        await updateUserById(req.user.id, { coins: finalCoins });
        isInstantAction = true;
        break;

      case 'instant_tax':
        // Pay 10 coins per owned country
        const ownedCountries = await getOwnedCountriesCount(req.user.id);
        const taxAmount = ownedCountries * 10;
        finalCoins = newCoins - taxAmount;
        await updateUserById(req.user.id, { coins: finalCoins });
        isInstantAction = true;
        additionalData.taxAmount = taxAmount;
        additionalData.ownedCountries = ownedCountries;
        break;

      case 'random_gift':
        // Give 50 coins to random team
        const allUsers = await getAllUsers();
        const otherUsers = allUsers.filter(u => u.id !== req.user.id);
        if (otherUsers.length > 0) {
          const randomUser = otherUsers[Math.floor(Math.random() * otherUsers.length)];
          await updateUserById(randomUser.id, { coins: randomUser.coins + 50 });
          
          // Notify both teams
          const giftNotification = {
            id: Date.now().toString(),
            userId: randomUser.id,
            type: 'gift-received',
            message: `You received 50 coins from ${user.teamName}'s spin!`,
            timestamp: new Date().toISOString(),
            read: false,
            recipientType: 'user'
          };
          await addNotification(giftNotification);
          io.to(randomUser.id).emit('notification', giftNotification);
          
          additionalData.giftedTeam = randomUser.teamName;
        }
        isInstantAction = true;
        break;

      case 'speed_buy':
        // Start 10-minute timer for speed buy challenge
        const speedBuyTimer = {
          userId: req.user.id,
          startTime: Date.now(),
          duration: 10 * 60 * 1000, // 10 minutes
          reward: 50
        };
        // Store timer in memory or database
        global.speedBuyTimers = global.speedBuyTimers || {};
        global.speedBuyTimers[req.user.id] = speedBuyTimer;
        
        additionalData.timerStarted = true;
        additionalData.duration = 10;
        break;

      case 'mcq':
        // Load random question for MCQ
        const fs = require('fs');
        const questions = JSON.parse(fs.readFileSync('./spiritual-questions.json', 'utf8'));
        const randomQuestion = questions.questions[Math.floor(Math.random() * questions.questions.length)];
        additionalData.question = randomQuestion;
        additionalData.timeLimit = 10; // 10 seconds
        break;
    }

    // Emit user-update for coin changes
    io.to(user.id || user._id).emit('user-update', {
      id: user.id || user._id,
      teamName: user.teamName,
      coins: finalCoins,
      score: user.score
    });

    // Add to inventory for admin cards and non-instant cards (but not instant challenges like MCQ)
    if (!isInstantAction && !randomCard.isInstantChallenge) {
      const cardToAdd = {
        id: Date.now().toString(),
        name: randomCard.name,
        type: randomCard.type,
        effect: randomCard.effect,
        obtainedAt: new Date().toISOString()
      };
      await addToUserInventory(req.user.id, cardToAdd);
      io.to(req.user.id).emit('inventory-update');
    }

    // User notification for spin
    const userSpinNotification = {
      id: Date.now().toString(),
      userId: req.user.id,
      type: 'spin',
      message: `You spun and received: ${randomCard.name} (${randomCard.type})`,
      timestamp: new Date().toISOString(),
      read: false,
      recipientType: 'user'
    };
    await addNotification(userSpinNotification);
    io.to(req.user.id).emit('notification', userSpinNotification);

    // Send admin notification for non-instant cards or special cases
    if (randomCard.actionType === 'admin' || !isInstantAction) {
      const adminSpinNotification = {
        id: Date.now().toString(),
        type: 'spin',
        teamId: user.id || user._id,
        teamName: user.teamName,
        message: `${user.teamName} spun the wheel and got: ${randomCard.name} (${randomCard.type})`,
        cardName: randomCard.name,
        cardType: randomCard.type,
        requiresGameSelection: randomCard.requiresGameSelection,
        requiresTeamSelection: randomCard.requiresTeamSelection,
        timestamp: new Date().toISOString(),
        read: false,
        recipientType: 'admin'
      };
      await addNotification(adminSpinNotification);
      io.emit('admin-notification', adminSpinNotification);
    }

    // Emit scoreboard update
    const updatedUsers = await getAllUsers();
    io.emit('scoreboard-update', updatedUsers);

    res.json({ 
      card: randomCard,
      cost,
      remainingCoins: finalCoins,
      actionType: randomCard.actionType,
      additionalData
    });
  } catch (error) {
    console.error('Spin error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin routes
app.get('/api/admin/notifications', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const notifications = await getAllNotifications();
    res.json(notifications);
  } catch (error) {
    console.error('Get notifications error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/admin/promocodes', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { code, teamId, discount } = req.body;
    const adminUser = await findUserById(req.user.id);
    
    // Validate discount: must be integer between 1 and 100
    if (!Number.isInteger(discount) || discount < 1 || discount > 100) {
      return res.status(400).json({ error: 'Discount must be an integer between 1 and 100.' });
    }
    
    // Prevent duplicate promocode for the same team
    let existingPromo = null;
    if (mongoConnected && db) {
      existingPromo = await db.collection('promoCodes').findOne({ code, teamId });
    } else {
      existingPromo = promoCodes.find(p => p.code === code && p.teamId === teamId);
    }
    if (existingPromo) {
      return res.status(400).json({ error: 'This promocode already exists for the selected team.' });
    }
    
    const promoCode = {
      id: Date.now().toString(),
      code,
      teamId,
      discount,
      used: false,
      createdAt: new Date().toISOString(),
      createdBy: req.user.id // Track which admin created this promo code
    };
    
    await addPromoCode(promoCode);
    
    // Notify the specific team
    const user = await findUserById(teamId);
    if (user) {
      const teamNotification = {
        id: Date.now().toString(),
        userId: teamId,
        type: 'promo-code',
        message: `You received a promo code: ${code} with ${discount}% discount!`,
        timestamp: new Date().toISOString(),
        read: false,
        recipientType: 'user'
      };
      await addNotification(teamNotification);
      io.to(teamId).emit('notification', teamNotification);
      
      // Create admin action notification
      const adminAction = {
        id: (Date.now() + 1).toString(),
        userId: req.user.id, // Admin's user ID
        type: 'admin-action',
        actionType: 'promo-code-created',
        message: `Admin ${adminUser.teamName} created a promo code (${code}) with ${discount}% discount for team ${user.teamName}.`,
        timestamp: new Date().toISOString(),
        read: false,
        recipientType: 'admin',
        metadata: {
          targetTeamId: teamId,
          targetTeamName: user.teamName,
          promoCode: code,
          discount: discount
        }
      };
      
      await addNotification(adminAction);
      // Emit to all admin clients
      io.emit('admin-notification', adminAction);
    }
    
    res.json(promoCode);
  } catch (error) {
    console.error('Create promo code error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/admin/cards', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { teamId, cardName, cardType } = req.body;
    const adminUser = await findUserById(req.user.id);
    const user = await findUserById(teamId);
    
    if (!user) {
      return res.status(404).json({ error: 'Team not found' });
    }

    const card = {
      id: Date.now().toString(),
      name: cardName,
      type: cardType,
      obtainedAt: new Date().toISOString()
    };

    await addToUserInventory(teamId, card);

    // Find the effect for the card
    let effect = '';
    try {
      const cardsList = getCardsByType(cardType === 'random' ? 'luck' : cardType);
      const found = cardsList.find(c => c.name === cardName);
      if (found) effect = found.effect;
    } catch (e) {
      console.error('Error finding card effect:', e);
    }

    // Format card type for display (capitalize first letter)
    const displayCardType = cardType.charAt(0).toUpperCase() + cardType.slice(1);

    // Notify the team with card name and effect
    const teamNotification = {
      id: Date.now().toString(),
      userId: teamId,
      type: 'card-received',
      message: `You received a new ${displayCardType} card: ${cardName}${effect ? ' - ' + effect : ''}`,
      timestamp: new Date().toISOString(),
      read: false,
      recipientType: 'user',
      metadata: {
        cardName,
        cardType,
        effect
      }
    };

    // Send notification to the team
    io.to(teamId).emit('notification', teamNotification);
    await addNotification(teamNotification);
    
    // Create admin action notification
    const adminAction = {
      id: (Date.now() + 1).toString(),
      userId: req.user.id, // Admin's user ID
      type: 'admin-action',
      actionType: 'card-assigned',
      message: `Admin ${adminUser.teamName} assigned ${displayCardType} card "${cardName}" to team ${user.teamName}.`,
      timestamp: new Date().toISOString(),
      read: false,
      recipientType: 'admin',
      metadata: {
        targetTeamId: teamId,
        targetTeamName: user.teamName,
        cardName: cardName,
        cardType: cardType,
        effect: effect || 'No effect description available'
      }
    };

    // Save and emit admin action notification
    await addNotification(adminAction);
    io.emit('admin-notification', adminAction);
    
    // Notify user that inventory has been updated
    io.to(teamId).emit('inventory-update');
    
    // Update scoreboard to reflect any changes
    const updatedUsers = await getAllUsers();
    io.emit('scoreboard-update', updatedUsers);

    res.json({
      ...card,
      effect: effect || null
    });
  } catch (error) {
    console.error('Give card error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/admin/coins', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { teamId, amount, reason } = req.body;
    const adminUser = await findUserById(req.user.id);
    const user = await findUserById(teamId);
    
    if (!user) {
      return res.status(404).json({ error: 'Team not found' });
    }

    const newCoins = user.coins + amount;
    await updateUserById(teamId, { coins: newCoins });
    
    // Emit user-update for this user
    io.to(teamId).emit('user-update', {
      id: teamId,
      teamName: user.teamName,
      coins: newCoins,
      score: user.score
    });

    // Notify the team
    const teamNotification = {
      id: Date.now().toString(),
      userId: teamId,
      type: 'coins-updated',
      message: `Your coins were ${amount > 0 ? 'increased' : 'decreased'} by ${Math.abs(amount)}. Reason: ${reason}`,
      timestamp: new Date().toISOString(),
      read: false,
      recipientType: 'user',
      metadata: {
        amount: amount,
        reason: reason
      }
    };

    await addNotification(teamNotification);
    io.to(teamId).emit('notification', teamNotification);
    
    // Create admin action notification
    const adminAction = {
      id: (Date.now() + 1).toString(),
      userId: req.user.id, // Admin's user ID
      type: 'admin-action',
      actionType: 'coins-updated',
      message: `Admin ${adminUser.teamName} ${amount > 0 ? 'added' : 'subtracted'} ${Math.abs(amount)} coins to team ${user.teamName}. Reason: ${reason}`,
      timestamp: new Date().toISOString(),
      read: false,
      recipientType: 'admin',
      metadata: {
        targetTeamId: teamId,
        targetTeamName: user.teamName,
        amount: amount,
        reason: reason
      }
    };

    await addNotification(adminAction);
    // Emit to all admin clients
    io.emit('admin-notification', adminAction);
    
    const updatedUsers = await getAllUsers();
    io.emit('scoreboard-update', updatedUsers);

    res.json({ 
      message: 'Coins updated successfully',
      user: {
        coins: newCoins,
        score: user.score
      }
    });
  } catch (error) {
    console.error('Update coins error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/admin/score', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { teamId, amount, reason } = req.body;
    const adminUser = await findUserById(req.user.id);
    const user = await findUserById(teamId);
    
    if (!user) {
      return res.status(404).json({ error: 'Team not found' });
    }

    const newScore = user.score + amount;
    await updateUserById(teamId, { score: newScore });
    
    // Emit user-update for this user
    io.to(teamId).emit('user-update', {
      id: teamId,
      teamName: user.teamName,
      coins: user.coins,
      score: newScore
    });

    // Notify the team
    const teamNotification = {
      id: Date.now().toString(),
      userId: teamId,
      type: 'score-updated',
      message: `Your score was ${amount > 0 ? 'increased' : 'decreased'} by ${Math.abs(amount)}. Reason: ${reason}`,
      timestamp: new Date().toISOString(),
      read: false,
      recipientType: 'user'
    };

    await addNotification(teamNotification);
    io.to(teamId).emit('notification', teamNotification);
    
    // Create admin action notification
    const adminAction = {
      id: (Date.now() + 1).toString(),
      userId: req.user.id, // Admin's user ID
      type: 'admin-action',
      actionType: 'score-update',
      message: `Admin ${adminUser.teamName} ${amount > 0 ? 'added' : 'subtracted'} ${Math.abs(amount)} points to team ${user.teamName}. Reason: ${reason}`,
      timestamp: new Date().toISOString(),
      read: false,
      recipientType: 'admin',
      metadata: {
        targetTeamId: teamId,
        targetTeamName: user.teamName,
        amount: amount,
        reason: reason
      }
    };

    await addNotification(adminAction);
    // Emit to all admin clients
    io.emit('admin-notification', adminAction);
    
    const updatedUsers = await getAllUsers();
    io.emit('scoreboard-update', updatedUsers);

    res.json({ 
      message: 'Score updated successfully',
      user: {
        coins: user.coins,
        score: newScore
      }
    });
  } catch (error) {
    console.error('Update score error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});



// Get user notifications
app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const userNotifications = await getUserNotifications(userId);
    res.json(userNotifications);
  } catch (error) {
    console.error('Get notifications error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get unread notifications count
app.get('/api/notifications/unread-count', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const unreadCount = await getUnreadNotificationsCount(userId);
    res.json({ unreadCount });
  } catch (error) {
    console.error('Get unread count error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Mark notification as read
app.post('/api/notifications/:notificationId/read', authenticateToken, async (req, res) => {
  try {
    const { notificationId } = req.params;
    const userId = req.user.id;
    
    await markNotificationAsRead(notificationId, userId);
    res.json({ message: 'Notification marked as read' });
  } catch (error) {
    console.error('Mark notification read error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Mark all notifications as read
app.post('/api/notifications/read-all', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    await markAllNotificationsAsRead(userId);
    
    // Get updated unread count to verify
    const unreadCount = await getUnreadNotificationsCount(userId);
    
    res.json({ 
      message: 'All notifications marked as read',
      unreadCount: unreadCount
    });
  } catch (error) {
    console.error('Mark all notifications read error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Debug endpoint to check notification status
app.get('/api/debug/notifications/:userId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    
    const allNotifications = await getUserNotifications(userId);
    const unreadCount = await getUnreadNotificationsCount(userId);
    
    const notificationsWithReadStatus = allNotifications.map(notification => ({
      id: notification.id,
      type: notification.type,
      message: notification.message,
      timestamp: notification.timestamp,
      read: notification.read,
      readExists: notification.hasOwnProperty('read'),
      userId: notification.userId
    }));
    
    res.json({
      userId,
      totalNotifications: allNotifications.length,
      unreadCount,
      notifications: notificationsWithReadStatus
    });
  } catch (error) {
    console.error('Debug notifications error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});



// Admin: Delete old notifications (cleanup)
app.delete('/api/admin/notifications/cleanup', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { daysOld = 30 } = req.body;
    await deleteOldNotifications(daysOld);
    res.json({ message: `Deleted notifications older than ${daysOld} days` });
  } catch (error) {
    console.error('Cleanup notifications error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin: Get all teams with their cards for admin dashboard
app.get('/api/admin/teams-cards', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const users = await getAllUsers();
    const teamsWithCards = [];
    
    // Filter only user role (teams) and get their inventory
    for (const user of users) {
      if (user.role === 'user') {
        const inventory = await getUserInventory(user.id || user._id);
        teamsWithCards.push({
          id: user.id || user._id,
          teamName: user.teamName,
          score: user.score,
          coins: user.coins,
          cards: inventory || []
        });
      }
    }
    
    // Sort by score (highest first)
    teamsWithCards.sort((a, b) => b.score - a.score);
    
    res.json(teamsWithCards);
  } catch (error) {
    console.error('Get teams with cards error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Debug route to print all users
app.get('/api/debug/users', async (req, res) => {
  try {
    const users = await getAllUsers();
    console.log('All users:', users);
    res.json(users);
  } catch (error) {
    console.error('Debug users error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Simple test endpoint to verify server is working
app.get('/api/test', (req, res) => {
  console.log('🧪 Test endpoint called');
  res.json({ 
    message: 'Server is working!', 
    timestamp: new Date().toISOString(),
    gameSettings: gameSettings
  });
});

// Health check endpoint (no authentication required)
app.get('/api/health', (req, res) => {
  console.log('🏥 Health check endpoint called');
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    gameSettings: gameSettings,
    mongoConnected: mongoConnected
  });
});

// Debug route to test admin login
app.post('/api/debug/admin-test', async (req, res) => {
  try {
    const { username, password } = req.body;
    console.log('Admin test login attempt:', { username, password });
    
    const user = await findUserByUsername(username);
    console.log('Found user:', user);
    
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    console.log('Password valid:', validPassword);
    
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid password' });
    }
    
    res.json({
      success: true,
      user: {
        id: user.id || user._id,
        username: user.username,
        role: user.role,
        teamName: user.teamName,
        isAdmin: user.role === 'admin'
      }
    });
  } catch (error) {
    console.error('Admin test error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Debug route to create test notifications
app.post('/api/debug/create-test-notifications', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    console.log('Creating test notifications for user:', userId);
    
    const testNotifications = [
      {
        id: Date.now().toString(),
        userId: userId,
        type: 'spin',
        message: 'You spun and got: Hidden Treasure - +400 Points instantly',
        timestamp: new Date().toISOString(),
        read: false,
        recipientType: 'user'
      },
      {
        id: (Date.now() + 1).toString(),
        userId: userId,
        type: 'coins-updated',
        message: '+100 coins: Admin bonus',
        timestamp: new Date(Date.now() - 60000).toISOString(), // 1 minute ago
        read: false,
        recipientType: 'user'
      },
      {
        id: (Date.now() + 2).toString(),
        userId: userId,
        type: 'score-updated',
        message: '+50 points: Challenge completed',
        timestamp: new Date(Date.now() - 120000).toISOString(), // 2 minutes ago
        read: true,
        recipientType: 'user'
      },
      {
        id: (Date.now() + 3).toString(),
        userId: userId,
        type: 'country-purchased',
        message: 'You purchased: Egypt for 200 coins',
        timestamp: new Date(Date.now() - 180000).toISOString(), // 3 minutes ago
        read: false,
        recipientType: 'user'
      },
      {
        id: (Date.now() + 4).toString(),
        userId: userId,
        type: 'global',
        message: 'Welcome to the Scout Game! Good luck!',
        timestamp: new Date(Date.now() - 300000).toISOString(), // 5 minutes ago
        read: true,
        recipientType: 'global'
      }
    ];
    
    // Add each notification to the database
    for (const notification of testNotifications) {
      await addNotification(notification);
    }
    
    console.log('✅ Created', testNotifications.length, 'test notifications');
    
    res.json({ 
      message: `Created ${testNotifications.length} test notifications`,
      notifications: testNotifications
    });
  } catch (error) {
    console.error('❌ Error creating test notifications:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Debug route to get all notifications for a user
app.get('/api/debug/user-notifications/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    console.log('Getting all notifications for user:', userId);
    
    const notifications = await getUserNotifications(userId);
    console.log('Found notifications:', notifications);
    
    res.json({
      userId,
      count: notifications.length,
      notifications
    });
  } catch (error) {
    console.error('❌ Error getting user notifications:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get("/api/user", authenticateToken, async (req, res) => {
  try {
    // req.user is populated by the authenticateToken middleware
    const user = await findUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json({
      id: user.id || user._id,
      username: user.username,
      role: user.role,
      teamName: user.teamName,
      coins: user.coins,
      score: user.score,
      totalMined: user.totalMined || 0,
      lastMined: user.lastMined
    });
  } catch (error) {
    console.error("Error fetching user details:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});


// Debug route to check user role
app.get('/api/debug/user-role/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    console.log('🔍 Checking user role for ID:', userId);
    
    const user = await findUserById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    console.log('🔍 Found user:', {
      id: user.id || user._id,
      username: user.username,
      role: user.role,
      roleType: typeof user.role
    });
    
    res.json({
      userId: user.id || user._id,
      username: user.username,
      role: user.role,
      roleType: typeof user.role,
      isAdmin: user.role === 'admin',
      isAdminCaseInsensitive: user.role?.toLowerCase() === 'admin'
    });
  } catch (error) {
    console.error('❌ Error checking user role:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Debug route to list all users and their roles
app.get('/api/debug/all-users', async (req, res) => {
  try {
    console.log('🔍 Getting all users...');
    
    const allUsers = await getAllUsers();
    const usersWithRoles = allUsers.map(user => ({
      id: user.id || user._id,
      username: user.username,
      role: user.role,
      roleType: typeof user.role,
      isAdmin: user.role === 'admin'
    }));
    
    console.log('🔍 All users with roles:', usersWithRoles);
    
    res.json({
      totalUsers: allUsers.length,
      adminUsers: usersWithRoles.filter(u => u.isAdmin),
      regularUsers: usersWithRoles.filter(u => !u.isAdmin),
      allUsers: usersWithRoles
    });
  } catch (error) {
    console.error('❌ Error getting all users:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Log all users on server start
getAllUsers().then(users => {
  console.log('All users on server start:', users);
});

// Schedule cleanup of old notifications (run daily at 2 AM)
setInterval(async () => {
  const now = new Date();
  if (now.getHours() === 2 && now.getMinutes() === 0) {
    try {
      console.log('🧹 Running scheduled notification cleanup...');
      await deleteOldNotifications(30); // Delete notifications older than 30 days
      console.log('✅ Notification cleanup completed');
    } catch (error) {
      console.error('❌ Notification cleanup failed:', error);
    }
  }
}, 60000); // Check every minute

// Global game settings - admin can toggle games on/off
let gameSettings = {
  1: true, 2: true, 3: true, 4: true, 5: true, 6: true,
  7: true, 8: true, 9: true, 10: true, 11: true, 12: true
};

// Load game settings from database
async function loadGameSettings() {
  if (!mongoConnected || !db) {
    console.log('📝 Using in-memory game settings');
    return;
  }

  try {
    const settings = await db.collection('gameSettings').findOne({ _id: 'games' });
    if (settings && settings.games) {
      gameSettings = settings.games;
      console.log('✅ Game settings loaded from database');
    } else {
      // Initialize default game settings in database
      await saveGameSettings();
      console.log('✅ Default game settings initialized in database');
    }
  } catch (error) {
    console.error('❌ Error loading game settings:', error);
  }
}

// Save game settings to database
async function saveGameSettings() {
  if (!mongoConnected || !db) return;

  try {
    await db.collection('gameSettings').replaceOne(
      { _id: 'games' },
      { _id: 'games', games: gameSettings, updatedAt: new Date() },
      { upsert: true }
    );
    console.log('✅ Game settings saved to database');
  } catch (error) {
    console.error('❌ Error saving game settings:', error);
  }
}

// Migrate existing notifications to ensure they have read field
async function migrateNotifications() {
  if (!mongoConnected || !db) return;

  try {
    // Update notifications that don't have a read field
    const result = await db.collection('notifications').updateMany(
      { read: { $exists: false } },
      { $set: { read: false } }
    );
    
    if (result.modifiedCount > 0) {
      console.log(`✅ Migrated ${result.modifiedCount} notifications to include read field`);
    }
  } catch (error) {
    console.error('❌ Error migrating notifications:', error);
  }
}

// Global country visibility settings - admin can hide/show country ownership
let countryVisibilitySettings = {};

// Helper function to get available games
function getAvailableGames() {
  console.log('🎮 Current gameSettings:', gameSettings);
  const availableGames = Object.keys(gameSettings).filter(game => gameSettings[game]);
  console.log('🎮 Available games:', availableGames);
  return availableGames;
}

// Helper function to get cards by type
function getCardsByType(spinType) {
  const cards = {
    lucky: [
      { name: "-50 Coins Instantly", type: 'lucky', effect: '-50 coins instantly', actionType: 'instant', coinChange: -50 },
      { name: "+75 Coins Instantly", type: 'lucky', effect: '+75 coins instantly', actionType: 'instant', coinChange: 75 },
      { name: "Borrow coins to buy a country", type: 'lucky', effect: 'Balance may go negative, limit -200', actionType: 'admin', requiresTeamSelection: false },
      { name: "Pay 10 coins as border tax", type: 'lucky', effect: 'Pay 10 coins for each country you own', actionType: 'instant_tax' },
      { name: "Shield: 2 hours protection", type: 'lucky', effect: '2 hours protection in shift', actionType: 'admin', requiresTeamSelection: true },
      { name: "+50 Coins to random team", type: 'lucky', effect: '+50 coins given to another random team', actionType: 'random_gift' }
    ],
    gamehelper: [
      { name: "Secret Info", type: 'gamehelper', effect: 'Choose game: Instantly reveals opponent & game details', actionType: 'admin', requiresGameSelection: true },
      { name: "Robin Hood", type: 'gamehelper', effect: 'Choose game & team: Steal 100 coins from them, gain 50 coins', actionType: 'admin', requiresGameSelection: true, requiresTeamSelection: true },
      { name: "Avenger", type: 'gamehelper', effect: 'Choose game & team: Alliance proposal (+50 each if accepted)', actionType: 'admin', requiresGameSelection: true, requiresTeamSelection: true },
      { name: "Betrayal", type: 'gamehelper', effect: 'Choose game: Counter alliance betrayals (+50 if betrayed & win)', actionType: 'admin', requiresGameSelection: true }
    ],
    challenge: [
      { name: "Speed Buy", type: 'challenge', effect: '10 minutes to buy a country (+50 reward)', actionType: 'speed_buy' },
      { name: "Freeze Player", type: 'challenge', effect: 'Choose game & team: Target player frozen (+50 to you)', actionType: 'admin', requiresGameSelection: true, requiresTeamSelection: true },
      { name: "Mystery Question", type: 'challenge', effect: 'Spiritual MCQ: 10sec timer (+15 correct, -10 wrong)', actionType: 'mcq', isInstantChallenge: true },
      { name: "Silent Game", type: 'challenge', effect: 'Choose game: Judge decides result (+50 or -30)', actionType: 'admin', requiresGameSelection: true }
    ],
    hightier: [
      { name: "+50 Coins Instantly", type: 'hightier', effect: '+50 coins instantly', actionType: 'instant', coinChange: 50 },
      { name: "Flip the Fate", type: 'hightier', effect: 'Choose game 1-11: If tied, next game has double consequences', actionType: 'admin', requiresGameSelection: true, maxGame: 11 }
    ],
    lowtier: [
      { name: "+100 Coins Instantly", type: 'lowtier', effect: '+100 coins instantly', actionType: 'instant', coinChange: 100 },
      { name: "-5 Coins Instantly", type: 'lowtier', effect: '-5 coins instantly', actionType: 'instant', coinChange: -5 }
    ],
    random: [
      { name: "Lucky Random", type: 'random', effect: 'Random card from Lucky, Game Helper, or Challenge', actionType: 'random_category' }
    ]
  };

  if (spinType === 'random') {
    const availableTypes = ['lucky', 'gamehelper', 'challenge'];
    const randomType = availableTypes[Math.floor(Math.random() * availableTypes.length)];
    const randomCards = cards[randomType];
    return [randomCards[Math.floor(Math.random() * randomCards.length)]];
  }

  return cards[spinType] || [];
}

// Socket.IO connection handling
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('join-team', (teamId) => {
    socket.join(teamId);
    console.log(`User joined team: ${teamId}`);
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    mongoConnected,
    environment: process.env.NODE_ENV || 'development'
  });
});

// Serve static files in production
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, '../client/build')));
  
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../client/build', 'index.html'));
  });
}

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('Shutting down gracefully...');
  if (mongoClient) {
    await mongoClient.close();
    console.log('MongoDB connection closed');
  }
  process.exit(0);
});

// All endpoints must be defined before server.listen()
// Validate promo code for preview (does not mark as used)
app.post('/api/promocode/validate', authenticateToken, async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) {
      return res.status(400).json({ valid: false, error: 'Promo code is required' });
    }
    const promo = await findPromoCode(code, req.user.id);
    if (promo) {
      return res.json({ valid: true, discount: promo.discount });
    } else {
      return res.json({ valid: false, discount: 0 });
    }
  } catch (error) {
    console.error('Promo code validation error:', error);
    res.status(500).json({ valid: false, error: 'Internal server error' });
  }
});

// MCQ Answer endpoint
app.post('/api/mcq/answer', authenticateToken, async (req, res) => {
  try {
    const { questionId, answer } = req.body;
    const user = await findUserById(req.user.id);
    
    // Load questions and verify answer
    const fs = require('fs');
    const questions = JSON.parse(fs.readFileSync('./spiritual-questions.json', 'utf8'));
    const question = questions.questions.find(q => q.id === questionId);
    
    if (!question) {
      return res.status(404).json({ error: 'Question not found' });
    }
    
    const isCorrect = answer === question.correct;
    let rewardCoins = isCorrect ? 15 : -10;
    
    const newCoins = user.coins + rewardCoins;
    await updateUserById(req.user.id, { coins: newCoins });
    
    // Emit user update
    io.to(user.id || user._id).emit('user-update', {
      id: user.id || user._id,
      teamName: user.teamName,
      coins: newCoins,
      score: user.score
    });
    
    // Notify user
    const notification = {
      id: Date.now().toString(),
      userId: req.user.id,
      type: 'mcq-reward',
      message: isCorrect 
        ? `Correct answer! You earned ${rewardCoins} coins.`
        : `Wrong answer! You lost ${Math.abs(rewardCoins)} coins.`,
      timestamp: new Date().toISOString(),
      read: false,
      recipientType: 'user'
    };
    await addNotification(notification);
    io.to(req.user.id).emit('notification', notification);
    
    // Update scoreboard
    const updatedUsers = await getAllUsers();
    io.emit('scoreboard-update', updatedUsers);
    
    res.json({ 
      correct: isCorrect, 
      reward: rewardCoins,
      correctAnswer: question.correct
    });
  } catch (error) {
    console.error('MCQ answer error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin toggle games endpoint
app.post('/api/admin/games/toggle', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { gameId, enabled } = req.body;
    
    if (!gameId || typeof enabled !== 'boolean') {
      return res.status(400).json({ error: 'Invalid game ID or enabled status' });
    }
    
    // Remove the hardcoded limit check to allow dynamic games
    gameSettings[gameId] = enabled;
    
    // Save to database
    await saveGameSettings();
    
    // Emit to all clients about game setting change
    io.emit('game-settings-update', gameSettings);
    
    res.json({ 
      success: true, 
      gameId, 
      enabled, 
      gameSettings 
    });
  } catch (error) {
    console.error('Toggle game error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Add new game
app.post('/api/admin/games/add', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { gameName } = req.body;
    
    if (!gameName || !gameName.trim()) {
      return res.status(400).json({ error: 'Game name is required' });
    }
    
    // Find the next available game ID
    const existingGameIds = Object.keys(gameSettings).map(id => parseInt(id)).sort((a, b) => a - b);
    let nextGameId = 1;
    
    for (let i = 0; i < existingGameIds.length; i++) {
      if (existingGameIds[i] !== nextGameId) {
        break;
      }
      nextGameId++;
    }
    
    // Add new game (enabled by default)
    gameSettings[nextGameId] = true;
    
    // Save to database
    await saveGameSettings();
    
    console.log(`New game ${nextGameId} (${gameName.trim()}) added by admin`);
    
    // Emit to all clients about game setting change
    io.emit('game-settings-update', gameSettings);
    
    res.json({ 
      success: true, 
      gameSettings, 
      newGameId: nextGameId,
      message: `Game ${nextGameId} added successfully` 
    });
  } catch (error) {
    console.error('Add game error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete game
app.delete('/api/admin/games/:gameId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { gameId } = req.params;
    const gameIdNum = parseInt(gameId);
    
    if (!gameId || !gameSettings.hasOwnProperty(gameId)) {
      return res.status(400).json({ error: 'Invalid game ID' });
    }
    
    // Don't allow deleting if it's the last game
    const remainingGames = Object.keys(gameSettings).filter(id => id !== gameId);
    if (remainingGames.length === 0) {
      return res.status(400).json({ error: 'Cannot delete the last game. At least one game must exist.' });
    }
    
    // Delete the game
    delete gameSettings[gameId];
    
    // Save to database
    await saveGameSettings();
    
    console.log(`Game ${gameId} deleted by admin`);
    
    // Emit to all clients about game setting change
    io.emit('game-settings-update', gameSettings);
    
    res.json({ 
      success: true, 
      gameSettings,
      message: `Game ${gameId} deleted successfully` 
    });
  } catch (error) {
    console.error('Delete game error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get game settings
app.get('/api/admin/games', authenticateToken, requireAdmin, async (req, res) => {
  try {
    console.log('🎮 Admin games endpoint called');
    console.log('🎮 Current gameSettings:', gameSettings);
    console.log('🎮 gameSettings type:', typeof gameSettings);
    console.log('🎮 gameSettings keys:', Object.keys(gameSettings));
    res.json(gameSettings);
  } catch (error) {
    console.error('Get game settings error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Simple test admin endpoint
app.get('/api/admin/test-simple', authenticateToken, requireAdmin, async (req, res) => {
  try {
    console.log('🧪 Simple admin test endpoint called');
    res.json({ 
      message: 'Simple admin endpoint works!',
      timestamp: new Date().toISOString(),
      gameSettings: gameSettings
    });
  } catch (error) {
    console.error('Simple admin test error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Even simpler test endpoint (no variables)
app.get('/api/admin/test-basic', authenticateToken, requireAdmin, async (req, res) => {
  try {
    console.log('🔧 Basic admin test endpoint called');
    res.json({ 
      message: 'Basic admin endpoint works!',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Basic admin test error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get available games for users
app.get('/api/games/available', authenticateToken, async (req, res) => {
  try {
    console.log('🎮 Available games endpoint called');
    const availableGames = getAvailableGames();
    console.log('🎮 Sending available games to frontend:', availableGames);
    res.json(availableGames);
  } catch (error) {
    console.error('Get available games error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin get card usage statistics
app.get('/api/admin/card-stats', authenticateToken, requireAdmin, async (req, res) => {
  try {
    console.log('📊 Admin card-stats endpoint called');
    const notifications = await getAllNotifications();
    
    // Filter card usage notifications
    const cardUsageNotifications = notifications.filter(n => n.type === 'card-used');
    
    // Calculate statistics
    const cardStats = {};
    const teamStats = {};
    const gameStats = {};
    
    cardUsageNotifications.forEach(notification => {
      const cardName = notification.cardName;
      const teamName = notification.teamName;
      const selectedGame = notification.selectedGame;
      
      // Card usage count
      if (!cardStats[cardName]) {
        cardStats[cardName] = { count: 0, type: notification.cardType };
      }
      cardStats[cardName].count++;
      
      // Team usage count
      if (!teamStats[teamName]) {
        teamStats[teamName] = 0;
      }
      teamStats[teamName]++;
      
      // Game selection count
      if (selectedGame) {
        if (!gameStats[selectedGame]) {
          gameStats[selectedGame] = 0;
        }
        gameStats[selectedGame]++;
      }
    });
    
    // Calculate totals and most popular
    const totalCardsUsed = cardUsageNotifications.length;
    const mostUsedCard = Object.keys(cardStats).reduce((a, b) => 
      cardStats[a].count > cardStats[b].count ? a : b, Object.keys(cardStats)[0]);
    const mostActiveTeam = Object.keys(teamStats).reduce((a, b) => 
      teamStats[a] > teamStats[b] ? a : b, Object.keys(teamStats)[0]);
    const mostSelectedGame = Object.keys(gameStats).reduce((a, b) => 
      gameStats[a] > gameStats[b] ? a : b, Object.keys(gameStats)[0]);
    
    res.json({
      totalCardsUsed,
      cardStats,
      teamStats,
      gameStats,
      insights: {
        mostUsedCard: mostUsedCard ? { name: mostUsedCard, count: cardStats[mostUsedCard].count } : null,
        mostActiveTeam: mostActiveTeam ? { name: mostActiveTeam, count: teamStats[mostActiveTeam] } : null,
        mostSelectedGame: mostSelectedGame ? { game: mostSelectedGame, count: gameStats[mostSelectedGame] } : null
      },
      recentUsage: cardUsageNotifications.slice(0, 10) // Last 10 card uses
    });
  } catch (error) {
    console.error('Get card stats error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin get all countries with ownership details
app.get('/api/admin/countries', authenticateToken, requireAdmin, async (req, res) => {
  try {
    console.log('🗺️ Admin countries endpoint called');
    const countries = await getAllCountries();
    const users = await getAllUsers();
    
    // Create a map of user IDs to team names for quick lookup
    const userMap = {};
    users.forEach(user => {
      userMap[user.id] = user.teamName;
    });
    
    // Add owner name and visibility info to each country
    const countriesWithDetails = countries.map(country => ({
      ...country,
      ownerName: country.owner ? userMap[country.owner] || 'Unknown' : null,
      isVisible: countryVisibilitySettings[country.id] !== false // Default to visible
    }));
    
    res.json(countriesWithDetails);
  } catch (error) {
    console.error('Get admin countries error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin toggle country visibility
app.post('/api/admin/countries/visibility', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { countryId, visible } = req.body;
    
    if (!countryId || typeof visible !== 'boolean') {
      return res.status(400).json({ error: 'Invalid country ID or visibility status' });
    }
    
    countryVisibilitySettings[countryId] = visible;
    
    // Emit to all clients about country visibility change
    io.emit('country-visibility-update', { countryId, visible });
    
    res.json({ 
      success: true, 
      countryId, 
      visible 
    });
  } catch (error) {
    console.error('Toggle country visibility error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin change country ownership
app.post('/api/admin/countries/ownership', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { countryId, newOwnerId } = req.body;
    
    if (!countryId) {
      return res.status(400).json({ error: 'Country ID is required' });
    }
    
    const country = await findCountryById(countryId);
    if (!country) {
      return res.status(404).json({ error: 'Country not found' });
    }
    
    // Update country ownership
    await updateCountryById(countryId, { 
      owner: newOwnerId || null,
      lastMined: new Date().toISOString()
    });
    
    // If assigning to a new owner, update their mining rate
    if (newOwnerId) {
      const newOwner = await findUserById(newOwnerId);
      if (newOwner) {
        const newMiningRate = await calculateUserMiningRate(newOwnerId);
        await updateUserById(newOwnerId, { miningRate: newMiningRate });
        
        // Emit user update
        io.to(newOwnerId).emit('user-update', {
          id: newOwnerId,
          teamName: newOwner.teamName,
          coins: newOwner.coins,
          score: newOwner.score,
          miningRate: newMiningRate
        });
      }
    }
    
    // If removing from previous owner, update their mining rate
    if (country.owner && country.owner !== newOwnerId) {
      const prevOwner = await findUserById(country.owner);
      if (prevOwner) {
        const prevMiningRate = await calculateUserMiningRate(country.owner);
        await updateUserById(country.owner, { miningRate: prevMiningRate });
        
        // Emit user update
        io.to(country.owner).emit('user-update', {
          id: country.owner,
          teamName: prevOwner.teamName,
          coins: prevOwner.coins,
          score: prevOwner.score,
          miningRate: prevMiningRate
        });
      }
    }
    
    // Emit country update to all clients
    io.emit('country-update', { countryId, newOwnerId });
    
    // Update scoreboard
    const updatedUsers = await getAllUsers();
    io.emit('scoreboard-update', updatedUsers);
    
    res.json({ 
      success: true, 
      countryId, 
      newOwnerId 
    });
  } catch (error) {
    console.error('Change country ownership error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Speed Buy completion check
app.post('/api/speedbuy/check', authenticateToken, async (req, res) => {
  try {
    const user = await findUserById(req.user.id);
    const timers = global.speedBuyTimers || {};
    const timer = timers[req.user.id];
    
    if (!timer) {
      return res.status(404).json({ error: 'No active speed buy challenge' });
    }
    
    const currentTime = Date.now();
    const timeElapsed = currentTime - timer.startTime;
    
    if (timeElapsed > timer.duration) {
      // Timer expired
      delete timers[req.user.id];
      return res.json({ expired: true, reward: 0 });
    }
    
    // Check if user bought a country in the last timer period
    // This is a simplified check - in a real implementation, you'd track purchases
    const countries = await getAllCountries();
    const recentPurchases = countries.filter(c => 
      c.owner === req.user.id && 
      new Date(c.lastMined) > new Date(timer.startTime)
    );
    
    if (recentPurchases.length > 0) {
      // User bought a country, give reward
      const newCoins = user.coins + timer.reward;
      await updateUserById(req.user.id, { coins: newCoins });
      
      // Emit user update
      io.to(user.id || user._id).emit('user-update', {
        id: user.id || user._id,
        teamName: user.teamName,
        coins: newCoins,
        score: user.score
      });
      
      // Notify user
      const notification = {
        id: Date.now().toString(),
        userId: req.user.id,
        type: 'speedbuy-reward',
        message: `Speed Buy completed! You earned ${timer.reward} coins.`,
        timestamp: new Date().toISOString(),
        read: false,
        recipientType: 'user'
      };
      await addNotification(notification);
      io.to(req.user.id).emit('notification', notification);
      
      delete timers[req.user.id];
      
      res.json({ 
        completed: true, 
        reward: timer.reward,
        remainingCoins: newCoins
      });
    } else {
      const remainingTime = timer.duration - timeElapsed;
      res.json({ 
        completed: false, 
        remainingTime: Math.ceil(remainingTime / 1000),
        reward: 0 
      });
    }
  } catch (error) {
    console.error('Speed buy check error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Helper function to calculate user's mining rate
async function calculateUserMiningRate(userId) {
  try {
    const countries = await getAllCountries();
    const ownedCountries = countries.filter(country => country.owner === userId);
    const totalMiningRate = ownedCountries.reduce((sum, country) => sum + (country.miningRate || 0), 0);
    return totalMiningRate;
  } catch (error) {
    console.error('Error calculating mining rate:', error);
    return 0;
  }
}

// Helper function to get owned countries count
async function getOwnedCountriesCount(userId) {
  try {
    const countries = await getAllCountries();
    const ownedCountries = countries.filter(country => country.owner === userId);
    return ownedCountries.length;
  } catch (error) {
    console.error('Error getting owned countries count:', error);
    return 0;
  }
}

// Helper function to get user's mining info
async function getUserMiningInfo(userId) {
  try {
    const user = await findUserById(userId);
    if (!user) return null;
    
    const miningRate = await calculateUserMiningRate(userId);
    const ownedCountries = await getAllCountries().then(countries => 
      countries.filter(country => country.owner === userId)
    );
    
    return {
      userId,
      miningRate,
      totalMined: user.totalMined || 0,
      lastMined: user.lastMined,
      ownedCountries: ownedCountries.map(country => ({
        id: country.id,
        name: country.name,
        miningRate: country.miningRate || 0
      }))
    };
  } catch (error) {
    console.error('Error getting user mining info:', error);
    return 0;
  }
}

// Mining system endpoints
app.get('/api/mining/info', authenticateToken, async (req, res) => {
  try {
    const miningInfo = await getUserMiningInfo(req.user.id);
    if (!miningInfo) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(miningInfo);
  } catch (error) {
    console.error('Get mining info error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/mining/collect', authenticateToken, async (req, res) => {
  try {
    const user = await findUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Get all countries owned by the user
    const allCountries = await getAllCountries();
    const ownedCountries = allCountries.filter(country => country.owner === req.user.id);

    if (ownedCountries.length === 0) {
      return res.status(400).json({ error: 'You need to own countries to mine coins' });
    }

    const now = new Date();
    let totalEarned = 0;
    const countriesWithEarnings = [];

    // Calculate earnings for each country individually
    for (const country of ownedCountries) {
      const countryLastMined = country.lastMined ? new Date(country.lastMined) : null;
      let countryEarned = 0;

      if (countryLastMined) {
        const elapsedMinutes = Math.floor((now - countryLastMined) / (1000 * 60));
        countryEarned = Math.floor((elapsedMinutes * (country.miningRate || 0)) / 60);
      } else {
        // First time mining for this country, give a small bonus
        countryEarned = Math.floor((country.miningRate || 0) / 60);
      }

      if (countryEarned > 0) {
        totalEarned += countryEarned;
        countriesWithEarnings.push({
          countryId: country.id,
          countryName: country.name,
          earned: countryEarned,
          miningRate: country.miningRate || 0
        });

        // Update this country's lastMined timestamp
        await updateCountryById(country.id, { lastMined: now.toISOString() });
      }
    }

    if (totalEarned <= 0) {
      return res.status(400).json({ 
        error: 'Not enough time has passed since last collection for any countries',
        ownedCountries: ownedCountries.map(c => ({
          name: c.name,
          lastMined: c.lastMined,
          miningRate: c.miningRate || 0
        }))
      });
    }

    // Update user data
    const newTotalMined = (user.totalMined || 0) + totalEarned;
    const newCoins = user.coins + totalEarned;
    
    await updateUserById(req.user.id, {
      totalMined: newTotalMined,
      coins: newCoins,
      lastMined: now.toISOString() // Update user's global lastMined for display purposes
    });

    // Emit user update
    io.to(req.user.id).emit('user-update', {
      id: req.user.id,
      teamName: user.teamName,
      coins: newCoins,
      score: user.score,
      totalMined: newTotalMined,
      lastMined: now.toISOString()
    });

    // Create user notification with breakdown
    const breakdownMessage = countriesWithEarnings.map(c => 
      `${c.countryName}: ${c.earned} coins`
    ).join(', ');

    const userNotification = {
      id: Date.now().toString(),
      userId: req.user.id,
      type: 'mining',
      message: `You mined ${totalEarned} coins! (${breakdownMessage})`,
      timestamp: now.toISOString(),
      read: false,
      recipientType: 'user',
      metadata: {
        totalEarned,
        countriesWithEarnings,
        collectionTime: now.toISOString()
      }
    };
    await addNotification(userNotification);
    io.to(req.user.id).emit('notification', userNotification);

    // Create admin notification
    const adminNotification = {
      id: (Date.now() + 1).toString(),
      type: 'mining',
      teamId: req.user.id,
      teamName: user.teamName,
      message: `User ${user.teamName} mined ${totalEarned} coins from ${countriesWithEarnings.length} countries`,
      timestamp: now.toISOString(),
      read: false,
      recipientType: 'admin',
      metadata: {
        totalEarned,
        totalMined: newTotalMined,
        countriesWithEarnings
      }
    };
    await addNotification(adminNotification);
    io.emit('admin-notification', adminNotification);

    // Update scoreboard
    const updatedUsers = await getAllUsers();
    io.emit('scoreboard-update', updatedUsers);

    res.json({
      message: `Successfully mined ${totalEarned} coins from ${countriesWithEarnings.length} countries!`,
      earned: totalEarned,
      totalMined: newTotalMined,
      newCoins,
      countriesWithEarnings
    });
  } catch (error) {
    console.error('Collect mining error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Catch-all route for unmatched paths
app.use('*', (req, res) => {
  console.log(`❌ 404 - Route not found: ${req.method} ${req.originalUrl}`);
  
  // Get all registered routes
  const allRoutes = app._router.stack
    .filter(r => r.route)
    .map(r => `${Object.keys(r.route.methods)[0].toUpperCase()} ${r.route.path}`);
  
  console.log(`🔍 Total routes registered: ${allRoutes.length}`);
  console.log(`🔍 All routes:`, allRoutes);
  
  // Check specifically for admin routes
  const adminRoutes = allRoutes.filter(route => route.includes('/admin'));
  console.log(`🔍 Admin routes:`, adminRoutes);
  
  res.status(404).json({ 
    error: 'Route not found', 
    method: req.method, 
    path: req.originalUrl,
    timestamp: new Date().toISOString(),
    totalRoutes: allRoutes.length,
    adminRoutes: adminRoutes
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 CORS Origin: * (Public Access)`);
  console.log(`🔧 Total routes registered: ${app._router.stack.filter(r => r.route).length}`);
  console.log(`🔧 Admin routes:`, app._router.stack
    .filter(r => r.route && r.route.path && r.route.path.includes('/admin'))
    .map(r => `${Object.keys(r.route.methods)[0].toUpperCase()} ${r.route.path}`)
  );
});