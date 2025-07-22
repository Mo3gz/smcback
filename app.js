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
    score: 0
  },
  {
    id: '2',
    username: 'team1',
    password: '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password
    role: 'user',
    teamName: 'Team Alpha',
    coins: 500,
    score: 0
  },
  {
    id: '3',
    username: 'team2',
    password: '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password
    role: 'user',
    teamName: 'Team Beta',
    coins: 500,
    score: 0
  }
];

let countries = [
  { id: '1', name: 'Egypt', cost: 200, owner: null, score: 150 },
  { id: '2', name: 'Morocco', cost: 180, owner: null, score: 140 },
  { id: '3', name: 'Algeria', cost: 160, owner: null, score: 130 },
  { id: '4', name: 'Tunisia', cost: 140, owner: null, score: 120 },
  { id: '5', name: 'Libya', cost: 120, owner: null, score: 110 },
  { id: '6', name: 'Sudan', cost: 100, owner: null, score: 100 },
  { id: '7', name: 'Ethiopia', cost: 90, owner: null, score: 90 },
  { id: '8', name: 'Kenya', cost: 80, owner: null, score: 80 },
  { id: '9', name: 'Nigeria', cost: 70, owner: null, score: 70 },
  { id: '10', name: 'Ghana', cost: 60, owner: null, score: 60 },
  // Added more countries
  { id: '11', name: 'South Africa', cost: 210, owner: null, score: 160 },
  { id: '12', name: 'Senegal', cost: 75, owner: null, score: 65 },
  { id: '13', name: 'Ivory Coast', cost: 85, owner: null, score: 75 },
  { id: '14', name: 'Cameroon', cost: 95, owner: null, score: 85 },
  { id: '15', name: 'Uganda', cost: 70, owner: null, score: 60 },
  { id: '16', name: 'Saudi Arabia', cost: 220, owner: null, score: 170 },
  { id: '17', name: 'United Arab Emirates', cost: 200, owner: null, score: 160 },
  { id: '18', name: 'Qatar', cost: 180, owner: null, score: 150 },
  { id: '19', name: 'Jordan', cost: 110, owner: null, score: 90 },
  { id: '20', name: 'Lebanon', cost: 100, owner: null, score: 80 },
  { id: '21', name: 'Turkey', cost: 230, owner: null, score: 180 },
  { id: '22', name: 'Greece', cost: 150, owner: null, score: 120 },
  { id: '23', name: 'Italy', cost: 250, owner: null, score: 200 },
  { id: '24', name: 'France', cost: 270, owner: null, score: 220 },
  { id: '25', name: 'Spain', cost: 260, owner: null, score: 210 },
  { id: '26', name: 'Germany', cost: 280, owner: null, score: 230 },
  { id: '27', name: 'United Kingdom', cost: 290, owner: null, score: 240 },
  { id: '28', name: 'Portugal', cost: 140, owner: null, score: 110 },
  { id: '29', name: 'Netherlands', cost: 200, owner: null, score: 160 },
  { id: '30', name: 'Belgium', cost: 190, owner: null, score: 150 }
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
  if (mongoConnected && db) {
    await db.collection('notifications').insertOne(notification);
  } else {
    notifications.push(notification);
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
        { userId: userId, read: { $ne: true } },
        { type: 'global', read: { $ne: true } },
        { type: 'scoreboard-update', read: { $ne: true } }
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
          { userId: userId, read: { $ne: true } },
          { type: 'global', read: { $ne: true } },
          { type: 'scoreboard-update', read: { $ne: true } }
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

function requireAdmin(req, res, next) {
  console.log('🔐 Admin check - User:', req.user);
  console.log('🔐 Full req.user:', JSON.stringify(req.user, null, 2));
  if (!req.user) {
    console.log('❌ Admin check failed: No user found in request');
    return res.status(401).json({ 
      error: 'Authentication required',
      details: 'No user found in request'
    });
  }
  // Special case: always allow 'ayman' as admin
  if (req.user.username === 'ayman') {
    console.log('✅ Admin check bypass: username is ayman');
    return next();
  }
  // More robust role checking
  const userRole = req.user.role;
  const isAdmin = userRole === 'admin' || userRole === 'ADMIN' || userRole === 'Admin';
  console.log('🔐 User role check:', {
    userRole,
    isAdmin,
    username: req.user.username,
    userId: req.user.id
  });
  if (!isAdmin) {
    console.log('❌ Admin check failed: User role is not admin');
    return res.status(403).json({ 
      error: 'Admin access required',
      details: {
        userRole: userRole,
        userId: req.user.id,
        username: req.user.username,
        requiredRole: 'admin'
      }
    });
  }
  console.log('✅ Admin check passed for user:', req.user.username);
  next();
}

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
    res.json(countries);
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

    // Update user
    await updateUserById(req.user.id, { 
      coins: newCoins, 
      score: newScore 
    });
    // Emit user-update for this user
    io.to(userId).emit('user-update', {
      id: userId,
      teamName: user.teamName,
      coins: newCoins,
      score: newScore
    });

    // Update country
    await updateCountryById(countryId, { owner: userId });

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
        score: newScore
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
    const { cardId, selectedTeam, description } = req.body;
    const user = await findUserById(req.user.id);
    const inventory = await getUserInventory(req.user.id);
    
    const card = inventory.find(card => card.id === cardId);
    if (!card) {
      return res.status(404).json({ error: 'Card not found in inventory' });
    }

    // Remove card from inventory
    await removeFromUserInventory(req.user.id, cardId);

    // Get target team name if selectedTeam is provided
    let targetTeamName = '';
    if (selectedTeam) {
      const targetTeam = await findUserById(selectedTeam);
      targetTeamName = targetTeam ? targetTeam.teamName : 'Unknown Team';
    }

    // Create notification for admin only
    const notification = {
      id: Date.now().toString(),
      type: 'card-used',
      teamId: req.user.id,
      teamName: user.teamName,
      cardName: card.name,
      cardType: card.type,
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
    
    let cost = 50;
    if (spinType === 'random') cost = 25;

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
    // Emit user-update for this user
    io.to(user.id || user._id).emit('user-update', {
      id: user.id || user._id,
      teamName: user.teamName,
      coins: newCoins,
      score: user.score
    });

    // Generate random card based on spin type
    const cards = getCardsByType(spinType);
    const randomCard = cards[Math.floor(Math.random() * cards.length)];
    
    const cardToAdd = {
      ...randomCard,
      id: Date.now().toString(),
      obtainedAt: new Date().toISOString()
    };

    await addToUserInventory(req.user.id, cardToAdd);

    // User notification for spin (send only to user, not admin)
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

    // Emit user update for real-time updates
    io.emit('user-update', {
      id: user.id || user._id,
      coins: newCoins,
      score: user.score
    });

    // Emit scoreboard update for all clients
    const updatedUsers = await getAllUsers();
    io.emit('scoreboard-update', updatedUsers);

    // Notify user that inventory has been updated
    io.to(req.user.id).emit('inventory-update');

    // Send admin notification for spin with team name and card
    const adminSpinNotification = {
      id: Date.now().toString(),
      type: 'spin',
      teamId: user.id || user._id,
      teamName: user.teamName,
      message: `${user.teamName} spun the wheel and got: ${randomCard.name} (${randomCard.type})`,
      cardName: randomCard.name,
      cardType: randomCard.type,
      timestamp: new Date().toISOString(),
      read: false,
      recipientType: 'admin'
    };
    await addNotification(adminSpinNotification);
    io.emit('admin-notification', adminSpinNotification);

    res.json({ 
      card: randomCard,
      cost,
      remainingCoins: newCoins
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
    // Validate discount: must be integer between 1 and 100
    if (!Number.isInteger(discount) || discount < 1 || discount > 100) {
      return res.status(400).json({ error: 'Discount must be an integer between 1 and 100.' });
    }
    const promoCode = {
      id: Date.now().toString(),
      code,
      teamId,
      discount,
      used: false,
      createdAt: new Date().toISOString()
    };
    
    await addPromoCode(promoCode);
    
    // Notify the specific team
    const user = await findUserById(teamId);
    if (user) {
      const notification = {
        id: Date.now().toString(),
        userId: teamId,
        type: 'promo-code',
        message: `You received a promo code: ${code} with ${discount}% discount!`,
        timestamp: new Date().toISOString(),
        read: false,
        recipientType: 'user'
      };
      await addNotification(notification); // <-- Save in DB
      io.to(teamId).emit('notification', notification);
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
    const user = await findUserById(teamId);
    
    if (!user) {
      return res.status(404).json({ error: 'Team not found' });
    }

    // Find the card effect from the card list
    const cards = {
      luck: [
        { name: 'Hidden Treasure', type: 'luck', effect: '+400 Points instantly' },
        { name: 'Camp Tax', type: 'luck', effect: '-300 Points go to the Bank' },
        { name: 'Golden Ticket', type: 'luck', effect: 'Pay 200 Points → If you win the next challenge, take +500 Points!' },
        { name: 'Mysterious Trader', type: 'luck', effect: 'Pay 150 Points → Get a random Attack Card' },
        { name: 'Everything Against Me', type: 'luck', effect: 'Instantly lose 250 Points' },
        { name: 'Double Up', type: 'luck', effect: 'Double your current points if you win any challenge in the next 30 minutes' },
        { name: 'Shady Deal', type: 'luck', effect: 'Steal 100 Points from any tent' }
      ],
      attack: [
        { name: 'Raid', type: 'attack', effect: 'Choose one team to raid. If you win the challenge, steal 300 Points from them.' },
        { name: 'Control Battle', type: 'attack', effect: 'Select one team to challenge in a one-on-one tent battle. Winner gets +500 Points.' },
        { name: 'Double Strike', type: 'attack', effect: 'Select one team to ally with and attack another tent together.' },
        { name: 'Break Alliances', type: 'attack', effect: 'Force 2 allied tents to break their alliance' },
        { name: 'Broad Day Robbery', type: 'attack', effect: 'Take 100 Points instantly from any tent' }
      ],
      alliance: [
        { name: 'Strategic Alliance', type: 'alliance', effect: 'Select one team to form an alliance with for 1 full day.' },
        { name: 'Betrayal Alliance', type: 'alliance', effect: 'Form an alliance, then betray them at the end to steal their points.' },
        { name: 'Golden Partnership', type: 'alliance', effect: 'Choose a team to team up with in the next challenge.' },
        { name: 'Temporary Truce', type: 'alliance', effect: 'Select 2 teams to pause all attacks between them for 1 full day.' },
        { name: 'Hidden Leader', type: 'alliance', effect: 'You become the challenge leader. Ally with another team.' }
      ]
    };
    const cardObj = (cards[cardType] || []).find(card => card.name === cardName);
    const cardEffect = cardObj ? cardObj.effect : '';

    const card = {
      id: Date.now().toString(),
      name: cardName,
      type: cardType,
      obtainedAt: new Date().toISOString()
    };

    await addToUserInventory(teamId, card);

    // Notify the team (user) with card name and effect
    const notification = {
      id: Date.now().toString(),
      type: 'card-received',
      message: `You received a new card: ${cardName}${cardEffect ? ' - ' + cardEffect : ''}`,
      timestamp: new Date().toISOString(),
      recipientType: 'user'
    };
    await addNotification(notification);
    io.to(teamId).emit('notification', notification);
    // Notify user that inventory has been updated
    io.to(teamId).emit('inventory-update');

    res.json(card);
  } catch (error) {
    console.error('Give card error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/admin/coins', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { teamId, amount, reason } = req.body;
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
    const notification = {
      id: Date.now().toString(),
      userId: teamId,
      type: 'coins-updated',
      message: `${amount > 0 ? '+' : ''}${amount} coins: ${reason}`,
      timestamp: new Date().toISOString(),
      read: false,
      recipientType: 'user'
    };

    await addNotification(notification);
    io.to(teamId).emit('notification', notification);
    
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
    const notification = {
      id: Date.now().toString(),
      userId: teamId,
      type: 'score-updated',
      message: `${amount > 0 ? '+' : ''}${amount} points: ${reason}`,
      timestamp: new Date().toISOString(),
      read: false,
      recipientType: 'user'
    };

    await addNotification(notification);
    io.to(teamId).emit('notification', notification);
    
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

// Add route to check admin status
app.get('/api/admin/check', authenticateToken, requireAdmin, async (req, res) => {
  try {
    res.json({ 
      message: 'Admin access confirmed',
      user: {
        id: req.user.id,
        username: req.user.username,
        role: req.user.role,
        teamName: req.user.teamName
      }
    });
  } catch (error) {
    console.error('Admin check error:', error);
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
    res.json({ message: 'All notifications marked as read' });
  } catch (error) {
    console.error('Mark all notifications read error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin: Get all notifications (for admin dashboard)
app.get('/api/admin/notifications', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const notifications = await getAllNotifications();
    res.json(notifications);
  } catch (error) {
    console.error('Get all notifications error:', error);
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

// Helper function to get cards by type
function getCardsByType(spinType) {
  const cards = {
    luck: [
      { name: 'Hidden Treasure', type: 'luck', effect: '+400 Points instantly' },
      { name: 'Camp Tax', type: 'luck', effect: '-300 Points go to the Bank' },
      { name: 'Golden Ticket', type: 'luck', effect: 'Pay 200 Points → If you win the next challenge, take +500 Points!' },
      { name: 'Mysterious Trader', type: 'luck', effect: 'Pay 150 Points → Get a random Attack Card' },
      { name: 'Everything Against Me', type: 'luck', effect: 'Instantly lose 250 Points' },
      { name: 'Double Up', type: 'luck', effect: 'Double your current points if you win any challenge in the next 30 minutes' },
      { name: 'Shady Deal', type: 'luck', effect: 'Steal 100 Points from any tent' }
    ],
    attack: [
      { name: 'Raid', type: 'attack', effect: 'Choose one team to raid. If you win the challenge, steal 300 Points from them.' },
      { name: 'Control Battle', type: 'attack', effect: 'Select one team to challenge in a one-on-one tent battle. Winner gets +500 Points.' },
      { name: 'Double Strike', type: 'attack', effect: 'Select one team to ally with and attack another tent together.' },
      { name: 'Break Alliances', type: 'attack', effect: 'Force 2 allied tents to break their alliance' },
      { name: 'Broad Day Robbery', type: 'attack', effect: 'Take 100 Points instantly from any tent' }
    ],
    alliance: [
      { name: 'Strategic Alliance', type: 'alliance', effect: 'Select one team to form an alliance with for 1 full day.' },
      { name: 'Betrayal Alliance', type: 'alliance', effect: 'Form an alliance, then betray them at the end to steal their points.' },
      { name: 'Golden Partnership', type: 'alliance', effect: 'Choose a team to team up with in the next challenge.' },
      { name: 'Temporary Truce', type: 'alliance', effect: 'Select 2 teams to pause all attacks between them for 1 full day.' },
      { name: 'Hidden Leader', type: 'alliance', effect: 'You become the challenge leader. Ally with another team.' }
    ]
  };

  if (spinType === 'random') {
    const allCards = [...cards.luck, ...cards.attack, ...cards.alliance];
    return [allCards[Math.floor(Math.random() * allCards.length)]];
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

const PORT = process.env.PORT || 5000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 CORS Origin: * (Public Access)`);

});

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