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
  'https://saintpaul.netlify.app',
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
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Cache-Control', 'Pragma', 'Accept', 'Origin', 'x-auth-token', 'x-username']
}));

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Origin', req.headers.origin);
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Cache-Control, Pragma, Accept, Origin, x-auth-token, x-username');
  next();
});

app.use(express.json());
app.use(cookieParser());



// Handle preflight requests
app.options('*', (req, res) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin);
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Cache-Control, Pragma, Accept, Origin, x-auth-token, x-username');
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
    lastMined: null,
    teamSettings: {
      scoreboardVisible: true,
      spinLimitations: {
        lucky: { enabled: false, limit: 1 },
        gamehelper: { enabled: false, limit: 1 },
        challenge: { enabled: false, limit: 1 },
        hightier: { enabled: false, limit: 1 },
        lowtier: { enabled: false, limit: 1 },
        random: { enabled: false, limit: 1 }
      },
      spinCounts: { lucky: 0, gamehelper: 0, challenge: 0, hightier: 0, lowtier: 0, random: 0 }
    }
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
    lastMined: null,
    teamSettings: {
      scoreboardVisible: true,
      spinLimitations: {
        lucky: { enabled: false, limit: 1 },
        gamehelper: { enabled: false, limit: 1 },
        challenge: { enabled: false, limit: 1 },
        hightier: { enabled: false, limit: 1 },
        lowtier: { enabled: false, limit: 1 },
        random: { enabled: false, limit: 1 }
      },
      spinCounts: { lucky: 0, gamehelper: 0, challenge: 0, hightier: 0, lowtier: 0, random: 0 }
    }
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
    lastMined: null,
    teamSettings: {
      scoreboardVisible: true,
      spinLimitations: {
        lucky: { enabled: false, limit: 1 },
        gamehelper: { enabled: false, limit: 1 },
        challenge: { enabled: false, limit: 1 },
        hightier: { enabled: false, limit: 1 },
        lowtier: { enabled: false, limit: 1 },
        random: { enabled: false, limit: 1 }
      },
      spinCounts: { lucky: 0, gamehelper: 0, challenge: 0, hightier: 0, lowtier: 0, random: 0 }
    }
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

    // Migrate existing users to ensure they have teamSettings
    await migrateUserTeamSettings();

  } catch (error) {
    console.error('❌ Error initializing default data:', error);
  }
}

// Helper function to get filtered countries based on visibility settings
function getFilteredCountries(countries) {
  return countries.filter(country => {
    const individualVisible = countryVisibilitySettings[country.id] !== false;
    const fiftyCoinsVisible = !gameSettings.fiftyCoinsCountriesHidden || country.cost !== 50;
    return individualVisible && fiftyCoinsVisible;
  });
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

// Enhanced Authentication middleware with better debugging - Safari (iOS + macOS) compatible
async function authenticateToken(req, res, next) {
  console.log('🔐 === AUTHENTICATION START ===');
  console.log('🔐 Request URL:', req.url);
  console.log('🔐 Request method:', req.method);
  console.log('🔐 User-Agent:', req.headers['user-agent']);
  
  // Detect Safari browser
  const userAgent = req.headers['user-agent'] || '';
  const isSafari = /^((?!chrome|android).)*safari/i.test(userAgent);
  const isIOS = /iPad|iPhone|iPod/.test(userAgent);
  const isMacOS = /Mac OS X/.test(userAgent);
  
  console.log('🔐 Browser detection:', { isSafari, isIOS, isMacOS });
  console.log('🔐 Headers:', JSON.stringify({
    authorization: req.headers.authorization,
    'x-auth-token': req.headers['x-auth-token'],
    'x-username': req.headers['x-username'],
    cookie: req.headers.cookie,
    origin: req.headers.origin
  }, null, 2));
  console.log('🔐 Cookies:', JSON.stringify(req.cookies, null, 2));
  
  // For Safari, try username-based authentication first
  if (isSafari) {
    const username = req.headers['x-username'] || req.query.username;
    console.log('🦁 Safari username check:', { 
      fromHeader: req.headers['x-username'], 
      fromQuery: req.query.username, 
      finalUsername: username 
    });
    if (username) {
      console.log('🦁 Safari username-based auth attempt for:', username);
      
      try {
        // Find user by username (await to ensure it completes)
        const user = await findUserByUsername(username);
        if (user) {
          console.log('✅ Safari username auth successful for:', user.username);
          req.user = {
            id: user.id || user._id,
            username: user.username,
            role: user.role,
            teamName: user.teamName
          };
          console.log('🔐 === AUTHENTICATION END (SAFARI USERNAME SUCCESS) ===');
          return next();
        } else {
          console.log('❌ Safari username auth failed - user not found:', username);
        }
      } catch (error) {
        console.log('❌ Safari username auth error:', error.message);
      }
    }
  }
  
  // Enhanced token extraction for all browsers compatibility
  let token = null;
  let tokenSource = 'none';
  
  // Universal token extraction order (try all sources for better compatibility)
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    token = req.headers.authorization.split(' ')[1];
    tokenSource = 'authorization header';
  } else if (req.headers['x-auth-token']) {
    token = req.headers['x-auth-token'];
    tokenSource = 'x-auth-token header';
  } else if (req.cookies.token) {
    token = req.cookies.token;
    tokenSource = 'cookie';
  } else if (req.body.token) {
    token = req.body.token;
    tokenSource = 'request body';
  } else if (req.query.token) {
    token = req.query.token;
    tokenSource = 'query parameter';
  }
  
  console.log('🔐 Token found:', token ? 'Yes' : 'No');
  console.log('🔐 Token source:', tokenSource);
  
  if (!token) {
    console.log('❌ No token provided');
    console.log('🔐 === AUTHENTICATION END (NO TOKEN) ===');
    return res.status(401).json({ 
      error: 'Access token required',
      debug: {
        cookies: req.cookies,
        authHeader: req.headers.authorization,
        xAuthToken: req.headers['x-auth-token'],
        xUsername: req.headers['x-username'],
        userAgent: req.headers['user-agent'],
        platform: isSafari ? 'safari' : 'other',
        isIOS: isIOS,
        isMacOS: isMacOS
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
          tokenPreview: token.substring(0, 20) + '...',
          tokenSource: tokenSource,
          platform: isSafari ? 'safari' : 'other'
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

// Enhanced Admin middleware with better debugging - Fixed for admin access
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
  console.log('🔐   - Role length:', req.user.role ? req.user.role.length : 'undefined');
  
  // Enhanced admin check with multiple conditions
  const username = req.user.username;
  const userRole = req.user.role;
  
  // Check for admin bypass (username-based)
  if (username === 'ayman' || username === 'admin' || username === 'Admin') {
    console.log('✅ Admin check BYPASS: username is admin user');
    console.log('🔐 === ADMIN CHECK END (BYPASS) ===');
    return next();
  }
  
  // Check for role-based admin access
  const isAdminByRole = userRole === 'admin' || 
                       userRole === 'ADMIN' || 
                       userRole === 'Admin' ||
                       userRole === 'administrator' ||
                       userRole === 'Administrator';
  
  console.log('🔐 Role check details:');
  console.log('🔐   - User role:', userRole);
  console.log('🔐   - Is admin (strict):', userRole === 'admin');
  console.log('🔐   - Is admin (case insensitive):', isAdminByRole);
  console.log('🔐   - Role comparison results:');
  console.log('🔐     - admin:', userRole === 'admin');
  console.log('🔐     - ADMIN:', userRole === 'ADMIN');
  console.log('🔐     - Admin:', userRole === 'Admin');
  
  if (isAdminByRole) {
    console.log('✅ Admin check passed for user:', username);
    console.log('🔐 === ADMIN CHECK END (SUCCESS) ===');
    return next();
  }
  
  console.log('❌ Admin check failed: User role is not admin');
  console.log('🔐 === ADMIN CHECK END (FAILED) ===');
  return res.status(403).json({ 
    error: 'Admin access required',
    debug: {
      userRole: userRole,
      userId: req.user.id,
      username: username,
      requiredRole: 'admin',
      isAdminCheck: isAdminByRole,
      roleType: typeof userRole,
      roleLength: userRole ? userRole.length : 'undefined'
    }
  });
}

// Safari-specific admin middleware (works with username authentication)
function requireAdminSafari(req, res, next) {
  console.log('🦁 === SAFARI ADMIN CHECK START ===');
  console.log('🦁 Request URL:', req.url);
  console.log('🦁 User from request:', JSON.stringify(req.user, null, 2));
  
  if (!req.user) {
    console.log('❌ Safari admin check failed: No user found in request');
    console.log('🦁 === SAFARI ADMIN CHECK END (NO USER) ===');
    return res.status(401).json({ 
      error: 'Authentication required',
      debug: 'No user found in request object (Safari)'
    });
  }
  
  console.log('🦁 Safari user details:');
  console.log('🦁   - ID:', req.user.id);
  console.log('🦁   - Username:', req.user.username);
  console.log('🦁   - Role:', req.user.role);
  
  // Safari admin check (simplified)
  const username = req.user.username;
  const userRole = req.user.role;
  
  // Check for admin bypass (username-based)
  if (username === 'ayman' || username === 'admin' || username === 'Admin') {
    console.log('✅ Safari admin check BYPASS: username is admin user');
    console.log('🦁 === SAFARI ADMIN CHECK END (BYPASS) ===');
    return next();
  }
  
  // Check for role-based admin access
  const isAdminByRole = userRole === 'admin' || 
                       userRole === 'ADMIN' || 
                       userRole === 'Admin' ||
                       userRole === 'administrator' ||
                       userRole === 'Administrator';
  
  if (isAdminByRole) {
    console.log('✅ Safari admin check passed for user:', username);
    console.log('🦁 === SAFARI ADMIN CHECK END (SUCCESS) ===');
    return next();
  }
  
  console.log('❌ Safari admin check failed: User role is not admin');
  console.log('🦁 === SAFARI ADMIN CHECK END (FAILED) ===');
  return res.status(403).json({ 
    error: 'Admin access required (Safari)',
    debug: {
      userRole: userRole,
      userId: req.user.id,
      username: username,
      requiredRole: 'admin',
      isAdminCheck: isAdminByRole,
      platform: 'safari'
    }
  });
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

// Debug endpoint to check current authentication state - Enhanced for Safari (iOS + macOS)
app.get('/api/debug/auth-state', (req, res) => {
  console.log('🔍 Auth state check');
  console.log('🔍 Cookies:', req.cookies);
  console.log('🔍 Headers:', req.headers);
  
  const userAgent = req.headers['user-agent'] || '';
  const isSafari = /^((?!chrome|android).)*safari/i.test(userAgent);
  const isIOS = /iPad|iPhone|iPod/.test(userAgent);
  const isMacOS = /Mac OS X/.test(userAgent);
  
  const token = req.cookies.token || 
                (req.headers.authorization && req.headers.authorization.split(' ')[1]) ||
                req.headers['x-auth-token'] ||
                req.body.token ||
                req.query.token;
  
  res.json({
    cookies: req.cookies,
    headers: {
      authorization: req.headers.authorization,
      'x-auth-token': req.headers['x-auth-token'],
      'user-agent': req.headers['user-agent'],
      'origin': req.headers.origin
    },
    hasToken: !!token,
    tokenSource: req.cookies.token ? 'cookie' : 
                req.headers.authorization ? 'authorization header' :
                req.headers['x-auth-token'] ? 'x-auth-token header' :
                req.body.token ? 'request body' :
                req.query.token ? 'query parameter' : 'none',
    browser: {
      isSafari: isSafari,
      isIOS: isIOS,
      isMacOS: isMacOS,
      platform: isSafari ? 'safari' : 
                isIOS ? 'ios' : 
                isMacOS ? 'macos' : 'other'
    },
    timestamp: new Date().toISOString()
  });
});

// Safari-specific debug endpoint
app.get('/api/debug/safari-auth', async (req, res) => {
  console.log('🦁 Safari auth debug check');
  
  const userAgent = req.headers['user-agent'] || '';
  const isSafari = /^((?!chrome|android).)*safari/i.test(userAgent);
  const isIOS = /iPad|iPhone|iPod/.test(userAgent);
  const isMacOS = /Mac OS X/.test(userAgent);
  
  // Safari-specific token extraction
  const token = (req.headers.authorization && req.headers.authorization.split(' ')[1]) ||
                req.headers['x-auth-token'] ||
                req.cookies.token ||
                req.body.token ||
                req.query.token;
  
  // Test username-based authentication
  const username = req.headers['x-username'] || req.query.username;
  let user = null;
  if (username) {
    try {
      user = await findUserByUsername(username);
    } catch (error) {
      console.log('❌ Error finding user:', error.message);
    }
  }
  
  res.json({
    safari: {
      isSafari: isSafari,
      isIOS: isIOS,
      isMacOS: isMacOS,
      userAgent: userAgent
    },
    token: {
      hasToken: !!token,
      source: req.headers.authorization ? 'authorization header' :
              req.headers['x-auth-token'] ? 'x-auth-token header' :
              req.cookies.token ? 'cookie' :
              req.body.token ? 'request body' :
              req.query.token ? 'query parameter' : 'none',
      preview: token ? token.substring(0, 20) + '...' : null
    },
    usernameAuth: {
      provided: username,
      found: user ? { id: user.id || user._id, username: user.username, role: user.role } : null,
      success: !!user
    },
    cookies: req.cookies,
    headers: {
      authorization: req.headers.authorization,
      'x-auth-token': req.headers['x-auth-token'],
      'x-username': req.headers['x-username']
    },
    timestamp: new Date().toISOString()
  });
});

// Endpoint to manually trigger spin reset when frontend detects all limitations completed
app.post('/api/spin/reset-when-completed', authenticateToken, async (req, res) => {
  try {
    const user = await findUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const spinLimitations = user.teamSettings?.spinLimitations || {};
    const currentSpinCounts = user.teamSettings?.spinCounts || {};

    // Check if ALL ENABLED spin types have reached their limits (according to admin settings)
    // Explicitly exclude 'regular' spin type as requested by user
    const enabledSpinTypes = Object.entries(spinLimitations)
      .filter(([type, lim]) => lim.enabled && lim.limit > 0 && type !== 'regular')
      .map(([type]) => type);
    
    const completedSpinTypes = enabledSpinTypes.filter(type => {
      const limitation = spinLimitations[type];
      const count = currentSpinCounts[type] || 0;
      const limit = limitation?.limit || 1;
      return count >= limit;
    });

    console.log(`🔄 Manual reset check for ${user.teamName}:`);
    console.log(`🔄   - Enabled spin types: ${enabledSpinTypes.join(', ')} (${enabledSpinTypes.length} total)`);
    console.log(`🔄   - Completed spin types: ${completedSpinTypes.join(', ')} (${completedSpinTypes.length} total)`);
    console.log(`🔄   - Current spin counts:`, currentSpinCounts);

    if (enabledSpinTypes.length > 0 && completedSpinTypes.length === enabledSpinTypes.length) {
      console.log(`🎉 Manual reset triggered for ${user.teamName}! All enabled spin types completed.`);

      const resetTeamSettings = {
        ...user.teamSettings,
        spinCounts: {
          lucky: 0,
          gamehelper: 0,
          challenge: 0,
          hightier: 0,
          lowtier: 0,
          random: 0
        }
      };

      await updateUserById(req.user.id, { teamSettings: resetTeamSettings });

      // Send socket notifications
      if (io) {
        io.emit('spin-counts-reset', { 
          userId: req.user.id,
          message: `🎉 Manual reset: All ${enabledSpinTypes.length} enabled spin types completed. Counts reset to 0.`
        });

        io.to(req.user.id).emit('spin-counts-reset', { 
          userId: req.user.id,
          message: `🎉 Manual reset: All ${enabledSpinTypes.length} enabled spin types completed. Counts reset to 0.`
        });

        io.emit('user-team-settings-updated', {
          userId: req.user.id,
          teamSettings: resetTeamSettings
        });
      }

      res.json({ 
        success: true, 
        message: 'Spin counts reset successfully',
        resetData: {
          enabledSpinTypes,
          completedSpinTypes,
          resetCounts: resetTeamSettings.spinCounts
        }
      });
    } else {
      res.json({ 
        success: false, 
        message: 'Not all enabled spin types are completed yet',
        data: {
          enabledSpinTypes,
          completedSpinTypes,
          currentSpinCounts
        }
      });
    }
  } catch (error) {
    console.error('Error in manual spin reset:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Debug endpoint to simulate a spin and check reset logic
app.post('/api/debug/test-spin-reset', authenticateToken, async (req, res) => {
  try {
    console.log('🔄 === TEST SPIN RESET DEBUG START ===');
    console.log('🔄 User from token:', JSON.stringify(req.user, null, 2));
    
    const user = await findUserById(req.user.id);
    console.log('🔄 User from database:', JSON.stringify(user, null, 2));
    
    const teamSettings = user?.teamSettings || {};
    const spinLimitations = teamSettings.spinLimitations || {};
    const currentSpinCounts = teamSettings.spinCounts || { lucky: 0, gamehelper: 0, challenge: 0, hightier: 0, lowtier: 0, random: 0 };
    
    console.log('🔄 Current spin limitations:', spinLimitations);
    console.log('🔄 Current spin counts:', currentSpinCounts);
    
    // Simulate the reset check logic
    // Explicitly exclude 'regular' spin type as requested by user
    const enabledSpinTypes = Object.entries(spinLimitations)
      .filter(([type, lim]) => lim.enabled && lim.limit > 0 && type !== 'regular')
      .map(([type]) => type);
    
    const completedSpinTypes = enabledSpinTypes.filter(type => 
      (currentSpinCounts[type] || 0) >= (spinLimitations[type]?.limit || 1)
    );
    
    console.log('🔄 Test results:');
    console.log('🔄   - Enabled spin types:', enabledSpinTypes);
    console.log('🔄   - Completed spin types:', completedSpinTypes);
    console.log('🔄   - All completed:', enabledSpinTypes.length > 0 && completedSpinTypes.length === enabledSpinTypes.length);
    
    res.json({
      success: true,
      spinLimitations,
      currentSpinCounts,
      enabledSpinTypes,
      completedSpinTypes,
      shouldReset: enabledSpinTypes.length > 0 && completedSpinTypes.length === enabledSpinTypes.length
    });
  } catch (error) {
    console.error('Test spin reset error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Debug endpoint to manually reset user spin counts (for testing)
app.post('/api/debug/reset-spins', authenticateToken, async (req, res) => {
  try {
    console.log('🔄 === MANUAL SPIN RESET DEBUG START ===');
    console.log('🔄 User from token:', JSON.stringify(req.user, null, 2));
    
    const user = await findUserById(req.user.id);
    console.log('🔄 User from database:', JSON.stringify(user, null, 2));
    
    const currentTeamSettings = user?.teamSettings || {};
    const currentSpinCounts = currentTeamSettings.spinCounts || { lucky: 0, gamehelper: 0, challenge: 0, hightier: 0, lowtier: 0, random: 0 };
    
    console.log('🔄 Current spin counts before reset:', currentSpinCounts);
    
    // Reset all spin counts to 0
    const resetTeamSettings = {
      ...currentTeamSettings,
      spinCounts: {
        lucky: 0,
        gamehelper: 0,
        challenge: 0,
        hightier: 0,
        lowtier: 0,
        random: 0
      }
    };
    
    await updateUserById(req.user.id, { teamSettings: resetTeamSettings });
    
    console.log('🔄 Spin counts reset to 0');
    
    // Send notification to user
    if (io) {
      console.log('📡 Emitting manual spin reset socket events');
      
      // Emit spin reset event
      io.emit('spin-counts-reset', { 
        userId: req.user.id,
        message: `🔄 Manual spin reset completed! All spin counts have been reset to 0.`
      });
      
      // Emit team settings update
      io.emit('user-team-settings-updated', {
        userId: req.user.id,
        teamSettings: resetTeamSettings
      });
      
      console.log('📡 Manual spin reset socket events emitted');
    } else {
      console.log('❌ Socket.io not available for manual reset');
    }
    
    res.json({
      success: true,
      message: 'Spin counts reset successfully',
      previousCounts: currentSpinCounts,
      newCounts: resetTeamSettings.spinCounts
    });
  } catch (error) {
    console.error('Manual spin reset error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Debug endpoint to check user spin status
app.get('/api/debug/spin-status', authenticateToken, async (req, res) => {
  try {
    console.log('🔍 === SPIN STATUS DEBUG START ===');
    console.log('🔍 User from token:', JSON.stringify(req.user, null, 2));
    
    const user = await findUserById(req.user.id);
    console.log('🔍 User from database:', JSON.stringify(user, null, 2));
    
    const teamSettings = user?.teamSettings || {};
    const spinLimitations = teamSettings.spinLimitations || {};
    const spinCounts = teamSettings.spinCounts || { lucky: 0, gamehelper: 0, challenge: 0, hightier: 0, lowtier: 0, random: 0 };
    
    // Check which spin types are enabled
    const enabledSpinTypes = Object.entries(spinLimitations)
      .filter(([type, lim]) => lim.enabled && lim.limit > 0)
      .map(([type]) => type);
    
    // Check which spin types are completed
    const completedSpinTypes = enabledSpinTypes.filter(type => 
      (spinCounts[type] || 0) >= (spinLimitations[type]?.limit || 1)
    );
    
    // Check if all enabled spins are completed
    const allCompleted = enabledSpinTypes.length > 0 && completedSpinTypes.length === enabledSpinTypes.length;
    
    console.log('🔍 Spin status analysis:');
    console.log('🔍   - Enabled spin types:', enabledSpinTypes);
    console.log('🔍   - Completed spin types:', completedSpinTypes);
    console.log('🔍   - All completed:', allCompleted);
    
    res.json({
      user: {
        id: req.user.id,
        username: req.user.username,
        teamName: user?.teamName
      },
      spinStatus: {
        spinLimitations,
        spinCounts,
        enabledSpinTypes,
        completedSpinTypes,
        allCompleted,
        shouldReset: allCompleted
      },
      debug: {
        enabledCount: enabledSpinTypes.length,
        completedCount: completedSpinTypes.length,
        resetTriggered: allCompleted
      }
    });
  } catch (error) {
    console.error('Spin status debug error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Debug endpoint to check user role and admin status
app.get('/api/debug/user-role', authenticateToken, async (req, res) => {
  try {
    console.log('🔍 === USER ROLE DEBUG START ===');
    console.log('🔍 User from token:', JSON.stringify(req.user, null, 2));
    
    const user = await findUserById(req.user.id);
    console.log('🔍 User from database:', JSON.stringify(user, null, 2));
    
    const username = req.user.username;
    const userRole = req.user.role;
    const dbUserRole = user?.role;
    
    // Check admin conditions
    const isAdminByUsername = username === 'ayman' || username === 'admin' || username === 'Admin';
    const isAdminByRole = userRole === 'admin' || 
                         userRole === 'ADMIN' || 
                         userRole === 'Admin' ||
                         userRole === 'administrator' ||
                         userRole === 'Administrator';
    const isAdminByDbRole = dbUserRole === 'admin' || 
                           dbUserRole === 'ADMIN' || 
                           dbUserRole === 'Admin' ||
                           dbUserRole === 'administrator' ||
                           dbUserRole === 'Administrator';
    
    console.log('🔍 Admin check results:');
    console.log('🔍   - Username:', username);
    console.log('🔍   - Token role:', userRole);
    console.log('🔍   - DB role:', dbUserRole);
    console.log('🔍   - Is admin by username:', isAdminByUsername);
    console.log('🔍   - Is admin by token role:', isAdminByRole);
    console.log('🔍   - Is admin by DB role:', isAdminByDbRole);
    
    res.json({
      user: {
        id: req.user.id,
        username: username,
        role: userRole,
        roleType: typeof userRole,
        roleLength: userRole ? userRole.length : 'undefined'
      },
      databaseUser: user ? {
        id: user.id || user._id,
        username: user.username,
        role: dbUserRole,
        roleType: typeof dbUserRole
      } : null,
      adminChecks: {
        isAdminByUsername: isAdminByUsername,
        isAdminByTokenRole: isAdminByRole,
        isAdminByDbRole: isAdminByDbRole,
        wouldPassAdminCheck: isAdminByUsername || isAdminByRole
      },
      debug: {
        tokenRole: userRole,
        dbRole: dbUserRole,
        rolesMatch: userRole === dbUserRole,
        timestamp: new Date().toISOString()
      }
    });
    
    console.log('🔍 === USER ROLE DEBUG END ===');
  } catch (error) {
    console.error('❌ User role debug error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Debug endpoint to check card collection status
app.get('/api/debug/card-collection', authenticateToken, async (req, res) => {
  try {
    console.log('🎴 === CARD COLLECTION DEBUG START ===');
    console.log('🎴 User from token:', JSON.stringify(req.user, null, 2));
    
    const user = await findUserById(req.user.id);
    console.log('🎴 User from database:', JSON.stringify(user, null, 2));
    
    const teamSettings = user?.teamSettings || {};
    const receivedCards = teamSettings.receivedCards || {};
    
    // Get all available cards for each spin type
    const allCards = {
      lucky: getCardsByType('lucky'),
      gamehelper: getCardsByType('gamehelper'),
      challenge: getCardsByType('challenge'),
      hightier: getCardsByType('hightier'),
      lowtier: getCardsByType('lowtier'),
      random: getCardsByType('random')
    };
    
    const collectionStatus = {};
    
    Object.keys(allCards).forEach(spinType => {
      const totalCards = allCards[spinType].length;
      const receivedCardsForType = receivedCards[spinType] || [];
      const collectedCount = receivedCardsForType.length;
      const remainingCount = totalCards - collectedCount;
      const percentage = totalCards > 0 ? Math.round((collectedCount / totalCards) * 100) : 0;
      
      collectionStatus[spinType] = {
        totalCards,
        collectedCards: receivedCardsForType,
        collectedCount,
        remainingCount,
        percentage,
        isComplete: collectedCount >= totalCards,
        availableCards: allCards[spinType].filter(card => !receivedCardsForType.includes(card.name))
      };
    });
    
    console.log('🎴 Card collection status:', collectionStatus);
    
    res.json({
      user: {
        id: req.user.id,
        username: req.user.username,
        teamName: user?.teamName
      },
      collectionStatus,
      receivedCards,
      debug: {
        timestamp: new Date().toISOString()
      }
    });
    
    console.log('🎴 === CARD COLLECTION DEBUG END ===');
  } catch (error) {
    console.error('❌ Card collection debug error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin endpoint to reset card collection for a user
app.post('/api/admin/reset-card-collection', authenticateToken, async (req, res) => {
  try {
    console.log('🔄 === ADMIN RESET CARD COLLECTION START ===');
    console.log('🔄 Admin request from:', JSON.stringify(req.user, null, 2));
    
    // Check if user is admin
    const username = req.user.username;
    const userRole = req.user.role;
    const isAdmin = username === 'ayman' || username === 'admin' || username === 'Admin' ||
                   userRole === 'admin' || userRole === 'ADMIN' || userRole === 'Admin' ||
                   userRole === 'administrator' || userRole === 'Administrator';
    
    if (!isAdmin) {
      console.log('❌ Non-admin user attempted to reset card collection');
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const { userId, spinType } = req.body;
    
    if (!userId) {
      return res.status(400).json({ error: 'User ID is required' });
    }
    
    const targetUser = await findUserById(userId);
    if (!targetUser) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const teamSettings = targetUser.teamSettings || {};
    const receivedCards = teamSettings.receivedCards || {};
    
    if (spinType) {
      // Reset specific spin type
      receivedCards[spinType] = [];
      console.log(`🔄 Reset card collection for ${targetUser.teamName} - spin type: ${spinType}`);
    } else {
      // Reset all spin types
      Object.keys(receivedCards).forEach(type => {
        receivedCards[type] = [];
      });
      console.log(`🔄 Reset all card collections for ${targetUser.teamName}`);
    }
    
    const updatedTeamSettings = {
      ...teamSettings,
      receivedCards
    };
    
    await updateUserById(userId, { teamSettings: updatedTeamSettings });
    
    // Send notification to the user
    const resetNotification = {
      id: Date.now().toString(),
      userId: userId,
      type: 'card-collection-reset',
      message: spinType 
        ? `Your ${spinType} card collection has been reset by admin.`
        : 'All your card collections have been reset by admin.',
      timestamp: new Date().toISOString(),
      read: false,
      recipientType: 'user'
    };
    await addNotification(resetNotification);
    
    // Send socket notification to the user
    if (io) {
      io.to(userId).emit('notification', resetNotification);
      io.emit('user-team-settings-updated', {
        userId: userId,
        teamSettings: updatedTeamSettings
      });
    }
    
    res.json({
      success: true,
      message: spinType 
        ? `Card collection reset for ${targetUser.teamName} - ${spinType} spin type`
        : `All card collections reset for ${targetUser.teamName}`,
      user: {
        id: targetUser.id,
        teamName: targetUser.teamName
      },
      resetData: {
        spinType: spinType || 'all',
        receivedCards
      }
    });
    
    console.log('🔄 === ADMIN RESET CARD COLLECTION END ===');
  } catch (error) {
    console.error('❌ Admin reset card collection error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Helper to get cookie options based on environment - Enhanced for Safari (iOS + macOS)
function getCookieOptions() {
  const isProduction = process.env.NODE_ENV === 'production';
  
  // Safari-specific cookie options for both iOS and macOS
  return {
    httpOnly: false, // Allow JavaScript access for Safari compatibility
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'lax', // Use 'lax' for Safari compatibility (works better than 'none')
    secure: false, // Disable secure for localhost to work with Safari
    path: '/',
    domain: undefined, // Let browser set domain automatically
  };
}

// Add auth logout route for compatibility
app.post('/api/auth/logout', (req, res) => {
  try {
    console.log('🚪 === AUTH LOGOUT START ===');
    console.log('🚪 Auth logout request received');
    const cookieOptions = getCookieOptions();
    res.clearCookie('token', cookieOptions);
    res.clearCookie('authToken', cookieOptions);
    res.clearCookie('session', cookieOptions);
    console.log('✅ Auth logout successful - cookies cleared');
    console.log('🚪 === AUTH LOGOUT END ===');
    res.json({ 
      message: 'Logged out successfully',
      success: true 
    });
  } catch (error) {
    console.error('❌ Auth logout error:', error);
    res.status(500).json({ 
      error: 'Logout failed',
      success: false 
    });
  }
});

// Safari-specific logout endpoint (no cookies to clear)
app.post('/api/safari/logout', (req, res) => {
  try {
    console.log('🦁 === SAFARI LOGOUT START ===');
    console.log('🦁 Safari logout request received');
    console.log('🦁 User-Agent:', req.headers['user-agent']);
    
    // Safari logout - no cookies to clear, just acknowledge
    console.log('✅ Safari logout successful - no cookies to clear');
    console.log('🦁 === SAFARI LOGOUT END ===');
    res.json({ 
      message: 'Safari logout successful - clear localStorage on frontend',
      success: true,
      safari: true
    });
  } catch (error) {
    console.error('❌ Safari logout error:', error);
    res.status(500).json({ 
      error: 'Safari logout failed',
      success: false 
    });
  }
});

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

// Add auth routes for compatibility
app.post('/api/auth/login', async (req, res) => {
  try {
    console.log('🔑 === AUTH LOGIN START ===');
    console.log('🔑 Auth login attempt:', { username: req.body.username });
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
    console.log('✅ Auth login successful for user:', username);
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
    console.log('🔑 Sending auth response:', responseData);
    console.log('🔑 === AUTH LOGIN END (SUCCESS) ===');
    res.json(responseData);
  } catch (error) {
    console.error('❌ Auth login error:', error);
    console.log('🔑 === AUTH LOGIN END (ERROR) ===');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Safari-specific login endpoint (no cookies, localStorage only)
app.post('/api/safari/login', async (req, res) => {
  try {
    console.log('🦁 === SAFARI LOGIN START ===');
    console.log('🦁 Safari login attempt:', { username: req.body.username });
    console.log('🦁 User-Agent:', req.headers['user-agent']);
    
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
    
    // Enhanced token payload with debugging
    const tokenPayload = { 
      id: user.id || user._id, 
      username: user.username, 
      role: user.role, 
      teamName: user.teamName 
    };
    
    console.log('🦁 Creating Safari token with payload:', tokenPayload);
    console.log('🦁 User role details:');
    console.log('🦁   - Role:', user.role);
    console.log('🦁   - Role type:', typeof user.role);
    console.log('🦁   - Role length:', user.role ? user.role.length : 'undefined');
    console.log('🦁   - Is admin role:', user.role === 'admin');
    
    const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '24h' });
    
    // Verify token was created correctly
    try {
      const decodedToken = jwt.verify(token, JWT_SECRET);
      console.log('🦁 Token verification test:', {
        id: decodedToken.id,
        username: decodedToken.username,
        role: decodedToken.role,
        roleType: typeof decodedToken.role
      });
    } catch (verifyError) {
      console.error('❌ Safari token verification failed:', verifyError);
    }
    
    // Safari-specific response (no cookies, only token in response)
    const responseData = {
      user: {
        id: user.id || user._id,
        username: user.username,
        role: user.role,
        teamName: user.teamName,
        coins: user.coins,
        score: user.score
      },
      token: token, // Token for localStorage
      safari: true, // Flag to indicate Safari-specific response
      message: 'Safari login successful - store token in localStorage'
    };
    
    console.log('🦁 Safari login successful for user:', username);
    console.log('🦁 Sending Safari response:', responseData);
    console.log('🦁 === SAFARI LOGIN END (SUCCESS) ===');
    
    // Don't set cookies for Safari - let frontend handle localStorage
    res.json(responseData);
  } catch (error) {
    console.error('❌ Safari login error:', error);
    console.log('🦁 === SAFARI LOGIN END (ERROR) ===');
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    console.log('🔍 === AUTH ME START ===');
    console.log('🔍 User-Agent:', req.headers['user-agent']);
    const user = await findUserById(req.user.id);
    if (!user) {
      console.log('❌ User not found in auth/me:', req.user.id);
      return res.status(404).json({ error: "User not found" });
    }
    console.log('✅ Auth me successful for user:', user.username);
    res.json({
      id: user.id || user._id,
      username: user.username,
      role: user.role,
      teamName: user.teamName,
      coins: user.coins,
      score: user.score,
      totalMined: user.totalMined || 0,
      lastMined: user.lastMined,
      teamSettings: user.teamSettings || {
        scoreboardVisible: true,
        spinLimitations: {
          lucky: { enabled: true, limit: 1 },
          gamehelper: { enabled: true, limit: 1 },
          challenge: { enabled: true, limit: 1 },
          hightier: { enabled: true, limit: 1 },
          lowtier: { enabled: true, limit: 1 },
          random: { enabled: true, limit: 1 }
        },
        spinCounts: { lucky: 0, gamehelper: 0, challenge: 0, hightier: 0, lowtier: 0, random: 0 }
      }
    });
    console.log('🔍 === AUTH ME END (SUCCESS) ===');
  } catch (error) {
    console.error("Error in auth/me:", error);
    console.log('🔍 === AUTH ME END (ERROR) ===');
    res.status(500).json({ error: "Internal server error" });
  }
});

// Mobile-specific authentication endpoint for iOS/macOS
app.get('/api/mobile/auth/me', async (req, res) => {
  try {
    console.log('📱 === MOBILE AUTH ME START ===');
    console.log('📱 User-Agent:', req.headers['user-agent']);
    
    // Extract token from multiple sources for mobile compatibility
    const token = req.cookies.token || 
                  (req.headers.authorization && req.headers.authorization.split(' ')[1]) ||
                  req.headers['x-auth-token'] ||
                  req.body.token ||
                  req.query.token;
    
    if (!token) {
      console.log('❌ No token found in mobile auth/me');
      return res.status(401).json({ 
        error: 'Access token required',
        debug: {
          cookies: req.cookies,
          authHeader: req.headers.authorization,
          xAuthToken: req.headers['x-auth-token'],
          userAgent: req.headers['user-agent']
        }
      });
    }
    
    // Verify token
    jwt.verify(token, JWT_SECRET, async (err, decoded) => {
      if (err) {
        console.log('❌ Token verification failed in mobile auth/me:', err.message);
        return res.status(401).json({ error: 'Invalid token' });
      }
      
      const user = await findUserById(decoded.id);
      if (!user) {
        console.log('❌ User not found in mobile auth/me:', decoded.id);
        return res.status(404).json({ error: "User not found" });
      }
      
      console.log('✅ Mobile auth me successful for user:', user.username);
      res.json({
        id: user.id || user._id,
        username: user.username,
        role: user.role,
        teamName: user.teamName,
        coins: user.coins,
        score: user.score,
        totalMined: user.totalMined || 0,
        lastMined: user.lastMined,
        teamSettings: user.teamSettings || {
          scoreboardVisible: true,
          spinLimitations: {
            lucky: { enabled: true, limit: 1 },
            gamehelper: { enabled: true, limit: 1 },
            challenge: { enabled: true, limit: 1 },
            hightier: { enabled: true, limit: 1 },
            lowtier: { enabled: true, limit: 1 },
            random: { enabled: true, limit: 1 }
          },
          spinCounts: { lucky: 0, gamehelper: 0, challenge: 0, hightier: 0, lowtier: 0, random: 0 }
        }
      });
      console.log('📱 === MOBILE AUTH ME END (SUCCESS) ===');
    });
  } catch (error) {
    console.error("Error in mobile auth/me:", error);
    console.log('📱 === MOBILE AUTH ME END (ERROR) ===');
    res.status(500).json({ error: "Internal server error" });
  }
});

// Safari-specific authentication endpoint (no cookies, localStorage only)
app.get('/api/safari/auth/me', async (req, res) => {
  try {
    console.log('🦁 === SAFARI AUTH ME START ===');
    console.log('🦁 User-Agent:', req.headers['user-agent']);
    
    // Safari-specific token extraction (no cookies, only headers)
    const token = (req.headers.authorization && req.headers.authorization.split(' ')[1]) ||
                  req.headers['x-auth-token'] ||
                  req.body.token ||
                  req.query.token;
    
    if (!token) {
      console.log('❌ No token found in Safari auth/me');
      return res.status(401).json({ 
        error: 'Access token required',
        debug: {
          authHeader: req.headers.authorization,
          xAuthToken: req.headers['x-auth-token'],
          userAgent: req.headers['user-agent'],
          platform: 'safari'
        }
      });
    }
    
    // Verify token
    jwt.verify(token, JWT_SECRET, async (err, decoded) => {
      if (err) {
        console.log('❌ Token verification failed in Safari auth/me:', err.message);
        return res.status(401).json({ error: 'Invalid token' });
      }
      
      const user = await findUserById(decoded.id);
      if (!user) {
        console.log('❌ User not found in Safari auth/me:', decoded.id);
        return res.status(404).json({ error: "User not found" });
      }
      
      console.log('✅ Safari auth me successful for user:', user.username);
      res.json({
        id: user.id || user._id,
        username: user.username,
        role: user.role,
        teamName: user.teamName,
        coins: user.coins,
        score: user.score,
        totalMined: user.totalMined || 0,
        lastMined: user.lastMined,
        teamSettings: user.teamSettings || {
          scoreboardVisible: true,
          spinLimitations: {
            lucky: { enabled: true, limit: 1 },
            gamehelper: { enabled: true, limit: 1 },
            challenge: { enabled: true, limit: 1 },
            hightier: { enabled: true, limit: 1 },
            lowtier: { enabled: true, limit: 1 },
            random: { enabled: true, limit: 1 }
          },
          spinCounts: { lucky: 0, gamehelper: 0, challenge: 0, hightier: 0, lowtier: 0, random: 0 }
        }
      });
      console.log('🦁 === SAFARI AUTH ME END (SUCCESS) ===');
    });
  } catch (error) {
    console.error("Error in Safari auth/me:", error);
    console.log('🦁 === SAFARI AUTH ME END (ERROR) ===');
    res.status(500).json({ error: "Internal server error" });
  }
});

// SIMPLE Safari authentication - NO TOKEN REQUIRED (for testing)
app.get('/api/safari/simple-auth', async (req, res) => {
  try {
    console.log('🦁 === SAFARI SIMPLE AUTH START ===');
    console.log('🦁 User-Agent:', req.headers['user-agent']);
    
    // Get username from query parameter or header
    const username = req.query.username || req.headers['x-username'];
    
    if (!username) {
      console.log('❌ No username provided in Safari simple auth');
      return res.status(400).json({ 
        error: 'Username required',
        debug: {
          query: req.query,
          headers: req.headers,
          userAgent: req.headers['user-agent']
        }
      });
    }
    
    const user = await findUserByUsername(username);
    if (!user) {
      console.log('❌ User not found in Safari simple auth:', username);
      return res.status(404).json({ error: "User not found" });
    }
    
    console.log('✅ Safari simple auth successful for user:', user.username);
    res.json({
      id: user.id || user._id,
      username: user.username,
      role: user.role,
      teamName: user.teamName,
      coins: user.coins,
      score: user.score,
      totalMined: user.totalMined || 0,
      lastMined: user.lastMined,
      teamSettings: user.teamSettings || {
        scoreboardVisible: true,
        spinLimitations: {
          lucky: { enabled: true, limit: 1 },
          gamehelper: { enabled: true, limit: 1 },
          challenge: { enabled: true, limit: 1 },
          hightier: { enabled: true, limit: 1 },
          lowtier: { enabled: true, limit: 1 },
          random: { enabled: true, limit: 1 }
        },
        spinCounts: { lucky: 0, gamehelper: 0, challenge: 0, hightier: 0, lowtier: 0, random: 0 }
      },
      safari: true,
      message: 'Safari simple auth successful - no token required'
    });
    console.log('🦁 === SAFARI SIMPLE AUTH END (SUCCESS) ===');
  } catch (error) {
    console.error("Error in Safari simple auth:", error);
    console.log('🦁 === SAFARI SIMPLE AUTH END (ERROR) ===');
    res.status(500).json({ error: "Internal server error" });
  }
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
    
    // Enhanced token payload with debugging
    const tokenPayload = { 
      id: user.id || user._id, 
      username: user.username, 
      role: user.role, 
      teamName: user.teamName 
    };
    
    console.log('🔑 Creating token with payload:', tokenPayload);
    console.log('🔑 User role details:');
    console.log('🔑   - Role:', user.role);
    console.log('🔑   - Role type:', typeof user.role);
    console.log('🔑   - Role length:', user.role ? user.role.length : 'undefined');
    console.log('🔑   - Is admin role:', user.role === 'admin');
    
    const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '24h' });
    
    // Verify token was created correctly
    try {
      const decodedToken = jwt.verify(token, JWT_SECRET);
      console.log('🔑 Token verification test:', {
        id: decodedToken.id,
        username: decodedToken.username,
        role: decodedToken.role,
        roleType: typeof decodedToken.role
      });
    } catch (verifyError) {
      console.error('❌ Token verification failed:', verifyError);
    }
    
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

// Debug endpoint to test authentication
app.get('/api/auth/test', async (req, res) => {
  try {
    console.log('🧪 === AUTH TEST START ===');
    console.log('🧪 Headers:', JSON.stringify({
      authorization: req.headers.authorization,
      'x-auth-token': req.headers['x-auth-token'],
      cookie: req.headers.cookie
    }, null, 2));
    
    // Try to extract token
    let token = null;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.headers['x-auth-token']) {
      token = req.headers['x-auth-token'];
    } else if (req.cookies.token) {
      token = req.cookies.token;
    }
    
    if (token) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        console.log('🧪 Token verified successfully:', decoded);
        res.json({ 
          success: true, 
          message: 'Token is valid',
          user: decoded,
          tokenSource: req.headers.authorization ? 'authorization' : 
                      req.headers['x-auth-token'] ? 'x-auth-token' : 'cookie'
        });
      } catch (verifyError) {
        console.log('🧪 Token verification failed:', verifyError.message);
        res.status(401).json({ 
          success: false, 
          message: 'Token is invalid',
          error: verifyError.message 
        });
      }
    } else {
      console.log('🧪 No token found');
      res.status(401).json({ 
        success: false, 
        message: 'No token provided',
        headers: {
          authorization: req.headers.authorization ? 'present' : 'missing',
          'x-auth-token': req.headers['x-auth-token'] ? 'present' : 'missing',
          cookie: req.cookies.token ? 'present' : 'missing'
        }
      });
    }
    
    console.log('🧪 === AUTH TEST END ===');
  } catch (error) {
    console.error('🧪 Auth test error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Token refresh endpoint for better cross-browser compatibility
app.post('/api/auth/refresh', async (req, res) => {
  try {
    console.log('🔄 === TOKEN REFRESH START ===');
    
    // Extract token from various sources
    let token = null;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.headers['x-auth-token']) {
      token = req.headers['x-auth-token'];
    } else if (req.cookies.token) {
      token = req.cookies.token;
    } else if (req.body.token) {
      token = req.body.token;
    }
    
    if (!token) {
      console.log('❌ No token provided for refresh');
      return res.status(401).json({ error: 'No token provided' });
    }
    
    console.log('🔄 Attempting to refresh token...');
    
    // Verify the existing token
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log('✅ Token verified, user:', decoded.username);
    
    // Find the user to ensure they still exist
    const user = await findUserById(decoded.id);
    if (!user) {
      console.log('❌ User not found during refresh');
      return res.status(401).json({ error: 'User not found' });
    }
    
    // Create new token with updated payload
    const newTokenPayload = { 
      id: user.id || user._id, 
      username: user.username, 
      role: user.role, 
      teamName: user.teamName 
    };
    
    const newToken = jwt.sign(newTokenPayload, JWT_SECRET, { expiresIn: '24h' });
    
    // Set new cookie
    const cookieOptions = getCookieOptions();
    res.cookie('token', newToken, cookieOptions);
    
    console.log('✅ Token refreshed successfully for:', user.username);
    console.log('🔄 === TOKEN REFRESH END (SUCCESS) ===');
    
    res.json({ 
      token: newToken,
      user: {
        id: user.id || user._id,
        username: user.username,
        role: user.role,
        teamName: user.teamName
      }
    });
    
  } catch (error) {
    console.error('❌ Token refresh error:', error);
    console.log('🔄 === TOKEN REFRESH END (ERROR) ===');
    res.status(401).json({ error: 'Token refresh failed' });
  }
});

app.get('/api/scoreboard', async (req, res) => {
  try {
    const users = await getAllUsers();
          const scoreboard = users
        .filter(user => user.role === 'user')
        .filter(user => {
          // Check if team has scoreboard visibility disabled
          const teamSettings = user.teamSettings || {};
          return teamSettings.scoreboardVisible !== false;
        })
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
    
          // Apply global 50 coins visibility filter
      const filteredCountries = countries.filter(country => {
        const individualVisible = countryVisibilitySettings[country.id] !== false;
        const fiftyCoinsVisible = !gameSettings.fiftyCoinsCountriesHidden || country.cost !== 50;
        return individualVisible && fiftyCoinsVisible;
      });
    
    // Include mining rate in the response
    const countriesWithMining = filteredCountries.map(country => ({
      ...country,
      miningRate: country.miningRate || 0
    }));
    res.json(countriesWithMining);
  } catch (error) {
    console.error('Get countries error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint to get available countries for borrowing (unowned countries)
app.get('/api/countries/available-for-borrow', authenticateToken, async (req, res) => {
  try {
    const user = await findUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const countries = await getAllCountries();
    
    // Filter for unowned countries and apply visibility settings
    const availableCountries = countries.filter(country => {
      const individualVisible = countryVisibilitySettings[country.id] !== false;
      const fiftyCoinsVisible = !gameSettings.fiftyCoinsCountriesHidden || country.cost !== 50;
      const isUnowned = !country.owner;
      const withinBorrowLimit = user.coins - country.cost >= -200;
      
      return individualVisible && fiftyCoinsVisible && isUnowned && withinBorrowLimit;
    });
    
    // Sort by cost (cheapest first)
    availableCountries.sort((a, b) => a.cost - b.cost);
    
    res.json(availableCountries);
  } catch (error) {
    console.error('Get available countries for borrow error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/countries/buy', authenticateToken, async (req, res) => {
  try {
    console.log('🏛️ Country buy request:', { countryId: req.body.countryId, userId: req.user.id });
    
    const { countryId } = req.body;
    const user = await findUserById(req.user.id);
    const country = await findCountryById(countryId);

    if (!country) {
      console.log('❌ Country not found:', countryId);
      return res.status(404).json({ error: 'Country not found' });
    }

    if (country.owner) {
      console.log('❌ Country already owned:', { countryId, owner: country.owner });
      return res.status(400).json({ error: 'Country already owned' });
    }

    if (user.coins < country.cost) {
      console.log('❌ Insufficient coins:', { userCoins: user.coins, countryCost: country.cost });
      return res.status(400).json({ error: 'Insufficient coins' });
    }

    let newCoins = user.coins - country.cost;
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
    if (global.speedBuyTimers && global.speedBuyTimers[userId]) {
      const timer = global.speedBuyTimers[userId];
      const currentTime = Date.now();
      
      console.log('🏃 Speed Buy timer found:', { 
        userId, 
        timerStart: timer.startTime, 
        timerDuration: timer.duration, 
        currentTime, 
        timeRemaining: timer.startTime + timer.duration - currentTime 
      });
      
      // Check if timer is still active
      if (currentTime < (timer.startTime + timer.duration)) {
        // Give Speed Buy reward instantly
        const speedBuyReward = timer.reward;
        const newCoinsWithReward = newCoins + speedBuyReward;
        
        console.log('🎉 Speed Buy reward applied:', { 
          originalCoins: newCoins, 
          reward: speedBuyReward, 
          newCoins: newCoinsWithReward 
        });
        
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
        delete global.speedBuyTimers[userId];
        
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
    
    // Filter countries based on visibility settings before emitting
    const filteredCountries = getFilteredCountries(updatedCountries);
    
    io.emit('scoreboard-update', updatedUsers);
    io.emit('countries-update', filteredCountries);

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

    console.log('✅ Country purchase successful:', { 
      countryName: country.name, 
      finalCoins: newCoins, 
      finalScore: newScore, 
      miningRate: newMiningRate 
    });
    
    res.json({ 
      message: `Successfully bought ${country.name}`,
      user: {
        coins: newCoins,
        score: newScore,
        miningRate: newMiningRate
      }
    });
  } catch (error) {
    console.error('❌ Buy country error:', error);
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
      const { selectedCountry } = req.body;
      
      if (!selectedCountry) {
        return res.status(400).json({ error: 'Please select a country to buy' });
      }
      
      // Get the selected country
      const country = await findCountryById(selectedCountry);
      if (!country) {
        return res.status(404).json({ error: 'Selected country not found' });
      }
      
      if (country.owner) {
        return res.status(400).json({ error: 'Selected country is already owned' });
      }
      
      // Check if user balance would go below -200 after purchase
      const newBalance = user.coins - country.cost;
      if (newBalance < -200) {
        return res.status(400).json({ 
          error: `Cannot borrow - purchase would make balance ${newBalance} which is below the -200 limit` 
        });
      }
      
      // Remove card from inventory
      await removeFromUserInventory(req.user.id, cardId);
      
      // Calculate new balance and score
      const finalCoins = newBalance;
      const newScore = user.score + country.score;
      const userId = user.id || user._id;
      
      // Calculate new mining rate after buying the country
      const currentCountries = await getAllCountries();
      const ownedCountries = currentCountries.filter(c => c.owner === userId);
      const newMiningRate = ownedCountries.reduce((sum, c) => sum + (c.miningRate || 0), 0) + (country.miningRate || 0);
      
      // Update user with new coins, score, and mining rate
      await updateUserById(req.user.id, { 
        coins: finalCoins, 
        score: newScore,
        miningRate: newMiningRate
      });
      
      // Update country with ownership and mining start time
      await updateCountryById(selectedCountry, { 
        owner: userId,
        lastMined: new Date().toISOString()
      });
      
      // Emit user-update for this user with mining rate
      io.to(userId).emit('user-update', {
        id: userId,
        teamName: user.teamName,
        coins: finalCoins,
        score: newScore,
        miningRate: newMiningRate
      });
      
      // Create notification for the country purchase
      const purchaseNotification = {
        id: Date.now().toString(),
        userId: userId,
        type: 'country-purchased',
        message: `You purchased ${country.name} for ${country.cost} coins using the Borrow card! New balance: ${finalCoins} coins`,
        timestamp: new Date().toISOString(),
        read: false,
        recipientType: 'user'
      };
      await addNotification(purchaseNotification);
      io.to(userId).emit('notification', purchaseNotification);
      
      // Create admin notification
      const adminNotification = {
        id: (Date.now() + 1).toString(),
        type: 'card-used',
        message: `Team ${user.teamName} used Borrow card to purchase ${country.name} for ${country.cost} coins. New balance: ${finalCoins} coins`,
        teamId: req.user.id,
        teamName: user.teamName,
        cardName: card.name,
        cardType: card.type,
        selectedCountry: country.name,
        description: `Purchased ${country.name} for ${country.cost} coins`,
        timestamp: new Date().toISOString(),
        read: false,
        recipientType: 'admin'
      };
      await addNotification(adminNotification);
      io.emit('admin-notification', adminNotification);
      
      // Emit countries update with filtered countries
      const allCountries = await getAllCountries();
      const filteredCountries = getFilteredCountries(allCountries);
      io.emit('countries-update', filteredCountries);
      
      // Notify user that inventory has been updated
      io.to(req.user.id).emit('inventory-update');
      io.emit('inventory-update');
      
      // Emit scoreboard update to refresh all users' data
      const updatedUsers = await getAllUsers();
      io.emit('scoreboard-update', updatedUsers);
      
      return res.json({ 
        success: true,
        message: 'Country purchased successfully with borrowed coins!',
        purchasedCountry: country,
        newBalance: finalCoins,
        newScore: newScore
      });
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
    console.log('🎰 === SPIN REQUEST START ===');
    console.log('🎰 Spin request received:', { spinType, promoCode, userId: req.user.id });
    console.log('🎰 User from token:', JSON.stringify(req.user, null, 2));
    
    const user = await findUserById(req.user.id);
    
    // Check team spin limitations
    const teamSettings = user.teamSettings || {};
    const spinLimitations = teamSettings.spinLimitations || {};
    const spinCounts = teamSettings.spinCounts || { regular: 0, lucky: 0, special: 0 };
    
    // Map spin types to limitation categories
    const spinCategory = spinType === 'lucky' ? 'lucky' : 
                        spinType === 'gamehelper' ? 'gamehelper' :
                        spinType === 'challenge' ? 'challenge' :
                        spinType === 'hightier' ? 'hightier' :
                        spinType === 'lowtier' ? 'lowtier' :
                        spinType === 'random' ? 'random' : 'lucky';
    
    const limitation = spinLimitations[spinCategory];
    if (limitation && limitation.enabled && limitation.limit > 0) {
      const currentCount = spinCounts[spinCategory] || 0;
      
      // Check if user has reached the limit for this spin type
      if (currentCount >= limitation.limit) {
        console.log(`❌ User ${user.teamName} has reached limit for ${spinCategory} spins (${currentCount}/${limitation.limit})`);
        return res.status(400).json({ 
          error: `Spin limit reached for ${spinCategory} spins. You have used ${currentCount}/${limitation.limit} spins.` 
        });
      }
    }
    
    // Set costs for new spin types
    let cost = 50;
    switch(spinType) {
      case 'lucky': cost = 50; break;
          case 'gamehelper': cost = 50; break;
    case 'challenge': cost = 50; break;
    case 'hightier': cost = 50; break;
    case 'lowtier': cost = 50; break;
      case 'random': cost = 30; break;
      default: cost = 50;
    }

    // Check promo code
    if (promoCode) {
      const promo = await findPromoCode(promoCode, req.user.id);
      if (promo) {
        const originalCost = cost;
        cost = Math.floor(cost * (1 - promo.discount / 100));
        await markPromoCodeAsUsed(promoCode, req.user.id);
        
        // Send admin notification when promocode is used
        const adminNotification = {
          id: Date.now().toString(),
          userId: null, // Admin notification
          type: 'admin-action',
          actionType: 'promo-code-used',
          message: `Team ${user.teamName} used promo code "${promoCode}" (${promo.discount}% discount, saved ${originalCost - cost} coins)`,
          timestamp: new Date().toISOString(),
          read: false,
          recipientType: 'admin',
          metadata: {
            teamId: req.user.id,
            teamName: user.teamName,
            promoCode: promoCode,
            discount: promo.discount,
            originalCost: originalCost,
            finalCost: cost,
            savedAmount: originalCost - cost,
            spinType: spinType
          }
        };
        
        await addNotification(adminNotification);
        // Emit to all admin clients
        io.emit('admin-notification', adminNotification);
        
        console.log(`💳 Promo code "${promoCode}" used by team ${user.teamName}, saved ${originalCost - cost} coins`);
      }
    }

    if (user.coins < cost) {
      return res.status(400).json({ error: 'Insufficient coins' });
    }

    const newCoins = user.coins - cost;
    await updateUserById(req.user.id, { coins: newCoins });

    // Get all available cards for this spin type
    const allCards = getCardsByType(spinType);
    
    // Special handling for random spin type - no unique card collection
    if (spinType === 'random') {
      console.log(`🎲 Random spin - no unique card collection tracking`);
      randomCard = allCards[Math.floor(Math.random() * allCards.length)];
      cardPoolReset = false;
    } else {
      // Get user's received cards tracking (initialize if not exists)
      const receivedCards = teamSettings.receivedCards || {};
      const receivedCardsForType = receivedCards[spinType] || [];
      
      console.log(`🎴 Card collection for ${spinType}:`);
      console.log(`🎴   - Total available cards: ${allCards.length}`);
      console.log(`🎴   - Already received: ${receivedCardsForType.length}`);
      console.log(`🎴   - Received card names:`, receivedCardsForType);
      
      // Filter out already received cards
      const availableCards = allCards.filter(card => 
        !receivedCardsForType.includes(card.name)
      );
      
      console.log(`🎴   - Available cards: ${availableCards.length}`);
      console.log(`🎴   - Available card names:`, availableCards.map(card => card.name));
      
      // If no available cards (all have been received), reset the pool
      if (availableCards.length === 0) {
        console.log(`🔄 All cards for ${spinType} have been collected! Resetting card pool.`);
        cardPoolReset = true;
        randomCard = allCards[Math.floor(Math.random() * allCards.length)];
        
        // Reset received cards for this spin type
        receivedCards[spinType] = [];
        receivedCardsForType.length = 0;
      } else {
        // Select from available cards
        randomCard = availableCards[Math.floor(Math.random() * availableCards.length)];
      }
      
      // Add the selected card to received cards (unless it's a pool reset)
      if (!cardPoolReset) {
        receivedCardsForType.push(randomCard.name);
        receivedCards[spinType] = receivedCardsForType;
      }
    }
    
    console.log(`🎴 Selected card: ${randomCard.name}`);
    console.log(`🎴 Card pool reset: ${cardPoolReset}`);

    let finalCoins = newCoins;
    let isInstantAction = false;
    let additionalData = {};

    // Handle different action types
    switch(randomCard.actionType) {
      case 'instant':
        // Instant coin changes
        const coinChange = randomCard.coinChange || 0;
        finalCoins = newCoins + coinChange;
        await updateUserById(req.user.id, { coins: finalCoins });
        isInstantAction = true;
        
        // Send notification for significant coin changes (especially negative ones)
        if (coinChange !== 0) {
          const coinChangeNotification = {
            id: Date.now().toString(),
            userId: req.user.id,
            type: coinChange > 0 ? 'coins-gained' : 'coins-lost',
            message: coinChange > 0 
              ? `You gained ${coinChange} coins instantly!`
              : `You lost ${Math.abs(coinChange)} coins instantly!`,
            timestamp: new Date().toISOString(),
            read: false,
            recipientType: 'user'
          };
          await addNotification(coinChangeNotification);
          
          // Send socket notification to the user
          io.to(req.user.id).emit('notification', coinChangeNotification);
          
          console.log(`💰 ${user.teamName} ${coinChange > 0 ? 'gained' : 'lost'} ${Math.abs(coinChange)} coins instantly`);
        }
        break;

      case 'instant_tax':
        // Pay 10 coins per owned country
        const ownedCountries = await getOwnedCountriesCount(req.user.id);
        const taxAmount = ownedCountries * 2;
        finalCoins = newCoins - taxAmount;
        await updateUserById(req.user.id, { coins: finalCoins });
        isInstantAction = true;
        additionalData.taxAmount = taxAmount;
        additionalData.ownedCountries = ownedCountries;
        
        // Send notification to user about the tax payment
        const taxNotification = {
          id: Date.now().toString(),
          userId: req.user.id,
          type: 'tax-paid',
          message: `You paid ${taxAmount} coins in border tax for ${ownedCountries} countries you own.`,
          timestamp: new Date().toISOString(),
          read: false,
          recipientType: 'user'
        };
        await addNotification(taxNotification);
        
        // Send socket notification to the user
        io.to(req.user.id).emit('notification', taxNotification);
        
        console.log(`💰 ${user.teamName} paid ${taxAmount} coins in border tax for ${ownedCountries} countries`);
        break;

      case 'random_gift':
        // Give 50 coins to random team (exclude admins and the team who spun)
        const allUsers = await getAllUsers();
        const eligibleUsers = allUsers.filter(u => 
          u.id !== req.user.id && // Exclude the team who spun
          u.role !== 'admin' // Exclude admins
        );
        
        if (eligibleUsers.length > 0) {
          const randomUser = eligibleUsers[Math.floor(Math.random() * eligibleUsers.length)];
          await updateUserById(randomUser.id, { coins: randomUser.coins + 50 });
          
          // Send notification to the team that received the coins
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
          
          // Send socket notification to the team that received the coins
          io.to(randomUser.id).emit('notification', giftNotification);
          
          // Also send user-update to refresh their coin count in real-time
          io.to(randomUser.id).emit('user-update', {
            id: randomUser.id,
            teamName: randomUser.teamName,
            coins: randomUser.coins + 50,
            score: randomUser.score
          });
          
          additionalData.giftedTeam = randomUser.teamName;
          console.log(`🎁 ${user.teamName} gave 50 coins to ${randomUser.teamName} via spin`);
        } else {
          console.log(`🎁 No eligible teams found for random gift (all teams are admins or only the spinning team exists)`);
          additionalData.giftedTeam = null;
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
        isInstantAction = true;
        break;

      case 'mcq':
        // Load random question for MCQ
        const fs = require('fs');
        const questions = JSON.parse(fs.readFileSync('./spiritual-questions.json', 'utf8'));
        const randomQuestion = questions.questions[Math.floor(Math.random() * questions.questions.length)];
        additionalData.question = randomQuestion;
        additionalData.timeLimit = 13; // 13 seconds
        isInstantAction = true;
        break;

      case 'random_category':
        // This is handled by the getCardsByType function for random spin type
        // The card should be treated as an admin card since it's a special action
        isInstantAction = false;
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
        requiresGameSelection: randomCard.requiresGameSelection,
        requiresTeamSelection: randomCard.requiresTeamSelection,
        maxGame: randomCard.maxGame,
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

    // Update spin counts and check for reset after EVERY spin
    const currentUser = await findUserById(req.user.id);
    const currentSpinCounts = currentUser.teamSettings?.spinCounts || { lucky: 0, gamehelper: 0, challenge: 0, hightier: 0, lowtier: 0, random: 0 };
    
    const updatedSpinCounts = { ...currentSpinCounts };
    
    // Update the count for the current spin category (if it has a limitation)
    if (limitation && limitation.enabled) {
      updatedSpinCounts[spinCategory] = (updatedSpinCounts[spinCategory] || 0) + 1;
      console.log(`🔄 Updating spin count for ${spinCategory}: ${currentSpinCounts[spinCategory] || 0} -> ${updatedSpinCounts[spinCategory]}`);
    }
    
    // Check if ALL ENABLED spin types have reached their limits (according to admin settings)
    // Explicitly exclude 'regular' spin type as requested by user
    const enabledSpinTypes = Object.entries(spinLimitations)
      .filter(([type, lim]) => lim.enabled && lim.limit > 0 && type !== 'regular')
      .map(([type]) => type);
    
    const completedSpinTypes = enabledSpinTypes.filter(type => {
      const limitation = spinLimitations[type];
      const count = updatedSpinCounts[type] || 0;
      const limit = limitation?.limit || 1;
      return count >= limit;
    });
    
    console.log(`🔄 Spin completion check for ${user.teamName} after spin:`);
    console.log(`🔄   - Enabled spin types: ${enabledSpinTypes.join(', ')} (${enabledSpinTypes.length} total)`);
    console.log(`🔄   - Completed spin types: ${completedSpinTypes.join(', ')} (${completedSpinTypes.length} total)`);
    console.log(`🔄   - Current spin counts:`, updatedSpinCounts);
    console.log(`🔄   - Spin limitations:`, spinLimitations);
    console.log(`🔄   - All completed check: ${enabledSpinTypes.length > 0 && completedSpinTypes.length === enabledSpinTypes.length}`);
    console.log(`🔄   - Should reset: ${enabledSpinTypes.length > 0 && completedSpinTypes.length === enabledSpinTypes.length ? 'YES' : 'NO'}`);
    
    // Debug: Check each enabled spin type individually
    enabledSpinTypes.forEach(type => {
      const count = updatedSpinCounts[type] || 0;
      const limit = spinLimitations[type]?.limit || 1;
      const isCompleted = count >= limit;
      console.log(`🔍 DEBUG ${type}: ${count}/${limit} - ${isCompleted ? 'COMPLETED' : 'NOT COMPLETED'}`);
    });
    
    let finalTeamSettings;
    
    // ALWAYS send spin limitation status to frontend for real-time checking
    if (io) {
      const spinStatusData = {
        userId: req.user.id,
        enabledSpinTypes,
        completedSpinTypes,
        currentSpinCounts: updatedSpinCounts,
        spinLimitations,
        allCompleted: enabledSpinTypes.length > 0 && completedSpinTypes.length === enabledSpinTypes.length,
        shouldReset: enabledSpinTypes.length > 0 && completedSpinTypes.length === enabledSpinTypes.length
      };
      
      console.log(`📡 Sending spin limitation status to frontend:`, spinStatusData);
      
      // Send to specific user
      io.to(req.user.id).emit('spin-limitation-status', spinStatusData);
      
      // Also broadcast to all clients
      io.emit('spin-limitation-status', spinStatusData);
    }
    
    // Only reset if ALL enabled spin types have been completed AND there are enabled spin types
    // This prevents resetting when no limitations are set or when only some spin types are completed
    if (enabledSpinTypes.length > 0 && completedSpinTypes.length === enabledSpinTypes.length) {
      console.log(`🎉 User ${user.teamName} has completed ALL enabled spin types! Resetting counts.`);
      console.log(`🎉   - All ${enabledSpinTypes.length} enabled spin types completed`);
      console.log(`🎉   - Resetting all spin counts to 0`);
      
      finalTeamSettings = {
        ...currentUser.teamSettings,
        spinCounts: {
          lucky: 0,
          gamehelper: 0,
          challenge: 0,
          hightier: 0,
          lowtier: 0,
          random: 0
        }
      };
      
      // Send notification to user that their spins have been reset
      if (io) {
        console.log(`📡 Emitting spin-counts-reset socket event to user ${req.user.id}`);
        
        // Send simple notification to the user
        io.to(req.user.id).emit('spin-counts-reset', { 
          userId: req.user.id,
          message: `Limit Reseted`
        });
        
        console.log(`📡 Spin reset socket event emitted successfully`);
      } else {
        console.log(`❌ Socket.io not available for spin reset notification`);
      }
    } else {
      // Just update with the new count
      finalTeamSettings = {
        ...currentUser.teamSettings,
        spinCounts: updatedSpinCounts
      };
    }
    
    // Update team settings with received cards tracking (only for non-random spins)
    if (spinType !== 'random') {
      finalTeamSettings.receivedCards = receivedCards;
    }
    
    await updateUserById(req.user.id, { teamSettings: finalTeamSettings });
    
    // Send updated team settings to the user
    if (io) {
      io.emit('user-team-settings-updated', {
        userId: req.user.id,
        teamSettings: finalTeamSettings
      });
    }
    


    // Emit scoreboard update
    const updatedUsers = await getAllUsers();
    io.emit('scoreboard-update', updatedUsers);

    res.json({ 
      card: randomCard,
      cost,
      remainingCoins: finalCoins,
      actionType: randomCard.actionType,
      additionalData,
      cardPoolReset,
      receivedCardsCount: spinType === 'random' ? 0 : (receivedCardsForType?.length || 0),
      totalCardsForType: spinType === 'random' ? 0 : allCards.length
    });

    console.log('🎰 === SPIN REQUEST END ===');
  } catch (error) {
    console.error('❌ Spin error:', error);
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

// Get all promocodes (admin only)
app.get('/api/admin/promocodes', authenticateToken, requireAdmin, async (req, res) => {
  try {
    let allPromocodes = [];
    if (mongoConnected && db) {
      allPromocodes = await db.collection('promoCodes').find({}).toArray();
    } else {
      allPromocodes = promoCodes;
    }
    
    // Get team names for each promocode
    const promocodesWithTeamNames = await Promise.all(
      allPromocodes.map(async (promo) => {
        let teamName = 'Unassigned';
        if (promo.teamId) {
          const user = await findUserById(promo.teamId);
          if (user) {
            teamName = user.teamName;
          }
        }
        return {
          ...promo,
          teamName
        };
      })
    );
    
    res.json(promocodesWithTeamNames);
  } catch (error) {
    console.error('Get promocodes error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create new promocode
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

// Update promocode (assign to team, change percentage, etc.)
app.put('/api/admin/promocodes/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { teamId, discount, used } = req.body;
    const adminUser = await findUserById(req.user.id);
    
    // Validate discount if provided
    if (discount !== undefined && (!Number.isInteger(discount) || discount < 1 || discount > 100)) {
      return res.status(400).json({ error: 'Discount must be an integer between 1 and 100.' });
    }
    
    let updateData = {};
    if (teamId !== undefined) updateData.teamId = teamId;
    if (discount !== undefined) updateData.discount = discount;
    if (used !== undefined) {
      updateData.used = used;
      if (used) {
        updateData.usedAt = new Date().toISOString();
      }
    }
    
    let updatedPromo = null;
    if (mongoConnected && db) {
      const result = await db.collection('promoCodes').updateOne(
        { id },
        { $set: updateData }
      );
      if (result.modifiedCount > 0) {
        updatedPromo = await db.collection('promoCodes').findOne({ id });
      }
    } else {
      const promoIndex = promoCodes.findIndex(p => p.id === id);
      if (promoIndex !== -1) {
        promoCodes[promoIndex] = { ...promoCodes[promoIndex], ...updateData };
        updatedPromo = promoCodes[promoIndex];
      }
    }
    
    if (!updatedPromo) {
      return res.status(404).json({ error: 'Promocode not found' });
    }
    
    // If assigning to a team, send notification
    if (teamId && teamId !== updatedPromo.teamId) {
      const user = await findUserById(teamId);
      if (user) {
        const teamNotification = {
          id: Date.now().toString(),
          userId: teamId,
          type: 'promo-code',
          message: `You received a promo code: ${updatedPromo.code} with ${updatedPromo.discount}% discount!`,
          timestamp: new Date().toISOString(),
          read: false,
          recipientType: 'user'
        };
        await addNotification(teamNotification);
        io.to(teamId).emit('notification', teamNotification);
        
        // Create admin action notification
        const adminAction = {
          id: (Date.now() + 1).toString(),
          userId: req.user.id,
          type: 'admin-action',
          actionType: 'promo-code-assigned',
          message: `Admin ${adminUser.teamName} assigned promo code (${updatedPromo.code}) to team ${user.teamName}.`,
          timestamp: new Date().toISOString(),
          read: false,
          recipientType: 'admin',
          metadata: {
            targetTeamId: teamId,
            targetTeamName: user.teamName,
            promoCode: updatedPromo.code,
            discount: updatedPromo.discount
          }
        };
        
        await addNotification(adminAction);
        io.emit('admin-notification', adminAction);
      }
    }
    
    res.json(updatedPromo);
  } catch (error) {
    console.error('Update promocode error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Initialize promocodes with the provided list
app.post('/api/admin/promocodes/initialize', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const adminUser = await findUserById(req.user.id);
    
    // List of promocodes to initialize
    const promocodesToAdd = [
      'GD85CRTZJ', 'SUJUKCFUP', 'KLMNOPQR', 'STUVWXYZ', 'ABCDEFGH',
      'IJKLMNOP', 'QRSTUVWX', 'YZABCDEF', 'GHIJKLMN', 'OPQRSTUV',
      'WXYZABCD', 'EFGHIJKL', 'MNOPQRST', 'UVWXYZAB', 'CDEFGHIJ'
    ];
    
    const addedPromocodes = [];
    
    for (const code of promocodesToAdd) {
      // Check if promocode already exists
      let existingPromo = null;
      if (mongoConnected && db) {
        existingPromo = await db.collection('promoCodes').findOne({ code });
      } else {
        existingPromo = promoCodes.find(p => p.code === code);
      }
      
      if (!existingPromo) {
        const promoCode = {
          id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
          code,
          teamId: null, // Initially unassigned
          discount: 10, // Default 10% discount
          used: false,
          createdAt: new Date().toISOString(),
          createdBy: req.user.id
        };
        
        await addPromoCode(promoCode);
        addedPromocodes.push(promoCode);
      }
    }
    
    // Create admin action notification
    const adminAction = {
      id: Date.now().toString(),
      userId: req.user.id,
      type: 'admin-action',
      actionType: 'promocodes-initialized',
      message: `Admin ${adminUser.teamName} initialized ${addedPromocodes.length} promocodes.`,
      timestamp: new Date().toISOString(),
      read: false,
      recipientType: 'admin',
      metadata: {
        promocodesCount: addedPromocodes.length
      }
    };
    
    await addNotification(adminAction);
    io.emit('admin-notification', adminAction);
    
    res.json({ 
      message: `Initialized ${addedPromocodes.length} promocodes`,
      addedPromocodes 
    });
  } catch (error) {
    console.error('Initialize promocodes error:', error);
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

    // Find the card definition to get its properties
    let cardDefinition = null;
    try {
      const cardsList = getCardsByType(cardType === 'random' ? 'lucky' : cardType);
      cardDefinition = cardsList.find(c => c.name === cardName);
    } catch (e) {
      console.error('Error finding card definition:', e);
    }

    const card = {
      id: Date.now().toString(),
      name: cardName,
      type: cardType,
      effect: cardDefinition ? cardDefinition.effect : '',
      requiresGameSelection: cardDefinition ? cardDefinition.requiresGameSelection : false,
      requiresTeamSelection: cardDefinition ? cardDefinition.requiresTeamSelection : false,
      maxGame: cardDefinition ? cardDefinition.maxGame : null,
      obtainedAt: new Date().toISOString()
    };

    await addToUserInventory(teamId, card);

    // Get the effect from the card definition we already found
    const effect = cardDefinition ? cardDefinition.effect : '';

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

// Test endpoint to check if admin routes are accessible
app.get('/api/admin-test', (req, res) => {
  console.log('🧪 Admin test endpoint called');
  res.json({ 
    message: 'Admin test endpoint works!', 
    timestamp: new Date().toISOString(),
    gameSettings: gameSettings,
    note: 'This endpoint tests if admin routes are accessible'
  });
});

// Simple admin test endpoint (no authentication required)
app.get('/api/admin/test-public', (req, res) => {
  console.log('🔧 Public admin test endpoint called');
  res.json({ 
    message: 'Public admin endpoint works!', 
    timestamp: new Date().toISOString(),
    gameSettings: gameSettings,
    note: 'This endpoint does not require authentication'
  });
});

// Debug endpoint to list all registered routes
app.get('/api/debug/routes', (req, res) => {
  console.log('🔍 Debug routes endpoint called');
  const routes = [];
  
  app._router.stack.forEach((middleware) => {
    if (middleware.route) {
      // Routes registered directly on the app
      const path = middleware.route.path;
      const methods = Object.keys(middleware.route.methods);
      routes.push({ path, methods });
    } else if (middleware.name === 'router') {
      // Router middleware
      middleware.handle.stack.forEach((handler) => {
        if (handler.route) {
          const path = handler.route.path;
          const methods = Object.keys(handler.route.methods);
          routes.push({ path, methods });
        }
      });
    }
  });
  
  res.json({
    message: 'Available routes',
    routes: routes.filter(route => route.path.startsWith('/api/')),
    totalRoutes: routes.length,
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
    
    // Enhanced admin check
    const isAdmin = user.role === 'admin' || 
                   user.role === 'ADMIN' || 
                   user.role === 'Admin' ||
                   user.username === 'ayman' ||
                   user.username === 'admin' ||
                   user.username === 'Admin';
    
    res.json({
      success: true,
      user: {
        id: user.id || user._id,
        username: user.username,
        role: user.role,
        teamName: user.teamName,
        isAdmin: isAdmin,
        roleType: typeof user.role,
        roleLength: user.role ? user.role.length : 'undefined'
      },
      adminChecks: {
        roleCheck: user.role === 'admin',
        usernameCheck: user.username === 'ayman',
        combinedCheck: isAdmin
      }
    });
  } catch (error) {
    console.error('Admin test error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Simple admin test endpoint (no authentication required)
app.get('/api/debug/admin-test-simple', async (req, res) => {
  try {
    console.log('🔧 Simple admin test endpoint called');
    
    // Get all users and check their admin status
    const allUsers = await getAllUsers();
    const adminUsers = allUsers.filter(user => {
      const isAdmin = user.role === 'admin' || 
                     user.role === 'ADMIN' || 
                     user.role === 'Admin' ||
                     user.username === 'ayman' ||
                     user.username === 'admin' ||
                     user.username === 'Admin';
      return isAdmin;
    });
    
    res.json({
      message: 'Admin test endpoint works!',
      totalUsers: allUsers.length,
      adminUsers: adminUsers.map(user => ({
        id: user.id || user._id,
        username: user.username,
        role: user.role,
        roleType: typeof user.role,
        isAdmin: true
      })),
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('❌ Simple admin test error:', error);
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
      lastMined: user.lastMined,
      teamSettings: user.teamSettings || {
        scoreboardVisible: true,
        spinLimitations: {
          lucky: { enabled: true, limit: 1 },
          gamehelper: { enabled: true, limit: 1 },
          challenge: { enabled: true, limit: 1 },
          hightier: { enabled: true, limit: 1 },
          lowtier: { enabled: true, limit: 1 },
          random: { enabled: true, limit: 1 }
        },
        spinCounts: { lucky: 0, gamehelper: 0, challenge: 0, hightier: 0, lowtier: 0, random: 0 }
      }
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
  1: { enabled: true, name: 'Game 1' },
  2: { enabled: true, name: 'Game 2' },
  3: { enabled: true, name: 'Game 3' },
  4: { enabled: true, name: 'Game 4' },
  5: { enabled: true, name: 'Game 5' },
  6: { enabled: true, name: 'Game 6' },
  7: { enabled: true, name: 'Game 7' },
  8: { enabled: true, name: 'Game 8' },
  9: { enabled: true, name: 'Game 9' },
  10: { enabled: true, name: 'Game 10' },
  11: { enabled: true, name: 'Game 11' },
  12: { enabled: true, name: 'Game 12' },
  // Global settings
  fiftyCoinsCountriesHidden: false // Global setting for 50 coins countries visibility
};

// Load game settings from database
async function loadGameSettings() {
  if (!mongoConnected || !db) {
    console.log('📝 Using in-memory game settings');
    return;
  }

  try {
    const settings = await db.collection('gameSettings').findOne({ _id: 'games' });
    console.log('📝 Database settings found:', settings);
    if (settings && settings.games) {
      gameSettings = settings.games;
      console.log('✅ Game settings loaded from database:', gameSettings);
      
      // Ensure fiftyCoinsCountriesHidden setting exists
      if (typeof gameSettings.fiftyCoinsCountriesHidden === 'undefined') {
        gameSettings.fiftyCoinsCountriesHidden = false;
        await saveGameSettings();
        console.log('✅ Added missing fiftyCoinsCountriesHidden setting');
      }
      
      // Validate the loaded settings
      const availableGames = getAvailableGames();
      if (availableGames.length === 0) {
        console.warn('⚠️ Loaded game settings have no enabled games, resetting to defaults...');
        await resetGameSettings();
      }
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

// Reset game settings to defaults
async function resetGameSettings() {
  console.log('🔄 Resetting game settings to defaults...');
  gameSettings = {
    1: { enabled: true, name: 'Game 1' },
    2: { enabled: true, name: 'Game 2' },
    3: { enabled: true, name: 'Game 3' },
    4: { enabled: true, name: 'Game 4' },
    5: { enabled: true, name: 'Game 5' },
    6: { enabled: true, name: 'Game 6' },
    7: { enabled: true, name: 'Game 7' },
    8: { enabled: true, name: 'Game 8' },
    9: { enabled: true, name: 'Game 9' },
    10: { enabled: true, name: 'Game 10' },
    11: { enabled: true, name: 'Game 11' },
    12: { enabled: true, name: 'Game 12' },
    // Global settings
    fiftyCoinsCountriesHidden: false // Global setting for 50 coins countries visibility
  };
  await saveGameSettings();
  console.log('✅ Game settings reset to defaults');
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

// Migrate existing users to ensure they have teamSettings
async function migrateUserTeamSettings() {
  if (!mongoConnected || !db) return;

  try {
    const defaultTeamSettings = {
      scoreboardVisible: true,
      spinLimitations: {
        lucky: { enabled: true, limit: 1 },
        gamehelper: { enabled: true, limit: 1 },
        challenge: { enabled: true, limit: 1 },
        hightier: { enabled: true, limit: 1 },
        lowtier: { enabled: true, limit: 1 },
        random: { enabled: true, limit: 1 }
      },
      spinCounts: { lucky: 0, gamehelper: 0, challenge: 0, hightier: 0, lowtier: 0, random: 0 }
    };

    // Update users that don't have teamSettings
    const result = await db.collection('users').updateMany(
      { teamSettings: { $exists: false } },
      { $set: { teamSettings: defaultTeamSettings } }
    );
    
    if (result.modifiedCount > 0) {
      console.log(`✅ Migrated ${result.modifiedCount} users to include teamSettings`);
    }
  } catch (error) {
    console.error('❌ Error migrating user team settings:', error);
  }
}

// Global country visibility settings - admin can hide/show country ownership
let countryVisibilitySettings = {};

// Helper function to get available games
function getAvailableGames() {
  console.log('🎮 getAvailableGames called, gameSettings:', gameSettings);
  
  // Ensure gameSettings has the correct structure
  if (!gameSettings || typeof gameSettings !== 'object') {
    console.warn('🎮 Invalid gameSettings, using defaults');
    gameSettings = {
      1: { enabled: true, name: 'Game 1' },
      2: { enabled: true, name: 'Game 2' },
      3: { enabled: true, name: 'Game 3' },
      4: { enabled: true, name: 'Game 4' },
      5: { enabled: true, name: 'Game 5' },
      6: { enabled: true, name: 'Game 6' },
      7: { enabled: true, name: 'Game 7' },
      8: { enabled: true, name: 'Game 8' },
      9: { enabled: true, name: 'Game 9' },
      10: { enabled: true, name: 'Game 10' },
      11: { enabled: true, name: 'Game 11' },
      12: { enabled: true, name: 'Game 12' }
    };
  }
  
  const availableGames = Object.keys(gameSettings)
    .filter(gameId => gameSettings[gameId] && gameSettings[gameId].enabled)
    .map(gameId => gameId); // Return just the game IDs as strings
  console.log('🎮 getAvailableGames result:', availableGames);
  return availableGames;
}

// Helper function to get cards by type
function getCardsByType(spinType) {
  const cards = {
    lucky: [
      { name: "-20 Coins Instantly", type: 'lucky', effect: '', actionType: 'instant', coinChange: -20 },
      { name: "+100 Coins Instantly", type: 'lucky', effect: '', actionType: 'instant', coinChange: 100 },
      { name: "Borrow coins to buy a country", type: 'lucky', effect: 'Balance may go negative, limit -200', actionType: 'admin', requiresTeamSelection: false },
      { name: "Pay 2 coins as border tax", type: 'lucky', effect: 'Pay 2 coins for each country you own', actionType: 'instant_tax' },
      { name: "Game Protection", type: 'lucky', effect: 'Protection for selected game', actionType: 'admin', requiresGameSelection: true },
      { name: "+50 Coins to random team", type: 'lucky', effect: '+50 coins given to another random team', actionType: 'random_gift' }
    ],
    gamehelper: [
      { name: "Secret Info", type: 'gamehelper', effect: 'Choose game: Instantly reveals opponent & game details', actionType: 'admin', requiresGameSelection: true },
      { name: "Robin Hood", type: 'gamehelper', effect: 'Choose game & team: Steal 100 coins from them, If they won', actionType: 'admin', requiresGameSelection: true, requiresTeamSelection: true },
      { name: "Avenger", type: 'gamehelper', effect: 'Choose game & team: Alliance proposal (+100 each if accepted)', actionType: 'admin', requiresGameSelection: true, requiresTeamSelection: true },
      { name: "Betrayal", type: 'gamehelper', effect: 'Choose game: Counter alliance betrayals (+100 if betrayed & win)', actionType: 'admin', requiresGameSelection: true }
    ],
    challenge: [
      { name: "Speed Buy", type: 'challenge', effect: '10 minutes to buy a country (+50 reward)', actionType: 'speed_buy' },
      { name: "Freeze Player", type: 'challenge', effect: 'Choose game: Judger decides: Freeze one player from your team (+75 coins to you)', actionType: 'admin', requiresGameSelection: true},
      { name: "Mystery Question", type: 'challenge', effect: 'Spiritual MCQ: 13sec timer (+100 correct, no penalty wrong)', actionType: 'mcq', isInstantChallenge: true },
      { name: "Silent Game", type: 'challenge', effect: 'Choose game: Judge decides result (+150 or -100)', actionType: 'admin', requiresGameSelection: true }
    ],
    hightier: [
      { name: "+75 Coins Instantly", type: 'hightier', effect: '+75 coins instantly', actionType: 'instant', coinChange: 75 },
      { name: "Flip the Fate", type: 'hightier', effect: 'Choose game: If tied → +100 Bonus, If lost → -50 Penalty', actionType: 'admin', requiresGameSelection: true},
      { name: "-20 Coins Instantly", type: 'hightier', effect: '-20 coins instantly', actionType: 'instant', coinChange: -20 }
    ],
    lowtier: [
      { name: "+100 Coins Instantly", type: 'lowtier', effect: '+100 coins instantly', actionType: 'instant', coinChange: 100 },
      { name: "-10 Coins Instantly", type: 'lowtier', effect: '-10 coins instantly', actionType: 'instant', coinChange: -10 },
      { name: "Victory Multiplier", type: 'lowtier', effect: 'Choose a game: If your team wins, you earn x1.5 coins', actionType: 'admin', requiresGameSelection: true}
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

  // Send current global 50 coins visibility state to new connections
  socket.emit('fifty-coins-countries-visibility-update', { hidden: gameSettings.fiftyCoinsCountriesHidden });

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
  console.log('🏥 Health check endpoint called');
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    mongoConnected,
    environment: process.env.NODE_ENV || 'development',
    gameSettings: gameSettings
  });
});

// Simple root endpoint test
app.get('/', (req, res) => {
  console.log('🏠 Root endpoint called');
  res.json({ 
    message: 'Server is running!', 
    timestamp: new Date().toISOString(),
    status: 'ok'
  });
});

// Serve static files in production
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, '../client/build')));
  
  // Only serve index.html for non-API routes
  app.get('*', (req, res, next) => {
    // Skip API routes
    if (req.path.startsWith('/api/')) {
      return next();
    }
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
    console.log('🔍 MCQ: Answer endpoint called');
    console.log('🔍 MCQ: Request body:', req.body);
    console.log('🔍 MCQ: User:', req.user);
    
    const { questionId, answer } = req.body;
    
    if (!questionId || answer === undefined) {
      console.error('❌ MCQ: Missing questionId or answer');
      return res.status(400).json({ error: 'Missing questionId or answer' });
    }
    
    const user = await findUserById(req.user.id);
    if (!user) {
      console.error('❌ MCQ: User not found');
      return res.status(404).json({ error: 'User not found' });
    }
    
    console.log('🔍 MCQ: User found:', user.teamName);
    
    // Load questions and verify answer
    const fs = require('fs');
    const questions = JSON.parse(fs.readFileSync('./spiritual-questions.json', 'utf8'));
    const question = questions.questions.find(q => q.id === questionId);
    
    console.log('🔍 MCQ: Looking for question ID:', questionId);
    console.log('🔍 MCQ: Available question IDs:', questions.questions.map(q => q.id));
    
    if (!question) {
      console.error('❌ MCQ: Question not found for ID:', questionId);
      return res.status(404).json({ error: 'Question not found' });
    }
    
    console.log('🔍 MCQ: Question found:', question.question);
    console.log('🔍 MCQ: User answer:', answer);
    console.log('🔍 MCQ: Correct answer:', question.correct);
    
    const isCorrect = answer === question.correct;
    let rewardCoins = isCorrect ? 100 : 0; // No penalty for wrong answers, +100 for correct
    
    console.log('🔍 MCQ: Is correct:', isCorrect);
    console.log('🔍 MCQ: Reward coins:', rewardCoins);
    
    const newCoins = user.coins + rewardCoins;
    await updateUserById(req.user.id, { coins: newCoins });
    
    console.log('🔍 MCQ: Updated user coins:', user.coins, '->', newCoins);
    
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
        ? `Correct answer! You earned ${rewardCoins} coins!`
        : `Wrong answer! No penalty - try again next time.`,
      timestamp: new Date().toISOString(),
      read: false,
      recipientType: 'user'
    };
    await addNotification(notification);
    io.to(req.user.id).emit('notification', notification);
    
    // Update scoreboard
    const updatedUsers = await getAllUsers();
    io.emit('scoreboard-update', updatedUsers);
    
    console.log('✅ MCQ: Answer processed successfully');
    
    res.json({ 
      correct: isCorrect, 
      reward: rewardCoins,
      correctAnswer: question.correct
    });
  } catch (error) {
    console.error('❌ MCQ: Answer error:', error);
    console.error('❌ MCQ: Error stack:', error.stack);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin toggle games endpoint
app.post('/api/admin/games/toggle', authenticateToken, requireAdmin, async (req, res) => {
  try {
    console.log('🎮 Toggle games endpoint called');
    console.log('🎮 Request body:', req.body);
    console.log('🎮 User:', req.user);
    
    const { gameId, enabled, gameName } = req.body;
    
    if (!gameId || typeof enabled !== 'boolean') {
      console.log('🎮 Invalid request:', { gameId, enabled });
      return res.status(400).json({ error: 'Invalid game ID or enabled status' });
    }
    
    console.log('🎮 Before toggle - gameSettings:', gameSettings);
    console.log('🎮 Toggling game', gameId, 'to', enabled, 'with name:', gameName);
    
    // Update game settings with proper structure
    if (!gameSettings[gameId]) {
      gameSettings[gameId] = { 
        enabled: enabled, 
        name: gameName || `Game ${gameId}` 
      };
    } else {
      gameSettings[gameId].enabled = enabled;
      if (gameName) {
        gameSettings[gameId].name = gameName;
      }
    }
    
    console.log('🎮 After toggle - gameSettings:', gameSettings);
    
    // Save to database
    await saveGameSettings();
    
    // Emit to all clients about game setting change
    io.emit('game-settings-update', gameSettings);
    
    console.log('🎮 Toggle successful, sending response');
    
    res.json({ 
      success: true, 
      gameId, 
      enabled, 
      gameName: gameSettings[gameId].name,
      gameSettings 
    });
  } catch (error) {
    console.error('Toggle game error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update game name
app.put('/api/admin/games/:gameId/name', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { gameId } = req.params;
    const { gameName } = req.body;
    
    if (!gameName || !gameName.trim()) {
      return res.status(400).json({ error: 'Game name is required' });
    }
    
    if (!gameSettings.hasOwnProperty(gameId)) {
      return res.status(400).json({ error: 'Invalid game ID' });
    }
    
    // Update the game name
    gameSettings[gameId].name = gameName.trim();
    
    // Save to database
    await saveGameSettings();
    
    console.log(`Game ${gameId} name updated to "${gameName.trim()}" by admin`);
    
    // Emit to all clients about game setting change
    io.emit('game-settings-update', gameSettings);
    
    res.json({ 
      success: true, 
      gameId,
      gameName: gameName.trim(),
      gameSettings,
      message: `Game ${gameId} name updated successfully` 
    });
  } catch (error) {
    console.error('Update game name error:', error);
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
    
    // Add new game (enabled by default) with custom name
    gameSettings[nextGameId] = { 
      enabled: true, 
      name: gameName.trim() 
    };
    
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

// Reset game settings to defaults
app.post('/api/admin/games/reset', authenticateToken, requireAdmin, async (req, res) => {
  try {
    console.log('🔄 Resetting game settings to defaults');
    
    // Reset to default settings with proper structure
    gameSettings = {
      1: { enabled: true, name: 'Game 1' },
      2: { enabled: true, name: 'Game 2' },
      3: { enabled: true, name: 'Game 3' },
      4: { enabled: true, name: 'Game 4' },
      5: { enabled: true, name: 'Game 5' },
      6: { enabled: true, name: 'Game 6' },
      7: { enabled: true, name: 'Game 7' },
      8: { enabled: true, name: 'Game 8' },
      9: { enabled: true, name: 'Game 9' },
      10: { enabled: true, name: 'Game 10' },
      11: { enabled: true, name: 'Game 11' },
      12: { enabled: true, name: 'Game 12' }
    };
    
    // Save to database
    await saveGameSettings();
    
    console.log('✅ Game settings reset to defaults');
    
    // Emit to all clients about game setting change
    io.emit('game-settings-update', gameSettings);
    
    res.json({ 
      success: true, 
      gameSettings,
      message: 'Game settings reset to defaults successfully' 
    });
  } catch (error) {
    console.error('Reset game settings error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get game settings (with authentication)
app.get('/api/admin/games', authenticateToken, requireAdmin, async (req, res) => {
  try {
    console.log('🎮 Admin games endpoint called');
    res.json(gameSettings);
  } catch (error) {
    console.error('Get game settings error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});




// Get available games for users (moved after admin routes to avoid conflicts)
app.get('/api/games/available', authenticateToken, async (req, res) => {
  try {
    console.log('🎮 Available games endpoint called');
    console.log('🎮 Current gameSettings:', gameSettings);
    const availableGames = getAvailableGames();
    console.log('🎮 Sending available games to frontend:', availableGames);
    res.json(availableGames);
  } catch (error) {
    console.error('Get available games error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Debug endpoint to check and reset game settings
app.get('/api/debug/game-settings', authenticateToken, requireAdmin, async (req, res) => {
  try {
    console.log('🔍 Debug game settings endpoint called');
    console.log('🔍 Current gameSettings:', gameSettings);
    
    const availableGames = getAvailableGames();
    console.log('🔍 Available games count:', availableGames.length);
    
    if (availableGames.length === 0) {
      console.log('🔍 No available games found, resetting to defaults...');
      await resetGameSettings();
      const newAvailableGames = getAvailableGames();
      res.json({
        message: 'Game settings reset to defaults',
        previousCount: 0,
        newCount: newAvailableGames.length,
        availableGames: newAvailableGames,
        gameSettings: gameSettings
      });
    } else {
      res.json({
        message: 'Game settings are correct',
        availableGamesCount: availableGames.length,
        availableGames: availableGames,
        gameSettings: gameSettings
      });
    }
  } catch (error) {
    console.error('Debug game settings error:', error);
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

// Admin get all teams with their settings
app.get('/api/admin/teams', authenticateToken, requireAdmin, async (req, res) => {
  try {
    console.log('👥 Admin teams endpoint called');
    const users = await getAllUsers();
    
    // Filter only user role (teams) and get their settings
    const teams = users
      .filter(user => user.role === 'user')
      .map(user => ({
        id: user.id || user._id,
        teamName: user.teamName,
        username: user.username,
        score: user.score,
        coins: user.coins,
        totalMined: user.totalMined,
        lastMined: user.lastMined,
        // Team settings (initialize with defaults if not exists)
        settings: user.teamSettings || {
          scoreboardVisible: true,
          spinLimitations: {
            lucky: { enabled: false, limit: 1 },
            gamehelper: { enabled: false, limit: 1 },
            challenge: { enabled: false, limit: 1 },
            hightier: { enabled: false, limit: 1 },
            lowtier: { enabled: false, limit: 1 },
            random: { enabled: false, limit: 1 }
          },
          spinCounts: {
            lucky: 0,
            gamehelper: 0,
            challenge: 0,
            hightier: 0,
            lowtier: 0,
            random: 0
          }
        }
      }));
    
    // Sort by score (highest first)
    teams.sort((a, b) => b.score - a.score);
    
    res.json(teams);
  } catch (error) {
    console.error('Get teams error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin update team settings
app.put('/api/admin/teams/:teamId/settings', authenticateToken, requireAdmin, async (req, res) => {
  try {
    console.log('⚙️ Admin update team settings endpoint called');
    const { teamId } = req.params;
    const { scoreboardVisible, spinLimitations, resetSpinCounts } = req.body;
    
    console.log('📝 Request body:', { teamId, scoreboardVisible, spinLimitations, resetSpinCounts });
    
    const user = await findUserById(teamId);
    if (!user) {
      console.log(`❌ Team not found: ${teamId}`);
      return res.status(404).json({ error: 'Team not found' });
    }
    
    console.log(`👤 Found team: ${user.teamName} (${teamId})`);
    
    // Initialize default settings if they don't exist
    const currentSettings = user.teamSettings || {
      scoreboardVisible: true,
      spinLimitations: {
        lucky: { enabled: false, limit: 1 },
        gamehelper: { enabled: false, limit: 1 },
        challenge: { enabled: false, limit: 1 },
        hightier: { enabled: false, limit: 1 },
        lowtier: { enabled: false, limit: 1 },
        random: { enabled: false, limit: 1 }
      },
      spinCounts: {
        lucky: 0,
        gamehelper: 0,
        challenge: 0,
        hightier: 0,
        lowtier: 0,
        random: 0
      }
    };
    
    // Update team settings
    const updatedSettings = {
      ...currentSettings,
      scoreboardVisible: scoreboardVisible !== undefined ? scoreboardVisible : currentSettings.scoreboardVisible,
      spinLimitations: spinLimitations || currentSettings.spinLimitations
    };
    
    // Reset spin counts if requested
    if (resetSpinCounts) {
      updatedSettings.spinCounts = {
        lucky: 0,
        gamehelper: 0,
        challenge: 0,
        hightier: 0,
        lowtier: 0,
        random: 0
      };
      
      // Send notification to user about spin count reset
      const resetNotification = {
        id: Date.now().toString(),
        userId: teamId,
        type: 'spin-counts-reset',
        message: 'Your spin counts have been reset by admin.',
        timestamp: new Date().toISOString(),
        read: false,
        recipientType: 'user'
      };
      await addNotification(resetNotification);
      
      // Send socket notification to the user
      io.to(teamId).emit('notification', resetNotification);
      
      console.log(`🔄 Admin reset spin counts for team ${user.teamName}`);
    } else {
      // Check if user has exceeded any new limits and handle accordingly
      const currentSpinCounts = currentSettings.spinCounts || { lucky: 0, gamehelper: 0, challenge: 0, hightier: 0, lowtier: 0, random: 0 };
      const newSpinLimitations = updatedSettings.spinLimitations;
      
      // Check if any spin type has exceeded the new limit
      let needsReset = false;
      const enabledSpinTypes = Object.entries(newSpinLimitations)
        .filter(([type, lim]) => lim.enabled && lim.limit > 0)
        .map(([type]) => type);
      
      const completedSpinTypes = enabledSpinTypes.filter(type => 
        (currentSpinCounts[type] || 0) >= (newSpinLimitations[type]?.limit || 1)
      );
      
      // If all enabled spin types are completed, reset all counts
      if (enabledSpinTypes.length > 0 && completedSpinTypes.length === enabledSpinTypes.length) {
        console.log(`🔄 User ${user.teamName} has completed all enabled spin types after limit change, resetting counts`);
        updatedSettings.spinCounts = {
          lucky: 0,
          gamehelper: 0,
          challenge: 0,
          hightier: 0,
          lowtier: 0,
          random: 0
        };
        needsReset = true;
      }
      
      if (needsReset) {
        console.log(`🔄 Reset spin counts for user ${user.teamName} due to limit changes`);
      }
    }
    
    console.log(`🔄 Updating team ${user.teamName} with settings:`, updatedSettings);
    
    await updateUserById(teamId, { teamSettings: updatedSettings });
    
    console.log(`✅ Successfully updated team ${user.teamName}`);
    
    // Emit socket event for real-time updates
    if (io) {
      io.emit('team-settings-updated', { teamId, settings: updatedSettings });
      // Also emit to the specific user if they're online
      io.emit('user-team-settings-updated', { 
        userId: teamId, 
        teamSettings: updatedSettings 
      });
      
      // Emit specific spin count reset event if counts were reset
      if (resetSpinCounts) {
        io.emit('spin-counts-reset', { 
          userId: teamId,
          teamName: user.teamName
        });
      }
    }
    
    res.json({ success: true, settings: updatedSettings });
  } catch (error) {
    console.error('❌ Update team settings error:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// Admin update all teams settings
app.put('/api/admin/teams/settings/all', authenticateToken, requireAdmin, async (req, res) => {
  try {
    console.log('⚙️ Admin update all teams settings endpoint called');
    const { scoreboardVisible, spinLimitations, resetSpinCounts } = req.body;
    
    console.log('📝 Request body:', { scoreboardVisible, spinLimitations, resetSpinCounts });
    
    const users = await getAllUsers();
    const teamUsers = users.filter(user => user.role === 'user');
    
    console.log(`👥 Found ${teamUsers.length} teams to update`);
    
    const updatePromises = teamUsers.map(async (user) => {
      try {
        // Initialize default settings if they don't exist
                 const currentSettings = user.teamSettings || {
           scoreboardVisible: true,
           spinLimitations: {
             lucky: { enabled: false, limit: 1 },
             gamehelper: { enabled: false, limit: 1 },
             challenge: { enabled: false, limit: 1 },
             hightier: { enabled: false, limit: 1 },
             lowtier: { enabled: false, limit: 1 },
             random: { enabled: false, limit: 1 }
           },
           spinCounts: {
             lucky: 0,
             gamehelper: 0,
             challenge: 0,
             hightier: 0,
             lowtier: 0,
             random: 0
           }
         };
        
        const updatedSettings = {
          ...currentSettings,
          scoreboardVisible: scoreboardVisible !== undefined ? scoreboardVisible : currentSettings.scoreboardVisible,
          spinLimitations: spinLimitations || currentSettings.spinLimitations
        };
        
        if (resetSpinCounts) {
          updatedSettings.spinCounts = {
            lucky: 0,
            gamehelper: 0,
            challenge: 0,
            hightier: 0,
            lowtier: 0,
            random: 0
          };
          
          // Send notification to user about spin count reset
          const resetNotification = {
            id: Date.now().toString(),
            userId: user.id || user._id,
            type: 'spin-counts-reset',
            message: 'Your spin counts have been reset by admin.',
            timestamp: new Date().toISOString(),
            read: false,
            recipientType: 'user'
          };
          await addNotification(resetNotification);
          
          // Send socket notification to the user
          io.to(user.id || user._id).emit('notification', resetNotification);
          
          console.log(`🔄 Admin reset spin counts for team ${user.teamName}`);
        } else {
          // Check if user has exceeded any new limits and handle accordingly
          const currentSpinCounts = currentSettings.spinCounts || { lucky: 0, gamehelper: 0, challenge: 0, hightier: 0, lowtier: 0, random: 0 };
          const newSpinLimitations = updatedSettings.spinLimitations;
          
          // Check if any spin type has exceeded the new limit
          let needsReset = false;
          const enabledSpinTypes = Object.entries(newSpinLimitations)
            .filter(([type, lim]) => lim.enabled && lim.limit > 0)
            .map(([type]) => type);
          
          const completedSpinTypes = enabledSpinTypes.filter(type => 
            (currentSpinCounts[type] || 0) >= (newSpinLimitations[type]?.limit || 1)
          );
          
          // Only reset if ALL enabled spin types have been completed AND there are enabled spin types
          // This prevents resetting when no limitations are set or when only some spin types are completed
          if (enabledSpinTypes.length > 0 && completedSpinTypes.length === enabledSpinTypes.length) {
            console.log(`🔄 User ${user.teamName} has completed all enabled spin types after limit change, resetting counts`);
            updatedSettings.spinCounts = {
              lucky: 0,
              gamehelper: 0,
              challenge: 0,
              hightier: 0,
              lowtier: 0,
              random: 0
            };
            needsReset = true;
          }
          
          if (needsReset) {
            console.log(`🔄 Reset spin counts for user ${user.teamName} due to limit changes`);
          }
        }
        
        console.log(`🔄 Updating team ${user.teamName} (${user.id || user._id}) with settings:`, updatedSettings);
        
        return await updateUserById(user.id || user._id, { teamSettings: updatedSettings });
      } catch (userError) {
        console.error(`❌ Error updating team ${user.teamName}:`, userError);
        throw userError;
      }
    });
    
    const results = await Promise.all(updatePromises);
    console.log(`✅ Successfully updated ${results.length} teams`);
    
    // Emit socket event for real-time updates
    if (io) {
      io.emit('all-teams-settings-updated', { scoreboardVisible, spinLimitations, resetSpinCounts });
      // Emit to all users for their individual team settings
      teamUsers.forEach(user => {
        const userSettings = user.teamSettings || {
          scoreboardVisible: true,
          spinLimitations: {
            lucky: { enabled: false, limit: 1 },
            gamehelper: { enabled: false, limit: 1 },
            challenge: { enabled: false, limit: 1 },
            hightier: { enabled: false, limit: 1 },
            lowtier: { enabled: false, limit: 1 },
            random: { enabled: false, limit: 1 }
          },
          spinCounts: {
            lucky: 0,
            gamehelper: 0,
            challenge: 0,
            hightier: 0,
            lowtier: 0,
            random: 0
          }
        };
        
        const finalSettings = {
          ...userSettings,
          scoreboardVisible: scoreboardVisible !== undefined ? scoreboardVisible : userSettings.scoreboardVisible,
          spinLimitations: spinLimitations || userSettings.spinLimitations
        };
        
        if (resetSpinCounts) {
          finalSettings.spinCounts = {
            lucky: 0,
            gamehelper: 0,
            challenge: 0,
            hightier: 0,
            lowtier: 0,
            random: 0
          };
        }
        
        io.emit('user-team-settings-updated', { 
          userId: user.id || user._id, 
          teamSettings: finalSettings 
        });
        
        // Emit specific spin count reset event if counts were reset
        if (resetSpinCounts) {
          io.emit('spin-counts-reset', { 
            userId: user.id || user._id,
            teamName: user.teamName
          });
        }
      });
    }
    
    res.json({ success: true, updatedTeams: teamUsers.length });
  } catch (error) {
    console.error('❌ Update all teams settings error:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
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
    
    // Filter countries based on visibility settings for admin view
    const filteredCountries = getFilteredCountries(countriesWithDetails);
    
    res.json(filteredCountries);
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
    
    // Also emit countries update with filtered countries
    const allCountries = await getAllCountries();
    const filteredCountries = getFilteredCountries(allCountries);
    io.emit('countries-update', filteredCountries);
    
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

// Admin get 50 coins countries visibility state
app.get('/api/admin/countries/fifty-coins-visibility', authenticateToken, requireAdmin, async (req, res) => {
  try {
        res.json({
      success: true,
      hidden: gameSettings.fiftyCoinsCountriesHidden
    });
  } catch (error) {
    console.error('Get 50 coins countries visibility state error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin toggle 50 coins countries visibility globally
app.post('/api/admin/countries/toggle-fifty-coins', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { hidden } = req.body;
    
    if (typeof hidden !== 'boolean') {
      return res.status(400).json({ error: 'Invalid visibility status' });
    }
    
    gameSettings.fiftyCoinsCountriesHidden = hidden;
    await saveGameSettings(); // Save to database
    
    // Emit to all clients about 50 coins countries visibility change
    io.emit('fifty-coins-countries-visibility-update', { hidden });
    
    // Also emit countries update to refresh the map
    const allCountries = await getAllCountries();
    const filteredCountries = getFilteredCountries(allCountries);
    
    io.emit('countries-update', filteredCountries);
    
    res.json({ 
      success: true, 
      hidden: gameSettings.fiftyCoinsCountriesHidden,
      message: `50 coins countries are now ${hidden ? 'hidden' : 'visible'}`
    });
  } catch (error) {
    console.error('Toggle 50 coins countries visibility error:', error);
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
    
    // Also emit countries update with filtered countries
    const allCountries = await getAllCountries();
    const filteredCountries = getFilteredCountries(allCountries);
    io.emit('countries-update', filteredCountries);
    
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

// Admin add new country
app.post('/api/admin/countries/add', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { name, cost, score, miningRate } = req.body;
    
    if (!name || !name.trim()) {
      return res.status(400).json({ error: 'Country name is required' });
    }
    
    if (!cost || cost < 0) {
      return res.status(400).json({ error: 'Valid cost is required' });
    }
    
    if (!score || score < 0) {
      return res.status(400).json({ error: 'Valid score is required' });
    }
    
    if (!miningRate || miningRate < 0) {
      return res.status(400).json({ error: 'Valid mining rate is required' });
    }
    
    // Generate new country ID
    const countries = await getAllCountries();
    const maxId = Math.max(...countries.map(c => parseInt(c.id)), 0);
    const newId = (maxId + 1).toString();
    
    const newCountry = {
      id: newId,
      name: name.trim(),
      cost: parseInt(cost),
      owner: null,
      score: parseInt(score),
      miningRate: parseInt(miningRate)
    };
    
    // Save to database
    if (mongoConnected && db) {
      await db.collection('countries').insertOne(newCountry);
    } else {
      countries.push(newCountry);
    }
    
    console.log(`New country "${name}" added by admin`);
    
    // Emit to all clients about new country
    io.emit('country-added', newCountry);
    
    // Also emit countries update with filtered countries
    const allCountries = await getAllCountries();
    const filteredCountries = getFilteredCountries(allCountries);
    io.emit('countries-update', filteredCountries);
    
    res.json({ 
      success: true, 
      country: newCountry,
      message: `Country "${name}" added successfully` 
    });
  } catch (error) {
    console.error('Add country error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin delete country
app.delete('/api/admin/countries/:countryId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { countryId } = req.params;
    
    const country = await findCountryById(countryId);
    if (!country) {
      return res.status(404).json({ error: 'Country not found' });
    }
    
    // If country has an owner, update their mining rate
    if (country.owner) {
      const owner = await findUserById(country.owner);
      if (owner) {
        const newMiningRate = await calculateUserMiningRate(country.owner);
        await updateUserById(country.owner, { miningRate: newMiningRate });
        
        // Emit user update
        io.to(country.owner).emit('user-update', {
          id: country.owner,
          teamName: owner.teamName,
          coins: owner.coins,
          score: owner.score,
          miningRate: newMiningRate
        });
      }
    }
    
    // Delete from database
    if (mongoConnected && db) {
      await db.collection('countries').deleteOne({ id: countryId });
    } else {
      const index = countries.findIndex(c => c.id === countryId);
      if (index !== -1) {
        countries.splice(index, 1);
      }
    }
    
    console.log(`Country "${country.name}" deleted by admin`);
    
    // Emit to all clients about country deletion
    io.emit('country-deleted', { countryName: country.name });
    
    // Also emit countries update with filtered countries
    const allCountries = await getAllCountries();
    const filteredCountries = getFilteredCountries(allCountries);
    io.emit('countries-update', filteredCountries);
    
    res.json({ 
      success: true, 
      countryId,
      message: `Country "${country.name}" deleted successfully` 
    });
  } catch (error) {
    console.error('Delete country error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin update country properties
app.put('/api/admin/countries/:countryId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { countryId } = req.params;
    const { name, cost, score, miningRate } = req.body;
    
    const country = await findCountryById(countryId);
    if (!country) {
      return res.status(404).json({ error: 'Country not found' });
    }
    
    const updates = {};
    
    if (name && name.trim()) {
      updates.name = name.trim();
    }
    
    if (cost !== undefined && cost >= 0) {
      updates.cost = parseInt(cost);
    }
    
    if (score !== undefined && score >= 0) {
      updates.score = parseInt(score);
    }
    
    if (miningRate !== undefined && miningRate >= 0) {
      updates.miningRate = parseInt(miningRate);
    }
    
    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'No valid updates provided' });
    }
    
    // Update country
    await updateCountryById(countryId, updates);
    
    // If mining rate changed and country has owner, update their mining rate
    if (updates.miningRate && country.owner) {
      const owner = await findUserById(country.owner);
      if (owner) {
        const newMiningRate = await calculateUserMiningRate(country.owner);
        await updateUserById(country.owner, { miningRate: newMiningRate });
        
        // Emit user update
        io.to(country.owner).emit('user-update', {
          id: country.owner,
          teamName: owner.teamName,
          coins: owner.coins,
          score: owner.score,
          miningRate: newMiningRate
        });
      }
    }
    
    console.log(`Country "${country.name}" updated by admin`);
    
    // Emit to all clients about country update
    io.emit('country-updated', { countryId, updates });
    
    res.json({ 
      success: true, 
      countryId,
      updates,
      message: `Country "${country.name}" updated successfully` 
    });
  } catch (error) {
    console.error('Update country error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin adjust user coins
app.post('/api/admin/users/:userId/coins', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { coins, operation } = req.body; // operation: 'set', 'add', 'subtract'
    
    if (!coins || coins < 0) {
      return res.status(400).json({ error: 'Valid coins amount is required' });
    }
    
    if (!['set', 'add', 'subtract'].includes(operation)) {
      return res.status(400).json({ error: 'Invalid operation. Use: set, add, or subtract' });
    }
    
    const user = await findUserById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    let newCoins;
    switch (operation) {
      case 'set':
        newCoins = coins;
        break;
      case 'add':
        newCoins = user.coins + coins;
        break;
      case 'subtract':
        newCoins = Math.max(0, user.coins - coins);
        break;
    }
    
    await updateUserById(userId, { coins: newCoins });
    
    console.log(`User "${user.teamName}" coins adjusted by admin: ${operation} ${coins} = ${newCoins}`);
    
    // Emit user update
    io.to(userId).emit('user-update', {
      id: userId,
      teamName: user.teamName,
      coins: newCoins,
      score: user.score
    });
    
    // Update scoreboard
    const updatedUsers = await getAllUsers();
    io.emit('scoreboard-update', updatedUsers);
    
    res.json({ 
      success: true, 
      userId,
      operation,
      oldCoins: user.coins,
      newCoins,
      message: `User coins updated successfully` 
    });
  } catch (error) {
    console.error('Adjust user coins error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin adjust user score
app.post('/api/admin/users/:userId/score', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { score, operation } = req.body; // operation: 'set', 'add', 'subtract'
    
    if (!score || score < 0) {
      return res.status(400).json({ error: 'Valid score amount is required' });
    }
    
    if (!['set', 'add', 'subtract'].includes(operation)) {
      return res.status(400).json({ error: 'Invalid operation. Use: set, add, or subtract' });
    }
    
    const user = await findUserById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    let newScore;
    switch (operation) {
      case 'set':
        newScore = score;
        break;
      case 'add':
        newScore = user.score + score;
        break;
      case 'subtract':
        newScore = Math.max(0, user.score - score);
        break;
    }
    
    await updateUserById(userId, { score: newScore });
    
    console.log(`User "${user.teamName}" score adjusted by admin: ${operation} ${score} = ${newScore}`);
    
    // Emit user update
    io.to(userId).emit('user-update', {
      id: userId,
      teamName: user.teamName,
      coins: user.coins,
      score: newScore
    });
    
    // Update scoreboard
    const updatedUsers = await getAllUsers();
    io.emit('scoreboard-update', updatedUsers);
    
    res.json({ 
      success: true, 
      userId,
      operation,
      oldScore: user.score,
      newScore,
      message: `User score updated successfully` 
    });
  } catch (error) {
    console.error('Adjust user score error:', error);
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

    // Create user notification
    const userNotification = {
      id: Date.now().toString(),
      userId: req.user.id,
      type: 'mining',
      message: `You mined ${totalEarned} coins!`,
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
  res.status(404).json({ 
    error: 'Route not found', 
    method: req.method, 
    path: req.originalUrl
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 CORS Origin: * (Public Access)`);
  console.log(`🌐 Server URL: http://localhost:${PORT}`);
});