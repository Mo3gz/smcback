require('dotenv').config();

const config = {
  app: {
    port: process.env.PORT || 3001,
    nodeEnv: process.env.NODE_ENV || 'development',
  },
  jwt: {
    secret: process.env.JWT_SECRET || 'Aymaan',
    cookieName: 'auth_token',
    expiresIn: '7d',
  },
  cors: {
    allowedOrigins: [
      'https://smcscout.netlify.app',
      'https://smcscout.netlify.app/',
      'http://localhost:3000',
      'http://localhost:3001',
      'https://localhost:3000',
      'https://localhost:3001',
      'https://smcfront1-production.up.railway.app',
      'https://smcfront1.vercel.app'
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH', 'HEAD'],
    allowedHeaders: [
      'Content-Type', 
      'Authorization', 
      'X-Requested-With', 
      'Cache-Control', 
      'Pragma', 
      'Accept', 
      'Origin', 
      'x-auth-token',
      'Access-Control-Allow-Origin',
      'Access-Control-Allow-Credentials',
      'Access-Control-Allow-Methods',
      'Access-Control-Allow-Headers'
    ],
    exposedHeaders: ['Set-Cookie', 'x-auth-token']
  },
  mongo: {
    uri: process.env.MONGODB_URI,
    dbName: process.env.MONGO_DB_NAME || 'scoring-system'
  },
  defaultValues: {
    initialCoins: 500,
    adminUsername: 'ayman',
    adminPassword: '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi' // password
  }
};

module.exports = config;
