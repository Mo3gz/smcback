const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const config = require('../config');
const User = require('../models/User');
const Notification = require('../models/Notification');

const getCookieOptions = () => ({
  httpOnly: true,
  secure: config.app.nodeEnv === 'production',
  sameSite: config.app.nodeEnv === 'production' ? 'none' : 'lax',
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  path: '/',
  domain: config.app.nodeEnv === 'production' ? undefined : undefined, // Let browser handle domain
});

const generateToken = (userId) => {
  return jwt.sign(
    { userId },
    config.jwt.secret,
    { expiresIn: config.jwt.expiresIn }
  );
};

exports.login = async (req, res) => {
  try {
    const { username, password } = req.body;

    // Find user
    const user = await User.findByUsername(username);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate token
    const token = generateToken(user.id);
    console.log('🔑 Generated token for user:', user.id, 'token length:', token.length);

    // Set cookie
    const cookieOptions = getCookieOptions();
    res.cookie(config.jwt.cookieName, token, cookieOptions);
    console.log('🍪 Cookie set with options:', cookieOptions);

    // Don't send password back
    const { password: _, ...userWithoutPassword } = user;

    // Add login notification
    await Notification.create({
      userId: user.id,
      type: 'login',
      message: 'You have successfully logged in',
      read: false
    });

    res.json({
      user: userWithoutPassword,
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
};

exports.logout = (req, res) => {
  try {
    res.clearCookie(config.jwt.cookieName, {
      httpOnly: true,
      secure: config.app.nodeEnv === 'production',
      sameSite: config.app.nodeEnv === 'production' ? 'none' : 'lax',
      path: '/',
    });
    
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Logout failed' });
  }
};

exports.register = async (req, res) => {
  try {
    const { username, password, teamName } = req.body;

    // Check if username exists
    const existingUser = await User.findByUsername(username);
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    // Create user
    const newUser = await User.create({
      username,
      password,
      teamName,
      role: 'user',
      coins: 500,
      score: 0
    });

    // Generate token
    const token = generateToken(newUser.id);

    // Set cookie
    res.cookie(config.jwt.cookieName, token, getCookieOptions());

    // Don't send password back
    const { password: _, ...userWithoutPassword } = newUser;

    // Add welcome notification
    await Notification.create({
      userId: newUser.id,
      type: 'welcome',
      message: `Welcome to the game, ${teamName}! You've received 500 starting coins.`,
      read: false
    });

    res.status(201).json({
      user: userWithoutPassword,
      token
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
};

exports.getCurrentUser = async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    // Don't send password back
    const { password, ...userWithoutPassword } = req.user;
    res.json(userWithoutPassword);
  } catch (error) {
    console.error('Get current user error:', error);
    res.status(500).json({ error: 'Failed to get current user' });
  }
};

exports.getScoreboard = async (req, res) => {
  try {
    const users = await User.getLeaderboard(50); // Get users
    
    // Filter out admins and map to include relevant fields for the scoreboard
    const scoreboard = users
      .filter(user => user.role !== 'admin') // Exclude admins
      .map(user => ({
        id: user.id,
        username: user.username,
        teamName: user.teamName || user.username, // Fallback to username if no teamName
        score: user.score || 0,
        coins: user.coins || 0,
        role: user.role || 'user' // Include role for consistency
      }));
    
    res.json(scoreboard);
  } catch (error) {
    console.error('Get scoreboard error:', error);
    res.status(500).json({ error: 'Failed to get scoreboard' });
  }
};
