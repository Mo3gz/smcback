const Inventory = require('../models/Inventory');
const User = require('../models/User');
const Notification = require('../models/Notification');
const config = require('../config');

// Get user's inventory
exports.getUserInventory = async (req, res) => {
  try {
    const inventory = await Inventory.getUserInventory(req.user.id);
    res.json(inventory);
  } catch (error) {
    console.error('Get inventory error:', error);
    res.status(500).json({ error: 'Failed to get inventory' });
  }
};

// Use an item from inventory
exports.useItem = async (req, res) => {
  try {
    const { itemId, targetUserId, description } = req.body;
    const userId = req.user.id;

    // Get user's inventory
    const inventory = await Inventory.getUserInventory(userId);
    
    // Find the item
    const item = inventory.find(item => item.id === itemId);
    if (!item) {
      return res.status(404).json({ error: 'Item not found in inventory' });
    }

    // Handle different item types
    switch (item.type) {
      case 'score-boost':
        // Apply score boost to user
        const user = await User.findById(userId);
        const scoreIncrease = item.value || 50; // Default 50 points if value not specified
        
        await User.updateUser(userId, {
          score: (user.score || 0) + scoreIncrease
        });

        // Create notification
        await Notification.create({
          userId,
          type: 'item-used',
          message: `You used ${item.name} and gained ${scoreIncrease} points!`,
          read: false
        });
        break;

      case 'coin-boost':
        // Apply coin boost to user
        const coinIncrease = item.value || 100; // Default 100 coins if value not specified
        
        await User.updateUser(userId, {
          coins: (user.coins || 0) + coinIncrease
        });

        // Create notification
        await Notification.create({
          userId,
          type: 'item-used',
          message: `You used ${item.name} and received ${coinIncrease} coins!`,
          read: false
        });
        break;

      case 'special-card':
        // Handle special card usage (e.g., steal coins from another player)
        if (!targetUserId) {
          return res.status(400).json({ error: 'Target user is required for this item' });
        }

        const targetUser = await User.findById(targetUserId);
        if (!targetUser) {
          return res.status(404).json({ error: 'Target user not found' });
        }

        const coinsToSteal = Math.min(targetUser.coins || 0, item.value || 100);
        
        // Update both users
        await Promise.all([
          User.updateUser(userId, {
            coins: (user.coins || 0) + coinsToSteal
          }),
          User.updateUser(targetUserId, {
            coins: Math.max(0, (targetUser.coins || 0) - coinsToSteal)
          })
        ]);

        // Create notifications
        await Promise.all([
          Notification.create({
            userId,
            type: 'item-used',
            message: `You used ${item.name} and stole ${coinsToSteal} coins from ${targetUser.teamName}!`,
            read: false
          }),
          Notification.create({
            userId: targetUserId,
            type: 'item-used-against',
            message: `${user.teamName} used ${item.name} and stole ${coinsToSteal} of your coins!`,
            read: false
          })
        ]);
        break;

      default:
        return res.status(400).json({ error: 'Invalid item type' });
    }

    // Remove the used item from inventory
    await Inventory.removeItem(userId, itemId);

    // Emit socket event
    if (req.io) {
      req.io.emit('inventoryUpdated', { userId });
      
      if (targetUserId) {
        req.io.emit('inventoryUpdated', { userId: targetUserId });
      }
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Use item error:', error);
    res.status(500).json({ error: 'Failed to use item' });
  }
};

// Admin: Add item to user's inventory
exports.addItemToInventory = async (req, res) => {
  try {
    const { userId, item } = req.body;
    
    if (!userId || !item || !item.id || !item.name || !item.type) {
      return res.status(400).json({ error: 'Invalid item data' });
    }

    // Add item to inventory
    await Inventory.addItem(userId, {
      ...item,
      addedAt: new Date()
    });

    // Create notification
    await Notification.create({
      userId,
      type: 'item-received',
      message: `You received a new item: ${item.name}`,
      read: false
    });

    // Emit socket event
    if (req.io) {
      req.io.emit('inventoryUpdated', { userId });
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Add item error:', error);
    res.status(500).json({ error: 'Failed to add item to inventory' });
  }
};

// Spin the wheel to get a random item
exports.spinWheel = async (req, res) => {
  try {
    const userId = req.user.id;
    const { spinType } = req.body;

    // Check if user has enough coins
    const user = await User.findById(userId);
    const spinCost = spinType === 'premium' ? 100 : 50;
    
    if (user.coins < spinCost) {
      return res.status(400).json({ error: 'Not enough coins' });
    }

    // Define possible rewards based on spin type
    const rewards = {
      normal: [
        { type: 'coin-boost', name: 'Small Coin Bag', value: 50 },
        { type: 'score-boost', name: 'Score Booster', value: 25 },
        { type: 'special-card', name: 'Lucky Card', value: 25 }
      ],
      premium: [
        { type: 'coin-boost', name: 'Large Coin Bag', value: 200 },
        { type: 'score-boost', name: 'Super Score Booster', value: 100 },
        { type: 'special-card', name: 'Golden Card', value: 100 },
        { type: 'special-card', name: 'Mystery Box', value: 150 }
      ]
    };

    // Select random reward
    const possibleRewards = rewards[spinType] || rewards.normal;
    const randomReward = possibleRewards[Math.floor(Math.random() * possibleRewards.length)];
    
    // Add reward to inventory
    const rewardItem = {
      ...randomReward,
      id: `item-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      obtainedAt: new Date()
    };

    await Inventory.addItem(userId, rewardItem);
    
    // Deduct coins
    await User.updateUser(userId, {
      coins: user.coins - spinCost
    });

    // Create notification
    await Notification.create({
      userId,
      type: 'spin-reward',
      message: `You spun the wheel and got: ${rewardItem.name}!`,
      read: false
    });

    // Emit socket events
    if (req.io) {
      req.io.emit('inventoryUpdated', { userId });
      req.io.emit('userUpdated', { userId });
    }

    res.json({
      success: true,
      reward: rewardItem,
      coins: user.coins - spinCost
    });
  } catch (error) {
    console.error('Spin wheel error:', error);
    res.status(500).json({ error: 'Failed to spin the wheel' });
  }
};
