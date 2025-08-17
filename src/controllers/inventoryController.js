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

    console.log('🎮 Card usage attempt:', {
      userId,
      itemId,
      targetUserId,
      description,
      userRole: req.user.role
    });

    // Get user's inventory
    const inventory = await Inventory.getUserInventory(userId);
    console.log('📦 User inventory:', inventory.length, 'items');
    
    // Find the item
    const item = inventory.find(item => item.id === itemId);
    if (!item) {
      console.log('❌ Item not found in inventory:', itemId);
      return res.status(404).json({ error: 'Item not found in inventory' });
    }

    console.log('🃏 Found item:', item);

    // Get current user data
    const user = await User.findById(userId);

    // Handle different item types
    switch (item.type) {
      case 'luck':
        // Handle luck cards - some have instant effects
        if (item.name === "i`amphoteric") {
          // Instant +150 coins
          await User.updateUser(userId, {
            coins: (user.coins || 0) + 150
          });
          
          await Notification.create({
            userId,
            type: 'item-used',
            message: `You used ${item.name} and gained 150 coins instantly!`,
            read: false
          });
        } else if (item.name === "Everything Against Me") {
          // Instant -75 coins
          await User.updateUser(userId, {
            coins: Math.max(0, (user.coins || 0) - 75)
          });
          
          await Notification.create({
            userId,
            type: 'item-used',
            message: `You used ${item.name} and lost 75 coins!`,
            read: false
          });
        } else {
          // Other luck cards create notifications for admin/manual handling
          await Notification.create({
            userId,
            type: 'item-used',
            message: `You used ${item.name}: ${item.effect}. An admin will handle this.`,
            read: false
          });
        }
        break;

      case 'attack':
        // Attack cards require a target
        if (!targetUserId) {
          return res.status(400).json({ error: 'Target user is required for attack cards' });
        }

        const targetUser = await User.findById(targetUserId);
        if (!targetUser) {
          return res.status(404).json({ error: 'Target user not found' });
        }

        // Handle specific attack cards
        if (item.name === 'ana-el-7aramy') {
          // Steal 100 coins directly
          const coinsToSteal = Math.min(targetUser.coins || 0, 100);
          
          await Promise.all([
            User.updateUser(userId, {
              coins: (user.coins || 0) + coinsToSteal
            }),
            User.updateUser(targetUserId, {
              coins: Math.max(0, (targetUser.coins || 0) - coinsToSteal)
            })
          ]);

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
        } else {
          // Other attack cards create notifications for admin/manual handling
          await Promise.all([
            Notification.create({
              userId,
              type: 'item-used',
              message: `You used ${item.name} against ${targetUser.teamName}: ${item.effect}`,
              read: false
            }),
            Notification.create({
              userId: targetUserId,
              type: 'item-used-against',
              message: `${user.teamName} used ${item.name} against you: ${item.effect}`,
              read: false
            })
          ]);
        }
        break;

      case 'alliance':
        // Alliance cards require a target
        if (!targetUserId) {
          return res.status(400).json({ error: 'Target user is required for alliance cards' });
        }

        const allianceTarget = await User.findById(targetUserId);
        if (!allianceTarget) {
          return res.status(404).json({ error: 'Target user not found' });
        }

        // Create notifications for alliance
        await Promise.all([
          Notification.create({
            userId,
            type: 'item-used',
            message: `You used ${item.name} with ${allianceTarget.teamName}: ${item.effect}`,
            read: false
          }),
          Notification.create({
            userId: targetUserId,
            type: 'item-used-against',
            message: `${user.teamName} used ${item.name} with you: ${item.effect}`,
            read: false
          })
        ]);
        break;

      // Legacy support for old card types
      case 'score-boost':
      case 'coin-boost':  
      case 'special-card':
        await Notification.create({
          userId,
          type: 'item-used',
          message: `You used ${item.name}: ${item.effect}`,
          read: false
        });
        break;

      default:
        return res.status(400).json({ error: 'Invalid item type' });
    }

    // Remove the used item from inventory
    await Inventory.removeItem(userId, itemId);
    console.log('✅ Item removed from inventory');

    // Emit socket event
    if (req.io) {
      req.io.emit('inventory-update', { userId });
      req.io.emit('user-update', { userId });
      console.log('📡 Socket events emitted for user:', userId);
      
      if (targetUserId) {
        req.io.emit('inventory-update', { userId: targetUserId });
        req.io.emit('user-update', { userId: targetUserId });
        console.log('📡 Socket events emitted for target:', targetUserId);
      }
    } else {
      console.log('⚠️ No socket.io instance available');
    }

    console.log('✅ Card used successfully');
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
      req.io.emit('inventory-update', { userId });
      req.io.emit('user-update', { userId });
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
    const { spinType, promoCode } = req.body;

    // Check if user has enough coins
    const user = await User.findById(userId);
    
    // Calculate spin cost (different for each type)
    let spinCost = 50; // Default cost
    switch (spinType) {
      case 'luck':
      case 'attack':
      case 'alliance':
        spinCost = 50;
        break;
      case 'random':
        spinCost = 25;
        break;
      case 'premium':
        spinCost = 100;
        break;
    }

    // Apply promo code discount if provided
    if (promoCode) {
      // Simple promo code validation - you can extend this
      const discountCodes = {
        'SAVE10': 10,
        'SAVE20': 20,
        'SAVE50': 50,
        'FREE': 100
      };
      
      const discount = discountCodes[promoCode.toUpperCase()] || 0;
      spinCost = Math.max(0, Math.floor(spinCost * (1 - discount / 100)));
    }
    
    if (user.coins < spinCost) {
      return res.status(400).json({ error: 'Not enough coins' });
    }

    // Define possible rewards based on spin type
    const rewards = {
      luck: [
        { name: "i`amphoteric", type: 'luck', effect: '+150 Coins instantly' },
        { name: "Everything Against Me", type: 'luck', effect: 'Instantly lose 75 Coins' },
        { name: 'el-7aramy', type: 'luck', effect: 'Btsr2 100 coin men ay khema, w law et3raft birg3o el double' }
      ],
      attack: [
        { name: 'wesh-le-wesh', type: 'attack', effect: '1v1 battle' },
        { name: 'ana-el-7aramy', type: 'attack', effect: 'Btakhod 100 coins men ay khema mnghir ay challenge' },
        { name: 'ana-w-bas', type: 'attack', effect: 'Bt3mel risk 3ala haga' }
      ],
      alliance: [
        { name: 'el-nadala', type: 'alliance', effect: 'Bt3mel t7alof w tlghih f ay wa2t w takhod el coins 3ady' },
        { name: 'el-sohab', type: 'alliance', effect: 'Bt3mel t7alof 3ady' },
        { name: 'el-melok', type: 'alliance', effect: 'Btst5dm el khema el taniaa y3melo el challenges makanak' }
      ],
      random: [
        // Mix of all types for random spin
        { name: "i`amphoteric", type: 'luck', effect: '+150 Coins instantly' },
        { name: 'wesh-le-wesh', type: 'attack', effect: '1v1 battle' },
        { name: 'el-sohab', type: 'alliance', effect: 'Bt3mel t7alof 3ady' },
        { name: 'el-7aramy', type: 'luck', effect: 'Btsr2 100 coin men ay khema, w law et3raft birg3o el double' },
        { name: 'ana-el-7aramy', type: 'attack', effect: 'Btakhod 100 coins men ay khema mnghir ay challenge' },
        { name: 'el-nadala', type: 'alliance', effect: 'Bt3mel t7alof w tlghih f ay wa2t w takhod el coins 3ady' }
      ],
      premium: [
        // Premium versions with better effects
        { name: 'Premium Lucky Card', type: 'luck', effect: '+300 Coins instantly' },
        { name: 'Premium Attack Card', type: 'attack', effect: 'Steal 200 coins from any team' },
        { name: 'Premium Alliance Card', type: 'alliance', effect: 'Form unbreakable alliance' }
      ]
    };

    // Select random reward
    const possibleRewards = rewards[spinType] || rewards.random;
    const randomReward = possibleRewards[Math.floor(Math.random() * possibleRewards.length)];
    
    // Add reward to inventory
    const rewardItem = {
      ...randomReward,
      id: `item-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      obtainedAt: new Date()
    };

    await Inventory.addItem(userId, rewardItem);
    
    // Deduct coins
    const newCoins = user.coins - spinCost;
    await User.updateUser(userId, {
      coins: newCoins
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
      req.io.emit('inventory-update', { userId });
      req.io.emit('user-update', { userId });
    }

    // Return response in format expected by frontend
    res.json({
      success: true,
      card: rewardItem,  // Frontend expects 'card' not 'reward'
      remainingCoins: newCoins  // Frontend expects 'remainingCoins' not 'coins'
    });
  } catch (error) {
    console.error('Spin wheel error:', error);
    res.status(500).json({ error: 'Failed to spin the wheel' });
  }
};

// Validate promo code
exports.validatePromoCode = async (req, res) => {
  try {
    const { code } = req.body;
    
    if (!code) {
      return res.json({ valid: false, discount: 0 });
    }

    // Simple promo code validation - you can extend this with database storage
    const discountCodes = {
      'SAVE10': 10,
      'SAVE20': 20,
      'SAVE50': 50,
      'FREE': 100,
      'WELCOME': 25,
      'SPIN30': 30
    };
    
    const discount = discountCodes[code.toUpperCase()] || 0;
    
    res.json({
      valid: discount > 0,
      discount: discount
    });
  } catch (error) {
    console.error('Validate promo code error:', error);
    res.status(500).json({ valid: false, discount: 0 });
  }
};
