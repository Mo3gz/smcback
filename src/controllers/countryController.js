const Country = require('../models/Country');
const User = require('../models/User');
const Notification = require('../models/Notification');

// Get all countries
exports.getAllCountries = async (req, res) => {
  try {
    const countries = await Country.find();
    res.json(countries);
  } catch (error) {
    console.error('Get countries error:', error);
    res.status(500).json({ error: 'Failed to get countries' });
  }
};

// Get country by ID
exports.getCountryById = async (req, res) => {
  try {
    const { id } = req.params;
    const country = await Country.findById(id);
    
    if (!country) {
      return res.status(404).json({ error: 'Country not found' });
    }
    
    res.json(country);
  } catch (error) {
    console.error('Get country error:', error);
    res.status(500).json({ error: 'Failed to get country' });
  }
};

// Buy a country
exports.buyCountry = async (req, res) => {
  try {
    const { countryId } = req.body;
    const userId = req.user.id;

    // Get user and country
    const [user, country] = await Promise.all([
      User.findById(userId),
      Country.findById(countryId)
    ]);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (!country) {
      return res.status(404).json({ error: 'Country not found' });
    }

    // Check if country is already owned
    if (country.owner) {
      return res.status(400).json({ error: 'Country is already owned' });
    }

    // Check if user has enough coins
    if (user.coins < country.cost) {
      return res.status(400).json({ error: 'Not enough coins' });
    }

    // Update user's coins and score
    const updatedUser = await User.updateUser(userId, {
      coins: user.coins - country.cost,
      score: (user.score || 0) + country.score
    });

    // Update country owner
    await Country.updateOne(
      { _id: country._id },
      { 
        owner: userId,
        ownedAt: new Date()
      }
    );

    // Create notification
    await Notification.create({
      userId,
      type: 'country-purchase',
      message: `You have purchased ${country.name} for ${country.cost} coins`,
      read: false
    });

    // Emit socket event
    if (req.io) {
      req.io.emit('countryPurchased', {
        countryId: country.id,
        userId,
        teamName: user.teamName
      });
    }

    res.json({
      success: true,
      user: updatedUser,
      country: {
        ...country,
        owner: userId
      }
    });
  } catch (error) {
    console.error('Buy country error:', error);
    res.status(500).json({ error: 'Failed to buy country' });
  }
};

// Get available countries
exports.getAvailableCountries = async (req, res) => {
  try {
    const countries = await Country.find({ owner: null });
    res.json(countries);
  } catch (error) {
    console.error('Get available countries error:', error);
    res.status(500).json({ error: 'Failed to get available countries' });
  }
};

// Get user's countries
exports.getUserCountries = async (req, res) => {
  try {
    const { userId } = req.params;
    const countries = await Country.find({ owner: userId });
    res.json(countries);
  } catch (error) {
    console.error('Get user countries error:', error);
    res.status(500).json({ error: 'Failed to get user countries' });
  }
};

// Admin: Reset country ownership
exports.resetCountryOwnership = async (req, res) => {
  try {
    const { countryId } = req.params;
    
    const country = await Country.findById(countryId);
    if (!country) {
      return res.status(404).json({ error: 'Country not found' });
    }

    // Get previous owner if any
    const previousOwnerId = country.owner;
    
    // Reset ownership
    await Country.updateOne(
      { _id: countryId },
      { 
        $unset: { owner: "", ownedAt: "" },
        $set: { updatedAt: new Date() }
      }
    );

    // Notify previous owner if exists
    if (previousOwnerId) {
      await Notification.create({
        userId: previousOwnerId,
        type: 'country-lost',
        message: `You have lost ownership of ${country.name}`,
        read: false
      });
    }

    // Emit socket event
    if (req.io) {
      req.io.emit('countryReset', { countryId });
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Reset country ownership error:', error);
    res.status(500).json({ error: 'Failed to reset country ownership' });
  }
};
