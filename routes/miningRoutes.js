const express = require('express');
const router = express.Router();
const { ObjectId } = require('mongodb');
const MiningService = require('../services/miningService');
const authMiddleware = require('../middleware/auth');

module.exports = function(db) {
    const miningService = new MiningService(db);

    // Get mining stats for all user's countries
    router.get('/stats', authMiddleware, async (req, res) => {
        try {
            const stats = await miningService.getUserMiningStats(req.user.id);
            res.json({ success: true, data: stats });
        } catch (error) {
            console.error('Error getting mining stats:', error);
            res.status(500).json({ 
                success: false, 
                message: 'Failed to get mining stats',
                error: error.message 
            });
        }
    });

    // Mine a specific country
    router.post('/mine/:countryId', authMiddleware, async (req, res) => {
        try {
            const { countryId } = req.params;
            const userId = req.user.id;

            if (!ObjectId.isValid(countryId)) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'Invalid country ID' 
                });
            }

            const result = await miningService.mineCountry(countryId, userId);
            
            if (!result.success) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'Failed to mine country' 
                });
            }

            // Send notification to user
            if (result.coinsMined > 0) {
                await notifyMiningComplete(userId, countryId, result.coinsMined);
                
                // Notify admin if significant amount was mined
                if (result.coinsMined >= 100) {
                    await notifyAdminMining(userId, countryId, result.coinsMined);
                }
            }

            res.json({
                success: true,
                coinsMined: result.coinsMined,
                newBalance: result.newBalance,
                timeElapsed: result.timeElapsed
            });

        } catch (error) {
            console.error('Error mining country:', error);
            res.status(500).json({ 
                success: false, 
                message: 'Failed to mine country',
                error: error.message 
            });
        }
    });

    // Helper function to send notification to user
    async function notifyMiningComplete(userId, countryId, coinsMined) {
        try {
            const notifications = db.collection('notifications');
            const country = await db.collection('countries').findOne({ _id: new ObjectId(countryId) });
            
            if (country) {
                await notifications.insertOne({
                    userId: new ObjectId(userId),
                    type: 'mining_complete',
                    title: 'Mining Complete',
                    message: `You've mined ${coinsMined} coins from ${country.name}!`,
                    read: false,
                    data: {
                        countryId: country._id,
                        countryName: country.name,
                        coinsMined
                    },
                    timestamp: new Date()
                });
            }
        } catch (error) {
            console.error('Error sending mining notification:', error);
        }
    }

    // Helper function to notify admin
    async function notifyAdminMining(userId, countryId, coinsMined) {
        try {
            const users = db.collection('users');
            const notifications = db.collection('notifications');
            
            const [admin, user, country] = await Promise.all([
                users.findOne({ role: 'admin' }),
                users.findOne({ _id: new ObjectId(userId) }),
                db.collection('countries').findOne({ _id: new ObjectId(countryId) })
            ]);

            if (admin && user && country) {
                await notifications.insertOne({
                    userId: admin._id,
                    type: 'admin_mining_alert',
                    title: 'Significant Mining Activity',
                    message: `${user.username} mined ${coinsMined} coins from ${country.name}!`,
                    read: false,
                    data: {
                        userId: user._id,
                        username: user.username,
                        countryId: country._id,
                        countryName: country.name,
                        coinsMined
                    },
                    timestamp: new Date()
                });
            }
        } catch (error) {
            console.error('Error sending admin mining notification:', error);
        }
    }

    return router;
};
