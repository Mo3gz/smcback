const Country = require('../models/country');
const { ObjectId } = require('mongodb');

class MiningService {
    constructor(db) {
        this.db = db;
        this.collection = db.collection(Country.collectionName);
    }

    /**
     * Calculate the number of coins mined since last check
     * @param {Date} lastMined - Last time the country was mined
     * @param {number} miningRate - Coins per hour
     * @returns {Object} {coins: number, timeElapsed: number} - Coins mined and time elapsed in hours
     */
    calculateMiningReward(lastMined, miningRate) {
        const now = new Date();
        const timeElapsedMs = now - new Date(lastMined);
        const hoursElapsed = timeElapsedMs / (1000 * 60 * 60);
        
        const coinsMined = Math.floor(hoursElapsed * miningRate);
        
        return {
            coins: coinsMined,
            timeElapsed: hoursElapsed
        };
    }

    /**
     * Mine coins for a specific country
     * @param {string} countryId - The ID of the country to mine
     * @param {string} userId - The ID of the user mining the country
     * @returns {Promise<{success: boolean, coinsMined: number, newBalance: number, timeElapsed: number}>}
     */
    async mineCountry(countryId, userId) {
        const session = this.db.client.startSession();
        try {
            let result;
            
            await session.withTransaction(async () => {
                // 1. Get the country with proper locking
                const country = await this.collection.findOneAndUpdate(
                    { _id: new ObjectId(countryId), ownerId: userId },
                    { $set: { miningLock: true } },
                    { 
                        returnDocument: 'after',
                        session 
                    }
                );

                if (!country || !country.value) {
                    throw new Error('Country not found or not owned by user');
                }

                // 2. Calculate mining reward
                const { coins: coinsMined, timeElapsed } = this.calculateMiningReward(
                    country.value.lastMined,
                    country.value.miningRate
                );

                if (coinsMined <= 0) {
                    result = { success: true, coinsMined: 0, newBalance: 0, timeElapsed: 0 };
                    return;
                }

                // 3. Update user's balance
                const usersCollection = this.db.collection('users');
                const updateResult = await usersCollection.findOneAndUpdate(
                    { _id: new ObjectId(userId) },
                    { 
                        $inc: { balance: coinsMined },
                        $set: { lastActive: new Date() }
                    },
                    { 
                        returnDocument: 'after',
                        session 
                    }
                );

                if (!updateResult.value) {
                    throw new Error('User not found');
                }

                // 4. Update country's lastMined time
                await this.collection.updateOne(
                    { _id: new ObjectId(countryId) },
                    { 
                        $set: { 
                            lastMined: new Date(),
                            miningLock: false
                        } 
                    },
                    { session }
                );

                result = { 
                    success: true, 
                    coinsMined, 
                    newBalance: updateResult.value.balance,
                    timeElapsed
                };
            });

            return result;
        } catch (error) {
            console.error('Mining error:', error);
            // Ensure lock is released on error
            await this.collection.updateOne(
                { _id: new ObjectId(countryId) },
                { $set: { miningLock: false } }
            );
            throw error;
        } finally {
            await session.endSession();
        }
    }

    /**
     * Get mining stats for all user's countries
     * @param {string} userId - The ID of the user
     * @returns {Promise<Array>} - Array of mining stats for each country
     */
    async getUserMiningStats(userId) {
        const countries = await this.collection
            .find({ ownerId: userId })
            .toArray();

        const now = new Date();
        
        return countries.map(country => {
            const timeElapsedMs = now - new Date(country.lastMined);
            const hoursElapsed = timeElapsedMs / (1000 * 60 * 60);
            const coinsAvailable = Math.floor(hoursElapsed * country.miningRate);
            
            return {
                countryId: country._id,
                countryName: country.name,
                miningRate: country.miningRate,
                lastMined: country.lastMined,
                timeSinceLastMine: hoursElapsed,
                coinsAvailable,
                nextMineIn: coinsAvailable > 0 ? 0 : 1 - (hoursElapsed % 1)
            };
        });
    }
}

module.exports = MiningService;
