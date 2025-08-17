// Calculate mining amount based on time and rate
exports.calculateMiningAmount = (hours, miningRate) => {
  // Basic linear calculation - you can adjust this formula as needed
  return hours * miningRate;
};

// Calculate offline mining with potential bonuses/penalties
exports.calculateOfflineMining = (hours, miningRate) => {
  // Cap offline mining at 24 hours to prevent abuse
  const cappedHours = Math.min(hours, 24);
  
  // Apply a small penalty for offline mining (e.g., 80% of normal rate)
  const OFFLINE_MINING_FACTOR = 0.8;
  
  return this.calculateMiningAmount(cappedHours, miningRate) * OFFLINE_MINING_FACTOR;
};

// Format mining rate for display
exports.formatMiningRate = (miningRate) => {
  return {
    perHour: miningRate,
    perDay: miningRate * 24,
    perWeek: miningRate * 24 * 7,
    perMonth: miningRate * 24 * 30 // Approximate
  };
};

// Get mining efficiency based on various factors
exports.calculateMiningEfficiency = (userStats, countryStats) => {
  // Base efficiency is the country's mining rate
  let efficiency = countryStats.miningRate;
  
  // Apply any user-specific modifiers here
  // For example, premium users might get a bonus
  if (userStats.isPremium) {
    efficiency *= 1.2; // 20% bonus for premium users
  }
  
  return efficiency;
};
