const express = require('express');
const router = express.Router();
const countryController = require('../controllers/countryController');
const { authenticate, requireAdmin } = require('../middleware/auth');

// Public routes
router.get('/', countryController.getAllCountries);
router.get('/available', countryController.getAvailableCountries);
router.get('/:id', countryController.getCountryById);

// Protected routes
router.post('/buy', authenticate, countryController.buyCountry);
router.get('/user/:userId', authenticate, countryController.getUserCountries);

// Admin routes
router.post('/:countryId/reset', authenticate, requireAdmin, countryController.resetCountryOwnership);

module.exports = router;
