const mongoose = require('mongoose');

const countrySchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true
  },
  code: {
    type: String,
    required: true,
    unique: true,
    uppercase: true
  },
  miningRate: {
    type: Number,
    required: true,
    default: 1.0
  },
  isActive: {
    type: Boolean,
    default: true
  }
}, { timestamps: true });

module.exports = mongoose.model('Country', countrySchema);
