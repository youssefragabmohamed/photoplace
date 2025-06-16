const mongoose = require('mongoose');

const saveSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  photoId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Photo',
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Compound index to prevent duplicate saves
saveSchema.index({ userId: 1, photoId: 1 }, { unique: true });

// Index for faster queries
saveSchema.index({ photoId: 1, createdAt: -1 });

const Save = mongoose.model('Save', saveSchema);

module.exports = Save; 