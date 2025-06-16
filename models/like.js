const mongoose = require('mongoose');

const likeSchema = new mongoose.Schema({
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

// Compound index to prevent duplicate likes
likeSchema.index({ userId: 1, photoId: 1 }, { unique: true });

// Index for faster queries
likeSchema.index({ photoId: 1, createdAt: -1 });

const Like = mongoose.model('Like', likeSchema);

module.exports = Like; 