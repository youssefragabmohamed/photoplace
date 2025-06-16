const mongoose = require('mongoose');

const followSchema = new mongoose.Schema({
  followerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  followingId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Create a compound index to ensure a user can only follow another user once
followSchema.index({ followerId: 1, followingId: 1 }, { unique: true });

// Create indexes for faster queries
followSchema.index({ followerId: 1 });
followSchema.index({ followingId: 1 });

const Follow = mongoose.model('Follow', followSchema);

module.exports = Follow; 