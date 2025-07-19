const mongoose = require('mongoose');

const notificationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['like', 'comment', 'follow'], required: true },
  fromUser: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  photoId: { type: mongoose.Schema.Types.ObjectId, ref: 'Photo' },
  commentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Comment' },
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

// Index for faster queries
notificationSchema.index({ userId: 1, createdAt: -1 });
notificationSchema.index({ userId: 1, read: 1 });

const Notification = mongoose.model('Notification', notificationSchema);

module.exports = mongoose.model('Notification', notificationSchema); 