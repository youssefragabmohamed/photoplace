const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true
  },
  fullName: {
    type: String,
    trim: true
  },
  bio: {
    type: String,
    trim: true,
    maxlength: 150
  },
  profilePic: {
    type: String,
    default: '/default-profile.jpg'
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
}, {
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Add any virtuals or methods you need
userSchema.virtual('photos', {
  ref: 'Photo',
  localField: '_id',
  foreignField: 'userId'
});

module.exports = mongoose.model('User', userSchema);