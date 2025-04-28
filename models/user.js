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
    maxlength: 500
  },
  link: {
    type: String,
    trim: true
  },
  location: {
    type: String,
    trim: true
  },
  portfolio: [{
    photoId: { type: mongoose.Schema.Types.ObjectId, ref: 'Photo' }, // Updated field
    url: String,
    title: String,
    description: String
  }],
  portfolioTitle: {
    type: String,
    default: 'My Portfolio'
  },
  portfolioDescription: {
    type: String,
    default: ''
  },
  profilePic: {
    type: String,
    default: '/default-profile.jpg'
  },
  followers: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  following: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  savedPhotos: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Photo'
  }],
  createdAt: {
    type: Date,
    default: Date.now
  }
}, {
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual population for photos
userSchema.virtual('photos', {
  ref: 'Photo',
  localField: '_id',
  foreignField: 'userId'
});

// Virtual for followers count
userSchema.virtual('followersCount').get(function() {
  return this.followers.length;
});

// Virtual for following count
userSchema.virtual('followingCount').get(function() {
  return this.following.length;
});

module.exports = mongoose.model('User', userSchema);