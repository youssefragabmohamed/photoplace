const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 30
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    validate: {
      validator: v => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v),
      message: props => `${props.value} is not a valid email!`
    }
  },
  password: {
    type: String,
    required: true,
    minlength: 8
  },
  fullName: {
    type: String,
    trim: true,
    maxlength: 50
  },
  bio: {
    type: String,
    trim: true,
    maxlength: 500,
    default: ''
  },
  link: {
    type: String,
    trim: true,
    validate: {
      validator: v => /^https?:\/\/.+\..+/.test(v),
      message: props => `${props.value} is not a valid URL!`
    }
  },
  location: {
    type: String,
    trim: true,
    maxlength: 50
  },
  portfolio: [{
    photoId: { 
      type: mongoose.Schema.Types.ObjectId, 
      ref: 'Photo',
      required: true 
    },
    url: { 
      type: String, 
      required: true,
      validate: {
        validator: v => /^https?:\/\/.+\..+/.test(v),
        message: props => `${props.value} is not a valid URL!`
      }
    },
    title: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100
    },
    description: {
      type: String,
      trim: true,
      maxlength: 500
    }
  }],
  portfolioTitle: {
    type: String,
    default: 'My Portfolio',
    trim: true,
    maxlength: 100
  },
  portfolioDescription: {
    type: String,
    default: '',
    trim: true,
    maxlength: 500
  },
  profilePic: {
    type: String,
    default: '/default-profile.jpg',
    validate: {
      validator: v => /^https?:\/\/.+\..+/.test(v) || v.startsWith('/'),
      message: props => `${props.value} is not a valid image path!`
    }
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
    default: Date.now,
    immutable: true
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  toJSON: { virtuals: true },
  toObject: { virtuals: true },
  timestamps: true
});

// Update timestamp on save
userSchema.pre('save', function(next) {
  // Initialize arrays if they don't exist
  if (!this.followers) this.followers = [];
  if (!this.following) this.following = [];
  if (!this.savedPhotos) this.savedPhotos = [];
  
  // Update timestamp
  this.updatedAt = Date.now();
  next();
});

// Virtuals
userSchema.virtual('photos', {
  ref: 'Photo',
  localField: '_id',
  foreignField: 'userId'
});

userSchema.virtual('followersCount').get(function() {
  return this.followers ? this.followers.length : 0;
});

userSchema.virtual('followingCount').get(function() {
  return this.following ? this.following.length : 0;
});

userSchema.virtual('photosCount', {
  ref: 'Photo',
  localField: '_id',
  foreignField: 'userId',
  count: true
});

module.exports = mongoose.model('User', userSchema);