const mongoose = require("mongoose");

const photoSchema = new mongoose.Schema({
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
  },
  url: { 
    type: String, 
    required: true,
    validate: {
      validator: function(v) {
        // Accept both relative paths (/uploads/) and full URLs (http/https)
        return /^(\/uploads\/|https?:\/\/).*/.test(v);
      },
      message: props => `${props.value} is not a valid URL or path! Must start with /uploads/ or http:// or https://`
    }
  },
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  location: { 
    type: String, 
    required: true,
    enum: ['digital', 'traditional'],
    default: 'digital'
  },
  dimensions: {
    height: { type: Number, min: 1 },
    width: { type: Number, min: 1 }
  },
  createdAt: { 
    type: Date, 
    default: Date.now,
    immutable: true
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Update timestamp on save
photoSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model("Photo", photoSchema);