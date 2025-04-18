const mongoose = require("mongoose");

const photoSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  url: {
    type: String,
    required: true
  },
  description: {
    type: String,
    maxlength: 500
  },
  width: {  // ← NEW FIELD
    type: Number,
    required: true
  },
  height: {  // ← NEW FIELD
    type: Number,
    required: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  likes: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  createdAt: {
    type: Date,
    default: Date.now
  }
}, { timestamps: true });

// Indexes for better performance
photoSchema.index({ userId: 1 });
photoSchema.index({ createdAt: -1 });

module.exports = mongoose.model("Photo", photoSchema);