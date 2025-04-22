const mongoose = require("mongoose");

const photoSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: String,
  url: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  location: { 
    type: String, 
    required: true,
    enum: ['digital', 'traditional'], // Only allow these values
    default: 'digital'
  },
  height: Number,
  width: Number,
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Photo", photoSchema);