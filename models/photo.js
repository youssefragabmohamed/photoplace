const mongoose = require("mongoose");

const photoSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: String,
  url: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  height: Number, // made optional for Pinterest-style layout
  width: Number,  // made optional
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Photo", photoSchema);
