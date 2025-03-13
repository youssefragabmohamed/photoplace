const mongoose = require("mongoose");

const photoSchema = new mongoose.Schema({
  title: { type: String, required: true },
  url: { type: String, required: true },
  description: { type: String, default: "" },
}, { timestamps: true }); // Add timestamps to track creation and modification dates

const Photo = mongoose.model("Photo", photoSchema);

module.exports = Photo;
