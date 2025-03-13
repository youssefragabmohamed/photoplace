const mongoose = require("mongoose");

// Define the User schema
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true, // Ensure username is unique
  },
  email: {
    type: String,
    required: true,
    unique: true, // Ensure email is unique
  },
  password: {
    type: String,
    required: true,
  },
  bio: {
    type: String,
    default: "", // Optional bio field
  },
  profilePicture: {
    type: String,
    default: "", // Optional profile picture URL
  },
}, { timestamps: true }); // Add timestamps for createdAt and updatedAt

// Create the User model
const User = mongoose.model("User", userSchema);

module.exports = User;