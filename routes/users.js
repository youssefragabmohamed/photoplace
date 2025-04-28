const express = require('express');
const User = require('../models/user');  // Make sure this path is correct based on your project structure
const authMiddleware = require('../middleware/auth');  // Adjust the path based on where your auth middleware is located
const router = express.Router();

// Route to get a user's profile (including bio and portfolio)
router.get('/:userId', authMiddleware, async (req, res) => {
  try {
    // Fetch the user by userId, excluding the password field
    const user = await User.findById(req.params.userId).select('-password');
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Return the user data
    res.status(200).json({ user });
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch user profile", error: err.message });
  }
});

// Route to update a user's profile (username, email, bio, portfolio, etc.)
router.put('/:userId', authMiddleware, async (req, res) => {
  try {
    // Ensure the logged-in user can only update their own profile
    if (req.params.userId !== req.userId) {
      return res.status(403).json({ message: "You can only update your own profile" });
    }

    const { username, email, bio, location, portfolio } = req.body;

    // Prepare the update object with fields that can be updated
    const updateFields = {};
    if (username) updateFields.username = username;
    if (email) updateFields.email = email;
    if (bio) updateFields.bio = bio;
    if (location) updateFields.location = location;
    if (portfolio && Array.isArray(portfolio)) updateFields.portfolio = portfolio;

    // Update the user data
    const user = await User.findByIdAndUpdate(
      req.params.userId,
      updateFields,
      { new: true }  // Return the updated user document
    ).select('-password');  // Exclude password from the response

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Return the updated user
    res.status(200).json({ user });
  } catch (err) {
    res.status(500).json({ message: "Failed to update user profile", error: err.message });
  }
});

// Route to delete a user's profile
router.delete('/:userId', authMiddleware, async (req, res) => {
  try {
    // Ensure the logged-in user can only delete their own profile
    if (req.params.userId !== req.userId) {
      return res.status(403).json({ message: "You can only delete your own profile" });
    }

    // Delete the user
    const user = await User.findByIdAndDelete(req.params.userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Return success message
    res.status(200).json({ message: "User deleted successfully" });
  } catch (err) {
    res.status(500).json({ message: "Failed to delete user", error: err.message });
  }
});

module.exports = router;
