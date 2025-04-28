const express = require('express');
const User = require('../models/user');
const authMiddleware = require('../middleware/auth');
const router = express.Router();

// Get current user's profile
router.get('/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId)
      .select('-password')
      .populate('savedPhotos');
    res.status(200).json({ user });
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch profile", error: err.message });
  }
});

// Get any user's profile
router.get('/:userId', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId)
      .select('-password -savedPhotos')
      .populate('followers following', 'username profilePic');
    
    if (!user) return res.status(404).json({ message: "User not found" });

    const isFollowing = user.followers.some(id => id.equals(req.userId));
    res.status(200).json({ 
      user,
      isFollowing,
      followersCount: user.followers.length,
      followingCount: user.following.length
    });
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch profile", error: err.message });
  }
});

// Update profile
router.patch('/:userId', authMiddleware, async (req, res) => {
  try {
    if (req.params.userId !== req.userId) {
      return res.status(403).json({ message: "Unauthorized" });
    }

    const updates = Object.keys(req.body);
    const allowedUpdates = [
      'username', 'email', 'bio', 'link', 'location',
      'portfolio', 'portfolioTitle', 'portfolioDescription'
    ];
    const isValidOperation = updates.every(update => allowedUpdates.includes(update));

    if (!isValidOperation) {
      return res.status(400).json({ message: "Invalid updates!" });
    }

    const user = await User.findByIdAndUpdate(
      req.params.userId,
      req.body,
      { new: true, runValidators: true }
    ).select('-password');

    res.status(200).json({ user });
  } catch (err) {
    res.status(500).json({ message: "Update failed", error: err.message });
  }
});

// Delete profile
router.delete('/:userId', authMiddleware, async (req, res) => {
  try {
    if (req.params.userId !== req.userId) {
      return res.status(403).json({ message: "Unauthorized" });
    }

    const user = await User.findByIdAndDelete(req.params.userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    res.status(200).json({ message: "User deleted successfully" });
  } catch (err) {
    res.status(500).json({ message: "Delete failed", error: err.message });
  }
});

module.exports = router;