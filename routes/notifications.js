const express = require('express');
const router = express.Router();
const Notification = require('../models/notification');
const authMiddleware = require('../middleware/auth');

// Get notifications for user
router.get('/', authMiddleware, async (req, res) => {
  const notifications = await Notification.find({ userId: req.userId })
    .populate('fromUser', 'username profilePic')
    .populate('photoId')
    .populate('commentId')
    .sort({ createdAt: -1 });
  res.json(notifications);
});

// Mark as read
router.post('/:id/read', authMiddleware, async (req, res) => {
  await Notification.findByIdAndUpdate(req.params.id, { read: true });
  res.json({ read: true });
});

module.exports = router; 