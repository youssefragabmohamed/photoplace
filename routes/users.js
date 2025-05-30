const express = require('express');
const User = require('../models/user');
const Photo = require('../models/photo');
const authMiddleware = require('../middleware/auth');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Configure multer for profile picture uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(process.cwd(), 'uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'profile-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
    if (!allowedTypes.includes(file.mimetype)) {
      const error = new Error('Invalid file type. Only JPEG, PNG and GIF are allowed.');
      error.code = 'INVALID_FILE_TYPE';
      return cb(error, false);
    }
    cb(null, true);
  }
});

// Get current user's profile with populated data
router.get('/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId)
      .select('-password')
      .populate('followers following savedPhotos');
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ user });
  } catch (error) {
    console.error('Get current user error:', error);
    res.status(500).json({ message: 'Error fetching user data' });
  }
});

// Get any user's profile
router.get('/:userId', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId)
      .select('-password -savedPhotos')
      .populate('followers following', 'username profilePic')
      .populate({
        path: 'portfolio.photoId',
        select: 'title url description'
      });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const photosCount = await Photo.countDocuments({ userId: req.params.userId });
    const isFollowing = user.followers.some(id => id.equals(req.userId));

    res.status(200).json({ 
      user,
      isFollowing,
      followersCount: user.followers.length,
      followingCount: user.following.length,
      photosCount
    });
  } catch (err) {
    res.status(500).json({ 
      message: "Failed to fetch profile", 
      error: err.message 
    });
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
      'portfolioTitle', 'portfolioDescription'
    ];
    
    const isValidOperation = updates.every(update => 
      allowedUpdates.includes(update)
    );

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
    res.status(500).json({ 
      message: "Update failed", 
      error: err.message 
    });
  }
});

// Delete profile
router.delete('/:userId', authMiddleware, async (req, res) => {
  try {
    if (req.params.userId !== req.userId) {
      return res.status(403).json({ message: "Unauthorized" });
    }

    const user = await User.findByIdAndDelete(req.params.userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Delete all user's photos
    await Photo.deleteMany({ userId: req.params.userId });

    res.status(200).json({ message: "User deleted successfully" });
  } catch (err) {
    res.status(500).json({ 
      message: "Delete failed", 
      error: err.message 
    });
  }
});

// Register User
router.post('/signup', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Check if user already exists
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Create new user
        user = new User({
            username,
            email,
            password
        });

        // Save user to database
        await user.save();

        // Create JWT token
        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });

        res.status(201).json({
            message: 'User created successfully',
            user: {
                id: user._id,
                username: user.username,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Error creating user' });
    }
});

// Login User
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Check password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Create token
        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });

        res.json({
            message: 'Logged in successfully',
            user: {
                id: user._id,
                username: user.username,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Error logging in' });
    }
});

// Get User Profile
router.get('/profile', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select('-password');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json(user);
    } catch (error) {
        console.error('Profile fetch error:', error);
        res.status(500).json({ message: 'Error fetching profile' });
    }
});

// Logout User
router.post('/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ message: 'Logged out successfully' });
});

// Update profile picture
router.post('/update-pic', authMiddleware, upload.single('profilePic'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: "No file uploaded" });
    }

    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Delete old profile picture if it exists
    if (user.profilePic && !user.profilePic.includes('default-profile.jpg')) {
      const oldPicPath = path.join(process.cwd(), 'uploads', path.basename(user.profilePic));
      if (fs.existsSync(oldPicPath)) {
        fs.unlinkSync(oldPicPath);
      }
    }

    // Update user's profile picture path
    const profilePicPath = `/uploads/${req.file.filename}`;
    user.profilePic = profilePicPath;
    await user.save();

    res.status(200).json({
      message: "Profile picture updated successfully",
      profilePic: profilePicPath
    });
  } catch (err) {
    console.error('Profile picture update error:', err);
    res.status(500).json({ 
      message: "Failed to update profile picture", 
      error: err.message 
    });
  }
});

// Search users
router.get('/search', authMiddleware, async (req, res) => {
  try {
    const { query } = req.query;
    const page = Math.max(1, parseInt(req.query.page) || 1); // Ensure page is at least 1
    const limit = Math.min(20, Math.max(1, parseInt(req.query.limit) || 20)); // Limit between 1 and 20
    const skip = (page - 1) * limit;

    // Validate query length if provided
    if (query && (query.length < 2 || query.length > 50)) {
      return res.status(400).json({
        message: 'Search query must be between 2 and 50 characters'
      });
    }

    let searchQuery = {};
    if (query) {
      searchQuery = {
        $or: [
          { username: { $regex: query, $options: 'i' } },
          { name: { $regex: query, $options: 'i' } }
        ]
      };
    }

    const [users, total] = await Promise.all([
      User.find(searchQuery)
        .select('username name profilePic bio followers following')
        .skip(skip)
        .limit(limit)
        .lean(),
      User.countDocuments(searchQuery)
    ]).catch(err => {
      throw new Error('Database query failed');
    });

    // Add follower counts and remove sensitive data
    const sanitizedUsers = users.map(user => ({
      ...user,
      followersCount: user.followers?.length || 0,
      followingCount: user.following?.length || 0,
      followers: undefined,
      following: undefined
    }));

    res.json({
      users: sanitizedUsers,
      page,
      totalPages: Math.ceil(total / limit),
      hasMore: page * limit < total,
      total
    });
  } catch (err) {
    console.error('User search error:', err);
    res.status(500).json({
      message: 'Failed to search users',
      error: err.message
    });
  }
});

module.exports = router;