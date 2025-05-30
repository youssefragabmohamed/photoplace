const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const Photo = require('../models/photo');
const User = require('../models/user');
const authMiddleware = require('../middleware/auth');
const Notification = require('../models/notification');
const rateLimit = require('express-rate-limit');

// File Upload Configuration with better error handling
const uploadsDir = path.join(process.cwd(), "uploads");
try {
  if (!fs.existsSync(uploadsDir)) {
    // Create directory with full permissions
    fs.mkdirSync(uploadsDir, { recursive: true });
    // Explicitly set permissions after creation
    fs.chmodSync(uploadsDir, 0o777);
    console.log("✅ Created uploads directory with full permissions:", uploadsDir);
  } else {
    // Ensure existing directory has correct permissions
    fs.chmodSync(uploadsDir, 0o777);
    console.log("✅ Updated uploads directory permissions:", uploadsDir);
  }
} catch (err) {
  console.error("❌ Failed to create/update uploads directory:", err);
}

// Multer configuration with enhanced error handling
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // Double check directory exists and is writable
    try {
      if (!fs.existsSync(uploadsDir)) {
        fs.mkdirSync(uploadsDir, { recursive: true });
        fs.chmodSync(uploadsDir, 0o777);
      }
      // Test write permissions
      fs.accessSync(uploadsDir, fs.constants.W_OK);
      cb(null, uploadsDir);
    } catch (err) {
      console.error("❌ Upload directory error:", err);
      cb(new Error("Upload directory is not writable"));
    }
  },
  filename: (req, file, cb) => {
    try {
      const safeName = `${Date.now()}-${file.originalname.replace(/[^a-zA-Z0-9.]/g, '-')}`;
      cb(null, safeName);
    } catch (err) {
      cb(new Error("Failed to generate safe filename"));
    }
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`Invalid file type. Only ${allowedTypes.join(', ')} are allowed`), false);
    }
  }
});

// Rate limiting configuration
const searchLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    message: 'Too many search requests, please try again later',
    error: 'RATE_LIMIT_EXCEEDED'
  }
});

// Cache configuration for frequently searched queries
const searchCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// Sanitize search query
const sanitizeSearchQuery = (query) => {
  // Remove any MongoDB operators or special characters
  return query.replace(/[${}()]/g, '').trim();
};

// Get all photos
router.get('/', authMiddleware, async (req, res) => {
  try {
    let query = {};
    if (req.query.location && req.query.location !== 'all') {
      query.location = req.query.location;
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 12;
    const skip = (page - 1) * limit;

    const [photos, total] = await Promise.all([
      Photo.find(query)
        .populate('userId', 'username profilePic')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      Photo.countDocuments(query)
    ]);

    if (!photos) {
      return res.status(200).json({
        photos: [],
        page,
        totalPages: 0,
        hasMore: false
      });
    }

    res.status(200).json({
      photos,
      page,
      totalPages: Math.ceil(total / limit),
      hasMore: page * limit < total
    });
  } catch (err) {
    console.error("Photos error:", err);
    res.status(500).json({
      message: "Failed to fetch photos",
      error: err.message
    });
  }
});

// Upload photo with enhanced error handling
router.post('/upload', authMiddleware, (req, res, next) => {
  console.log('Starting upload process...');
  upload.single('photo')(req, res, (err) => {
    if (err) {
      console.error('Multer error:', err);
      return res.status(400).json({
        message: err.message || "File upload failed",
        error: err
      });
    }
    next();
  });
}, async (req, res) => {
  try {
    // Log the full request details
    console.log('Upload request received:', {
      file: req.file ? {
        filename: req.file.filename,
        mimetype: req.file.mimetype,
        size: req.file.size,
        path: req.file.path
      } : 'missing',
      body: req.body,
      userId: req.userId
    });

    if (!req.file) {
      return res.status(400).json({ 
        message: "No file uploaded",
        details: "The request must include a file in the 'photo' field"
      });
    }

    // Verify file exists on disk
    try {
      await fs.promises.access(req.file.path, fs.constants.F_OK);
      console.log('File successfully saved to disk:', req.file.path);
    } catch (err) {
      throw new Error(`File was not properly saved to disk: ${err.message}`);
    }

    if (!req.body.title) {
      // Clean up the uploaded file
      try {
        fs.unlinkSync(req.file.path);
        console.log('Cleaned up file due to missing title');
      } catch (unlinkErr) {
        console.error("Failed to clean up file after title validation:", unlinkErr);
      }
      return res.status(400).json({ 
        message: "Title is required",
        details: "Please provide a title for the photo"
      });
    }

    const photoUrl = `/uploads/${req.file.filename}`;
    console.log('Generated photo URL:', photoUrl);

    const photo = new Photo({
      title: req.body.title,
      description: req.body.description || "",
      url: photoUrl,
      userId: req.userId,
      location: req.body.location || 'digital'
    });

    // Log the photo object before saving
    console.log('Attempting to save photo:', JSON.stringify(photo, null, 2));

    const savedPhoto = await photo.save();
    console.log('Photo saved to database:', savedPhoto._id);

    // Populate user data more carefully
    const populatedPhoto = await Photo.findById(savedPhoto._id)
      .populate({
        path: 'userId',
        select: 'username profilePic followers following savedPhotos',
        options: { lean: true }
      })
      .lean();

    if (!populatedPhoto) {
      throw new Error('Failed to retrieve saved photo');
    }

    // Ensure arrays exist
    if (!populatedPhoto.userId) {
      populatedPhoto.userId = { username: 'Unknown', profilePic: '/default-profile.jpg' };
    }
    
    // Add counts manually to avoid virtual field issues
    populatedPhoto.userId.followersCount = populatedPhoto.userId.followers?.length || 0;
    populatedPhoto.userId.followingCount = populatedPhoto.userId.following?.length || 0;

    // Remove arrays from response to avoid undefined length issues
    delete populatedPhoto.userId.followers;
    delete populatedPhoto.userId.following;
    delete populatedPhoto.userId.savedPhotos;

    // Log successful upload
    console.log('Upload completed successfully:', {
      photoId: savedPhoto._id,
      url: photoUrl,
      userId: req.userId
    });

    res.status(201).json({ 
      photo: populatedPhoto,
      message: "Photo uploaded successfully"
    });
  } catch (err) {
    console.error("Upload error details:", {
      error: err.message,
      stack: err.stack,
      userId: req?.userId,
      file: req?.file
    });
    
    // Cleanup uploaded file if it exists
    if (req.file && req.file.path) {
      try {
        fs.unlinkSync(req.file.path);
        console.log("Cleaned up uploaded file after error");
      } catch (unlinkErr) {
        console.error("Failed to cleanup uploaded file:", unlinkErr);
      }
    }

    // Send detailed error response
    res.status(500).json({ 
      message: "Upload failed",
      error: err.message,
      details: process.env.NODE_ENV === 'development' ? {
        stack: err.stack,
        path: req?.file?.path,
        userId: req?.userId
      } : undefined
    });
  }
});

// Get user's photos
router.get('/user/:userId', authMiddleware, async (req, res) => {
  try {
    const query = { userId: req.params.userId };
    if (req.query.location) {
      query.location = req.query.location;
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 12;
    const skip = (page - 1) * limit;

    const [photos, total] = await Promise.all([
      Photo.find(query)
        .populate('userId', 'username profilePic')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit),
      Photo.countDocuments(query)
    ]);

    res.status(200).json({
      photos,
      page,
      totalPages: Math.ceil(total / limit),
      hasMore: page * limit < total
    });
  } catch (err) {
    res.status(500).json({
      message: "Failed to fetch user photos",
      error: err.message
    });
  }
});

// Get saved photos
router.get('/saved', authMiddleware, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 12;
    const skip = (page - 1) * limit;

    const user = await User.findById(req.userId)
      .populate({
        path: 'savedPhotos',
        options: {
          skip: skip,
          limit: limit,
          sort: { createdAt: -1 }
        },
        populate: {
          path: 'userId',
          select: 'username profilePic'
        }
      });

    if (!user) {
      console.error(`Saved photos error: User with ID ${req.userId} not found`);
      return res.status(404).json({ message: "User not found" });
    }

    const total = user.savedPhotos ? user.savedPhotos.length : 0;
    
    res.status(200).json({
      photos: user.savedPhotos || [],
      page,
      totalPages: Math.ceil(total / limit),
      hasMore: page * limit < total
    });
  } catch (err) {
    console.error("Saved photos error:", err);
    res.status(500).json({ 
      message: "Failed to fetch saved photos",
      error: err.message
    });
  }
});

// Save/unsave photo
router.post('/save/:photoId', authMiddleware, async (req, res) => {
  try {
    const photo = await Photo.findById(req.params.photoId).populate('userId');
    if (!photo) return res.status(404).json({ message: "Photo not found" });

    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    const alreadySaved = user.savedPhotos.includes(photo._id);
    
    if (alreadySaved) {
      user.savedPhotos = user.savedPhotos.filter(id => !id.equals(photo._id));
      await user.save();
      return res.status(200).json({ 
        message: "Photo removed from saved", 
        isSaved: false 
      });
    } else {
      user.savedPhotos.push(photo._id);
      await user.save();

      // Create notification
      if (photo.userId._id.toString() !== req.userId) {
        const notification = new Notification({
          userId: photo.userId._id,
          type: 'save',
          fromUser: req.userId,
          photoId: photo._id,
          message: `${user.username} saved your photo "${photo.title}"`
        });
        await notification.save();

        // Send real-time notification
        const io = req.app.get('io');
        const connectedUsers = req.app.get('connectedUsers');
        const ownerSocketId = connectedUsers.get(photo.userId._id.toString());
        
        if (ownerSocketId) {
          io.to(ownerSocketId).emit('notification', {
            ...notification.toObject(),
            fromUser: {
              _id: user._id,
              username: user.username,
              profilePic: user.profilePic
            }
          });
        }
      }

      return res.status(200).json({ 
        message: "Photo saved successfully", 
        isSaved: true 
      });
    }
  } catch (err) {
    res.status(500).json({ 
      message: "Failed to save photo", 
      error: err.message 
    });
  }
});

// Like/unlike photo
router.post('/like/:photoId', authMiddleware, async (req, res) => {
  try {
    const photo = await Photo.findById(req.params.photoId).populate('userId');
    if (!photo) return res.status(404).json({ message: "Photo not found" });

    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    const alreadyLiked = photo.likes.includes(req.userId);
    
    if (alreadyLiked) {
      photo.likes = photo.likes.filter(id => !id.equals(req.userId));
      await photo.save();
      return res.status(200).json({ 
        message: "Photo unliked", 
        isLiked: false,
        likes: photo.likes.length
      });
    } else {
      photo.likes.push(req.userId);
      await photo.save();

      // Create notification
      if (photo.userId._id.toString() !== req.userId) {
        const notification = new Notification({
          userId: photo.userId._id,
          type: 'like',
          fromUser: req.userId,
          photoId: photo._id,
          message: `${user.username} liked your photo "${photo.title}"`
        });
        await notification.save();

        // Send real-time notification
        const io = req.app.get('io');
        const connectedUsers = req.app.get('connectedUsers');
        const ownerSocketId = connectedUsers.get(photo.userId._id.toString());
        
        if (ownerSocketId) {
          io.to(ownerSocketId).emit('notification', {
            ...notification.toObject(),
            fromUser: {
              _id: user._id,
              username: user.username,
              profilePic: user.profilePic
            }
          });
        }
      }

      return res.status(200).json({ 
        message: "Photo liked", 
        isLiked: true,
        likes: photo.likes.length
      });
    }
  } catch (err) {
    res.status(500).json({ 
      message: "Failed to like photo", 
      error: err.message 
    });
  }
});

// Delete photo
router.delete('/:photoId', authMiddleware, async (req, res) => {
  try {
    const photo = await Photo.findOneAndDelete({ 
      _id: req.params.photoId,
      userId: req.userId
    });

    if (!photo) {
      return res.status(404).json({ message: "Photo not found or unauthorized" });
    }

    try {
      const filename = photo.url.split('/').pop();
      const filePath = path.join(uploadsDir, filename);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    } catch (fileErr) {
      console.error("File deletion error:", fileErr);
    }

    res.status(200).json({ message: "Photo deleted successfully" });
  } catch (err) {
    res.status(500).json({ 
      message: "Failed to delete photo", 
      error: err.message 
    });
  }
});

// Get single photo
router.get('/:photoId', authMiddleware, async (req, res) => {
  try {
    const photo = await Photo.findById(req.params.photoId)
      .populate('userId', 'username profilePic');
    
    if (!photo) {
      return res.status(404).json({ message: "Photo not found" });
    }

    res.status(200).json(photo);
  } catch (err) {
    res.status(500).json({
      message: "Failed to fetch photo",
      error: err.message
    });
  }
});

// Search photos with rate limiting and caching
router.get('/search', authMiddleware, searchLimiter, async (req, res) => {
  try {
    const { query, location, sortBy = 'recent' } = req.query;
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(20, Math.max(1, parseInt(req.query.limit) || 12));
    const skip = (page - 1) * limit;

    // Validate query length if provided
    if (query && (query.length < 2 || query.length > 50)) {
      return res.status(400).json({
        message: 'Search query must be between 2 and 50 characters'
      });
    }

    // Validate location
    const validLocations = ['all', 'digital', 'nature', 'urban', 'studio'];
    if (location && !validLocations.includes(location)) {
      return res.status(400).json({
        message: 'Invalid location filter'
      });
    }

    // Validate sort option
    const validSortOptions = ['recent', 'likes', 'oldest'];
    if (!validSortOptions.includes(sortBy)) {
      return res.status(400).json({
        message: 'Invalid sort option'
      });
    }

    // Generate cache key
    const cacheKey = JSON.stringify({
      query: query || '',
      location: location || 'all',
      sortBy,
      page,
      limit
    });

    // Check cache
    const cachedResult = searchCache.get(cacheKey);
    if (cachedResult) {
      return res.status(200).json(cachedResult);
    }

    // Build search query
    let searchQuery = {};
    
    if (query) {
      const sanitizedQuery = sanitizeSearchQuery(query);
      searchQuery.$or = [
        { title: { $regex: sanitizedQuery, $options: 'i' } },
        { description: { $regex: sanitizedQuery, $options: 'i' } }
      ];
    }

    if (location && location !== 'all') {
      searchQuery.location = location;
    }

    // Build sort options
    let sortOptions = {};
    switch (sortBy) {
      case 'likes':
        sortOptions = { 'likes.length': -1, createdAt: -1 };
        break;
      case 'oldest':
        sortOptions = { createdAt: 1 };
        break;
      default:
        sortOptions = { createdAt: -1 };
    }

    try {
      const [photos, total] = await Promise.all([
        Photo.find(searchQuery)
          .populate('userId', 'username profilePic')
          .sort(sortOptions)
          .skip(skip)
          .limit(limit)
          .lean()
          .maxTimeMS(5000), // Set maximum execution time
        Photo.countDocuments(searchQuery)
      ]);

      const result = {
        photos,
        page,
        totalPages: Math.ceil(total / limit),
        hasMore: page * limit < total,
        total,
        query: query || '',
        location: location || 'all',
        sortBy
      };

      // Cache the result
      searchCache.set(cacheKey, result);
      setTimeout(() => searchCache.delete(cacheKey), CACHE_TTL);

      res.status(200).json(result);
    } catch (dbError) {
      console.error('Database query error:', dbError);
      throw new Error('Failed to search photos');
    }
  } catch (err) {
    console.error("Search error:", err);
    res.status(500).json({
      message: err.message || "Failed to search photos",
      error: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
  }
});

module.exports = router; 