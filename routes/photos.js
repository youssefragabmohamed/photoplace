const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const Photo = require('../models/photo');
const User = require('../models/user');
const authMiddleware = require('../middleware/auth');

// File Upload Configuration with better error handling
const uploadsDir = path.join(process.cwd(), "uploads");
try {
  if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true, mode: 0o755 });
    console.log("✅ Created uploads directory:", uploadsDir);
  }
} catch (err) {
  console.error("❌ Failed to create uploads directory:", err);
  // Don't exit process, let individual requests handle the error
}

// Multer configuration with error handling
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // Check if directory exists before trying to save
    if (!fs.existsSync(uploadsDir)) {
      return cb(new Error("Uploads directory not available"));
    }
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const safeName = `${Date.now()}-${file.originalname.replace(/[^a-zA-Z0-9.]/g, '-')}`;
    cb(null, safeName);
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

// Get all photos
router.get('/', authMiddleware, async (req, res) => {
  try {
    let query = {};
    if (req.query.location && req.query.location !== 'all') {
      query.location = req.query.location;
    }

    const photos = await Photo.find(query)
      .populate('userId', 'username profilePic')
      .sort({ createdAt: -1 })
      .lean();

    if (!photos) {
      return res.status(200).json([]);
    }

    res.status(200).json(photos);
  } catch (err) {
    console.error("Photos error:", err);
    res.status(500).json({
      message: "Failed to fetch photos",
      error: err.message
    });
  }
});

// Upload photo with enhanced error handling
router.post('/upload', authMiddleware, upload.single('photo'), async (req, res) => {
  try {
    console.log('Upload request received:', {
      file: req.file ? 'present' : 'missing',
      body: req.body
    });

    if (!req.file) {
      return res.status(400).json({ message: "No file uploaded" });
    }

    if (!req.body.title) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ message: "Title is required" });
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

    const savedPhoto = await photo.save();
    console.log('Photo saved to database:', savedPhoto._id);

    const populatedPhoto = await Photo.findById(savedPhoto._id)
      .populate('userId', 'username profilePic');

    res.status(201).json({ photo: populatedPhoto });
  } catch (err) {
    console.error("Upload error:", err);
    
    // Cleanup uploaded file if it exists
    if (req.file && fs.existsSync(req.file.path)) {
      try {
        fs.unlinkSync(req.file.path);
      } catch (unlinkErr) {
        console.error("Failed to cleanup uploaded file:", unlinkErr);
      }
    }

    res.status(500).json({ 
      message: "Upload failed",
      error: err.message,
      details: process.env.NODE_ENV === 'development' ? err.stack : undefined
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

    const photos = await Photo.find(query)
      .populate('userId', 'username profilePic')
      .sort({ createdAt: -1 });

    res.status(200).json(photos);
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
    const user = await User.findById(req.userId)
      .populate({
        path: 'savedPhotos',
        populate: {
          path: 'userId',
          select: 'username profilePic'
        }
      });

    if (!user) {
      console.error(`Saved photos error: User with ID ${req.userId} not found`);
      return res.status(404).json({ message: "User not found" });
    }
    
    res.status(200).json(user.savedPhotos || []);
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
    const photo = await Photo.findById(req.params.photoId);
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

module.exports = router; 