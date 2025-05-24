require('dotenv').config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const morgan = require("morgan");
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const cookieParser = require("cookie-parser");
const connectDB = require("./db");
const Photo = require("./models/photo.js");
const User = require("./models/user.js");

// Import user routes
const userRoutes = require('./routes/users');

const app = express();
const PORT = process.env.PORT || 5000;

// Validate required environment variables
const requiredEnvVars = ['JWT_SECRET', 'MONGODB_URI'];
requiredEnvVars.forEach(varName => {
  if (!process.env[varName]) {
    console.error(`❌ Missing required environment variable: ${varName}`);
    process.exit(1);
  }
});

// Database Connection
mongoose.connection.on('connected', () => console.log('✅ MongoDB Connected'));
mongoose.connection.on('error', (err) => console.error('❌ MongoDB Error:', err));
process.on('SIGINT', async () => {
  await mongoose.connection.close();
  process.exit(0);
});

// Enhanced CORS Configuration
const allowedOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim()) 
  : [
      "https://frontend-photoplace.vercel.app", // Corrected URL with hyphen
      "http://localhost:3000" // Local development
    ];

console.log("Allowed Origins:", allowedOrigins);

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.error('CORS Error: Origin not allowed -', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'], // Include OPTIONS
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'], // Allowed headers
  optionsSuccessStatus: 200 // For legacy browsers
};

// Apply CORS middleware to all routes
app.use(cors(corsOptions));

// Explicit preflight handling
app.options('*', cors(corsOptions));

// Enhanced Security Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https://*.onrender.com"],
      connectSrc: ["'self'", ...allowedOrigins],
    }
  },
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

app.use(cookieParser());
app.use(rateLimit({ 
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: "Too many requests from this IP, please try again later"
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(morgan("dev"));

// Force HTTPS in production
app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production' && req.headers['x-forwarded-proto'] !== 'https') {
    return res.redirect(`https://${req.headers.host}${req.url}`);
  }
  next();
});

// File Upload Configuration with better error handling
const uploadsDir = path.join(process.cwd(), "uploads");
if (!fs.existsSync(uploadsDir)) {
  try {
    fs.mkdirSync(uploadsDir, { recursive: true });
    console.log("✅ Created uploads directory");
  } catch (err) {
    console.error("❌ Failed to create uploads directory:", err);
    process.exit(1);
  }
}

// File Upload Configuration without file size limitations
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, uploadsDir);
    },
    filename: (req, file, cb) => {
      const safeName = `${Date.now()}-${file.originalname.replace(/[^a-zA-Z0-9.]/g, '-')}`;
      cb(null, safeName);
    }
  }),
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`Invalid file type. Only ${allowedTypes.join(', ')} are allowed`), false);
    }
  }
});

// Serve static files with proper CORS headers
app.use('/uploads', express.static(uploadsDir, {
  setHeaders: (res, path) => {
    res.set('Access-Control-Allow-Origin', allowedOrigins.join(', '));
    res.set('Cross-Origin-Resource-Policy', 'cross-origin');
    res.set('Cache-Control', 'public, max-age=31536000, immutable');
  }
}));

// Health check endpoint
app.get('/healthcheck', (req, res) => {
  res.status(200).json({ 
    status: 'healthy',
    uploadsDirExists: fs.existsSync(uploadsDir),
  });
});

// Auth Middleware
const authMiddleware = (req, res, next) => {
  if (req.method === 'OPTIONS') {
    return next();
  }
  
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: "Authentication required" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid or expired token" });
  }
};

// ========== ROUTES ========== //

// Session Endpoint
app.get("/api/auth/session", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) return res.status(404).json({ message: "User not found" });
    res.status(200).json({ user });
  } catch (err) {
    res.status(500).json({ message: "Session check failed", error: err.message });
  }
});

// Logout Endpoint
app.post("/api/auth/logout", authMiddleware, (req, res) => {
  try {
    res.clearCookie('token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
      domain: process.env.COOKIE_DOMAIN || '.onrender.com'
    });
    res.status(200).json({ message: "Logged out successfully" });
  } catch (err) {
    res.status(500).json({ 
      message: "Logout failed", 
      error: err.message 
    });
  }
});

// Profile Endpoint (NEW)
app.get("/api/profile/:userId", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId).select('-password');
    if (!user) return res.status(404).json({ message: "User not found" });
    
    const photos = await Photo.find({ userId: req.params.userId });
    
    res.status(200).json({
      user,
      photosCount: photos.length,
      joined: user.createdAt
    });
  } catch (err) {
    res.status(500).json({ 
      message: "Failed to fetch profile", 
      error: err.message 
    });
  }
});

// Auth Routes
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // Validate input
    if (!username || !email || !password) {
      return res.status(400).json({ 
        success: false,
        message: "All fields required" 
      });
    }

    // Check for existing user
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(409).json({ 
        success: false,
        message: "User already exists" 
      });
    }

    // Create new user
    const user = new User({
      username,
      email,
      password: await bcrypt.hash(password, 12)
    });

    await user.save();

    // Generate token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { 
      expiresIn: '7d' 
    });
    
    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
      maxAge: 604800000,
      domain: process.env.COOKIE_DOMAIN || '.onrender.com'
    });

    // Send response
    res.status(201).json({ 
      success: true,
      token, 
      user: { 
        _id: user._id, 
        username: user.username, 
        email: user.email 
      },
      message: "Registration successful"
    });
    
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ 
      success: false,
      message: "Registration failed", 
      error: err.message,
      stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
  }
});

// Login Endpoint
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
      maxAge: 604800000,
      domain: process.env.COOKIE_DOMAIN || '.onrender.com'
    });

    res.status(200).json({ 
      token,
      user: {
        _id: user._id,
        username: user.username,
        email: user.email
      }
    });
  } catch (err) {
    res.status(500).json({ 
      message: "Login failed", 
      error: err.message 
    });
  }
});

// Photo Upload with enhanced error handling
app.post("/api/photos/upload", authMiddleware, upload.single('photo'), async (req, res) => {
  try {
    console.log('Upload request received - File:', req.file);
    console.log('Upload request received - Body:', req.body);

    // Check if a file was uploaded
    if (!req.file) {
      return res.status(400).json({ 
        message: "No file uploaded",
        details: {
          allowedTypes: ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
        }
      });
    }

    // Ensure required fields are present
    if (!req.body.title) {
      try {
        if (req.file) fs.unlinkSync(req.file.path); // Cleanup uploaded file if title is missing
      } catch (cleanupErr) {
        console.error("Cleanup error:", cleanupErr);
      }
      return res.status(400).json({ 
        message: "Title is required",
        details: "Include a title in your form data"
      });
    }

    // Parse other fields from the form data
    const { title, description, location } = req.body;
    
    // Generate the photo URL
    const photoUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
    
    // Create a new photo document
    const photo = new Photo({
      title,
      description: description || "",
      url: photoUrl,
      userId: req.userId,
      location: location || 'digital'
    });

    await photo.save();
    
    // Populate user data in the response
    const populatedPhoto = await Photo.findById(photo._id)
      .populate('userId', 'username profilePic');
    
    res.status(201).json({ 
      success: true,
      photo: populatedPhoto,
      message: "Photo uploaded successfully"
    });
  } catch (err) {
    console.error("Upload Error:", err);
    
    // Cleanup the uploaded file in case of an error
    try {
      if (req.file && fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }
    } catch (cleanupErr) {
      console.error("File cleanup failed:", cleanupErr);
    }

    res.status(500).json({ 
      message: "Upload failed", 
      error: err.message,
      details: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
  }
});

// Get all photos for gallery with optional location filter
app.get("/api/photos", authMiddleware, async (req, res) => {
  try {
    const photos = await Photo.find({})
      .populate('userId', 'username profilePic')
      .sort({ createdAt: -1 });
    
    res.status(200).json(photos || []);
  } catch (err) {
    console.error("Photos error:", err);
    res.status(500).json({
      message: "Failed to fetch photos",
      error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

// Get photos by user ID with optional location filter
app.get("/api/photos/user/:userId", authMiddleware, async (req, res) => {
  try {
    const query = { userId: req.params.userId };
    
    // Add location filter if provided in query params
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

// Follow User Route
app.post("/api/follow/:userId", authMiddleware, async (req, res) => {
  try {
    const targetUser = await User.findById(req.params.userId);
    if (!targetUser) return res.status(404).json({ message: "User not found" });

    const currentUser = await User.findById(req.userId);
    if (targetUser._id.equals(currentUser._id)) {
      return res.status(400).json({ message: "You cannot follow yourself" });
    }

    // Add user to followers and following
    if (!targetUser.followers.includes(currentUser._id)) {
      targetUser.followers.push(currentUser._id);
      currentUser.following.push(targetUser._id);

      await targetUser.save();
      await currentUser.save();

      res.status(200).json({ message: "Followed user successfully" });
    } else {
      res.status(400).json({ message: "Already following this user" });
    }
  } catch (err) {
    res.status(500).json({ message: "Failed to follow user", error: err.message });
  }
});

// Unfollow User Route
app.post("/api/unfollow/:userId", authMiddleware, async (req, res) => {
  try {
    const targetUser = await User.findById(req.params.userId);
    if (!targetUser) return res.status(404).json({ message: "User not found" });

    const currentUser = await User.findById(req.userId);

    // Remove user from followers and following
    if (targetUser.followers.includes(currentUser._id)) {
      targetUser.followers = targetUser.followers.filter(id => !id.equals(currentUser._id));
      currentUser.following = currentUser.following.filter(id => !id.equals(targetUser._id));

      await targetUser.save();
      await currentUser.save();

      res.status(200).json({ message: "Unfollowed user successfully" });
    } else {
      res.status(400).json({ message: "You are not following this user" });
    }
  } catch (err) {
    res.status(500).json({ message: "Failed to unfollow user", error: err.message });
  }
});

// Profile Endpoint (with following and followers count)
app.get("/api/profile/:userId", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId).select('-password');
    if (!user) return res.status(404).json({ message: "User not found" });

    const photos = await Photo.find({ userId: req.params.userId });

    const isFollowing = user.followers.includes(req.userId);

    res.status(200).json({
      user,
      isFollowing,
      followersCount: user.followers.length,
      followingCount: user.following.length,
      photosCount: photos.length,
      joined: user.createdAt
    });
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch profile", error: err.message });
  }
});

// Delete Photo by ID
app.delete("/api/photos/:photoId", authMiddleware, async (req, res) => {
  try {
    const photo = await Photo.findOneAndDelete({ 
      _id: req.params.photoId,
      userId: req.userId // Ensure user can only delete their own photos
    });

    if (!photo) {
      return res.status(404).json({ message: "Photo not found or unauthorized" });
    }

    // Delete the actual file from uploads directory
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

// Get single photo by ID
app.get("/api/photos/:photoId", authMiddleware, async (req, res) => {
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

// Save Photo Route
app.post("/api/photos/save/:photoId", authMiddleware, async (req, res) => {
  try {
    const photo = await Photo.findById(req.params.photoId);
    if (!photo) return res.status(404).json({ message: "Photo not found" });

    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    // Check if already saved
    const alreadySaved = user.savedPhotos.includes(photo._id);
    
    if (alreadySaved) {
      // Remove from saved
      user.savedPhotos = user.savedPhotos.filter(id => !id.equals(photo._id));
      await user.save();
      return res.status(200).json({ 
        message: "Photo removed from saved", 
        isSaved: false 
      });
    } else {
      // Add to saved
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

// Get Saved Photos Route
app.get("/api/photos/saved", authMiddleware, async (req, res) => {
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
      return res.status(404).json({ message: "User not found" });
    }
    
    res.status(200).json(user.savedPhotos || []);
  } catch (err) {
    console.error("Saved photos error:", err);
    res.status(500).json({ 
      message: "Failed to fetch saved photos",
      error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

// Use user routes
app.use('/api/users', userRoutes);

// Update profile route (including profile picture)
app.patch("/api/profile/update/:userId", authMiddleware, upload.single('profilePic'), async (req, res) => {
  try {
    const updates = {};
    
    if (req.file) {
      updates.profilePic = `https://${req.get('host')}/uploads/${req.file.filename}`;
    }
    if (req.body.bio) updates.bio = req.body.bio;
    if (req.body.link) updates.link = req.body.link;
    if (req.body.portfolioTitle) updates.portfolioTitle = req.body.portfolioTitle;
    if (req.body.portfolioDescription) updates.portfolioDescription = req.body.portfolioDescription;

    const user = await User.findByIdAndUpdate(
      req.params.userId,
      updates,
      { new: true }
    ).select('-password');

    if (!user) return res.status(404).json({ message: "User not found" });

    res.status(200).json(user);
  } catch (err) {
    res.status(500).json({ 
      message: "Failed to update profile", 
      error: err.message 
    });
  }
});

// Add to portfolio
app.post("/api/profile/portfolio/:photoId", authMiddleware, async (req, res) => {
  try {
    const photo = await Photo.findById(req.params.photoId);
    if (!photo) {
      return res.status(404).json({ message: "Photo not found" });
    }

    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Check ownership
    if (!photo.userId.equals(req.userId)) {
      return res.status(403).json({ message: "You can only add your own photos to portfolio" });
    }

    // Check if already in portfolio
    if (user.portfolio.some(item => item.photoId.equals(photo._id))) {
      return res.status(400).json({ message: "Photo already in portfolio" });
    }

    user.portfolio.push({
      photoId: photo._id,
      url: photo.url,
      title: photo.title,
      description: photo.description || ""
    });

    await user.save();
    
    // Return updated user with populated portfolio
    const updatedUser = await User.findById(req.userId)
      .populate({
        path: 'portfolio.photoId',
        select: 'title url description'
      });
    
    res.status(200).json(updatedUser);
  } catch (err) {
    res.status(500).json({ 
      message: "Failed to add to portfolio", 
      error: err.message 
    });
  }
});

// Remove from portfolio
app.delete("/api/profile/portfolio/:photoId", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    user.portfolio = user.portfolio.filter(
      item => !item.photoId.equals(req.params.photoId)
    );

    await user.save();
    res.status(200).json({ message: "Removed from portfolio" });
  } catch (err) {
    res.status(500).json({ 
      message: "Failed to remove from portfolio", 
      error: err.message 
    });
  }
});


// Enhanced Error Handling
app.use((req, res) => res.status(404).json({ 
  message: "Endpoint not found",
  availableEndpoints: [
    '/api/auth/signup',
    '/api/auth/login',
    '/api/photos',
    '/api/profile/:userId'
  ]
}));

app.use((err, req, res, next) => {
  console.error("Server Error:", err.stack);
  
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({ 
        message: "File too large",
        details: "Maximum file size is 10MB"
      });
    }
    return res.status(400).json({ 
      message: "File upload error",
      error: err.message 
    });
  }
  
  if (err.message.includes('Invalid file type')) {
    return res.status(415).json({ 
      message: "Invalid file type",
      allowedTypes: ['image/jpeg', 'image/png', 'image/gif', 'image/webp']
    });
  }

  if (err.message.includes('CORS')) {
    return res.status(403).json({ 
      message: "CORS error",
      allowedOrigins,
      yourOrigin: req.headers.origin
    });
  }

  res.status(500).json({ 
    message: "Internal server error",
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// Start Server
connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🌐 Allowed origins: ${allowedOrigins.join(', ')}`);
    console.log(`🔒 Secure cookies: ${process.env.NODE_ENV === 'production'}`);
    console.log(`📁 Uploads directory: ${uploadsDir}`);
  });
}).catch(err => {
  console.error("❌ Failed to connect to MongoDB:", err);
  process.exit(1);
});