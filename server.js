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

const app = express();
const PORT = process.env.PORT || 5000;

// Enhanced Database Connection Events
mongoose.connection.on('connected', () => {
  console.log('✅ MongoDB Atlas Connected');
});

mongoose.connection.on('error', (err) => {
  console.error('❌ MongoDB Error:', err.message);
});

process.on('SIGINT', async () => {
  await mongoose.connection.close();
  console.log('MongoDB connection closed');
  process.exit(0);
});

// Security Middleware
app.use(helmet());
app.use(cookieParser());
app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // limit each IP to 200 requests per windowMs
  message: "Too many requests, please try again later"
}));

// Comprehensive CORS Configuration
const allowedOrigins = [
  "https://frontendphotoplace.vercel.app",
  "https://frontendphotoplace-git-main-youssefs-projects-bb475890.vercel.app",
  "http://localhost:3000",
  process.env.FRONTEND_URL
].filter(Boolean);

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`Origin ${origin} not allowed by CORS`));
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
  credentials: true,
  preflightContinue: false,
  optionsSuccessStatus: 204
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // Handle preflight requests

// Static Files Configuration
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}
app.use('/uploads', express.static(uploadsDir));

// Enhanced Body Parsing
app.use(express.json({
  limit: '10mb',
  verify: (req, res, buf) => {
    try {
      JSON.parse(buf.toString());
    } catch (e) {
      throw new Error('Invalid JSON payload');
    }
  }
}));

app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(morgan("dev"));

// Secure File Upload Configuration
const upload = multer({
  storage: multer.diskStorage({
    destination: uploadsDir,
    filename: (req, file, cb) => {
      const safeName = Date.now() + '-' + 
        file.originalname.replace(/[^a-zA-Z0-9.]/g, '-');
      cb(null, safeName);
    }
  }),
  limits: { 
    fileSize: 10 * 1024 * 1024, // 10MB
    files: 1
  },
  fileFilter: (req, file, cb) => {
    const allowedMimes = [
      'image/jpeg',
      'image/png',
      'image/gif',
      'image/webp'
    ];
    
    if (allowedMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only images are allowed.'));
    }
  }
}).single('photo');

// Database Connection
connectDB();

// Enhanced Auth Middleware
const authMiddleware = (req, res, next) => {
  const token = req.cookies.token || req.header('Authorization')?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ message: "Authentication required" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    res.status(401).json({ 
      message: "Invalid or expired token",
      error: err.message
    });
  }
};

// Health Check Route
app.get("/", (req, res) => {
  res.json({
    status: "running",
    apiVersion: "1.3.0",
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Authentication Routes
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { username, email, password, fullName } = req.body;
    
    if (!username || !email || !password) {
      return res.status(400).json({ 
        message: "All fields are required",
        fields: { username: !username, email: !email, password: !password }
      });
    }

    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(409).json({
        message: "User already exists",
        conflict: existingUser.username === username ? 'username' : 'email'
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = new User({ 
      username, 
      email, 
      password: hashedPassword,
      fullName: fullName || username
    });

    await user.save();

    const token = jwt.sign(
      { userId: user._id }, 
      process.env.JWT_SECRET, 
      { expiresIn: '7d' }
    );

    // Set HTTP-only cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.status(201).json({
      token,
      user: {
        _id: user._id,
        username: user.username,
        email: user.email,
        fullName: user.fullName,
        createdAt: user.createdAt
      }
    });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ 
      message: "Registration failed",
      error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { userId: user._id }, 
      process.env.JWT_SECRET, 
      { expiresIn: '7d' }
    );

    // Set HTTP-only cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({
      token,
      user: {
        _id: user._id,
        username: user.username,
        email: user.email,
        fullName: user.fullName,
        profilePic: user.profilePic
      }
    });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie('token');
  res.json({ message: "Logged out successfully" });
});

// Session Check Endpoint
app.get("/api/auth/session", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId)
      .select('-password')
      .lean();

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({ user });
  } catch (err) {
    res.status(500).json({ 
      message: "Session check failed",
      error: err.message 
    });
  }
});

// Profile Routes
app.get("/api/profile/:userId", async (req, res) => {
  try {
    const user = await User.findById(req.params.userId)
      .select('-password')
      .lean();

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const photosCount = await Photo.countDocuments({ userId: user._id });
    const followersCount = await User.countDocuments({ following: user._id });
    const followingCount = user.following ? user.following.length : 0;

    res.json({
      user: {
        ...user,
        photosCount,
        followersCount,
        followingCount
      }
    });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

app.get("/api/profile/:userId/photos", async (req, res) => {
  try {
    const photos = await Photo.find({ userId: req.params.userId })
      .sort({ createdAt: -1 })
      .lean();

    res.json(photos);
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Photo Routes
app.get("/api/photos", async (req, res) => {
  try {
    const photos = await Photo.find()
      .sort({ createdAt: -1 })
      .lean();

    res.json(photos);
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

app.post("/api/photos/upload", authMiddleware, (req, res) => {
  upload(req, res, async (err) => {
    try {
      if (err) throw err;
      if (!req.file) throw new Error("No file uploaded");

      const photo = new Photo({
        title: req.body.title,
        description: req.body.description,
        url: `/uploads/${req.file.filename}`,
        userId: req.userId
      });

      await photo.save();

      // Update user's photos count
      await User.findByIdAndUpdate(req.userId, {
        $inc: { photosCount: 1 }
      });

      res.status(201).json({
        photo: {
          ...photo.toObject(),
          url: `${process.env.BASE_URL}${photo.url}`
        }
      });
    } catch (err) {
      if (req.file) fs.unlinkSync(req.file.path);
      res.status(400).json({ 
        message: err.code === 'LIMIT_FILE_SIZE' 
          ? "File too large (max 10MB)" 
          : err.message 
      });
    }
  });
});

app.get("/api/photos/:id", async (req, res) => {
  try {
    const photo = await Photo.findById(req.params.id).lean();
    if (!photo) {
      return res.status(404).json({ message: "Photo not found" });
    }
    res.json(photo);
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

app.delete("/api/photos/:id", authMiddleware, async (req, res) => {
  try {
    const photo = await Photo.findOneAndDelete({ 
      _id: req.params.id, 
      userId: req.userId 
    });

    if (!photo) {
      return res.status(404).json({ message: "Photo not found or unauthorized" });
    }

    fs.unlinkSync(path.join(__dirname, photo.url));
    
    // Update user's photos count
    await User.findByIdAndUpdate(req.userId, {
      $inc: { photosCount: -1 }
    });

    res.status(204).end();
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Follow Routes
app.post("/api/follow/:userId", authMiddleware, async (req, res) => {
  try {
    if (req.params.userId === req.userId) {
      return res.status(400).json({ message: "Cannot follow yourself" });
    }

    const userToFollow = await User.findById(req.params.userId);
    if (!userToFollow) {
      return res.status(404).json({ message: "User not found" });
    }

    const currentUser = await User.findById(req.userId);
    if (currentUser.following.includes(req.params.userId)) {
      return res.status(400).json({ message: "Already following this user" });
    }

    await User.findByIdAndUpdate(req.userId, {
      $addToSet: { following: req.params.userId }
    });

    res.json({ message: "Successfully followed user" });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

app.post("/api/unfollow/:userId", authMiddleware, async (req, res) => {
  try {
    const currentUser = await User.findById(req.userId);
    if (!currentUser.following.includes(req.params.userId)) {
      return res.status(400).json({ message: "Not following this user" });
    }

    await User.findByIdAndUpdate(req.userId, {
      $pull: { following: req.params.userId }
    });

    res.json({ message: "Successfully unfollowed user" });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Enhanced Error Handling
app.use((req, res) => {
  res.status(404).json({ 
    message: "Endpoint not found",
    documentation: process.env.API_DOCS_URL 
  });
});

app.use((err, req, res, next) => {
  console.error("🚨 Error:", err.stack);
  
  if (err.message.includes('CORS')) {
    return res.status(403).json({ 
      message: "Cross-origin request denied",
      allowedOrigins
    });
  }

  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ 
      message: "File too large. Maximum size is 10MB." 
    });
  }

  res.status(500).json({ 
    message: "Internal server error",
    ...(process.env.NODE_ENV === 'development' && { 
      error: err.message,
      stack: err.stack 
    })
  });
});

// Server Startup
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌐 Allowed CORS origins: ${allowedOrigins.join(', ')}`);
  console.log(`🔗 Base URL: ${process.env.BASE_URL}`);
});