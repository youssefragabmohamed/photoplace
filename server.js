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
const sizeOf = require('image-size');
const cookieParser = require("cookie-parser");
const connectDB = require("./db");
const Photo = require("./models/photo.js");
const User = require("./models/user.js");

const app = express();
const PORT = process.env.PORT || 5000;

// Database Connection
mongoose.connection.on('connected', () => console.log('✅ MongoDB Connected'));
mongoose.connection.on('error', (err) => console.error('❌ MongoDB Error:', err));
process.on('SIGINT', async () => {
  await mongoose.connection.close();
  process.exit(0);
});

// Enhanced Security Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https://*.onrender.com"],
      connectSrc: ["'self'", process.env.ALLOWED_ORIGINS].filter(Boolean)
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

// CORS Configuration
const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || [];

const corsOptions = {
  origin: function (origin, callback) {
    if (process.env.NODE_ENV === 'development' || !origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  exposedHeaders: ['set-cookie'],
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// File Upload Configuration
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: uploadsDir,
    filename: (req, file, cb) => {
      const safeName = `${Date.now()}-${file.originalname.replace(/[^a-zA-Z0-9.]/g, '-')}`;
      cb(null, safeName);
    }
  }),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type'), false);
    }
  }
});

// Serve static files with proper CORS headers
app.use('/uploads', express.static(uploadsDir, {
  setHeaders: (res, path) => {
    res.set('Access-Control-Allow-Origin', allowedOrigins.join(', '));
    res.set('Cross-Origin-Resource-Policy', 'cross-origin');
    res.set('Cache-Control', 'public, max-age=31536000, immutable');
    res.set('Content-Security-Policy', 'upgrade-insecure-requests');
  }
}));

// Health check endpoint
app.get('/healthcheck', (req, res) => {
  res.status(200).json({ status: 'healthy' });
});

// Auth Middleware
const authMiddleware = (req, res, next) => {
  if (req.method === 'OPTIONS') return next();
  
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

// Auth Routes
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ message: "All fields required" });
    }

    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(409).json({ message: "User already exists" });
    }

    const user = new User({
      username,
      email,
      password: await bcrypt.hash(password, 12)
    });

    await user.save();

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
      maxAge: 604800000,
      domain: process.env.COOKIE_DOMAIN || '.onrender.com'
    });

    res.status(201).json({ 
      token, 
      user: { 
        _id: user._id, 
        username: user.username, 
        email: user.email 
      } 
    });
  } catch (err) {
    res.status(500).json({ message: "Registration failed", error: err.message });
  }
});

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
    res.status(500).json({ message: "Login failed", error: err.message });
  }
});

app.post("/api/auth/logout", authMiddleware, (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'none',
    domain: process.env.COOKIE_DOMAIN || '.onrender.com'
  });
  res.status(200).json({ message: "Logged out successfully" });
});

// Photo Endpoints
app.get("/api/photos", authMiddleware, async (req, res) => {
  try {
    const photos = await Photo.find({ userId: req.userId }).populate('userId', 'username');
    res.status(200).json(photos);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch photos", error: err.message });
  }
});

app.get("/api/photos/:id", authMiddleware, async (req, res) => {
  try {
    const photo = await Photo.findOne({
      _id: req.params.id,
      userId: req.userId
    }).populate('userId', 'username');

    if (!photo) {
      return res.status(404).json({ message: "Photo not found" });
    }

    res.status(200).json(photo);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch photo", error: err.message });
  }
});

app.post("/api/photos/upload", authMiddleware, upload.single('photo'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ 
        message: "No file uploaded",
        details: "Ensure you're sending the file with field name 'photo' in FormData"
      });
    }

    if (!req.body.title) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ 
        message: "Title is required",
        details: "Include a title in your form data"
      });
    }

    // Get image dimensions
    const dimensions = sizeOf(req.file.path);
    const photoUrl = `https://${req.get('host')}/uploads/${req.file.filename}`;
    
    const photo = new Photo({
      title: req.body.title,
      description: req.body.description || "",
      url: photoUrl,
      width: dimensions.width,
      height: dimensions.height,
      userId: req.userId
    });

    await photo.save();
    res.status(201).json({ 
      success: true,
      photo,
      message: "Photo uploaded successfully"
    });
  } catch (err) {
    if (req.file) fs.unlinkSync(req.file.path);
    res.status(500).json({ 
      message: "Upload failed", 
      error: err.message
    });
  }
});

app.delete("/api/photos/:id", authMiddleware, async (req, res) => {
  try {
    const photo = await Photo.findOne({ 
      _id: req.params.id,
      userId: req.userId 
    });

    if (!photo) {
      return res.status(404).json({ message: "Photo not found" });
    }

    const filename = photo.url.split('/uploads/')[1];
    const filePath = path.join(uploadsDir, filename);
    
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    await Photo.deleteOne({ _id: req.params.id });
    res.status(200).json({ message: "Photo deleted successfully" });
  } catch (err) {
    res.status(500).json({ message: "Failed to delete photo", error: err.message });
  }
});

// Error Handling
app.use((req, res) => res.status(404).json({ message: "Endpoint not found" }));
app.use((err, req, res, next) => {
  console.error("Server Error:", err.stack);
  
  if (err.message.includes('CORS')) {
    return res.status(403).json({ message: err.message });
  }
  
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ message: "File too large (max 10MB)" });
  }
  
  if (err.message.includes('Invalid file type')) {
    return res.status(415).json({ message: "Invalid file type" });
  }

  res.status(500).json({ message: "Internal server error" });
});

connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🌐 Allowed origins: ${allowedOrigins.join(', ')}`);
    console.log(`🔒 Secure cookies: ${process.env.NODE_ENV === 'production'}`);
  });
});