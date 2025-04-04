// server.js
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

// Database Connection
mongoose.connection.on('connected', () => console.log('✅ MongoDB Connected'));
mongoose.connection.on('error', (err) => console.error('❌ MongoDB Error:', err));
process.on('SIGINT', async () => {
  await mongoose.connection.close();
  process.exit(0);
});

// Enhanced Security Middleware
app.use(helmet());
app.use(cookieParser());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 200 }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(morgan("dev"));

// CORS Configuration
const allowedOrigins = [
  "https://frontendphotoplace.vercel.app",
  "http://localhost:3000",
  process.env.FRONTEND_URL
].filter(Boolean);

app.use(cors({
  origin: allowedOrigins,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

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

app.use('/uploads', express.static(uploadsDir));

// Auth Middleware
const authMiddleware = (req, res, next) => {
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

// Routes
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
      domain: process.env.COOKIE_DOMAIN || undefined
    });

    res.status(201).json({ token, user: { _id: user._id, username: user.username, email: user.email } });
  } catch (err) {
    res.status(500).json({ message: "Registration failed", error: err.message });
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
      domain: process.env.COOKIE_DOMAIN || undefined
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

// Updated Upload Endpoint
app.post("/api/photos/upload", authMiddleware, upload.single('photo'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: "No file uploaded" });
    if (!req.body.title) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ message: "Title is required" });
    }

    const photo = new Photo({
      title: req.body.title,
      description: req.body.description || "",
      url: `/uploads/${req.file.filename}`,
      userId: req.userId
    });

    await photo.save();
    await User.findByIdAndUpdate(req.userId, { $inc: { photosCount: 1 } });

    res.status(201).json({
      photo: {
        ...photo.toObject(),
        url: `${process.env.BASE_URL || `http://localhost:${PORT}`}${photo.url}`
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

// Error Handling
app.use((req, res) => res.status(404).json({ message: "Endpoint not found" }));
app.use((err, req, res, next) => {
  console.error("Error:", err.stack);
  res.status(500).json({ message: "Internal server error" });
});

connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🌐 Allowed origins: ${allowedOrigins.join(', ')}`);
  });
});