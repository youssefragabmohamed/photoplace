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
      "https://frontendphotoplace.vercel.app",
      "http://localhost:3000"
    ];

console.log("Allowed Origins:", allowedOrigins);

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

// Improved CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    console.log("Incoming Origin:", origin);
    
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.some(allowedOrigin => {
      // Compare origins directly or check if the request origin matches a pattern
      return origin === allowedOrigin || 
             origin.startsWith(allowedOrigin.replace('https://', 'http://')) ||
             origin.endsWith(`.${allowedOrigin.replace(/https?:\/\//, '')}`);
    })) {
      return callback(null, true);
    }
    
    console.error('CORS Error: Origin not allowed -', origin);
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  exposedHeaders: ['set-cookie'],
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

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
  limits: { 
    fileSize: 10 * 1024 * 1024,
    files: 1
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
    diskSpace: require('diskusage').checkSync(uploadsDir)
  });
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
    res.status(500).json({ 
      message: "Registration failed", 
      error: err.message,
      stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
  }
});

// [Other auth routes remain the same...]

// Photo Upload with enhanced error handling
app.post("/api/photos/upload", authMiddleware, upload.single('photo'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ 
        message: "No file uploaded",
        details: {
          allowedTypes: ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
          maxSize: "10MB"
        }
      });
    }

    if (!req.body.title) {
      try {
        if (req.file) fs.unlinkSync(req.file.path);
      } catch (cleanupErr) {
        console.error("Cleanup error:", cleanupErr);
      }
      return res.status(400).json({ 
        message: "Title is required",
        details: "Include a title in your form data"
      });
    }

    // Get image dimensions
    let dimensions;
    try {
      dimensions = sizeOf(req.file.path);
    } catch (err) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ 
        message: "Invalid image file",
        details: "The uploaded file is not a valid image"
      });
    }

    const photoUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
    
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
    console.error("Upload Error:", err);
    
    // Clean up uploaded file if error occurred
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

// Get all photos for gallery (authenticated)
app.get("/api/photos", authMiddleware, async (req, res) => {
  try {
    const photos = await Photo.find({})
      .populate('userId', 'username profilePic')
      .sort({ createdAt: -1 }); // Newest first

    res.status(200).json(photos);
  } catch (err) {
    res.status(500).json({
      message: "Failed to fetch gallery photos",
      error: err.message
    });
  }
});

// [Other photo routes remain the same...]

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