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
const photoRoutes = require('./routes/photos');
const notificationsRouter = require('./routes/notifications');

const app = express();
const server = require('http').createServer(app);

// Trust proxy - required for rate limiting behind reverse proxies
app.set('trust proxy', 1);

// Enhanced CORS Configuration
const allowedOrigins = [
  "https://frontend-photoplace.vercel.app",
  "http://localhost:3000"
];

console.log("Allowed Origins:", allowedOrigins);

// Socket.IO setup with CORS
const io = require('socket.io')(server, {
  cors: {
    origin: allowedOrigins,
    methods: ["GET", "POST"],
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"]
  }
});

const PORT = process.env.PORT || 5000;

// Connect to MongoDB
connectDB().catch(console.error);

// Validate required environment variables
const requiredEnvVars = ['JWT_SECRET', 'MONGODB_URI'];
requiredEnvVars.forEach(varName => {
  if (!process.env[varName]) {
    console.error(`❌ Missing required environment variable: ${varName}`);
    process.exit(1);
  }
});

// Database Connection
mongoose.connection.on('connected', async () => {
  console.log('✅ MongoDB Connected');
});

mongoose.connection.on('error', (err) => console.error('❌ MongoDB Error:', err));
process.on('SIGINT', async () => {
  await mongoose.connection.close();
  process.exit(0);
});

// Enhanced CORS Configuration
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) {
      return callback(null, true);
    }
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.error('CORS Error: Origin not allowed -', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  optionsSuccessStatus: 200
};

// Apply CORS middleware
app.use(cors(corsOptions));

// Handle preflight requests
app.options('*', cors(corsOptions));

// Enhanced Security Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https://*.onrender.com"],
      connectSrc: [
        "'self'",
        ...allowedOrigins
      ],
      frameAncestors: ["'none'"],
      formAction: ["'self'"]
    }
  },
  crossOriginResourcePolicy: { policy: "cross-origin" },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: true,
  dnsPrefetchControl: true,
  frameguard: { action: 'deny' },
  hidePoweredBy: true,
  hsts: true,
  ieNoOpen: true,
  noSniff: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  xssFilter: true
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

// Serve static files from uploads directory
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${file.fieldname}-${uniqueSuffix}${ext}`);
  }
});

// File filter function
const fileFilter = (req, file, cb) => {
  // Check file type
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
  if (!allowedTypes.includes(file.mimetype)) {
    return cb(new Error('Invalid file type. Only JPEG, PNG and GIF are allowed.'), false);
  }

  // Check file size (2MB limit)
  const maxSize = 2 * 1024 * 1024; // 2MB
  if (file.size > maxSize) {
    return cb(new Error('File too large. Maximum size is 2MB.'), false);
  }

  // Check file extension
  const ext = path.extname(file.originalname).toLowerCase();
  const allowedExts = ['.jpg', '.jpeg', '.png', '.gif'];
  if (!allowedExts.includes(ext)) {
    return cb(new Error('Invalid file extension. Only .jpg, .jpeg, .png and .gif are allowed.'), false);
  }

  cb(null, true);
};

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 2 * 1024 * 1024, // 2MB limit
    files: 1 // Only allow one file per request
  },
  fileFilter: fileFilter
});

// Error handling for multer
const handleMulterError = (err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({
        error: 'File too large',
        details: 'Maximum file size is 2MB'
      });
    }
    if (err.code === 'LIMIT_FILE_COUNT') {
      return res.status(413).json({
        error: 'Too many files',
        details: 'Only one file can be uploaded at a time'
      });
    }
    return res.status(400).json({
      error: 'File upload error',
      details: err.message
    });
  }
  next(err);
};

// Apply multer error handling
app.use(handleMulterError);

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

// Socket.IO connection handling
const connectedUsers = new Map();

io.on('connection', (socket) => {
  console.log('A user connected:', socket.id);

  // Handle user authentication
  socket.on('authenticate', (userId) => {
    connectedUsers.set(userId, socket.id);
    console.log(`User ${userId} authenticated with socket ${socket.id}`);
  });

  // Handle disconnection
  socket.on('disconnect', () => {
    // Remove user from connected users
    for (const [userId, socketId] of connectedUsers.entries()) {
      if (socketId === socket.id) {
        connectedUsers.delete(userId);
        console.log(`User ${userId} disconnected`);
        break;
      }
    }
  });
});

// Export io instance to use in routes
app.set('io', io);
app.set('connectedUsers', connectedUsers);

// Global rate limiter
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // limit each IP to 1000 requests per windowMs
  message: {
    message: 'Too many requests from this IP, please try again later',
    error: 'RATE_LIMIT_EXCEEDED'
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false // Disable the `X-RateLimit-*` headers
});

// Apply global rate limiter to all requests
app.use(globalLimiter);

// Enhanced rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: "Too many requests from this IP, please try again later",
  standardHeaders: true,
  legacyHeaders: false
});

// Apply rate limiting to all routes
app.use(limiter);

// Specific rate limit for file uploads
const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // Limit each IP to 10 uploads per hour
  message: "Too many uploads from this IP, please try again later"
});

// Apply upload rate limiting to upload routes
app.use('/api/photos/upload', uploadLimiter);

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

// Profile Endpoint (UPDATED)
app.get("/api/profile/:userId", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId)
      .select('-password')
      .lean();
      
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    
    const photos = await Photo.find({ userId: req.params.userId })
      .sort({ createdAt: -1 })
      .lean();
    
    res.status(200).json({
      user,
      photos: photos || [],
      photosCount: photos ? photos.length : 0,
      joined: user.createdAt
    });
  } catch (err) {
    console.error("Profile error:", err);
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

// Use routes
app.use('/api/users', userRoutes);
app.use('/api/photos', photoRoutes);
app.use('/api/notifications', notificationsRouter);

// Serve uploaded files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Global error handling middleware
app.use((err, req, res, next) => {
  console.error('❌ Error:', err);
  
  // Handle specific error types
  if (err.name === 'ValidationError') {
    return res.status(400).json({
      error: 'Validation Error',
      details: Object.values(err.errors).map(e => e.message)
    });
  }
  
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      error: 'Invalid token'
    });
  }
  
  // Default error response
  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === 'production' 
      ? 'Internal server error' 
      : err.message
  });
});

// Start Server
connectDB().then(() => {
  server.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🌐 Allowed origins: ${allowedOrigins.join(', ')}`);
    console.log(`🔒 Secure cookies: ${process.env.NODE_ENV === 'production'}`);
    console.log(`📁 Uploads directory: ${uploadsDir}`);
  });
}).catch(err => {
  console.error("❌ Failed to connect to MongoDB:", err);
  process.exit(1);
});