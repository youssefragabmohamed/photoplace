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
const connectDB = require("./db");
const Photo = require("./models/photo.js");
const User = require("./models/user.js");

const app = express();
const PORT = process.env.PORT || 5000;

/* ======================
   Security Middleware
   ====================== */
app.use(helmet());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per window
});
app.use(limiter);

const allowedOrigins = [
  "https://frontendphotoplace.vercel.app",
  "http://localhost:3000"
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  methods: ["GET", "POST", "DELETE", "PUT"],
  credentials: true
}));
app.options("*", cors());

/* ======================
   Utility Middleware
   ====================== */
app.use(express.json());
app.use(morgan("dev"));

/* ======================
   File Upload Setup
   ====================== */
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
}

const sanitizeFilename = (name) => name.replace(/[^a-zA-Z0-9.]/g, "-");

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + sanitizeFilename(file.originalname))
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith("image/")) {
    cb(null, true);
  } else {
    cb(new Error("Only images are allowed!"), false);
  }
};

const upload = multer({ 
  storage, 
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter
}).single("photo");

const parseFormData = multer().none();

/* ======================
   Database Connection
   ====================== */
connectDB();

// Validate critical environment variables
if (!process.env.JWT_SECRET || !process.env.MONGODB_URI) {
  console.error("Missing required environment variables!");
  process.exit(1);
}

/* ======================
   Authentication Middleware
   ====================== */
const authMiddleware = (req, res, next) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");

  if (!token) {
    return res.status(401).json({ message: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    res.status(400).json({ message: "Invalid token" });
  }
};

/* ======================
   API Routes
   ====================== */
// Health check endpoint
app.get("/", (req, res) => {
  res.status(200).json({ 
    status: "running", 
    message: "PhotoPlace backend server is operational",
    version: "1.0.0"
  });
});

// API documentation endpoint
app.get("/api-docs", (req, res) => {
  res.json({
    endpoints: {
      signup: "POST /api/users/signup",
      login: "POST /api/users/login",
      getPhotos: "GET /api/photos",
      uploadPhoto: "POST /api/photos/upload",
      deletePhoto: "DELETE /api/photos/:id"
    }
  });
});

// User routes
app.post("/api/users/signup", async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({
      username: req.body.username,
      email: req.body.email,
      password: hashedPassword
    });
    await user.save();
    res.status(201).json({ message: "User created successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error creating user", error: error.message });
  }
});

app.post("/api/users/login", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) return res.status(400).json({ message: "User not found" });

    const validPassword = await bcrypt.compare(req.body.password, user.password);
    if (!validPassword) return res.status(400).json({ message: "Invalid password" });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d"
    });

    res.status(200).json({
      token,
      user: {
        _id: user._id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    res.status(500).json({ message: "Error logging in", error });
  }
});

// Photo routes
app.get("/api/photos", async (req, res) => {
  try {
    const query = req.query.userId ? { userId: req.query.userId } : {};
    const photos = await Photo.find(query);
    const updatedPhotos = photos.map(photo => ({
      ...photo._doc,
      url: `${process.env.BASE_URL || 'https://photoplace-backend-4i8v.onrender.com'}${photo.url}`
    }));
    res.json(updatedPhotos);
  } catch (error) {
    res.status(500).json({ message: "Error fetching photos", error });
  }
});

app.post("/api/photos/upload", (req, res) => {
  parseFormData(req, res, (err) => {
    if (err) return res.status(400).json({ message: "Error parsing form data" });

    upload(req, res, async (err) => {
      if (err) {
        return res.status(400).json({ 
          message: err.code === "LIMIT_FILE_SIZE" 
            ? "File too large (max 10MB)" 
            : "Error uploading file" 
        });
      }

      if (!req.file) return res.status(400).json({ message: "No file uploaded" });
      if (!req.body.userId) return res.status(400).json({ message: "userId is required" });

      try {
        const newPhoto = new Photo({
          title: req.body.title,
          url: `/uploads/${req.file.filename}`,
          description: req.body.description,
          userId: req.body.userId
        });

        await newPhoto.save();
        res.status(201).json({
          message: "Photo uploaded successfully",
          photo: {
            ...newPhoto._doc,
            url: `${process.env.BASE_URL || 'https://photoplace-backend-4i8v.onrender.com'}${newPhoto.url}`
          }
        });
      } catch (error) {
        res.status(500).json({ message: "Error uploading photo", error });
      }
    });
  });
});

app.delete("/api/photos/:id", authMiddleware, async (req, res) => {
  try {
    const photo = await Photo.findById(req.params.id);
    if (!photo) return res.status(404).json({ message: "Photo not found" });

    // Delete file from filesystem
    const filePath = path.join(__dirname, photo.url);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

    await Photo.findByIdAndDelete(req.params.id);
    res.status(200).json({ message: "Photo deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error deleting photo", error });
  }
});

/* ======================
   Error Handling
   ====================== */
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ message: "Internal server error" });
});

/* ======================
   Server Start
   ====================== */
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🔗 Base URL: ${process.env.BASE_URL || `http://localhost:${PORT}`}`);
});