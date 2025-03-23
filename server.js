const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const connectDB = require("./db");
const Photo = require("./models/photo.js");
const User = require("./models/user.js");
const multer = require("multer");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({
  origin: "https://frontendphotoplace.vercel.app",
  methods: ["GET", "POST", "DELETE", "PUT"],
  credentials: true,
}));
app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Handle CORS preflight requests (important for DELETE)
app.options("*", cors());

// Connect to MongoDB
connectDB();

// Ensure the "uploads" folder exists
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
}

// Storage setup for Multer (for photo uploads)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  },
});

// File size limit - 10MB
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } }).single("photo");

// Middleware to parse non-file fields (title, description, userId)
const parseFormData = multer().none();

// Storage setup for Multer (for profile picture uploads)
const profilePictureStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/profile-pictures");
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  },
});

const profilePictureUpload = multer({ storage: profilePictureStorage });

// Middleware to verify JWT token
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

// ✅ **User Signup**
app.post("/api/users/signup", async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: "User created successfully" });
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).json({ message: "Error creating user", error: error.message });
  }
});

// ✅ **User Login**
app.post("/api/users/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: "Invalid password" });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.status(200).json({
      token,
      user: {
        _id: user._id,
        username: user.username,
        email: user.email,
      },
    });
  } catch (error) {
    res.status(500).json({ message: "Error logging in", error });
  }
});

// ✅ **Get User Profile**
app.get("/api/users/:userId/profile", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId).select("-password");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ message: "Error fetching user profile", error });
  }
});

// ✅ **Update User Profile**
app.put(
  "/api/users/:userId/profile",
  authMiddleware,
  profilePictureUpload.single("profilePicture"),
  async (req, res) => {
    const { bio } = req.body;
    const profilePicture = req.file ? `/uploads/profile-pictures/${req.file.filename}` : null;

    try {
      const updateData = { bio };
      if (profilePicture) {
        updateData.profilePicture = profilePicture;
      }

      const user = await User.findByIdAndUpdate(
        req.params.userId,
        updateData,
        { new: true }
      ).select("-password");

      res.status(200).json(user);
    } catch (error) {
      res.status(500).json({ message: "Error updating profile", error });
    }
  }
);

// ✅ **Fetch All Photos (Ensure Full URL)**
app.get("/api/photos", async (req, res) => {
  const { userId } = req.query;

  try {
    const query = userId ? { userId } : {};
    const photos = await Photo.find(query);
    const updatedPhotos = photos.map((photo) => ({
      ...photo._doc,
      url: `https://photoplace-backend-4i8v.onrender.com${photo.url}`,
    }));
    res.json(updatedPhotos);
  } catch (error) {
    console.error("Error fetching photos:", error);
    res.status(500).json({ success: false, message: "Error fetching photos" });
  }
});

// ✅ **Fetch Single Photo by ID**
app.get("/api/photos/:id", async (req, res) => {
  try {
    const photo = await Photo.findById(req.params.id);
    if (!photo) {
      return res.status(404).json({ message: "Photo not found" });
    }
    res.json({
      ...photo._doc,
      url: `https://photoplace-backend-4i8v.onrender.com${photo.url}`,
    });
  } catch (error) {
    console.error("Error fetching photo:", error);
    res.status(500).json({ message: "Error fetching photo", error });
  }
});

// ✅ **Upload Photos (Ensure Full URL)**
app.post("/api/photos/upload", (req, res, next) => {
  // First, parse the non-file fields (title, description, userId)
  parseFormData(req, res, (err) => {
    if (err) {
      return res.status(400).json({ success: false, message: "Error parsing form data" });
    }

    // Then, handle the file upload
    upload(req, res, async (err) => {
      if (err) {
        return res.status(400).json({ success: false, message: "Error uploading file" });
      }

      if (!req.file) {
        return res.status(400).json({ success: false, message: "No file uploaded" });
      }

      const { title, description, userId } = req.body;
      if (!title || !userId) {
        return res.status(400).json({ success: false, message: "Title and userId are required" });
      }

      try {
        const newPhoto = new Photo({
          title,
          url: `/uploads/${req.file.filename}`,
          description,
          userId,
        });

        await newPhoto.save();
        res.status(201).json({
          success: true,
          message: "Photo uploaded successfully",
          photo: {
            ...newPhoto._doc,
            url: `https://photoplace-backend-4i8v.onrender.com${newPhoto.url}`,
          },
        });
      } catch (error) {
        console.error("Error uploading photo:", error);
        res.status(500).json({ success: false, message: "Error uploading photo", error });
      }
    });
  });
});

// ✅ **Delete or Archive Photo**
app.delete("/api/photos/:photoId", authMiddleware, async (req, res) => {
  try {
    const photo = await Photo.findById(req.params.photoId);
    if (!photo) {
      return res.status(404).json({ message: "Photo not found" });
    }

    // Soft delete (archive)
    photo.archived = true;
    await photo.save();

    res.status(200).json({ message: "Photo archived successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error archiving photo", error });
  }
});

// ✅ **Delete Photo**
app.delete("/api/photos/:id", async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`🔍 Attempting to delete photo with ID: ${id}`);

    const photo = await Photo.findById(id);
    if (!photo) {
      return res.status(404).json({ message: "Photo not found" });
    }

    const filePath = path.join(__dirname, "uploads", photo.url.replace("/uploads/", ""));
    console.log(`🗑️ File path to delete: ${filePath}`);

    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      console.log("✅ File deleted successfully");
    } else {
      console.log("⚠️ File not found, skipping deletion");
    }

    await Photo.findByIdAndDelete(id);
    console.log("✅ Photo deleted from database");

    res.status(200).json({ message: "Photo deleted successfully" });
  } catch (err) {
    console.error("❌ Error deleting photo:", err);
    res.status(500).json({ message: "Error deleting photo", error: err });
  }
});

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));