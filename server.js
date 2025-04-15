require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcrypt");
const crypto = require("crypto");

// Directory constants (replace with actual paths)
const DECRYPTED_DIR = path.join(__dirname, 'decrypted-images');
const ENCRYPTED_DIR = path.join(__dirname, "encrypted-images");
const RECEIVED_DIR = path.join(__dirname, "received-images");

if (!fs.existsSync(ENCRYPTED_DIR)) fs.mkdirSync(ENCRYPTED_DIR);
if (!fs.existsSync(RECEIVED_DIR)) fs.mkdirSync(RECEIVED_DIR);
if (!fs.existsSync(DECRYPTED_DIR)) fs.mkdirSync(DECRYPTED_DIR);

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.raw({ type: ['application/octet-stream', 'image/jpeg'], limit: "10mb" }));

// Static folders
app.use("/images", express.static(DECRYPTED_DIR));

// MongoDB
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log("✅ Connected to MongoDB"))
  .catch(err => console.error("❌ MongoDB error:", err));

// User Schema
const userSchema = new mongoose.Schema({
    productnumber: { type: Number, required: true, unique: true },
    name: { type: String, required: true },
    mobile: { type: String, required: true, match: /^\d{10}$/ },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    aesKey: { type: String, required: true },
    agree: { type: Boolean, required: true },
});
const User = mongoose.model("User", userSchema);

// Image Schema
const imageSchema = new mongoose.Schema({
  filename: { type: String, required: true },
  iv: { type: String, required: true },
  email: { type: String, required: true },
  timestamp: { type: Date, default: Date.now }
});
const Image = mongoose.model("Image", imageSchema);

// Signup
app.post("/signup", async (req, res) => {
  try {
      const { productnumber, name, mobile, email, password, confirmPassword, aesKey, agree } = req.body;

      if (!productnumber || !name || !mobile || !email || !password || !confirmPassword || !aesKey || !agree) {
          return res.status(400).json({ success: false, message: "All fields are required" });
      }

      if (password !== confirmPassword) {
          return res.status(400).json({ success: false, message: "Passwords do not match" });
      }

      const existingUser = await User.findOne({ $or: [{ email }, { productnumber }] });
      if (existingUser) {
          return res.status(400).json({ success: false, message: "Email or Product Number already registered" });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      // ⛔ Do NOT hash AES key — store it as is
      const newUser = new User({
          productnumber,
          name,
          mobile,
          email,
          password: hashedPassword,
          aesKey, // stored in plaintext for encryption/decryption
          agree
      });

      await newUser.save();

      res.status(201).json({ success: true, message: "User registered successfully" });
  } catch (err) {
      console.error("Signup Error:", err);
      res.status(500).json({ success: false, message: "Server error", error: err.message });
  }
});

// Login
app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ success: false, message: "Email and password are required" });
        }

        const user = await User.findOne({ email });
        if (!user) return res.status(401).json({ success: false, message: "Invalid email or password" });

        const isPasswordMatch = await bcrypt.compare(password, user.password);
        if (!isPasswordMatch) return res.status(401).json({ success: false, message: "Invalid email or password" });

        res.status(200).json({
            success: true,
            message: "Login successful",
            user: { productnumber: user.productnumber, name: user.name, email: user.email }
        });
    } catch (err) {
        res.status(500).json({ success: false, message: "Server error", error: err.message });
    }
});

// ESP32-CAM Upload Endpoint
app.post("/upload", async (req, res) => {
    try {
        const buffer = req.body;

        if (!buffer || !buffer.length) {
            return res.status(400).json({ success: false, message: "No image data received" });
        }

        // Save original image
        const timestamp = Date.now();
        const originalFilename = `img_${timestamp}.jpg`;
        const originalPath = path.join(RECEIVED_DIR, originalFilename);
        fs.writeFileSync(originalPath, buffer);

        // Get AES Key from one registered user (modify if user-specific needed)
        const user = await User.findOne({}); // You can modify this to retrieve by user email, if applicable
        if (!user || !user.aesKey) {
            return res.status(500).json({ success: false, message: "No AES key found in DB" });
        }

        // Create 128-bit key from AES Key (stored as plaintext in the DB)
        const keyBuffer = Buffer.alloc(16);
        Buffer.from(user.aesKey, "utf8").copy(keyBuffer);

        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv("aes-128-cbc", keyBuffer, iv);
        let encrypted = cipher.update(buffer);
        encrypted = Buffer.concat([encrypted, cipher.final()]);

        const encryptedFilename = `enc_${timestamp}.jpg`; // Naming the encrypted file
        const encryptedPath = path.join(ENCRYPTED_DIR, encryptedFilename);
        fs.writeFileSync(encryptedPath, encrypted);

        // Save metadata
        const newImage = new Image({
            filename: encryptedFilename,
            iv: iv.toString("hex"),
            email: user.email // Store the email associated with the encryption
        });
        await newImage.save();

        // Delete original image
        fs.unlinkSync(originalPath);

        res.status(200).json({ success: true, message: "Image received and encrypted", filename: encryptedFilename });
    } catch (err) {
        console.error("Upload/Encrypt error:", err);
        res.status(500).json({ success: false, message: "Server error", error: err.message });
    }
});


// Route: Decrypt and return images
app.post("/decrypt-images", async (req, res) => {
    try {
      const { email, aesKey } = req.body;
  
      if (!email || !aesKey) {
        return res.status(400).json({ success: false, message: "Email and AES Key are required" });
      }
  
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({ success: false, message: "Invalid email" });
      }
  
      if (aesKey !== user.aesKey) {
        return res.status(401).json({ success: false, message: "Invalid AES Key" });
      }
  
      const images = await Image.find({ email }).sort({ timestamp: -1 });
      if (!images.length) {
        return res.status(404).json({ success: false, message: "No images found for this user" });
      }
  
      const decryptedImages = [];
  
      for (let image of images) {
        const encryptedPath = path.join(ENCRYPTED_DIR, image.filename);
        const decryptedFilename = `dec_${image.filename}`;
        const decryptedPath = path.join(DECRYPTED_DIR, decryptedFilename);
  
        // If already decrypted, just push the path
        if (fs.existsSync(decryptedPath)) {
          decryptedImages.push({
            filename: decryptedFilename,
            imagePath: `http://localhost:${PORT}/decrypted-images/${decryptedFilename}`,
            timestamp: image.timestamp,
          });
          continue;
        }
  
        // If encrypted image file is missing, skip it
        if (!fs.existsSync(encryptedPath)) {
          //console.warn(`Encrypted file not found: ${encryptedPath}`);
          continue;
        }
  
        const encryptedBuffer = fs.readFileSync(encryptedPath);
        const iv = Buffer.from(image.iv, "hex");
  
        if (iv.length !== 16) {
          console.error(`Invalid IV length for image: ${image.filename}`);
          continue;
        }
  
        try {
          const decipher = crypto.createDecipheriv("aes-128-cbc", Buffer.from(aesKey, "utf8"), iv);
          let decrypted = decipher.update(encryptedBuffer);
          decrypted = Buffer.concat([decrypted, decipher.final()]);
  
          fs.writeFileSync(decryptedPath, decrypted);
  
          decryptedImages.push({
            filename: decryptedFilename,
            imagePath: `http://localhost:${PORT}/decrypted-images/${decryptedFilename}`,
            timestamp: image.timestamp,
          });
        } catch (decryptionError) {
          console.error(`Decryption failed for ${image.filename}:`, decryptionError.message);
          continue;
        }
      }
  
      res.status(200).json({
        success: true,
        message: "Images decrypted successfully",
        images: decryptedImages,
      });
    } catch (err) {
      console.error("Decryption Error:", err.message);
      res.status(500).json({ success: false, message: "Server error", error: err.message });
    }
  });
  
  // Route 2: Fetch decrypted images (already processed)
  app.post("/get-decrypted-images", async (req, res) => {
    try {
      const { email } = req.body;
  
      if (!email) {
        return res.status(400).json({ success: false, message: "Email is required" });
      }
  
      const images = await Image.find({ email }).sort({ timestamp: -1 });
      if (!images.length) {
        return res.status(404).json({ success: false, message: "No images found" });
      }
  
      const decryptedImages = [];
  
      for (let image of images) {
        const decryptedFilename = `dec_${image.filename}`;
        const decryptedPath = path.join(DECRYPTED_DIR, decryptedFilename);
  
        if (fs.existsSync(decryptedPath)) {
          decryptedImages.push({
            filename: decryptedFilename,
            imagePath: `http://localhost:${PORT}/images/${decryptedFilename}`,
            timestamp: image.timestamp,
          });
        }
      }
  
      if (!decryptedImages.length) {
        return res.status(404).json({ success: false, message: "No decrypted images found" });
      }
  
      res.status(200).json({
        success: true,
        message: "Decrypted images fetched successfully",
        images: decryptedImages,
      });
    } catch (err) {
      console.error("Error fetching decrypted images:", err);
      res.status(500).json({ success: false, message: "Server error", error: err.message });
    }
  });


  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
  