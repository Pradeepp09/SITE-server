require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const bcrypt = require('bcryptjs');
const crypto = require("crypto");
const cloudinary = require('./cloudinary');
const streamifier = require('streamifier');

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
app.post('/upload', express.raw({ type: 'image/jpeg', limit: '10mb' }), async (req, res) => {
    try {
        const buffer = req.body;

        if (!buffer || !buffer.length) {
            return res.status(400).json({ success: false, message: "No image data received" });
        }

        const timestamp = Date.now();

        // Retrieve user and AES key
        const user = await User.findOne({});
        if (!user || !user.aesKey) {
            return res.status(500).json({ success: false, message: "No AES key found in DB" });
        }

        // Prepare AES key
        const keyBuffer = Buffer.alloc(16);
        Buffer.from(user.aesKey, 'utf8').copy(keyBuffer);

        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-128-cbc', keyBuffer, iv);
        let encrypted = cipher.update(buffer);
        encrypted = Buffer.concat([encrypted, cipher.final()]);

        // Upload encrypted image to Cloudinary
const uploadToCloudinary = () => {
    return new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
            {
                resource_type: 'image',
                public_id: `encrypted/enc_${timestamp}`, // corrected string interpolation
                overwrite: true
            },
            (error, result) => {
                if (error) reject(error);
                else resolve(result);
            }
        );

        streamifier.createReadStream(encrypted).pipe(uploadStream);
    });
};

let result;
try {
    result = await uploadToCloudinary();
} catch (err) {
    return res.status(500).json({
        success: false,
        message: "Cloudinary upload failed",
        error: err.message
    });
}

// Save image metadata to DB
const newImage = new Image({
    filename: `enc_${timestamp}.jpg`, // corrected string interpolation
    iv: iv.toString('hex'),
    cloudinaryUrl: result.secure_url,
    email: user.email
});

await newImage.save();

res.status(200).json({
    success: true,
    message: "Image encrypted and uploaded to Cloudinary",
    cloudinaryUrl: result.secure_url
});


// Route: Decrypt and return images
const axios = require('axios');

app.post("/decrypt-images", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, message: "Email is required" });

    const user = await User.findOne({ email });
    if (!user || !user.aesKey) {
      return res.status(404).json({ success: false, message: "User or AES key not found" });
    }

    const images = await Image.find({ email }).sort({ timestamp: -1 });
    if (!images.length) {
      return res.status(404).json({ success: false, message: "No images found for this user" });
    }

    const keyBuffer = Buffer.alloc(16);
    Buffer.from(user.aesKey, 'utf8').copy(keyBuffer);

    const decryptedUploads = [];

    for (const image of images) {
      const encryptedResponse = await axios.get(image.cloudinaryUrl, { responseType: 'arraybuffer' });
      const encryptedBuffer = Buffer.from(encryptedResponse.data);
      const ivBuffer = Buffer.from(image.iv, 'hex');

      const decipher = crypto.createDecipheriv('aes-128-cbc', keyBuffer, ivBuffer);
      let decrypted = decipher.update(encryptedBuffer);
      decrypted = Buffer.concat([decrypted, decipher.final()]);

      const cloudResult = await new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
          {
            resource_type: 'image',
            public_id: `decrypted/${image.filename.replace('enc_', 'dec_')}`,
            overwrite: true
          },
          (error, result) => {
            if (error) reject(error);
            else resolve(result);
          }
        );
        streamifier.createReadStream(decrypted).pipe(uploadStream);
      });

      // Optionally update DB with decrypted URL
      image.decryptedUrl = cloudResult.secure_url;
      await image.save();

      decryptedUploads.push({
        originalFilename: image.filename,
        decryptedUrl: cloudResult.secure_url
      });
    }

    res.status(200).json({
      success: true,
      message: "Decrypted images uploaded to Cloudinary",
      images: decryptedUploads
    });

  } catch (err) {
    console.error("Error in /decrypt-images:", err.message);
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
        const decryptedFilename = dec_${image.filename};
        const decryptedPath = path.join(DECRYPTED_DIR, decryptedFilename);
  
        if (fs.existsSync(decryptedPath)) {
          decryptedImages.push({
            filename: decryptedFilename,
            imagePath: http://localhost:${PORT}/images/${decryptedFilename},
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
    console.log(Server running on http://localhost:${PORT});
  });
