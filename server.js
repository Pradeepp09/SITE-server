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

const DECRYPTED_DIR = path.join(__dirname, 'decrypted-images');
const ENCRYPTED_DIR = path.join(__dirname, "encrypted-images");

if (!fs.existsSync(ENCRYPTED_DIR)) fs.mkdirSync(ENCRYPTED_DIR);
if (!fs.existsSync(DECRYPTED_DIR)) fs.mkdirSync(DECRYPTED_DIR);

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());
app.use(express.raw({ type: ['application/octet-stream', 'image/jpeg'], limit: "10mb" }));

app.use("/images", express.static(DECRYPTED_DIR));

mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log("✅ Connected to MongoDB"))
  .catch(err => console.error("❌ MongoDB error:", err));

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

const imageSchema = new mongoose.Schema({
  filename: { type: String, required: true },
  iv: { type: String, required: true },
  email: { type: String, required: true },
  cloudinaryUrl: { type: String, required: true },
  timestamp: { type: Date, default: Date.now }
});
const Image = mongoose.model("Image", imageSchema);

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
      const newUser = new User({
          productnumber,
          name,
          mobile,
          email,
          password: hashedPassword,
          aesKey,
          agree
      });

      await newUser.save();

      res.status(201).json({ success: true, message: "User registered successfully" });
  } catch (err) {
      console.error("Signup Error:", err);
      res.status(500).json({ success: false, message: "Server error", error: err.message });
  }
});

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

app.post('/upload', async (req, res) => {
    try {
        const buffer = req.body;
        const timestamp = Date.now();
        const user = await User.findOne({});
        if (!user || !user.aesKey) {
            return res.status(500).json({ success: false, message: "No AES key found in DB" });
        }

        const keyBuffer = Buffer.alloc(16);
        Buffer.from(user.aesKey, 'utf8').copy(keyBuffer);

        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-128-cbc', keyBuffer, iv);
        let encrypted = cipher.update(buffer);
        encrypted = Buffer.concat([encrypted, cipher.final()]);

        const uploadToCloudinary = () => {
            return new Promise((resolve, reject) => {
                const uploadStream = cloudinary.uploader.upload_stream(
                    {
                        resource_type: 'image',
                        public_id: `encrypted/enc_${timestamp}`,
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

        const result = await uploadToCloudinary();

        const newImage = new Image({
            filename: `enc_${timestamp}.jpg`,
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
    } catch (err) {
        console.error("Upload/Encrypt error:", err.message);
        res.status(500).json({ success: false, message: "Server error", error: err.message });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
