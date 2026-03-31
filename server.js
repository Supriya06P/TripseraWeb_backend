require('dotenv').config(); 
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');

const app = express();

// --- MIDDLEWARE ---
app.use(cors({
    origin: ["http://localhost:3000","http://localhost:8080"],
    methods: ["POST", "GET", "PUT", "DELETE", "OPTIONS"],
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"]
}));
// app.use(cors({
//     origin: "*", // Allows any frontend to connect (Use this to test if it's working)
//     methods: ["POST", "GET", "PUT", "DELETE", "OPTIONS"],
//     credentials: true
// }));
app.use(express.json());
app.get('/', (req, res) => {
  res.send('🚀 Backend is running successfully!');
});



// --- DATABASE CONNECTION ---
const dbURI = process.env.MONGODB_URI;

if (!dbURI) {
  console.error("❌ Error: No MONGODB_URI found in environment variables.");
}

// Optimized connection for restricted networks (like college Wi-Fi) and Vercel
const connectionOptions = {
  serverSelectionTimeoutMS: 5000, // Timeout after 5 seconds instead of 30
  socketTimeoutMS: 45000,         // Close sockets after 45 seconds of inactivity
  family: 4                       // Force IPv4 to avoid DNS resolution issues
};

mongoose.connect(dbURI, connectionOptions)
  .then(() => console.log("✅ MongoDB Connected Successfully!"))
  .catch(err => {
    console.error("❌ Connection Error:", err.message);
    console.log("💡 Tip: Ensure IP 0.0.0.0/0 is whitelisted in Atlas Network Access.");
  });
const Razorpay = require('razorpay');
const crypto = require('crypto'); // Built-in Node module for signature verification

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});


app.post('/api/create-order', async (req, res) => {
  try {
    const { amount } = req.body;
    
    // Check if keys are actually present right before using them
    if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
      return res.status(500).json({ error: "Server keys are not configured in .env" });
    }

    const options = {
      amount: parseInt(amount) * 100, // Ensure this is 50000 for 500 INR
      currency: "INR",
      receipt: `receipt_${Date.now()}`,
    };

    const order = await razorpay.orders.create(options);
    res.json(order);
  } catch (error) {
    // THIS IS THE CRITICAL LOG
    console.error("RAZORPAY SDK ERROR OBJECT:", error); 
    
    // Return the specific Razorpay error if available
    res.status(500).json({ 
      error: error.description || error.message || "Razorpay Order Creation Failed" 
    });
  }
});

// Step 2: Verify the payment signature
app.post('/api/verify-payment', async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

    // Create the expected signature using your Secret Key
    const sign = razorpay_order_id + "|" + razorpay_payment_id;
    const expectedSign = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(sign.toString())
      .digest("hex");

    // Compare signatures
    if (razorpay_signature === expectedSign) {
      return res.status(200).json({ success: true, message: "Payment verified successfully" });
    } else {
      return res.status(400).json({ success: false, message: "Invalid signature" });
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});
// --- 1. SCHEMAS ---
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  agencyName: String,
  role: { type: String, default: "user" },
  createdAt: { type: Date, default: Date.now }
});

const flyerSchema = new mongoose.Schema({
  title: String,
  price: { type: Number, default: 0 },
  thumbnail: String,
  canvasSize: {
    width: { type: Number, default: 400 },
    height: { type: Number, default: 560 }
  },
  backgroundColor: String,
  elements: Array,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Flyer = mongoose.model('Flyer', flyerSchema);

// --- 2. AUTH ROUTES ---

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, agencyName, adminKey } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const role = adminKey === process.env.ADMIN_SECRET_KEY ? "admin" : "user";

    const newUser = new User({
      email,
      password: hashedPassword,
      agencyName: agencyName || "My Agency",
      role
    });

    await newUser.save();
    res.status(201).json({ message: "User created successfully" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/auth/signin', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET || process.env.ADMIN_SECRET_KEY, 
      { expiresIn: '1d' }
    );

    res.json({
      token,
      user: {
        email: user.email,
        agencyName: user.agencyName,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// --- 3. DASHBOARD & USER ROUTES ---

app.get('/api/users/count', async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    res.json({ total: totalUsers });
  } catch (error) {
    res.status(500).json({ message: "Error fetching user count" });
  }
});

// --- 4. FLYER ROUTES ---

app.post('/api/save-flyer', async (req, res) => {
  try {
    const newFlyer = new Flyer(req.body);
    await newFlyer.save();
    res.status(201).json({ message: "Saved successfully!" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/flyers', async (req, res) => {
  try {
    const flyers = await Flyer.find().sort({ createdAt: -1 });
    res.status(200).json(flyers);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/flyers/latest', async (req, res) => {
  try {
    const latest = await Flyer.findOne().sort({ createdAt: -1 });
    if (!latest) return res.status(404).json({ message: "No templates found" });
    res.status(200).json(latest);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/flyers/recent-count', async (req, res) => {
  try {
    const tenDaysAgo = new Date();
    tenDaysAgo.setDate(tenDaysAgo.getDate() - 10);
    const count = await Flyer.countDocuments({ createdAt: { $gte: tenDaysAgo } });
    res.json({ count });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/flyers/:id', async (req, res) => {
  try {
    const deletedFlyer = await Flyer.findByIdAndDelete(req.params.id);
    if (!deletedFlyer) return res.status(404).json({ message: "Flyer not found" });
    res.status(200).json({ message: "Deleted successfully" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// --- 5. PROXY ROUTE ---
app.get('/api/proxy', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).send("URL is required");

  try {
    const response = await axios({
      url,
      method: 'GET',
      responseType: 'stream',
    });

    // --- ADD THIS LINE ---
    // This tells the browser/html2canvas that it's safe to export this image
    res.set('Access-Control-Allow-Origin', '*'); 
    
    res.set('Content-Type', response.headers['content-type']);
    response.data.pipe(res);
  } catch (error) {
    console.error("Proxy error:", error.message);
    res.status(500).send("Error fetching image");
  }
});

// --- SERVER START / EXPORT ---
const PORT = process.env.PORT || 5000;

// Only start the listener if we're not on Vercel
if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => console.log(`🚀 Tripsera Backend running on port ${PORT}`));
}
// app.listen(PORT, () => {
//   console.log(`🚀 Tripsera Backend running on port ${PORT}`);
// });

// Export the app for Vercel serverless functions
module.exports = app;
