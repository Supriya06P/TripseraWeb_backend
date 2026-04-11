require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const Razorpay = require('razorpay');
const crypto = require('crypto');

const app = express();

// --- 1. MIDDLEWARE (Updated CORS) ---
app.use(cors({
    origin: function (origin, callback) {
        // Allows local dev and any Vercel subdomain for Tripsera
        const allowedOrigins = [
            "http://localhost:3000",
            "http://localhost:8080",
            "http://localhost:5173",
            "https://tripsera-web-frontend.vercel.app",
            "https://tripsera2026.vercel.app"
        ];
        if (!origin || allowedOrigins.indexOf(origin) !== -1 || origin.endsWith(".vercel.app")) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ["POST", "GET", "PUT", "DELETE", "OPTIONS"],
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json());

// Handle preflight OPTIONS requests for all routes
app.options('*', cors());

// --- 2. DATABASE CONNECTION (Serverless Optimized) ---
let isConnected = false;

const connectToMongoDB = async () => {
    if (isConnected) return;
    const dbURI = process.env.MONGODB_URI;
    if (!dbURI) throw new Error("MONGODB_URI is missing in environment variables.");

    try {
        const db = await mongoose.connect(dbURI, {
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
            family: 4
        });
        isConnected = db.connections[0].readyState;
        console.log("✅ MongoDB Connected Successfully!");
    } catch (error) {
        console.error("❌ MongoDB Connection Error:", error.message);
        throw error;
    }
};

// Ensure DB is connected before handling any request
app.use(async (req, res, next) => {
    try {
        await connectToMongoDB();
        next();
    } catch (error) {
        res.status(500).json({ message: "Database connection failed", error: error.message });
    }
});
// --- NEW: PHONE AUTH OTP ROUTE ---
app.post('/api/auth/send-otp', async (req, res) => {
    try {
        const { phone } = req.body;

        if (!phone) {
            return res.status(400).json({ message: "Phone number is required" });
        }

        // Logic: Generate a random 6-digit OTP
        const otp = Math.floor(100000 + Math.random() * 900000);

        
        console.log(`DEBUG: OTP for ${phone} is ${otp}`);

        // Success response
        res.status(200).json({ 
            success: true, 
            message: "OTP sent successfully!", 
            otp: otp // Sending OTP in response ONLY for your development/testing
        });
    } catch (error) {
        res.status(500).json({ message: "Backend error: " + error.message });
    }
});
// --- 3. RAZORPAY CONFIG ---
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// --- 4. SCHEMAS & MODELS (HMR Safe) ---
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

// Prevent "Cannot overwrite model" error on Vercel
const User = mongoose.models.User || mongoose.model('User', userSchema);
const Flyer = mongoose.models.Flyer || mongoose.model('Flyer', flyerSchema);

// --- 5. ROUTES ---

app.get('/', (req, res) => {
    res.send('🚀 Tripsera Backend is running successfully!');
});

// PAYMENT
app.post('/api/create-order', async (req, res) => {
    try {
        const { amount } = req.body;
        const options = {
            amount: parseInt(amount) * 100,
            currency: "INR",
            receipt: `receipt_${Date.now()}`,
        };
        const order = await razorpay.orders.create(options);
        res.json(order);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/verify-payment', async (req, res) => {
    try {
        const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
        const sign = razorpay_order_id + "|" + razorpay_payment_id;
        const expectedSign = crypto
            .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
            .update(sign.toString())
            .digest("hex");

        if (razorpay_signature === expectedSign) {
            res.status(200).json({ success: true, message: "Payment verified successfully" });
        } else {
            res.status(400).json({ success: false, message: "Invalid signature" });
        }
    } catch (error) {
        res.status(500).send("Internal Server Error");
    }
});

// AUTH
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { email, password, agencyName, adminKey } = req.body;
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ message: "User already exists" });

        const hashedPassword = await bcrypt.hash(password, 10);
        const role = adminKey === process.env.ADMIN_SECRET_KEY ? "admin" : "user";

        const newUser = new User({ email, password: hashedPassword, agencyName: agencyName || "My Agency", role });
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
            user: { email: user.email, agencyName: user.agencyName, role: user.role }
        });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.get('/api/auth/google', (req, res) => {
    // Replace with your actual Google Client ID
    const clientID = process.env.VITE_GOOGLE_CLIENT_ID;
    const redirectURI = encodeURIComponent("https://tripsera-web-backend.vercel.app/auth"); 
    const scope = encodeURIComponent("email profile");
    
    const googleUrl = `https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=${clientID}&redirect_uri=${redirectURI}&scope=${scope}`;
    
    res.redirect(googleUrl);
});
// --- NEW: GOOGLE SYNC ROUTE ---
// --- ADD THIS TO YOUR BACKEND ROUTES ---
app.post('/api/auth/google-sync', async (req, res) => {
    try {
        const { email, name, googleId } = req.body;

        // 1. Find or Create User
        let user = await User.findOne({ email });

        if (!user) {
            // Create user if they don't exist (using a random password for social login)
            const hashedPassword = await bcrypt.hash(crypto.randomBytes(16).toString('hex'), 10);
            user = new User({
                email,
                name,
                password: hashedPassword,
                agencyName: name || "Travel Agency",
                role: "user"
            });
            await user.save();
        }

        // 2. Create JWT Token
        const token = jwt.sign(
            { id: user._id, role: user.role },
            process.env.JWT_SECRET || 'your_secret_key', 
            { expiresIn: '1d' }
        );

        res.status(200).json({
            token,
            user: { email: user.email, agencyName: user.agencyName, role: user.role }
        });
    } catch (error) {
        res.status(500).json({ message: "Sync error: " + error.message });
    }
});
// DASHBOARD
app.get('/api/users/count', async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        res.json({ total: totalUsers });
    } catch (error) {
        res.status(500).json({ message: "Error fetching user count" });
    }
});

// FLYERS
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

// PROXY
app.get('/api/proxy', async (req, res) => {
    const { url } = req.query;
    if (!url) return res.status(400).send("URL is required");
    try {
        const response = await axios({ url, method: 'GET', responseType: 'stream' });
        res.set('Access-Control-Allow-Origin', '*'); 
        res.set('Content-Type', response.headers['content-type']);
        response.data.pipe(res);
    } catch (error) {
        res.status(500).send("Error fetching image");
    }
});

// --- 6. EXPORT / START ---
const PORT = process.env.PORT || 5000;

if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => console.log(`🚀 Tripsera Backend running on port ${PORT}`));
}

module.exports = app;
