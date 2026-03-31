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

// --- 1. MIDDLEWARE ---
app.use(cors({
    origin: [
        "http://localhost:3000", 
        "http://localhost:8080", 
    ],
    methods: ["POST", "GET", "PUT", "DELETE", "OPTIONS"],
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json());

// --- 2. DATABASE CONNECTION (SERVERLESS OPTIMIZED) ---
let isConnected = false; 

const connectToMongoDB = async () => {
    if (isConnected) return; // Use existing connection if it's already open

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

// Middleware to ensure DB is connected before any route runs
app.use(async (req, res, next) => {
    try {
        await connectToMongoDB();
        next();
    } catch (error) {
        res.status(500).json({ message: "Database connection failed", error: error.message });
    }
});

// --- 3. RAZORPAY CONFIG ---
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// --- 4. SCHEMAS & MODELS ---
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

// Important: Use mongoose.models to prevent "Cannot overwrite model" error on Vercel
const User = mongoose.models.User || mongoose.model('User', userSchema);
const Flyer = mongoose.models.Flyer || mongoose.model('Flyer', flyerSchema);

// --- 5. ROUTES ---

app.get('/', (req, res) => {
    res.send('🚀 Tripsera Backend is running successfully!');
});

// --- PAYMENT ROUTES ---
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
        const expectedSign = crypto.createHmac("sha256", process.env.RAZORPAY_KEY_SECRET).update(sign.toString()).digest("hex");

        if (razorpay_signature === expectedSign) {
            res.status(200).json({ success: true, message: "Payment verified" });
        } else {
            res.status(400).json({ success: false, message: "Invalid signature" });
        }
    } catch (error) {
        res.status(500).send("Internal Server Error");
    }
});

// --- AUTH ROUTES ---
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

        const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET || "secret", { expiresIn: '1d' });
        res.json({ token, user: { email: user.email, agencyName: user.agencyName, role: user.role } });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// --- DASHBOARD & FLYER ROUTES ---
app.get('/api/users/count', async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        res.json({ total: totalUsers });
    } catch (error) {
        res.status(500).json({ message: "Error count" });
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

app.post('/api/save-flyer', async (req, res) => {
    try {
        const newFlyer = new Flyer(req.body);
        await newFlyer.save();
        res.status(201).json({ message: "Saved!" });
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

app.delete('/api/flyers/:id', async (req, res) => {
    try {
        const deletedFlyer = await Flyer.findByIdAndDelete(req.params.id);
        if (!deletedFlyer) return res.status(404).json({ message: "Flyer not found" });
        res.status(200).json({ message: "Deleted successfully" });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// --- PROXY ROUTE ---
app.get('/api/proxy', async (req, res) => {
    const { url } = req.query;
    if (!url) return res.status(400).send("URL is required");
    try {
        const response = await axios({ url, method: 'GET', responseType: 'stream' });
        res.set('Access-Control-Allow-Origin', '*'); 
        res.set('Content-Type', response.headers['content-type']);
        response.data.pipe(res);
    } catch (error) {
        res.status(500).send("Error");
    }
});

// --- 6. EXPORT / START ---
const PORT = process.env.PORT || 5000;

// On Vercel, we MUST NOT call app.listen() for production.
// Vercel turns this file into a serverless function automatically.
if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => console.log(`🚀 Local Server: http://localhost:${PORT}`));
}

module.exports = app;
