const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const multer = require('multer');
const path = require('path');
const cors = require('cors');

// Initialize app
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: process.env.CORS_ORIGIN || 'http://localhost:3001',
    credentials: true,
}));

// Environment Variables
const SECRET_KEY = process.env.SECRET_KEY || crypto.randomBytes(32).toString('hex');
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/news';

// Log secret key for debugging (optional, remove in production)
console.log('Using Secret Key:', SECRET_KEY);

// MongoDB Connection
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });
const db = mongoose.connection;
db.once('open', () => {
    console.log('Connected to MongoDB...');
});

// Mongoose Models
const User = mongoose.model('User', {
    name: String,
    contact: Number,
    email: String,
    password: String,
    isDriver: { type: Boolean, default: false },
    driverVerification: {
        aadharCard: String,
        carName: String,
        carNo: String,
        livePhoto: String,
        verified: { type: Boolean, default: false },
    },
});

const Ride = mongoose.model('Ride', {
    driverName: String,
    driverContact: Number,
    driverId: mongoose.Schema.Types.ObjectId,
    driverCarName: String,
    driverCarNo: String,
    driverPhoto: String,
    leavingFrom: String,
    goingTo: String,
    date: String,
    time: String,
    passengers: Number,
    price: Number,
});

// Authentication Middleware
const authenticateUser = async (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ msg: "Not authenticated" });
    }
    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ msg: "Invalid token" });
    }
};

// Routes

// User Registration
app.post('/register', async (req, res) => {
    try {
        const { name, contact, email, password } = req.body;
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(409).json({ msg: "Email already exists", code: 409 });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ name, contact, email, password: hashedPassword });
        const savedUser = await newUser.save();

        const token = jwt.sign({
            name: savedUser.name, 
            contact: savedUser.contact, 
            email: savedUser.email, 
            userid: savedUser._id, 
            isDriver: savedUser.isDriver,
        }, SECRET_KEY);

        res.cookie('token', token, { httpOnly: true });
        res.status(201).json({ msg: "Registration successful", code: 201, user: savedUser });
    } catch (error) {
        res.status(500).json({ msg: "Error registering user", error });
    }
});

// User Login
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ msg: "Invalid credentials", code: 401 });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ msg: "Invalid credentials", code: 401 });
        }

        const token = jwt.sign({
            name: user.name,
            contact: user.contact,
            email: user.email,
            userid: user._id,
            isDriver: user.isDriver,
        }, SECRET_KEY);

        res.cookie('token', token, { httpOnly: true });
        res.json({ msg: 'Login successful', code: 200, user });
    } catch (error) {
        res.status(500).json({ msg: "Error logging in", error });
    }
});

// User Logout
app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ msg: "Logout successful", code: 200 });
});

// File Upload Setup
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'frontend/public/'),
    filename: (req, file, cb) => {
        const extension = file.mimetype.split('/')[1];
        const contact = req.user.contact;
        cb(null, `${file.fieldname}-${contact}.${extension}`);
    },
});
const upload = multer({ storage }).fields([{ name: 'livePhoto', maxCount: 1 }]);

// Verify Driver Profile
app.post('/verify', authenticateUser, upload, async (req, res) => {
    try {
        const { carName, carNo } = req.body;
        const livePhoto = req.files['livePhoto'] ? req.files['livePhoto'][0].path : null;

        const user = await User.findById(req.user.userid);
        user.driverVerification = { carName, carNo, livePhoto, verified: true };
        user.isDriver = true;
        await user.save();

        res.status(201).json({ msg: "Driver profile verified successfully", code: 201, user });
    } catch (error) {
        res.status(500).json({ msg: "Verification failed", error });
    }
});

// Create Ride
app.post('/createRide', authenticateUser, async (req, res) => {
    try {
        const { driverCarName, driverCarNo, leavingFrom, goingTo, date, time, passengers, price } = req.body;
        const newRide = new Ride({
            driverName: req.user.name,
            driverContact: req.user.contact,
            driverId: req.user.userid,
            driverCarName,
            driverCarNo,
            leavingFrom,
            goingTo,
            date,
            time,
            passengers,
            price,
        });

        const savedRide = await newRide.save();
        res.status(201).json({ msg: "Ride created successfully", ride: savedRide, code: 201 });
    } catch (error) {
        res.status(500).json({ msg: "Error creating ride", error });
    }
});

// Search Rides
app.post('/searchRides', authenticateUser, async (req, res) => {
    try {
        const { leavingFrom, goingTo, date, passengers } = req.body;
        const rides = await Ride.find({
            driverName: { $ne: req.user.name },
            leavingFrom,
            goingTo,
            date,
            passengers: { $gte: passengers },
        });

        res.json({ code: 200, rides });
    } catch (error) {
        res.status(500).json({ msg: "Error fetching rides", error });
    }
});

// Start Server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}...`);
});
