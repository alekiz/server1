require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const serverless = require('serverless-http');
const morgan = require('morgan');
const winston = require('winston');
const axios = require('axios');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 4000;

// --- Global DB Connection (cached) ---
if (!global.__MONGO_CONN__) {
  global.__MONGO_CONN__ = mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
  })
    .then((conn) => {
      console.log('MongoDB connected (cached)');
      return conn;
    })
    .catch((err) => {
      console.error('MongoDB connection error:', err);
    }); // Removed process.exit(1)
}

const dbConnect = () => global.__MONGO_CONN__;

// Trust the first proxy (for rate limiting behind proxies/Vercel)
app.set('trust proxy', 1);

// Logger configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.json()
  ),
  transports: [
      new winston.transports.Console(),
      new winston.transports.File({ filename: 'error.log', level: 'error' }),
      new winston.transports.File({ filename: 'combined.log' }),
  ],
});

// -----------------------------
// Middlewares
// -----------------------------
app.use(express.json());
app.use(cookieParser());
app.use(helmet());
app.use(cors({
  origin: 'https://crypto1-ten.vercel.app',
  credentials: true,
}));
app.options('*', cors());
app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  keyGenerator: (req) => req.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 'unknown',
  message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

// -----------------------------
// User Schema & Model
// -----------------------------
const userSchema = new mongoose.Schema({
  username:    { type: String, required: true },
  email:       { type: String, required: true, unique: true },
  password:    { type: String, required: true },
  country:     { type: String, required: true },
  phoneNumber: { type: String, required: true },
  investmentBalance: { type: Number, default: 0 },
  totalInvested: { type: Number, default: 0 },
  mines: { type: Number, default: 0 },
  role: { type: String, default: "user" },
  refreshToken: { type: String },
}, { timestamps: true });

const User = mongoose.models.User || mongoose.model('User', userSchema);

// -----------------------------
// JWT Utility Functions
// -----------------------------
const generateAccessToken = (user) => jwt.sign(
  { id: user._id, email: user.email, role: user.role },
  process.env.JWT_SECRET,
  { expiresIn: '15m' }
);

const generateRefreshToken = (user) => jwt.sign(
  { id: user._id, email: user.email, role: user.role },
  process.env.JWT_REFRESH_SECRET,
  { expiresIn: '7d' }
);

// -----------------------------
// Middleware: Protect Route
// -----------------------------
const protect = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Not authorized, no token provided' });
  }
  const token = authHeader.split(' ')[1];
  try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded;
      next();
  } catch (error) {
      return res.status(401).json({ error: 'Not authorized, token failed' });
  }
};

// -----------------------------
// Authentication Endpoints
// -----------------------------
app.post('/api/auth/signup', async (req, res) => {
  try {
    await dbConnect();
    const { username, email, password, country, phoneNumber } = req.body;
    if (!username || !email || !password || !country || !phoneNumber) {
      return res.status(400).json({ error: 'Please provide all required fields' });
    }
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ error: 'Username or Email already exists' });
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const user = await User.create({ username, email, password: hashedPassword, country, phoneNumber, role: "user" });
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    user.refreshToken = refreshToken;
    await user.save();
    res.cookie('refreshToken', refreshToken, { 
      httpOnly: true, 
      secure: process.env.NODE_ENV === "production", 
      sameSite: "Strict", 
      maxAge: 7 * 24 * 60 * 60 * 1000 
    });
    res.status(201).json({ message: 'Sign up successful. Please sign in.', accessToken });
  } catch (error) {
    logger.error('Sign up error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ... [Keep other endpoints the same as in the original code] ...

// -----------------------------
// Start Server / Export for Serverless
// -----------------------------
module.exports = app;
module.exports.handler = serverless(app);
