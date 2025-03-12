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

// --- Global Cached Mongoose Connection ---
// This caches the connection across invocations.
if (!global.__MONGO_CONN__) {
  global.__MONGO_CONN__ = null;
}

async function dbConnect() {
  if (global.__MONGO_CONN__) {
    return global.__MONGO_CONN__;
  }
  if (!process.env.MONGODB_URI) {
    throw new Error("MONGODB_URI is not defined in .env");
  }
  // Connect with options tailored for serverless environments.
  global.__MONGO_CONN__ = mongoose
    .connect(process.env.MONGODB_URI, {
      connectTimeoutMS: 30000,
      socketTimeoutMS: 30000,
      tls: true,
      tlsAllowInvalidCertificates: process.env.NODE_ENV !== 'production',
      retryWrites: false
    })
    .then(conn => {
      console.log("MongoDB connected (cached)");
      return conn;
    })
    .catch(err => {
      console.error("MongoDB connection error:", err);
      // Instead of process.exit(1), we throw the error.
      throw err;
    });
  return global.__MONGO_CONN__;
}

// Initiate the connection on cold start.
dbConnect().catch(err => {
  // Log error on cold start; the function will error out when invoked.
  console.error("Initial MongoDB connection failed:", err);
});

// -----------------------------
// Express Middleware & Configuration
// -----------------------------
app.set('trust proxy', 1);

// Logger configuration with Winston.
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.json()
  ),
  transports: [
      new winston.transports.Console(),
      new winston.transports.File({ filename: 'error.log', level: 'error' }),
      new winston.transports.File({ filename: 'combined.log' })
  ],
});

// Simplified CORS configuration.
app.use(cors({
  origin: 'https://crypto1-ten.vercel.app', // Update this URL as needed.
  credentials: true,
}));
app.options('*', cors());

app.use(express.json());
app.use(cookieParser());
app.use(helmet());
app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  keyGenerator: (req, res) => req.ip || req.headers['x-forwarded-for'] || 'unknown',
  message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

// -----------------------------
// Mongoose User Schema & Model
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
  refreshToken: { type: String }
}, { timestamps: true });
const User = mongoose.models.User || mongoose.model('User', userSchema);

// -----------------------------
// Utility Functions for JWT Tokens
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
// Middleware: Protect Routes
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
    const user = await User.create({
      username,
      email,
      password: hashedPassword,
      country,
      phoneNumber,
      role: "user"
    });
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

app.post('/api/auth/signin', async (req, res) => {
  try {
    await dbConnect();
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Please provide email and password' });
    }
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
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
    res.status(200).json({ message: 'Sign in successful', accessToken, roles: [user.role] });
  } catch (error) {
    logger.error('Sign in error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/auth/protected', protect, async (req, res) => {
  try {
    await dbConnect();
    const user = await User.findById(req.user.id).select('-password -__v -refreshToken');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.status(200).json({ user });
  } catch (error) {
    logger.error('Protected route error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/refresh', async (req, res) => {
  try {
    await dbConnect();
    const { refreshToken } = req.cookies;
    if (!refreshToken) {
      return res.status(401).json({ error: 'No refresh token provided' });
    }
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(decoded.id);
    if (!user || user.refreshToken !== refreshToken) {
      return res.status(403).json({ error: 'Invalid refresh token' });
    }
    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);
    user.refreshToken = newRefreshToken;
    await user.save();
    res.cookie('refreshToken', newRefreshToken, { 
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 7 * 24 * 60 * 60 * 1000 
    });
    res.status(200).json({ accessToken: newAccessToken });
  } catch (error) {
    logger.error('Refresh token error:', error);
    res.status(401).json({ error: 'Invalid refresh token' });
  }
});

// -----------------------------
// Payment Endpoints (Using Paystack)
// -----------------------------
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const baseURL = process.env.PAYSTACK_BASE_URL || 'https://api.paystack.co';

async function verifyTransaction(reference) {
  try {
    const response = await axios.get(
      `${baseURL}/transaction/verify/${encodeURIComponent(reference)}`,
      { headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` } }
    );
    logger.info({ action: 'VerificationResponse', reference, status: response.status, data: response.data });
    return response.data;
  } catch (error) {
    logger.error({ action: 'VerificationError', reference, error: error.response ? error.response.data : error.message });
    throw error;
  }
}

app.post('/initiate-payment', async (req, res) => {
  try {
    await dbConnect();
    const { amount, email, phone } = req.body;
    logger.info({ action: 'PaymentInitiated', amount, email, phone });
    const response = await axios.post(
      `${baseURL}/charge`,
      { amount: amount * 100, email, mobile_money: { phone, provider: 'mpesa' } },
      { headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`, 'Content-Type': 'application/json' } }
    );
    logger.info({ action: 'PaystackAPIResponse', status: response.status, data: response.data });
    const verification = await verifyTransaction(response.data.data.reference);
    res.json({ success: true, paymentInitiated: response.data, verificationResult: verification });
  } catch (error) {
    logger.error({ action: 'PaymentError', error: error.response ? error.response.data : error.message, stack: error.stack });
    const statusCode = error.response ? error.response.status : 500;
    res.status(statusCode).json({ success: false, error: error.response ? error.response.data : error.message });
  }
});

app.get('/verify-payment/:reference', async (req, res) => {
  try {
    await dbConnect();
    const { reference } = req.params;
    logger.info({ action: 'ManualVerificationAttempt', reference });
    const result = await verifyTransaction(reference);
    if (result.data.status === 'success') {
      const amount = result.data.amount / 100;
      const user = await User.findOne({ email: result.data.customer.email });
      if (user) {
        user.investmentBalance += amount;
        user.totalInvested += amount;
        user.mines = Math.floor(user.investmentBalance / 500);
        await user.save();
      }
    }
    res.json({ success: true, verifiedData: result.data });
  } catch (error) {
    res.status(500).json({ success: false, error: error.response ? error.response.data : error.message });
  }
});

app.post('/paystack-webhook', (req, res) => {
  const signature = req.headers['x-paystack-signature'];
  const hash = crypto.createHmac('sha512', PAYSTACK_SECRET_KEY)
                     .update(JSON.stringify(req.body))
                     .digest('hex');
  if (hash !== signature) {
    logger.error({ action: 'WebhookSecurityFail', receivedSignature: signature, computedHash: hash });
    return res.status(401).send('Unauthorized');
  }
  const event = req.body;
  logger.info({ action: 'WebhookReceived', event });
  switch (event.event) {
    case 'charge.success':
      logger.info({ action: 'PaymentSuccess', data: event.data });
      User.findOne({ email: event.data.customer.email }).then(user => {
        if (user) {
          user.investmentBalance += event.data.amount / 100;
          user.totalInvested += event.data.amount / 100;
          user.mines = Math.floor(user.investmentBalance / 500);
          user.save();
        }
      });
      break;
    case 'charge.failed':
      logger.error({ action: 'PaymentFailed', data: event.data });
      break;
    case 'transfer.success':
      logger.info({ action: 'TransferSuccess', data: event.data });
      break;
    default:
      logger.info({ action: 'UnhandledEvent', data: event });
  }
  res.sendStatus(200);
});

// -----------------------------
// Start Server / Export for Serverless Deployment
// -----------------------------
if (process.env.NODE_ENV !== 'serverless') {
  app.listen(PORT, () => {
    logger.info(`Server running on port ${PORT}`);
  });
}

// Export both the Express app and the serverless handler.
const handler = serverless(app);
module.exports = handler;
module.exports.app = app;
