const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { customAlphabet } = require('nanoid');
const winston = require('winston');


dotenv.config();

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

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    logger.info('MongoDB connected successfully');
  } catch (err) {
    logger.error(`MongoDB connection error: ${err.message}`);
    process.exit(1);
  }
};

const UserSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) {
    next();
  }
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

UserSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', UserSchema);

const UrlSchema = new mongoose.Schema({
  originalUrl: {
    type: String,
    required: true,
  },
  shortCode: {
    type: String,
    required: true,
    unique: true,
  },
  clickCount: {
    type: Number,
    default: 0,
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  expiresAt: {
    type: Date,
  },
});

const Url = mongoose.model('Url', UrlSchema);

const generateShortCode = customAlphabet('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 7);

const protect = (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    try {
      token = req.headers.authorization.split(' ')[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded.id;
      next();
    } catch (error) {
      logger.error(`Authentication error: ${error.message}`);
      return res.status(401).json({ message: 'Unauthorized access: Invalid token' });
    }
  }
  if (!token) {
    return res.status(401).json({ message: 'Unauthorized access: No token provided' });
  }
};

const errorHandler = (err, req, res, next) => {
  logger.error(`Server error: ${err.message}`, { stack: err.stack });
  const statusCode = res.statusCode === 200 ? 500 : res.statusCode;
  res.status(statusCode).json({
    message: err.message,
    stack: process.env.NODE_ENV === 'production' ? null : err.stack,
  });
};

const registerUser = async (req, res, next) => {
  const { email, password } = req.body;
  try {
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: 'User already exists' });
    }
    const user = await User.create({ email, password });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.status(201).json({
      message: 'User registered successfully',
      token,
      email: user.email,
    });
    logger.info(`User registered: ${user.email}`);
  } catch (error) {
    next(error);
  }
};

const authUser = async (req, res, next) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (user && (await user.matchPassword(password))) {
      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
      res.status(200).json({
        message: 'Authentication successful',
        token,
        email: user.email,
      });
      logger.info(`User logged in: ${user.email}`);
    } else {
      res.status(401).json({ message: 'Invalid email or password' });
    }
  } catch (error) {
    next(error);
  }
};

const createShortUrl = async (req, res, next) => {
  const { originalUrl, customCode, expiresIn } = req.body;
  let shortCode;
  try {
    if (!originalUrl) {
      return res.status(400).json({ message: 'Original URL is required' });
    }
    if (customCode) {
      const existingUrl = await Url.findOne({ shortCode: customCode });
      if (existingUrl) {
        return res.status(409).json({ message: 'Custom short code already in use' });
      }
      shortCode = customCode;
    } else {
      let unique = false;
      while (!unique) {
        shortCode = generateShortCode();
        const existingUrl = await Url.findOne({ shortCode });
        if (!existingUrl) {
          unique = true;
        }
      }
    }
    let expiresAt = null;
    if (expiresIn) {
      const expirationTime = Date.now() + expiresIn * 1000;
      expiresAt = new Date(expirationTime);
    }
    const url = await Url.create({
      originalUrl,
      shortCode,
      userId: req.user,
      expiresAt,
    });
    const shortUrl = `${req.protocol}://${req.get('host')}/${url.shortCode}`;
    const analyticsUrl = `${req.protocol}://${req.get('host')}/api/links/${url.shortCode}/analytics`;
    res.status(201).json({
      message: 'Short URL created successfully',
      shortUrl,
      analyticsUrl,
      originalUrl: url.originalUrl,
      shortCode: url.shortCode,
      createdAt: url.createdAt,
      expiresAt: url.expiresAt,
    });
    logger.info(`Short URL created: ${shortUrl} for user ${req.user}`);
  } catch (error) {
    next(error);
  }
};

const redirectToOriginalUrl = async (req, res, next) => {
  const { shortCode } = req.params;
  try {
    const url = await Url.findOne({ shortCode });
    if (!url) {
      logger.warn(`Redirection failed: Short code ${shortCode} not found`);
      return res.status(404).json({ message: 'Short URL not found' });
    }
    if (url.expiresAt && url.expiresAt < Date.now()) {
      logger.warn(`Redirection failed: Short code ${shortCode} expired`);
      return res.status(410).json({ message: 'Short URL has expired' });
    }
    url.clickCount += 1;
    await url.save();
    logger.info(`Redirecting ${shortCode} to ${url.originalUrl}. Click count: ${url.clickCount}`);
    res.redirect(url.originalUrl);
  } catch (error) {
    next(error);
  }
};

const getLinkAnalytics = async (req, res, next) => {
  const { shortCode } = req.params;
  try {
    const url = await Url.findOne({ shortCode, userId: req.user });
    if (!url) {
      logger.warn(`Analytics access failed: Short code ${shortCode} not found or unauthorized for user ${req.user}`);
      return res.status(404).json({ message: 'Link not found or unauthorized' });
    }
    res.status(200).json({
      message: 'Link analytics retrieved successfully',
      shortCode: url.shortCode,
      originalUrl: url.originalUrl,
      clickCount: url.clickCount,
      createdAt: url.createdAt,
      expiresAt: url.expiresAt,
    });
    logger.info(`Analytics retrieved for short code ${shortCode} by user ${req.user}`);
  } catch (error) {
    next(error);
  }
};

const getUserLinks = async (req, res, next) => {
  try {
    const urls = await Url.find({ userId: req.user });
    res.status(200).json({
      message: 'User links retrieved successfully',
      links: urls.map(url => ({
        shortCode: url.shortCode,
        originalUrl: url.originalUrl,
        clickCount: url.clickCount,
        createdAt: url.createdAt,
        expiresAt: url.expiresAt,
        shortUrl: `${req.protocol}://${req.get('host')}/${url.shortCode}`,
        analyticsUrl: `${req.protocol}://${req.get('host')}/api/links/${url.shortCode}/analytics`,
      })),
    });
    logger.info(`User links listed for user ${req.user}`);
  } catch (error) {
    next(error);
  }
};

const deleteShortUrl = async (req, res, next) => {
  const { shortCode } = req.params;
  try {
    const result = await Url.deleteOne({ shortCode, userId: req.user });
    if (result.deletedCount === 0) {
      logger.warn(`Deletion failed: Short code ${shortCode} not found or unauthorized for user ${req.user}`);
      return res.status(404).json({ message: 'Link not found or unauthorized' });
    }
    res.status(200).json({ message: 'Link deleted successfully', shortCode });
    logger.info(`Short URL deleted: ${shortCode} by user ${req.user}`);
  } catch (error) {
    next(error);
  }
};

const app = express();

connectDB();

app.use(express.json());

// // ---
// ## Enhanced Logging with Sensitive Data Redaction
// ---
// ```javascript
// app.use((req, res, next) => {
//   const logData = {
//     ip: req.ip,
//     method: req.method,
//     url: req.url,
//     userAgent: req.headers['user-agent'],
//     params: req.params,
//   };

//   // Create a copy of the body to avoid modifying the original request object
//   const bodyToLog = { ...req.body };

//   // Redact sensitive fields
//   if (bodyToLog.password) {
//     bodyToLog.password = '[REDACTED]';
//   }
//   if (bodyToLog.email && (req.url === '/api/auth/register' || req.url === '/api/auth/login')) {
//     bodyToLog.email = '[REDACTED]';
//   }

//   logData.body = bodyToLog;

//   logger.info(`${req.method} ${req.url}`, logData);
//   next();
// });

app.post('/api/auth/register', registerUser);
app.post('/api/auth/login', authUser);

app.post('/api/shorten', protect, createShortUrl);
app.get('/api/links', protect, getUserLinks);
app.get('/api/links/:shortCode/analytics', protect, getLinkAnalytics);
app.delete('/api/links/:shortCode', protect, deleteShortUrl);

app.get('/:shortCode', redirectToOriginalUrl);

app.use(errorHandler);

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});