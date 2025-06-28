require('module-alias/register');
const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const xss = require("xss-clean");
const hpp = require("hpp");
const mongoSanitize = require("express-mongo-sanitize");
const validator = require("validator");
const crypto = require("crypto");
const https = require("https");
const fs = require("fs");
const path = require("path");
const morgan = require("morgan");
const winston = require("winston");
const expressWinston = require("express-winston");
const toobusy = require("toobusy-js");
const csrf = require("csurf");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const { createLogger, transports, format } = require('winston');
require('winston-daily-rotate-file'); // Add this at the top with other requires
// Load .env variables
dotenv.config();

// Initialize express app
const app = express();

// ========================
// SECURITY CONFIGURATION
// ========================

// 1. HTTPS Enforcement (in production)
if (process.env.NODE_ENV === 'production') {
  app.use((req, res, next) => {
    if (!req.secure) {
      return res.redirect(`https://${req.headers.host}${req.url}`);
    }
    next();
  });
}

// 2. Advanced Security Headers with Helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  },
  hsts: {
    maxAge: 63072000, // 2 years in seconds
    includeSubDomains: true,
    preload: true
  },
  referrerPolicy: { policy: 'same-origin' }
}));

// 3. CORS Configuration (Restrict to your frontend domains)
const whitelist = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : [];
const corsOptions = {
  origin: function (origin, callback) {
    if (whitelist.indexOf(origin) !== -1 || !origin) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-CSRF-Token'],
  credentials: true,
  maxAge: 86400 // 24 hours
};
app.use(cors(corsOptions));

// 4. Rate Limiting (Advanced)
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again after 15 minutes',
  skip: (req) => {
    // Skip rate limiting for certain paths or in development
    return req.path === '/healthcheck' || process.env.NODE_ENV === 'development';
  },
  handler: (req, res) => {
    res.status(429).json({
      status: 'error',
      message: 'Too many requests, please try again later.'
    });
  }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 1 hour
  max: 15, // limit each IP to 5 login attempts per hour
  message: 'Too many login attempts from this IP, please try again after an hour'
});

app.use('/api/v1/signin', authLimiter);
app.use('/api/v1/signup', authLimiter);
app.use('/api/v1/', apiLimiter);

// 5. Other Security Middleware
app.use(xss()); // Prevent XSS attacks
app.use(hpp()); // Prevent HTTP Parameter Pollution
app.use(mongoSanitize()); // Sanitize data against NoSQL injection
app.use(cookieParser(process.env.COOKIE_SECRET)); // Signed cookies
app.use(express.json({ limit: "10kb" })); // Body parser
app.use(express.urlencoded({ extended: true, limit: "10kb" }));

// 6. Session Configuration (for CSRF protection)
app.use(session({
  name: 'sessionId',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGO_URI,
    ttl: 24 * 60 * 60 // 1 day
  }),
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000 // 1 day
  }
}));

// 7. CSRF Protection
const csrfProtection = csrf({
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'strict'
  }
});
app.use(csrfProtection);

// 8. Request Size Limiting
app.use((req, res, next) => {
  if (req.headers['content-length'] > 1024 * 10) { // 10KB
    return res.status(413).json({
      status: 'fail',
      message: 'Request entity too large'
    });
  }
  next();
});

// 9. Server Overload Protection
app.use((req, res, next) => {
  if (toobusy()) {
    res.status(503).json({
      status: 'error',
      message: 'Server too busy. Please try again later.'
    });
  } else {
    next();
  }
});

// ========================
// LOGGING & MONITORING
// ========================

// 1. Request Logging
app.use(morgan('combined', {
  skip: (req, res) => req.path === '/healthcheck'
}));

// 2. Error/Activity Logging
// Replace the existing logger with:
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.DailyRotateFile({
      filename: 'logs/error-%DATE%.log',
      level: 'error',
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '30d' // Keep logs for 30 days
    }),
    new winston.transports.DailyRotateFile({
      filename: 'logs/combined-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '30d'
    }),
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ],
  exceptionHandlers: [
    new winston.transports.DailyRotateFile({
      filename: 'logs/exceptions-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '30d'
    })
  ]
});
const logDir = 'logs';

if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir);
  logger.info(`Created ${logDir} directory for logs`);
}
// 3. Express Winston for request/response logging
app.use(expressWinston.logger({
  winstonInstance: logger,
  meta: true,
  msg: 'HTTP {{req.method}} {{req.url}}',
  expressFormat: true,
  colorize: false,
  ignoreRoute: (req, res) => req.path === '/healthcheck'
}));

// ========================
// DATABASE CONFIGURATION
// ========================

// MongoDB connection with retry logic
const connectWithRetry = () => {
  mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
    maxPoolSize: 10,
    retryWrites: true,
    w: 'majority'
  })
  .then(() => logger.info("Connected to MongoDB"))
  .catch(err => {
    logger.error("MongoDB connection error:", err);
    setTimeout(connectWithRetry, 5000);
  });
};
connectWithRetry();

// ========================
// USER MODEL
// ========================

// User Schema with enhanced security
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, "Email is required"],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, "Please provide a valid email"],
    index: true
  },
  password: {
    type: String,
    required: [true, "Password is required"],
    minlength: [12, "Password must be at least 12 characters"],
    select: false
  },
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  loginAttempts: { type: Number, default: 0 },
  lockUntil: { type: Date },
  twoFactorSecret: String,
  twoFactorEnabled: { type: Boolean, default: false },
  createdAt: {
    type: Date,
    default: Date.now,
    immutable: true
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});
// Add this after the schema definition but before creating the model
userSchema.index({ email: 1 }, { unique: true }); // Faster email lookups
userSchema.index({ passwordResetToken: 1 }, { expireAfterSeconds: 600 }); // Auto-delete expired tokens
userSchema.index({ lockUntil: 1 }, { sparse: true }); // Optimize account lock queries
// Password hashing with stronger salt
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  
  try {
    const salt = await bcrypt.genSalt(16); // Increased salt rounds
    this.password = await bcrypt.hash(this.password, salt);
    this.passwordChangedAt = Date.now() - 1000; // Ensure token is created after
    next();
  } catch (err) {
    next(err);
  }
});

// Account lockout for brute force protection
userSchema.methods.incrementLoginAttempts = async function() {
  if (this.lockUntil && this.lockUntil > Date.now()) {
    throw new Error('Account is temporarily locked');
  }
  
  this.loginAttempts += 1;
  
  if (this.loginAttempts >= 5) {
    this.lockUntil = Date.now() + 30 * 60 * 1000; // Lock for 30 minutes
  }
  
  await this.save();
};

userSchema.methods.resetLoginAttempts = async function() {
  this.loginAttempts = 0;
  this.lockUntil = undefined;
  await this.save();
};

// Method to compare passwords with timing-safe comparison
userSchema.methods.comparePassword = async function (candidatePassword) {
  if (this.lockUntil && this.lockUntil > Date.now()) {
    throw new Error('Account is temporarily locked. Try again later.');
  }
  
  const isMatch = await bcrypt.compare(candidatePassword, this.password);
  
  if (!isMatch) {
    await this.incrementLoginAttempts();
    return false;
  }
  
  await this.resetLoginAttempts();
  return true;
};

// Check if password was changed after token was issued
userSchema.methods.changedPasswordAfter = function(JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

// Generate password reset token
userSchema.methods.createPasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');
  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
  return resetToken;
};

const User = mongoose.model("User", userSchema);
User.createIndexes().catch(err => 
  logger.error("User index creation error:", err)
);
// ========================
// AUTH UTILITIES
// ========================

// Generate JWT Token with enhanced security
const createSendToken = (user, statusCode, req, res) => {
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '1h', // Shorter expiration
    issuer: process.env.JWT_ISSUER || 'your-company',
    audience: process.env.JWT_AUDIENCE || 'your-app',
    algorithm: 'HS256'
  });

  const cookieOptions = {
    expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000),
    httpOnly: true,
    secure: req.secure || req.headers['x-forwarded-proto'] === 'https',
    sameSite: 'strict',
    domain: process.env.COOKIE_DOMAIN
  };

  res.cookie('jwt', token, cookieOptions);

  // Remove sensitive data from output
  user.password = undefined;
  user.passwordChangedAt = undefined;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  user.twoFactorSecret = undefined;
  user.loginAttempts = undefined;
  user.lockUntil = undefined;

  res.status(statusCode).json({
    status: "success",
    token,
    csrfToken: req.csrfToken(),
    data: {
      user
    }
  });
};

// Input validation middleware with stricter rules
const validateSignup = (req, res, next) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({
      status: "fail",
      message: "Email and password are required",
    });
  }
  
  if (!validator.isEmail(email)) {
    return res.status(400).json({
      status: "fail",
      message: "Please provide a valid email",
    });
  }
  
  if (password.length < 12) {
    return res.status(400).json({
      status: "fail",
      message: "Password must be at least 12 characters",
    });
  }

  if (!validator.isStrongPassword(password, { 
    minLength: 12, 
    minLowercase: 1, 
    minUppercase: 1, 
    minNumbers: 1, 
    minSymbols: 1 
  })) {
    return res.status(400).json({
      status: "fail",
      message: "Password must contain at least one uppercase, one lowercase, one number and one symbol"
    });
  }
  
  next();
};

// ========================
// ROUTES
// ========================

// Health check endpoint
app.get('/healthcheck', (req, res) => {
    const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
  res.status(200).json({
    status: 'ok',
    uptime: process.uptime(),
    db: dbStatus,  // Add this line
    timestamp: new Date()
  });
});

// Home route
app.get("/", (req, res) => {
  res.send("API is running...");
});

// Signup Route with enhanced security
app.post("/api/v1/signup", validateSignup, async (req, res, next) => {
  try {
    const { email, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        status: "fail",
        message: "User already exists with this email",
      });
    }

    // Additional security checks
    if (validator.contains(email, '<script>') || validator.contains(password, '<script>')) {
      return res.status(400).json({
        status: "fail",
        message: "Invalid input detected"
      });
    }

    const newUser = await User.create({ email, password });
    createSendToken(newUser, 201, req, res);
  } catch (err) {
    logger.error("Signup error:", err);
    res.status(500).json({
      status: "error",
      message: "Internal server error",
    });
  }
});

// Signin Route with brute force protection
app.post("/api/v1/signin", async (req, res, next) => {
  try {
    const { email, password } = req.body;

    // 1) Check if email and password exist
    if (!email || !password) {
      return res.status(400).json({
        status: "fail",
        message: "Please provide email and password",
      });
    }

    // 2) Check if user exists
    const user = await User.findOne({ email }).select("+password +loginAttempts +lockUntil");

    if (!user) {
      // Simulate password comparison to prevent timing attacks
      await bcrypt.compare(password, '$2a$12$fakehashforsecurity');
      return res.status(401).json({
        status: "fail",
        message: "Incorrect email or password",
      });
    }

    // 3) Check if account is locked
    if (user.lockUntil && user.lockUntil > Date.now()) {
      const remainingTime = Math.ceil((user.lockUntil - Date.now()) / (60 * 1000));
      return res.status(403).json({
        status: "fail",
        message: `Account is temporarily locked. Try again in ${remainingTime} minutes.`
      });
    }

    // 4) Check if password is correct
    if (!(await user.comparePassword(password))) {
      return res.status(401).json({
        status: "fail",
        message: "Incorrect email or password",
      });
    }

    // 5) If everything ok, send token to client
    createSendToken(user, 200, req, res);
  } catch (err) {
    logger.error("Signin error:", err);
    res.status(500).json({
      status: "error",
      message: "Internal server error",
    });
  }
});

// Protected route example with JWT verification
const protect = async (req, res, next) => {
  try {
    // 1) Getting token and check if it's there
    let token;
    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith("Bearer")
    ) {
      token = req.headers.authorization.split(" ")[1];
    } else if (req.cookies.jwt) {
      token = req.cookies.jwt;
    }

    if (!token) {
      return res.status(401).json({
        status: "fail",
        message: "You are not logged in! Please log in to get access.",
      });
    }

    // 2) Verification token
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: process.env.JWT_ISSUER,
      audience: process.env.JWT_AUDIENCE
    });

    // 3) Check if user still exists
    const currentUser = await User.findById(decoded.id);
    if (!currentUser) {
      return res.status(401).json({
        status: "fail",
        message: "The user belonging to this token does no longer exist.",
      });
    }

    // 4) Check if user changed password after the token was issued
    if (currentUser.changedPasswordAfter(decoded.iat)) {
      return res.status(401).json({
        status: "fail",
        message: "User recently changed password! Please log in again.",
      });
    }

    // 5) Grant access to protected route
    req.user = currentUser;
    res.locals.user = currentUser;
    next();
  } catch (err) {
    logger.error("Authentication error:", err);
    res.status(401).json({
      status: "fail",
      message: "Invalid token. Please log in again.",
    });
  }
};

// Example protected route
app.get("/api/v1/protected", protect, (req, res) => {
  res.status(200).json({
    status: "success",
    data: {
      user: req.user
    }
  });
});

// Logout route
app.get("/api/v1/logout", (req, res) => {
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true
  });
  res.status(200).json({ status: "success" });
});

// ========================
// ERROR HANDLING
// ========================

// 404 Handler
app.all('*', (req, res) => {
  res.status(404).json({
    status: 'fail',
    message: `Can't find ${req.originalUrl} on this server!`
  });
});

// Global error handler
app.use((err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';

  logger.error(`${err.statusCode} - ${err.message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);

  if (process.env.NODE_ENV === 'development') {
    res.status(err.statusCode).json({
      status: err.status,
      message: err.message,
      stack: err.stack,
      error: err
    });
  } else {
    // Production error handling - don't leak stack traces
    if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid or expired token. Please log in again.'
      });
    }

    res.status(err.statusCode).json({
      status: err.status,
      message: err.message
    });
  }
});

// ========================
// SERVER INITIALIZATION
// ========================

// HTTPS Server (in production)
let server;
// Render handles HTTPS automatically - no need for manual SSL config
if (process.env.NODE_ENV === 'production') {
  // Trust Render's proxy
  app.set('trust proxy', 1);
  
  // Use HTTP server (Render terminates SSL at the load balancer)
  server = app.listen(process.env.PORT || 10000, () => {
    logger.info(`Server running on port ${process.env.PORT || 10000}`);
  });
} else {
  server = app.listen(process.env.PORT || 5000, () => {
    logger.info(`Server running on port ${process.env.PORT || 5000}`);
  });
}

// Handle unhandled rejections
process.on('unhandledRejection', (err) => {
  logger.error('UNHANDLED REJECTION! 💥 Shutting down...');
  logger.error(err.name, err.message);
  server.close(() => {
    process.exit(1);
  });
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  logger.error('UNCAUGHT EXCEPTION! 💥 Shutting down...');
  logger.error(err.name, err.message);
  server.close(() => {
    process.exit(1);
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('👋 SIGTERM RECEIVED. Shutting down gracefully');
  server.close(() => {
    logger.info('💥 Process terminated!');
  });
});