require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

const app = express();

// Security Middlewares
app.use(helmet());
app.use(cors());
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// User Schema
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
// Health Profile Schema
const HealthProfileSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  email: { type: String, required: true, unique: true },
  username: { type: String, required: true },
  age: { type: Number, required: true },
  gender: { type: String, required: true, enum: ['Male', 'Female', 'Other'] },
  height: { type: Number, required: true }, // in cm
  weight: { type: Number, required: true }, // in kg
  targetWeight: { type: Number },
  bloodGroup: { type: String, enum: ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-'] },
  conditions: [{ type: String }],
  dietPreference: { type: String, enum: ['Vegetarian', 'Vegan', 'Non-vegetarian', 'Pescatarian', 'Keto', 'Paleo', 'Other'] },
  healthGoal: { type: String, enum: ['Weight Loss', 'Weight Gain', 'Maintain Weight', 'Muscle Building', 'Improve Fitness', 'Manage Condition'] },
  dailyCalorieTarget: { type: Number },
  bmi: { type: Number },
  smokingHabit: { type: String, enum: ['Non-smoker', 'Occasional', 'Regular', 'Former smoker'] },
  alcoholConsumption: { type: String, enum: ['Non-drinker', 'Occasional', 'Regular', 'Former drinker'] },
  emergencyContact: {
    name: { type: String },
    phone: { type: String }
  },
  allergies: [{ type: String }],
  medications: [{ 
    name: { type: String },
    dosage: { type: String },
    frequency: { type: String }
  }],
  activityLevel: { type: String, enum: ['Sedentary', 'Lightly Active', 'Moderately Active', 'Very Active', 'Extremely Active'] },
  sleepHours: { type: Number },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Calculate BMI before saving
HealthProfileSchema.pre('save', function(next) {
  if (this.height && this.weight) {
    const heightInMeters = this.height / 100;
    this.bmi = parseFloat((this.weight / (heightInMeters * heightInMeters)).toFixed(1));
  }
  this.updatedAt = Date.now();
  next();
});

const HealthProfile = mongoose.model('HealthProfile', HealthProfileSchema);
// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Input Validation Middleware
const validateInputs = (method) => {
  switch (method) {
    case 'signup': {
      return [
        body('username').not().isEmpty().trim().escape(),
        body('email').isEmail().normalizeEmail(),
        body('password').isLength({ min: 6 })
      ]
    }
    case 'signin': {
      return [
        body('email').isEmail().normalizeEmail(),
        body('password').exists()
      ]
    }
    case 'updatePassword': {
      return [
        body('currentPassword').exists(),
        body('newPassword').isLength({ min: 6 })
      ]
    }
    case 'updateProfile': {
      return [
        body('username').optional().not().isEmpty().trim().escape(),
        body('email').optional().isEmail().normalizeEmail()
      ]
    }
  }
}

// Auth Middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    req.user = user;
    next();
  } catch (err) {
    console.error(err);
    res.status(401).json({ message: 'Invalid token' });
  }
}

// Generate JWT Token
const generateToken = (userId) => {
  return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: '1h' });
}

// Signup Route
app.post('/signup', validateInputs('signup'), async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { username, email, password } = req.body;

    // Check if user exists
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new user
    user = new User({
      username,
      email,
      password: hashedPassword
    });

    await user.save();

    // Generate token
    const token = generateToken(user._id);

    res.status(201).json({ token, userId: user._id, username: user.username });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Signin Route
app.post('/signin', validateInputs('signin'), async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { email, password } = req.body;

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Generate token
    const token = generateToken(user._id);

    res.json({ token, userId: user._id, username: user.username });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});
// Get Health Profile
app.get('/health-profile', authenticate, async (req, res) => {
  try {
    const healthProfile = await HealthProfile.findOne({ userId: req.user._id });
    
    if (!healthProfile) {
      return res.status(404).json({ message: 'Health profile not found' });
    }
    
    res.json(healthProfile);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create/Update Health Profile
app.post('/health-profile', authenticate, [
  body('age').isInt({ min: 1, max: 120 }),
  body('gender').isIn(['Male', 'Female', 'Other']),
  body('height').isFloat({ min: 50, max: 250 }),
  body('weight').isFloat({ min: 2, max: 300 }),
  body('bloodGroup').optional().isIn(['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-']),
  body('dietPreference').optional().isIn(['Vegetarian', 'Vegan', 'Non-vegetarian', 'Pescatarian', 'Keto', 'Paleo', 'Other']),
  body('healthGoal').optional().isIn(['Weight Loss', 'Weight Gain', 'Maintain Weight', 'Muscle Building', 'Improve Fitness', 'Manage Condition']),
  body('dailyCalorieTarget').optional().isInt({ min: 500, max: 10000 }),
  body('smokingHabit').optional().isIn(['Non-smoker', 'Occasional', 'Regular', 'Former smoker']),
  body('alcoholConsumption').optional().isIn(['Non-drinker', 'Occasional', 'Regular', 'Former drinker']),
  body('activityLevel').optional().isIn(['Sedentary', 'Lightly Active', 'Moderately Active', 'Very Active', 'Extremely Active']),
  body('sleepHours').optional().isFloat({ min: 0, max: 24 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const {
      age, gender, height, weight, targetWeight, bloodGroup,
      conditions, dietPreference, healthGoal, dailyCalorieTarget,
      smokingHabit, alcoholConsumption, emergencyContact,
      allergies, medications, activityLevel, sleepHours
    } = req.body;

    let healthProfile = await HealthProfile.findOne({ userId: req.user._id });

    if (healthProfile) {
      // Update existing profile
      healthProfile = await HealthProfile.findOneAndUpdate(
        { userId: req.user._id },
        {
          age, gender, height, weight, targetWeight, bloodGroup,
          conditions, dietPreference, healthGoal, dailyCalorieTarget,
          smokingHabit, alcoholConsumption, emergencyContact,
          allergies, medications, activityLevel, sleepHours
        },
        { new: true, runValidators: true }
      );
    } else {
      // Create new profile
      healthProfile = new HealthProfile({
        userId: req.user._id,
        email: req.user.email,
        username: req.user.username,
        age, gender, height, weight, targetWeight, bloodGroup,
        conditions, dietPreference, healthGoal, dailyCalorieTarget,
        smokingHabit, alcoholConsumption, emergencyContact,
        allergies, medications, activityLevel, sleepHours
      });
      await healthProfile.save();
    }

    res.json({ message: 'Health profile saved successfully', healthProfile });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});
// Update Password Route
app.put('/update-password', authenticate, validateInputs('updatePassword'), async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { currentPassword, newPassword } = req.body;
    const user = req.user;

    // Check current password
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Current password is incorrect' });
    }

    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    // Update password
    user.password = hashedPassword;
    await user.save();

    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update Profile Route
app.put('/update-profile', authenticate, validateInputs('updateProfile'), async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { username, email } = req.body;
    const user = req.user;

    // Check if new email is already taken
    if (email && email !== user.email) {
      const emailExists = await User.findOne({ email });
      if (emailExists) {
        return res.status(400).json({ message: 'Email already in use' });
      }
    }

    // Check if new username is already taken
    if (username && username !== user.username) {
      const usernameExists = await User.findOne({ username });
      if (usernameExists) {
        return res.status(400).json({ message: 'Username already in use' });
      }
    }

    // Update fields
    if (username) user.username = username;
    if (email) user.email = email;

    await user.save();

    res.json({ 
      message: 'Profile updated successfully',
      user: {
        username: user.username,
        email: user.email,
        createdAt: user.createdAt
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete Account Route
app.delete('/delete-account', authenticate, async (req, res) => {
  try {
    const user = req.user;
    await User.findByIdAndDelete(user._id);
    res.json({ message: 'Account deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Protected Route Example
app.get('/profile', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something broke!' });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});