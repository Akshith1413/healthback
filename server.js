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

// Add virtual for health profile
UserSchema.virtual('healthProfile', {
  ref: 'HealthProfile',
  localField: '_id',
  foreignField: 'userId',
  justOne: true
});

// Enable virtuals in toJSON and toObject
UserSchema.set('toJSON', { virtuals: true });
UserSchema.set('toObject', { virtuals: true });
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
const FamilySchema = new mongoose.Schema({
  familyName: { type: String, required: true },
  owner: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  members: [{
    user: { 
      type: mongoose.Schema.Types.ObjectId, 
      ref: 'User', 
      required: true 
    },
    role: { 
      type: String, 
      enum: ['owner', 'member', 'child', 'elder'], 
      default: 'member' 
    },
    joinedAt: { 
      type: Date, 
      default: Date.now 
    },
    status: { 
      type: String, 
      enum: ['pending', 'accepted', 'rejected'], 
      default: 'pending' 
    }
  }],
  createdAt: { 
    type: Date, 
    default: Date.now 
  },
  updatedAt: { 
    type: Date, 
    default: Date.now 
  }
});

// Update timestamp before saving
FamilySchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

const Family = mongoose.model('Family', FamilySchema);

// Family Request Schema
const FamilyRequestSchema = new mongoose.Schema({
  fromUser: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  toUser: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  family: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Family', 
    required: true 
  },
  status: { 
    type: String, 
    enum: ['pending', 'accepted', 'rejected'], 
    default: 'pending' 
  },
  message: { 
    type: String, 
    default: '' 
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  },
  updatedAt: { 
    type: Date, 
    default: Date.now 
  }
});

// Update timestamp before saving
FamilyRequestSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

const FamilyRequest = mongoose.model('FamilyRequest', FamilyRequestSchema);
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
// Get user's family
app.get('/family', authenticate, async (req, res) => {
  try {
    const family = await Family.findOne({
      $or: [
        { owner: req.user._id },
        { 'members.user': req.user._id, 'members.status': 'accepted' }
      ]
    }).populate('owner', 'username email')
      .populate('members.user', 'username email');
    
    if (!family) {
      return res.status(404).json({ message: 'No family found' });
    }
    
    res.json(family);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create new family
app.post('/family', authenticate, [
  body('familyName').not().isEmpty().trim().escape()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { familyName } = req.body;

    // Check if user already has a family
    const existingFamily = await Family.findOne({
      $or: [
        { owner: req.user._id },
        { 'members.user': req.user._id, 'members.status': 'accepted' }
      ]
    });

    if (existingFamily) {
      return res.status(400).json({ message: 'You already belong to a family' });
    }

    // Create new family
    const family = new Family({
      familyName,
      owner: req.user._id,
      members: [{
        user: req.user._id,
        role: 'owner',
        status: 'accepted'
      }]
    });

    await family.save();
    
    // Populate the data before sending response
    await family.populate('owner', 'username email');
    await family.populate('members.user', 'username email');

    res.status(201).json({ message: 'Family created successfully', family });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Send family invitation
app.post('/family/invite', authenticate, [
  body('email').isEmail().normalizeEmail(),
  body('familyId').not().isEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { email, familyId, message } = req.body;

    // Check if family exists and user is the owner
    const family = await Family.findOne({ 
      _id: familyId, 
      owner: req.user._id 
    });

    if (!family) {
      return res.status(404).json({ message: 'Family not found or you are not the owner' });
    }

    // Find the user to invite
    const userToInvite = await User.findOne({ email });
    if (!userToInvite) {
      return res.status(404).json({ message: 'User with this email not found' });
    }

    // Check if user is already in the family
    const alreadyMember = family.members.some(
      member => member.user.toString() === userToInvite._id.toString() && member.status === 'accepted'
    );

    if (alreadyMember) {
      return res.status(400).json({ message: 'User is already a family member' });
    }

    // Check if there's already a pending request
    const existingRequest = await FamilyRequest.findOne({
      fromUser: req.user._id,
      toUser: userToInvite._id,
      family: familyId,
      status: 'pending'
    });

    if (existingRequest) {
      return res.status(400).json({ message: 'Invitation already sent to this user' });
    }

    // Create invitation
    const familyRequest = new FamilyRequest({
      fromUser: req.user._id,
      toUser: userToInvite._id,
      family: familyId,
      message: message || `${req.user.username} invited you to join their family`
    });

    await familyRequest.save();
    
    // Populate data for response
    await familyRequest.populate('fromUser', 'username email');
    await familyRequest.populate('toUser', 'username email');
    await familyRequest.populate('family');

    res.status(201).json({ message: 'Invitation sent successfully', request: familyRequest });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get pending family requests
app.get('/family/requests', authenticate, async (req, res) => {
  try {
    const requests = await FamilyRequest.find({
      toUser: req.user._id,
      status: 'pending'
    }).populate('fromUser', 'username email')
      .populate('family', 'familyName');

    res.json(requests);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Respond to family request
app.post('/family/requests/:requestId/respond', authenticate, [
  body('response').isIn(['accepted', 'rejected'])
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { response } = req.body;
    const { requestId } = req.params;

    const familyRequest = await FamilyRequest.findOne({
      _id: requestId,
      toUser: req.user._id,
      status: 'pending'
    }).populate('family');

    if (!familyRequest) {
      return res.status(404).json({ message: 'Request not found' });
    }

    if (response === 'accepted') {
      // Add user to family
      const family = await Family.findById(familyRequest.family._id);
      family.members.push({
        user: req.user._id,
        role: 'member',
        status: 'accepted'
      });
      await family.save();
    }

    // Update request status
    familyRequest.status = response;
    await familyRequest.save();

    res.json({ message: `Request ${response} successfully` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get family health dashboard
app.get('/family/health-dashboard', authenticate, async (req, res) => {
  try {
    // Get user's family
    const family = await Family.findOne({
      $or: [
        { owner: req.user._id },
        { 'members.user': req.user._id, 'members.status': 'accepted' }
      ]
    }).populate({
      path: 'members.user',
      select: 'username email',
      populate: {
        path: 'healthProfile',
        model: 'HealthProfile',
        select: 'age gender height weight bloodGroup conditions allergies'
      }
    });

    if (!family) {
      return res.status(404).json({ message: 'No family found' });
    }

    // Filter only accepted members with health profiles
    const familyMembers = family.members
      .filter(member => member.status === 'accepted')
      .map(member => ({
        _id: member.user._id,
        username: member.user.username,
        email: member.user.email,
        role: member.role,
        healthProfile: member.user.healthProfile || null
      }));

    res.json({
      familyName: family.familyName,
      members: familyMembers
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Remove family member
app.delete('/family/members/:memberId', authenticate, async (req, res) => {
  try {
    const { memberId } = req.params;

    const family = await Family.findOne({
      owner: req.user._id
    });

    if (!family) {
      return res.status(404).json({ message: 'You are not the owner of any family' });
    }

    // Check if member exists
    const memberIndex = family.members.findIndex(
      member => member.user.toString() === memberId && member.status === 'accepted'
    );

    if (memberIndex === -1) {
      return res.status(404).json({ message: 'Member not found' });
    }

    // Cannot remove yourself if you're the owner
    if (memberId === req.user._id.toString() && family.owner.toString() === req.user._id.toString()) {
      return res.status(400).json({ message: 'As the owner, you cannot remove yourself. Transfer ownership first.' });
    }

    // Remove member
    family.members.splice(memberIndex, 1);
    await family.save();

    res.json({ message: 'Member removed successfully' });
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