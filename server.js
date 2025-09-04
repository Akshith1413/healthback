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
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
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

// Group Schema
const GroupSchema = new mongoose.Schema({
  groupName: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  description: {
    type: String,
    required: true,
    maxlength: 500
  },
  category: {
    type: String,
    required: true,
    enum: [
      'chronic_diseases',
      'mental_health',
      'fitness_goals',
      'diet_nutrition',
      'age_groups',
      'gender_specific',
      'recovery_support',
      'preventive_care',
      'family_health',
      'other'
    ]
  },
  targetConditions: [{
    type: String,
    trim: true
  }],
  severityLevel: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'medium'
  },
  privacy: {
    type: String,
    enum: ['public', 'private'],
    default: 'public'
  },
  requireApproval: {
    type: Boolean,
    default: false
  },
  creator: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  moderators: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  members: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    joinedAt: {
      type: Date,
      default: Date.now
    },
    role: {
      type: String,
      enum: ['admin', 'moderator', 'member', 'pending'],
      default: 'member'
    }
  }],
  membersCount: {
    type: Number,
    default: 0
  },
  maxMembers: {
    type: Number,
    min: 1,
    max: 10000
  },
  minAge: {
    type: Number,
    min: 0,
    max: 120
  },
  maxAge: {
    type: Number,
    min: 0,
    max: 120
  },
  allowedGenders: [{
    type: String,
    enum: ['Male', 'Female', 'Other']
  }],
  tags: [{
    type: String,
    trim: true
  }],
  isActive: {
    type: Boolean,
    default: true
  },
  deletedAt: {
    type: Date
  }
}, {
  timestamps: true
});

// Indexes for better query performance
GroupSchema.index({ category: 1, privacy: 1, isActive: 1 });
GroupSchema.index({ targetConditions: 1, isActive: 1 });
GroupSchema.index({ creator: 1 });
GroupSchema.index({ 'members.user': 1 });
GroupSchema.index({ groupName: 'text', description: 'text' });

const Group = mongoose.model('Group', GroupSchema);

// Family Schema
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
      enum: ['owner', 'admin', 'member', 'child', 'elder'], 
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
  description: { type: String },
  familyType: {
    type: String,
    enum: ['immediate', 'extended', 'friends', 'health_group', 'other'],
    default: 'immediate'
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
        user: req.user._id,
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

// ===================
// GROUP ROUTES
// ===================

// GET /groups - Get all groups (public + user's private groups)
app.get('/groups', authenticate, async (req, res) => {
  try {
    const publicGroups = await Group.find({
      privacy: 'public',
      isActive: true
    }).populate('creator', 'username email')
      .populate('members.user', 'username email')
      .populate('moderators', 'username email')
      .sort({ createdAt: -1 });

    const userPrivateGroups = await Group.find({
      $or: [
        { creator: req.user.id },
        { 'members.user': req.user.id }
      ],
      privacy: 'private',
      isActive: true
    }).populate('creator', 'username email')
      .populate('members.user', 'username email')
      .populate('moderators', 'username email')
      .sort({ createdAt: -1 });

    const allGroups = [...publicGroups, ...userPrivateGroups];

    res.json(allGroups);
  } catch (err) {
    console.error('Get groups error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /groups/my - Get user's groups (created + joined)
app.get('/groups/my', authenticate, async (req, res) => {
  try {
    const groups = await Group.find({
      $or: [
        { creator: req.user.id },
        { 'members.user': req.user.id }
      ],
      isActive: true
    }).populate('creator', 'username email')
      .populate('members.user', 'username email')
      .populate('moderators', 'username email')
      .sort({ createdAt: -1 });

    res.json(groups);
  } catch (err) {
    console.error('Get my groups error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /groups/discover - Discover groups by condition/category
app.get('/groups/discover', authenticate, async (req, res) => {
  try {
    const { condition, category, search } = req.query;
    let query = { privacy: 'public', isActive: true };

    if (condition) {
      query.targetConditions = { $in: [condition] };
    }
    
    if (category) {
      query.category = category;
    }

    if (search) {
      query.$or = [
        { groupName: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { targetConditions: { $in: [new RegExp(search, 'i')] } }
      ];
    }

    const groups = await Group.find(query)
      .populate('creator', 'username email')
      .populate('members.user', 'username email')
      .limit(50)
      .sort({ membersCount: -1, createdAt: -1 });

    res.json(groups);
  } catch (err) {
    console.error('Discover groups error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /groups/suggested - Get suggested groups based on user's health profile
app.get('/groups/suggested', authenticate, async (req, res) => {
  try {
    const healthProfile = await HealthProfile.findOne({ user: req.user.id });
    
    if (!healthProfile) {
      return res.json([]);
    }

    const userConditions = healthProfile.conditions || [];
    const userAge = healthProfile.age;
    const userGender = healthProfile.gender;

    let query = {
      privacy: 'public',
      isActive: true,
      'members.user': { $ne: req.user.id },
      creator: { $ne: req.user.id }
    };

    // Find groups matching user's conditions
    if (userConditions.length > 0) {
      query.targetConditions = { $in: userConditions };
    }

    const conditionGroups = await Group.find(query)
      .populate('creator', 'username email')
      .populate('members.user', 'username email')
      .limit(10)
      .sort({ membersCount: -1 });

    // Find age-appropriate groups
    let ageGroups = [];
    if (userAge) {
      const ageQuery = {
        ...query,
        $and: [
          { $or: [{ minAge: { $lte: userAge } }, { minAge: { $exists: false } }] },
          { $or: [{ maxAge: { $gte: userAge } }, { maxAge: { $exists: false } }] }
        ]
      };
      delete ageQuery.targetConditions;

      ageGroups = await Group.find(ageQuery)
        .populate('creator', 'username email')
        .populate('members.user', 'username email')
        .limit(5)
        .sort({ membersCount: -1 });
    }

    // Combine and deduplicate
    const allSuggested = [...conditionGroups, ...ageGroups];
    const uniqueGroups = allSuggested.filter((group, index, self) =>
      index === self.findIndex(g => g._id.toString() === group._id.toString())
    );

    res.json(uniqueGroups.slice(0, 15));
  } catch (err) {
    console.error('Get suggested groups error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /groups - Create a new group
app.post('/groups', authenticate, async (req, res) => {
  try {
    const {
      groupName,
      description,
      category,
      targetConditions,
      severityLevel,
      privacy,
      requireApproval,
      maxMembers,
      minAge,
      maxAge,
      allowedGenders
    } = req.body;

    // Validation
    if (!groupName || !description || !category) {
      return res.status(400).json({
        message: 'Group name, description, and category are required'
      });
    }

    // Check if group name already exists
    const existingGroup = await Group.findOne({ 
      groupName: { $regex: new RegExp(`^${groupName}$`, 'i') },
      isActive: true
    });

    if (existingGroup) {
      return res.status(400).json({
        message: 'A group with this name already exists'
      });
    }

    const newGroup = new Group({
      groupName,
      description,
      category,
      targetConditions: targetConditions || [],
      severityLevel,
      privacy: privacy || 'public',
      requireApproval: requireApproval || false,
      maxMembers: maxMembers || null,
      minAge: minAge || null,
      maxAge: maxAge || null,
      allowedGenders: allowedGenders || [],
      creator: req.user.id,
      moderators: [req.user.id],
      members: [{
        user: req.user.id,
        joinedAt: new Date(),
        role: 'admin'
      }],
      membersCount: 1
    });

    await newGroup.save();

    const populatedGroup = await Group.findById(newGroup._id)
      .populate('creator', 'username email')
      .populate('members.user', 'username email')
      .populate('moderators', 'username email');

    res.status(201).json(populatedGroup);
  } catch (err) {
    console.error('Create group error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /groups/:id - Get group details
app.get('/groups/:id', authenticate, async (req, res) => {
  try {
    const group = await Group.findById(req.params.id)
      .populate('creator', 'username email')
      .populate('members.user', 'username email')
      .populate('moderators', 'username email');

    if (!group || !group.isActive) {
      return res.status(404).json({ message: 'Group not found' });
    }

    // Check if user has access to private group
    if (group.privacy === 'private') {
      const isMember = group.members.some(m => m.user._id.toString() === req.user.id);
      const isCreator = group.creator._id.toString() === req.user.id;
      
      if (!isMember && !isCreator) {
        return res.status(403).json({ message: 'Access denied' });
      }
    }

    res.json(group);
  } catch (err) {
    console.error('Get group details error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /groups/:id/join - Join a group
app.post('/groups/:id/join', authenticate, async (req, res) => {
  try {
    const group = await Group.findById(req.params.id);
    
    if (!group || !group.isActive) {
      return res.status(404).json({ message: 'Group not found' });
    }

    // Check if already a member
    const isAlreadyMember = group.members.some(m => m.user.toString() === req.user.id);
    if (isAlreadyMember) {
      return res.status(400).json({ message: 'You are already a member of this group' });
    }

    // Check member limit
    if (group.maxMembers && group.membersCount >= group.maxMembers) {
      return res.status(400).json({ message: 'Group has reached maximum capacity' });
    }

    // Check age and gender restrictions
    const healthProfile = await HealthProfile.findOne({ user: req.user.id });
    if (healthProfile) {
      if (group.minAge && healthProfile.age < group.minAge) {
        return res.status(400).json({ message: 'You do not meet the minimum age requirement' });
      }
      if (group.maxAge && healthProfile.age > group.maxAge) {
        return res.status(400).json({ message: 'You exceed the maximum age limit' });
      }
      if (group.allowedGenders.length > 0 && !group.allowedGenders.includes(healthProfile.gender)) {
        return res.status(400).json({ message: 'This group has gender restrictions' });
      }
    }

    const memberRole = group.requireApproval ? 'pending' : 'member';
    
    group.members.push({
      user: req.user.id,
      joinedAt: new Date(),
      role: memberRole
    });

    if (!group.requireApproval) {
      group.membersCount += 1;
    }

    await group.save();

    const updatedGroup = await Group.findById(group._id)
      .populate('creator', 'username email')
      .populate('members.user', 'username email')
      .populate('moderators', 'username email');

    res.json({
      message: group.requireApproval ? 'Join request sent for approval' : 'Successfully joined the group',
      group: updatedGroup
    });
  } catch (err) {
    console.error('Join group error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /groups/:id/leave - Leave a group
app.post('/groups/:id/leave', authenticate, async (req, res) => {
  try {
    const group = await Group.findById(req.params.id);
    
    if (!group) {
      return res.status(404).json({ message: 'Group not found' });
    }

    // Check if user is the creator
    if (group.creator.toString() === req.user.id) {
      return res.status(400).json({ message: 'Group creator cannot leave. Please transfer ownership or delete the group.' });
    }

    // Remove user from members
    const memberIndex = group.members.findIndex(m => m.user.toString() === req.user.id);
    if (memberIndex === -1) {
      return res.status(400).json({ message: 'You are not a member of this group' });
    }

    group.members.splice(memberIndex, 1);
    group.membersCount = Math.max(0, group.membersCount - 1);

    // Remove from moderators if applicable
    group.moderators = group.moderators.filter(m => m.toString() !== req.user.id);

    await group.save();

    res.json({ message: 'Successfully left the group' });
  } catch (err) {
    console.error('Leave group error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /groups/:id/approve-member - Approve pending member (moderator/admin only)
app.post('/groups/:id/approve-member', authenticate, async (req, res) => {
  try {
    const { userId } = req.body;
    const group = await Group.findById(req.params.id);
    
    if (!group) {
      return res.status(404).json({ message: 'Group not found' });
    }

    // Check if user is moderator or creator
    const isCreator = group.creator.toString() === req.user.id;
    const isModerator = group.moderators.includes(req.user.id);
    
    if (!isCreator && !isModerator) {
      return res.status(403).json({ message: 'Only moderators can approve members' });
    }

    // Find and update member
    const member = group.members.find(m => m.user.toString() === userId && m.role === 'pending');
    if (!member) {
      return res.status(404).json({ message: 'Pending member not found' });
    }

    member.role = 'member';
    group.membersCount += 1;

    await group.save();

    const updatedGroup = await Group.findById(group._id)
      .populate('creator', 'username email')
      .populate('members.user', 'username email')
      .populate('moderators', 'username email');

    res.json({ message: 'Member approved successfully', group: updatedGroup });
  } catch (err) {
    console.error('Approve member error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// DELETE /groups/:id - Delete group (creator only)
app.delete('/groups/:id', authenticate, async (req, res) => {
  try {
    const group = await Group.findById(req.params.id);
    
    if (!group) {
      return res.status(404).json({ message: 'Group not found' });
    }

    // Check if user is the creator
    if (group.creator.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Only the group creator can delete the group' });
    }

    group.isActive = false;
    group.deletedAt = new Date();
    await group.save();

    res.json({ message: 'Group deleted successfully' });
  } catch (err) {
    console.error('Delete group error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ===================
// FAMILY ROUTES
// ===================

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
  body('familyName').not().isEmpty().trim().escape(),
  body('familyType').optional().isIn(['immediate', 'extended', 'friends', 'health_group', 'other']),
  body('description').optional().trim().escape()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { familyName, familyType, description } = req.body;

    // Create new family
    const family = new Family({
      familyName,
      familyType: familyType || 'immediate',
      description,
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

// Delete family (only for owner)
app.delete('/family/:familyId', authenticate, async (req, res) => {
  try {
    const { familyId } = req.params;

    const family = await Family.findOne({
      _id: familyId,
      owner: req.user._id
    });

    if (!family) {
      return res.status(404).json({ message: 'Family not found or you are not the owner' });
    }

    await Family.findByIdAndDelete(familyId);
    
    // Also delete all related requests
    await FamilyRequest.deleteMany({ family: familyId });
    
    res.json({ message: 'Family deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get family health dashboard
app.get('/family/:familyId/health-dashboard', authenticate, async (req, res) => {
  try {
    const { familyId } = req.params;

    // Get family and verify user is a member
    const family = await Family.findOne({
      _id: familyId,
      'members.user': req.user._id,
      'members.status': 'accepted'
    }).populate({
      path: 'members.user',
      select: 'username email',
      populate: {
        path: 'healthProfile',
        model: 'HealthProfile',
        select: 'age gender height weight bloodGroup conditions allergies medications activityLevel'
      }
    });

    if (!family) {
      return res.status(404).json({ message: 'Family not found or access denied' });
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

// Send family invitation
app.post('/family/:familyId/invite', authenticate, [
  body('email').isEmail().normalizeEmail(),
  body('message').optional().trim().escape(),
  body('role').optional().isIn(['admin', 'member', 'child', 'elder'])
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { email, message, role } = req.body;
    const { familyId } = req.params;

    // Check if family exists and user is a member with appropriate permissions
    const family = await Family.findOne({ 
      _id: familyId,
      'members.user': req.user._id,
      'members.status': 'accepted',
      $or: [
        { 'members.role': 'owner' },
        { 'members.role': 'admin' }
      ]
    });

    if (!family) {
      return res.status(403).json({ message: 'You do not have permission to invite members to this family' });
    }

    // Find the user to invite
    const userToInvite = await User.findOne({ email });
    if (!userToInvite) {
      return res.status(404).json({ message: 'User with this email not found' });
    }

    // Check if user is already in the family
    const alreadyMember = family.members.some(
      member => member.user.toString() === userToInvite._id.toString()
    );

    if (alreadyMember) {
      return res.status(400).json({ message: 'User is already in this family' });
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
      role: role || 'member',
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

// Send family invitation (alternative endpoint)
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
    })
    .populate('fromUser', 'username email')
    .populate('family', 'familyName familyType')
    .sort({ createdAt: -1 });

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
        role: familyRequest.role,
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

// Leave family
app.post('/family/:familyId/leave', authenticate, async (req, res) => {
  try {
    const { familyId } = req.params;

    const family = await Family.findById(familyId);
    if (!family) {
      return res.status(404).json({ message: 'Family not found' });
    }

    // Check if user is the owner
    if (family.owner.toString() === req.user._id.toString()) {
      return res.status(400).json({ message: 'Owners cannot leave their family. Transfer ownership or delete the family instead.' });
    }

    // Remove user from family members
    family.members = family.members.filter(
      member => member.user.toString() !== req.user._id.toString()
    );

    await family.save();
    res.json({ message: 'Left family successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Remove family member (only for owners/admins)
app.delete('/family/:familyId/members/:memberId', authenticate, async (req, res) => {
  try {
    const { familyId, memberId } = req.params;

    const family = await Family.findOne({
      _id: familyId,
      'members.user': req.user._id,
      'members.status': 'accepted',
      $or: [
        { 'members.role': 'owner' },
        { 'members.role': 'admin' }
      ]
    });

    if (!family) {
      return res.status(403).json({ message: 'You do not have permission to remove members' });
    }

    // Check if trying to remove owner
    if (family.owner.toString() === memberId) {
      return res.status(400).json({ message: 'Cannot remove the family owner' });
    }

    // Check if trying to remove yourself
    if (memberId === req.user._id.toString()) {
      return res.status(400).json({ message: 'Use the leave family option instead' });
    }

    // Remove member
    family.members = family.members.filter(
      member => member.user.toString() !== memberId
    );

    await family.save();
    res.json({ message: 'Member removed successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get family health dashboard (alternative endpoint)
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

// Remove family member (alternative endpoint)
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

// Get all user's families (both owned and joined)
app.get('/families', authenticate, async (req, res) => {
  try {
    const families = await Family.find({
      'members.user': req.user._id,
      'members.status': 'accepted'
    })
    .populate('owner', 'username email')
    .populate('members.user', 'username email')
    .sort({ createdAt: -1 });
    
    res.json(families);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get family by ID
app.get('/family/:id', authenticate, async (req, res) => {
  try {
    const family = await Family.findOne({
      _id: req.params.id,
      'members.user': req.user._id,
      'members.status': 'accepted'
    })
    .populate('owner', 'username email')
    .populate('members.user', 'username email');
    
    if (!family) {
      return res.status(404).json({ message: 'Family not found or access denied' });
    }
    
    res.json(family);
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