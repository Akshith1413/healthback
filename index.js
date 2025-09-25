module.exports = (app, mongoose, authenticate) => {

   const { body, validationResult } = require('express-validator');
    // 3. FIX: Standardized error response helper
const standardErrorResponse = (res, statusCode, message, details = null) => {
  const response = {
    success: false,
    message: message,
    timestamp: new Date().toISOString(),
    ...(details && process.env.NODE_ENV === 'development' && { details })
  };
  
  return res.status(statusCode).json(response);
};

const formatIndianPhoneNumber = (phoneNumber) => {
  if (!phoneNumber) return phoneNumber;
  
  // Remove all non-digits
  const cleaned = phoneNumber.replace(/\D/g, '');
  
  // Check if it's a valid Indian mobile number (10 digits starting with 6-9)
  if (cleaned.length === 10 && /^[6-9]/.test(cleaned)) {
    return `+91 ${cleaned.slice(0, 5)} ${cleaned.slice(5)}`;
  }
  
  // Return original if not a standard Indian mobile number
  return phoneNumber;
};
// Food Item Schema
const FoodItemSchema = new mongoose.Schema({
  name: { type: String, required: true },
  brand: { type: String, default: '' },
  servingSize: { type: String, required: true },
  calories: { type: Number, required: true },
  protein: { type: Number, required: true },
  carbs: { type: Number, required: true },
  fat: { type: Number, required: true },
  fiber: { type: Number, default: 0 },
  sugar: { type: Number, default: 0 },
  sodium: { type: Number, default: 0 },
  cholesterol: { type: Number, default: 0 },
  isCustom: { type: Boolean, default: false },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now }
});

const FoodItem = mongoose.model('FoodItem', FoodItemSchema);
// Appointment Statistics Schema for better performance
const AppointmentStatisticsSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true,
    index: true  // Remove the separate .index() call below
  },
  userEmail: {
    type: String,
    required: true,
    index: true  // Remove the separate .index() call below
  },
  total: { type: Number, default: 0 },
  confirmed: { type: Number, default: 0 },
  pending: { type: Number, default: 0 },
  completed: { type: Number, default: 0 },
  cancelled: { type: Number, default: 0 },
  upcoming: { type: Number, default: 0 },
  activeReminders: { type: Number, default: 0 },
  lastUpdated: { type: Date, default: Date.now }
}, {
  timestamps: true
});


const AppointmentStatistics = mongoose.model('AppointmentStatistics', AppointmentStatisticsSchema);
let statisticsUpdateQueue = new Map();
let updateTimer = null;

const debouncedUpdateStatistics = (userId, userEmail) => {
  const key = `${userId}_${userEmail}`;
  statisticsUpdateQueue.set(key, { userId, userEmail });
  
  if (updateTimer) {
    clearTimeout(updateTimer);
  }
  
  updateTimer = setTimeout(async () => {
    const updates = Array.from(statisticsUpdateQueue.values());
    statisticsUpdateQueue.clear();
    
    await Promise.all(
      updates.map(({ userId, userEmail }) => 
        updateAppointmentStatistics(userId, userEmail)
      )
    );
  }, 1000); // Batch updates every 1 second
};

// Add index for better performance
// AppointmentStatisticsSchema.index({ userId: 1 });
// AppointmentStatisticsSchema.index({ userEmail: 1 });
// Function to update appointment statistics

const validateAppointment = [
  body('patientName').trim().isLength({ min: 2, max: 100 }).escape(),
  body('phone').isMobilePhone('any', { strictMode: false }),
  body('doctorName').trim().isLength({ min: 2, max: 100 }).escape(),
  body('specialty').isIn([
    'General Practice', 'Cardiology', 'Dermatology', 'Endocrinology',
    'Gastroenterology', 'Neurology', 'Orthopedics', 'Pediatrics',
    'Psychiatry', 'Radiology', 'Surgery', 'Urology'
  ]),
  body('date').isISO8601().toDate(),
  body('time').matches(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/),
  body('clinic').trim().isLength({ min: 2, max: 200 }).escape(),
  body('agreeToTerms').equals('true').withMessage('You must agree to terms and conditions')
];
const updateAppointmentStatistics = async (userId, userEmail) => {
  try {
    console.log('Updating statistics for user:', userEmail);
    
    const currentDate = new Date();
    currentDate.setHours(0, 0, 0, 0);
    
    const [
      total,
      confirmed,
      pending,
      completed,
      cancelled,
      upcomingAppointments
    ] = await Promise.all([
      Appointment.countDocuments({ userId, userEmail, isActive: true }),
      Appointment.countDocuments({ userId, userEmail, status: 'confirmed', isActive: true }),
      Appointment.countDocuments({ userId, userEmail, status: 'pending', isActive: true }),
      Appointment.countDocuments({ userId, userEmail, status: 'completed', isActive: true }),
      Appointment.countDocuments({ userId, userEmail, status: 'cancelled', isActive: true }),
      Appointment.find({ 
        userId, 
        userEmail, 
        date: { $gte: currentDate },
        status: { $in: ['confirmed', 'pending'] },
        isActive: true 
      })
    ]);
    
    const upcomingCount = upcomingAppointments.length;
    const activeReminders = upcomingAppointments.filter(apt => 
      apt.reminderSet && !apt.reminderSent
    ).length;
    
    await AppointmentStatistics.findOneAndUpdate(
      { userId, userEmail },
      {
        total,
        confirmed,
        pending,
        completed,
        cancelled,
        upcoming: upcomingCount,
        activeReminders,
        lastUpdated: new Date()
      },
      { upsert: true, new: true }
    );
    
    console.log('Statistics updated successfully for user:', userEmail);
  } catch (error) {
    console.error('Error updating appointment statistics:', error);
  }
};
// Custom Recipe Schema
const RecipeSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String },
  ingredients: [{
    foodItem: { type: mongoose.Schema.Types.ObjectId, ref: 'FoodItem' },
    quantity: { type: Number, required: true },
    unit: { type: String, required: true }
  }],
  servings: { type: Number, required: true },
  instructions: [{ type: String }],
  nutrition: {
    calories: { type: Number },
    protein: { type: Number },
    carbs: { type: Number },
    fat: { type: Number },
    fiber: { type: Number }
  },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  isPublic: { type: Boolean, default: false },
  tags: [{ type: String }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

RecipeSchema.pre('save', async function(next) {
  this.updatedAt = Date.now();
  
  // Calculate nutrition from ingredients
  if (this.ingredients.length > 0 && this.isModified('ingredients')) {
    try {
      // Populate ingredients if they're ObjectIds
      let populatedIngredients = this.ingredients;
      if (typeof this.ingredients[0].foodItem === 'object' && 
          this.ingredients[0].foodItem._id) {
        // Already populated
      } else {
        // Need to populate
        const recipe = await this.populate('ingredients.foodItem').execPopulate();
        populatedIngredients = recipe.ingredients;
      }
      
      let totalCalories = 0;
      let totalProtein = 0;
      let totalCarbs = 0;
      let totalFat = 0;
      let totalFiber = 0;
      
      populatedIngredients.forEach(ingredient => {
        if (ingredient.foodItem) {
          totalCalories += (ingredient.foodItem.calories * ingredient.quantity);
          totalProtein += (ingredient.foodItem.protein * ingredient.quantity);
          totalCarbs += (ingredient.foodItem.carbs * ingredient.quantity);
          totalFat += (ingredient.foodItem.fat * ingredient.quantity);
          totalFiber += (ingredient.foodItem.fiber * ingredient.quantity);
        }
      });
      
      this.nutrition = {
        calories: Math.round(totalCalories / this.servings),
        protein: Math.round(totalProtein / this.servings),
        carbs: Math.round(totalCarbs / this.servings),
        fat: Math.round(totalFat / this.servings),
        fiber: Math.round(totalFiber / this.servings)
      };
    } catch (error) {
      console.error('Error calculating recipe nutrition:', error);
      // Continue without nutrition data
    }
  }
  
  next();
});

const Recipe = mongoose.model('Recipe', RecipeSchema);
const requestTimeout = (timeout = 30000) => {
  return (req, res, next) => {
    const timer = setTimeout(() => {
      if (!res.headersSent) {
        res.status(408).json({
          success: false,
          message: 'Request timeout'
        });
      }
    }, timeout);
    
    res.on('finish', () => clearTimeout(timer));
    next();
  };
};
const requestLogger = (req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    const logLevel = res.statusCode >= 400 ? 'ERROR' : 'INFO';
    
    console.log(
      `[${logLevel}] ${req.method} ${req.originalUrl} - ${res.statusCode} - ${duration}ms`
    );
    
    if (res.statusCode >= 500) {
      console.error(`Server error on ${req.method} ${req.originalUrl}:`, {
        statusCode: res.statusCode,
        duration,
        userAgent: req.get('User-Agent'),
        ip: req.ip
      });
    }
  });
  
  next();
};
// 9. FIX: Improve error handling middleware
app.use(requestTimeout(30000));
app.use(requestLogger);
app.use((err, req, res, next) => {
  console.error('Unhandled error:', {
    error: err.message,
    stack: err.stack,
    url: req.originalUrl,
    method: req.method,
    user: req.user?.email || 'anonymous'
  });

  if (res.headersSent) {
    return next(err);
  }

  // Handle specific error types
  if (err.name === 'ValidationError') {
    return res.status(400).json({
      success: false,
      message: 'Validation error',
      errors: Object.values(err.errors).map(e => e.message)
    });
  }
  
  if (err.name === 'MongoError' && err.code === 11000) {
    return res.status(409).json({
      success: false,
      message: 'Duplicate entry detected'
    });
  }
  
  if (err.name === 'CastError') {
    return res.status(400).json({
      success: false,
      message: 'Invalid ID format'
    });
  }

  // Default error response
  res.status(500).json({
    success: false,
    message: process.env.NODE_ENV === 'development' 
      ? err.message 
      : 'Internal server error'
  });
});
// Meal Schema
const MealSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  name: { type: String, required: true },
  type: { 
    type: String, 
    enum: ['breakfast', 'lunch', 'dinner', 'snack', 'other'],
    required: true 
  },
  items: [{
    foodItem: { type: mongoose.Schema.Types.ObjectId, ref: 'FoodItem' },
    recipe: { type: mongoose.Schema.Types.ObjectId, ref: 'Recipe' },
    quantity: { type: Number, required: true },
    unit: { type: String, required: true }
  }],
  totalNutrition: {
    calories: { type: Number },
    protein: { type: Number },
    carbs: { type: Number },
    fat: { type: Number },
    fiber: { type: Number }
  },
  date: { type: Date, required: true },
  time: { type: String, required: true },
  notes: { type: String },
  createdAt: { type: Date, default: Date.now }
});

// In your server.js file, update the MealSchema pre-save hook
// Also fix the Meal Schema pre-save hook
MealSchema.pre('save', async function(next) {
  try {
    console.log('Pre-save hook triggered for meal:', this.name);
    
    // Calculate total nutrition from items
    let totalCalories = 0;
    let totalProtein = 0;
    let totalCarbs = 0;
    let totalFat = 0;
    let totalFiber = 0;
    
    if (this.items && this.items.length > 0) {
      // Check if items are populated
      const firstItem = this.items[0];
      if (firstItem.foodItem && typeof firstItem.foodItem === 'object' && firstItem.foodItem.calories !== undefined) {
        // Items are already populated
        this.items.forEach(item => {
          if (item.foodItem) {
            totalCalories += (item.foodItem.calories || 0) * (item.quantity || 1);
            totalProtein += (item.foodItem.protein || 0) * (item.quantity || 1);
            totalCarbs += (item.foodItem.carbs || 0) * (item.quantity || 1);
            totalFat += (item.foodItem.fat || 0) * (item.quantity || 1);
            totalFiber += (item.foodItem.fiber || 0) * (item.quantity || 1);
          }
        });
      } else if (firstItem.foodItem) {
        // Items need to be populated
        try {
          await this.populate('items.foodItem');
          this.items.forEach(item => {
            if (item.foodItem) {
              totalCalories += (item.foodItem.calories || 0) * (item.quantity || 1);
              totalProtein += (item.foodItem.protein || 0) * (item.quantity || 1);
              totalCarbs += (item.foodItem.carbs || 0) * (item.quantity || 1);
              totalFat += (item.foodItem.fat || 0) * (item.quantity || 1);
              totalFiber += (item.foodItem.fiber || 0) * (item.quantity || 1);
            }
          });
        } catch (populateError) {
          console.error('Error populating items in pre-save hook:', populateError);
        }
      }
    }
    
    this.totalNutrition = {
      calories: Math.round(totalCalories),
      protein: Math.round(totalProtein * 100) / 100,
      carbs: Math.round(totalCarbs * 100) / 100,
      fat: Math.round(totalFat * 100) / 100,
      fiber: Math.round(totalFiber * 100) / 100
    };
    
    console.log('Calculated nutrition:', this.totalNutrition);
    next();
  } catch (error) {
    console.error('Error in meal pre-save hook:', error);
    next(error);
  }
});
const Meal = mongoose.model('Meal', MealSchema);

// Water Intake Schema
const WaterIntakeSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true }, // in ml
  date: { type: Date, required: true },
  time: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const WaterIntake = mongoose.model('WaterIntake', WaterIntakeSchema);

// Nutritional Goals Schema
const NutritionalGoalsSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  dailyCalories: { type: Number, required: true },
  protein: { type: Number, required: true }, // in grams
  carbs: { type: Number, required: true }, // in grams
  fat: { type: Number, required: true }, // in grams
  fiber: { type: Number, default: 25 }, // in grams
  water: { type: Number, default: 2000 }, // in ml
  mealFrequency: { type: Number, default: 3 }, // meals per day
  dietaryRestrictions: [{ type: String }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

NutritionalGoalsSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

const NutritionalGoals = mongoose.model('NutritionalGoals', NutritionalGoalsSchema);

// Weight Tracking Schema
const WeightTrackingSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  weight: { type: Number, required: true }, // in kg
  date: { type: Date, required: true },
  notes: { type: String },
  createdAt: { type: Date, default: Date.now }
});

const WeightTracking = mongoose.model('WeightTracking', WeightTrackingSchema);

// Meal Plan Template Schema
const MealPlanTemplateSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  name: { type: String, required: true },
  description: { type: String },
  meals: [{
    day: { type: String, enum: ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'] },
    mealType: { type: String, enum: ['breakfast', 'lunch', 'dinner', 'snack'] },
    items: [{
      foodItem: { type: mongoose.Schema.Types.ObjectId, ref: 'FoodItem' },
      recipe: { type: mongoose.Schema.Types.ObjectId, ref: 'Recipe' },
      quantity: { type: Number },
      unit: { type: String }
    }]
  }],
  isPublic: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

MealPlanTemplateSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

const MealPlanTemplate = mongoose.model('MealPlanTemplate', MealPlanTemplateSchema);


// Appointment Schema
const AppointmentSchema = new mongoose.Schema({
  // Patient Information
  patientName: {
    type: String,
    required: true,
    trim: true
  },
  phone: {
    type: String,
    required: true,
    trim: true
  },
  
  // Healthcare Provider
  doctorName: {
    type: String,
    required: true,
    trim: true
  },
  specialty: {
    type: String,
    required: true,
    enum: [
      'General Practice', 'Cardiology', 'Dermatology', 'Endocrinology',
      'Gastroenterology', 'Neurology', 'Orthopedics', 'Pediatrics',
      'Psychiatry', 'Radiology', 'Surgery', 'Urology'
    ]
  },
  website: {
    type: String,
    trim: true
  },
  
  // Appointment Details
  date: {
    type: Date,
    required: true
  },
  time: {
    type: String,
    required: true,
    match: /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/
  },
  duration: {
    type: String,
    required: true,
    enum: ['15 minutes', '30 minutes', '45 minutes', '1 hour', '1.5 hours', '2 hours'],
    default: '30 minutes'
  },
  type: {
    type: String,
    required: true,
    enum: [
      'Regular Checkup', 'Consultation', 'Follow-up', 'Emergency',
      'Procedure', 'Surgery', 'Lab Test', 'Vaccination'
    ]
  },
  status: {
    type: String,
    enum: ['pending', 'confirmed', 'completed', 'cancelled'],
    default: 'pending'
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high'],
    default: 'medium'
  },
  cost: {
    type: Number,
    min: 0,
    default: 0
  },
  paymentMethod: {
    type: String,
    enum: ['insurance', 'credit_card', 'cash'],
    default: 'insurance'
  },
  
  // Location & Contact
  clinic: {
    type: String,
    required: true,
    trim: true
  },
  address: {
    type: String,
    trim: true
  },
  
  // Insurance Information
  insuranceProvider: {
    type: String,
    trim: true
  },
  policyNumber: {
    type: String,
    trim: true
  },
  
  // Medical Information
  symptoms: {
    type: String,
    trim: true
  },
  referralRequired: {
    type: Boolean,
    default: false
  },
  referralSource: {
    type: String,
    trim: true
  },
  
  // Follow-up Information
  followUpRequired: {
    type: Boolean,
    default: false
  },
  followUpDate: {
    type: Date
  },
  
  // Reminders & Notes
  reminderSet: {
    type: Boolean,
    default: true
  },
  reminderTime: {
    type: String,
    enum: ['1 hour before', '2 hours before', '1 day before', '2 days before'],
    default: '1 day before'
  },
  notes: {
    type: String,
    trim: true
  },
  
  // Terms & Conditions
  agreeToTerms: {
    type: Boolean,
    required: true,
    validate: {
      validator: function(v) {
        return v === true;
      },
      message: 'You must agree to terms and conditions'
    }
  },
  
  // User reference - using your existing User model
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  userEmail: {
    type: String,
    required: true
  },
  
  // System fields
  isActive: {
    type: Boolean,
    default: true
  },
  reminderSent: {
    type: Boolean,
    default: false
  },
  lastReminderSent: {
    type: Date
  }
}, {
  timestamps: true
});

// Indexes for better performance
AppointmentSchema.index({ userId: 1, date: 1, time: 1 });
AppointmentSchema.index({ userEmail: 1, date: 1 });
AppointmentSchema.index({ date: 1, reminderSet: 1, status: 1 });
AppointmentSchema.index({ status: 1, isActive: 1 });

// Virtual for appointment datetime
AppointmentSchema.virtual('appointmentDateTime').get(function() {
  const dateStr = this.date.toISOString().split('T')[0];
  return new Date(`${dateStr} ${this.time}`);
});
AppointmentSchema.pre('save', function(next) {
  if (this.isModified('phone')) {
    this.phone = formatIndianPhoneNumber(this.phone);
  }
  next();
});
// Method to check if reminder should be sent
AppointmentSchema.methods.shouldSendReminder = function() {
  if (!this.reminderSet || this.status !== 'confirmed' || this.reminderSent) {
    return false;
  }
  
  const now = new Date();
  const appointmentDateTime = this.appointmentDateTime;
  const timeDiff = appointmentDateTime.getTime() - now.getTime();
  const hoursDiff = timeDiff / (1000 * 3600);
  
  switch (this.reminderTime) {
    case '1 hour before':
      return hoursDiff <= 1 && hoursDiff > 0;
    case '2 hours before':
      return hoursDiff <= 2 && hoursDiff > 0;
    case '1 day before':
      return hoursDiff <= 24 && hoursDiff > 0;
    case '2 days before':
      return hoursDiff <= 48 && hoursDiff > 0;
    default:
      return false;
  }
};
AppointmentSchema.post('save', function(doc) {
  if (doc.userId && doc.userEmail) {
    debouncedUpdateStatistics(doc.userId, doc.userEmail);
  }
});

AppointmentSchema.post('findOneAndUpdate', function(doc) {
  if (doc && doc.userId && doc.userEmail) {
    debouncedUpdateStatistics(doc.userId, doc.userEmail);
  }
});

AppointmentSchema.post('findOneAndDelete', function(doc) {
  if (doc && doc.userId && doc.userEmail) {
    debouncedUpdateStatistics(doc.userId, doc.userEmail);
  }
});

const Appointment = mongoose.model('Appointment', AppointmentSchema);

// Reminder Settings Schema
const ReminderSettingsSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true
  },
  userEmail: {
    type: String,
    required: true
  },
  defaultReminderTimes: [{
    type: String,
    enum: ['1 hour before', '2 hours before', '1 day before', '1 week before']
  }],
  notificationMethods: {
    browser: {
      type: Boolean,
      default: true
    },
    email: {
      type: Boolean,
      default: true
    },
    sms: {
      type: Boolean,
      default: false
    }
  },
  emailAddress: {
    type: String,
    trim: true
  },
  phoneNumber: {
    type: String,
    trim: true
  }
}, {
  timestamps: true
});
ReminderSettingsSchema.pre('save', function(next) {
  if (this.isModified('phoneNumber')) {
    this.phoneNumber = formatIndianPhoneNumber(this.phoneNumber);
  }
  next();
});
const ReminderSettings = mongoose.model('ReminderSettings', ReminderSettingsSchema);

// Add this helper function
const convertToUTC = (date) => {
  if (!date) return date;
  
  // If it's a string, parse it
  if (typeof date === 'string') {
    date = new Date(date);
  }
  
  // Convert local date to UTC by using the same UTC time
  return new Date(Date.UTC(
    date.getUTCFullYear(),
    date.getUTCMonth(),
    date.getUTCDate(),
    date.getUTCHours(),
    date.getUTCMinutes(),
    date.getUTCSeconds()
  ));
};


// Food Items Routes
app.get('/api/food-items', authenticate, async (req, res) => {
  try {
    const { search, page = 1, limit = 20 } = req.query;
    let query = { $or: [{ isCustom: false }, { createdBy: req.user._id }] };
    
    if (search) {
      query.name = { $regex: search, $options: 'i' };
    }
    
    const foodItems = await FoodItem.find(query)
      .limit(limit * 1)
      .skip((page - 1) * limit);
    
    res.json(foodItems);
  } catch (error) {
    console.error('Get food items error:', error);
    standardErrorResponse(res, 500, 'Failed to retrieve food items', error.message);
  }
});
app.get('/api/food-items/:id', authenticate, async (req, res) => {
  try {
    const foodItem = await FoodItem.findById(req.params.id);
    if (!foodItem) {
      return standardErrorResponse(res, 404, 'Food item not found');
    }
    res.json(foodItem);
  } catch (error) {
    console.error('Get food item error:', error);
    standardErrorResponse(res, 500, 'Failed to retrieve food item', error.message);
  }
});
app.post('/api/food-items', authenticate, async (req, res) => {
  try {
    const foodItem = new FoodItem({
      ...req.body,
      isCustom: true,
      createdBy: req.user._id
    });
    
    await foodItem.save();
    res.status(201).json(foodItem);
  } catch (error) {
    console.error('Get food item error:', error);
    standardErrorResponse(res, 500, 'Failed to retrieve food item', error.message);
  }
});

// Recipe Routes
app.get('/api/recipes', authenticate, async (req, res) => {
  try {
    const recipes = await Recipe.find({
      $or: [{ createdBy: req.user._id }, { isPublic: true }]
    }).populate('ingredients.foodItem');
    
    res.json(recipes);
  } catch (error) {
    console.error('Get recipes error:', error);
    standardErrorResponse(res, 500, 'Failed to retrieve food item', error.message);
  }
});

app.post('/api/recipes', authenticate, async (req, res) => {
  try {
    const recipe = new Recipe({
      ...req.body,
      createdBy: req.user._id
    });
    
    await recipe.save();
    await recipe.populate('ingredients.foodItem');
    res.status(201).json(recipe);
  } catch (error) {
    console.error('Create recipe error:', error);
    standardErrorResponse(res, 500, 'Failed to create recipe', error.message); // FIXED
  }
});

// Meal Routes
app.get('/api/meals', authenticate, async (req, res) => {
  try {
    const { date } = req.query;
    let query = { userId: req.user._id };
    
    if (date) {
      query.date = new Date(date);
    }
    
    const meals = await Meal.find(query)
      .populate('items.foodItem')
      .populate('items.recipe');
    
    res.json(meals);
  } catch (error) {
    standardErrorResponse(res, 500, 'Failed to retrieve meals', error.message);
  }
});
// Delete a meal
app.delete('/api/meals/:id', authenticate, async (req, res) => {
  try {
    const meal = await Meal.findById(req.params.id);
    if (!meal) {
      return standardErrorResponse(res, 404, 'Meal not found');
    }
    
    // Check if the meal belongs to the user
    if (meal.userId.toString() !== req.user._id.toString()) {
      return standardErrorResponse(res, 403, 'Not authorized'); 
    }
    
    await Meal.findByIdAndDelete(req.params.id);
    res.json({ message: 'Meal deleted successfully' });
  } catch (error) {
    console.error('Delete meal error:', error);
    standardErrorResponse(res, 500, 'Failed to delete meal', error.message);
  }
});
// Fixed Meal creation route in your server file
app.post('/api/meals', authenticate, async (req, res) => {
  try {
    const mealData = req.body;
    
    // Validate required fields
    if (!mealData.name || !mealData.type || !mealData.items || mealData.items.length === 0) {
      return standardErrorResponse(res, 400, 'Name, type, and at least one food item are required');
    }
    
    console.log('Received meal data:', JSON.stringify(mealData, null, 2));
    
    // Process items - create FoodItem records for USDA foods
    const processedItems = await Promise.all(mealData.items.map(async (item) => {
      if (item.fdcId) {
        // This is a USDA food item, create a FoodItem record first
        const foodItem = new FoodItem({
          name: item.name || 'Unknown Food',
          brand: item.brandOwner || item.brand || '',
          servingSize: `${item.servingSize || 100} ${item.servingSizeUnit || 'g'}`,
          calories: Math.max(0, item.calories || 0),
          protein: Math.max(0, item.protein || 0),
          carbs: Math.max(0, item.carbs || 0),
          fat: Math.max(0, item.fat || 0),
          fiber: Math.max(0, item.fiber || 0),
          isCustom: true,
          createdBy: req.user._id
        });
        
        await foodItem.save();
        console.log('Created USDA food item:', foodItem.name);
        
        return {
          foodItem: foodItem._id,
          quantity: Math.max(0.1, item.quantity || 1),
          unit: item.servingSizeUnit || 'g'
        };
      } else if (item.foodItem) {
        // Regular food item with foodItem ID
        return {
          foodItem: item.foodItem,
          quantity: Math.max(0.1, item.quantity || 1),
          unit: item.unit || 'serving'
        };
      } else {
        console.error('Invalid item structure:', item);
        throw new Error(`Invalid food item structure for item: ${item.name || 'Unknown'}`);
      }
    }));
    
    // Create the meal with processed items
    const meal = new Meal({
      userId: req.user._id,
      name: mealData.name.trim(),
      type: mealData.type,
      items: processedItems,
      date: convertToUTC(new Date(mealData.date)),
      time: mealData.time || new Date().toLocaleTimeString(),
      notes: mealData.notes?.trim() || ''
    });
    
    // Save and populate
    await meal.save();
    await meal.populate('items.foodItem');
    
    // Return the fully populated meal
    const populatedMeal = await Meal.findById(meal._id)
      .populate('items.foodItem')
      .populate('items.recipe');
      
    res.status(201).json(populatedMeal);
    
  } catch (error) {
    console.error('Error creating meal:', error);
    standardErrorResponse(res, 500, 'Failed to create meal', error.message);
  }
});
// Water Intake Routes
app.get('/api/water-intake', authenticate, async (req, res) => {
  try {
    const { date } = req.query;
    let query = { userId: req.user._id };
    
    if (date) {
      query.date = new Date(date);
    }
    
    const waterIntakes = await WaterIntake.find(query);
    const total = waterIntakes.reduce((sum, intake) => sum + intake.amount, 0);
    
    res.json({ entries: waterIntakes, total });
  }  catch (error) {
    console.error('Get water intake error:', error);
    standardErrorResponse(res, 500, 'Failed to retrieve water intake data', error.message);
  }
});

app.post('/api/water-intake', authenticate, async (req, res) => {
  try {
    const waterIntake = new WaterIntake({
      ...req.body,
      userId: req.user._id
    });
    
    await waterIntake.save();
    res.status(201).json(waterIntake);
  } catch (error) {
    console.error('Create water intake error:', error);
    standardErrorResponse(res, 500, 'Failed to create water intake entry', error.message);
  }
});

// Nutritional Goals Routes
app.get('/api/nutritional-goals', authenticate, async (req, res) => {
  try {
    let goals = await NutritionalGoals.findOne({ userId: req.user._id });
    
    if (!goals) {
      // Create default goals based on user profile
      const healthProfile = await HealthProfile.findOne({ userId: req.user._id });
      if (healthProfile) {
        const bmr = healthProfile.gender === 'Male' 
          ? 88.362 + (13.397 * healthProfile.weight) + (4.799 * healthProfile.height) - (5.677 * healthProfile.age)
          : 447.593 + (9.247 * healthProfile.weight) + (3.098 * healthProfile.height) - (4.330 * healthProfile.age);
        
        const activityMultipliers = {
          'Sedentary': 1.2,
          'Lightly Active': 1.375,
          'Moderately Active': 1.55,
          'Very Active': 1.725,
          'Extremely Active': 1.9
        };
        
        const tdee = bmr * (activityMultipliers[healthProfile.activityLevel] || 1.2);
        
        goals = new NutritionalGoals({
          userId: req.user._id,
          dailyCalories: Math.round(tdee),
          protein: Math.round((tdee * 0.3) / 4), // 30% of calories from protein
          carbs: Math.round((tdee * 0.5) / 4),   // 50% of calories from carbs
          fat: Math.round((tdee * 0.2) / 9)      // 20% of calories from fat
        });
        
        await goals.save();
      }
    }
    
    res.json(goals);
  } catch (error) {
    console.error('Get nutritional goals error:', error);
    standardErrorResponse(res, 500, 'Failed to retrieve nutritional goals', error.message);
  }
});

app.put('/api/nutritional-goals', authenticate, async (req, res) => {
  try {
    let goals = await NutritionalGoals.findOne({ userId: req.user._id });
    
    if (goals) {
      goals.set(req.body);
      await goals.save();
    } else {
      goals = new NutritionalGoals({
        ...req.body,
        userId: req.user._id
      });
      await goals.save();
    }
    
    res.json(goals);
  }  catch (error) {
    console.error('Update nutritional goals error:', error);
    standardErrorResponse(res, 500, 'Failed to update nutritional goals', error.message);
  }
});

// Reports and Analytics Routes
app.get('/api/reports/daily', authenticate, async (req, res) => {
  try {
    const { date } = req.query;
    const targetDate = date ? new Date(date) : new Date();
    
    // Get meals for the day
    const meals = await Meal.find({
      userId: req.user._id,
      date: {
        $gte: new Date(targetDate.setHours(0, 0, 0, 0)),
        $lt: new Date(targetDate.setHours(23, 59, 59, 999))
      }
    }).populate('items.foodItem').populate('items.recipe');
    
    // Get water intake for the day
    const waterIntakes = await WaterIntake.find({
      userId: req.user._id,
      date: {
        $gte: new Date(targetDate.setHours(0, 0, 0, 0)),
        $lt: new Date(targetDate.setHours(23, 59, 59, 999))
      }
    });
    
    // Calculate totals
    const totalNutrition = meals.reduce((acc, meal) => ({
      calories: acc.calories + (meal.totalNutrition?.calories || 0),
      protein: acc.protein + (meal.totalNutrition?.protein || 0),
      carbs: acc.carbs + (meal.totalNutrition?.carbs || 0),
      fat: acc.fat + (meal.totalNutrition?.fat || 0),
      fiber: acc.fiber + (meal.totalNutrition?.fiber || 0)
    }), { calories: 0, protein: 0, carbs: 0, fat: 0, fiber: 0 });
    
    const totalWater = waterIntakes.reduce((sum, intake) => sum + intake.amount, 0);
    
    // Get goals
    const goals = await NutritionalGoals.findOne({ userId: req.user._id });
    
    res.json({
      date: targetDate,
      meals,
      waterIntakes,
      totalNutrition,
      totalWater,
      goals: goals || {}
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/reports/weekly', authenticate, async (req, res) => {
  try {
    const { startDate } = req.query;
    const start = startDate ? new Date(startDate) : new Date();
    start.setHours(0, 0, 0, 0);
    
    const end = new Date(start);
    end.setDate(start.getDate() + 6);
    end.setHours(23, 59, 59, 999);
    
    // Get meals for the week
    const meals = await Meal.find({
      userId: req.user._id,
      date: { $gte: start, $lte: end }
    }).populate('items.foodItem').populate('items.recipe');
    
    // Group by date
    const dailyData = {};
    for (let i = 0; i < 7; i++) {
      const currentDate = new Date(start);
      currentDate.setDate(start.getDate() + i);
      const dateStr = currentDate.toISOString().split('T')[0];
      
      dailyData[dateStr] = {
        date: dateStr,
        meals: [],
        totalNutrition: { calories: 0, protein: 0, carbs: 0, fat: 0, fiber: 0 },
        totalWater: 0
      };
    }
    
    // Process meals
    meals.forEach(meal => {
      const dateStr = meal.date.toISOString().split('T')[0];
      if (dailyData[dateStr]) {
        dailyData[dateStr].meals.push(meal);
        dailyData[dateStr].totalNutrition.calories += meal.totalNutrition?.calories || 0;
        dailyData[dateStr].totalNutrition.protein += meal.totalNutrition?.protein || 0;
        dailyData[dateStr].totalNutrition.carbs += meal.totalNutrition?.carbs || 0;
        dailyData[dateStr].totalNutrition.fat += meal.totalNutrition?.fat || 0;
        dailyData[dateStr].totalNutrition.fiber += meal.totalNutrition?.fiber || 0;
      }
    });
    
    // Get water intake for the week
    const waterIntakes = await WaterIntake.find({
      userId: req.user._id,
      date: { $gte: start, $lte: end }
    });
    
    waterIntakes.forEach(intake => {
      const dateStr = intake.date.toISOString().split('T')[0];
      if (dailyData[dateStr]) {
        dailyData[dateStr].totalWater += intake.amount;
      }
    });
    
    // Get goals
    const goals = await NutritionalGoals.findOne({ userId: req.user._id });
    
    res.json({
      startDate: start.toISOString().split('T')[0],
      endDate: end.toISOString().split('T')[0],
      dailyData: Object.values(dailyData),
      goals: goals || {}
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Weight Tracking Routes
app.get('/api/weight-tracking', authenticate, async (req, res) => {
  try {
    const { startDate, endDate, limit = 30 } = req.query;
    let query = { userId: req.user._id };
    
    if (startDate && endDate) {
      query.date = {
        $gte: new Date(startDate),
        $lte: new Date(endDate)
      };
    }
    
    const weights = await WeightTracking.find(query)
      .sort({ date: -1 })
      .limit(parseInt(limit));
    
    res.json(weights);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/weight-tracking', authenticate, async (req, res) => {
  try {
    const weightEntry = new WeightTracking({
      ...req.body,
      userId: req.user._id
    });
    
    await weightEntry.save();
    res.status(201).json(weightEntry);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Meal Plan Templates Routes
app.get('/api/meal-plan-templates', authenticate, async (req, res) => {
  try {
    const templates = await MealPlanTemplate.find({
      $or: [{ userId: req.user._id }, { isPublic: true }]
    }).populate('meals.items.foodItem').populate('meals.items.recipe');
    
    res.json(templates);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/meal-plan-templates', authenticate, async (req, res) => {
  try {
    const template = new MealPlanTemplate({
      ...req.body,
      userId: req.user._id
    });
    
    await template.save();
    await template.populate('meals.items.foodItem');
    await template.populate('meals.items.recipe');
    res.status(201).json(template);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Generate Meal Plan from Template
app.post('/api/generate-meal-plan', authenticate, async (req, res) => {
  try {
    const { templateId, startDate } = req.body;
    const template = await MealPlanTemplate.findById(templateId)
      .populate('meals.items.foodItem')
      .populate('meals.items.recipe');
    
    if (!template) {
      return res.status(404).json({ message: 'Template not found' });
    }
    
    const start = new Date(startDate);
    const mealsToCreate = [];
    
    template.meals.forEach(meal => {
      const mealDate = new Date(start);
      const dayOffset = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
        .indexOf(meal.day);
      
      mealDate.setDate(start.getDate() + dayOffset);
      
      const newMeal = new Meal({
        userId: req.user._id,
        name: `${meal.mealType} - ${template.name}`,
        type: meal.mealType,
        items: meal.items,
        date: mealDate,
        time: '12:00' // Default time
      });
      
      mealsToCreate.push(newMeal);
    });
    
    const createdMeals = await Meal.insertMany(mealsToCreate);
    res.json(createdMeals);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});
// Health Profile Integration
app.get('/api/health-profile', authenticate, async (req, res) => {
  try {
    const healthProfile = await HealthProfile.findOne({ userId: req.user._id });
    res.json(healthProfile);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Dietary Recommendations
app.get('/api/recommendations', authenticate, async (req, res) => {
  try {
    const healthProfile = await HealthProfile.findOne({ userId: req.user._id });
    const goals = await NutritionalGoals.findOne({ userId: req.user._id });
    
    if (!healthProfile || !goals) {
      return res.json({ recommendations: [] });
    }
    
    const recommendations = [];
    
    // Example recommendations based on health profile
    if (healthProfile.healthGoal === 'Weight Loss') {
      recommendations.push({
        type: 'goal',
        message: 'Consider a moderate calorie deficit of 500 calories per day for sustainable weight loss',
        priority: 'high'
      });
    }
    
    if (healthProfile.allergies && healthProfile.allergies.length > 0) {
      recommendations.push({
        type: 'safety',
        message: `Be mindful of your allergies: ${healthProfile.allergies.join(', ')}`,
        priority: 'high'
      });
    }
    
    if (healthProfile.conditions && healthProfile.conditions.includes('Diabetes')) {
      recommendations.push({
        type: 'health',
        message: 'Focus on low glycemic index foods and consistent carbohydrate intake',
        priority: 'high'
      });
    }
    
    res.json({ recommendations });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// APPOINTMENT ROUTES

// GET /api/appointments - Get all appointments for authenticated user
app.get('/api/appointments', authenticate, async (req, res) => {
  try {
    const { status, search, sortBy = 'date', sortOrder = 'asc', page = 1, limit = 50 } = req.query;
    
    let query = {
      userId: req.user._id,
      userEmail: req.user.email,
      isActive: true
    };
    
    // Filter by status
    if (status && status !== 'all') {
      query.status = status;
    }
    
    // Search functionality
    if (search) {
      const searchRegex = new RegExp(search, 'i');
      query.$or = [
        { patientName: searchRegex },
        { doctorName: searchRegex },
        { specialty: searchRegex },
        { clinic: searchRegex }
      ];
    }
    
    // Sort options
    const sortOptions = {};
    if (sortBy === 'date') {
      sortOptions.date = sortOrder === 'desc' ? -1 : 1;
      sortOptions.time = sortOrder === 'desc' ? -1 : 1;
    } else {
      sortOptions[sortBy] = sortOrder === 'desc' ? -1 : 1;
    }
    
    const appointments = await Appointment.find(query)
      .sort(sortOptions)
      .limit(limit * 1)
      .skip((page - 1) * limit);
    
    const total = await Appointment.countDocuments(query);
    
    res.json({
      success: true,
      appointments,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (err) {
    console.error('Get appointments error:', err);
    standardErrorResponse(res, 500, 'Failed to retrieve appointments', err.message);
  }
});

// GET /api/appointments/:id - Get specific appointment
app.get('/api/appointments/:id', authenticate, async (req, res) => {
  try {
    const appointment = await Appointment.findOne({
      _id: req.params.id,
      userId: req.user._id,
      userEmail: req.user.email,
      isActive: true
    });
    
    if (!appointment) {
      return standardErrorResponse(res, 404, 'Appointment not found');
    }
    
    res.json({ success: true, appointment });
  } catch (err) {
    console.error('Get appointment error:', err);
    standardErrorResponse(res, 500, 'Failed to retrieve appointment', err.message); // FIXED
  }
});

// POST /api/appointments - Create new appointment
app.post('/api/appointments', authenticate, validateAppointment, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        success: false, 
        message: 'Validation error', 
        errors: errors.array() 
      });
    }

    const appointmentData = {
      ...req.body,
      userId: req.user._id,
      userEmail: req.user.email
    };
    
    // Validate appointment date is not in the past
    const appointmentDate = new Date(appointmentData.date);
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    if (appointmentDate < today) {
      return standardErrorResponse(res, 400, 'Appointment date cannot be in the past');
    }
    
    // Convert to UTC properly
    if (appointmentData.date) {
      appointmentData.date = convertToUTC(appointmentData.date);
    }
    
    // Check for conflicting appointments
    const conflictingAppointment = await Appointment.findOne({
      userId: req.user._id,
      userEmail: req.user.email,
      date: appointmentData.date,
      time: appointmentData.time,
      status: { $ne: 'cancelled' },
      isActive: true
    });
    
    if (conflictingAppointment) {
      return standardErrorResponse(res, 409, 'You already have an appointment at this date and time');
    }
    
    const appointment = new Appointment(appointmentData);
    await appointment.save();
    
    // Use debounced statistics update
    debouncedUpdateStatistics(req.user._id, req.user.email);
    
    res.status(201).json({
      success: true,
      message: 'Appointment scheduled successfully!',
      appointment
    });
    
  } catch (err) {
    console.error('Create appointment error:', err);
    
    if (err.name === 'ValidationError') {
      const errors = {};
      Object.keys(err.errors).forEach(key => {
        errors[key] = err.errors[key].message;
      });
      return res.status(400).json({ 
        success: false, 
        message: 'Validation error', 
        errors 
      });
    }
    
    standardErrorResponse(res, 500, 'Failed to create appointment', err.message);
  }
});

// PUT /api/appointments/:id - Update appointment
app.put('/api/appointments/:id', authenticate, async (req, res) => {
  try {
    const appointment = await Appointment.findOne({
      _id: req.params.id,
      userId: req.user._id,
      userEmail: req.user.email,
      isActive: true
    });
    
    if (!appointment) {
      return res.status(404).json({ success: false, message: 'Appointment not found' });
    }
    
    // Validate appointment date is not in the past
    if (req.body.date) {
      const appointmentDate = new Date(req.body.date);
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      
      if (appointmentDate < today) {
        return res.status(400).json({ 
          success: false, 
          message: 'Appointment date cannot be in the past' 
        });
      }
    }
    
    // Check for conflicting appointments (exclude current appointment)
    if (req.body.date || req.body.time) {
      const checkDate = req.body.date || appointment.date;
      const checkTime = req.body.time || appointment.time;
      
      const conflictingAppointment = await Appointment.findOne({
        _id: { $ne: req.params.id },
        userId: req.user._id,
        userEmail: req.user.email,
        date: checkDate,
        time: checkTime,
        status: { $ne: 'cancelled' },
        isActive: true
      });
      
      if (conflictingAppointment) {
        return res.status(400).json({ 
          success: false,
          message: 'You already have another appointment at this date and time' 
        });
      }
    }
    
    Object.keys(req.body).forEach(key => {
      appointment[key] = req.body[key];
    });
    
    // Reset reminder if date/time changed
    if (req.body.date || req.body.time) {
      appointment.reminderSent = false;
      appointment.lastReminderSent = undefined;
    }
    if (req.body.date) {
      req.body.date = convertToUTC(req.body.date);
    }
    await appointment.save();
    
    res.json({
      success: true,
      message: 'Appointment updated successfully!',
      appointment
    });
  } catch (err) {
    console.error('Update appointment error:', err);
    if (err.name === 'ValidationError') {
      const errors = {};
      Object.keys(err.errors).forEach(key => {
        errors[key] = err.errors[key].message;
      });
      return res.status(400).json({ 
        success: false, 
        message: 'Validation error', 
        errors 
      });
    }
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// PATCH /api/appointments/:id/status - Update appointment status
app.patch('/api/appointments/:id/status', authenticate, async (req, res) => {
  try {
    const { status } = req.body;
    
    if (!['pending', 'confirmed', 'completed', 'cancelled'].includes(status)) {
      return res.status(400).json({ success: false, message: 'Invalid status' });
    }
    
    const appointment = await Appointment.findOneAndUpdate(
      {
        _id: req.params.id,
        userId: req.user._id,
        userEmail: req.user.email,
        isActive: true
      },
      { status },
      { new: true }
    );
    
    if (!appointment) {
      return res.status(404).json({ success: false, message: 'Appointment not found' });
    }
    
    res.json({
      success: true,
      message: `Appointment ${status}!`,
      appointment
    });
  } catch (err) {
    console.error('Update appointment status error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// DELETE /api/appointments/:id - Delete appointment (soft delete)
app.delete('/api/appointments/:id', authenticate, async (req, res) => {
  try {
    const appointment = await Appointment.findOneAndUpdate(
      {
        _id: req.params.id,
        userId: req.user._id,
        userEmail: req.user.email,
        isActive: true
      },
      { isActive: false },
      { new: true }
    );
    
    if (!appointment) {
      return res.status(404).json({ success: false, message: 'Appointment not found' });
    }
    
    res.json({ success: true, message: 'Appointment deleted successfully!' });
  } catch (err) {
    console.error('Delete appointment error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// GET /api/appointments/reminders/active - Get active reminders
app.get('/api/appointments/reminders/active', authenticate, async (req, res) => {
  try {
    const now = new Date();
    const twoDaysFromNow = new Date(now.getTime() + (48 * 60 * 60 * 1000));
    
    const appointments = await Appointment.find({
      userId: req.user._id,
      userEmail: req.user.email,
      reminderSet: true,
      status: 'confirmed',
      isActive: true,
      date: { $gte: now, $lte: twoDaysFromNow }
    }).sort({ date: 1, time: 1 });
    
    const activeReminders = appointments.filter(appointment => 
      appointment.shouldSendReminder()
    );
    
    res.json({ success: true, reminders: activeReminders });
  } catch (err) {
    console.error('Get active reminders error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// GET /api/appointments/statistics - Get appointment statistics
// GET /api/appointments/statistics - Get appointment statistics (OPTIMIZED)
app.get('/api/appointments/statistics', authenticate, async (req, res) => {
  try {
    const userId = req.user._id;
    const userEmail = req.user.email;
    
    // Try to get cached statistics first
    let statistics = await AppointmentStatistics.findOne({ userId, userEmail });
    
    // If no cached data or data is older than 5 minutes, recalculate
    if (!statistics || (new Date() - statistics.lastUpdated) > 5 * 60 * 1000) {
      console.log('Cache miss or stale data, recalculating statistics for user:', userEmail);
      await updateAppointmentStatistics(userId, userEmail);
      statistics = await AppointmentStatistics.findOne({ userId, userEmail });
    }
    
    // If still no statistics (first time user), return zeros
    if (!statistics) {
      statistics = {
        total: 0,
        confirmed: 0,
        pending: 0,
        completed: 0,
        cancelled: 0,
        upcoming: 0,
        activeReminders: 0
      };
    }
    
    res.json({
      success: true,
      statistics: {
        total: statistics.total || 0,
        confirmed: statistics.confirmed || 0,
        pending: statistics.pending || 0,
        completed: statistics.completed || 0,
        cancelled: statistics.cancelled || 0,
        upcoming: statistics.upcoming || 0,
        activeReminders: statistics.activeReminders || 0
      }
    });
    
  } catch (err) {
    console.error('Get statistics error:', err);
    
    // Fallback: try to calculate real-time if cache fails
    try {
      const userId = req.user._id;
      const userEmail = req.user.email;
      
      const currentDate = new Date();
      currentDate.setHours(0, 0, 0, 0);
      
      const total = await Appointment.countDocuments({ userId, userEmail, isActive: true });
      const confirmed = await Appointment.countDocuments({ userId, userEmail, status: 'confirmed', isActive: true });
      const pending = await Appointment.countDocuments({ userId, userEmail, status: 'pending', isActive: true });
      const upcomingAppointments = await Appointment.find({ 
        userId, 
        userEmail, 
        date: { $gte: currentDate },
        status: { $in: ['confirmed', 'pending'] },
        isActive: true 
      });
      
      const upcomingCount = upcomingAppointments.length;
      const activeReminders = upcomingAppointments.filter(apt => 
        apt.reminderSet && !apt.reminderSent
      ).length;
      
      res.json({
        success: true,
        statistics: {
          total,
          confirmed,
          pending,
          completed: 0,
          cancelled: 0,
          upcoming: upcomingCount,
          activeReminders
        }
      });
    } catch (fallbackError) {
      console.error('Fallback statistics also failed:', fallbackError);
      res.status(500).json({ 
        success: false, 
        message: 'Failed to retrieve statistics',
        error: err.message 
      });
    }
  }
});
// GET /api/appointments/settings/reminders - Get reminder settings
app.get('/api/appointments/settings/reminders', authenticate, async (req, res) => {
  try {
    let settings = await ReminderSettings.findOne({ 
      userId: req.user._id,
      userEmail: req.user.email 
    });
    
    if (!settings) {
      settings = new ReminderSettings({
        userId: req.user._id,
        userEmail: req.user.email,
        emailAddress: req.user.email,
        defaultReminderTimes: ['1 day before'],
        notificationMethods: {
          browser: true,
          email: true,
          sms: false
        }
      });
      await settings.save();
    }
    
    res.json({ success: true, settings });
  } catch (err) {
    console.error('Get reminder settings error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// PUT /api/appointments/settings/reminders - Update reminder settings
app.put('/api/appointments/settings/reminders', authenticate, async (req, res) => {
  try {
    const settings = await ReminderSettings.findOneAndUpdate(
      { 
        userId: req.user._id,
        userEmail: req.user.email 
      },
      {
        ...req.body,
        userId: req.user._id,
        userEmail: req.user.email
      },
      { new: true, upsert: true }
    );
    
    res.json({
      success: true,
      message: 'Reminder settings updated successfully!',
      settings
    });
  } catch (err) {
    console.error('Update reminder settings error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// GET /api/appointments/by-date/:date - Get appointments for specific date
app.get('/api/appointments/by-date/:date', authenticate, async (req, res) => {
  try {
    const { date } = req.params;
    
    // Create start and end of day in UTC
    const startDate = new Date(date);
    startDate.setUTCHours(0, 0, 0, 0);
    
    const endDate = new Date(date);
    endDate.setUTCHours(23, 59, 59, 999);

    const appointments = await Appointment.find({
      userId: req.user._id,
      userEmail: req.user.email,
      date: {
        $gte: startDate,
        $lt: endDate
      },
      isActive: true
    }).sort({ time: 1 });
    
    res.json({ success: true, appointments, date: date });
  } catch (err) {
    console.error('Get appointments by date error:', err);
    standardErrorResponse(res, 500, 'Failed to retrieve appointments', err.message);
  }
});

// GET /api/appointments/upcoming - Get upcoming appointments (next 7 days)
app.get('/api/appointments/upcoming', authenticate, async (req, res) => {
  try {
    const now = new Date();
    const nextWeek = new Date(now.getTime() + (7 * 24 * 60 * 60 * 1000));
    
    const appointments = await Appointment.find({
      userId: req.user._id,
      userEmail: req.user.email,
      date: { $gte: now, $lte: nextWeek },
      status: { $in: ['confirmed', 'pending'] },
      isActive: true
    }).sort({ date: 1, time: 1 }).limit(10);
    
    res.json({ success: true, appointments });
  } catch (err) {
    console.error('Get upcoming appointments error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});


// Helper function to format phone number (you can customize this based on your needs)

console.log('Appointment scheduling API routes loaded successfully');



};