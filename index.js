module.exports = (app, mongoose, authenticate) => {
    const standardErrorResponse = (res, statusCode, message, details = null) => {
  const response = {
    success: false,
    message: message,
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

// Custom Recipe Schema
// Recipe Schema
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
                let totalCalories = 0;
                let totalProtein = 0;
                let totalCarbs = 0;
                let totalFat = 0;
                let totalFiber = 0;
                
                // Populate ingredients if needed
                if (this.ingredients[0].foodItem && typeof this.ingredients[0].foodItem === 'object') {
                    // Already populated
                    this.ingredients.forEach(ingredient => {
                        if (ingredient.foodItem) {
                            totalCalories += (ingredient.foodItem.calories * ingredient.quantity);
                            totalProtein += (ingredient.foodItem.protein * ingredient.quantity);
                            totalCarbs += (ingredient.foodItem.carbs * ingredient.quantity);
                            totalFat += (ingredient.foodItem.fat * ingredient.quantity);
                            totalFiber += (ingredient.foodItem.fiber * ingredient.quantity);
                        }
                    });
                } else {
                    // Need to populate
                    await this.populate('ingredients.foodItem');
                    this.ingredients.forEach(ingredient => {
                        if (ingredient.foodItem) {
                            totalCalories += (ingredient.foodItem.calories * ingredient.quantity);
                            totalProtein += (ingredient.foodItem.protein * ingredient.quantity);
                            totalCarbs += (ingredient.foodItem.carbs * ingredient.quantity);
                            totalFat += (ingredient.foodItem.fat * ingredient.quantity);
                            totalFiber += (ingredient.foodItem.fiber * ingredient.quantity);
                        }
                    });
                }
                
                this.nutrition = {
                    calories: Math.round(totalCalories / this.servings),
                    protein: Math.round(totalProtein / this.servings),
                    carbs: Math.round(totalCarbs / this.servings),
                    fat: Math.round(totalFat / this.servings),
                    fiber: Math.round(totalFiber / this.servings)
                };
            } catch (error) {
                console.error('Error calculating recipe nutrition:', error);
            }
        }
        
        next();
    });
const Recipe = mongoose.model('Recipe', RecipeSchema);
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

    MealSchema.pre('save', async function(next) {
        try {
            let totalCalories = 0;
            let totalProtein = 0;
            let totalCarbs = 0;
            let totalFat = 0;
            let totalFiber = 0;
            
            if (this.items && this.items.length > 0) {
                // Populate food items if needed
                if (this.items[0].foodItem && typeof this.items[0].foodItem === 'object') {
                    // Already populated
                    this.items.forEach(item => {
                        if (item.foodItem) {
                            totalCalories += (item.foodItem.calories || 0) * (item.quantity || 1);
                            totalProtein += (item.foodItem.protein || 0) * (item.quantity || 1);
                            totalCarbs += (item.foodItem.carbs || 0) * (item.quantity || 1);
                            totalFat += (item.foodItem.fat || 0) * (item.quantity || 1);
                            totalFiber += (item.foodItem.fiber || 0) * (item.quantity || 1);
                        }
                    });
                } else {
                    // Need to populate
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
                }
            }
            
            this.totalNutrition = {
                calories: Math.round(totalCalories),
                protein: Math.round(totalProtein * 100) / 100,
                carbs: Math.round(totalCarbs * 100) / 100,
                fat: Math.round(totalFat * 100) / 100,
                fiber: Math.round(totalFiber * 100) / 100
            };
            
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
        dailyCalories: { type: Number, default: 2000 },
        protein: { type: Number, default: 150 }, // in grams
        carbs: { type: Number, default: 250 },   // in grams
        fat: { type: Number, default: 67 },      // in grams
        fiber: { type: Number, default: 25 },    // in grams
        water: { type: Number, default: 2000 },  // in ml
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

// Appointment Statistics Schema
const AppointmentStatsSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  userEmail: {
    type: String,
    required: true
  },
  total: {
    type: Number,
    default: 0
  },
  confirmed: {
    type: Number,
    default: 0
  },
  pending: {
    type: Number,
    default: 0
  },
  activeReminders: {
    type: Number,
    default: 0
  },
  completed: {
    type: Number,
    default: 0
  },
  lastUpdated: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Create index for faster queries
AppointmentStatsSchema.index({ userId: 1, userEmail: 1 });

const AppointmentStats = mongoose.model('AppointmentStats', AppointmentStatsSchema);
// GET /api/appointments/count/total - Get total appointments count for user
app.get('/api/appointments/count/total', authenticate, async (req, res) => {
  try {
    const userId = req.user._id;
    const userEmail = req.user.email;
    
    const totalCount = await Appointment.countDocuments({ 
      userId: userId, 
      userEmail: userEmail, 
      isActive: true 
    });
    
    res.json({
      success: true,
      count: totalCount,
      message: `Total appointments: ${totalCount}`
    });
  } catch (err) {
    console.error('Get total appointments count error:', err);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to get total appointments count' 
    });
  }
});
// GET /api/appointments/count/pending - Get pending appointments count for user
app.get('/api/appointments/count/pending', authenticate, async (req, res) => {
  try {
    const userId = req.user._id;
    const userEmail = req.user.email;
    
    const pendingCount = await Appointment.countDocuments({ 
      userId: userId, 
      userEmail: userEmail, 
      status: 'pending',
      isActive: true 
    });
    
    res.json({
      success: true,
      count: pendingCount,
      message: `Pending appointments: ${pendingCount}`
    });
  } catch (err) {
    console.error('Get pending appointments count error:', err);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to get pending appointments count' 
    });
  }
});
// GET /api/appointments/count/confirmed - Get confirmed appointments count for user
app.get('/api/appointments/count/confirmed', authenticate, async (req, res) => {
  try {
    const userId = req.user._id;
    const userEmail = req.user.email;
    
    const confirmedCount = await Appointment.countDocuments({ 
      userId: userId, 
      userEmail: userEmail, 
      status: 'confirmed',
      isActive: true 
    });
    
    res.json({
      success: true,
      count: confirmedCount,
      message: `Confirmed appointments: ${confirmedCount}`
    });
  } catch (err) {
    console.error('Get confirmed appointments count error:', err);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to get confirmed appointments count' 
    });
  }
});
// GET /api/appointments/count/completed - Get completed appointments count for user
app.get('/api/appointments/count/completed', authenticate, async (req, res) => {
  try {
    const userId = req.user._id;
    const userEmail = req.user.email;
    
    const completedCount = await Appointment.countDocuments({ 
      userId: userId, 
      userEmail: userEmail, 
      status: 'completed',
      isActive: true 
    });
    
    res.json({
      success: true,
      count: completedCount,
      message: `Completed appointments: ${completedCount}`
    });
  } catch (err) {
    console.error('Get completed appointments count error:', err);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to get completed appointments count' 
    });
  }
});
// GET /api/appointments/count/active-reminders - Get active reminders count for user
app.get('/api/appointments/count/active-reminders', authenticate, async (req, res) => {
  try {
    const userId = req.user._id;
    const userEmail = req.user.email;
    const now = new Date();
    const twoDaysFromNow = new Date(now.getTime() + (48 * 60 * 60 * 1000));
    
    // First get appointments that match the criteria
    const appointments = await Appointment.find({
      userId: userId,
      userEmail: userEmail,
      reminderSet: true,
      status: 'confirmed',
      isActive: true,
      date: { $gte: now, $lte: twoDaysFromNow }
    });
    
    // Filter appointments that should send reminders
    const activeRemindersCount = appointments.filter(appointment => 
      appointment.shouldSendReminder()
    ).length;
    
    res.json({
      success: true,
      count: activeRemindersCount,
      message: `Active reminders: ${activeRemindersCount}`
    });
  } catch (err) {
    console.error('Get active reminders count error:', err);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to get active reminders count' 
    });
  }
});
// GET /api/appointments/statistics/all - Get all statistics in one call
app.get('/api/appointments/statistics/all', authenticate, async (req, res) => {
  try {
    const userId = req.user._id;
    const userEmail = req.user.email;
    const now = new Date();
    const twoDaysFromNow = new Date(now.getTime() + (48 * 60 * 60 * 1000));
    
    // Get all counts in parallel for better performance
    const [
      totalCount,
      pendingCount,
      confirmedCount,
      completedCount,
      appointmentsForReminders
    ] = await Promise.all([
      // Total appointments
      Appointment.countDocuments({ 
        userId: userId, 
        userEmail: userEmail, 
        isActive: true 
      }),
      
      // Pending appointments
      Appointment.countDocuments({ 
        userId: userId, 
        userEmail: userEmail, 
        status: 'pending',
        isActive: true 
      }),
      
      // Confirmed appointments
      Appointment.countDocuments({ 
        userId: userId, 
        userEmail: userEmail, 
        status: 'confirmed',
        isActive: true 
      }),
      
      // Completed appointments
      Appointment.countDocuments({ 
        userId: userId, 
        userEmail: userEmail, 
        status: 'completed',
        isActive: true 
      }),
      
      // Appointments for reminders calculation
      Appointment.find({
        userId: userId,
        userEmail: userEmail,
        reminderSet: true,
        status: 'confirmed',
        isActive: true,
        date: { $gte: now, $lte: twoDaysFromNow }
      })
    ]);
    
    // Calculate active reminders
    const activeRemindersCount = appointmentsForReminders.filter(appointment => 
      appointment.shouldSendReminder()
    ).length;
    
    res.json({
      success: true,
      statistics: {
        total: totalCount,
        pending: pendingCount,
        confirmed: confirmedCount,
        completed: completedCount,
        activeReminders: activeRemindersCount
      },
      message: 'Statistics retrieved successfully'
    });
  } catch (err) {
    console.error('Get all statistics error:', err);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to get statistics' 
    });
  }
});

// GET /api/appointments/reminders - Get all active reminders for user
app.get('/api/appointments/reminders', authenticate, async (req, res) => {
  try {
    const userId = req.user._id;
    const userEmail = req.user.email;
    const now = new Date();
    const oneWeekFromNow = new Date(now.getTime() + (7 * 24 * 60 * 60 * 1000));
    
    // Get appointments that are upcoming and have reminders set
    const appointments = await Appointment.find({
      userId: userId,
      userEmail: userEmail,
      status: { $in: ['confirmed', 'pending'] },
      isActive: true,
      date: { $gte: now, $lte: oneWeekFromNow }
    }).sort({ date: 1, time: 1 });
    
    // Filter appointments that need reminders
    const reminders = appointments.filter(appointment => {
      const appointmentDateTime = new Date(`${appointment.date.toISOString().split('T')[0]} ${appointment.time}`);
      const timeDiff = appointmentDateTime.getTime() - now.getTime();
      const hoursDiff = timeDiff / (1000 * 3600);
      
      return hoursDiff <= 48; // Show reminders for appointments within 48 hours
    }).map(appointment => {
      const appointmentDateTime = new Date(`${appointment.date.toISOString().split('T')[0]} ${appointment.time}`);
      const timeDiff = appointmentDateTime.getTime() - now.getTime();
      const hoursDiff = Math.ceil(timeDiff / (1000 * 3600));
      
      return {
        _id: appointment._id,
        patientName: appointment.patientName,
        doctorName: appointment.doctorName,
        specialty: appointment.specialty,
        date: appointment.date,
        time: appointment.time,
        duration: appointment.duration,
        clinic: appointment.clinic,
        address: appointment.address,
        phone: appointment.phone,
        status: appointment.status,
        hoursUntil: hoursDiff,
        urgency: hoursDiff <= 1 ? 'urgent' : hoursDiff <= 24 ? 'today' : 'upcoming'
      };
    });
    
    res.json({
      success: true,
      reminders: reminders,
      total: reminders.length
    });
  } catch (err) {
    console.error('Get reminders error:', err);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to get reminders' 
    });
  }
});

// PATCH /api/appointments/reminders/:id/snooze - Snooze a reminder for 1 hour
app.patch('/api/appointments/reminders/:id/snooze', authenticate, async (req, res) => {
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
    
    // In a real app, you would update a snooze field in the database
    // For now, we'll just return success
    res.json({
      success: true,
      message: 'Reminder snoozed for 1 hour'
    });
  } catch (err) {
    console.error('Snooze reminder error:', err);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to snooze reminder' 
    });
  }
});

// PATCH /api/appointments/reminders/:id/mark-missed - Mark reminder as missed
app.patch('/api/appointments/reminders/:id/mark-missed', authenticate, async (req, res) => {
  try {
    const appointment = await Appointment.findOneAndUpdate(
      {
        _id: req.params.id,
        userId: req.user._id,
        userEmail: req.user.email,
        isActive: true
      },
      { 
        status: 'cancelled',
        reminderSet: false 
      },
      { new: true }
    );
    
    if (!appointment) {
      return res.status(404).json({ success: false, message: 'Appointment not found' });
    }
    
    res.json({
      success: true,
      message: 'Appointment marked as missed'
    });
  } catch (err) {
    console.error('Mark missed error:', err);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to mark as missed' 
    });
  }
});

// DELETE /api/appointments/reminders/:id - Delete reminder (soft delete)
app.delete('/api/appointments/reminders/:id', authenticate, async (req, res) => {
  try {
    const appointment = await Appointment.findOneAndUpdate(
      {
        _id: req.params.id,
        userId: req.user._id,
        userEmail: req.user.email,
        isActive: true
      },
      { 
        reminderSet: false 
      },
      { new: true }
    );
    
    if (!appointment) {
      return res.status(404).json({ success: false, message: 'Appointment not found' });
    }
    
    res.json({
      success: true,
      message: 'Reminder deleted successfully'
    });
  } catch (err) {
    console.error('Delete reminder error:', err);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to delete reminder' 
    });
  }
});
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
            
            res.json({
                success: true,
                data: foodItems,
                page: parseInt(page),
                limit: parseInt(limit)
            });
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
            res.json({
                success: true,
                data: foodItem
            });
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
            res.status(201).json({
                success: true,
                message: 'Food item created successfully',
                data: foodItem
            });
        } catch (error) {
            console.error('Create food item error:', error);
            standardErrorResponse(res, 500, 'Failed to create food item', error.message);
        }
    });

// Recipe Routes
app.get('/api/recipes', authenticate, async (req, res) => {
        try {
            const recipes = await Recipe.find({
                $or: [{ createdBy: req.user._id }, { isPublic: true }]
            }).populate('ingredients.foodItem');
            
            res.json({
                success: true,
                data: recipes
            });
        } catch (error) {
            console.error('Get recipes error:', error);
            standardErrorResponse(res, 500, 'Failed to retrieve recipes', error.message);
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
            
            res.status(201).json({
                success: true,
                message: 'Recipe created successfully',
                data: recipe
            });
        } catch (error) {
            console.error('Create recipe error:', error);
            standardErrorResponse(res, 500, 'Failed to create recipe', error.message);
        }
    });

// Meal Routes - FIXED
    app.get('/api/meals', authenticate, async (req, res) => {
        try {
            const { date } = req.query;
            let query = { userId: req.user._id };
            
            if (date) {
                const targetDate = new Date(date);
                const startOfDay = new Date(targetDate);
                startOfDay.setHours(0, 0, 0, 0);
                
                const endOfDay = new Date(targetDate);
                endOfDay.setHours(23, 59, 59, 999);
                
                query.date = { $gte: startOfDay, $lte: endOfDay };
            }
            
            const meals = await Meal.find(query)
                .populate('items.foodItem')
                .populate('items.recipe')
                .sort({ time: 1 });
            
            res.json({
                success: true,
                data: meals
            });
        } catch (error) {
            console.error('Get meals error:', error);
            standardErrorResponse(res, 500, 'Failed to retrieve meals', error.message);
        }
    });

    // In your server code, update the meal creation route
app.post('/api/meals', authenticate, async (req, res) => {
    try {
        const mealData = req.body;
        
        console.log('Received meal data:', mealData);
        
        // Process items - handle both USDA foods and regular food items
        const processedItems = await Promise.all(mealData.items.map(async (item) => {
            console.log('Processing item:', item);
            
            if (item.fdcId) {
                // This is a USDA food item - create a FoodItem record
                const foodItem = new FoodItem({
                    name: item.name,
                    brand: item.brandOwner || item.brand || '',
                    servingSize: `${item.servingSize || 100} ${item.servingSizeUnit || 'g'}`,
                    calories: item.calories || 0,
                    protein: item.protein || 0,
                    carbs: item.carbs || 0,
                    fat: item.fat || 0,
                    fiber: item.fiber || 0,
                    isCustom: true,
                    createdBy: req.user._id
                });
                
                await foodItem.save();
                console.log('Created food item:', foodItem);
                
                return {
                    foodItem: foodItem._id,
                    quantity: item.quantity || 1,
                    unit: item.servingSizeUnit || 'g'
                };
            } else if (item.foodItem) {
                // Regular food item with foodItem ID
                return {
                    foodItem: item.foodItem,
                    quantity: item.quantity || 1,
                    unit: item.unit || 'serving'
                };
            } else if (item.calories !== undefined) {
                // Direct nutrition data without fdcId - create a custom food item
                const foodItem = new FoodItem({
                    name: item.name || 'Custom Food',
                    brand: item.brandOwner || item.brand || '',
                    servingSize: `${item.servingSize || 100} ${item.servingSizeUnit || 'g'}`,
                    calories: item.calories || 0,
                    protein: item.protein || 0,
                    carbs: item.carbs || 0,
                    fat: item.fat || 0,
                    fiber: item.fiber || 0,
                    isCustom: true,
                    createdBy: req.user._id
                });
                
                await foodItem.save();
                console.log('Created custom food item:', foodItem);
                
                return {
                    foodItem: foodItem._id,
                    quantity: item.quantity || 1,
                    unit: item.servingSizeUnit || 'g'
                };
            } else {
                throw new Error('Invalid food item structure');
            }
        }));

        console.log('Processed items:', processedItems);

        // Create the meal with processed items
        const meal = new Meal({
            userId: req.user._id,
            name: mealData.name,
            type: mealData.type,
            items: processedItems,
            date: new Date(mealData.date),
            time: mealData.time || new Date().toLocaleTimeString(),
            notes: mealData.notes || ''
        });

        console.log('Saving meal:', meal);
        
        await meal.save();

        // Populate and return the meal with full nutrition data
        const populatedMeal = await Meal.findById(meal._id)
            .populate('items.foodItem')
            .populate('items.recipe');
            
        console.log('Populated meal:', populatedMeal);
            
        res.status(201).json({
            success: true,
            message: 'Meal created successfully',
            data: populatedMeal
        });
        
    } catch (error) {
        console.error('Error creating meal:', error);
        standardErrorResponse(res, 500, 'Failed to create meal', error.message);
    }
});

    app.delete('/api/meals/:id', authenticate, async (req, res) => {
        try {
            const meal = await Meal.findById(req.params.id);
            if (!meal) {
                return standardErrorResponse(res, 404, 'Meal not found');
            }
            
            if (meal.userId.toString() !== req.user._id.toString()) {
                return standardErrorResponse(res, 403, 'Not authorized'); 
            }
            
            await Meal.findByIdAndDelete(req.params.id);
            res.json({
                success: true,
                message: 'Meal deleted successfully'
            });
        } catch (error) {
            console.error('Delete meal error:', error);
            standardErrorResponse(res, 500, 'Failed to delete meal', error.message);
        }
    });
 // Water Intake Routes
    app.get('/api/water-intake', authenticate, async (req, res) => {
        try {
            const { date } = req.query;
            let query = { userId: req.user._id };
            
            if (date) {
                const targetDate = new Date(date);
                const startOfDay = new Date(targetDate);
                startOfDay.setHours(0, 0, 0, 0);
                
                const endOfDay = new Date(targetDate);
                endOfDay.setHours(23, 59, 59, 999);
                
                query.date = { $gte: startOfDay, $lte: endOfDay };
            }
            
            const waterIntakes = await WaterIntake.find(query);
            const total = waterIntakes.reduce((sum, intake) => sum + intake.amount, 0);
            
            res.json({
                success: true,
                data: {
                    entries: waterIntakes,
                    total: total
                }
            });
        } catch (error) {
            console.error('Get water intake error:', error);
            standardErrorResponse(res, 500, 'Failed to retrieve water intake data', error.message);
        }
    });


    // Add this route to your existing server code
app.get('/api/reports/weekly-calories', authenticate, async (req, res) => {
  try {
    const { startDate } = req.query;
    const userId = req.user._id;
    
    // Calculate date range (last 7 days)
    const endDate = startDate ? new Date(startDate) : new Date();
    const startDateObj = new Date(endDate);
    startDateObj.setDate(endDate.getDate() - 6); // 7 days total
    
    // Set to start and end of days
    startDateObj.setHours(0, 0, 0, 0);
    endDate.setHours(23, 59, 59, 999);
    
    // Get meals for the date range
    const meals = await Meal.find({
      userId: userId,
      date: { 
        $gte: startDateObj, 
        $lte: endDate 
      },
      isActive: true
    }).populate('items.foodItem').populate('items.recipe');
    
    // Get water intake for the date range
    const waterIntakes = await WaterIntake.find({
      userId: userId,
      date: { 
        $gte: startDateObj, 
        $lte: endDate 
      }
    });
    
    // Group data by day
    const dailyData = {};
    
    // Initialize all days in the range
    for (let i = 0; i < 7; i++) {
      const currentDate = new Date(startDateObj);
      currentDate.setDate(startDateObj.getDate() + i);
      const dateKey = currentDate.toISOString().split('T')[0];
      const dayName = currentDate.toLocaleDateString('en-US', { weekday: 'short' });
      
      dailyData[dateKey] = {
        day: `${dayName} ${currentDate.getDate()}`,
        date: dateKey,
        calories: 0,
        protein: 0,
        carbs: 0,
        fat: 0,
        fiber: 0,
        water: 0
      };
    }
    
    // Process meals data
    meals.forEach(meal => {
      const dateKey = meal.date.toISOString().split('T')[0];
      if (dailyData[dateKey]) {
        dailyData[dateKey].calories += meal.totalNutrition?.calories || 0;
        dailyData[dateKey].protein += meal.totalNutrition?.protein || 0;
        dailyData[dateKey].carbs += meal.totalNutrition?.carbs || 0;
        dailyData[dateKey].fat += meal.totalNutrition?.fat || 0;
        dailyData[dateKey].fiber += meal.totalNutrition?.fiber || 0;
      }
    });
    
    // Process water intake data
    waterIntakes.forEach(intake => {
      const dateKey = intake.date.toISOString().split('T')[0];
      if (dailyData[dateKey]) {
        dailyData[dateKey].water += intake.amount || 0;
      }
    });
    
    // Convert to array and ensure proper data types
    const weeklyData = Object.values(dailyData).map(day => ({
      ...day,
      calories: Math.round(day.calories),
      protein: Math.round(day.protein * 10) / 10, // Keep 1 decimal place
      carbs: Math.round(day.carbs * 10) / 10,
      fat: Math.round(day.fat * 10) / 10,
      fiber: Math.round(day.fiber * 10) / 10
    }));
    
    // Sort by date
    weeklyData.sort((a, b) => new Date(a.date) - new Date(b.date));
    
    res.json({
      success: true,
      data: {
        dailyData: weeklyData,
        startDate: startDateObj.toISOString().split('T')[0],
        endDate: endDate.toISOString().split('T')[0],
        summary: {
          totalCalories: weeklyData.reduce((sum, day) => sum + day.calories, 0),
          averageCalories: Math.round(weeklyData.reduce((sum, day) => sum + day.calories, 0) / weeklyData.length),
          daysTracked: weeklyData.filter(day => day.calories > 0).length
        }
      }
    });
    
  } catch (error) {
    console.error('Weekly calories report error:', error);
    standardErrorResponse(res, 500, 'Failed to generate weekly calories report', error.message);
  }
});
// Add this route to calculate daily totals
app.get('/api/daily-totals', authenticate, async (req, res) => {
  try {
    const { date } = req.query;
    const targetDate = date ? new Date(date) : new Date();
    
    const startOfDay = new Date(targetDate);
    startOfDay.setHours(0, 0, 0, 0);
    
    const endOfDay = new Date(targetDate);
    endOfDay.setHours(23, 59, 59, 999);
    
    // Get meals for the day
    const meals = await Meal.find({
      userId: req.user._id,
      date: { $gte: startOfDay, $lte: endOfDay }
    }).populate('items.foodItem').populate('items.recipe');
    
    // Get water intake for the day
    const waterIntakes = await WaterIntake.find({
      userId: req.user._id,
      date: { $gte: startOfDay, $lte: endOfDay }
    });
    
    // Calculate totals from meals
    const totals = {
      calories: 0,
      protein: 0,
      carbs: 0,
      fat: 0,
      fiber: 0
    };
    
    meals.forEach(meal => {
      if (meal.totalNutrition) {
        totals.calories += Number(meal.totalNutrition.calories) || 0;
        totals.protein += Number(meal.totalNutrition.protein) || 0;
        totals.carbs += Number(meal.totalNutrition.carbs) || 0;
        totals.fat += Number(meal.totalNutrition.fat) || 0;
        totals.fiber += Number(meal.totalNutrition.fiber) || 0;
      }
    });
    
    // Calculate water total
    const waterTotal = waterIntakes.reduce((sum, intake) => sum + intake.amount, 0);
    
    // Get goals
    const goals = await NutritionalGoals.findOne({ userId: req.user._id }) || {
      dailyCalories: 2000,
      protein: 150,
      carbs: 250,
      fat: 67,
      fiber: 25,
      water: 2000
    };
    
    res.json({
      success: true,
      data: {
        date: targetDate.toISOString().split('T')[0],
        totals: {
          calories: Math.round(totals.calories),
          protein: Math.round(totals.protein),
          carbs: Math.round(totals.carbs),
          fat: Math.round(totals.fat),
          fiber: Math.round(totals.fiber),
          water: waterTotal
        },
        goals: goals,
        mealsCount: meals.length,
        waterEntriesCount: waterIntakes.length
      }
    });
    
  } catch (error) {
    console.error('Daily totals error:', error);
    standardErrorResponse(res, 500, 'Failed to calculate daily totals', error.message);
  }
});
    app.post('/api/water-intake', authenticate, async (req, res) => {
        try {
            const waterIntake = new WaterIntake({
                ...req.body,
                userId: req.user._id
            });
            
            await waterIntake.save();
            res.status(201).json({
                success: true,
                message: 'Water intake recorded successfully',
                data: waterIntake
            });
        } catch (error) {
            console.error('Create water intake error:', error);
            standardErrorResponse(res, 500, 'Failed to create water intake entry', error.message);
        }
    });


// Nutritional Goals Routes - FIXED
    app.get('/api/nutritional-goals', authenticate, async (req, res) => {
        try {
            let goals = await NutritionalGoals.findOne({ userId: req.user._id });
            
            if (!goals) {
                // Create default goals
                goals = new NutritionalGoals({
                    userId: req.user._id,
                    dailyCalories: 2000,
                    protein: 150,
                    carbs: 250,
                    fat: 67,
                    fiber: 25,
                    water: 2000
                });
                
                await goals.save();
            }
            
            res.json({
                success: true,
                data: goals
            });
        } catch (error) {
            console.error('Get nutritional goals error:', error);
            // Return default goals instead of error
            res.json({
                success: false,
                message: 'Using default nutritional goals',
                data: {
                    dailyCalories: 2000,
                    protein: 150,
                    carbs: 250,
                    fat: 67,
                    fiber: 25,
                    water: 2000,
                    fromDefaults: true
                }
            });
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
            
            res.json({
                success: true,
                message: 'Nutritional goals updated successfully',
                data: goals
            });
        } catch (error) {
            console.error('Update nutritional goals error:', error);
            standardErrorResponse(res, 500, 'Failed to update nutritional goals', error.message);
        }
    });

  app.post('/api/nutritional-goals', authenticate, async (req, res) => {
        try {
            // Check if goals already exist
            const existingGoals = await NutritionalGoals.findOne({ userId: req.user._id });
            if (existingGoals) {
                return res.status(400).json({
                    success: false,
                    message: 'Nutritional goals already exist for this user'
                });
            }
            
            const goals = new NutritionalGoals({
                ...req.body,
                userId: req.user._id
            });
            
            await goals.save();
            
            res.status(201).json({
                success: true,
                message: 'Nutritional goals created successfully',
                data: goals
            });
        } catch (error) {
            console.error('Create nutritional goals error:', error);
            standardErrorResponse(res, 500, 'Failed to create nutritional goals', error.message);
        }
    });

// Reports Routes
    app.get('/api/reports/daily', authenticate, async (req, res) => {
        try {
            const { date } = req.query;
            const targetDate = date ? new Date(date) : new Date();
            
            const startOfDay = new Date(targetDate);
            startOfDay.setHours(0, 0, 0, 0);
            
            const endOfDay = new Date(targetDate);
            endOfDay.setHours(23, 59, 59, 999);
            
            // Get meals for the day
            const meals = await Meal.find({
                userId: req.user._id,
                date: { $gte: startOfDay, $lte: endOfDay }
            }).populate('items.foodItem').populate('items.recipe');
            
            // Get water intake for the day
            const waterIntakes = await WaterIntake.find({
                userId: req.user._id,
                date: { $gte: startOfDay, $lte: endOfDay }
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
            const goals = await NutritionalGoals.findOne({ userId: req.user._id }) || {
                dailyCalories: 2000,
                protein: 150,
                carbs: 250,
                fat: 67,
                fiber: 25,
                water: 2000
            };
            
            res.json({
                success: true,
                data: {
                    date: targetDate.toISOString().split('T')[0],
                    meals: meals,
                    waterIntakes: waterIntakes,
                    totalNutrition: totalNutrition,
                    totalWater: totalWater,
                    goals: goals
                }
            });
        } catch (error) {
            console.error('Daily report error:', error);
            standardErrorResponse(res, 500, 'Failed to generate daily report', error.message);
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
            
            // Get water intake for the week
            const waterIntakes = await WaterIntake.find({
                userId: req.user._id,
                date: { $gte: start, $lte: end }
            });
            
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
            
            // Process water intakes
            waterIntakes.forEach(intake => {
                const dateStr = intake.date.toISOString().split('T')[0];
                if (dailyData[dateStr]) {
                    dailyData[dateStr].totalWater += intake.amount;
                }
            });
            
            // Get goals
            const goals = await NutritionalGoals.findOne({ userId: req.user._id }) || {
                dailyCalories: 2000,
                protein: 150,
                carbs: 250,
                fat: 67,
                fiber: 25,
                water: 2000
            };
            
            res.json({
                success: true,
                data: {
                    startDate: start.toISOString().split('T')[0],
                    endDate: end.toISOString().split('T')[0],
                    dailyData: Object.values(dailyData),
                    goals: goals
                }
            });
        } catch (error) {
            console.error('Weekly report error:', error);
            standardErrorResponse(res, 500, 'Failed to generate weekly report', error.message);
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
app.post('/api/appointments', authenticate, async (req, res) => {
  try {
    const appointmentData = {
      ...req.body,
      userId: req.user._id,
      userEmail: req.user.email
    };
    
    // Validate appointment date is not in the past
    const appointmentDate = new Date(appointmentData.date);
    const today = new Date();
    today.setHours(0, 0, 0, 0);
     if (appointmentData.date) {
      appointmentData.date = convertToUTC(appointmentData.date);
    }
    if (appointmentDate < today) {
      return standardErrorResponse(res, 400, 'Appointment date cannot be in the past');
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
      return res.status(400).json({ 
        success: false,
        message: 'You already have an appointment at this date and time' 
      });
    }
    
    const appointment = new Appointment(appointmentData);
    await appointment.save();
    
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
    res.status(500).json({ success: false, message: 'Server error' });
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