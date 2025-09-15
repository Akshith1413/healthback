module.exports = (app, mongoose, authenticate) => {
    
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
    res.status(500).json({ message: 'Server error' });
  }
});
app.get('/api/food-items/:id', authenticate, async (req, res) => {
  try {
    const foodItem = await FoodItem.findById(req.params.id);
    if (!foodItem) {
      return res.status(404).json({ message: 'Food item not found' });
    }
    res.json(foodItem);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
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
    res.status(500).json({ message: 'Server error' });
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
    res.status(500).json({ message: 'Server error' });
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
    res.status(500).json({ message: 'Server error' });
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
    res.status(500).json({ message: 'Server error' });
  }
});
// Delete a meal
app.delete('/api/meals/:id', authenticate, async (req, res) => {
  try {
    const meal = await Meal.findById(req.params.id);
    if (!meal) {
      return res.status(404).json({ message: 'Meal not found' });
    }
    
    // Check if the meal belongs to the user
    if (meal.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Not authorized' });
    }
    
    await Meal.findByIdAndDelete(req.params.id);
    res.json({ message: 'Meal deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});
// Fixed Meal creation route in your server file
app.post('/api/meals', authenticate, async (req, res) => {
  try {
    const mealData = req.body;
    console.log('Received meal data:', JSON.stringify(mealData, null, 2));
    
    // Process items - create FoodItem records for USDA foods
    const processedItems = await Promise.all(mealData.items.map(async (item) => {
      if (item.fdcId) {
        // This is a USDA food item, create a FoodItem record first
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
        console.log('Created USDA food item:', foodItem.name);
        
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
      } else {
        // Handle case where item might be malformed
        console.error('Invalid item structure:', item);
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
    
    // Save the meal first
    await meal.save();
    console.log('Meal saved with ID:', meal._id);
    
    // Populate the meal with food item details
    await meal.populate('items.foodItem');
    console.log('Meal populated');
    
    // Calculate nutrition (this should trigger the pre-save hook)
    await meal.save();
    console.log('Nutrition calculated');
    
    // Return the fully populated meal
    const populatedMeal = await Meal.findById(meal._id)
      .populate('items.foodItem')
      .populate('items.recipe');
      
    console.log('Returning meal:', populatedMeal.name);
    res.status(201).json(populatedMeal);
    
  } catch (error) {
    console.error('Error creating meal:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({ 
      message: 'Server error', 
      error: error.message,
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
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
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
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
    res.status(500).json({ message: 'Server error' });
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
    res.status(500).json({ message: 'Server error' });
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
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
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
};