module.exports = (app, mongoose, authenticate) => {

// Medical Support Schema
const MedicalSupportSchema = new mongoose.Schema({
  fullName: { type: String, required: true, trim: true },
  age: { type: Number, required: true },
  symptoms: { type: String, required: true, trim: true }
}, { timestamps: true });

const MedicalSupport = mongoose.model("MedicalSupport", MedicalSupportSchema);

// Routes
app.post("/api/medical-support", async (req, res) => {
  try {
    const { fullName, age, symptoms } = req.body;
    const supportReq = new MedicalSupport({ fullName, age, symptoms });
    await supportReq.save();
    res.status(201).json({
      success: true,
      message: "Medical support request saved",
      data: supportReq
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error saving request",
      error: error.message
    });
  }
});

app.get("/api/medical-support", async (req, res) => {
  try {
    const requests = await MedicalSupport.find().sort({ createdAt: -1 });
    res.json({ success: true, count: requests.length, data: requests });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error fetching requests",
      error: error.message
    });
  }
});

// Medical Assistance Schema
const MedicalAssistanceSchema = new mongoose.Schema({
  assistanceType: { type: String, required: true, enum: ["General Inquiry", "Emergency", "Follow-up"] },
  details: { type: String, required: true, trim: true }
}, { timestamps: true });

const MedicalAssistance = mongoose.models.MedicalAssistance || mongoose.model("MedicalAssistance", MedicalAssistanceSchema);

// POST - create medical assistance request
app.post("/api/medical-assistance", async (req, res) => {
  try {
    const { assistanceType, details } = req.body;

    if (!assistanceType || !details) {
      return res.status(400).json({
        success: false,
        message: "All fields are required"
      });
    }

    const newRequest = new MedicalAssistance({ assistanceType, details });
    await newRequest.save();

    res.status(201).json({
      success: true,
      message: "Medical assistance request submitted successfully",
      data: newRequest
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error saving request",
      error: error.message
    });
  }
});

// GET - fetch all medical assistance requests
app.get("/api/medical-assistance", async (req, res) => {
  try {
    const requests = await MedicalAssistance.find().sort({ createdAt: -1 });
    res.json({
      success: true,
      count: requests.length,
      data: requests
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error fetching requests",
      error: error.message
    });
  }
});

// Medical Conditions Schema
const MedicalConditionsSchema = new mongoose.Schema({
  chronicConditions: { type: [String], default: [] },
  currentMedications: { type: String, trim: true },
  knownAllergies: { type: String, trim: true },
  familyHistory: { type: String, trim: true },
  smokingStatus: { type: String, enum: ["Never", "Former Smoker", "Current Smoker"], required: true },
  exerciseFrequency: { type: String, enum: ["Never", "Weekly", "Daily"], required: true }
}, { timestamps: true });

const MedicalConditions = mongoose.models.MedicalConditions || mongoose.model("MedicalConditions", MedicalConditionsSchema);

// POST - save medical conditions assessment
app.post("/api/medical-conditions", async (req, res) => {
  try {
    const {
      chronicConditions,
      currentMedications,
      knownAllergies,
      familyHistory,
      smokingStatus,
      exerciseFrequency
    } = req.body;

    const newAssessment = new MedicalConditions({
      chronicConditions,
      currentMedications,
      knownAllergies,
      familyHistory,
      smokingStatus,
      exerciseFrequency
    });

    await newAssessment.save();
    res.status(201).json({ success: true, message: "Medical conditions assessment submitted", data: newAssessment });
  } catch (error) {
    res.status(500).json({ success: false, message: "Error saving assessment", error: error.message });
  }
});

// GET - fetch all medical condition assessments
app.get("/api/medical-conditions", async (req, res) => {
  try {
    const assessments = await MedicalConditions.find().sort({ createdAt: -1 });
    res.json({ success: true, count: assessments.length, data: assessments });
  } catch (error) {
    res.status(500).json({ success: false, message: "Error fetching assessments", error: error.message });
  }
});

// Trainer Module Schema
const TrainerModuleSchema = new mongoose.Schema({
  fitnessGoal: { type: String, required: true },
  workoutTime: { type: String, required: true },
  additionalNotes: { type: String, trim: true }
}, { timestamps: true });

const TrainerModule = mongoose.models.TrainerModule || mongoose.model("TrainerModule", TrainerModuleSchema);

// POST - save trainer module
app.post("/api/trainer-module", async (req, res) => {
  try {
    const { fitnessGoal, workoutTime, additionalNotes } = req.body;

    const newEntry = new TrainerModule({
      fitnessGoal,
      workoutTime,
      additionalNotes
    });

    await newEntry.save();
    res.status(201).json({ success: true, message: "Trainer module submitted successfully", data: newEntry });
  } catch (error) {
    res.status(500).json({ success: false, message: "Error submitting trainer module", error: error.message });
  }
});

// GET - fetch all trainer modules
app.get("/api/trainer-module", async (req, res) => {
  try {
    const entries = await TrainerModule.find().sort({ createdAt: -1 });
    res.json({ success: true, count: entries.length, data: entries });
  } catch (error) {
    res.status(500).json({ success: false, message: "Error fetching trainer modules", error: error.message });
  }
});

// Virtual Consultation Schema
const VirtualConsultationSchema = new mongoose.Schema({
  consultationType: { type: String, required: true },
  preferredDoctor: { type: String, required: true },
  preferredDate: { type: String, required: true },
  preferredTime: { type: String, required: true },
  reasonForVisit: { type: String, trim: true },
  insuranceProvider: { type: String, trim: true }
}, { timestamps: true });

const VirtualConsultation = mongoose.models.VirtualConsultation || mongoose.model("VirtualConsultation", VirtualConsultationSchema);

// POST - save virtual consultation booking
app.post("/api/virtual-consultation", async (req, res) => {
  try {
    const {
      consultationType,
      preferredDoctor,
      preferredDate,
      preferredTime,
      reasonForVisit,
      insuranceProvider
    } = req.body;

    const newBooking = new VirtualConsultation({
      consultationType,
      preferredDoctor,
      preferredDate,
      preferredTime,
      reasonForVisit,
      insuranceProvider
    });

    await newBooking.save();
    res.status(201).json({ success: true, message: "Virtual consultation booked successfully", data: newBooking });
  } catch (error) {
    res.status(500).json({ success: false, message: "Error booking consultation", error: error.message });
  }
});

// GET - fetch all virtual consultations
app.get("/api/virtual-consultation", async (req, res) => {
  try {
    const bookings = await VirtualConsultation.find().sort({ createdAt: -1 });
    res.json({ success: true, count: bookings.length, data: bookings });
  } catch (error) {
    res.status(500).json({ success: false, message: "Error fetching consultations", error: error.message });
  }
});

};