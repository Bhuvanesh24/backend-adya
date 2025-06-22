import mongoose from "mongoose";

const notificationSchema = new mongoose.Schema({
  message: { type: String, required: true },
  type: { type: String, enum: ['info', 'warning', 'error'], default: 'info' },
  createdAt: { type: Date, default: Date.now },
  isRead: { type: Boolean, default: false }
});

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  skills: [String],
  professionalSummary: String,

  experience: [
    {
      jobTitle: { type: String, required: true },
      company: String,
      yearsOfExperience: Number,
      description: String
    }
  ],
  jobPreferences: {
    titles: [String],
    locations: [String],
    jobType: String,
    industries: [String],
    expectedSalary: String,
    workMode: String,
    relocate: Boolean
  },
  
  resumes: [String],
  coverLetters: [String],
  jobGoals: {
    weeklyTarget: { type: Number, default: 0 },
    currentWeekCount: { type: Number, default: 0 },
    lastReset: { type: Date, default: Date.now }
  },
  notifications: [notificationSchema], 
  applications: [{ type: mongoose.Schema.Types.ObjectId, ref: "Application" }],

  createdAt: { type: Date, default: Date.now }
 
  
});


const User = mongoose.models.User || mongoose.model("User", userSchema);
export default User;
