import { application } from "express";
import mongoose from "mongoose";

const ApplicationSchema = new mongoose.Schema({

  jobTitle: { type: String, required: true },
  company: { type: String, required: true },
  location: String,
  jobLink: String,
  jobDescription: String,

  currentStatus: {
    type: String,
    enum: ["applied", "under review", "interview scheduled", "offered", "rejected"],
    default: "applied"
  },
  salary : Number,
  statusHistory: [
    {
      status: {
        type: String,
        enum: ["applied", "under review", "interview scheduled", "offered", "rejected"]
      },
      updatedAt: { type: Date, default: Date.now },
      updatedBy: String,
      note: String
    }
  ],

  reminders: {
    type: {
      dueDate: { type: Date, required: true },
      title: String,
      isCompleted: { type: Boolean, default: false }
    },
    default: null,
    required: false
  },

  notes: { type: String, default: "" }, 
  appliedAt: { type: Date },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});


export default mongoose.model('Application', ApplicationSchema);