import mongoose from 'mongoose';

const jobSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true
  },
  company: {
    name: { type: String, required: true },
    website: { type: String },
    industry: { type: String },
    location: { type: String }
  },
  jobType: {
    type: String,
    enum: ['Full-time', 'Part-time', 'Contract', 'Internship', 'Freelance', 'Remote'],
    default: 'Full-time'
  },
  status : Boolean,
  source: {
    type: String, 
    default: 'Manual'
  },
  url: {
    type: String,
    trim: true
  },
  description: {
    type: String
  },
  responsibilities: [String],
  requirements: [String],
  salary: {
    min: Number,
    max: Number,
    currency: { type: String, default: 'Ruppess' }
  },
  workMode: {
    type: String,
    enum: ['On-site', 'Remote', 'Hybrid'],
    default: 'On-site'
  },
  postedDate: {
    type: Date
  },
  tags: [String], 

  createdAt: {
    type: Date,
    default: Date.now
  },
  newsInsights: [{
    source: String,
    title: String,
    url: String,
    publishedAt: Date
  }],
  reviews: [{
    source: String,
    rating: Number,
    summary: String
  }]
});

const Job = mongoose.model('Job', jobSchema);
export default Job;
