// routes/jobRoutes.js
import express from 'express';
import {
  createJob,
  getAllJobs,
  getJobById,
  updateJob,
  deleteJob,
  getJobsByUserPreferences,
  getRecommendedJobs,
  searchJobsFromAPI,
  getCompanyInsights,
  getSalaryData
} from '../controllers/job.controller.js';
import { requireAuth } from '../middlewares/auth.js';

const router = express.Router();

// Public routes (no authentication required)
router.get('/search', searchJobsFromAPI); // Search jobs from external API
router.get('/company/:companyName/insights', getCompanyInsights); // Get company insights
router.get('/salary-data', getSalaryData); // Get salary data
router.get('/all', getAllJobs); // Get all manual jobs with filters
router.get('/:id', getJobById); // Get specific job by ID

// Protected routes (authentication required)
router.use(requireAuth);

// Primary job search route - combines manual + API based on user preferences
router.get('/', getJobsByUserPreferences); // Main job search based on user skills/preferences

// User preference-based routes
router.get('/recommendations', getRecommendedJobs); // Get recommended jobs

// Admin/Company routes for job management
router.post('/', createJob); // Create new job
router.put('/:id', updateJob); // Update job
router.delete('/:id', deleteJob); // Delete job

export default router;