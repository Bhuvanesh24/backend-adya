// controllers/jobController.js
import Job from '../models/Job.js';
import { fetchJobsFromAPI, fetchCompanyInfo, fetchSalaryData } from '../services/jobApiService.js';
import User from '../models/User.js';

// Create a new manual job entry
export const createJob = async (req, res) => {
  try {
    const jobData = req.body;
    const newJob = new Job(jobData);
    await newJob.save();
    
    res.status(201).json({
      success: true,
      message: 'Job created successfully',
      data: newJob
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      message: 'Error creating job',
      error: error.message
    });
  }
};

// Get all manual jobs with pagination and filters (for admin/browsing)
export const getAllJobs = async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    const filters = {};
    
    // Apply filters based on query parameters
    if (req.query.jobType) filters.jobType = req.query.jobType;
    if (req.query.workMode) filters.workMode = req.query.workMode;
    if (req.query.status !== undefined) filters.status = req.query.status === 'true';
    if (req.query.company) filters['company.name'] = new RegExp(req.query.company, 'i');
    if (req.query.location) filters['company.location'] = new RegExp(req.query.location, 'i');
    if (req.query.tags) filters.tags = { $in: req.query.tags.split(',') };
    
    // Salary range filter
    if (req.query.minSalary || req.query.maxSalary) {
      filters.$or = [];
      if (req.query.minSalary) {
        filters.$or.push({ 'salary.min': { $gte: parseInt(req.query.minSalary) } });
      }
      if (req.query.maxSalary) {
        filters.$or.push({ 'salary.max': { $lte: parseInt(req.query.maxSalary) } });
      }
    }

    const jobs = await Job.find(filters)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);
    
    const total = await Job.countDocuments(filters);
    
    res.json({
      success: true,
      data: jobs,
      pagination: {
        current: page,
        total: Math.ceil(total / limit),
        count: jobs.length,
        totalJobs: total
      },
      source: 'manual_only'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching jobs',
      error: error.message
    });
  }
};

// Get job by ID
export const getJobById = async (req, res) => {
  try {
    const job = await Job.findById(req.params.id);
    
    if (!job) {
      return res.status(404).json({
        success: false,
        message: 'Job not found'
      });
    }
    
    res.json({
      success: true,
      data: job
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching job',
      error: error.message
    });
  }
};

// Update job
export const updateJob = async (req, res) => {
  try {
    const job = await Job.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true, runValidators: true }
    );
    
    if (!job) {
      return res.status(404).json({
        success: false,
        message: 'Job not found'
      });
    }
    
    res.json({
      success: true,
      message: 'Job updated successfully',
      data: job
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      message: 'Error updating job',
      error: error.message
    });
  }
};

// Delete job
export const deleteJob = async (req, res) => {
  try {
    const job = await Job.findByIdAndDelete(req.params.id);
    
    if (!job) {
      return res.status(404).json({
        success: false,
        message: 'Job not found'
      });
    }
    
    res.json({
      success: true,
      message: 'Job deleted successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error deleting job',
      error: error.message
    });
  }
};

// MAIN JOB SEARCH - Get jobs based on user preferences (combines manual + API)
// This is the primary route when user goes to job search
export const getJobsByUserPreferences = async (req, res) => {
  try {
    const userId = req.user.id;
    const user = await User.findById(userId);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    const preferences = user.jobPreferences || {};
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    
    // Build search parameters from user preferences
    const searchParams = {
      query: preferences.titles ? preferences.titles.join(' ') : preferences.skills ? preferences.skills.join(' ') : 'software engineer',
      location: preferences.locations ? preferences.locations[0] : 'remote',
      jobType: preferences.jobType,
      workMode: preferences.workMode,
      page: page
    };
    
    // Combine manual jobs and API jobs
    const [manualJobs, apiJobs] = await Promise.all([
      getManualJobsByPreferences(preferences, limit / 2),
      fetchJobsFromAPI(searchParams)
    ]);
    
    // Merge and sort jobs by relevance and date
    const allJobs = [...manualJobs, ...apiJobs]
      .sort((a, b) => {
        // Sort by relevance score if available, then by date
        const scoreA = calculateRelevanceScore(a, preferences);
        const scoreB = calculateRelevanceScore(b, preferences);
        if (scoreA !== scoreB) return scoreB - scoreA;
        return new Date(b.createdAt || b.postedDate) - new Date(a.createdAt || a.postedDate);
      })
      .slice(0, limit);
    
    res.json({
      success: true,
      data: allJobs,
      pagination: {
        current: page,
        hasMore: allJobs.length === limit
      },
      sources: {
        manual: manualJobs.length,
        api: apiJobs.length,
        total: allJobs.length
      },
      message: 'Jobs based on your preferences and skills'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching jobs by preferences',
      error: error.message
    });
  }
};

// Get recommended jobs based on similar preferences
export const getRecommendedJobs = async (req, res) => {
  try {
    const userId = req.user.id;
    const user = await User.findById(userId);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    const preferences = user.jobPreferences || {};
    
    // Find jobs with similar tags or requirements
    const recommendedJobs = await Job.find({
      status: true,
      $or: [
        { tags: { $in: preferences.skills || [] } },
        { requirements: { $in: preferences.skills || [] } },
        { 'company.industry': { $in: preferences.industries || [] } },
        { jobType: preferences.jobType }
      ]
    }).limit(20).sort({ createdAt: -1 });
    
    res.json({
      success: true,
      data: recommendedJobs,
      message: 'Recommended jobs based on your profile'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching recommended jobs',
      error: error.message
    });
  }
};

// Search jobs from external API + manual jobs based on custom query
export const searchJobsFromAPI = async (req, res) => {
  try {
    const { query, location, page = 1, includeManual = true } = req.query;
    
    if (!query) {
      return res.status(400).json({
        success: false,
        message: 'Query parameter is required'
      });
    }
    
    const searchPromises = [fetchJobsFromAPI({ query, location, page })];
    
    // Also search manual jobs if requested
    if (includeManual === 'true') {
      const manualSearchFilters = {
        status: true,
        $or: [
          { title: new RegExp(query, 'i') },
          { description: new RegExp(query, 'i') },
          { tags: new RegExp(query, 'i') },
          { requirements: new RegExp(query, 'i') }
        ]
      };
      
      if (location && location !== 'remote') {
        manualSearchFilters['company.location'] = new RegExp(location, 'i');
      }
      
      searchPromises.push(Job.find(manualSearchFilters).limit(10).sort({ createdAt: -1 }));
    }
    
    const [apiJobs, manualJobs = []] = await Promise.all(searchPromises);
    
    // Combine and sort results
    const allJobs = [...apiJobs, ...manualJobs].sort((a, b) => 
      new Date(b.createdAt || b.postedDate) - new Date(a.createdAt || a.postedDate)
    );
    
    res.json({
      success: true,
      data: allJobs,
      sources: {
        api: apiJobs.length,
        manual: manualJobs.length,
        total: allJobs.length
      },
      searchQuery: query,
      location: location
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error searching jobs',
      error: error.message
    });
  }
};

// Get company information and insights
export const getCompanyInsights = async (req, res) => {
  try {
    const { companyName } = req.params;
    
    const companyInfo = await fetchCompanyInfo(companyName);
    
    res.json({
      success: true,
      data: companyInfo
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching company insights',
      error: error.message
    });
  }
};

// Get salary data for a specific role and location
export const getSalaryData = async (req, res) => {
  try {
    const { jobTitle, location } = req.query;
    
    if (!jobTitle) {
      return res.status(400).json({
        success: false,
        message: 'Job title is required'
      });
    }
    
    const salaryData = await fetchSalaryData(jobTitle, location);
    
    res.json({
      success: true,
      data: salaryData
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching salary data',
      error: error.message
    });
  }
};

// Helper function to get manual jobs by preferences
const getManualJobsByPreferences = async (preferences, limit = 25) => {
  const filters = { status: true }; // Only active jobs
  
  if (preferences.jobType) filters.jobType = preferences.jobType;
  if (preferences.workMode) filters.workMode = preferences.workMode;
  if (preferences.locations && preferences.locations.length > 0) {
    filters['company.location'] = { $in: preferences.locations.map(loc => new RegExp(loc, 'i')) };
  }
  if (preferences.industries && preferences.industries.length > 0) {
    filters['company.industry'] = { $in: preferences.industries };
  }
  if (preferences.titles && preferences.titles.length > 0) {
    filters.$or = preferences.titles.map(title => ({
      title: new RegExp(title, 'i')
    }));
  }
  
  return await Job.find(filters).sort({ createdAt: -1 }).limit(limit);
};

// Helper function to calculate relevance score
const calculateRelevanceScore = (job, preferences) => {
  let score = 0;
  
  // Check title match
  if (preferences.titles && preferences.titles.length > 0) {
    const titleMatch = preferences.titles.some(title => 
      job.title && job.title.toLowerCase().includes(title.toLowerCase())
    );
    if (titleMatch) score += 10;
  }
  
  // Check skills match
  if (preferences.skills && preferences.skills.length > 0) {
    const skillMatches = preferences.skills.filter(skill => 
      job.tags?.includes(skill) || job.requirements?.includes(skill)
    ).length;
    score += skillMatches * 5;
  }
  
  // Check location preference
  if (preferences.locations && preferences.locations.length > 0) {
    const locationMatch = preferences.locations.some(loc => 
      job.company?.location?.toLowerCase().includes(loc.toLowerCase())
    );
    if (locationMatch) score += 3;
  }
  
  // Check job type match
  if (preferences.jobType && job.jobType === preferences.jobType) {
    score += 2;
  }
  
  // Check work mode match
  if (preferences.workMode && job.workMode === preferences.workMode) {
    score += 2;
  }
  
  return score;
};