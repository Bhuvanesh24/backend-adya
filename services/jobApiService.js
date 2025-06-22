// services/jobApiService.js
import axios from 'axios';

const RAPIDAPI_KEY = '96af39b7f9msh9e3c3e1077f1f8dp106ce8jsn8eddcb6c1ae2';
const RAPIDAPI_HOST = 'jsearch.p.rapidapi.com';

// Base configuration for API requests
const apiConfig = {
  headers: {
    'X-RapidAPI-Key': RAPIDAPI_KEY,
    'X-RapidAPI-Host': RAPIDAPI_HOST
  }
};

// Fetch jobs from external API based on preferences or custom query
export const fetchJobsFromAPI = async (preferences = {}) => {
  try {
    const {
      query = 'software engineer',
      location = 'remote',
      page = '1',
      jobType,
      workMode,
      skills = []
    } = preferences;

    // Build search query based on preferences
    let searchQuery = query;
    
    if (skills.length > 0) {
      searchQuery += ` ${skills.join(' ')}`;
    }
    
    if (jobType) {
      searchQuery += ` ${jobType}`;
    }

    const options = {
      method: 'GET',
      url: 'https://jsearch.p.rapidapi.com/search',
      params: {
        query: `${searchQuery} in ${location}`,
        page: page.toString(),
        num_pages: '1',
        date_posted: 'month' // Get jobs posted in the last month
      },
      ...apiConfig
    };

    const response = await axios.request(options);
    const jobs = response.data.data || [];

    // Transform API response to match our schema
    return jobs.map(job => ({
      title: job.job_title,
      company: {
        name: job.employer_name,
        website: job.employer_website,
        location: job.job_city || job.job_country
      },
      jobType: mapJobType(job.job_employment_type),
      status: true,
      source: 'API',
      url: job.job_apply_link,
      description: job.job_description,
      requirements: extractRequirements(job.job_description),
      workMode: job.job_is_remote ? 'Remote' : 'On-site',
      postedDate: new Date(job.job_posted_at_datetime_utc),
      tags: extractTags(job.job_description),
      salary: {
        min: job.job_min_salary,
        max: job.job_max_salary,
        currency: job.job_salary_currency || 'USD'
      },
      apiData: {
        jobId: job.job_id,
        applyLink: job.job_apply_link,
        highlights: job.job_highlights,
        benefits: job.job_benefits
      }
    }));

  } catch (error) {
    console.error('Error fetching jobs from API:', error.message);
    throw new Error('Failed to fetch jobs from external API');
  }
};

// Fetch job details by ID from external API
export const fetchJobDetailsFromAPI = async (jobId) => {
  try {
    const options = {
      method: 'GET',
      url: 'https://jsearch.p.rapidapi.com/job-details',
      params: {
        job_id: jobId
      },
      ...apiConfig
    };

    const response = await axios.request(options);
    return response.data.data[0];
  } catch (error) {
    console.error('Error fetching job details:', error.message);
    throw new Error('Failed to fetch job details');
  }
};

// Search for jobs with custom parameters (not based on user preferences)
export const searchJobsCustom = async (searchParams) => {
  try {
    const {
      query,
      location = 'remote',
      page = '1',
      datePosted = 'month',
      jobType,
      remoteJobsOnly = false
    } = searchParams;

    const options = {
      method: 'GET',
      url: 'https://jsearch.p.rapidapi.com/search',
      params: {
        query: `${query} in ${location}`,
        page: page,
        num_pages: '1',
        date_posted: datePosted,
        remote_jobs_only: remoteJobsOnly
      },
      ...apiConfig
    };

    const response = await axios.request(options);
    return response.data.data || [];
  } catch (error) {
    console.error('Error in custom job search:', error.message);
    throw new Error('Failed to perform custom job search');
  }
};

// Fetch company information and news
export const fetchCompanyInfo = async (companyName) => {
  try {
    // This is a placeholder - you might want to integrate with other APIs
    // for company information like Clearbit, LinkedIn, or news APIs
    
    const companyData = {
      name: companyName,
      overview: `Information about ${companyName}`,
      newsInsights: await fetchCompanyNews(companyName),
      reviews: await fetchCompanyReviews(companyName)
    };

    return companyData;
  } catch (error) {
    console.error('Error fetching company info:', error.message);
    throw new Error('Failed to fetch company information');
  }
};

// Fetch company news (placeholder - integrate with news API)
export const fetchCompanyNews = async (companyName) => {
  try {
    // Placeholder for news API integration
    // You can integrate with NewsAPI, Google News API, etc.
    return [
      {
        source: 'TechCrunch',
        title: `Latest news about ${companyName}`,
        url: '#',
        publishedAt: new Date()
      }
    ];
  } catch (error) {
    console.error('Error fetching company news:', error.message);
    return [];
  }
};

// Fetch company reviews (placeholder)
export const fetchCompanyReviews = async (companyName) => {
  try {
    // Placeholder for reviews API integration
    // You can integrate with Glassdoor API, Indeed API, etc.
    return [
      {
        source: 'Glassdoor',
        rating: 4.2,
        summary: `Employee reviews for ${companyName}`
      }
    ];
  } catch (error) {
    console.error('Error fetching company reviews:', error.message);
    return [];
  }
};

// Fetch salary data for specific role and location
export const fetchSalaryData = async (jobTitle, location = 'United States') => {
  try {
    const options = {
      method: 'GET',
      url: 'https://jsearch.p.rapidapi.com/estimated-salary',
      params: {
        job_title: jobTitle,
        location: location
      },
      ...apiConfig
    };

    const response = await axios.request(options);
    const salaryData = response.data.data[0];

    return {
      jobTitle,
      location,
      salary: {
        min: salaryData?.min_salary,
        max: salaryData?.max_salary,
        median: salaryData?.median_salary,
        currency: salaryData?.salary_currency || 'USD'
      },
      publisher: salaryData?.publisher_name,
      negotiationTips: generateNegotiationTips(salaryData)
    };
  } catch (error) {
    console.error('Error fetching salary data:', error.message);
    throw new Error('Failed to fetch salary data');
  }
};

// Helper function to map job types from API to our schema
const mapJobType = (apiJobType) => {
  const typeMap = {
    'FULLTIME': 'Full-time',
    'PARTTIME': 'Part-time',
    'CONTRACTOR': 'Contract',
    'INTERN': 'Internship'
  };
  
  return typeMap[apiJobType] || 'Full-time';
};

// Helper function to extract requirements from job description
const extractRequirements = (description) => {
  if (!description) return [];
  
  // Simple extraction - you can enhance this with NLP
  const requirements = [];
  const keywords = ['experience', 'skills', 'required', 'must have', 'proficient'];
  
  keywords.forEach(keyword => {
    const regex = new RegExp(`${keyword}[^.]*`, 'gi');
    const matches = description.match(regex);
    if (matches) {
      requirements.push(...matches.slice(0, 3)); // Limit to first 3 matches
    }
  });
  
  return requirements.slice(0, 5); // Limit to 5 requirements
};

// Helper function to extract tags from job description
const extractTags = (description) => {
  if (!description) return [];
  
  // Common tech skills and keywords
  const techSkills = [
    'JavaScript', 'Python', 'Java', 'React', 'Node.js', 'SQL', 'MongoDB',
    'AWS', 'Docker', 'Kubernetes', 'Machine Learning', 'AI', 'DevOps',
    'Angular', 'Vue.js', 'PHP', 'C++', 'C#', '.NET', 'Ruby', 'Go'
  ];
  
  const foundTags = techSkills.filter(skill => 
    description.toLowerCase().includes(skill.toLowerCase())
  );
  
  return foundTags.slice(0, 10); // Limit to 10 tags
};

// Helper function to generate negotiation tips
const generateNegotiationTips = (salaryData) => {
  const tips = [
    'Research market rates for your role and location',
    'Highlight your unique skills and achievements',
    'Consider the total compensation package, not just base salary',
    'Practice your negotiation conversation beforehand',
    'Be prepared to justify your ask with concrete examples'
  ];
  
  if (salaryData?.median_salary) {
    tips.unshift(`The median salary for this role is ${salaryData.salary_currency} ${salaryData.median_salary.toLocaleString()}`);
  }
  
  return tips;
};