// routes/aiRoutes.js (Updated with file upload support)
import express from "express";
const router = express.Router()
import {upload} from "../utils/upload.js";
import { analyzeResume,generateCoverLetter,generateInterviewQuestions,analyzeSuccessProbability } from "../controllers/ai.controller.js";
import multer from "multer";
import { requireAuth } from "../middlewares/auth.js";

router.use(requireAuth);
// Middleware for request validation
const validateRequest = (requiredFields) => {
  return (req, res, next) => {
    const missingFields = requiredFields.filter(field => !req.body[field]);
    if (missingFields.length > 0) {
      return res.status(400).json({
        success: false,
        message: `Missing required fields: ${missingFields.join(', ')}`
      });
    }
    next();
  };
};

// Error handling middleware for multer
const handleUploadError = (error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    switch (error.code) {
      case 'LIMIT_FILE_SIZE':
        return res.status(400).json({
          success: false,
          message: 'File too large. Maximum size is 5MB.'
        });
      case 'LIMIT_FILE_COUNT':
        return res.status(400).json({
          success: false,
          message: 'Too many files. Only one file is allowed.'
        });
      default:
        return res.status(400).json({
          success: false,
          message: 'File upload error',
          error: error.message
        });
    }
  } else if (error) {
    return res.status(400).json({
      success: false,
      message: error.message
    });
  }
  next();
};

// Resume Analysis Routes
// POST /api/ai/analyze-resume (with file upload)
router.post('/analyze-resume',
  upload.single('resume'), 
  handleUploadError,
  validateRequest(['jobDescription']),
  analyzeResume
);



// Success Probability Analysis Routes
// POST /api/ai/analyze-success-probability (with file upload)
router.post('/analyze-success-probability',
  upload.single('resume'), // 'resume' is the field name for the file
  handleUploadError,
  validateRequest(['jobDescription']),
  analyzeSuccessProbability
);


// Cover Letter Generation Route (no file upload needed)
router.post('/generate-cover-letter',
  validateRequest(['jobTitle', 'jobDescription', 'companyName']),
  generateCoverLetter
);

// Interview Questions Generation Route (no file upload needed)
router.post('/generate-interview-questions',
  validateRequest(['companyName', 'jobTitle']),
  generateInterviewQuestions
);



// Get supported file formats
router.get('/supported-formats', (req, res) => {
  res.status(200).json({
    success: true,
    supportedFormats: {
      extensions: ['.pdf'],
      mimeTypes: [
        'application/pdf',
      ],
      maxFileSize: '5MB',
      note: 'PDF format provide the best text extraction results'
    }
  });
});

// Health check route
router.get('/health', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'AI services are running',
    timestamp: new Date().toISOString(),
    availableServices: [
      'Resume Analysis (with file upload)',
      'Cover Letter Generation', 
      'Interview Questions',
      'Success Probability Analysis (with file upload)'
    ],
    fileUploadSupport: {
      enabled: true,
      supportedFormats: ['.pdf'],
      maxSize: '5MB'
    }
  });
});

export default router;