import express from 'express';
import {
    getUserProfile,
    updatePersonalInfo,
    updateProfessionalSummary,
    updateSkills,
    addSkill,
    removeSkill,
    updateExperience,
    addExperience,
    removeExperience,
    updateJobPreferences,
    updateJobGoals,
    resetWeeklyJobGoals,
    uploadResume,
    uploadCoverLetter,
    deleteResume,
    deleteCoverLetter,
    getUserDocuments,
    downloadFile,
    addNotification,
    markNotificationRead,
    getUnreadNotificationsCount,
} from '../controllers/user.controller.js';
import {upload} from "../utils/upload.js";
import { requireAuth } from '../middlewares/auth.js';


const router = express.Router();
router.use(requireAuth);

// GET routes
router.get('/', getUserProfile);
router.get('/documents', getUserDocuments);
router.get('/notifications/unread-count', getUnreadNotificationsCount);
router.post('/download/', downloadFile);

// POST routes for updates
router.post('/personal-info', updatePersonalInfo);
router.post('/professional-summary', updateProfessionalSummary);
router.post('/skills', updateSkills);
router.post('/skills/add', addSkill);
router.post('/skills/remove', removeSkill);
router.post('/experience', updateExperience);
router.post('/experience/add', addExperience);
router.post('/job-preferences', updateJobPreferences);
router.post('/job-goals', updateJobGoals);
router.delete('/job-goals/reset', resetWeeklyJobGoals);

// File upload routes
router.post('/upload/resume', upload.single('resume'), uploadResume);
router.post('/upload/cover-letter', upload.single('coverLetter'), uploadCoverLetter);

// DELETE routes
router.delete('/experience/:index', removeExperience);
router.delete('/resume', deleteResume);
router.delete('/cover-letter', deleteCoverLetter);

// Notification routes
router.post('/notifications', addNotification);
router.put('/notifications/read', markNotificationRead);

export default router;