import express from 'express';
import {
  createApplication,
  getUserApplications,
  getApplicationById,
  updateApplicationStatus,
  updateApplication,
  deleteApplication,
  addNotes,
  addReminder,
  getUserReminders,
  updateReminderStatus,


} from '../controllers/application.controller.js';
import { requireAuth } from '../middlewares/auth.js'; // Assuming you have auth middleware

const router = express.Router();

// Apply authentication middleware to all routes
router.use(requireAuth);

// Application CRUD routes
router.post('/', createApplication);
router.get('/', getUserApplications);
router.get('/:applicationId', getApplicationById);
router.put('/', updateApplication);
router.delete('/:applicationId', deleteApplication);

// Status management routes
router.put('/status', updateApplicationStatus);

// Communication routes
// router.post('/communications', addCommunication);

// Notes routes
router.put('/notes', addNotes);

// Reminder management routes
router.post('/reminders', addReminder);
router.get('/app/reminders', getUserReminders);
router.put('/reminders/status-update', updateReminderStatus);




export default router;