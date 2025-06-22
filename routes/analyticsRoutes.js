import express from "express";
import { requireAuth } from '../middlewares/auth.js';
import { getApplicationStats,getDashboardSummary,getApplicationTimeline } from "../controllers/analytics.controller.js";
const router = express.Router();

router.use(requireAuth);

//Analytics
router.get('/stats', getApplicationStats);
router.get('/dashboard', getDashboardSummary);
router.get('/applications/:applicationId/timeline', getApplicationTimeline);

export default router;