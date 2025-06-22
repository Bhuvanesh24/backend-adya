import express from 'express';
import dotenv from 'dotenv';

import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';

import connectDB from './config/db.js';
import errorHandler from './middlewares/errorHandler.js';

import authRoutes from './routes/authRoutes.js';
import userRoutes from './routes/userRoutes.js';
import applicationRoutes from "./routes/applicationRoutes.js";
import jobRoutes from "./routes/jobRoutes.js";
import aiRoutes from "./routes/aiRoutes.js";
import analyticsRoutes from "./routes/analyticsRoutes.js";


import cookieParser from "cookie-parser";


// Load environment variables
dotenv.config();


// Init express app
const app = express();

// Security Middlewares
app.use(helmet());

// Rate Limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  message: 'Too many requests, please try again later.',
});
app.use(limiter);

// CORS Setup
app.use(
  cors({
    origin:
      process.env.NODE_ENV === 'production'
        ? ['https://your-frontend-domain.com']
        : ['http://localhost:8080', 'http://localhost:3001'],
    credentials: true,
  })
);


app.use(cookieParser());

// Body Parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// MongoDB Connection
await connectDB();

//Routes

app.use("/api/auth", authRoutes);
app.use("/api/user",userRoutes);
app.use("/api/user/applications",applicationRoutes);
app.use("/api/jobs",jobRoutes);
app.use("/api/ai",aiRoutes);
app.use("/api/analytics",analyticsRoutes);

// Health Check
app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
  });
});

// // 404 Fallback
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found',
  });
});

// Error Handler
app.use(errorHandler);

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});



