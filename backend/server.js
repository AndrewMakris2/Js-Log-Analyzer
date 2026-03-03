// server.js - Entry point for the Security Log Summarizer backend
// Starts Express server, registers middleware and routes

import express from 'express';
import cors from 'cors';
import multer from 'multer';
import { analyzeRouter } from './routes/analyze.js';
import dotenv from 'dotenv';

// Load environment variables from .env file (API keys etc)
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors({ origin: 'http://localhost:5173' })); // Vite dev server
app.use(express.json({ limit: '10mb' }));

// Multer - store uploaded files in memory (no disk writes)
export const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB max
});

// Routes
app.use('/api', analyzeRouter);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: err.message || 'Something went wrong',
  });
});

app.listen(PORT, () => {
  console.log(`Security Log Summarizer backend running on port ${PORT}`);
});