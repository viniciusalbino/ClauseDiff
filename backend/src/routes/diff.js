const express = require('express');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const { processDocuments } = require('../services/docProcessor');

const router = express.Router();

// Configure multer for memory storage
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
      cb(null, true);
    } else {
      cb(new Error('Only .docx files are allowed'));
    }
  }
});

// In-memory storage for results
const inMemoryResults = new Map();

// Cleanup function to remove old results
function cleanupResult(resultId) {
  setTimeout(() => {
    inMemoryResults.delete(resultId);
  }, 3600000); // 1 hour
}

/**
 * POST /diff
 * Compare two DOCX files and return diff results
 */
router.post('/', upload.fields([
  { name: 'file1', maxCount: 1 },
  { name: 'file2', maxCount: 1 }
]), async (req, res) => {
  try {
    // Validate files
    if (!req.files || !req.files.file1 || !req.files.file2) {
      return res.status(400).json({ error: 'Both files are required' });
    }

    const file1 = req.files.file1[0];
    const file2 = req.files.file2[0];

    // Process documents
    const result = await processDocuments(file1.buffer, file2.buffer);

    // Generate result ID and store in memory
    const resultId = uuidv4();
    inMemoryResults.set(resultId, {
      originalHtml: result.originalHtml,
      modifiedHtml: result.modifiedHtml
    });

    // Schedule cleanup
    cleanupResult(resultId);

    // Return response
    res.json({
      ...result,
      resultId
    });

  } catch (error) {
    console.error('Error processing documents:', error);
    res.status(500).json({ error: error.message || 'Internal server error' });
  }
});

module.exports = router; 