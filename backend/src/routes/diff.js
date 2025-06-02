const express = require('express');
const multer = require('multer');
const mammoth = require('mammoth');
const DiffMatchPatch = require('diff-match-patch');

const router = express.Router();
const upload = multer(); // memory storage

// Helper to extract text from .docx buffer
async function extractTextFromDocx(buffer) {
  const result = await mammoth.extractRawText({ buffer });
  return result.value;
}

// POST /diff
router.post('/', upload.fields([{ name: 'file1' }, { name: 'file2' }]), async (req, res) => {
  try {
    const file1 = req.files['file1']?.[0];
    const file2 = req.files['file2']?.[0];
    if (!file1 || !file2) {
      return res.status(400).json({ error: 'Both files are required.' });
    }
    const text1 = await extractTextFromDocx(file1.buffer);
    const text2 = await extractTextFromDocx(file2.buffer);

    const dmp = new DiffMatchPatch();
    let diffs = dmp.diff_main(text1, text2);
    dmp.diff_cleanupSemantic(diffs);
    const diffHtml = dmp.diff_prettyHtml(diffs);

    res.json({ diffHtml });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to process diff.' });
  }
});

module.exports = router; 