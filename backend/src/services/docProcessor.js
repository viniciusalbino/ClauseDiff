const mammoth = require('mammoth');
const { diff_match_patch } = require('diff-match-patch');

const dmp = new diff_match_patch();

/**
 * Converts a DOCX buffer to plain text using mammoth
 * @param {Buffer} buffer - The DOCX file buffer
 * @returns {Promise<string>} The extracted text
 */
async function convertDocxToText(buffer) {
  try {
    const result = await mammoth.extractRawText({ buffer });
    return result.value;
  } catch (error) {
    console.error('Error converting DOCX to text:', error);
    throw new Error('Failed to convert DOCX to text');
  }
}

/**
 * Computes the diff between two texts using diff-match-patch
 * @param {string} textA - Original text
 * @param {string} textB - Modified text
 * @returns {Array<[number, string]>} Array of diff operations
 */
function computeDiff(textA, textB) {
  const diffs = dmp.diff_main(textA, textB);
  dmp.diff_cleanupSemantic(diffs);
  return diffs;
}

/**
 * Processes two DOCX documents and generates HTML diff with statistics
 * @param {Buffer} fileBuf1 - Original document buffer
 * @param {Buffer} fileBuf2 - Modified document buffer
 * @returns {Promise<{originalHtml: string, modifiedHtml: string, stats: {added: number, removed: number, modified: number}}>}
 */
async function processDocuments(fileBuf1, fileBuf2) {
  // Convert both documents to text
  const [text1, text2] = await Promise.all([
    convertDocxToText(fileBuf1),
    convertDocxToText(fileBuf2)
  ]);

  // Compute diff
  const diffs = computeDiff(text1, text2);

  // Process diffs and generate HTML
  let originalHtml = '';
  let modifiedHtml = '';
  let stats = { added: 0, removed: 0, modified: 0 };
  let lastOp = null;

  for (const [op, text] of diffs) {
    switch (op) {
      case 0: // EQUAL
        originalHtml += text;
        modifiedHtml += text;
        lastOp = null;
        break;
      case -1: // DELETE
        originalHtml += `<del class="bg-red-100 line-through">${text}</del>`;
        stats.removed += text.length;
        lastOp = 'delete';
        break;
      case 1: // INSERT
        modifiedHtml += `<ins class="bg-green-100">${text}</ins>`;
        stats.added += text.length;
        if (lastOp === 'delete') {
          stats.modified++;
          stats.added--;
          stats.removed--;
        }
        lastOp = 'insert';
        break;
    }
  }

  return {
    originalHtml,
    modifiedHtml,
    stats
  };
}

module.exports = {
  processDocuments,
  // Export these for testing
  _internal: {
    convertDocxToText,
    computeDiff
  }
}; 