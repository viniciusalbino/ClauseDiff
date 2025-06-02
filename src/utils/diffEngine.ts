import { ComparisonResult, DIFF_INSERT, DIFF_DELETE, DIFF_EQUAL, DiffOperation } from '../../types';

const escapeHtml = (text: string): string => {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;')
    .replace(/\n/g, '<br />');
};

export const generateDiff = (text1: string, text2: string): ComparisonResult => {
  // Corrected from window.DiffMatchPatch to window.diff_match_patch
  const dmp = new window.diff_match_patch(); 
  const diffs = dmp.diff_main(text1, text2); // diffs is Array<[number, string]>
  dmp.diff_cleanupSemantic(diffs);

  let html1 = '';
  let html2 = '';
  let additions = 0;
  let deletions = 0;
  let totalDifferences = 0;
  
  // Convert numeric operations to string types
  const rawDiffs = diffs.map(([op, data]) => {
    let type: 'insert' | 'delete' | 'equal';
    switch (op) {
      case 1: type = 'insert'; break;
      case -1: type = 'delete'; break;
      default: type = 'equal';
    }
    return { type, text: data };
  });

  for (const chunk of rawDiffs) {
    const type = chunk.type;
    const data = chunk.text;
    const escapedData = escapeHtml(data);

    switch (type) {
      case DIFF_INSERT: // Present in text2, not in text1
        html2 += `<span class="bg-green-100 text-green-800">${escapedData}</span>`; 
        additions += data.length;
        if (data.trim() !== '') totalDifferences++;
        break;
      case DIFF_DELETE: // Present in text1, not in text2
        html1 += `<span class="bg-red-100 text-red-800 line-through">${escapedData}</span>`; 
        deletions += data.length;
        if (data.trim() !== '') totalDifferences++;
        break;
      case DIFF_EQUAL:
        html1 += escapedData;
        html2 += escapedData;
        break;
    }
  }
  
  return { 
    html1, 
    html2, 
    summary: { additions, deletions, totalDifferences }, 
    rawDiffs 
  };
};