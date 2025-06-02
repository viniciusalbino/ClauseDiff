import { DocumentData, ComparisonResult } from '../../types';
import { generateDiff } from '../utils/diffEngine';

const API_BASE_URL = 'http://localhost:3001';

export const compareDocuments = async (doc1: DocumentData, doc2: DocumentData): Promise<ComparisonResult> => {
  if (!doc1.originalFile || !doc2.originalFile) {
    throw new Error('Both documents must have files to compare');
  }

  // For now, we'll use the local diff engine since we're not using the backend yet
  return generateDiff(doc1.content, doc2.content);

  // TODO: Implement backend comparison when ready
  /*
  const formData = new FormData();
  formData.append('file1', doc1.originalFile);
  formData.append('file2', doc2.originalFile);

  const response = await fetch(`${API_BASE_URL}/diff`, {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.message || 'Failed to compare documents');
  }

  const result = await response.json();
  return result;
  */
}; 