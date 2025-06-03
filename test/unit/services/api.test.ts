import { compareDocuments } from '../../../src/services/api';
import { generateDiff } from '../../../src/utils/diffEngine';

describe('compareDocuments', () => {
  const doc1 = { content: 'A', originalFile: new File(['A'], 'a.txt'), type: 'text/plain', name: 'a.txt' };
  const doc2 = { content: 'B', originalFile: new File(['B'], 'b.txt'), type: 'text/plain', name: 'b.txt' };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('calls generateDiff when both documents have files', async () => {
    const diffResult = { html1: 'a', html2: 'b', summary: {}, rawDiffs: [] };
    jest.spyOn(require('../../../src/utils/diffEngine'), 'generateDiff').mockReturnValue(diffResult);
    const result = await compareDocuments(doc1, doc2);
    expect(result).toBe(diffResult);
  });

  it('throws if either document is missing a file', async () => {
    await expect(compareDocuments({ ...doc1, originalFile: undefined }, doc2)).rejects.toThrow();
    await expect(compareDocuments(doc1, { ...doc2, originalFile: undefined })).rejects.toThrow();
  });
}); 