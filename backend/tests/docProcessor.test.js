const { processDocuments, _internal: { computeDiff } } = require('../src/services/docProcessor');

// Mock mammoth
jest.mock('mammoth', () => ({
  extractRawText: jest.fn(({ buffer }) => Promise.resolve({ value: buffer.toString() }))
}));

describe('docProcessor', () => {
  describe('computeDiff', () => {
    it('should handle pure additions', () => {
      const textA = 'Hello world';
      const textB = 'Hello beautiful world';
      const diffs = computeDiff(textA, textB);
      
      // Check that we have the right operations
      expect(diffs).toHaveLength(3);
      expect(diffs[0][0]).toBe(0); // EQUAL "Hello "
      expect(diffs[1][0]).toBe(1); // INSERT "beautiful "
      expect(diffs[2][0]).toBe(0); // EQUAL "world"
    });

    it('should handle pure deletions', () => {
      const textA = 'Hello beautiful world';
      const textB = 'Hello world';
      const diffs = computeDiff(textA, textB);
      
      // Check that we have the right operations
      expect(diffs).toHaveLength(3);
      expect(diffs[0][0]).toBe(0); // EQUAL "Hello "
      expect(diffs[1][0]).toBe(-1); // DELETE "beautiful "
      expect(diffs[2][0]).toBe(0); // EQUAL "world"
    });

    it('should handle modifications', () => {
      const textA = 'The color is red';
      const textB = 'The color is blue';
      const diffs = computeDiff(textA, textB);
      
      // Check that we have the right operations, regardless of order
      expect(diffs).toHaveLength(3);
      expect(diffs[0][0]).toBe(0); // EQUAL "The color is "
      // The order of delete/insert might vary, so check both possibilities
      const hasDelete = diffs.some(([op, text]) => op === -1 && text === 'red');
      const hasInsert = diffs.some(([op, text]) => op === 1 && text === 'blue');
      expect(hasDelete).toBe(true);
      expect(hasInsert).toBe(true);
    });
  });

  describe('processDocuments', () => {
    beforeEach(() => {
      // Clear mock calls before each test
      jest.clearAllMocks();
    });

    it('should process additions correctly', async () => {
      const result = await processDocuments(
        Buffer.from('Hello world'),
        Buffer.from('Hello beautiful world')
      );

      expect(result.stats).toEqual({
        added: 'beautiful '.length,
        removed: 0,
        modified: 0
      });

      expect(result.originalHtml).not.toContain('<ins');
      expect(result.modifiedHtml).toContain('<ins class="bg-green-100">beautiful </ins>');
    });

    it('should process deletions correctly', async () => {
      const result = await processDocuments(
        Buffer.from('Hello beautiful world'),
        Buffer.from('Hello world')
      );

      expect(result.stats).toEqual({
        added: 0,
        removed: 'beautiful '.length,
        modified: 0
      });

      expect(result.originalHtml).toContain('<del class="bg-red-100 line-through">beautiful </del>');
      expect(result.modifiedHtml).not.toContain('<del');
    });

    it('should process modifications correctly', async () => {
      const result = await processDocuments(
        Buffer.from('The color is red'),
        Buffer.from('The color is blue')
      );

      // The exact stats might vary depending on how diff-match-patch interprets the change
      expect(result.stats.added).toBeGreaterThan(0);
      expect(result.stats.removed).toBeGreaterThan(0);
      expect(result.stats.modified).toBeGreaterThan(0);

      expect(result.originalHtml).toContain('<del');
      expect(result.modifiedHtml).toContain('<ins');
      expect(result.originalHtml).toContain('red');
      expect(result.modifiedHtml).toContain('blue');
    });
  });
}); 