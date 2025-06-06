import { DiffMatchPatchEngine } from '../../../../src/infrastructure/diff-engines/DiffMatchPatchEngine';
import { DiffResult } from '../../../../src/domain/entities/DiffResult';

describe('DiffMatchPatchEngine', () => {
  let engine: DiffMatchPatchEngine;

  beforeEach(() => {
    engine = new DiffMatchPatchEngine();
  });

  describe('Basic functionality', () => {
    it('should create engine instance', () => {
      expect(engine).toBeDefined();
      expect(engine.name).toBe('DiffMatchPatch');
      expect(engine.version).toBe('1.0.0');
    });

    it('should detect simple text changes', async () => {
      const result = await engine.compare({
        originalText: 'Hello world',
        modifiedText: 'Hello beautiful world'
      });

      expect(result).toBeInstanceOf(DiffResult);
      expect(result.chunks.length).toBeGreaterThan(0);
      expect(result.getOverallSimilarity()).toBeGreaterThan(0);
      expect(result.getOverallSimilarity()).toBeLessThan(1);
    });

    it('should handle identical texts', async () => {
      const result = await engine.compare({
        originalText: 'Same text',
        modifiedText: 'Same text'
      });

      expect(result.getOverallSimilarity()).toBe(1.0);
      expect(result.getTotalChangeCount()).toBe(0);
    });

    it('should handle empty texts', async () => {
      const result = await engine.compare({
        originalText: '',
        modifiedText: 'New text'
      });

      expect(result.getAdditions().length).toBeGreaterThan(0);
      expect(result.getDeletions().length).toBe(0);
    });
  });

  describe('Visualizations', () => {
    it('should generate HTML visualization', async () => {
      const result = await engine.compare({
        originalText: 'Hello world',
        modifiedText: 'Hello beautiful world'
      });

      const visualization = await engine.visualize(result, {
        format: 'html'
      });

      expect(visualization.format).toBe('html');
      expect(visualization.content).toContain('<');
    });

    it('should generate JSON visualization', async () => {
      const result = await engine.compare({
        originalText: 'Test',
        modifiedText: 'Test modified'
      });

      const visualization = await engine.visualize(result, {
        format: 'json'
      });

      expect(visualization.format).toBe('json');
      expect(() => JSON.parse(visualization.content)).not.toThrow();
    });
  });

  describe('Engine capabilities', () => {
    it('should provide engine summary', () => {
      const summary = engine.getSummary();

      expect(summary.engineName).toBe('DiffMatchPatch');
      expect(summary.algorithmType).toBe('diff-match-patch');
      expect(summary.capabilities).toBeDefined();
      expect(summary.complexity).toBeDefined();
    });

    it('should estimate processing time', () => {
      const estimatedTime = engine.estimateProcessingTime(1000, 1000);
      expect(typeof estimatedTime).toBe('number');
      expect(estimatedTime).toBeGreaterThan(0);
    });

    it('should validate if can process texts', () => {
      const canProcess = engine.canProcess('test text', 'modified test text');
      expect(canProcess).toBe(true);
    });
  });

  describe('Configuration', () => {
    it('should accept custom configuration', () => {
      const customConfig = {
        timeout: 5000,
        preserveWhitespace: true
      };

      expect(() => engine.configure(customConfig)).not.toThrow();
    });
  });

  describe('Error handling', () => {
    it('should handle invalid inputs gracefully', async () => {
      await expect(engine.compare({
        originalText: null as any,
        modifiedText: 'test'
      })).rejects.toThrow();
    });
  });
}); 