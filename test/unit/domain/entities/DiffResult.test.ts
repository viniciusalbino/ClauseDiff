import { 
  DiffResult, 
  DiffChunk, 
  DiffStatistics, 
  SimilarityMetrics, 
  ChangeSection,
  DiffOperation 
} from '../../../../src/domain/entities/DiffResult';

describe('DiffResult Entity', () => {
  const mockChunks: DiffChunk[] = [
    {
      operation: 'equal',
      text: 'Common text',
      originalIndex: 0,
      modifiedIndex: 0,
      lineNumber: 1
    },
    {
      operation: 'delete',
      text: 'Deleted text',
      originalIndex: 11,
      lineNumber: 2
    },
    {
      operation: 'insert',
      text: 'Inserted text',
      modifiedIndex: 11,
      lineNumber: 3
    },
    {
      operation: 'modify',
      text: 'Modified text',
      originalIndex: 25,
      modifiedIndex: 25,
      lineNumber: 4
    }
  ];

  const mockSimilarityMetrics: SimilarityMetrics = {
    jaccard: 0.75,
    levenshtein: 0.80,
    cosine: 0.85,
    overall: 0.80
  };

  const mockStatistics: DiffStatistics = {
    totalChanges: 3,
    additions: 1,
    deletions: 1,
    modifications: 1,
    charactersAdded: 13,
    charactersDeleted: 12,
    linesAdded: 1,
    linesDeleted: 1,
    similarity: mockSimilarityMetrics,
    processingTime: 150
  };

  const mockChangeSections: ChangeSection[] = [
    {
      startLine: 2,
      endLine: 4,
      changeType: 'delete',
      intensity: 'medium'
    },
    {
      startLine: 5,
      endLine: 8,
      changeType: 'insert',
      intensity: 'high'
    }
  ];

  describe('Constructor and Basic Properties', () => {
    it('should create a DiffResult with all required parameters', () => {
      const diffResult = new DiffResult(
        'result-123',
        'comparison-456',
        'myers',
        mockChunks,
        mockStatistics,
        mockChangeSections
      );

      expect(diffResult.id).toBe('result-123');
      expect(diffResult.comparisonId).toBe('comparison-456');
      expect(diffResult.algorithm).toBe('myers');
      expect(diffResult.chunks).toEqual(mockChunks);
      expect(diffResult.statistics).toEqual(mockStatistics);
      expect(diffResult.changeSections).toEqual(mockChangeSections);
      expect(diffResult.createdAt).toBeInstanceOf(Date);
      expect(diffResult.version).toBe('1.0');
    });

    it('should create DiffResult with minimal parameters (no change sections)', () => {
      const diffResult = new DiffResult(
        'result-123',
        'comparison-456',
        'diff-match-patch',
        [],
        {
          totalChanges: 0,
          additions: 0,
          deletions: 0,
          modifications: 0,
          charactersAdded: 0,
          charactersDeleted: 0,
          linesAdded: 0,
          linesDeleted: 0,
          similarity: { jaccard: 1, levenshtein: 1, cosine: 1, overall: 1 },
          processingTime: 0
        }
      );

      expect(diffResult.chunks).toHaveLength(0);
      expect(diffResult.changeSections).toHaveLength(0);
      expect(diffResult.statistics.totalChanges).toBe(0);
    });
  });

  describe('Chunk Operations', () => {
    let diffResult: DiffResult;

    beforeEach(() => {
      diffResult = new DiffResult(
        'result-123',
        'comparison-456',
        'myers',
        mockChunks,
        mockStatistics,
        mockChangeSections
      );
    });

    it('should get chunks by operation type', () => {
      const deletedChunks = diffResult.getChangesByType('delete');
      expect(deletedChunks).toHaveLength(1);
      expect(deletedChunks[0].operation).toBe('delete');
      expect(deletedChunks[0].text).toBe('Deleted text');

      const insertedChunks = diffResult.getChangesByType('insert');
      expect(insertedChunks).toHaveLength(1);
      expect(insertedChunks[0].operation).toBe('insert');

      const equalChunks = diffResult.getChangesByType('equal');
      expect(equalChunks).toHaveLength(1);
    });

    it('should return empty array for non-existent operation types', () => {
      const emptyResult = new DiffResult(
        'empty-123',
        'comparison-456',
        'myers',
        [mockChunks[0]], // Only equal chunk
        mockStatistics,
        []
      );
      
      const modifyChunks = emptyResult.getChangesByType('modify');
      expect(modifyChunks).toHaveLength(0);
    });

    it('should get additions using helper method', () => {
      const additions = diffResult.getAdditions();
      expect(additions).toHaveLength(1);
      expect(additions[0].operation).toBe('insert');
      expect(additions[0].text).toBe('Inserted text');
    });

    it('should get deletions using helper method', () => {
      const deletions = diffResult.getDeletions();
      expect(deletions).toHaveLength(1);
      expect(deletions[0].operation).toBe('delete');
      expect(deletions[0].text).toBe('Deleted text');
    });

    it('should get modifications using helper method', () => {
      const modifications = diffResult.getModifications();
      expect(modifications).toHaveLength(1);
      expect(modifications[0].operation).toBe('modify');
      expect(modifications[0].text).toBe('Modified text');
    });
  });

  describe('Statistics and Metrics', () => {
    let diffResult: DiffResult;

    beforeEach(() => {
      diffResult = new DiffResult(
        'result-123',
        'comparison-456',
        'myers',
        mockChunks,
        mockStatistics,
        mockChangeSections
      );
    });

    it('should provide accurate statistics', () => {
      expect(diffResult.statistics.totalChanges).toBe(3);
      expect(diffResult.statistics.additions).toBe(1);
      expect(diffResult.statistics.deletions).toBe(1);
      expect(diffResult.statistics.modifications).toBe(1);
      expect(diffResult.statistics.processingTime).toBe(150);
    });

    it('should get overall similarity', () => {
      const similarity = diffResult.getOverallSimilarity();
      expect(similarity).toBe(0.80);
    });

    it('should get total change count', () => {
      const changeCount = diffResult.getTotalChangeCount();
      expect(changeCount).toBe(3);
    });

    it('should get processing time', () => {
      const processingTime = diffResult.getProcessingTime();
      expect(processingTime).toBe(150);
    });

    it('should detect significant changes with default threshold', () => {
      expect(diffResult.hasSignificantChanges()).toBe(true);
    });

    it('should detect significant changes with custom threshold', () => {
      expect(diffResult.hasSignificantChanges(0.15)).toBe(false); // 80% similarity > 85% threshold
      expect(diffResult.hasSignificantChanges(0.25)).toBe(true);  // 80% similarity < 75% threshold
    });

    it('should handle no significant changes', () => {
      const highSimilarityStats = {
        ...mockStatistics,
        similarity: { jaccard: 0.95, levenshtein: 0.95, cosine: 0.95, overall: 0.95 }
      };
      
      const similarResult = new DiffResult(
        'similar-123',
        'comparison-456',
        'myers',
        [mockChunks[0]], // Only equal chunk
        highSimilarityStats,
        []
      );
      
      expect(similarResult.hasSignificantChanges()).toBe(false);
    });
  });

  describe('Change Sections', () => {
    let diffResult: DiffResult;

    beforeEach(() => {
      diffResult = new DiffResult(
        'result-123',
        'comparison-456',
        'myers',
        mockChunks,
        mockStatistics,
        mockChangeSections
      );
    });

    it('should get most changed sections', () => {
      const mostChanged = diffResult.getMostChangedSections();
      expect(mostChanged).toHaveLength(1); // Only one 'high' intensity section
      expect(mostChanged[0].intensity).toBe('high');
      expect(mostChanged[0].changeType).toBe('insert');
    });

    it('should limit most changed sections', () => {
      const limitedSections = diffResult.getMostChangedSections(1);
      expect(limitedSections).toHaveLength(1);
    });

    it('should return empty array when no high intensity sections exist', () => {
      const lowIntensitySections: ChangeSection[] = [
        {
          startLine: 1,
          endLine: 2,
          changeType: 'modify',
          intensity: 'low'
        }
      ];

      const lowIntensityResult = new DiffResult(
        'low-123',
        'comparison-456',
        'myers',
        mockChunks,
        mockStatistics,
        lowIntensitySections
      );

      const mostChanged = lowIntensityResult.getMostChangedSections();
      expect(mostChanged).toHaveLength(0);
    });
  });

  describe('Export Functionality', () => {
    let diffResult: DiffResult;

    beforeEach(() => {
      diffResult = new DiffResult(
        'result-123',
        'comparison-456',
        'semantic',
        mockChunks,
        mockStatistics,
        mockChangeSections
      );
    });

    it('should export summary with key metrics', () => {
      const summary = diffResult.exportSummary();

      expect(summary.id).toBe('result-123');
      expect(summary.algorithm).toBe('semantic');
      expect(summary.totalChanges).toBe(3);
      expect(summary.similarity).toBe(0.80);
      expect(summary.processingTime).toBe(150);
      expect(summary.createdAt).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/); // ISO format
    });

    it('should export to JSON format', () => {
      const jsonExport = diffResult.toJSON();

      expect(jsonExport).toEqual({
        id: 'result-123',
        comparisonId: 'comparison-456',
        algorithm: 'semantic',
        chunks: mockChunks,
        statistics: mockStatistics,
        changeSections: mockChangeSections,
        createdAt: diffResult.createdAt.toISOString(),
        version: '1.0'
      });
    });

    it('should restore from JSON', () => {
      const jsonData = {
        id: 'restored-123',
        comparisonId: 'comparison-789',
        algorithm: 'myers',
        chunks: mockChunks,
        statistics: mockStatistics,
        changeSections: mockChangeSections
      };

      const restoredResult = DiffResult.fromJSON(jsonData);

      expect(restoredResult.id).toBe('restored-123');
      expect(restoredResult.comparisonId).toBe('comparison-789');
      expect(restoredResult.algorithm).toBe('myers');
      expect(restoredResult.chunks).toEqual(mockChunks);
      expect(restoredResult.statistics).toEqual(mockStatistics);
      expect(restoredResult.changeSections).toEqual(mockChangeSections);
    });

    it('should handle JSON restoration without change sections', () => {
      const jsonData = {
        id: 'restored-123',
        comparisonId: 'comparison-789',
        algorithm: 'myers',
        chunks: mockChunks,
        statistics: mockStatistics
        // changeSections missing
      };

      const restoredResult = DiffResult.fromJSON(jsonData);
      expect(restoredResult.changeSections).toEqual([]);
    });
  });

  describe('Edge Cases and Validation', () => {
    it('should handle empty chunks array', () => {
      const emptyStats: DiffStatistics = {
        totalChanges: 0,
        additions: 0,
        deletions: 0,
        modifications: 0,
        charactersAdded: 0,
        charactersDeleted: 0,
        linesAdded: 0,
        linesDeleted: 0,
        similarity: { jaccard: 1, levenshtein: 1, cosine: 1, overall: 1 },
        processingTime: 0
      };

      const emptyResult = new DiffResult(
        'empty-123',
        'comparison-456',
        'myers',
        [],
        emptyStats,
        []
      );

      expect(emptyResult.chunks).toHaveLength(0);
      expect(emptyResult.getAdditions()).toHaveLength(0);
      expect(emptyResult.getDeletions()).toHaveLength(0);
      expect(emptyResult.getModifications()).toHaveLength(0);
      expect(emptyResult.getTotalChangeCount()).toBe(0);
      expect(emptyResult.hasSignificantChanges()).toBe(false);
    });

    it('should handle chunks without optional properties', () => {
      const minimalChunks: DiffChunk[] = [
        {
          operation: 'equal',
          text: 'Simple text'
        },
        {
          operation: 'insert',
          text: 'Added text'
        }
      ];

      const result = new DiffResult(
        'minimal-123',
        'comparison-456',
        'diff-match-patch',
        minimalChunks,
        mockStatistics,
        []
      );

      expect(result.chunks).toHaveLength(2);
      expect(result.getAdditions()).toHaveLength(1);
      expect(result.getChangesByType('equal')).toHaveLength(1);
    });

    it('should handle chunks with metadata', () => {
      const chunksWithMetadata: DiffChunk[] = [
        {
          operation: 'modify',
          text: 'Text with metadata',
          lineNumber: 1,
          metadata: {
            confidence: 0.95,
            source: 'semantic',
            semanticType: 'meaning'
          }
        }
      ];

      const result = new DiffResult(
        'metadata-123',
        'comparison-456',
        'semantic',
        chunksWithMetadata,
        mockStatistics,
        []
      );

      const modifications = result.getModifications();
      expect(modifications).toHaveLength(1);
      expect(modifications[0].metadata?.confidence).toBe(0.95);
      expect(modifications[0].metadata?.source).toBe('semantic');
      expect(modifications[0].metadata?.semanticType).toBe('meaning');
    });
  });

  describe('Performance', () => {
    it('should handle large number of chunks efficiently', () => {
      const largeChunks: DiffChunk[] = [];
      for (let i = 0; i < 10000; i++) {
        largeChunks.push({
          operation: i % 3 === 0 ? 'equal' : i % 3 === 1 ? 'insert' : 'delete',
          text: `Chunk ${i}`,
          lineNumber: i + 1
        });
      }

      const largeStats: DiffStatistics = {
        ...mockStatistics,
        totalChanges: 6667 // Approximately 2/3 of chunks are changes
      };

      const largeResult = new DiffResult(
        'large-123',
        'comparison-456',
        'myers',
        largeChunks,
        largeStats,
        []
      );

      const start = performance.now();
      const insertions = largeResult.getAdditions();
      const deletions = largeResult.getDeletions();
      const equals = largeResult.getChangesByType('equal');
      const end = performance.now();

      expect(insertions.length + deletions.length + equals.length).toBe(10000);
      expect(end - start).toBeLessThan(100); // Should complete in less than 100ms
    });

    it('should efficiently export large results', () => {
      const largeChunks: DiffChunk[] = [];
      for (let i = 0; i < 1000; i++) {
        largeChunks.push({
          operation: 'modify',
          text: `Large chunk content ${i}`.repeat(10),
          lineNumber: i + 1
        });
      }

      const largeResult = new DiffResult(
        'large-export-123',
        'comparison-456',
        'myers',
        largeChunks,
        mockStatistics,
        []
      );

      const start = performance.now();
      const summary = largeResult.exportSummary();
      const json = largeResult.toJSON();
      const end = performance.now();

      expect(summary.id).toBe('large-export-123');
      expect(json).toHaveProperty('chunks');
      expect(end - start).toBeLessThan(50); // Should complete in less than 50ms
    });
  });
}); 