import { DocumentComparison, DocumentMetadata, ComparisonConfig } from '../../../../src/domain/entities/DocumentComparison';

describe('DocumentComparison Entity', () => {
  const mockOriginalDoc: DocumentMetadata = {
    name: 'original.docx',
    size: 1024000, // 1MB
    type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    lastModified: new Date('2023-01-01')
  };

  const mockModifiedDoc: DocumentMetadata = {
    name: 'modified.docx',
    size: 1050000, // 1.05MB
    type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    lastModified: new Date('2023-01-02')
  };

  describe('Constructor and Basic Properties', () => {
    it('should create a comparison with required parameters', () => {
      const comparison = new DocumentComparison(
        'comp-123',
        mockOriginalDoc,
        mockModifiedDoc
      );

      expect(comparison.id).toBe('comp-123');
      expect(comparison.originalDocument).toEqual(mockOriginalDoc);
      expect(comparison.modifiedDocument).toEqual(mockModifiedDoc);
      expect(comparison.config.algorithm).toBe('diff-match-patch');
      expect(comparison.status).toBe('pending');
      expect(comparison.progress).toBe(0);
      expect(comparison.createdAt).toBeInstanceOf(Date);
      expect(comparison.error).toBeUndefined();
    });

    it('should create comparison with custom config', () => {
      const config: ComparisonConfig = {
        algorithm: 'myers',
        chunkSize: 1000,
        enableCache: true,
        timeout: 30000
      };

      const comparison = new DocumentComparison(
        'comp-123',
        mockOriginalDoc,
        mockModifiedDoc,
        config
      );

      expect(comparison.config).toEqual(config);
    });

    it('should use default config when not provided', () => {
      const comparison = new DocumentComparison(
        'comp-123',
        mockOriginalDoc,
        mockModifiedDoc
      );

      expect(comparison.config.algorithm).toBe('diff-match-patch');
    });
  });

  describe('Status Management', () => {
    let comparison: DocumentComparison;

    beforeEach(() => {
      comparison = new DocumentComparison(
        'comp-123',
        mockOriginalDoc,
        mockModifiedDoc
      );
    });

    it('should start in pending status', () => {
      expect(comparison.status).toBe('pending');
    });

    it('should update status correctly', () => {
      comparison.updateStatus('processing');
      expect(comparison.status).toBe('processing');

      comparison.updateStatus('completed');
      expect(comparison.status).toBe('completed');

      comparison.updateStatus('failed');
      expect(comparison.status).toBe('failed');
    });

    it('should check completion status', () => {
      expect(comparison.isCompleted()).toBe(false);
      
      comparison.updateStatus('completed');
      expect(comparison.isCompleted()).toBe(true);
    });

    it('should check failed status', () => {
      expect(comparison.isFailed()).toBe(false);
      
      comparison.updateStatus('failed');
      expect(comparison.isFailed()).toBe(true);
    });
  });

  describe('Progress Tracking', () => {
    let comparison: DocumentComparison;

    beforeEach(() => {
      comparison = new DocumentComparison(
        'comp-123',
        mockOriginalDoc,
        mockModifiedDoc
      );
    });

    it('should start with 0% progress', () => {
      expect(comparison.progress).toBe(0);
    });

    it('should update progress with valid values', () => {
      comparison.updateProgress(25);
      expect(comparison.progress).toBe(25);

      comparison.updateProgress(50);
      expect(comparison.progress).toBe(50);

      comparison.updateProgress(100);
      expect(comparison.progress).toBe(100);
    });

    it('should throw error for invalid progress values', () => {
      expect(() => {
        comparison.updateProgress(-1);
      }).toThrow('Progress must be between 0 and 100');

      expect(() => {
        comparison.updateProgress(101);
      }).toThrow('Progress must be between 0 and 100');
    });

    it('should automatically complete when progress reaches 100 during processing', () => {
      comparison.updateStatus('processing');
      comparison.updateProgress(100);
      
      expect(comparison.status).toBe('completed');
    });

    it('should not auto-complete when not in processing status', () => {
      comparison.updateProgress(100);
      expect(comparison.status).toBe('pending'); // Still pending, not auto-completed
    });
  });

  describe('Error Handling', () => {
    let comparison: DocumentComparison;

    beforeEach(() => {
      comparison = new DocumentComparison(
        'comp-123',
        mockOriginalDoc,
        mockModifiedDoc
      );
    });

    it('should set error message and failed status', () => {
      comparison.setError('Falha na comparação');

      expect(comparison.status).toBe('failed');
      expect(comparison.error).toBe('Falha na comparação');
      expect(comparison.isFailed()).toBe(true);
    });
  });

  describe('Document Validation', () => {
    it('should validate documents with correct size and type', () => {
      const comparison = new DocumentComparison(
        'comp-123',
        mockOriginalDoc,
        mockModifiedDoc
      );

      expect(comparison.validateDocuments()).toBe(true);
    });

    it('should reject documents exceeding size limit', () => {
      const largeDoc: DocumentMetadata = {
        name: 'large.docx',
        size: 6 * 1024 * 1024, // 6MB (exceeds 5MB limit)
        type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
      };

      const comparison = new DocumentComparison(
        'comp-123',
        largeDoc,
        mockModifiedDoc
      );

      expect(comparison.validateDocuments()).toBe(false);
    });

    it('should reject documents with invalid type', () => {
      const invalidTypeDoc: DocumentMetadata = {
        name: 'document.pdf',
        size: 1024000,
        type: 'application/pdf'
      };

      const comparison = new DocumentComparison(
        'comp-123',
        invalidTypeDoc,
        mockModifiedDoc
      );

      expect(comparison.validateDocuments()).toBe(false);
    });

    it('should validate edge case - exactly 5MB documents', () => {
      const exactSizeDoc: DocumentMetadata = {
        name: 'exact.docx',
        size: 5 * 1024 * 1024, // Exactly 5MB
        type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
      };

      const comparison = new DocumentComparison(
        'comp-123',
        exactSizeDoc,
        exactSizeDoc
      );

      expect(comparison.validateDocuments()).toBe(true);
    });
  });

  describe('Duration Calculation', () => {
    let comparison: DocumentComparison;

    beforeEach(() => {
      comparison = new DocumentComparison(
        'comp-123',
        mockOriginalDoc,
        mockModifiedDoc
      );
    });

    it('should return null for incomplete comparisons', () => {
      expect(comparison.getDuration()).toBeNull();
      
      comparison.updateStatus('processing');
      expect(comparison.getDuration()).toBeNull();
      
      comparison.updateStatus('failed');
      expect(comparison.getDuration()).toBeNull();
    });

    it('should calculate duration for completed comparisons', () => {
      comparison.updateStatus('completed');
      const duration = comparison.getDuration();
      
      expect(duration).not.toBeNull();
      expect(typeof duration).toBe('number');
      expect(duration!).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Algorithm Configuration', () => {
    it('should support diff-match-patch algorithm', () => {
      const config: ComparisonConfig = { algorithm: 'diff-match-patch' };
      const comparison = new DocumentComparison(
        'comp-123',
        mockOriginalDoc,
        mockModifiedDoc,
        config
      );

      expect(comparison.config.algorithm).toBe('diff-match-patch');
    });

    it('should support myers algorithm', () => {
      const config: ComparisonConfig = { algorithm: 'myers' };
      const comparison = new DocumentComparison(
        'comp-123',
        mockOriginalDoc,
        mockModifiedDoc,
        config
      );

      expect(comparison.config.algorithm).toBe('myers');
    });

    it('should support semantic algorithm', () => {
      const config: ComparisonConfig = { algorithm: 'semantic' };
      const comparison = new DocumentComparison(
        'comp-123',
        mockOriginalDoc,
        mockModifiedDoc,
        config
      );

      expect(comparison.config.algorithm).toBe('semantic');
    });
  });

  describe('Configuration Options', () => {
    it('should handle optional configuration parameters', () => {
      const config: ComparisonConfig = {
        algorithm: 'myers',
        chunkSize: 2000,
        enableCache: false,
        timeout: 60000
      };

      const comparison = new DocumentComparison(
        'comp-123',
        mockOriginalDoc,
        mockModifiedDoc,
        config
      );

      expect(comparison.config.chunkSize).toBe(2000);
      expect(comparison.config.enableCache).toBe(false);
      expect(comparison.config.timeout).toBe(60000);
    });

    it('should handle partial configuration', () => {
      const config: ComparisonConfig = {
        algorithm: 'semantic',
        enableCache: true
        // chunkSize and timeout not specified
      };

      const comparison = new DocumentComparison(
        'comp-123',
        mockOriginalDoc,
        mockModifiedDoc,
        config
      );

      expect(comparison.config.algorithm).toBe('semantic');
      expect(comparison.config.enableCache).toBe(true);
      expect(comparison.config.chunkSize).toBeUndefined();
      expect(comparison.config.timeout).toBeUndefined();
    });
  });

  describe('Integration Scenarios', () => {
    it('should handle complete comparison workflow', () => {
      const comparison = new DocumentComparison(
        'comp-123',
        mockOriginalDoc,
        mockModifiedDoc,
        { algorithm: 'myers', enableCache: true }
      );

      // Initial state
      expect(comparison.isCompleted()).toBe(false);
      expect(comparison.isFailed()).toBe(false);

      // Start processing
      comparison.updateStatus('processing');
      expect(comparison.status).toBe('processing');

      // Update progress
      comparison.updateProgress(50);
      expect(comparison.progress).toBe(50);
      expect(comparison.status).toBe('processing'); // Still processing

      // Complete
      comparison.updateProgress(100);
      expect(comparison.isCompleted()).toBe(true);
      expect(comparison.getDuration()).not.toBeNull();
    });

    it('should handle failed comparison workflow', () => {
      const comparison = new DocumentComparison(
        'comp-123',
        mockOriginalDoc,
        mockModifiedDoc
      );

      comparison.updateStatus('processing');
      comparison.updateProgress(30);
      
      // Simulate error
      comparison.setError('Network timeout');
      
      expect(comparison.isFailed()).toBe(true);
      expect(comparison.error).toBe('Network timeout');
      expect(comparison.progress).toBe(30); // Progress preserved
      expect(comparison.getDuration()).toBeNull(); // No duration for failed
    });
  });
}); 