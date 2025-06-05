/**
 * Testes unitários para FileProcessingResult entity
 * Testa todos os métodos e transições de estado seguindo princípios TDD
 * 
 * @author ClauseDiff Team
 * @version 1.0.0
 */

import { FileProcessingResult } from '../../../../src/domain/entities/FileProcessingResult';
import { ProcessingError, ProcessingErrorCodes } from '../../../../src/domain/interfaces/IFileProcessor';

describe('FileProcessingResult', () => {
  const mockFileMetadata = {
    name: 'test-document.pdf',
    size: 1024 * 100, // 100KB
    type: 'application/pdf' as const,
    lastModified: Date.now(),
    hash: 'abc123def456'
  };

  let result: FileProcessingResult;

  beforeEach(() => {
    const mockContext = {
      sessionId: 'test-session',
      startedAt: Date.now(),
      systemVersion: '1.0.0',
      environment: 'development' as const
    };
    
    result = new FileProcessingResult(
      'test-processing-id',
      'pending',
      '',
      mockFileMetadata,
      mockContext
    );
  });

  describe('Constructor', () => {
    it('should create instance with initial state', () => {
      expect(result.id).toBe('test-processing-id');
      expect(result.status).toBe('pending');
      expect(result.metadata).toEqual(mockFileMetadata);
      expect(result.createdAt).toBeGreaterThan(0);
      expect(result.content).toBe('');
    });

    it('should initialize with empty logs and errors', () => {
      expect(result.logs).toHaveLength(0);
      expect(result.errors).toHaveLength(0);
      expect(result.warnings).toHaveLength(0);
    });

    it('should create unique ID for each instance', () => {
      const result1 = new FileProcessingResult('id1', 'text/plain', mockFileMetadata);
      const result2 = new FileProcessingResult('id2', 'text/plain', mockFileMetadata);
      
      expect(result1.getId()).not.toBe(result2.getId());
    });
  });

  describe('Status Management', () => {
    it('should update status and add log entry', () => {
      result.updateStatus('processing');
      
      expect(result.getStatus()).toBe('processing');
      expect(result.getLogs()).toHaveLength(1);
      expect(result.getLogs()[0].message).toContain('Status changed');
      expect(result.getLogs()[0].level).toBe('info');
    });

    it('should handle all valid status transitions', () => {
      const validStatuses = ['pending', 'processing', 'completed', 'failed', 'cancelled'];
      
      validStatuses.forEach(status => {
        result.updateStatus(status as any);
        expect(result.getStatus()).toBe(status);
      });
    });

    it('should add contextual information to status change', () => {
      const context = { step: 'validation', progress: 50 };
      result.updateStatus('processing', context);
      
      const logs = result.getLogs();
      expect(logs[0].context).toEqual(context);
    });
  });

  describe('Validation Results', () => {
    it('should set successful validation result', () => {
      const validationDetails = { 
        size: 'ok', 
        type: 'supported',
        structure: 'valid' 
      };
      
      result.setValidationResult(true, validationDetails);
      
      expect(result.getValidationResult()).toBe(true);
      expect(result.getLogs()).toHaveLength(1);
      expect(result.getLogs()[0].message).toContain('Validation completed');
      expect(result.getLogs()[0].context?.details).toEqual(validationDetails);
    });

    it('should set failed validation result', () => {
      const validationDetails = { 
        error: 'File too large',
        maxSize: 1000000,
        actualSize: 2000000
      };
      
      result.setValidationResult(false, validationDetails);
      
      expect(result.getValidationResult()).toBe(false);
      expect(result.getLogs()).toHaveLength(1);
      expect(result.getLogs()[0].level).toBe('error');
    });

    it('should handle validation result without details', () => {
      result.setValidationResult(true);
      
      expect(result.getValidationResult()).toBe(true);
      expect(result.getLogs()[0].context?.details).toBeUndefined();
    });
  });

  describe('Processing Completion', () => {
    it('should mark as completed with processing result', () => {
      const processingResult = {
        status: 'completed' as const,
        content: 'Extracted text content',
        metadata: mockFileMetadata,
        startTime: Date.now() - 5000,
        endTime: Date.now(),
        duration: 5000,
        pagesProcessed: 10
      };

      result.markAsCompleted(processingResult);
      
      expect(result.getStatus()).toBe('completed');
      expect(result.getProcessingResult()).toEqual(processingResult);
      expect(result.getEndTime()).not.toBeNull();
      expect(result.getDuration()).toBeGreaterThan(0);
    });

    it('should calculate duration correctly', () => {
      const startTime = result.getStartTime().getTime();
      
      // Simulate processing time
      setTimeout(() => {
        result.markAsCompleted({
          status: 'completed',
          content: 'test',
          metadata: mockFileMetadata,
          startTime,
          endTime: Date.now(),
          duration: 100
        });
        
        expect(result.getDuration()).toBeGreaterThan(0);
      }, 10);
    });

    it('should add completion log with metrics', () => {
      const processingResult = {
        status: 'completed' as const,
        content: 'Test content with 100 characters',
        metadata: mockFileMetadata,
        startTime: Date.now() - 1000,
        endTime: Date.now(),
        duration: 1000,
        pagesProcessed: 5
      };

      result.markAsCompleted(processingResult);
      
      const logs = result.getLogs();
      const completionLog = logs.find(log => log.message.includes('Processing completed'));
      
      expect(completionLog).toBeDefined();
      expect(completionLog?.context?.metrics).toBeDefined();
      expect(completionLog?.context?.metrics.contentLength).toBe(processingResult.content.length);
      expect(completionLog?.context?.metrics.pagesProcessed).toBe(5);
    });
  });

  describe('Error Handling', () => {
    it('should add processing error', () => {
      const error = new ProcessingError(
        'Processing failed',
        ProcessingErrorCodes.EXTRACTION_FAILED,
        'application/pdf'
      );

      result.addError(error);
      
      expect(result.getErrors()).toHaveLength(1);
      expect(result.getErrors()[0]).toBe(error);
      expect(result.getLogs()).toHaveLength(1);
      expect(result.getLogs()[0].level).toBe('error');
    });

    it('should add multiple errors', () => {
      const error1 = new ProcessingError('Error 1', ProcessingErrorCodes.FILE_TOO_LARGE);
      const error2 = new ProcessingError('Error 2', ProcessingErrorCodes.PROCESSING_TIMEOUT);

      result.addError(error1);
      result.addError(error2);
      
      expect(result.getErrors()).toHaveLength(2);
      expect(result.getErrors()).toContain(error1);
      expect(result.getErrors()).toContain(error2);
    });

    it('should mark as failed when critical error added', () => {
      const criticalError = new ProcessingError(
        'Critical failure',
        ProcessingErrorCodes.FILE_CORRUPTED
      );

      result.addError(criticalError, true);
      
      expect(result.getStatus()).toBe('failed');
      expect(result.getEndTime()).not.toBeNull();
    });

    it('should not change status for non-critical errors', () => {
      result.updateStatus('processing');
      
      const nonCriticalError = new ProcessingError(
        'Minor issue',
        ProcessingErrorCodes.EXTRACTION_FAILED
      );

      result.addError(nonCriticalError, false);
      
      expect(result.getStatus()).toBe('processing');
    });
  });

  describe('Warning Management', () => {
    it('should add warning message', () => {
      const warning = 'File contains unusual formatting';
      const context = { page: 5, element: 'table' };

      result.addWarning(warning, context);
      
      expect(result.getWarnings()).toHaveLength(1);
      expect(result.getWarnings()[0]).toBe(warning);
      expect(result.getLogs()).toHaveLength(1);
      expect(result.getLogs()[0].level).toBe('warn');
      expect(result.getLogs()[0].context).toEqual(context);
    });

    it('should add multiple warnings', () => {
      result.addWarning('Warning 1');
      result.addWarning('Warning 2');
      
      expect(result.getWarnings()).toHaveLength(2);
      expect(result.getWarnings()).toContain('Warning 1');
      expect(result.getWarnings()).toContain('Warning 2');
    });
  });

  describe('Logging System', () => {
    it('should add custom log entry', () => {
      const message = 'Custom processing step';
      const level = 'debug';
      const context = { step: 'text-extraction', progress: 75 };

      result.addLog(message, level, context);
      
      const logs = result.getLogs();
      expect(logs).toHaveLength(1);
      expect(logs[0].message).toBe(message);
      expect(logs[0].level).toBe(level);
      expect(logs[0].context).toEqual(context);
      expect(logs[0].timestamp).toBeInstanceOf(Date);
    });

    it('should maintain chronological order of logs', () => {
      result.addLog('First log', 'info');
      result.addLog('Second log', 'info');
      result.addLog('Third log', 'info');
      
      const logs = result.getLogs();
      expect(logs).toHaveLength(3);
      expect(logs[0].message).toBe('First log');
      expect(logs[1].message).toBe('Second log');
      expect(logs[2].message).toBe('Third log');
      
      // Verify timestamps are in order
      expect(logs[0].timestamp.getTime()).toBeLessThanOrEqual(logs[1].timestamp.getTime());
      expect(logs[1].timestamp.getTime()).toBeLessThanOrEqual(logs[2].timestamp.getTime());
    });

    it('should generate unique sequence numbers for logs', () => {
      result.addLog('Log 1', 'info');
      result.addLog('Log 2', 'info');
      result.addLog('Log 3', 'info');
      
      const logs = result.getLogs();
      const sequenceNumbers = logs.map(log => log.sequenceNumber);
      
      expect(sequenceNumbers).toEqual([1, 2, 3]);
    });
  });

  describe('Metrics and Performance', () => {
    it('should track upload metrics', () => {
      const uploadResult = {
        url: 'https://storage.example.com/file123',
        size: 1024,
        duration: 2500,
        provider: 'supabase'
      };

      result.setUploadResult(uploadResult);
      
      expect(result.getUploadResult()).toEqual(uploadResult);
      expect(result.getLogs()).toHaveLength(1);
      expect(result.getLogs()[0].message).toContain('Upload completed');
    });

    it('should calculate processing metrics', () => {
      // Simulate processing
      result.updateStatus('processing');
      
      const processingResult = {
        status: 'completed' as const,
        content: 'A'.repeat(5000), // 5000 characters
        metadata: mockFileMetadata,
        startTime: Date.now() - 3000,
        endTime: Date.now(),
        duration: 3000,
        pagesProcessed: 10
      };

      result.markAsCompleted(processingResult);
      
      const metrics = result.getPerformanceMetrics();
      expect(metrics.processingDuration).toBe(3000);
      expect(metrics.charactersPerSecond).toBeCloseTo(5000 / 3, 1);
      expect(metrics.pagesPerMinute).toBeCloseTo(10 / (3000 / 60000), 1);
    });

    it('should handle metrics with zero duration', () => {
      const processingResult = {
        status: 'completed' as const,
        content: 'test',
        metadata: mockFileMetadata,
        startTime: Date.now(),
        endTime: Date.now(),
        duration: 0
      };

      result.markAsCompleted(processingResult);
      
      const metrics = result.getPerformanceMetrics();
      expect(metrics.charactersPerSecond).toBe(0);
      expect(metrics.pagesPerMinute).toBe(0);
    });
  });

  describe('Serialization', () => {
    it('should serialize to JSON correctly', () => {
      result.updateStatus('processing');
      result.addWarning('Test warning');
      result.addLog('Custom log', 'debug', { key: 'value' });

      const json = result.toJSON();
      
      expect(json.id).toBe('test-processing-id');
      expect(json.fileType).toBe('application/pdf');
      expect(json.status).toBe('processing');
      expect(json.fileMetadata).toEqual(mockFileMetadata);
      expect(json.logs).toHaveLength(3); // status change + warning + custom log
      expect(json.warnings).toHaveLength(1);
      expect(json.errors).toHaveLength(0);
    });

    it('should handle complex serialization with all data', () => {
      // Setup complex state
      result.updateStatus('processing');
      result.setValidationResult(true, { validated: true });
      
      const error = new ProcessingError('Test error', ProcessingErrorCodes.EXTRACTION_FAILED);
      result.addError(error);
      result.addWarning('Test warning');
      
      const processingResult = {
        status: 'completed' as const,
        content: 'Extracted content',
        metadata: mockFileMetadata,
        startTime: Date.now() - 1000,
        endTime: Date.now(),
        duration: 1000
      };
      result.markAsCompleted(processingResult);

      const json = result.toJSON();
      
      expect(json).toHaveProperty('id');
      expect(json).toHaveProperty('status');
      expect(json).toHaveProperty('logs');
      expect(json).toHaveProperty('errors');
      expect(json).toHaveProperty('warnings');
      expect(json).toHaveProperty('processingResult');
      expect(json).toHaveProperty('validationResult');
      expect(json).toHaveProperty('performanceMetrics');
    });

    it('should create instance from JSON', () => {
      const originalResult = new FileProcessingResult('original-id', 'text/plain', mockFileMetadata);
      originalResult.updateStatus('completed');
      originalResult.addWarning('Original warning');

      const json = originalResult.toJSON();
      const restoredResult = FileProcessingResult.fromJSON(json);
      
      expect(restoredResult.getId()).toBe(originalResult.getId());
      expect(restoredResult.getStatus()).toBe(originalResult.getStatus());
      expect(restoredResult.getWarnings()).toEqual(originalResult.getWarnings());
      expect(restoredResult.getLogs()).toHaveLength(originalResult.getLogs().length);
    });
  });

  describe('Edge Cases', () => {
    it('should handle null/undefined values gracefully', () => {
      expect(() => result.addWarning(null as any)).not.toThrow();
      expect(() => result.addWarning(undefined as any)).not.toThrow();
      expect(() => result.setValidationResult(true, null)).not.toThrow();
    });

    it('should handle empty strings', () => {
      result.addWarning('');
      result.addLog('', 'info');
      
      expect(result.getWarnings()).toContain('');
      expect(result.getLogs().some(log => log.message === '')).toBe(true);
    });

    it('should handle very large processing results', () => {
      const largeContent = 'A'.repeat(10 * 1024 * 1024); // 10MB string
      
      const processingResult = {
        status: 'completed' as const,
        content: largeContent,
        metadata: mockFileMetadata,
        startTime: Date.now() - 1000,
        endTime: Date.now(),
        duration: 1000
      };

      expect(() => result.markAsCompleted(processingResult)).not.toThrow();
      expect(result.getProcessingResult()?.content).toBe(largeContent);
    });
  });

  describe('State Consistency', () => {
    it('should maintain consistent state after multiple operations', () => {
      result.updateStatus('processing');
      result.setValidationResult(true);
      result.addWarning('Warning 1');
      result.addError(new ProcessingError('Error 1', ProcessingErrorCodes.EXTRACTION_FAILED));
      result.addWarning('Warning 2');
      
      expect(result.getStatus()).toBe('processing');
      expect(result.getValidationResult()).toBe(true);
      expect(result.getWarnings()).toHaveLength(2);
      expect(result.getErrors()).toHaveLength(1);
      expect(result.getLogs().length).toBeGreaterThan(0);
    });

    it('should handle concurrent-like operations', () => {
      // Simulate rapid operations
      for (let i = 0; i < 100; i++) {
        result.addLog(`Log ${i}`, 'info');
      }
      
      expect(result.getLogs()).toHaveLength(100);
      
      // Verify sequence numbers are correct
      const sequenceNumbers = result.getLogs().map(log => log.sequenceNumber);
      for (let i = 0; i < sequenceNumbers.length; i++) {
        expect(sequenceNumbers[i]).toBe(i + 1);
      }
    });
  });
}); 