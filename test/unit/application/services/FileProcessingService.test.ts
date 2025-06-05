/**
 * Testes unitários para FileProcessingService
 * Testa orquestração de processamento, eventos e funcionalidades principais
 * 
 * @author ClauseDiff Team
 * @version 1.0.0
 */

import { FileProcessingService } from '../../../../src/application/services/FileProcessingService';
import { IFileProcessor } from '../../../../src/domain/interfaces/IFileProcessor';
import { IStorageProvider } from '../../../../src/domain/interfaces/IStorageProvider';

// Mock básico para IFileProcessor
const mockProcessor: IFileProcessor = {
  canProcess: jest.fn().mockReturnValue(true),
  getCapabilities: jest.fn().mockReturnValue({
    supportedTypes: ['text/plain'],
    maxFileSize: 1024 * 1024,
    supportsMultiplePages: false,
    supportsFormatting: false,
    supportsStreaming: true,
    supportsCancellation: false,
    version: '1.0.0'
  }),
  validate: jest.fn().mockResolvedValue(true),
  process: jest.fn().mockResolvedValue({
    status: 'completed',
    content: 'Mock processed content',
    metadata: {
      name: 'test.txt',
      size: 100,
      type: 'text/plain',
      lastModified: Date.now()
    },
    startTime: Date.now() - 1000,
    endTime: Date.now(),
    duration: 1000
  })
};

// Mock básico para IStorageProvider
const mockStorageProvider: IStorageProvider = {
  upload: jest.fn().mockResolvedValue({
    url: 'https://storage.example.com/file123',
    path: 'uploads/file123.txt',
    size: 100,
    uploadedAt: new Date(),
    metadata: { contentType: 'text/plain' }
  }),
  download: jest.fn(),
  delete: jest.fn(),
  exists: jest.fn(),
  getMetadata: jest.fn(),
  listFiles: jest.fn(),
  getCapabilities: jest.fn().mockReturnValue({
    maxFileSize: 10 * 1024 * 1024,
    supportedTypes: ['text/plain'],
    supportsStreaming: true,
    supportsMetadata: true,
    supportsVersioning: false,
    provider: 'mock'
  })
};

describe('FileProcessingService', () => {
  let service: FileProcessingService;
  let mockFile: File;

  beforeEach(() => {
    // Reset mocks
    jest.clearAllMocks();
    
    // Create service instance
    service = new FileProcessingService();
    
    // Create mock file
    mockFile = new File(['Hello World'], 'test.txt', { type: 'text/plain' });
  });

  describe('Constructor', () => {
    it('should create service instance', () => {
      expect(service).toBeInstanceOf(FileProcessingService);
    });

    it('should initialize with default configuration', () => {
      const config = service.getConfiguration();
      expect(config).toBeDefined();
      expect(config.retryAttempts).toBeGreaterThan(0);
      expect(config.retryDelay).toBeGreaterThan(0);
    });
  });

  describe('Configuration Management', () => {
    it('should update configuration', () => {
      const newConfig = {
        retryAttempts: 5,
        retryDelay: 2000,
        enableParallelProcessing: true,
        maxConcurrentFiles: 10
      };

      service.updateConfiguration(newConfig);
      
      const config = service.getConfiguration();
      expect(config.retryAttempts).toBe(5);
      expect(config.retryDelay).toBe(2000);
      expect(config.enableParallelProcessing).toBe(true);
      expect(config.maxConcurrentFiles).toBe(10);
    });

    it('should merge configuration with existing values', () => {
      const partialConfig = { retryAttempts: 10 };
      
      service.updateConfiguration(partialConfig);
      
      const config = service.getConfiguration();
      expect(config.retryAttempts).toBe(10);
      expect(config.retryDelay).toBeDefined(); // Should maintain existing value
    });
  });

  describe('Event System', () => {
    it('should register and trigger event callbacks', () => {
      const mockCallback = jest.fn();
      
      service.onEvent('processing-started', mockCallback);
      service.processFile(mockFile, mockProcessor);
      
      expect(mockCallback).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'processing-started',
          data: expect.any(Object)
        })
      );
    });

    it('should support multiple callbacks for same event', () => {
      const callback1 = jest.fn();
      const callback2 = jest.fn();
      
      service.onEvent('processing-completed', callback1);
      service.onEvent('processing-completed', callback2);
      
      // Process a file to trigger the event
      service.processFile(mockFile, mockProcessor);
      
      expect(callback1).toHaveBeenCalled();
      expect(callback2).toHaveBeenCalled();
    });

    it('should remove event callbacks', () => {
      const mockCallback = jest.fn();
      
      const unsubscribe = service.onEvent('processing-started', mockCallback);
      unsubscribe();
      
      service.processFile(mockFile, mockProcessor);
      
      expect(mockCallback).not.toHaveBeenCalled();
    });
  });

  describe('File Processing', () => {
    it('should process single file successfully', async () => {
      const result = await service.processFile(mockFile, mockProcessor);
      
      expect(result).toBeDefined();
      expect(mockProcessor.validate).toHaveBeenCalledWith(mockFile);
      expect(mockProcessor.process).toHaveBeenCalledWith(mockFile, undefined);
    });

    it('should process file with options', async () => {
      const options = { extractTextOnly: true, maxCharacters: 1000 };
      
      const result = await service.processFile(mockFile, mockProcessor, options);
      
      expect(mockProcessor.process).toHaveBeenCalledWith(mockFile, options);
    });

    it('should handle processing with storage upload', async () => {
      const result = await service.processFile(mockFile, mockProcessor, {}, mockStorageProvider);
      
      expect(result).toBeDefined();
      expect(mockStorageProvider.upload).toHaveBeenCalled();
    });

    it('should validate file before processing', async () => {
      mockProcessor.validate = jest.fn().mockResolvedValue(false);
      
      await expect(service.processFile(mockFile, mockProcessor))
        .rejects
        .toThrow();
      
      expect(mockProcessor.validate).toHaveBeenCalled();
      expect(mockProcessor.process).not.toHaveBeenCalled();
    });
  });

  describe('Parallel Processing', () => {
    it('should process multiple files in parallel', async () => {
      const files = [
        new File(['Content 1'], 'file1.txt', { type: 'text/plain' }),
        new File(['Content 2'], 'file2.txt', { type: 'text/plain' }),
        new File(['Content 3'], 'file3.txt', { type: 'text/plain' })
      ];

      const results = await service.processFiles(files, mockProcessor);
      
      expect(results).toHaveLength(3);
      expect(mockProcessor.process).toHaveBeenCalledTimes(3);
    });

    it('should respect concurrency limits', async () => {
      service.updateConfiguration({ maxConcurrentFiles: 2 });
      
      const files = Array(5).fill(null).map((_, i) => 
        new File([`Content ${i}`], `file${i}.txt`, { type: 'text/plain' })
      );

      const results = await service.processFiles(files, mockProcessor);
      
      expect(results).toHaveLength(5);
    });

    it('should handle partial failures in parallel processing', async () => {
      const files = [
        new File(['Content 1'], 'file1.txt', { type: 'text/plain' }),
        new File(['Content 2'], 'file2.txt', { type: 'text/plain' })
      ];

      // Make second file fail validation
      mockProcessor.validate = jest.fn()
        .mockResolvedValueOnce(true)
        .mockResolvedValueOnce(false);

      const results = await service.processFiles(files, mockProcessor, {}, mockStorageProvider, {
        continueOnError: true
      });
      
      expect(results).toHaveLength(2);
      expect(results[0].success).toBe(true);
      expect(results[1].success).toBe(false);
    });
  });

  describe('Retry Mechanism', () => {
    it('should retry on failures', async () => {
      service.updateConfiguration({ retryAttempts: 3, retryDelay: 10 });
      
      mockProcessor.process = jest.fn()
        .mockRejectedValueOnce(new Error('Temporary failure'))
        .mockRejectedValueOnce(new Error('Another failure'))
        .mockResolvedValueOnce({
          status: 'completed',
          content: 'Success after retries',
          metadata: { name: 'test.txt', size: 100, type: 'text/plain', lastModified: Date.now() },
          startTime: Date.now() - 1000,
          endTime: Date.now(),
          duration: 1000
        });

      const result = await service.processFile(mockFile, mockProcessor);
      
      expect(result).toBeDefined();
      expect(mockProcessor.process).toHaveBeenCalledTimes(3);
    });

    it('should fail after max retry attempts', async () => {
      service.updateConfiguration({ retryAttempts: 2, retryDelay: 10 });
      
      mockProcessor.process = jest.fn()
        .mockRejectedValue(new Error('Persistent failure'));

      await expect(service.processFile(mockFile, mockProcessor))
        .rejects
        .toThrow('Persistent failure');
      
      expect(mockProcessor.process).toHaveBeenCalledTimes(2);
    });

    it('should use exponential backoff for retry delays', async () => {
      service.updateConfiguration({ retryAttempts: 3, retryDelay: 100 });
      
      const startTime = Date.now();
      
      mockProcessor.process = jest.fn()
        .mockRejectedValueOnce(new Error('Failure 1'))
        .mockRejectedValueOnce(new Error('Failure 2'))
        .mockResolvedValueOnce({
          status: 'completed',
          content: 'Success',
          metadata: { name: 'test.txt', size: 100, type: 'text/plain', lastModified: Date.now() },
          startTime: Date.now() - 1000,
          endTime: Date.now(),
          duration: 1000
        });

      await service.processFile(mockFile, mockProcessor);
      
      const endTime = Date.now();
      const totalTime = endTime - startTime;
      
      // Should have taken at least the base delay time
      expect(totalTime).toBeGreaterThan(100);
    });
  });

  describe('Performance Metrics', () => {
    it('should calculate processing metrics', async () => {
      const result = await service.processFile(mockFile, mockProcessor);
      
      expect(result.metrics).toBeDefined();
      expect(result.metrics.processingDuration).toBeGreaterThan(0);
    });

    it('should track throughput metrics', async () => {
      const files = Array(3).fill(null).map((_, i) => 
        new File([`Content ${i}`], `file${i}.txt`, { type: 'text/plain' })
      );

      const results = await service.processFiles(files, mockProcessor);
      
      const metrics = service.getOverallMetrics();
      expect(metrics.totalFilesProcessed).toBe(3);
      expect(metrics.averageProcessingTime).toBeGreaterThan(0);
    });

    it('should calculate performance rates', async () => {
      const content = 'A'.repeat(5000); // 5000 characters
      const file = new File([content], 'large.txt', { type: 'text/plain' });

      mockProcessor.process = jest.fn().mockResolvedValue({
        status: 'completed',
        content: content,
        metadata: { 
          name: 'large.txt', 
          size: content.length, 
          type: 'text/plain', 
          lastModified: Date.now()
        },
        startTime: Date.now() - 2000,
        endTime: Date.now(),
        duration: 2000
      });

      const result = await service.processFile(file, mockProcessor);
      
      expect(result.metrics.charactersPerSecond).toBeGreaterThan(0);
      expect(result.metrics.bytesPerSecond).toBeGreaterThan(0);
    });
  });

  describe('Error Handling', () => {
    it('should handle processor validation errors', async () => {
      mockProcessor.validate = jest.fn().mockRejectedValue(new Error('Validation failed'));
      
      await expect(service.processFile(mockFile, mockProcessor))
        .rejects
        .toThrow('Validation failed');
    });

    it('should handle processor processing errors', async () => {
      mockProcessor.process = jest.fn().mockRejectedValue(new Error('Processing failed'));
      
      await expect(service.processFile(mockFile, mockProcessor))
        .rejects
        .toThrow('Processing failed');
    });

    it('should handle storage upload errors', async () => {
      mockStorageProvider.upload = jest.fn().mockRejectedValue(new Error('Upload failed'));
      
      // Should still complete processing even if upload fails
      const result = await service.processFile(mockFile, mockProcessor, {}, mockStorageProvider);
      
      expect(result).toBeDefined();
      expect(result.uploadError).toBeDefined();
    });

    it('should handle timeout errors', async () => {
      service.updateConfiguration({ processingTimeout: 100 });
      
      mockProcessor.process = jest.fn().mockImplementation(() => 
        new Promise(resolve => setTimeout(resolve, 200))
      );
      
      await expect(service.processFile(mockFile, mockProcessor))
        .rejects
        .toThrow('timeout');
    });
  });

  describe('Statistics and Monitoring', () => {
    it('should track processing statistics', async () => {
      await service.processFile(mockFile, mockProcessor);
      await service.processFile(mockFile, mockProcessor);
      
      const stats = service.getStatistics();
      expect(stats.totalProcessed).toBe(2);
      expect(stats.successfulProcessing).toBe(2);
      expect(stats.failedProcessing).toBe(0);
    });

    it('should track error statistics', async () => {
      mockProcessor.process = jest.fn()
        .mockResolvedValueOnce({ status: 'completed', content: 'OK' })
        .mockRejectedValueOnce(new Error('Failed'));
      
      await service.processFile(mockFile, mockProcessor);
      
      try {
        await service.processFile(mockFile, mockProcessor);
      } catch (e) {
        // Expected failure
      }
      
      const stats = service.getStatistics();
      expect(stats.totalProcessed).toBe(2);
      expect(stats.successfulProcessing).toBe(1);
      expect(stats.failedProcessing).toBe(1);
    });

    it('should reset statistics', async () => {
      await service.processFile(mockFile, mockProcessor);
      
      let stats = service.getStatistics();
      expect(stats.totalProcessed).toBe(1);
      
      service.resetStatistics();
      
      stats = service.getStatistics();
      expect(stats.totalProcessed).toBe(0);
    });
  });

  describe('Context and Session Management', () => {
    it('should generate processing context', async () => {
      const result = await service.processFile(mockFile, mockProcessor);
      
      expect(result.context).toBeDefined();
      expect(result.context.sessionId).toBeDefined();
      expect(result.context.startedAt).toBeGreaterThan(0);
    });

    it('should use provided context', async () => {
      const customContext = {
        sessionId: 'custom-session-123',
        userId: 'user-456',
        clientIp: '192.168.1.1'
      };
      
      const result = await service.processFile(mockFile, mockProcessor, {}, undefined, customContext);
      
      expect(result.context.sessionId).toBe('custom-session-123');
      expect(result.context.userId).toBe('user-456');
      expect(result.context.clientIp).toBe('192.168.1.1');
    });
  });
}); 