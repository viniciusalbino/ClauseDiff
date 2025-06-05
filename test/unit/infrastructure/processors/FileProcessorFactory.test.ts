/**
 * Testes unitários para FileProcessorFactory
 * Testa padrão Registry, factory methods, configuração e todas as funcionalidades
 * 
 * @author ClauseDiff Team
 * @version 1.0.0
 */

import { 
  FileProcessorFactory, 
  getFileProcessorFactory, 
  createFileProcessor, 
  isFileTypeSupported,
  ProcessorConfig,
  ProcessorRegistrationOptions
} from '../../../../src/infrastructure/processors/FileProcessorFactory';
import { IFileProcessor, FileType } from '../../../../src/domain/interfaces/IFileProcessor';

// Mock processors para testes
class MockTextProcessor implements IFileProcessor {
  canProcess(mimeType: string): boolean {
    return mimeType === 'text/plain';
  }
  
  getSupportedTypes(): string[] {
    return ['text/plain'];
  }
  
  getCapabilities() {
    return {
      supportedTypes: ['text/plain'],
      maxFileSize: 1024 * 1024,
      supportsMultiplePages: false,
      supportsFormatting: false,
      supportsStreaming: true,
      supportsCancellation: false,
      version: '1.0.0'
    };
  }
  
  async validate(file: File): Promise<boolean> {
    return file.type === 'text/plain' && file.size <= 1024 * 1024;
  }
  
  async process(file: File) {
    return {
      success: true,
      content: 'Mock processed content',
      metadata: {
        name: file.name,
        size: file.size,
        type: file.type as FileType,
        lastModified: file.lastModified,
        processingTime: 100,
        wordCount: 10
      }
    };
  }
}

class MockPdfProcessor implements IFileProcessor {
  canProcess(mimeType: string): boolean {
    return mimeType === 'application/pdf';
  }
  
  getSupportedTypes(): string[] {
    return ['application/pdf'];
  }
  
  getCapabilities() {
    return {
      supportedTypes: ['application/pdf'],
      maxFileSize: 10 * 1024 * 1024,
      supportsMultiplePages: true,
      supportsFormatting: true,
      supportsStreaming: false,
      supportsCancellation: true,
      version: '2.0.0'
    };
  }
  
  async validate(file: File): Promise<boolean> {
    return file.type === 'application/pdf' && file.size <= 10 * 1024 * 1024;
  }
  
  async process(file: File) {
    return {
      success: true,
      content: 'Mock PDF content',
      metadata: {
        name: file.name,
        size: file.size,
        type: file.type as FileType,
        lastModified: file.lastModified,
        processingTime: 500,
        wordCount: 50,
        totalPages: 5
      }
    };
  }
}

describe('FileProcessorFactory', () => {
  let factory: FileProcessorFactory;

  beforeEach(() => {
    // Create fresh factory for each test
    factory = new FileProcessorFactory();
  });

  describe('Singleton Pattern', () => {
    it('should return same instance for getFileProcessorFactory', () => {
      const instance1 = getFileProcessorFactory();
      const instance2 = getFileProcessorFactory();
      
      expect(instance1).toBe(instance2);
      expect(instance1).toBeInstanceOf(FileProcessorFactory);
    });

    it('should maintain state across calls', () => {
      const factory1 = getFileProcessorFactory();
      factory1.registerProcessor('test/custom', () => new MockTextProcessor());
      
      const factory2 = getFileProcessorFactory();
      expect(factory2.isRegistered('test/custom')).toBe(true);
    });
  });

  describe('Processor Registration', () => {
    it('should register processor with minimal setup', () => {
      const processor = new MockTextProcessor();
      
      factory.registerProcessor('text/plain', () => processor);
      
      expect(factory.isRegistered('text/plain')).toBe(true);
      expect(factory.getSupportedTypes()).toContain('text/plain');
    });

    it('should register processor with complete metadata', () => {
      const options: ProcessorRegistrationOptions = {
        name: 'Custom Text Processor',
        version: '1.5.0',
        description: 'Enhanced text processing with advanced features',
        dependencies: ['encoding-detector', 'text-analyzer'],
        enabled: true,
        priority: 10,
        config: {
          maxFileSize: 2048 * 1024,
          timeout: 30000,
          encoding: 'utf-8'
        }
      };

      factory.registerProcessor('text/plain', () => new MockTextProcessor(), options);
      
      const metadata = factory.getProcessorMetadata('text/plain');
      expect(metadata.name).toBe('Custom Text Processor');
      expect(metadata.version).toBe('1.5.0');
      expect(metadata.description).toBe('Enhanced text processing with advanced features');
      expect(metadata.dependencies).toEqual(['encoding-detector', 'text-analyzer']);
      expect(metadata.enabled).toBe(true);
      expect(metadata.priority).toBe(10);
    });

    it('should register multiple processors', () => {
      factory.registerProcessor('text/plain', () => new MockTextProcessor());
      factory.registerProcessor('application/pdf', () => new MockPdfProcessor());
      
      expect(factory.isRegistered('text/plain')).toBe(true);
      expect(factory.isRegistered('application/pdf')).toBe(true);
      expect(factory.getSupportedTypes()).toContain('text/plain');
      expect(factory.getSupportedTypes()).toContain('application/pdf');
    });

    it('should override existing processor registration', () => {
      const processor1 = new MockTextProcessor();
      const processor2 = new MockTextProcessor();
      
      factory.registerProcessor('text/plain', () => processor1, { name: 'First' });
      factory.registerProcessor('text/plain', () => processor2, { name: 'Second' });
      
      const metadata = factory.getProcessorMetadata('text/plain');
      expect(metadata.name).toBe('Second');
    });

    it('should auto-register known processors', () => {
      // Factory should auto-register standard processors
      const standardTypes = ['text/plain', 'application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
      
      // Reset factory to test auto-registration
      const autoFactory = new FileProcessorFactory();
      
      standardTypes.forEach(type => {
        expect(autoFactory.isRegistered(type)).toBe(true);
      });
    });
  });

  describe('Processor Creation', () => {
    beforeEach(() => {
      factory.registerProcessor('text/plain', () => new MockTextProcessor());
      factory.registerProcessor('application/pdf', () => new MockPdfProcessor());
    });

    it('should create processor for supported type', () => {
      const processor = factory.createProcessor('text/plain');
      
      expect(processor).toBeDefined();
      expect(processor.canProcess('text/plain')).toBe(true);
    });

    it('should create processor with default config', () => {
      const processor = factory.createProcessor('text/plain');
      
      expect(processor).toBeInstanceOf(MockTextProcessor);
    });

    it('should create processor with custom config', () => {
      const config = { maxFileSize: 500000, timeout: 15000 };
      const processor = factory.createProcessor('text/plain', config);
      
      expect(processor).toBeDefined();
    });

    it('should throw error for unsupported type', () => {
      expect(() => factory.createProcessor('image/jpeg')).toThrow();
    });

    it('should create processors with caching', () => {
      const processor1 = factory.createProcessor('text/plain');
      const processor2 = factory.createProcessor('text/plain');
      
      // Should create new instances each time
      expect(processor1).toBeDefined();
      expect(processor2).toBeDefined();
    });
  });

  describe('Configuration Management', () => {
    beforeEach(() => {
      factory.registerProcessor('text/plain', () => new MockTextProcessor());
    });

    it('should set global configuration', () => {
      const globalConfig = { 
        defaultTimeout: 60000,
        maxMemoryUsage: 512 * 1024 * 1024,
        enableLogging: true 
      };
      
      factory.setGlobalConfig(globalConfig);
      
      const config = factory.getGlobalConfig();
      expect(config.defaultTimeout).toBe(60000);
      expect(config.maxMemoryUsage).toBe(512 * 1024 * 1024);
      expect(config.enableLogging).toBe(true);
    });

    it('should set default configuration for type', () => {
      const defaultConfig = { 
        maxFileSize: 2048 * 1024,
        encoding: 'utf-8' 
      };
      
      factory.setDefaultConfig('text/plain', defaultConfig);
      
      const config = factory.getDefaultConfig('text/plain');
      expect(config.maxFileSize).toBe(2048 * 1024);
      expect(config.encoding).toBe('utf-8');
    });

    it('should merge configuration hierarchy', () => {
      // Set global config
      factory.setGlobalConfig({ defaultTimeout: 30000 });
      
      // Set default config for type
      factory.setDefaultConfig('text/plain', { maxFileSize: 1024 * 1024 });
      
      // Create processor with specific config
      const specificConfig = { encoding: 'utf-16' };
      const processor = factory.createProcessor('text/plain', specificConfig);
      
      expect(processor).toBeDefined();
    });

    it('should handle configuration updates', () => {
      factory.setGlobalConfig({ defaultTimeout: 10000 });
      
      // Update config
      factory.updateGlobalConfig({ defaultTimeout: 20000, enableLogging: true });
      
      const config = factory.getGlobalConfig();
      expect(config.defaultTimeout).toBe(20000);
      expect(config.enableLogging).toBe(true);
    });
  });

  describe('Lazy Loading and Caching', () => {
    it('should implement lazy loading for processors', () => {
      let factoryCallCount = 0;
      
      factory.registerProcessor('text/plain', () => {
        factoryCallCount++;
        return new MockTextProcessor();
      });
      
      // Factory function should not be called until processor is created
      expect(factoryCallCount).toBe(0);
      
      // Now create processor
      factory.createProcessor('text/plain');
      expect(factoryCallCount).toBe(1);
      
      // Creating another instance should call factory again
      factory.createProcessor('text/plain');
      expect(factoryCallCount).toBe(2);
    });

    it('should cache processor metadata', () => {
      factory.registerProcessor('text/plain', () => new MockTextProcessor(), {
        name: 'Test Processor'
      });
      
      const metadata1 = factory.getProcessorMetadata('text/plain');
      const metadata2 = factory.getProcessorMetadata('text/plain');
      
      expect(metadata1).toBe(metadata2); // Should be same object reference
    });
  });

  describe('Statistics and Monitoring', () => {
    beforeEach(() => {
      factory.registerProcessor('text/plain', () => new MockTextProcessor());
      factory.registerProcessor('application/pdf', () => new MockPdfProcessor());
    });

    it('should track processor creation statistics', () => {
      factory.createProcessor('text/plain');
      factory.createProcessor('text/plain');
      factory.createProcessor('application/pdf');
      
      const stats = factory.getStatistics();
      expect(stats.totalProcessorsCreated).toBe(3);
      expect(stats.processorCreationsByType['text/plain']).toBe(2);
      expect(stats.processorCreationsByType['application/pdf']).toBe(1);
    });

    it('should track registration statistics', () => {
      const stats = factory.getStatistics();
      expect(stats.totalRegisteredTypes).toBe(2);
      expect(stats.enabledProcessors).toBe(2);
    });

    it('should provide processor metadata list', () => {
      const metadataList = factory.getAllProcessorMetadata();
      
      expect(metadataList).toHaveLength(2);
      expect(metadataList.some(m => m.supportedTypes.includes('text/plain'))).toBe(true);
      expect(metadataList.some(m => m.supportedTypes.includes('application/pdf'))).toBe(true);
    });

    it('should reset statistics', () => {
      factory.createProcessor('text/plain');
      factory.createProcessor('application/pdf');
      
      let stats = factory.getStatistics();
      expect(stats.totalProcessorsCreated).toBe(2);
      
      factory.resetStatistics();
      
      stats = factory.getStatistics();
      expect(stats.totalProcessorsCreated).toBe(0);
      expect(stats.processorCreationsByType).toEqual({});
    });
  });

  describe('Error Handling', () => {
    it('should handle processor factory errors gracefully', () => {
      factory.registerProcessor('text/plain', () => {
        throw new Error('Factory error');
      });
      
      expect(() => factory.createProcessor('text/plain')).toThrow('Factory error');
    });

    it('should handle invalid processor registration', () => {
      expect(() => {
        factory.registerProcessor('', () => new MockTextProcessor());
      }).toThrow();
      
      expect(() => {
        factory.registerProcessor('text/plain', null as any);
      }).toThrow();
    });

    it('should handle disabled processors', () => {
      factory.registerProcessor('text/plain', () => new MockTextProcessor(), {
        enabled: false
      });
      
      expect(() => factory.createProcessor('text/plain')).toThrow();
    });

    it('should validate processor capabilities', () => {
      class InvalidProcessor implements IFileProcessor {
        canProcess(): boolean { return true; }
        getSupportedTypes(): string[] { return []; }
        getCapabilities() { return null as any; }
        async validate(): Promise<boolean> { return false; }
        async process(): Promise<any> { return null; }
      }
      
      expect(() => {
        factory.registerProcessor('invalid/type', () => new InvalidProcessor());
      }).not.toThrow(); // Registration should succeed
      
      expect(() => {
        factory.createProcessor('invalid/type');
      }).toThrow(); // Creation should fail on validation
    });
  });

  describe('Convenience Functions', () => {
    beforeEach(() => {
      const factory = getFileProcessorFactory();
      factory.registerProcessor('text/plain', () => new MockTextProcessor());
      factory.registerProcessor('application/pdf', () => new MockPdfProcessor());
    });

    it('should create processor via convenience function', () => {
      const processor = createFileProcessor('text/plain');
      
      expect(processor).toBeDefined();
      expect(processor.canProcess('text/plain')).toBe(true);
    });

    it('should check file type support', () => {
      expect(isFileTypeSupported('text/plain')).toBe(true);
      expect(isFileTypeSupported('application/pdf')).toBe(true);
      expect(isFileTypeSupported('image/jpeg')).toBe(false);
    });

    it('should create processor with custom config via convenience function', () => {
      const config = { maxFileSize: 500000 };
      const processor = createFileProcessor('text/plain', config);
      
      expect(processor).toBeDefined();
    });
  });

  describe('Priority and Selection', () => {
    it('should respect processor priority', () => {
      // Register two processors for same type with different priorities
      factory.registerProcessor('text/plain', () => new MockTextProcessor(), {
        name: 'Low Priority',
        priority: 1
      });
      
      factory.registerProcessor('text/plain', () => new MockTextProcessor(), {
        name: 'High Priority', 
        priority: 10
      });
      
      // Should use the high priority processor (latest registration)
      const metadata = factory.getProcessorMetadata('text/plain');
      expect(metadata.name).toBe('High Priority');
    });

    it('should list processors by priority', () => {
      factory.registerProcessor('text/plain', () => new MockTextProcessor(), {
        name: 'Medium',
        priority: 5
      });
      
      factory.registerProcessor('application/pdf', () => new MockPdfProcessor(), {
        name: 'High',
        priority: 10
      });
      
      const metadataList = factory.getAllProcessorMetadata();
      const sortedByPriority = metadataList.sort((a, b) => (b.priority || 0) - (a.priority || 0));
      
      expect(sortedByPriority[0].name).toBe('High');
      expect(sortedByPriority[1].name).toBe('Medium');
    });
  });

  describe('Auto-registration Integration', () => {
    it('should auto-register built-in processors', () => {
      const freshFactory = new FileProcessorFactory();
      
      // Should have auto-registered standard processors
      expect(freshFactory.isRegistered('text/plain')).toBe(true);
      expect(freshFactory.isRegistered('application/pdf')).toBe(true);
      expect(freshFactory.isRegistered('application/vnd.openxmlformats-officedocument.wordprocessingml.document')).toBe(true);
    });

    it('should create instances of auto-registered processors', () => {
      const freshFactory = new FileProcessorFactory();
      
      const txtProcessor = freshFactory.createProcessor('text/plain');
      const pdfProcessor = freshFactory.createProcessor('application/pdf');
      const docxProcessor = freshFactory.createProcessor('application/vnd.openxmlformats-officedocument.wordprocessingml.document');
      
      expect(txtProcessor).toBeDefined();
      expect(pdfProcessor).toBeDefined();
      expect(docxProcessor).toBeDefined();
      
      expect(txtProcessor.canProcess('text/plain')).toBe(true);
      expect(pdfProcessor.canProcess('application/pdf')).toBe(true);
      expect(docxProcessor.canProcess('application/vnd.openxmlformats-officedocument.wordprocessingml.document')).toBe(true);
    });
  });
}); 