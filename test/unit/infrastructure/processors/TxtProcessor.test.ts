/**
 * Testes unitários para TxtProcessor
 * Testa processamento de arquivos de texto com detecção de encoding
 * 
 * @author ClauseDiff Team
 * @version 1.0.0
 */

import { TxtProcessor, createTxtProcessor, TXT_DEFAULTS } from '../../../../src/infrastructure/processors/TxtProcessor';
import { ProcessingError, ProcessingErrorCodes } from '../../../../src/domain/interfaces/IFileProcessor';

describe('TxtProcessor', () => {
  let processor: TxtProcessor;

  beforeEach(() => {
    processor = createTxtProcessor();
  });

  describe('Constructor and Factory', () => {
    it('should create instance with default settings', () => {
      expect(processor).toBeInstanceOf(TxtProcessor);
      
      const capabilities = processor.getCapabilities();
      expect(capabilities.maxFileSize).toBe(TXT_DEFAULTS.MAX_FILE_SIZE);
      expect(capabilities.supportedTypes).toContain(TXT_DEFAULTS.SUPPORTED_MIME_TYPE);
    });

    it('should create instance with custom settings', () => {
      const customProcessor = createTxtProcessor(1024 * 1024, 5000, 'utf-16');
      const capabilities = customProcessor.getCapabilities();
      
      expect(capabilities.maxFileSize).toBe(1024 * 1024);
    });

    it('should have correct default capabilities', () => {
      const capabilities = processor.getCapabilities();
      
      expect(capabilities.supportedTypes).toEqual([TXT_DEFAULTS.SUPPORTED_MIME_TYPE]);
      expect(capabilities.supportsMultiplePages).toBe(false);
      expect(capabilities.supportsFormatting).toBe(false);
      expect(capabilities.supportsStreaming).toBe(true);
      expect(capabilities.supportsCancellation).toBe(true);
      expect(capabilities.version).toBe('1.0.0');
    });
  });

  describe('File Type Support', () => {
    it('should support text/plain MIME type', () => {
      expect(processor.canProcess('text/plain')).toBe(true);
    });

    it('should not support unsupported MIME types', () => {
      expect(processor.canProcess('application/pdf')).toBe(false);
      expect(processor.canProcess('image/jpeg')).toBe(false);
      expect(processor.canProcess('application/json')).toBe(false);
    });

    it('should get supported types', () => {
      const supportedTypes = processor.getSupportedTypes();
      expect(supportedTypes).toContain('text/plain');
      expect(supportedTypes).toHaveLength(1);
    });
  });

  describe('File Validation', () => {
    it('should validate valid text file', async () => {
      const validFile = new File(['Hello World'], 'test.txt', { type: 'text/plain' });
      
      const isValid = await processor.validate(validFile);
      expect(isValid).toBe(true);
    });

    it('should reject files that are too large', async () => {
      const largeContent = 'A'.repeat(TXT_DEFAULTS.MAX_FILE_SIZE + 1);
      const largeFile = new File([largeContent], 'large.txt', { type: 'text/plain' });
      
      await expect(processor.validate(largeFile))
        .rejects
        .toThrow(ProcessingError);
    });

    it('should reject unsupported file types', async () => {
      const pdfFile = new File(['content'], 'test.pdf', { type: 'application/pdf' });
      
      await expect(processor.validate(pdfFile))
        .rejects
        .toThrow(ProcessingError);
    });

    it('should reject empty files', async () => {
      const emptyFile = new File([''], 'empty.txt', { type: 'text/plain' });
      
      await expect(processor.validate(emptyFile))
        .rejects
        .toThrow(ProcessingError);
    });

    it('should detect and reject binary files', async () => {
      // Create binary content (null bytes indicate binary)
      const binaryContent = new ArrayBuffer(100);
      const view = new Uint8Array(binaryContent);
      view[0] = 0x00; // null byte
      view[1] = 0xFF; // high byte
      
      const binaryFile = new File([binaryContent], 'binary.txt', { type: 'text/plain' });
      
      await expect(processor.validate(binaryFile))
        .rejects
        .toThrow(ProcessingError);
    });
  });

  describe('Text Processing', () => {
    it('should process simple UTF-8 text', async () => {
      const content = 'Hello World!\nThis is a test file.';
      const file = new File([content], 'test.txt', { type: 'text/plain' });
      
      const result = await processor.process(file);
      
      expect(result.success).toBe(true);
      expect(result.extractedText).toBe(content);
      expect(result.metadata.wordCount).toBe(6);
      expect(result.metadata.totalPages).toBe(1);
      expect(result.metadata.processorUsed).toBe('TxtProcessor');
    });

    it('should handle different line endings', async () => {
      const contentWithCRLF = 'Line 1\r\nLine 2\r\nLine 3';
      const file = new File([contentWithCRLF], 'windows.txt', { type: 'text/plain' });
      
      const result = await processor.process(file);
      
      expect(result.success).toBe(true);
      expect(result.extractedText).toContain('Line 1');
      expect(result.extractedText).toContain('Line 2');
      expect(result.extractedText).toContain('Line 3');
    });

    it('should handle Unicode characters', async () => {
      const unicodeContent = 'Olá mundo! 🌍 Café ñoño';
      const file = new File([unicodeContent], 'unicode.txt', { type: 'text/plain' });
      
      const result = await processor.process(file);
      
      expect(result.success).toBe(true);
      expect(result.extractedText).toBe(unicodeContent);
    });

    it('should calculate accurate word count', async () => {
      const content = 'The quick brown fox jumps over the lazy dog.';
      const file = new File([content], 'test.txt', { type: 'text/plain' });
      
      const result = await processor.process(file);
      
      expect(result.metadata.wordCount).toBe(9);
    });

    it('should calculate page count based on lines', async () => {
      const lines = Array(50).fill('Line of text').join('\n');
      const file = new File([lines], 'multiline.txt', { type: 'text/plain' });
      
      const result = await processor.process(file);
      
      expect(result.metadata.totalPages).toBe(2); // 50 lines = 2 pages (25 lines per page)
    });
  });

  describe('Encoding Detection', () => {
    it('should detect UTF-8 encoding', async () => {
      const utf8Content = 'UTF-8 text content';
      const file = new File([utf8Content], 'utf8.txt', { type: 'text/plain' });
      
      const result = await processor.process(file);
      
      expect(result.success).toBe(true);
      expect(result.extractedText).toBe(utf8Content);
    });

    it('should handle UTF-8 BOM', async () => {
      // UTF-8 BOM + content
      const bomContent = '\uFEFFHello with BOM';
      const file = new File([bomContent], 'bom.txt', { type: 'text/plain' });
      
      const result = await processor.process(file);
      
      expect(result.success).toBe(true);
      expect(result.extractedText).toBe('Hello with BOM'); // BOM should be stripped
    });

    it('should warn about low encoding confidence', async () => {
      // Create content that might be ambiguous
      const ambiguousContent = 'çãoñ'; // Could be multiple encodings
      const file = new File([ambiguousContent], 'ambiguous.txt', { type: 'text/plain' });
      
      const result = await processor.process(file);
      
      expect(result.success).toBe(true);
      // Should have warning about encoding confidence
      expect(result.warnings).toBeDefined();
    });
  });

  describe('Error Handling', () => {
    it('should handle processing timeout', async () => {
      const shortTimeoutProcessor = createTxtProcessor(undefined, 1); // 1ms timeout
      const content = 'A'.repeat(10000); // Large content
      const file = new File([content], 'large.txt', { type: 'text/plain' });
      
      await expect(shortTimeoutProcessor.process(file))
        .rejects
        .toThrow(ProcessingError);
    });

    it('should handle corrupted text gracefully', async () => {
      // Simulate corrupted content with mixed encodings
      const buffer = new ArrayBuffer(100);
      const view = new Uint8Array(buffer);
      
      // Fill with some valid UTF-8 and some invalid bytes
      for (let i = 0; i < 50; i++) {
        view[i] = 65 + (i % 26); // Valid ASCII
      }
      for (let i = 50; i < 100; i++) {
        view[i] = 0x80 + (i % 128); // Potentially invalid UTF-8
      }
      
      const file = new File([buffer], 'corrupted.txt', { type: 'text/plain' });
      
      const result = await processor.process(file);
      
      expect(result.success).toBe(true);
      expect(result.warnings).toBeDefined();
      expect(result.warnings.length).toBeGreaterThan(0);
    });

    it('should handle files with null bytes gracefully', async () => {
      const contentWithNull = 'Before null\0After null';
      const file = new File([contentWithNull], 'withnull.txt', { type: 'text/plain' });
      
      // This should be detected as binary and rejected in validation
      await expect(processor.validate(file))
        .rejects
        .toThrow(ProcessingError);
    });
  });

  describe('Performance Metrics', () => {
    it('should provide accurate processing time', async () => {
      const content = 'Test content for timing';
      const file = new File([content], 'timing.txt', { type: 'text/plain' });
      
      const startTime = Date.now();
      const result = await processor.process(file);
      const endTime = Date.now();
      
      expect(result.metadata.processingTime).toBeGreaterThan(0);
      expect(result.metadata.processingTime).toBeLessThanOrEqual(endTime - startTime + 10); // 10ms tolerance
    });

    it('should calculate accurate statistics', async () => {
      const content = 'Line 1\nLine 2\nLine 3\nShort line\nAnother line with more words';
      const file = new File([content], 'stats.txt', { type: 'text/plain' });
      
      const result = await processor.process(file);
      
      expect(result.metadata.wordCount).toBeGreaterThan(0);
      expect(result.metadata.totalPages).toBe(1); // 5 lines = 1 page
    });
  });

  describe('Cancellation Support', () => {
    it('should support cancellation capability', () => {
      const capabilities = processor.getCapabilities();
      expect(capabilities.supportsCancellation).toBe(true);
    });

    it('should handle cancellation during processing', async () => {
      const longContent = 'A'.repeat(1000000); // 1MB content
      const file = new File([longContent], 'long.txt', { type: 'text/plain' });
      
      // Start processing
      const processingPromise = processor.process(file);
      
      // Try to cancel (implementation specific)
      const cancelled = await processor.cancel?.('test-id');
      
      // Processor should support cancellation
      expect(cancelled).toBeDefined();
    });
  });

  describe('Edge Cases', () => {
    it('should handle files with only whitespace', async () => {
      const whitespaceContent = '   \n\t\r\n   ';
      const file = new File([whitespaceContent], 'whitespace.txt', { type: 'text/plain' });
      
      const result = await processor.process(file);
      
      expect(result.success).toBe(true);
      expect(result.extractedText).toBe(whitespaceContent);
      expect(result.metadata.wordCount).toBe(0);
    });

    it('should handle very long lines', async () => {
      const longLine = 'A'.repeat(10000);
      const file = new File([longLine], 'longline.txt', { type: 'text/plain' });
      
      const result = await processor.process(file);
      
      expect(result.success).toBe(true);
      expect(result.extractedText).toBe(longLine);
    });

    it('should handle files with special characters', async () => {
      const specialContent = '!@#$%^&*()[]{}|\\:";\'<>?,./-=_+`~';
      const file = new File([specialContent], 'special.txt', { type: 'text/plain' });
      
      const result = await processor.process(file);
      
      expect(result.success).toBe(true);
      expect(result.extractedText).toBe(specialContent);
    });

    it('should handle files with mixed line endings', async () => {
      const mixedContent = 'Line 1\nLine 2\r\nLine 3\rLine 4';
      const file = new File([mixedContent], 'mixed.txt', { type: 'text/plain' });
      
      const result = await processor.process(file);
      
      expect(result.success).toBe(true);
      expect(result.extractedText).toContain('Line 1');
      expect(result.extractedText).toContain('Line 2');
      expect(result.extractedText).toContain('Line 3');
      expect(result.extractedText).toContain('Line 4');
    });
  });

  describe('Options Support', () => {
    it('should handle extractTextOnly option', async () => {
      const content = 'Simple text content';
      const file = new File([content], 'simple.txt', { type: 'text/plain' });
      
      const result = await processor.process(file, { extractTextOnly: true });
      
      expect(result.success).toBe(true);
      expect(result.extractedText).toBe(content);
    });

    it('should handle maxCharacters option', async () => {
      const longContent = 'A'.repeat(1000);
      const file = new File([longContent], 'long.txt', { type: 'text/plain' });
      
      const result = await processor.process(file, { maxCharacters: 100 });
      
      expect(result.success).toBe(true);
      expect(result.extractedText.length).toBeLessThanOrEqual(100);
    });

    it('should handle custom timeout option', async () => {
      const content = 'Test content';
      const file = new File([content], 'test.txt', { type: 'text/plain' });
      
      const result = await processor.process(file, { timeoutMs: 30000 });
      
      expect(result.success).toBe(true);
      expect(result.extractedText).toBe(content);
    });
  });

  describe('File Extensions Support', () => {
    it('should handle .txt files', async () => {
      const content = 'Plain text content';
      const file = new File([content], 'document.txt', { type: 'text/plain' });
      
      const result = await processor.process(file);
      expect(result.success).toBe(true);
    });

    it('should handle .text files', async () => {
      const content = 'Text file content';
      const file = new File([content], 'document.text', { type: 'text/plain' });
      
      const result = await processor.process(file);
      expect(result.success).toBe(true);
    });

    it('should handle .log files', async () => {
      const content = '[INFO] Log entry\n[ERROR] Error message';
      const file = new File([content], 'application.log', { type: 'text/plain' });
      
      const result = await processor.process(file);
      expect(result.success).toBe(true);
      expect(result.extractedText).toContain('Log entry');
    });

    it('should handle .md files', async () => {
      const content = '# Markdown Title\n\nThis is **bold** text.';
      const file = new File([content], 'README.md', { type: 'text/plain' });
      
      const result = await processor.process(file);
      expect(result.success).toBe(true);
      expect(result.extractedText).toContain('Markdown Title');
    });

    it('should handle .markdown files', async () => {
      const content = '## Subtitle\n\nMarkdown content here.';
      const file = new File([content], 'doc.markdown', { type: 'text/plain' });
      
      const result = await processor.process(file);
      expect(result.success).toBe(true);
      expect(result.extractedText).toContain('Subtitle');
    });
  });
}); 