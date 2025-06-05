import { exportToPdf, exportToCsv } from '@/utils/exportHandler';
import { DIFF_INSERT, DIFF_DELETE, DIFF_EQUAL } from '../../../types';

// Mock jsPDF instance
const mockPdfInstance = {
  internal: {
    pageSize: {
      getWidth: jest.fn().mockReturnValue(595.28),
      getHeight: jest.fn().mockReturnValue(841.89)
    }
  },
  setFont: jest.fn(),
  setFontSize: jest.fn(),
  text: jest.fn(),
  addImage: jest.fn(),
  getImageProperties: jest.fn().mockReturnValue({ width: 800, height: 600 }),
  save: jest.fn()
};

// Mock jsPDF constructor
const mockJsPDF = jest.fn().mockImplementation(() => mockPdfInstance);

// Mock html2canvas
const mockHtml2Canvas = jest.fn();

// Mock DOM APIs
const mockElement = {
  id: 'test-element',
  isConnected: true,
  scrollHeight: 600,
  scrollWidth: 800,
  scrollLeft: 0,
  scrollTop: 0,
  innerHTML: '<div>Test content</div>'
};

const mockCanvas = {
  toDataURL: jest.fn().mockReturnValue('data:image/png;base64,mockImageData')
};

const mockBlob = jest.fn();
const mockURL = {
  createObjectURL: jest.fn().mockReturnValue('blob:mock-url'),
  revokeObjectURL: jest.fn()
};

const mockLink = {
  download: '',
  setAttribute: jest.fn(),
  style: { visibility: '' },
  click: jest.fn()
};

// Setup global mocks
beforeAll(() => {
  // Mock window objects
  Object.defineProperty(global, 'window', {
    value: {
      jspdf: { jsPDF: mockJsPDF },
      html2canvas: mockHtml2Canvas,
      getComputedStyle: jest.fn().mockReturnValue({ display: 'block' })
    },
    writable: true
  });

  // Mock document
  Object.defineProperty(global, 'document', {
    value: {
      readyState: 'complete',
      getElementById: jest.fn(),
      createElement: jest.fn().mockReturnValue(mockLink),
      body: {
        appendChild: jest.fn(),
        removeChild: jest.fn()
      }
    },
    writable: true
  });

  // Mock global constructors
  (global as any).Blob = mockBlob;
  (global as any).URL = mockURL;

  // Mock console and alert
  global.console.log = jest.fn();
  global.console.warn = jest.fn();
  global.console.error = jest.fn();
  global.alert = jest.fn();

  // Mock setTimeout to resolve immediately
  global.setTimeout = jest.fn().mockImplementation((callback) => {
    callback();
    return 1;
  }) as any;
});

beforeEach(() => {
  jest.clearAllMocks();
  
  // Reset mock implementations
  mockHtml2Canvas.mockResolvedValue(mockCanvas);
  mockBlob.mockImplementation((content, options) => ({ content, options }));
  
  // Reset document.getElementById mock
  (document.getElementById as jest.Mock).mockImplementation((id) => {
    if (id === 'element1' || id === 'element2') {
      return { ...mockElement, id };
    }
    return null;
  });
});

describe('exportHandler', () => {
  describe('exportToPdf', () => {
    it('should successfully export two elements to PDF', async () => {
      await exportToPdf('element1', 'element2', 'test.pdf');

      expect(document.getElementById).toHaveBeenCalledWith('element1');
      expect(document.getElementById).toHaveBeenCalledWith('element2');
      expect(mockHtml2Canvas).toHaveBeenCalledTimes(2);
      expect(mockPdfInstance.addImage).toHaveBeenCalledTimes(2);
      expect(mockPdfInstance.save).toHaveBeenCalledWith('test.pdf');
    });

    it('should use default filename when not provided', async () => {
      await exportToPdf('element1', 'element2');

      expect(mockPdfInstance.save).toHaveBeenCalledWith('comparacao_documentos.pdf');
    });

    it('should handle missing first element', async () => {
      (document.getElementById as jest.Mock).mockImplementation((id) => {
        if (id === 'element1') return null;
        if (id === 'element2') return mockElement;
        return null;
      });

      await exportToPdf('element1', 'element2');

      expect(console.error).toHaveBeenCalledWith('Elementos para exportação PDF não encontrados.');
      expect(alert).toHaveBeenCalledWith('Erro ao gerar PDF: elementos não encontrados.');
      expect(mockHtml2Canvas).not.toHaveBeenCalled();
    });

    it('should handle missing second element', async () => {
      (document.getElementById as jest.Mock).mockImplementation((id) => {
        if (id === 'element1') return mockElement;
        if (id === 'element2') return null;
        return null;
      });

      await exportToPdf('element1', 'element2');

      expect(console.error).toHaveBeenCalledWith('Elementos para exportação PDF não encontrados.');
      expect(alert).toHaveBeenCalledWith('Erro ao gerar PDF: elementos não encontrados.');
      expect(mockHtml2Canvas).not.toHaveBeenCalled();
    });

    it('should handle html2canvas errors', async () => {
      const canvasError = new Error('Canvas rendering failed');
      mockHtml2Canvas.mockRejectedValue(canvasError);

      await exportToPdf('element1', 'element2');

      expect(console.error).toHaveBeenCalledWith('ERRO DETALHADO AO GERAR PDF:', canvasError);
      expect(alert).toHaveBeenCalledWith(
        expect.stringContaining('ERRO AO GERAR PDF: Error - Canvas rendering failed')
      );
    });

    it('should handle errors without name or message', async () => {
      const unknownError = {};
      mockHtml2Canvas.mockRejectedValue(unknownError);

      await exportToPdf('element1', 'element2');

      expect(alert).toHaveBeenCalledWith(
        expect.stringContaining('ERRO AO GERAR PDF: UnknownError - No message')
      );
    });

    it('should log element properties for debugging', async () => {
      await exportToPdf('element1', 'element2');

      expect(console.log).toHaveBeenCalledWith('Document readyState:', 'complete');
      expect(console.log).toHaveBeenCalledWith(
        'Verificando elementos para PDF:',
        expect.objectContaining({
          el1Exists: true,
          el2Exists: true,
          el1Connected: true,
          el2Connected: true
        })
      );
    });

    it('should configure canvas options correctly', async () => {
      await exportToPdf('element1', 'element2');

      expect(mockHtml2Canvas).toHaveBeenCalledWith(
        expect.objectContaining({ id: 'element1' }),
        expect.objectContaining({
          allowTaint: true,
          useCORS: true,
          logging: true,
          backgroundColor: '#ffffff',
          removeContainer: true,
          taintTest: false,
          width: 800,
          height: 600,
          windowWidth: 800,
          windowHeight: 600,
          scrollX: 0,
          scrollY: 0,
          x: 0,
          y: 0,
          scale: 1
        })
      );
    });

    it('should handle elements with scroll offset', async () => {
      const scrolledElement = {
        ...mockElement,
        scrollLeft: 100,
        scrollTop: 50
      };

      (document.getElementById as jest.Mock).mockReturnValue(scrolledElement);

      await exportToPdf('element1', 'element2');

      expect(mockHtml2Canvas).toHaveBeenCalledWith(
        scrolledElement,
        expect.objectContaining({
          scrollX: -100,
          scrollY: -50
        })
      );
    });

    it('should warn when content exceeds page height', async () => {
      // Mock very tall images
      mockPdfInstance.getImageProperties.mockReturnValue({ width: 800, height: 2000 });

      await exportToPdf('element1', 'element2');

      expect(console.warn).toHaveBeenCalledWith(
        expect.stringContaining('Conteúdo da imagem excedeu a altura da página')
      );
    });

    it('should set PDF fonts and titles correctly', async () => {
      await exportToPdf('element1', 'element2');

      expect(mockPdfInstance.setFont).toHaveBeenCalledWith('Source Sans Pro', 'bold');
      expect(mockPdfInstance.setFontSize).toHaveBeenCalledWith(18);
      expect(mockPdfInstance.text).toHaveBeenCalledWith(
        'Relatório de Comparação de Documentos',
        expect.any(Number),
        expect.any(Number),
        { align: 'center' }
      );
    });
  });

  describe('exportToCsv', () => {
    const mockDiffs = [
      { type: 'insert' as const, text: 'Added text' },
      { type: 'delete' as const, text: 'Removed text' },
      { type: 'equal' as const, text: 'Unchanged text' },
      { type: 'insert' as const, text: 'Another addition' },
      { type: 'delete' as const, text: '' }, // Empty text should be ignored
      { type: 'insert' as const, text: '   ' } // Whitespace-only should be ignored
    ];

    it('should successfully export diffs to CSV', () => {
      exportToCsv(mockDiffs, 'test.csv');

      expect(mockBlob).toHaveBeenCalledWith(
        expect.any(String),
        { type: 'text/csv;charset=utf-8;' }
      );

      const csvContent = (mockBlob as jest.Mock).mock.calls[0][0];
      expect(csvContent).toContain('Tipo,Texto');
      expect(csvContent).toContain('Adição,"Added text"');
      expect(csvContent).toContain('Remoção,"Removed text"');
      expect(csvContent).toContain('Adição,"Another addition"');
      expect(csvContent).not.toContain('Unchanged text');

      expect(document.createElement).toHaveBeenCalledWith('a');
      expect(mockLink.setAttribute).toHaveBeenCalledWith('download', 'test.csv');
      expect(mockLink.click).toHaveBeenCalled();
    });

    it('should use default filename when not provided', () => {
      exportToCsv(mockDiffs);

      expect(mockLink.setAttribute).toHaveBeenCalledWith('download', 'relatorio_alteracoes.csv');
    });

    it('should handle empty diffs array', () => {
      exportToCsv([]);

      expect(alert).toHaveBeenCalledWith('Nenhuma alteração para exportar.');
      expect(mockBlob).not.toHaveBeenCalled();
    });

    it('should handle null/undefined diffs', () => {
      exportToCsv(null as any);

      expect(alert).toHaveBeenCalledWith('Nenhuma alteração para exportar.');
      expect(mockBlob).not.toHaveBeenCalled();
    });

    it('should sanitize CSV content properly', () => {
      const diffsWithSpecialChars = [
        { type: 'insert' as const, text: 'Text with "quotes" and\nnewlines' },
        { type: 'delete' as const, text: 'Text with, commas' }
      ];

      exportToCsv(diffsWithSpecialChars);

      const csvContent = (mockBlob as jest.Mock).mock.calls[0][0];
      expect(csvContent).toContain('"Text with ""quotes"" and newlines"');
      expect(csvContent).toContain('"Text with, commas"');
    });

    it('should filter out equal diffs and empty text', () => {
      const mixedDiffs = [
        { type: DIFF_EQUAL, text: 'Should not appear' },
        { type: DIFF_INSERT, text: '' },
        { type: DIFF_DELETE, text: '   ' },
        { type: DIFF_INSERT, text: 'Should appear' }
      ];

      exportToCsv(mixedDiffs);

      const csvContent = (mockBlob as jest.Mock).mock.calls[0][0];
      expect(csvContent).not.toContain('Should not appear');
      expect(csvContent).toContain('Should appear');
      
      // Should only have header + 1 valid row
      const lines = csvContent.split('\n').filter((line: string) => line.trim() !== '');
      expect(lines).toHaveLength(2); // Header + 1 data row
    });

    it('should handle browser without download support', () => {
      const linkWithoutDownload = { ...mockLink };
      delete (linkWithoutDownload as any).download;
      
      (document.createElement as jest.Mock).mockReturnValue(linkWithoutDownload);

      exportToCsv(mockDiffs);

      expect(alert).toHaveBeenCalledWith('Seu navegador não suporta download direto.');
    });

    it('should clean up URL object after download', () => {
      exportToCsv(mockDiffs);

      expect(URL.createObjectURL).toHaveBeenCalled();
      expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:mock-url');
      expect(document.body.removeChild).toHaveBeenCalledWith(mockLink);
    });

    it('should handle different diff types correctly', () => {
      const typedDiffs = [
        { type: 'insert' as const, text: 'Insert type' },
        { type: 'delete' as const, text: 'Delete type' },
        { type: 'equal' as const, text: 'Equal type' }
      ];

      exportToCsv(typedDiffs);

      const csvContent = (mockBlob as jest.Mock).mock.calls[0][0];
      expect(csvContent).toContain('Adição,"Insert type"');
      expect(csvContent).toContain('Remoção,"Delete type"');
      expect(csvContent).not.toContain('Equal type');
    });

    it('should handle large CSV content without truncation', () => {
      const largeDiffs = Array.from({ length: 1000 }, (_, i) => ({
        type: 'insert' as const,
        text: `Large content item ${i} with repeated text to increase size`
      }));

      exportToCsv(largeDiffs, 'large-test.csv');

      const csvContent = (mockBlob as jest.Mock).mock.calls[0][0];
      const lines = csvContent.split('\n').filter((line: string) => line.trim() !== '');
      expect(lines).toHaveLength(1001); // Header + 1000 data rows
      expect(csvContent).toContain('Large content item 999');
    });

    it('should handle special characters in CSV filename', () => {
      const mockDiffs = [
        { type: 'insert' as const, text: 'Test content' }
      ];

      exportToCsv(mockDiffs, 'file-with-special-chars-áéíóú.csv');

      expect(mockLink.setAttribute).toHaveBeenCalledWith('download', 'file-with-special-chars-áéíóú.csv');
    });

    it('should handle CSV content with Unicode characters', () => {
      const unicodeDiffs = [
        { type: 'insert' as const, text: '🚀 Emoji content with 中文 characters' },
        { type: 'delete' as const, text: 'ñáéíóú special chars' },
        { type: 'insert' as const, text: '表格数据 with symbols: ♥♦♣♠' }
      ];

      exportToCsv(unicodeDiffs);

      const csvContent = (mockBlob as jest.Mock).mock.calls[0][0];
      expect(csvContent).toContain('🚀 Emoji content with 中文 characters');
      expect(csvContent).toContain('ñáéíóú special chars');
      expect(csvContent).toContain('表格数据 with symbols: ♥♦♣♠');
    });

    it('should handle mixed line endings in CSV content', () => {
      const mixedLineDiffs = [
        { type: 'insert' as const, text: 'Line 1\nLine 2\r\nLine 3\rLine 4' },
        { type: 'delete' as const, text: 'Text with\n\nmultiple\r\n\rnewlines' }
      ];

      exportToCsv(mixedLineDiffs);

      const csvContent = (mockBlob as jest.Mock).mock.calls[0][0];
      // All line endings should be converted to spaces
      expect(csvContent).toContain('"Line 1 Line 2 Line 3 Line 4"');
      expect(csvContent).toContain('"Text with  multiple  newlines"');
    });
  });

  describe('PDF Export Edge Cases', () => {
    it('should handle elements with zero dimensions', async () => {
      const zeroSizeElement = {
        ...mockElement,
        scrollHeight: 0,
        scrollWidth: 0
      };

      (document.getElementById as jest.Mock).mockReturnValue(zeroSizeElement);

      await exportToPdf('element1', 'element2', 'zero-size.pdf');

      expect(mockHtml2Canvas).toHaveBeenCalledWith(
        zeroSizeElement,
        expect.objectContaining({
          width: 0,
          height: 0
        })
      );
    });

    it('should handle PDF generation with very small images', async () => {
      mockPdfInstance.getImageProperties.mockReturnValue({ width: 10, height: 5 });

      await exportToPdf('element1', 'element2');

      // Should still add images even if very small
      expect(mockPdfInstance.addImage).toHaveBeenCalledTimes(2);
      expect(mockPdfInstance.save).toHaveBeenCalled();
    });

    it('should handle special characters in PDF filename', async () => {
      await exportToPdf('element1', 'element2', 'file-with-special-chars-áéíóú.pdf');

      expect(mockPdfInstance.save).toHaveBeenCalledWith('file-with-special-chars-áéíóú.pdf');
    });

    it('should handle PDF generation with disconnected elements', async () => {
      const disconnectedElement = {
        ...mockElement,
        isConnected: false
      };

      (document.getElementById as jest.Mock).mockReturnValue(disconnectedElement);

      await exportToPdf('element1', 'element2');

      // Should still proceed with disconnected elements
      expect(mockHtml2Canvas).toHaveBeenCalledTimes(2);
      expect(console.log).toHaveBeenCalledWith(
        'Verificando elementos para PDF:',
        expect.objectContaining({
          el1Connected: false,
          el2Connected: false
        })
      );
    });

    it('should handle PDF with custom page dimensions', async () => {
      // Mock different page size
      mockPdfInstance.internal.pageSize.getWidth.mockReturnValue(841.89); // A4 landscape width
      mockPdfInstance.internal.pageSize.getHeight.mockReturnValue(595.28); // A4 landscape height

      await exportToPdf('element1', 'element2');

      expect(mockPdfInstance.addImage).toHaveBeenCalledWith(
        expect.any(String),
        'PNG',
        expect.any(Number),
        expect.any(Number),
        expect.any(Number), // width calculated based on new page size
        expect.any(Number), // height
        undefined,
        'FAST'
      );
    });
  });

  describe('Error Handling and Validation', () => {
    it('should handle CSV export with null text values', () => {
      const nullTextDiffs = [
        { type: 'insert' as const, text: null as any },
        { type: 'delete' as const, text: undefined as any },
        { type: 'insert' as const, text: 'Valid text' }
      ];

      // Should not throw error
      expect(() => exportToCsv(nullTextDiffs)).not.toThrow();
    });

    it('should handle PDF export with invalid element IDs', async () => {
      (document.getElementById as jest.Mock).mockReturnValue(null);

      await exportToPdf('invalid-id-1', 'invalid-id-2');

      expect(console.error).toHaveBeenCalledWith('Elementos para exportação PDF não encontrados.');
      expect(alert).toHaveBeenCalledWith('Erro ao gerar PDF: elementos não encontrados.');
      expect(mockHtml2Canvas).not.toHaveBeenCalled();
    });

    it('should handle html2canvas timeout or async errors', async () => {
      const timeoutError = new Error('Timeout');
      timeoutError.name = 'TimeoutError';
      mockHtml2Canvas.mockRejectedValue(timeoutError);

      await exportToPdf('element1', 'element2');

      expect(alert).toHaveBeenCalledWith(
        expect.stringContaining('ERRO AO GERAR PDF: TimeoutError - Timeout')
      );
    });

    it('should handle image data generation failures', async () => {
      mockCanvas.toDataURL.mockImplementation(() => {
        throw new Error('Image data generation failed');
      });

      await exportToPdf('element1', 'element2');

      expect(console.error).toHaveBeenCalledWith(
        'ERRO DETALHADO AO GERAR PDF:',
        expect.any(Error)
      );
    });

    it('should validate CSV blob creation parameters', () => {
      const mockDiffs = [
        { type: 'insert' as const, text: 'Test content' }
      ];

      exportToCsv(mockDiffs, 'validation-test.csv');

      expect(mockBlob).toHaveBeenCalledWith(
        expect.stringContaining('Tipo,Texto'),
        { type: 'text/csv;charset=utf-8;' }
      );

      const csvContent = (mockBlob as jest.Mock).mock.calls[0][0];
      expect(csvContent.startsWith('Tipo,Texto\n')).toBe(true);
    });

    it('should handle memory cleanup on PDF generation failure', async () => {
      const memoryError = new Error('Out of memory');
      mockHtml2Canvas.mockRejectedValue(memoryError);

      // Mock cleanup functions
      const mockRevokeObjectURL = jest.fn();
      global.URL.revokeObjectURL = mockRevokeObjectURL;

      await exportToPdf('element1', 'element2');

      expect(console.error).toHaveBeenCalledWith('ERRO DETALHADO AO GERAR PDF:', memoryError);
      // Error should be handled gracefully without crashing
    });
  });

  describe('Integration Tests', () => {
    it('should handle complete PDF export workflow', async () => {
      await exportToPdf('element1', 'element2', 'integration-test.pdf');

      // Verify complete workflow
      expect(document.getElementById).toHaveBeenCalledTimes(2);
      expect(mockHtml2Canvas).toHaveBeenCalledTimes(2);
      expect(mockPdfInstance.setFont).toHaveBeenCalled();
      expect(mockPdfInstance.setFontSize).toHaveBeenCalled();
      expect(mockPdfInstance.text).toHaveBeenCalled();
      expect(mockPdfInstance.addImage).toHaveBeenCalledTimes(2);
      expect(mockPdfInstance.save).toHaveBeenCalledWith('integration-test.pdf');
    });

    it('should handle complete CSV export workflow', () => {
      const diffs = [
        { type: DIFF_INSERT, text: 'New content' },
        { type: DIFF_DELETE, text: 'Old content' }
      ];

      exportToCsv(diffs, 'integration-test.csv');

      // Verify complete workflow
      expect(mockBlob).toHaveBeenCalled();
      expect(URL.createObjectURL).toHaveBeenCalled();
      expect(document.createElement).toHaveBeenCalledWith('a');
      expect(mockLink.click).toHaveBeenCalled();
      expect(URL.revokeObjectURL).toHaveBeenCalled();
      expect(document.body.removeChild).toHaveBeenCalled();
    });

    it('should handle concurrent PDF exports without interference', async () => {
      // Mock multiple PDF exports happening simultaneously
      const exportPromises = [
        exportToPdf('element1', 'element2', 'concurrent-1.pdf'),
        exportToPdf('element1', 'element2', 'concurrent-2.pdf'),
        exportToPdf('element1', 'element2', 'concurrent-3.pdf')
      ];

      await Promise.all(exportPromises);

      // Each export should complete independently
      expect(mockHtml2Canvas).toHaveBeenCalledTimes(6); // 2 calls per export × 3 exports
      expect(mockPdfInstance.save).toHaveBeenCalledTimes(3);
      expect(mockPdfInstance.save).toHaveBeenCalledWith('concurrent-1.pdf');
      expect(mockPdfInstance.save).toHaveBeenCalledWith('concurrent-2.pdf');
      expect(mockPdfInstance.save).toHaveBeenCalledWith('concurrent-3.pdf');
    });

    it('should handle sequential exports with different configurations', async () => {
      // First export with normal elements
      await exportToPdf('element1', 'element2', 'sequential-1.pdf');

      // Reset mocks
      jest.clearAllMocks();

      // Second export with larger elements
      const largeElement = {
        ...mockElement,
        scrollHeight: 2000,
        scrollWidth: 1500
      };
      (document.getElementById as jest.Mock).mockReturnValue(largeElement);

      await exportToPdf('element1', 'element2', 'sequential-2.pdf');

      // Verify second export used different dimensions
      expect(mockHtml2Canvas).toHaveBeenCalledWith(
        largeElement,
        expect.objectContaining({
          width: 1500,
          height: 2000
        })
      );
    });
  });

  describe('Performance and Stress Tests', () => {
    it('should handle CSV export with large dataset efficiently', () => {
      const startTime = Date.now();
      const largeDiffs = Array.from({ length: 10000 }, (_, i) => ({
        type: i % 2 === 0 ? 'insert' as const : 'delete' as const,
        text: `Performance test item ${i} with sufficient content to test memory usage and processing speed`
      }));

      exportToCsv(largeDiffs, 'performance-test.csv');

      const endTime = Date.now();
      const executionTime = endTime - startTime;

      // Export should complete within reasonable time (less than 1 second for this test)
      expect(executionTime).toBeLessThan(1000);

      // Verify all data was processed
      const csvContent = (mockBlob as jest.Mock).mock.calls[0][0];
      const lines = csvContent.split('\n').filter((line: string) => line.trim() !== '');
      expect(lines).toHaveLength(10001); // Header + 10000 data rows
    });

    it('should handle memory-efficient CSV processing', () => {
      // Create test with mixed content sizes
      const mixedSizeDiffs = [
        ...Array.from({ length: 100 }, (_, i) => ({
          type: 'insert' as const,
          text: 'Short text ' + i
        })),
        ...Array.from({ length: 50 }, (_, i) => ({
          type: 'delete' as const,
          text: 'Medium length text content that should test memory allocation and string processing capabilities for item ' + i
        })),
        ...Array.from({ length: 10 }, (_, i) => ({
          type: 'insert' as const,
          text: 'Very long text content that simulates large document differences and tests the system ability to handle substantial string data without memory leaks or performance degradation during CSV generation process for item number ' + i + ' with additional padding content to increase size significantly'
        }))
      ];

      expect(() => exportToCsv(mixedSizeDiffs, 'memory-test.csv')).not.toThrow();

      // Verify blob creation succeeded with expected size
      expect(mockBlob).toHaveBeenCalledWith(
        expect.stringMatching(/^Tipo,Texto\n/),
        { type: 'text/csv;charset=utf-8;' }
      );
    });

    it('should maintain performance with deeply nested HTML structures in PDF', async () => {
      const complexElement = {
        ...mockElement,
        innerHTML: '<div>' + '<div>'.repeat(100) + 'Nested content' + '</div>'.repeat(100) + '</div>',
        scrollHeight: 5000,
        scrollWidth: 1200
      };

      (document.getElementById as jest.Mock).mockReturnValue(complexElement);

      const startTime = Date.now();
      await exportToPdf('element1', 'element2', 'complex-structure.pdf');
      const endTime = Date.now();

      // Should complete within reasonable time even with complex structure
      expect(endTime - startTime).toBeLessThan(2000);
      expect(mockHtml2Canvas).toHaveBeenCalledTimes(2);
    });
  });

  describe('Type Safety and Validation Tests', () => {
    it('should handle TypeScript type validation for export functions', () => {
      // Test proper TypeScript inference
      const typedDiffs: Array<{ type: 'insert' | 'delete' | 'equal'; text: string }> = [
        { type: 'insert', text: 'TypeScript test' },
        { type: 'delete', text: 'Removed content' }
      ];

      expect(() => exportToCsv(typedDiffs, 'type-safety.csv')).not.toThrow();
    });

    it('should validate input parameters properly', async () => {
      // Test with empty string IDs
      await exportToPdf('', '', 'empty-ids.pdf');
      expect(console.error).toHaveBeenCalledWith('Elementos para exportação PDF não encontrados.');

      // Test with undefined filename
      await exportToPdf('element1', 'element2', undefined as any);
      expect(mockPdfInstance.save).toHaveBeenCalledWith('comparacao_documentos.pdf');
    });

    it('should handle edge cases in function parameters', () => {
      // Test CSV with empty filename
      exportToCsv([{ type: 'insert', text: 'test' }], '');
      expect(mockLink.setAttribute).toHaveBeenCalledWith('download', '');

      // Test CSV with undefined filename
      exportToCsv([{ type: 'insert', text: 'test' }], undefined as any);
      expect(mockLink.setAttribute).toHaveBeenCalledWith('download', 'relatorio_alteracoes.csv');
    });
  });
}); 