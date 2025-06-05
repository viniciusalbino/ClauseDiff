import { processDocxFile, processTxtFile, processPdfFile } from '@/utils/fileProcessor';
import { DocumentData } from '../../../types';

// Mock FileReader
const mockFileReader = {
  onload: null as any,
  onerror: null as any,
  readAsArrayBuffer: jest.fn(),
  readAsText: jest.fn(),
  result: null as any
};

// Mock global libraries
const mockMammoth = {
  extractRawText: jest.fn()
};

const mockPdfjsLib = {
  GlobalWorkerOptions: {
    workerSrc: ''
  },
  getDocument: jest.fn()
};

// Setup global mocks
beforeAll(() => {
  // Mock FileReader
  (global as any).FileReader = jest.fn().mockImplementation(() => mockFileReader);
  
  // Mock global window objects
  Object.defineProperty(global, 'window', {
    value: {
      mammoth: mockMammoth,
      pdfjsLib: mockPdfjsLib
    },
    writable: true
  });
});

beforeEach(() => {
  jest.clearAllMocks();
  // Reset FileReader mock state
  mockFileReader.onload = null;
  mockFileReader.onerror = null;
  mockFileReader.readAsArrayBuffer = jest.fn();
  mockFileReader.readAsText = jest.fn();
  mockFileReader.result = null;
});

describe('fileProcessor', () => {
  describe('processDocxFile', () => {
    const createMockFile = (name: string, type: string, content: string = 'test content') => {
      const file = new File([content], name, { type });
      return file;
    };

    it('should successfully process a DOCX file', async () => {
      const mockFile = createMockFile('test.docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
      const mockArrayBuffer = new ArrayBuffer(8);
      const expectedText = 'Extracted text from DOCX';

      mockMammoth.extractRawText.mockResolvedValue({ value: expectedText });

      // Mock FileReader to call onload immediately
      mockFileReader.readAsArrayBuffer.mockImplementation((file) => {
        mockFileReader.result = mockArrayBuffer;
        // Immediately call onload
        if (mockFileReader.onload) {
          mockFileReader.onload({ target: mockFileReader });
        }
      });

      const result = await processDocxFile(mockFile);

      expect(result).toEqual({
        name: 'test.docx',
        content: expectedText,
        type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        originalFile: mockFile
      });

      expect(mockFileReader.readAsArrayBuffer).toHaveBeenCalledWith(mockFile);
      expect(mockMammoth.extractRawText).toHaveBeenCalledWith({ arrayBuffer: mockArrayBuffer });
    });

    it('should handle mammoth extraction errors', async () => {
      const mockFile = createMockFile('test.docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
      const mockArrayBuffer = new ArrayBuffer(8);

      mockMammoth.extractRawText.mockRejectedValue(new Error('Mammoth parsing error'));

      mockFileReader.readAsArrayBuffer.mockImplementation((file) => {
        mockFileReader.result = mockArrayBuffer;
        if (mockFileReader.onload) {
          mockFileReader.onload({ target: mockFileReader });
        }
      });

      await expect(processDocxFile(mockFile)).rejects.toThrow('Falha ao processar o arquivo .docx.');
    });

    it('should handle FileReader load error (no result)', async () => {
      const mockFile = createMockFile('test.docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');

      mockFileReader.readAsArrayBuffer.mockImplementation((file) => {
        mockFileReader.result = null;
        if (mockFileReader.onload) {
          mockFileReader.onload({ target: mockFileReader });
        }
      });

      await expect(processDocxFile(mockFile)).rejects.toThrow('Falha ao ler o arquivo.');
    });

    it('should handle FileReader error event', async () => {
      const mockFile = createMockFile('test.docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');

      mockFileReader.readAsArrayBuffer.mockImplementation((file) => {
        if (mockFileReader.onerror) {
          mockFileReader.onerror(new Error('FileReader error'));
        }
      });

      await expect(processDocxFile(mockFile)).rejects.toThrow('Erro ao ler o arquivo.');
    });
  });

  describe('processTxtFile', () => {
    const createMockFile = (name: string, type: string, content: string = 'test content') => {
      const file = new File([content], name, { type });
      return file;
    };

    it('should successfully process a text file', async () => {
      const mockFile = createMockFile('test.txt', 'text/plain');
      const expectedText = 'This is text file content';

      mockFileReader.readAsText.mockImplementation((file) => {
        mockFileReader.result = expectedText;
        if (mockFileReader.onload) {
          mockFileReader.onload({ target: mockFileReader });
        }
      });

      const result = await processTxtFile(mockFile);

      expect(result).toEqual({
        name: 'test.txt',
        content: expectedText,
        type: 'text/plain',
        originalFile: mockFile
      });

      expect(mockFileReader.readAsText).toHaveBeenCalledWith(mockFile);
    });

    it('should handle FileReader error for text files', async () => {
      const mockFile = createMockFile('test.txt', 'text/plain');

      mockFileReader.readAsText.mockImplementation((file) => {
        if (mockFileReader.onerror) {
          mockFileReader.onerror(new Error('FileReader error'));
        }
      });

      await expect(processTxtFile(mockFile)).rejects.toThrow('Erro ao ler o arquivo.');
    });

    it('should handle empty text files (current behavior - treats empty string as error)', async () => {
      const mockFile = createMockFile('empty.txt', 'text/plain');
      const expectedText = '';

      mockFileReader.readAsText.mockImplementation((file) => {
        mockFileReader.result = expectedText;
        if (mockFileReader.onload) {
          // Use a proper event object that has both target and result
          mockFileReader.onload({ target: mockFileReader });
        }
      });

      // Note: This is arguably a bug in the implementation - empty strings are treated as errors
      // because the code checks `if (event.target && event.target.result)` and empty string is falsy
      await expect(processTxtFile(mockFile)).rejects.toThrow('Falha ao ler o arquivo.');
    });

    it('should handle text files with whitespace content', async () => {
      const mockFile = createMockFile('whitespace.txt', 'text/plain');
      const expectedText = ' '; // Single space - truthy

      mockFileReader.readAsText.mockImplementation((file) => {
        mockFileReader.result = expectedText;
        if (mockFileReader.onload) {
          mockFileReader.onload({ target: mockFileReader });
        }
      });

      const result = await processTxtFile(mockFile);

      expect(result).toEqual({
        name: 'whitespace.txt',
        content: ' ',
        type: 'text/plain',
        originalFile: mockFile
      });
    });
  });

  describe('processPdfFile', () => {
    const createMockFile = (name: string, type: string, content: string = 'test content') => {
      const file = new File([content], name, { type });
      return file;
    };

    const createMockPdfDoc = (numPages: number, pageTexts: string[]) => ({
      numPages,
      getPage: jest.fn().mockImplementation((pageNum: number) => 
        Promise.resolve({
          getTextContent: jest.fn().mockResolvedValue({
            items: pageTexts[pageNum - 1]?.split(' ').map(str => ({ str })) || []
          })
        })
      )
    });

    it('should successfully process a PDF file', async () => {
      const mockFile = createMockFile('test.pdf', 'application/pdf');
      const mockArrayBuffer = new ArrayBuffer(8);
      const pageTexts = ['Page one content', 'Page two content'];
      const mockPdfDoc = createMockPdfDoc(2, pageTexts);

      mockPdfjsLib.getDocument.mockReturnValue({
        promise: Promise.resolve(mockPdfDoc)
      });

      mockFileReader.readAsArrayBuffer.mockImplementation((file) => {
        mockFileReader.result = mockArrayBuffer;
        if (mockFileReader.onload) {
          mockFileReader.onload({ target: mockFileReader });
        }
      });

      const result = await processPdfFile(mockFile);

      expect(result).toEqual({
        name: 'test.pdf',
        content: 'Page one content\nPage two content',
        type: 'application/pdf',
        originalFile: mockFile
      });

      expect(mockFileReader.readAsArrayBuffer).toHaveBeenCalledWith(mockFile);
      expect(mockPdfjsLib.getDocument).toHaveBeenCalledWith({ data: mockArrayBuffer });
    });

    it('should handle PDF parsing errors', async () => {
      const mockFile = createMockFile('corrupt.pdf', 'application/pdf');
      const mockArrayBuffer = new ArrayBuffer(8);

      mockPdfjsLib.getDocument.mockReturnValue({
        promise: Promise.reject(new Error('PDF parsing error'))
      });

      mockFileReader.readAsArrayBuffer.mockImplementation((file) => {
        mockFileReader.result = mockArrayBuffer;
        if (mockFileReader.onload) {
          mockFileReader.onload({ target: mockFileReader });
        }
      });

      await expect(processPdfFile(mockFile)).rejects.toThrow('Falha ao processar o arquivo .pdf.');
    });

    it('should set worker source when not already set', async () => {
      const mockFile = createMockFile('test.pdf', 'application/pdf');
      const mockArrayBuffer = new ArrayBuffer(8);
      const pageTexts = ['Test content'];
      const mockPdfDoc = createMockPdfDoc(1, pageTexts);

      // Ensure worker source is empty initially
      mockPdfjsLib.GlobalWorkerOptions.workerSrc = '';

      mockPdfjsLib.getDocument.mockReturnValue({
        promise: Promise.resolve(mockPdfDoc)
      });

      mockFileReader.readAsArrayBuffer.mockImplementation((file) => {
        mockFileReader.result = mockArrayBuffer;
        if (mockFileReader.onload) {
          mockFileReader.onload({ target: mockFileReader });
        }
      });

      await processPdfFile(mockFile);

      expect(mockPdfjsLib.GlobalWorkerOptions.workerSrc).toBe('https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js');
    });
  });

  describe('Integration Tests', () => {
    it('should return correct DocumentData structure', async () => {
      const txtFile = new File(['test'], 'test.txt', { type: 'text/plain' });
      
      mockFileReader.readAsText.mockImplementation((file) => {
        mockFileReader.result = 'test content';
        if (mockFileReader.onload) {
          mockFileReader.onload({ target: mockFileReader });
        }
      });

      const result = await processTxtFile(txtFile);

      // Verify DocumentData interface compliance
      expect(result).toHaveProperty('name');
      expect(result).toHaveProperty('content');
      expect(result).toHaveProperty('type');
      expect(result).toHaveProperty('originalFile');
      
      expect(typeof result.name).toBe('string');
      expect(typeof result.content).toBe('string');
      expect(typeof result.type).toBe('string');
      expect(result.originalFile).toBeInstanceOf(File);
    });
  });
}); 