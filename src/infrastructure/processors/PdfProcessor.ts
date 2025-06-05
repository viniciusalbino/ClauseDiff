/**
 * Processador específico para arquivos PDF
 * Implementa IFileProcessor usando PDF.js para extração de texto
 * 
 * @class PdfProcessor
 * @implements {IFileProcessor}
 * @author ClauseDiff Team
 * @version 1.0.0
 */

import { 
  IFileProcessor, 
  ProcessingOptions, 
  ProcessingResult, 
  ProcessorCapabilities, 
  SupportedFileType,
  ProcessingError,
  ProcessingErrorCodes,
  FileMetadata
} from '../../domain/interfaces/IFileProcessor';

/**
 * Interface para PDF.js
 */
interface PdfJsPage {
  pageNumber: number;
  getTextContent(): Promise<PdfJsTextContent>;
}

interface PdfJsTextContent {
  items: Array<{
    str: string;
    transform: number[];
    width: number;
    height: number;
    dir: string;
    fontName: string;
  }>;
}

interface PdfJsDocument {
  numPages: number;
  getPage(pageNumber: number): Promise<PdfJsPage>;
}

interface PdfJsApi {
  getDocument(options: { data: ArrayBuffer }): {
    promise: Promise<PdfJsDocument>;
  };
  GlobalWorkerOptions: {
    workerSrc: string;
  };
}

/**
 * Processador para arquivos PDF usando PDF.js
 * Implementa o princípio da Responsabilidade Única (SRP)
 */
export class PdfProcessor implements IFileProcessor {
  private readonly supportedType: SupportedFileType = 'application/pdf';
  private readonly maxFileSize: number;
  private readonly timeoutMs: number;
  private readonly workerSrc: string;
  private pdfjs: PdfJsApi | null = null;

  constructor(
    maxFileSize: number = 50 * 1024 * 1024, // 50MB default
    timeoutMs: number = 60000, // 60s default (PDF processing pode ser mais lento)
    workerSrc: string = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js'
  ) {
    this.maxFileSize = maxFileSize;
    this.timeoutMs = timeoutMs;
    this.workerSrc = workerSrc;
    this.initializePdfJs();
  }

  /**
   * Inicializa o PDF.js
   */
  private async initializePdfJs(): Promise<void> {
    try {
      // Verifica se PDF.js está disponível globalmente (browser)
      if (typeof window !== 'undefined' && (window as any).pdfjsLib) {
        this.pdfjs = (window as any).pdfjsLib;
        
                 // Configura worker se não estiver configurado
         if (this.pdfjs && !this.pdfjs.GlobalWorkerOptions.workerSrc) {
           this.pdfjs.GlobalWorkerOptions.workerSrc = this.workerSrc;
         }
        return;
      }

      // Para ambientes Node.js, PDF.js deve ser fornecido externamente
      console.warn('PDF.js not available globally, PDF processing will not work');
    } catch (error) {
      console.error('Failed to initialize PDF.js:', error);
    }
  }

  /**
   * Verifica se pode processar o tipo de arquivo
   */
  canProcess(fileType: string): boolean {
    return fileType === this.supportedType;
  }

  /**
   * Valida o arquivo antes do processamento
   */
  async validate(file: File): Promise<boolean> {
    try {
      // Verifica se PDF.js está disponível
      if (!this.pdfjs) {
        throw new ProcessingError(
          'PDF.js not available for PDF processing',
          ProcessingErrorCodes.EXTRACTION_FAILED,
          this.supportedType
        );
      }

      // Verifica tipo MIME
      if (!this.canProcess(file.type)) {
        throw new ProcessingError(
          `Unsupported file type: ${file.type}`,
          ProcessingErrorCodes.UNSUPPORTED_FILE_TYPE,
          file.type
        );
      }

      // Verifica tamanho
      if (file.size > this.maxFileSize) {
        throw new ProcessingError(
          `File too large: ${file.size} bytes (max: ${this.maxFileSize})`,
          ProcessingErrorCodes.FILE_TOO_LARGE,
          this.supportedType
        );
      }

      // Verifica se o arquivo não está vazio
      if (file.size === 0) {
        throw new ProcessingError(
          'File is empty',
          ProcessingErrorCodes.INVALID_FILE_FORMAT,
          this.supportedType
        );
      }

      // Verifica extensão do arquivo
      const fileName = file.name.toLowerCase();
      if (!fileName.endsWith('.pdf')) {
        throw new ProcessingError(
          'File must have .pdf extension',
          ProcessingErrorCodes.INVALID_FILE_FORMAT,
          this.supportedType
        );
      }

      // Validação básica de header PDF (deve começar com %PDF)
      const header = await this.readFileHeader(file);
      if (!header.startsWith('%PDF')) {
        throw new ProcessingError(
          'Invalid PDF file format - missing PDF header',
          ProcessingErrorCodes.FILE_CORRUPTED,
          this.supportedType
        );
      }

      return true;
    } catch (error) {
      if (error instanceof ProcessingError) {
        throw error;
      }
      throw new ProcessingError(
        'Validation failed',
        ProcessingErrorCodes.VALIDATION_FAILED,
        this.supportedType,
        error as Error
      );
    }
  }

  /**
   * Processa o arquivo PDF e extrai o conteúdo
   */
  async process(file: File, options: ProcessingOptions = {}): Promise<ProcessingResult> {
    const startTime = Date.now();
    
    try {
      // Valida o arquivo
      await this.validate(file);

      // Prepara metadados
      const metadata: FileMetadata = {
        name: file.name,
        size: file.size,
        type: this.supportedType,
        lastModified: file.lastModified
      };

      // Lê o arquivo como ArrayBuffer
      const arrayBuffer = await this.readFileAsArrayBuffer(file);
      
      // Verifica timeout
      const timeoutMs = options.timeoutMs || this.timeoutMs;
      
      // Processa com timeout
      const extractionStartTime = Date.now();
      const extractedText = await this.processWithTimeout(arrayBuffer, timeoutMs);
      const extractionTime = Date.now() - extractionStartTime;

      // Processa opções
      let content = extractedText.text;
      const warnings: string[] = [...extractedText.warnings];

      // Aplica limitação de caracteres se especificada
      if (options.maxCharacters && content.length > options.maxCharacters) {
        content = content.substring(0, options.maxCharacters);
        warnings.push(`Content truncated to ${options.maxCharacters} characters`);
      }

      // Verifica se foi extraído algum conteúdo
      if (!content || content.trim().length === 0) {
        throw new ProcessingError(
          'No text content could be extracted from the PDF file',
          ProcessingErrorCodes.EXTRACTION_FAILED,
          this.supportedType
        );
      }

      const endTime = Date.now();

      return {
        status: 'completed',
        content: content.trim(),
        metadata,
        startTime,
        endTime,
        duration: endTime - startTime,
        pagesProcessed: extractedText.pagesProcessed,
        warnings: warnings.length > 0 ? warnings : undefined
      };

    } catch (error) {
      const endTime = Date.now();
      
      if (error instanceof ProcessingError) {
        return {
          status: 'failed',
          content: '',
          metadata: {
            name: file.name,
            size: file.size,
            type: this.supportedType,
            lastModified: file.lastModified
          },
          startTime,
          endTime,
          duration: endTime - startTime,
          error: error.message,
          stackTrace: error.stack
        };
      }

      // Erro não esperado
      const processingError = new ProcessingError(
        'Unexpected error during PDF processing',
        ProcessingErrorCodes.EXTRACTION_FAILED,
        this.supportedType,
        error as Error
      );

      return {
        status: 'failed',
        content: '',
        metadata: {
          name: file.name,
          size: file.size,
          type: this.supportedType,
          lastModified: file.lastModified
        },
        startTime,
        endTime,
        duration: endTime - startTime,
        error: processingError.message,
        stackTrace: processingError.stack
      };
    }
  }

  /**
   * Obtém as capacidades do processador
   */
  getCapabilities(): ProcessorCapabilities {
    return {
      supportedTypes: [this.supportedType],
      maxFileSize: this.maxFileSize,
      supportsMultiplePages: true,
      supportsFormatting: false, // PDF.js extrai apenas texto
      supportsStreaming: false,
      supportsCancellation: false,
      version: '1.0.0'
    };
  }

  /**
   * Lê arquivo como ArrayBuffer
   */
  private readFileAsArrayBuffer(file: File): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      
      reader.onload = (event) => {
        if (event.target?.result) {
          resolve(event.target.result as ArrayBuffer);
        } else {
          reject(new Error('Failed to read file as ArrayBuffer'));
        }
      };
      
      reader.onerror = () => {
        reject(new Error('FileReader error occurred'));
      };
      
      reader.readAsArrayBuffer(file);
    });
  }

  /**
   * Lê o header do arquivo para validação
   */
  private readFileHeader(file: File): Promise<string> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      const blob = file.slice(0, 8); // Primeiros 8 bytes para %PDF-1.x
      
      reader.onload = (event) => {
        if (event.target?.result) {
          const text = new TextDecoder().decode(event.target.result as ArrayBuffer);
          resolve(text);
        } else {
          reject(new Error('Failed to read file header'));
        }
      };
      
      reader.onerror = () => {
        reject(new Error('FileReader error occurred'));
      };
      
      reader.readAsArrayBuffer(blob);
    });
  }

  /**
   * Processa com timeout
   */
  private async processWithTimeout(
    arrayBuffer: ArrayBuffer, 
    timeoutMs: number
  ): Promise<{ text: string; pagesProcessed: number; warnings: string[] }> {
    if (!this.pdfjs) {
      throw new ProcessingError(
        'PDF.js not initialized',
        ProcessingErrorCodes.EXTRACTION_FAILED,
        this.supportedType
      );
    }

    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        reject(new ProcessingError(
          `Processing timeout after ${timeoutMs}ms`,
          ProcessingErrorCodes.PROCESSING_TIMEOUT,
          this.supportedType
        ));
      }, timeoutMs);

      this.extractTextFromPdf(arrayBuffer)
        .then((result) => {
          clearTimeout(timeoutId);
          resolve(result);
        })
        .catch((error) => {
          clearTimeout(timeoutId);
          reject(new ProcessingError(
            'Failed to extract text from PDF',
            ProcessingErrorCodes.EXTRACTION_FAILED,
            this.supportedType,
            error
          ));
        });
    });
  }

  /**
   * Extrai texto do PDF usando PDF.js
   */
  private async extractTextFromPdf(
    arrayBuffer: ArrayBuffer
  ): Promise<{ text: string; pagesProcessed: number; warnings: string[] }> {
    if (!this.pdfjs) {
      throw new Error('PDF.js not available');
    }

    const warnings: string[] = [];
    let fullText = '';
    let pagesProcessed = 0;

    try {
      // Carrega o documento PDF
      const pdfDoc = await this.pdfjs.getDocument({ data: arrayBuffer }).promise;
      const totalPages = pdfDoc.numPages;

      // Processa cada página
      for (let pageNum = 1; pageNum <= totalPages; pageNum++) {
        try {
          const page = await pdfDoc.getPage(pageNum);
          const textContent = await page.getTextContent();
          
          // Extrai texto dos items
          const pageText = textContent.items
            .map((item: any) => item.str)
            .join(' ');
          
          if (pageText.trim()) {
            fullText += pageText + '\n';
          } else {
            warnings.push(`Page ${pageNum} appears to be empty or contains no text`);
          }
          
          pagesProcessed++;
        } catch (pageError) {
          warnings.push(`Failed to process page ${pageNum}: ${pageError}`);
          // Continua processando outras páginas
        }
      }

      // Verifica se processou pelo menos uma página
      if (pagesProcessed === 0) {
        throw new Error('No pages could be processed from the PDF');
      }

      // Adiciona warning se nem todas as páginas foram processadas
      if (pagesProcessed < totalPages) {
        warnings.push(`Only ${pagesProcessed} of ${totalPages} pages were successfully processed`);
      }

      return {
        text: fullText.trim(),
        pagesProcessed,
        warnings
      };

    } catch (error) {
      throw new Error(`PDF processing failed: ${error}`);
    }
  }

  /**
   * Método para cancelar processamento (não implementado para PDF)
   */
  async cancel?(processId: string): Promise<boolean> {
    // PDF processing pode ser longo, mas cancelamento não implementado ainda
    return false;
  }
}

/**
 * Factory function para criar instância do PdfProcessor
 */
export function createPdfProcessor(
  maxFileSize?: number,
  timeoutMs?: number,
  workerSrc?: string
): PdfProcessor {
  return new PdfProcessor(maxFileSize, timeoutMs, workerSrc);
}

/**
 * Configurações padrão para PDF
 */
export const PDF_DEFAULTS = {
  MAX_FILE_SIZE: 50 * 1024 * 1024, // 50MB
  TIMEOUT_MS: 60000, // 60 segundos
  SUPPORTED_MIME_TYPE: 'application/pdf' as const,
  WORKER_SRC: 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js',
  ESTIMATED_WORDS_PER_PAGE: 300 // PDFs geralmente têm menos palavras por página
} as const; 