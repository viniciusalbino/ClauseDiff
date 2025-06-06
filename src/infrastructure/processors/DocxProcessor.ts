/**
 * Processador específico para arquivos DOCX
 * Implementa IFileProcessor usando mammoth.js para extração de texto
 * 
 * @class DocxProcessor
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

import * as mammoth from 'mammoth';

/**
 * Interface para mammoth.js
 */
interface MammothResult {
  value: string;
  messages: Array<{
    type: string;
    message: string;
  }>;
}

interface MammothApi {
  extractRawText(options: { arrayBuffer: ArrayBuffer }): Promise<MammothResult>;
  extractRawText(options: { buffer: Buffer }): Promise<MammothResult>;
}

/**
 * Processador para arquivos DOCX usando mammoth.js
 * Implementa o princípio da Responsabilidade Única (SRP)
 */
export class DocxProcessor implements IFileProcessor {
  private readonly supportedType: SupportedFileType = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
  private readonly maxFileSize: number;
  private readonly timeoutMs: number;
  private mammoth: MammothApi | null = null;

  constructor(
    maxFileSize: number = 50 * 1024 * 1024, // 50MB default
    timeoutMs: number = 30000 // 30s default
  ) {
    this.maxFileSize = maxFileSize;
    this.timeoutMs = timeoutMs;
    this.initializeMammoth();
  }

  /**
   * Inicializa o mammoth.js
   */
  private async initializeMammoth(): Promise<void> {
    try {
      // Use the imported mammoth directly
      this.mammoth = mammoth as any;
    } catch (error) {
      console.error('Failed to initialize mammoth:', error);
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
      // Verifica se mammoth está disponível
      if (!this.mammoth) {
                 throw new ProcessingError(
           'Mammoth.js not available for DOCX processing',
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
      if (!fileName.endsWith('.docx')) {
        throw new ProcessingError(
          'File must have .docx extension',
          ProcessingErrorCodes.INVALID_FILE_FORMAT,
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
   * Processa o arquivo DOCX e extrai o conteúdo
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
      const result = await this.processWithTimeout(arrayBuffer, timeoutMs);
      const extractionTime = Date.now() - extractionStartTime;

      // Processa opções
      let content = result.value;
      const warnings: string[] = [];

      // Aplica limitação de caracteres se especificada
      if (options.maxCharacters && content.length > options.maxCharacters) {
        content = content.substring(0, options.maxCharacters);
        warnings.push(`Content truncated to ${options.maxCharacters} characters`);
      }

      // Adiciona warnings do mammoth
      if (result.messages && result.messages.length > 0) {
        result.messages.forEach(msg => {
          if (msg.type === 'warning') {
            warnings.push(`Mammoth warning: ${msg.message}`);
          }
        });
      }

      // Verifica se foi extraído algum conteúdo
      if (!content || content.trim().length === 0) {
        throw new ProcessingError(
          'No text content could be extracted from the DOCX file',
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
        pagesProcessed: this.estimatePages(content),
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
        'Unexpected error during DOCX processing',
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
      supportsFormatting: false, // mammoth extractRawText remove formatação
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
   * Processa com timeout
   */
  private async processWithTimeout(arrayBuffer: ArrayBuffer, timeoutMs: number): Promise<MammothResult> {
    if (!this.mammoth) {
             throw new ProcessingError(
         'Mammoth.js not initialized',
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

      this.mammoth!.extractRawText({ arrayBuffer })
        .then((result) => {
          clearTimeout(timeoutId);
          resolve(result);
        })
        .catch((error) => {
          clearTimeout(timeoutId);
          reject(new ProcessingError(
            'Failed to extract text from DOCX',
            ProcessingErrorCodes.EXTRACTION_FAILED,
            this.supportedType,
            error
          ));
        });
    });
  }

  /**
   * Estima número de páginas baseado no conteúdo
   */
  private estimatePages(content: string): number {
    // Estimativa simples: ~500 palavras por página
    const wordCount = content.split(/\s+/).length;
    return Math.max(1, Math.ceil(wordCount / 500));
  }

  /**
   * Método para cancelar processamento (não implementado para DOCX)
   */
  async cancel?(processId: string): Promise<boolean> {
    // DOCX processing é geralmente rápido, cancelamento não implementado
    return false;
  }
}

/**
 * Factory function para criar instância do DocxProcessor
 */
export function createDocxProcessor(
  maxFileSize?: number,
  timeoutMs?: number
): DocxProcessor {
  return new DocxProcessor(maxFileSize, timeoutMs);
}

/**
 * Configurações padrão para DOCX
 */
export const DOCX_DEFAULTS = {
  MAX_FILE_SIZE: 50 * 1024 * 1024, // 50MB
  TIMEOUT_MS: 30000, // 30 segundos
  SUPPORTED_MIME_TYPE: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' as const,
  ESTIMATED_WORDS_PER_PAGE: 500
} as const; 