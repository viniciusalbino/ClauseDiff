/**
 * Processador específico para arquivos TXT
 * Implementa IFileProcessor para processamento de texto plano
 * 
 * @class TxtProcessor
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
 * Encodings suportados para detecção automática
 */
type SupportedEncoding = 'utf-8' | 'utf-16' | 'iso-8859-1' | 'windows-1252';

/**
 * Resultado da detecção de encoding
 */
interface EncodingDetectionResult {
  encoding: SupportedEncoding;
  confidence: number;
  bom?: boolean; // Byte Order Mark detectado
}

/**
 * Processador para arquivos TXT (texto plano)
 * Implementa o princípio da Responsabilidade Única (SRP)
 */
export class TxtProcessor implements IFileProcessor {
  private readonly supportedType: SupportedFileType = 'text/plain';
  private readonly maxFileSize: number;
  private readonly timeoutMs: number;
  private readonly defaultEncoding: SupportedEncoding;

  constructor(
    maxFileSize: number = 50 * 1024 * 1024, // 50MB default
    timeoutMs: number = 10000, // 10s default (TXT é rápido)
    defaultEncoding: SupportedEncoding = 'utf-8'
  ) {
    this.maxFileSize = maxFileSize;
    this.timeoutMs = timeoutMs;
    this.defaultEncoding = defaultEncoding;
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

      // Verifica extensão do arquivo (mais flexível para TXT)
      const fileName = file.name.toLowerCase();
      const validExtensions = ['.txt', '.text', '.log', '.md', '.markdown'];
      const hasValidExtension = validExtensions.some(ext => fileName.endsWith(ext));
      
      if (!hasValidExtension) {
        throw new ProcessingError(
          `File must have a text extension (${validExtensions.join(', ')})`,
          ProcessingErrorCodes.INVALID_FILE_FORMAT,
          this.supportedType
        );
      }

      // Validação básica de conteúdo de texto
      const isValidText = await this.validateTextContent(file);
      if (!isValidText) {
        throw new ProcessingError(
          'File does not appear to contain valid text content',
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
   * Processa o arquivo TXT e extrai o conteúdo
   */
  async process(file: File, options: ProcessingOptions = {}): Promise<ProcessingResult> {
    const startTime = Date.now();
    
    try {
      // Valida o arquivo
      await this.validate(file);

      // Detecta encoding automaticamente
      const encodingResult = await this.detectEncoding(file);
      
      // Prepara metadados
      const metadata: FileMetadata = {
        name: file.name,
        size: file.size,
        type: this.supportedType,
        lastModified: file.lastModified,
        encoding: encodingResult.encoding
      };

      // Verifica timeout
      const timeoutMs = options.timeoutMs || this.timeoutMs;
      
      // Processa com timeout
      const extractionStartTime = Date.now();
      const textContent = await this.processWithTimeout(file, encodingResult.encoding, timeoutMs);
      const extractionTime = Date.now() - extractionStartTime;

      // Processa opções
      let content = textContent;
      const warnings: string[] = [];

      // Adiciona warning sobre encoding se confiança for baixa
      if (encodingResult.confidence < 0.8) {
        warnings.push(`Encoding detection confidence low (${Math.round(encodingResult.confidence * 100)}%), using ${encodingResult.encoding}`);
      }

      // Aplica limitação de caracteres se especificada
      if (options.maxCharacters && content.length > options.maxCharacters) {
        content = content.substring(0, options.maxCharacters);
        warnings.push(`Content truncated to ${options.maxCharacters} characters`);
      }

      // Verifica se foi extraído algum conteúdo
      if (!content || content.trim().length === 0) {
        throw new ProcessingError(
          'No text content could be extracted from the file',
          ProcessingErrorCodes.EXTRACTION_FAILED,
          this.supportedType
        );
      }

      // Análise básica do conteúdo
      const contentAnalysis = this.analyzeContent(content);

      const endTime = Date.now();

      return {
        status: 'completed',
        content: content.trim(),
        metadata,
        startTime,
        endTime,
        duration: endTime - startTime,
        pagesProcessed: contentAnalysis.estimatedPages,
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
        'Unexpected error during TXT processing',
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
      supportsMultiplePages: false, // TXT é um arquivo contínuo
      supportsFormatting: false, // Texto plano sem formatação
      supportsStreaming: true, // Pode ser implementado para arquivos grandes
      supportsCancellation: true, // Processamento é rápido, mas pode ser cancelado
      version: '1.0.0'
    };
  }

  /**
   * Valida se o conteúdo parece ser texto válido
   */
  private async validateTextContent(file: File): Promise<boolean> {
    try {
      // Lê uma pequena amostra do arquivo para validação
      const sampleSize = Math.min(1024, file.size); // Primeiros 1KB
      const blob = file.slice(0, sampleSize);
      const sample = await this.readBlobAsText(blob, this.defaultEncoding);
      
             // Verifica se contém principalmente caracteres imprimíveis
       const printableChars = sample.replace(/[\r\n\t\s]/g, '').length;
       const whitespaceMatches = sample.match(/[\r\n\t\s]/g);
       const nonPrintableChars = sample.length - printableChars - (whitespaceMatches?.length || 0);
      
      // Se mais de 10% são caracteres não imprimíveis, provavelmente não é texto
      const nonPrintableRatio = nonPrintableChars / sample.length;
      
      return nonPrintableRatio < 0.1;
    } catch (error) {
      return false;
    }
  }

  /**
   * Detecta o encoding do arquivo automaticamente
   */
  private async detectEncoding(file: File): Promise<EncodingDetectionResult> {
    try {
      // Lê uma amostra do arquivo para detecção
      const sampleSize = Math.min(4096, file.size); // Primeiros 4KB
      const blob = file.slice(0, sampleSize);
      const arrayBuffer = await this.readBlobAsArrayBuffer(blob);
      const bytes = new Uint8Array(arrayBuffer);

      // Verifica BOM (Byte Order Mark)
      if (bytes.length >= 3 && bytes[0] === 0xEF && bytes[1] === 0xBB && bytes[2] === 0xBF) {
        return { encoding: 'utf-8', confidence: 1.0, bom: true };
      }

      if (bytes.length >= 2 && bytes[0] === 0xFF && bytes[1] === 0xFE) {
        return { encoding: 'utf-16', confidence: 1.0, bom: true };
      }

      if (bytes.length >= 2 && bytes[0] === 0xFE && bytes[1] === 0xFF) {
        return { encoding: 'utf-16', confidence: 1.0, bom: true };
      }

      // Heurística simples para detecção de encoding
      let utf8Confidence = 0;
      let latin1Confidence = 0;

      // Verifica sequências UTF-8 válidas
      for (let i = 0; i < bytes.length; i++) {
        const byte = bytes[i];
        if (byte < 0x80) {
          utf8Confidence += 0.1; // ASCII é compatível com UTF-8
        } else if (byte >= 0xC2 && byte <= 0xDF && i + 1 < bytes.length && 
                   bytes[i + 1] >= 0x80 && bytes[i + 1] <= 0xBF) {
          utf8Confidence += 1; // Sequência UTF-8 de 2 bytes válida
          i++; // Pula o próximo byte
        } else if (byte >= 0xE0 && byte <= 0xEF && i + 2 < bytes.length &&
                   bytes[i + 1] >= 0x80 && bytes[i + 1] <= 0xBF &&
                   bytes[i + 2] >= 0x80 && bytes[i + 2] <= 0xBF) {
          utf8Confidence += 1.5; // Sequência UTF-8 de 3 bytes válida
          i += 2; // Pula os próximos bytes
        } else if (byte >= 0x80 && byte <= 0xFF) {
          latin1Confidence += 0.5; // Caracteres estendidos latinos
        }
      }

      // Normaliza confiança baseada no tamanho da amostra
      utf8Confidence = Math.min(1.0, utf8Confidence / (bytes.length * 0.1));
      latin1Confidence = Math.min(1.0, latin1Confidence / (bytes.length * 0.1));

      // Decide o encoding baseado na maior confiança
      if (utf8Confidence > latin1Confidence) {
        return { encoding: 'utf-8', confidence: utf8Confidence };
      } else if (latin1Confidence > 0.5) {
        return { encoding: 'iso-8859-1', confidence: latin1Confidence };
      } else {
        // Fallback para UTF-8 com baixa confiança
        return { encoding: 'utf-8', confidence: 0.5 };
      }

    } catch (error) {
      // Em caso de erro, usa encoding padrão
      return { encoding: this.defaultEncoding, confidence: 0.5 };
    }
  }

  /**
   * Processa com timeout
   */
  private async processWithTimeout(file: File, encoding: SupportedEncoding, timeoutMs: number): Promise<string> {
    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        reject(new ProcessingError(
          `Processing timeout after ${timeoutMs}ms`,
          ProcessingErrorCodes.PROCESSING_TIMEOUT,
          this.supportedType
        ));
      }, timeoutMs);

      this.readFileAsText(file, encoding)
        .then((text) => {
          clearTimeout(timeoutId);
          resolve(text);
        })
        .catch((error) => {
          clearTimeout(timeoutId);
          reject(new ProcessingError(
            'Failed to read text content',
            ProcessingErrorCodes.EXTRACTION_FAILED,
            this.supportedType,
            error
          ));
        });
    });
  }

  /**
   * Lê arquivo como texto com encoding específico
   */
  private readFileAsText(file: File, encoding: SupportedEncoding): Promise<string> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      
      reader.onload = (event) => {
        if (event.target?.result) {
          resolve(event.target.result as string);
        } else {
          reject(new Error('Failed to read file as text'));
        }
      };
      
      reader.onerror = () => {
        reject(new Error('FileReader error occurred'));
      };
      
      // FileReader suporta apenas algumas encodings, fallback para UTF-8
      const readerEncoding = ['utf-8', 'utf-16'].includes(encoding) ? encoding : 'utf-8';
      reader.readAsText(file, readerEncoding);
    });
  }

  /**
   * Lê blob como texto
   */
  private readBlobAsText(blob: Blob, encoding: SupportedEncoding): Promise<string> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      
      reader.onload = (event) => {
        if (event.target?.result) {
          resolve(event.target.result as string);
        } else {
          reject(new Error('Failed to read blob as text'));
        }
      };
      
      reader.onerror = () => {
        reject(new Error('FileReader error occurred'));
      };
      
      const readerEncoding = ['utf-8', 'utf-16'].includes(encoding) ? encoding : 'utf-8';
      reader.readAsText(blob, readerEncoding);
    });
  }

  /**
   * Lê blob como ArrayBuffer
   */
  private readBlobAsArrayBuffer(blob: Blob): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      
      reader.onload = (event) => {
        if (event.target?.result) {
          resolve(event.target.result as ArrayBuffer);
        } else {
          reject(new Error('Failed to read blob as ArrayBuffer'));
        }
      };
      
      reader.onerror = () => {
        reject(new Error('FileReader error occurred'));
      };
      
      reader.readAsArrayBuffer(blob);
    });
  }

  /**
   * Analisa o conteúdo para estatísticas básicas
   */
  private analyzeContent(content: string): { estimatedPages: number; lineCount: number; wordCount: number } {
    const lines = content.split('\n').length;
    const words = content.split(/\s+/).filter(word => word.length > 0).length;
    
    // Estima páginas baseado em linhas (assumindo ~25 linhas por página)
    const estimatedPages = Math.max(1, Math.ceil(lines / 25));
    
    return {
      estimatedPages,
      lineCount: lines,
      wordCount: words
    };
  }

  /**
   * Método para cancelar processamento
   */
  async cancel?(processId: string): Promise<boolean> {
    // TXT processing é geralmente muito rápido, mas pode ser cancelado
    // Para implementação futura com streaming de arquivos grandes
    return true;
  }
}

/**
 * Factory function para criar instância do TxtProcessor
 */
export function createTxtProcessor(
  maxFileSize?: number,
  timeoutMs?: number,
  defaultEncoding?: SupportedEncoding
): TxtProcessor {
  return new TxtProcessor(maxFileSize, timeoutMs, defaultEncoding);
}

/**
 * Configurações padrão para TXT
 */
export const TXT_DEFAULTS = {
  MAX_FILE_SIZE: 50 * 1024 * 1024, // 50MB
  TIMEOUT_MS: 10000, // 10 segundos
  SUPPORTED_MIME_TYPE: 'text/plain' as const,
  DEFAULT_ENCODING: 'utf-8' as const,
  ESTIMATED_LINES_PER_PAGE: 25,
  VALID_EXTENSIONS: ['.txt', '.text', '.log', '.md', '.markdown'] as const
} as const; 