/**
 * Decorator para adicionar logging automático aos processadores de arquivo
 * Implementa padrão Decorator seguindo princípios SOLID
 * 
 * @class LoggingDecorator
 * @author ClauseDiff Team
 * @version 1.0.0
 */

import { 
  IFileProcessor,
  SupportedFileType,
  ProcessingOptions,
  ProcessingResult,
  FileMetadata,
  ProcessorCapabilities,
  ProcessingError,
  ProcessingErrorCodes
} from '../../domain/interfaces/IFileProcessor';

/**
 * Níveis de log disponíveis
 */
export enum LogLevel {
  DEBUG = 'debug',
  INFO = 'info',
  WARN = 'warn',
  ERROR = 'error'
}

/**
 * Configurações do logger
 */
export interface LoggerConfig {
  /** Nível mínimo de log */
  level: LogLevel;
  /** Se deve incluir timestamp */
  includeTimestamp: boolean;
  /** Se deve incluir stack trace em erros */
  includeStackTrace: boolean;
  /** Formatação personalizada de mensagens */
  formatter?: LogFormatter;
  /** Transports personalizados */
  transports?: LogTransport[];
  /** Contexto adicional a ser incluído em todos os logs */
  context?: Record<string, any>;
  /** Se deve fazer log de métricas de performance */
  logPerformanceMetrics: boolean;
  /** Se deve fazer log do conteúdo extraído (cuidado com dados sensíveis) */
  logExtractedContent: boolean;
  /** Tamanho máximo do conteúdo a ser logado */
  maxContentLength: number;
}

/**
 * Formatador de mensagens de log
 */
export type LogFormatter = (
  level: LogLevel,
  message: string,
  metadata: LogMetadata
) => string;

/**
 * Transport para envio de logs
 */
export interface LogTransport {
  /** Nome do transport */
  name: string;
  /** Função para enviar log */
  log: (level: LogLevel, message: string, metadata: LogMetadata) => void | Promise<void>;
  /** Nível mínimo para este transport */
  level?: LogLevel;
}

/**
 * Metadados do log
 */
export interface LogMetadata {
  /** Timestamp do log */
  timestamp: string;
  /** ID do processamento */
  processingId?: string;
  /** Tipo de arquivo sendo processado */
  fileType?: SupportedFileType;
  /** Nome do arquivo */
  fileName?: string;
  /** Tamanho do arquivo */
  fileSize?: number;
  /** Duração da operação em ms */
  duration?: number;
  /** Erro associado (se houver) */
  error?: ProcessingError;
  /** Contexto adicional */
  context?: Record<string, any>;
  /** Métricas de performance */
  metrics?: Record<string, number>;
  /** Stack trace (para erros) */
  stackTrace?: string;
}

/**
 * Decorator que adiciona logging automático aos processadores
 * Implementa o padrão Decorator preservando a interface original
 */
export class LoggingDecorator implements IFileProcessor {
  private readonly processor: IFileProcessor;
  private readonly config: LoggerConfig;
  private readonly processingId: string;
  private readonly startTimes: Map<string, number> = new Map();

  constructor(
    processor: IFileProcessor,
    config: Partial<LoggerConfig> = {}
  ) {
    this.processor = processor;
    this.processingId = `log_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    // Configurações padrão
    this.config = {
      level: LogLevel.INFO,
      includeTimestamp: true,
      includeStackTrace: true,
      logPerformanceMetrics: true,
      logExtractedContent: false,
      maxContentLength: 500,
      transports: [new ConsoleTransport()],
      ...config
    };

    this.log(LogLevel.INFO, 'LoggingDecorator initialized', {
      context: {
        processorType: processor.constructor.name,
        config: this.sanitizeConfig(this.config)
      }
    });
  }

  /**
   * Processa arquivo com logging automático
   */
  async process(
    file: File,
    options: ProcessingOptions = {}
  ): Promise<ProcessingResult> {
    const operationId = `process_${Date.now()}`;
    this.startTimer(operationId);

    const baseMetadata: LogMetadata = {
      timestamp: new Date().toISOString(),
      processingId: this.processingId,
      fileType: file.type as SupportedFileType,
      fileName: file.name,
      fileSize: file.size,
      context: { 
        options,
        ...this.config.context 
      }
    };

    this.log(LogLevel.INFO, 'Starting file processing', {
      ...baseMetadata,
      metrics: {
        fileSize: file.size,
        fileLastModified: file.lastModified
      }
    });

    try {
      // Log início da validação
      this.log(LogLevel.DEBUG, 'Starting file validation', baseMetadata);

      // Executa processamento real
      const result = await this.processor.process(file, options);

      // Calcula métricas de performance
      const duration = this.endTimer(operationId);
      const performanceMetrics = this.calculatePerformanceMetrics(result, duration, file.size);

      this.log(LogLevel.INFO, 'File processing completed successfully', {
        ...baseMetadata,
        duration,
        metrics: performanceMetrics
      });

      // Log de conteúdo extraído (se habilitado)
      if (this.config.logExtractedContent && result.content) {
        const contentPreview = this.truncateContent(result.content, this.config.maxContentLength);
        this.log(LogLevel.DEBUG, 'Extracted content preview', {
          ...baseMetadata,
          context: {
            ...baseMetadata.context,
            contentLength: result.content.length,
            contentPreview
          }
        });
      }

      // Log de métricas detalhadas
      if (this.config.logPerformanceMetrics) {
        this.log(LogLevel.INFO, 'Performance metrics', {
          ...baseMetadata,
          duration,
          metrics: {
            ...performanceMetrics,
            duration: result.duration,
            pagesProcessed: result.pagesProcessed || 0,
            startTime: result.startTime,
            endTime: result.endTime
          }
        });
      }

      return result;

    } catch (error) {
      const duration = this.endTimer(operationId);
      const processingError = error instanceof ProcessingError ? error : new ProcessingError(
        `Processing failed: ${error}`,
        ProcessingErrorCodes.EXTRACTION_FAILED,
        file.type
      );

      this.log(LogLevel.ERROR, 'File processing failed', {
        ...baseMetadata,
        duration,
        error: processingError,
        stackTrace: this.config.includeStackTrace ? processingError.stack : undefined
      });

      throw processingError;
    }
  }

  /**
   * Valida arquivo com logging
   */
  async validate(fileBuffer: Buffer, fileMetadata: FileMetadata): Promise<boolean> {
    const operationId = `validate_${Date.now()}`;
    this.startTimer(operationId);

    const baseMetadata: LogMetadata = {
      timestamp: new Date().toISOString(),
      processingId: this.processingId,
      fileType: fileMetadata.mimeType as SupportedFileType,
      fileName: fileMetadata.fileName,
      fileSize: fileMetadata.size,
      context: this.config.context
    };

    this.log(LogLevel.DEBUG, 'Starting file validation', baseMetadata);

    try {
      const isValid = await this.processor.validate(fileBuffer, fileMetadata);
      const duration = this.endTimer(operationId);

      this.log(LogLevel.INFO, `File validation ${isValid ? 'passed' : 'failed'}`, {
        ...baseMetadata,
        duration,
        context: {
          ...baseMetadata.context,
          validationResult: isValid
        }
      });

      return isValid;

    } catch (error) {
      const duration = this.endTimer(operationId);
      const validationError = error instanceof ProcessingError ? error : new ProcessingError(
        `Validation failed: ${error}`,
        ProcessingErrorCodes.INVALID_FILE_FORMAT,
        fileMetadata.mimeType
      );

      this.log(LogLevel.ERROR, 'File validation failed', {
        ...baseMetadata,
        duration,
        error: validationError,
        stackTrace: this.config.includeStackTrace ? validationError.stack : undefined
      });

      throw validationError;
    }
  }

  /**
   * Obtém capacidades do processador com logging
   */
  getCapabilities(): ProcessorCapabilities {
    this.log(LogLevel.DEBUG, 'Getting processor capabilities', {
      timestamp: new Date().toISOString(),
      processingId: this.processingId,
      context: this.config.context
    });

    const capabilities = this.processor.getCapabilities();

    this.log(LogLevel.DEBUG, 'Processor capabilities retrieved', {
      timestamp: new Date().toISOString(),
      processingId: this.processingId,
      context: {
        ...this.config.context,
        capabilities
      }
    });

    return capabilities;
  }

  /**
   * Obtém tipos suportados com logging
   */
  getSupportedTypes(): SupportedFileType[] {
    this.log(LogLevel.DEBUG, 'Getting supported types', {
      timestamp: new Date().toISOString(),
      processingId: this.processingId,
      context: this.config.context
    });

    const supportedTypes = this.processor.getSupportedTypes();

    this.log(LogLevel.DEBUG, 'Supported types retrieved', {
      timestamp: new Date().toISOString(),
      processingId: this.processingId,
      context: {
        ...this.config.context,
        supportedTypes
      }
    });

    return supportedTypes;
  }

  /**
   * Atualiza configuração do logger
   */
  updateConfig(newConfig: Partial<LoggerConfig>): void {
    Object.assign(this.config, newConfig);
    
    this.log(LogLevel.INFO, 'Logger configuration updated', {
      timestamp: new Date().toISOString(),
      processingId: this.processingId,
      context: {
        newConfig: this.sanitizeConfig(newConfig),
        fullConfig: this.sanitizeConfig(this.config)
      }
    });
  }

  /**
   * Adiciona transport de log
   */
  addTransport(transport: LogTransport): void {
    if (!this.config.transports) {
      this.config.transports = [];
    }
    
    this.config.transports.push(transport);
    
    this.log(LogLevel.INFO, 'Log transport added', {
      timestamp: new Date().toISOString(),
      processingId: this.processingId,
      context: {
        transportName: transport.name,
        totalTransports: this.config.transports.length
      }
    });
  }

  /**
   * Remove transport de log
   */
  removeTransport(transportName: string): boolean {
    if (!this.config.transports) {
      return false;
    }

    const initialLength = this.config.transports.length;
    this.config.transports = this.config.transports.filter(t => t.name !== transportName);
    const removed = this.config.transports.length < initialLength;

    if (removed) {
      this.log(LogLevel.INFO, 'Log transport removed', {
        timestamp: new Date().toISOString(),
        processingId: this.processingId,
        context: {
          transportName,
          remainingTransports: this.config.transports.length
        }
      });
    }

    return removed;
  }

  /**
   * Obtém estatísticas de logging
   */
  getLoggingStatistics(): Record<string, any> {
    return {
      processingId: this.processingId,
      config: this.sanitizeConfig(this.config),
      activeTimers: Array.from(this.startTimes.keys()),
      transports: this.config.transports?.map(t => ({ 
        name: t.name, 
        level: t.level || 'inherited' 
      })) || []
    };
  }

  /**
   * Inicia timer para operação
   */
  private startTimer(operationId: string): void {
    this.startTimes.set(operationId, Date.now());
  }

  /**
   * Finaliza timer e retorna duração
   */
  private endTimer(operationId: string): number {
    const startTime = this.startTimes.get(operationId);
    if (!startTime) {
      return 0;
    }
    
    this.startTimes.delete(operationId);
    return Date.now() - startTime;
  }

  /**
   * Calcula métricas de performance
   */
  private calculatePerformanceMetrics(
    result: ProcessingResult,
    duration: number,
    fileSize: number
  ): Record<string, number> {
    const metrics: Record<string, number> = {
      duration,
      fileSize,
      bytesPerSecond: duration > 0 ? fileSize / (duration / 1000) : 0
    };

    if (result.metadata.totalPages) {
      metrics.pagesPerMinute = duration > 0 ? (result.metadata.totalPages / duration) * 60000 : 0;
    }

    if (result.metadata.wordCount) {
      metrics.wordsPerSecond = duration > 0 ? result.metadata.wordCount / (duration / 1000) : 0;
    }

    if (result.extractedText) {
      metrics.charactersPerSecond = duration > 0 ? result.extractedText.length / (duration / 1000) : 0;
    }

    return metrics;
  }

  /**
   * Trunca conteúdo para log
   */
  private truncateContent(content: string, maxLength: number): string {
    if (content.length <= maxLength) {
      return content;
    }
    
    return content.substring(0, maxLength) + '... (truncated)';
  }

  /**
   * Remove dados sensíveis da configuração para log
   */
  private sanitizeConfig(config: Partial<LoggerConfig>): Record<string, any> {
    const sanitized = { ...config };
    
    // Remove transports do log (podem conter dados sensíveis)
    if (sanitized.transports) {
      sanitized.transports = sanitized.transports.map(t => ({ 
        name: t.name, 
        level: t.level || 'inherited' 
      }));
    }

    return sanitized;
  }

  /**
   * Envia log para todos os transports
   */
  private log(level: LogLevel, message: string, metadata: Partial<LogMetadata> = {}): void {
    if (!this.shouldLog(level)) {
      return;
    }

    const fullMetadata: LogMetadata = {
      timestamp: new Date().toISOString(),
      processingId: this.processingId,
      ...metadata
    };

    const formattedMessage = this.config.formatter 
      ? this.config.formatter(level, message, fullMetadata)
      : this.formatMessage(level, message, fullMetadata);

    // Envia para todos os transports
    this.config.transports?.forEach(transport => {
      if (!transport.level || this.shouldLogForLevel(level, transport.level)) {
        try {
          transport.log(level, formattedMessage, fullMetadata);
        } catch (error) {
          console.error(`Error in log transport ${transport.name}:`, error);
        }
      }
    });
  }

  /**
   * Verifica se deve fazer log baseado no nível
   */
  private shouldLog(level: LogLevel): boolean {
    return this.shouldLogForLevel(level, this.config.level);
  }

  /**
   * Verifica se deve fazer log para um nível específico
   */
  private shouldLogForLevel(messageLevel: LogLevel, configLevel: LogLevel): boolean {
    const levels = [LogLevel.DEBUG, LogLevel.INFO, LogLevel.WARN, LogLevel.ERROR];
    return levels.indexOf(messageLevel) >= levels.indexOf(configLevel);
  }

  /**
   * Formata mensagem de log padrão
   */
  private formatMessage(level: LogLevel, message: string, metadata: LogMetadata): string {
    const timestamp = this.config.includeTimestamp ? `[${metadata.timestamp}] ` : '';
    const levelStr = `[${level.toUpperCase()}] `;
    const processingId = `[${metadata.processingId}] `;
    const fileInfo = metadata.fileName ? `[${metadata.fileName}] ` : '';
    
    return `${timestamp}${levelStr}${processingId}${fileInfo}${message}`;
  }
}

/**
 * Transport padrão para console
 */
export class ConsoleTransport implements LogTransport {
  readonly name = 'console';
  
  log(level: LogLevel, message: string, metadata: LogMetadata): void {
    const logMethod = this.getConsoleMethod(level);
    logMethod(message);
    
    // Log metadata em debug mode
    if (level === LogLevel.DEBUG && metadata.context) {
      console.debug('Metadata:', metadata);
    }
  }

  private getConsoleMethod(level: LogLevel): (...args: any[]) => void {
    switch (level) {
      case LogLevel.ERROR:
        return console.error;
      case LogLevel.WARN:
        return console.warn;
      case LogLevel.DEBUG:
        return console.debug;
      default:
        return console.log;
    }
  }
}

/**
 * Transport para arquivo (exemplo de implementação)
 */
export class FileTransport implements LogTransport {
  readonly name = 'file';
  private readonly filePath: string;

  constructor(filePath: string) {
    this.filePath = filePath;
  }

  async log(level: LogLevel, message: string, metadata: LogMetadata): Promise<void> {
    // Implementação seria feita com fs.appendFile ou biblioteca de logging
    // Por enquanto, apenas um exemplo da interface
    const logEntry = {
      timestamp: metadata.timestamp,
      level,
      message,
      metadata
    };
    
    // Em uma implementação real:
    // await fs.appendFile(this.filePath, JSON.stringify(logEntry) + '\n');
    console.log(`Would write to ${this.filePath}:`, JSON.stringify(logEntry));
  }
}

/**
 * Factory function para criar LoggingDecorator
 */
export function withLogging(
  processor: IFileProcessor,
  config?: Partial<LoggerConfig>
): LoggingDecorator {
  return new LoggingDecorator(processor, config);
}

/**
 * Configurações padrão do logger
 */
export const LOGGING_DEFAULTS = {
  LEVEL: LogLevel.INFO,
  INCLUDE_TIMESTAMP: true,
  INCLUDE_STACK_TRACE: true,
  LOG_PERFORMANCE_METRICS: true,
  LOG_EXTRACTED_CONTENT: false,
  MAX_CONTENT_LENGTH: 500
} as const; 