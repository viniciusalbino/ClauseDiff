/**
 * Serviço principal para orquestração de processamento de arquivos
 * Implementa padrão Facade e Orchestrator seguindo princípios SOLID
 * 
 * @class FileProcessingService
 * @author ClauseDiff Team
 * @version 1.0.0
 */

import { 
  IFileProcessor,
  SupportedFileType, 
  ProcessingOptions,
  ProcessingResult,
  ProcessingStatus,
  FileMetadata,
  ProcessingError,
  ProcessingErrorCodes
} from '../interfaces/IFileProcessor';

import { IStorageProvider } from '../interfaces/IStorageProvider';
import { FileProcessingResult } from '../entities/FileProcessingResult';
import { FileProcessorFactory, getFileProcessorFactory } from '../../infrastructure/factories/FileProcessorFactory';

/**
 * Configurações do serviço de processamento
 */
export interface ProcessingServiceConfig {
  /** Tamanho máximo global de arquivo (bytes) */
  maxFileSize?: number;
  /** Timeout global para processamento (ms) */
  timeoutMs?: number;
  /** Provider de storage a ser usado */
  storageProvider?: IStorageProvider;
  /** Se deve fazer upload automático após processamento */
  autoUpload?: boolean;
  /** Se deve manter histórico de processamento */
  keepHistory?: boolean;
  /** Configurações específicas por tipo de arquivo */
  processorConfigs?: Record<SupportedFileType, any>;
  /** Se deve validar arquivos antes do processamento */
  enableValidation?: boolean;
  /** Configurações de retry */
  retryConfig?: RetryConfig;
}

/**
 * Configurações de retry
 */
interface RetryConfig {
  /** Máximo de tentativas */
  maxAttempts: number;
  /** Delay inicial em ms */
  initialDelay: number;
  /** Multiplicador para exponential backoff */
  backoffMultiplier: number;
  /** Delay máximo em ms */
  maxDelay: number;
  /** Códigos de erro que devem ser retentados */
  retryableErrors: ProcessingErrorCodes[];
}

/**
 * Contexto de processamento
 */
interface ProcessingContext {
  /** ID único do processamento */
  id: string;
  /** Metadados do arquivo */
  fileMetadata: FileMetadata;
  /** Opções de processamento */
  options: ProcessingOptions;
  /** Timestamp de início */
  startTime: number;
  /** Tentativa atual */
  currentAttempt: number;
  /** Histórico de tentativas */
  attemptHistory: ProcessingAttempt[];
}

/**
 * Informações de uma tentativa de processamento
 */
interface ProcessingAttempt {
  /** Número da tentativa */
  attempt: number;
  /** Timestamp de início */
  startTime: number;
  /** Timestamp de fim */
  endTime?: number;
  /** Status da tentativa */
  status: ProcessingStatus;
  /** Erro ocorrido (se houver) */
  error?: ProcessingError;
  /** Duração em ms */
  duration?: number;
}

/**
 * Resultado detalhado do processamento
 */
export interface DetailedProcessingResult extends ProcessingResult {
  /** Contexto do processamento */
  context: ProcessingContext;
  /** Resultado da entidade */
  entityResult: FileProcessingResult;
  /** URL de download (se disponível) */
  downloadUrl?: string;
  /** Métricas de performance */
  performanceMetrics: PerformanceMetrics;
}

/**
 * Métricas de performance
 */
interface PerformanceMetrics {
  /** Tempo total de processamento (ms) */
  totalDuration: number;
  /** Tempo de validação (ms) */
  validationDuration?: number;
  /** Tempo de processamento efetivo (ms) */
  processingDuration: number;
  /** Tempo de upload (ms) */
  uploadDuration?: number;
  /** Tamanho do arquivo processado (bytes) */
  fileSize: number;
  /** Páginas por minuto processadas */
  pagesPerMinute?: number;
  /** Palavras por segundo processadas */
  wordsPerSecond?: number;
}

/**
 * Eventos do processamento
 */
export type ProcessingEvent = 
  | 'processing-started'
  | 'validation-completed'
  | 'processing-progress'
  | 'processing-completed'
  | 'upload-started'
  | 'upload-progress'
  | 'upload-completed'
  | 'processing-failed'
  | 'retry-attempted';

/**
 * Callback para eventos de processamento
 */
export type ProcessingEventCallback = (
  event: ProcessingEvent,
  data: any,
  context: ProcessingContext
) => void;

/**
 * Serviço principal de processamento de arquivos
 * Implementa padrão Facade para coordenar todo o fluxo
 */
export class FileProcessingService {
  private readonly factory: FileProcessorFactory;
  private readonly config: Required<ProcessingServiceConfig>;
  private readonly activeProcessings: Map<string, ProcessingContext> = new Map();
  private readonly eventCallbacks: Map<ProcessingEvent, ProcessingEventCallback[]> = new Map();
  private readonly defaultRetryConfig: RetryConfig;

  constructor(config: ProcessingServiceConfig = {}) {
    this.factory = getFileProcessorFactory();
    
    // Configurações padrão
    this.defaultRetryConfig = {
      maxAttempts: 3,
      initialDelay: 1000,
      backoffMultiplier: 2,
      maxDelay: 10000,
      retryableErrors: [
        ProcessingErrorCodes.PROCESSING_TIMEOUT,
        ProcessingErrorCodes.MEMORY_ERROR,
        ProcessingErrorCodes.NETWORK_ERROR
      ]
    };

    this.config = {
      maxFileSize: config.maxFileSize || 100 * 1024 * 1024, // 100MB
      timeoutMs: config.timeoutMs || 300000, // 5 minutos
      storageProvider: config.storageProvider || null,
      autoUpload: config.autoUpload ?? false,
      keepHistory: config.keepHistory ?? true,
      processorConfigs: config.processorConfigs || {},
      enableValidation: config.enableValidation ?? true,
      retryConfig: { ...this.defaultRetryConfig, ...config.retryConfig }
    };
  }

  /**
   * Processa um arquivo completo
   */
  async processFile(
    fileBuffer: Buffer,
    fileMetadata: FileMetadata,
    options: ProcessingOptions = {},
    onProgress?: ProcessingEventCallback
  ): Promise<DetailedProcessingResult> {
    const context = this.createProcessingContext(fileMetadata, options);
    
    try {
      // Registra callback de progresso
      if (onProgress) {
        this.addEventListener('processing-progress', onProgress);
      }

      // Inicia processamento
      this.activeProcessings.set(context.id, context);
      this.emitEvent('processing-started', { context }, context);

      // Validação inicial
      if (this.config.enableValidation) {
        await this.validateFile(fileBuffer, fileMetadata, context);
      }

      // Processamento principal com retry
      const processingResult = await this.processWithRetry(
        fileBuffer,
        fileMetadata,
        options,
        context
      );

      // Upload automático se configurado
      let downloadUrl: string | undefined;
      if (this.config.autoUpload && this.config.storageProvider) {
        downloadUrl = await this.uploadResult(processingResult, context);
      }

      // Cria resultado final
      const detailedResult = this.createDetailedResult(
        processingResult,
        context,
        downloadUrl
      );

      this.emitEvent('processing-completed', { result: detailedResult }, context);
      
      return detailedResult;

    } catch (error) {
      this.handleProcessingError(error, context);
      throw error;
    } finally {
      // Cleanup
      this.activeProcessings.delete(context.id);
      if (onProgress) {
        this.removeEventListener('processing-progress', onProgress);
      }
    }
  }

  /**
   * Processa múltiplos arquivos em paralelo
   */
  async processFiles(
    files: Array<{ buffer: Buffer; metadata: FileMetadata; options?: ProcessingOptions }>,
    globalOptions: ProcessingOptions = {},
    onProgress?: ProcessingEventCallback
  ): Promise<DetailedProcessingResult[]> {
    const promises = files.map(file => 
      this.processFile(
        file.buffer,
        file.metadata,
        { ...globalOptions, ...file.options },
        onProgress
      )
    );

    // Processa todos em paralelo, mas captura erros individuais
    const results = await Promise.allSettled(promises);
    
    return results.map((result, index) => {
      if (result.status === 'fulfilled') {
        return result.value;
      } else {
        // Cria resultado de erro para arquivos que falharam
        const file = files[index];
        const context = this.createProcessingContext(file.metadata, file.options || {});
        
        return this.createErrorResult(result.reason, context);
      }
    });
  }

  /**
   * Valida se um arquivo pode ser processado
   */
  async validateFile(
    fileBuffer: Buffer,
    fileMetadata: FileMetadata,
    context?: ProcessingContext
  ): Promise<boolean> {
    const startTime = Date.now();

    try {
      // Validação de tamanho
      if (fileBuffer.length > this.config.maxFileSize) {
        throw new ProcessingError(
          `File size ${fileBuffer.length} exceeds maximum ${this.config.maxFileSize}`,
          ProcessingErrorCodes.FILE_TOO_LARGE,
          fileMetadata.mimeType
        );
      }

      // Validação de tipo suportado
      if (!this.factory.isTypeSupported(fileMetadata.mimeType)) {
        throw new ProcessingError(
          `Unsupported file type: ${fileMetadata.mimeType}`,
          ProcessingErrorCodes.UNSUPPORTED_FILE_TYPE,
          fileMetadata.mimeType
        );
      }

      // Validação específica do processador
      const processor = this.factory.getProcessor(fileMetadata.mimeType as SupportedFileType);
      const capabilities = processor.getCapabilities();
      
      if (fileBuffer.length > capabilities.maxFileSize) {
        throw new ProcessingError(
          `File size exceeds processor limit: ${capabilities.maxFileSize}`,
          ProcessingErrorCodes.FILE_TOO_LARGE,
          fileMetadata.mimeType
        );
      }

      if (context) {
        const duration = Date.now() - startTime;
        this.emitEvent('validation-completed', { duration, success: true }, context);
      }

      return true;

    } catch (error) {
      if (context) {
        const duration = Date.now() - startTime;
        this.emitEvent('validation-completed', { duration, success: false, error }, context);
      }
      throw error;
    }
  }

  /**
   * Obtém estatísticas dos processadores disponíveis
   */
  getProcessorStatistics() {
    return this.factory.getStatistics();
  }

  /**
   * Obtém lista de tipos de arquivo suportados
   */
  getSupportedFileTypes(): SupportedFileType[] {
    return this.factory.getSupportedTypes();
  }

  /**
   * Verifica se um tipo de arquivo é suportado
   */
  isFileTypeSupported(fileType: string): boolean {
    return this.factory.isTypeSupported(fileType);
  }

  /**
   * Obtém processamentos ativos
   */
  getActiveProcessings(): ProcessingContext[] {
    return Array.from(this.activeProcessings.values());
  }

  /**
   * Cancela um processamento ativo
   */
  async cancelProcessing(processingId: string): Promise<boolean> {
    const context = this.activeProcessings.get(processingId);
    if (!context) {
      return false;
    }

    // Aqui implementaríamos a lógica de cancelamento
    // Por enquanto, apenas remove do mapa ativo
    this.activeProcessings.delete(processingId);
    
    return true;
  }

  /**
   * Adiciona listener para eventos
   */
  addEventListener(event: ProcessingEvent, callback: ProcessingEventCallback): void {
    if (!this.eventCallbacks.has(event)) {
      this.eventCallbacks.set(event, []);
    }
    this.eventCallbacks.get(event)!.push(callback);
  }

  /**
   * Remove listener de eventos
   */
  removeEventListener(event: ProcessingEvent, callback: ProcessingEventCallback): void {
    const callbacks = this.eventCallbacks.get(event);
    if (callbacks) {
      const index = callbacks.indexOf(callback);
      if (index > -1) {
        callbacks.splice(index, 1);
      }
    }
  }

  /**
   * Cria contexto de processamento
   */
  private createProcessingContext(
    fileMetadata: FileMetadata,
    options: ProcessingOptions
  ): ProcessingContext {
    return {
      id: `proc_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      fileMetadata,
      options,
      startTime: Date.now(),
      currentAttempt: 0,
      attemptHistory: []
    };
  }

  /**
   * Processamento principal com retry
   */
  private async processWithRetry(
    fileBuffer: Buffer,
    fileMetadata: FileMetadata,
    options: ProcessingOptions,
    context: ProcessingContext
  ): Promise<ProcessingResult> {
    let lastError: ProcessingError | undefined;

    for (let attempt = 1; attempt <= this.config.retryConfig.maxAttempts; attempt++) {
      context.currentAttempt = attempt;
      
      const attemptInfo: ProcessingAttempt = {
        attempt,
        startTime: Date.now(),
        status: 'processing'
      };

      try {
        // Emite evento de tentativa
        if (attempt > 1) {
          this.emitEvent('retry-attempted', { attempt, lastError }, context);
        }

        // Processamento efetivo
        const result = await this.executeProcessing(fileBuffer, fileMetadata, options, context);
        
        // Sucesso
        attemptInfo.endTime = Date.now();
        attemptInfo.duration = attemptInfo.endTime - attemptInfo.startTime;
        attemptInfo.status = 'completed';
        context.attemptHistory.push(attemptInfo);

        return result;

      } catch (error) {
        lastError = error instanceof ProcessingError ? error : new ProcessingError(
          `Processing failed: ${error}`,
          ProcessingErrorCodes.UNKNOWN_ERROR,
          fileMetadata.mimeType
        );

        attemptInfo.endTime = Date.now();
        attemptInfo.duration = attemptInfo.endTime - attemptInfo.startTime;
        attemptInfo.status = 'failed';
        attemptInfo.error = lastError;
        context.attemptHistory.push(attemptInfo);

        // Verifica se deve tentar novamente
        const shouldRetry = attempt < this.config.retryConfig.maxAttempts &&
                           this.config.retryConfig.retryableErrors.includes(lastError.code);

        if (shouldRetry) {
          // Calcula delay com exponential backoff
          const delay = Math.min(
            this.config.retryConfig.initialDelay * Math.pow(this.config.retryConfig.backoffMultiplier, attempt - 1),
            this.config.retryConfig.maxDelay
          );
          
          await new Promise(resolve => setTimeout(resolve, delay));
          continue;
        }

        // Não deve tentar novamente
        break;
      }
    }

    throw lastError || new ProcessingError(
      'Processing failed after all retry attempts',
      ProcessingErrorCodes.UNKNOWN_ERROR,
      fileMetadata.mimeType
    );
  }

  /**
   * Executa o processamento efetivo
   */
  private async executeProcessing(
    fileBuffer: Buffer,
    fileMetadata: FileMetadata,
    options: ProcessingOptions,
    context: ProcessingContext
  ): Promise<ProcessingResult> {
    const startTime = Date.now();

    // Obtém processador
    const processor = this.factory.createProcessor(
      fileMetadata.mimeType as SupportedFileType,
      {
        maxFileSize: this.config.maxFileSize,
        timeoutMs: this.config.timeoutMs,
        ...this.config.processorConfigs[fileMetadata.mimeType as SupportedFileType]
      }
    );

    // Executa processamento
    const result = await processor.process(fileBuffer, fileMetadata, options);

    // Calcula métricas
    const duration = Date.now() - startTime;
    this.emitEvent('processing-progress', { 
      progress: 100, 
      duration,
      result 
    }, context);

    return result;
  }

  /**
   * Upload do resultado processado
   */
  private async uploadResult(
    result: ProcessingResult,
    context: ProcessingContext
  ): Promise<string> {
    if (!this.config.storageProvider) {
      throw new Error('Storage provider not configured');
    }

    this.emitEvent('upload-started', {}, context);

    try {
      const uploadResult = await this.config.storageProvider.upload(
        Buffer.from(result.extractedText, 'utf-8'),
        {
          fileName: `${context.fileMetadata.fileName}_processed.txt`,
          mimeType: 'text/plain',
          size: Buffer.byteLength(result.extractedText, 'utf-8')
        }
      );

      this.emitEvent('upload-completed', { uploadResult }, context);
      
      return uploadResult.url;

    } catch (error) {
      throw new ProcessingError(
        `Upload failed: ${error}`,
        ProcessingErrorCodes.NETWORK_ERROR,
        context.fileMetadata.mimeType
      );
    }
  }

  /**
   * Cria resultado detalhado
   */
  private createDetailedResult(
    processingResult: ProcessingResult,
    context: ProcessingContext,
    downloadUrl?: string
  ): DetailedProcessingResult {
    const totalDuration = Date.now() - context.startTime;
    const lastAttempt = context.attemptHistory[context.attemptHistory.length - 1];
    
    // Cria entidade de resultado
    const entityResult = new FileProcessingResult(
      context.id,
      context.fileMetadata.mimeType as SupportedFileType,
      context.fileMetadata
    );
    
    entityResult.updateStatus('completed');
    entityResult.setValidationResult(true);
    entityResult.markAsCompleted(processingResult);

    return {
      ...processingResult,
      context,
      entityResult,
      downloadUrl,
      performanceMetrics: {
        totalDuration,
        processingDuration: lastAttempt?.duration || 0,
        fileSize: context.fileMetadata.size,
        pagesPerMinute: processingResult.metadata.totalPages ? 
          (processingResult.metadata.totalPages / totalDuration) * 60000 : undefined,
        wordsPerSecond: processingResult.metadata.wordCount ? 
          (processingResult.metadata.wordCount / totalDuration) * 1000 : undefined
      }
    };
  }

  /**
   * Cria resultado de erro
   */
  private createErrorResult(error: any, context: ProcessingContext): DetailedProcessingResult {
    const processingError = error instanceof ProcessingError ? error : new ProcessingError(
      `Processing failed: ${error}`,
      ProcessingErrorCodes.UNKNOWN_ERROR,
      context.fileMetadata.mimeType
    );

    const entityResult = new FileProcessingResult(
      context.id,
      context.fileMetadata.mimeType as SupportedFileType,
      context.fileMetadata
    );
    
    entityResult.updateStatus('failed');
    entityResult.addError(processingError);

    return {
      success: false,
      extractedText: '',
      metadata: {
        processingTime: Date.now() - context.startTime,
        totalPages: 0,
        wordCount: 0,
        processorUsed: 'unknown'
      },
      errors: [processingError],
      context,
      entityResult,
      performanceMetrics: {
        totalDuration: Date.now() - context.startTime,
        processingDuration: 0,
        fileSize: context.fileMetadata.size
      }
    };
  }

  /**
   * Manipula erro de processamento
   */
  private handleProcessingError(error: any, context: ProcessingContext): void {
    this.emitEvent('processing-failed', { error }, context);
  }

  /**
   * Emite evento para listeners
   */
  private emitEvent(event: ProcessingEvent, data: any, context: ProcessingContext): void {
    const callbacks = this.eventCallbacks.get(event);
    if (callbacks) {
      callbacks.forEach(callback => {
        try {
          callback(event, data, context);
        } catch (error) {
          console.error(`Error in event callback for ${event}:`, error);
        }
      });
    }
  }
}

/**
 * Instância singleton do serviço
 */
let serviceInstance: FileProcessingService | null = null;

/**
 * Função para obter instância singleton do serviço
 */
export function getFileProcessingService(config?: ProcessingServiceConfig): FileProcessingService {
  if (!serviceInstance) {
    serviceInstance = new FileProcessingService(config);
  }
  return serviceInstance;
}

/**
 * Função para criar nova instância do serviço
 */
export function createFileProcessingService(config?: ProcessingServiceConfig): FileProcessingService {
  return new FileProcessingService(config);
}

/**
 * Configurações padrão do serviço
 */
export const SERVICE_DEFAULTS = {
  MAX_FILE_SIZE: 100 * 1024 * 1024, // 100MB
  TIMEOUT_MS: 300000, // 5 minutos
  MAX_RETRY_ATTEMPTS: 3,
  INITIAL_RETRY_DELAY: 1000,
  BACKOFF_MULTIPLIER: 2,
  MAX_RETRY_DELAY: 10000
} as const; 