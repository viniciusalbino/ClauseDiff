/**
 * Entidade de domínio para resultado de processamento de arquivo
 * Implementa conceitos de Domain-Driven Design (DDD) e princípios SOLID
 * 
 * @entity FileProcessingResult
 * @author ClauseDiff Team
 * @version 1.0.0
 */

import { ProcessingStatus, ProcessingOptions, FileMetadata, ProcessorCapabilities } from '../interfaces/IFileProcessor';
import { UploadResult, StorageProviderType } from '../interfaces/IStorageProvider';

/**
 * Tipos de operação de processamento
 */
export type ProcessingOperation = 'extract_text' | 'extract_metadata' | 'validate' | 'convert' | 'compare' | 'upload';

/**
 * Nível de severidade para logs e warnings
 */
export type SeverityLevel = 'info' | 'warning' | 'error' | 'critical';

/**
 * Informações de contexto do processamento
 */
export interface ProcessingContext {
  /** ID único da sessão de processamento */
  sessionId: string;
  /** ID do usuário que iniciou o processamento */
  userId?: string;
  /** IP do cliente que fez a requisição */
  clientIp?: string;
  /** User agent do navegador */
  userAgent?: string;
  /** Timestamp de início da operação */
  startedAt: number;
  /** Versão do sistema que processou */
  systemVersion: string;
  /** Ambiente de execução (dev, staging, prod) */
  environment: 'development' | 'staging' | 'production';
}

/**
 * Métricas de performance do processamento
 */
export interface ProcessingMetrics {
  /** Tempo total de processamento em milissegundos */
  totalDuration: number;
  /** Tempo de extração de conteúdo */
  extractionTime?: number;
  /** Tempo de validação */
  validationTime?: number;
  /** Tempo de upload (se aplicável) */
  uploadTime?: number;
  /** Uso de memória pico em bytes */
  peakMemoryUsage?: number;
  /** Número de operações de I/O realizadas */
  ioOperations?: number;
  /** Taxa de transferência em bytes/segundo */
  throughput?: number;
  /** Número de chunks processados */
  chunksProcessed?: number;
}

/**
 * Log entry para auditoria detalhada
 */
export interface ProcessingLogEntry {
  /** Timestamp do evento */
  timestamp: number;
  /** Nível de severidade */
  level: SeverityLevel;
  /** Mensagem descritiva */
  message: string;
  /** Dados adicionais estruturados */
  data?: Record<string, any>;
  /** Stack trace em caso de erro */
  stackTrace?: string;
  /** Operação sendo executada */
  operation?: ProcessingOperation;
}

/**
 * Resultado de validação de arquivo
 */
export interface ValidationResult {
  /** Se o arquivo passou na validação */
  isValid: boolean;
  /** Lista de regras violadas */
  violations: ValidationViolation[];
  /** Score de confiança (0-100) */
  confidenceScore: number;
  /** Metadados descobertos durante validação */
  discoveredMetadata?: Record<string, any>;
}

/**
 * Violação de regra de validação
 */
export interface ValidationViolation {
  /** Código da regra violada */
  ruleCode: string;
  /** Descrição da violação */
  message: string;
  /** Nível de severidade */
  severity: SeverityLevel;
  /** Campo/propriedade afetada */
  field?: string;
  /** Valor que causou a violação */
  value?: any;
  /** Sugestão de correção */
  suggestion?: string;
}

/**
 * Resultado de comparação entre documentos
 */
export interface ComparisonResult {
  /** Score de similaridade (0-100) */
  similarityScore: number;
  /** Número de diferenças encontradas */
  differencesCount: number;
  /** Diferenças detalhadas por seção */
  differences: DocumentDifference[];
  /** Resumo estatístico */
  statistics: ComparisonStatistics;
}

/**
 * Diferença entre documentos
 */
export interface DocumentDifference {
  /** Tipo da diferença */
  type: 'added' | 'removed' | 'modified' | 'moved';
  /** Seção do documento */
  section: string;
  /** Texto original (se aplicável) */
  originalText?: string;
  /** Texto modificado (se aplicável) */
  modifiedText?: string;
  /** Posição no documento */
  position: {
    line?: number;
    column?: number;
    page?: number;
  };
  /** Confiança na detecção (0-100) */
  confidence: number;
}

/**
 * Estatísticas de comparação
 */
export interface ComparisonStatistics {
  /** Total de palavras no documento original */
  originalWordCount: number;
  /** Total de palavras no documento modificado */
  modifiedWordCount: number;
  /** Percentual de conteúdo similar */
  similarityPercentage: number;
  /** Número de páginas comparadas */
  pagesCompared: number;
  /** Tempo de comparação em milissegundos */
  comparisonTime: number;
}

/**
 * Entidade principal para resultado de processamento de arquivo
 * Implementa padrões DDD com rich domain model
 */
export class FileProcessingResult {
  private _id: string;
  private _status: ProcessingStatus;
  private _content: string;
  private _metadata: FileMetadata;
  private _context: ProcessingContext;
  private _metrics: ProcessingMetrics;
  private _logs: ProcessingLogEntry[];
  private _validationResult?: ValidationResult;
  private _comparisonResult?: ComparisonResult;
  private _uploadResult?: UploadResult;
  private _options: ProcessingOptions;
  private _createdAt: number;
  private _updatedAt: number;
  private _errors: ProcessingLogEntry[];
  private _warnings: ProcessingLogEntry[];

  constructor(
    id: string,
    status: ProcessingStatus,
    content: string,
    metadata: FileMetadata,
    context: ProcessingContext,
    options: ProcessingOptions = {}
  ) {
    this._id = id;
    this._status = status;
    this._content = content;
    this._metadata = { ...metadata };
    this._context = { ...context };
    this._options = { ...options };
    this._logs = [];
    this._errors = [];
    this._warnings = [];
    this._createdAt = Date.now();
    this._updatedAt = Date.now();
    this._metrics = {
      totalDuration: 0
    };

    this.validateInvariants();
  }

  // Getters
  get id(): string { return this._id; }
  get status(): ProcessingStatus { return this._status; }
  get content(): string { return this._content; }
  get metadata(): Readonly<FileMetadata> { return { ...this._metadata }; }
  get context(): Readonly<ProcessingContext> { return { ...this._context }; }
  get metrics(): Readonly<ProcessingMetrics> { return { ...this._metrics }; }
  get logs(): ReadonlyArray<ProcessingLogEntry> { return [...this._logs]; }
  get validationResult(): Readonly<ValidationResult> | undefined { return this._validationResult ? { ...this._validationResult } : undefined; }
  get comparisonResult(): Readonly<ComparisonResult> | undefined { return this._comparisonResult ? { ...this._comparisonResult } : undefined; }
  get uploadResult(): Readonly<UploadResult> | undefined { return this._uploadResult ? { ...this._uploadResult } : undefined; }
  get options(): Readonly<ProcessingOptions> { return { ...this._options }; }
  get createdAt(): number { return this._createdAt; }
  get updatedAt(): number { return this._updatedAt; }
  get errors(): ReadonlyArray<ProcessingLogEntry> { return [...this._errors]; }
  get warnings(): ReadonlyArray<ProcessingLogEntry> { return [...this._warnings]; }

  /**
   * Atualiza o status do processamento
   */
  updateStatus(newStatus: ProcessingStatus, message?: string): void {
    const previousStatus = this._status;
    this._status = newStatus;
    this._updatedAt = Date.now();

    this.addLog('info', `Status changed from ${previousStatus} to ${newStatus}`, {
      previousStatus,
      newStatus,
      message
    });

    this.validateInvariants();
  }

  /**
   * Atualiza o conteúdo extraído
   */
  updateContent(content: string): void {
    if (!content || content.trim().length === 0) {
      throw new Error('Content cannot be empty');
    }
    
    this._content = content;
    this._updatedAt = Date.now();
    
    this.addLog('info', 'Content updated', {
      contentLength: content.length
    });
  }

  /**
   * Define resultado de validação
   */
  setValidationResult(result: ValidationResult): void {
    this._validationResult = { ...result };
    this._updatedAt = Date.now();

    // Adiciona warnings/errors baseado nas violações
    result.violations.forEach(violation => {
      if (violation.severity === 'error' || violation.severity === 'critical') {
        this.addError(violation.message, { violation });
      } else {
        this.addWarning(violation.message, { violation });
      }
    });

    this.addLog('info', `Validation completed: ${result.isValid ? 'PASSED' : 'FAILED'}`, {
      violationCount: result.violations.length,
      confidenceScore: result.confidenceScore
    });
  }

  /**
   * Define resultado de comparação
   */
  setComparisonResult(result: ComparisonResult): void {
    this._comparisonResult = { ...result };
    this._updatedAt = Date.now();

    this.addLog('info', 'Comparison completed', {
      similarityScore: result.similarityScore,
      differencesCount: result.differencesCount
    });
  }

  /**
   * Define resultado de upload
   */
  setUploadResult(result: UploadResult): void {
    this._uploadResult = { ...result };
    this._updatedAt = Date.now();

    this.addLog('info', 'Upload completed', {
      fileId: result.fileId,
      size: result.size,
      provider: result.provider
    });
  }

  /**
   * Atualiza métricas de performance
   */
  updateMetrics(metrics: Partial<ProcessingMetrics>): void {
    this._metrics = { ...this._metrics, ...metrics };
    this._updatedAt = Date.now();
  }

  /**
   * Adiciona entrada de log
   */
  addLog(level: SeverityLevel, message: string, data?: Record<string, any>, operation?: ProcessingOperation): void {
    const logEntry: ProcessingLogEntry = {
      timestamp: Date.now(),
      level,
      message,
      data,
      operation
    };

    this._logs.push(logEntry);

    // Adiciona aos arrays específicos conforme severidade
    if (level === 'error' || level === 'critical') {
      this._errors.push(logEntry);
    } else if (level === 'warning') {
      this._warnings.push(logEntry);
    }
  }

  /**
   * Adiciona erro ao processamento
   */
  addError(message: string, data?: Record<string, any>, stackTrace?: string): void {
    this.addLog('error', message, data);
    
    if (stackTrace) {
      const lastLog = this._logs[this._logs.length - 1];
      lastLog.stackTrace = stackTrace;
    }
  }

  /**
   * Adiciona warning ao processamento
   */
  addWarning(message: string, data?: Record<string, any>): void {
    this.addLog('warning', message, data);
  }

  /**
   * Marca o processamento como completado
   */
  markAsCompleted(finalContent?: string): void {
    if (finalContent) {
      this.updateContent(finalContent);
    }

    this.updateStatus('completed', 'Processing completed successfully');
    
    // Calcula duração total
    const totalDuration = Date.now() - this._createdAt;
    this.updateMetrics({ totalDuration });
  }

  /**
   * Marca o processamento como falho
   */
  markAsFailed(error: string, stackTrace?: string): void {
    this.updateStatus('failed', error);
    this.addError(error, undefined, stackTrace);
    
    const totalDuration = Date.now() - this._createdAt;
    this.updateMetrics({ totalDuration });
  }

  /**
   * Verifica se o processamento foi bem-sucedido
   */
  isSuccessful(): boolean {
    return this._status === 'completed' && this._errors.length === 0;
  }

  /**
   * Verifica se há warnings
   */
  hasWarnings(): boolean {
    return this._warnings.length > 0;
  }

  /**
   * Verifica se há erros
   */
  hasErrors(): boolean {
    return this._errors.length > 0;
  }

  /**
   * Obtém resumo do processamento
   */
  getSummary(): ProcessingSummary {
    return {
      id: this._id,
      status: this._status,
      fileName: this._metadata.name,
      fileSize: this._metadata.size,
      contentLength: this._content.length,
      duration: this._metrics.totalDuration,
      hasErrors: this.hasErrors(),
      hasWarnings: this.hasWarnings(),
      errorCount: this._errors.length,
      warningCount: this._warnings.length,
      isValidationPassed: this._validationResult?.isValid ?? true,
      isUploadCompleted: !!this._uploadResult,
      createdAt: this._createdAt,
      updatedAt: this._updatedAt
    };
  }

  /**
   * Serializa para JSON
   */
  toJSON(): ProcessingResultJSON {
    return {
      id: this._id,
      status: this._status,
      content: this._content,
      metadata: this._metadata,
      context: this._context,
      metrics: this._metrics,
      logs: this._logs,
      validationResult: this._validationResult,
      comparisonResult: this._comparisonResult,
      uploadResult: this._uploadResult,
      options: this._options,
      createdAt: this._createdAt,
      updatedAt: this._updatedAt,
      errors: this._errors,
      warnings: this._warnings
    };
  }

  /**
   * Cria instância a partir de JSON
   */
  static fromJSON(json: ProcessingResultJSON): FileProcessingResult {
    const instance = new FileProcessingResult(
      json.id,
      json.status,
      json.content,
      json.metadata,
      json.context,
      json.options
    );

    instance._metrics = json.metrics;
    instance._logs = json.logs;
    instance._validationResult = json.validationResult;
    instance._comparisonResult = json.comparisonResult;
    instance._uploadResult = json.uploadResult;
    instance._createdAt = json.createdAt;
    instance._updatedAt = json.updatedAt;
    instance._errors = json.errors;
    instance._warnings = json.warnings;

    return instance;
  }

  /**
   * Valida invariantes da entidade
   */
  private validateInvariants(): void {
    if (!this._id || this._id.trim().length === 0) {
      throw new Error('FileProcessingResult ID cannot be empty');
    }

    if (!this._metadata.name || this._metadata.name.trim().length === 0) {
      throw new Error('File metadata name cannot be empty');
    }

    if (this._metadata.size < 0) {
      throw new Error('File size cannot be negative');
    }

    if (this._createdAt > this._updatedAt) {
      throw new Error('Created date cannot be after updated date');
    }
  }
}

/**
 * Resumo de processamento para displays rápidos
 */
export interface ProcessingSummary {
  id: string;
  status: ProcessingStatus;
  fileName: string;
  fileSize: number;
  contentLength: number;
  duration: number;
  hasErrors: boolean;
  hasWarnings: boolean;
  errorCount: number;
  warningCount: number;
  isValidationPassed: boolean;
  isUploadCompleted: boolean;
  createdAt: number;
  updatedAt: number;
}

/**
 * Representação JSON da entidade
 */
export interface ProcessingResultJSON {
  id: string;
  status: ProcessingStatus;
  content: string;
  metadata: FileMetadata;
  context: ProcessingContext;
  metrics: ProcessingMetrics;
  logs: ProcessingLogEntry[];
  validationResult?: ValidationResult;
  comparisonResult?: ComparisonResult;
  uploadResult?: UploadResult;
  options: ProcessingOptions;
  createdAt: number;
  updatedAt: number;
  errors: ProcessingLogEntry[];
  warnings: ProcessingLogEntry[];
} 