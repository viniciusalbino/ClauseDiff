/**
 * Factory para criação de processadores de arquivo com Registry pattern
 * Implementa Open/Closed Principle permitindo extensão sem modificação
 * 
 * @class FileProcessorFactory
 * @author ClauseDiff Team
 * @version 1.0.0
 */

import { 
  IFileProcessor, 
  SupportedFileType, 
  ProcessorCapabilities,
  ProcessingError,
  ProcessingErrorCodes
} from '../../domain/interfaces/IFileProcessor';

import { DocxProcessor, createDocxProcessor, DOCX_DEFAULTS } from '../processors/DocxProcessor';
import { PdfProcessor, createPdfProcessor, PDF_DEFAULTS } from '../processors/PdfProcessor';
import { TxtProcessor, createTxtProcessor, TXT_DEFAULTS } from '../processors/TxtProcessor';

/**
 * Configuração para um processador registrado
 */
interface ProcessorRegistration {
  /** Factory function para criar o processador */
  factory: ProcessorFactory;
  /** Tipos MIME suportados por este processador */
  supportedTypes: SupportedFileType[];
  /** Configurações padrão */
  defaultConfig?: ProcessorConfig;
  /** Metadados do processador */
  metadata: ProcessorMetadata;
}

/**
 * Metadados de um processador
 */
interface ProcessorMetadata {
  /** Nome do processador */
  name: string;
  /** Versão do processador */
  version: string;
  /** Descrição */
  description: string;
  /** Dependências externas */
  dependencies?: string[];
  /** Se está habilitado */
  enabled: boolean;
}

/**
 * Configurações para criação de processador
 */
interface ProcessorConfig {
  /** Tamanho máximo de arquivo em bytes */
  maxFileSize?: number;
  /** Timeout em milissegundos */
  timeoutMs?: number;
  /** Configurações específicas do processador */
  options?: Record<string, any>;
}

/**
 * Factory function type para criar processadores
 */
type ProcessorFactory = (config?: ProcessorConfig) => IFileProcessor;

/**
 * Estatísticas do registry
 */
interface RegistryStatistics {
  /** Total de processadores registrados */
  totalProcessors: number;
  /** Processadores habilitados */
  enabledProcessors: number;
  /** Tipos de arquivo suportados */
  supportedTypes: SupportedFileType[];
  /** Processadores por tipo */
  processorsByType: Record<string, string[]>;
}

/**
 * Factory principal para processadores de arquivo
 * Implementa Registry pattern com lazy loading e configuração dinâmica
 */
export class FileProcessorFactory {
  private static instance: FileProcessorFactory;
  private readonly registry: Map<string, ProcessorRegistration> = new Map();
  private readonly typeToProcessorMap: Map<SupportedFileType, string> = new Map();
  private readonly processorCache: Map<string, IFileProcessor> = new Map();
  private globalConfig: ProcessorConfig = {};

  private constructor() {
    this.initializeDefaultProcessors();
  }

  /**
   * Obtém instância singleton da factory
   */
  static getInstance(): FileProcessorFactory {
    if (!FileProcessorFactory.instance) {
      FileProcessorFactory.instance = new FileProcessorFactory();
    }
    return FileProcessorFactory.instance;
  }

  /**
   * Inicializa processadores padrão
   */
  private initializeDefaultProcessors(): void {
    // Registra processador DOCX
    this.registerProcessor('docx', {
      factory: (config?: ProcessorConfig) => createDocxProcessor(
        config?.maxFileSize || DOCX_DEFAULTS.MAX_FILE_SIZE,
        config?.timeoutMs || DOCX_DEFAULTS.TIMEOUT_MS
      ),
      supportedTypes: [DOCX_DEFAULTS.SUPPORTED_MIME_TYPE],
      defaultConfig: {
        maxFileSize: DOCX_DEFAULTS.MAX_FILE_SIZE,
        timeoutMs: DOCX_DEFAULTS.TIMEOUT_MS
      },
      metadata: {
        name: 'DOCX Processor',
        version: '1.0.0',
        description: 'Processes Microsoft Word .docx files using mammoth.js',
        dependencies: ['mammoth.js'],
        enabled: true
      }
    });

    // Registra processador PDF
    this.registerProcessor('pdf', {
      factory: (config?: ProcessorConfig) => createPdfProcessor(
        config?.maxFileSize || PDF_DEFAULTS.MAX_FILE_SIZE,
        config?.timeoutMs || PDF_DEFAULTS.TIMEOUT_MS,
        config?.options?.workerSrc || PDF_DEFAULTS.WORKER_SRC
      ),
      supportedTypes: [PDF_DEFAULTS.SUPPORTED_MIME_TYPE],
      defaultConfig: {
        maxFileSize: PDF_DEFAULTS.MAX_FILE_SIZE,
        timeoutMs: PDF_DEFAULTS.TIMEOUT_MS,
        options: {
          workerSrc: PDF_DEFAULTS.WORKER_SRC
        }
      },
      metadata: {
        name: 'PDF Processor',
        version: '1.0.0',
        description: 'Processes PDF files using PDF.js',
        dependencies: ['PDF.js'],
        enabled: true
      }
    });

    // Registra processador TXT
    this.registerProcessor('txt', {
      factory: (config?: ProcessorConfig) => createTxtProcessor(
        config?.maxFileSize || TXT_DEFAULTS.MAX_FILE_SIZE,
        config?.timeoutMs || TXT_DEFAULTS.TIMEOUT_MS,
        config?.options?.defaultEncoding || TXT_DEFAULTS.DEFAULT_ENCODING
      ),
      supportedTypes: [TXT_DEFAULTS.SUPPORTED_MIME_TYPE],
      defaultConfig: {
        maxFileSize: TXT_DEFAULTS.MAX_FILE_SIZE,
        timeoutMs: TXT_DEFAULTS.TIMEOUT_MS,
        options: {
          defaultEncoding: TXT_DEFAULTS.DEFAULT_ENCODING
        }
      },
      metadata: {
        name: 'TXT Processor',
        version: '1.0.0',
        description: 'Processes plain text files with automatic encoding detection',
        dependencies: [],
        enabled: true
      }
    });
  }

  /**
   * Registra um novo processador no registry
   */
  registerProcessor(id: string, registration: ProcessorRegistration): void {
    if (this.registry.has(id)) {
      throw new Error(`Processor with id '${id}' is already registered`);
    }

    // Valida registration
    this.validateRegistration(registration);

    // Registra o processador
    this.registry.set(id, registration);

    // Mapeia tipos MIME para o processador
    registration.supportedTypes.forEach(type => {
      if (this.typeToProcessorMap.has(type)) {
        throw new Error(`File type '${type}' is already handled by another processor`);
      }
      this.typeToProcessorMap.set(type, id);
    });

    // Limpa cache se necessário
    this.processorCache.delete(id);
  }

  /**
   * Remove um processador do registry
   */
  unregisterProcessor(id: string): boolean {
    const registration = this.registry.get(id);
    if (!registration) {
      return false;
    }

    // Remove mapeamentos de tipo
    registration.supportedTypes.forEach(type => {
      this.typeToProcessorMap.delete(type);
    });

    // Remove do registry e cache
    this.registry.delete(id);
    this.processorCache.delete(id);

    return true;
  }

  /**
   * Cria processador para um tipo de arquivo específico
   */
  createProcessor(fileType: SupportedFileType, config?: ProcessorConfig): IFileProcessor {
    const processorId = this.typeToProcessorMap.get(fileType);
    
    if (!processorId) {
      throw new ProcessingError(
        `No processor registered for file type: ${fileType}`,
        ProcessingErrorCodes.UNSUPPORTED_FILE_TYPE,
        fileType
      );
    }

    return this.createProcessorById(processorId, config);
  }

  /**
   * Cria processador por ID
   */
  createProcessorById(id: string, config?: ProcessorConfig): IFileProcessor {
    const registration = this.registry.get(id);
    
    if (!registration) {
      throw new Error(`No processor registered with id: ${id}`);
    }

    if (!registration.metadata.enabled) {
      throw new Error(`Processor '${id}' is disabled`);
    }

    // Mescla configurações (global + padrão + específica)
    const mergedConfig = this.mergeConfigs(
      this.globalConfig,
      registration.defaultConfig || {},
      config || {}
    );

    // Cria nova instância (não usa cache para permitir configurações diferentes)
    try {
      return registration.factory(mergedConfig);
    } catch (error) {
      throw new Error(`Failed to create processor '${id}': ${error}`);
    }
  }

  /**
   * Obtém processador em cache ou cria novo (singleton por ID)
   */
  getProcessor(fileType: SupportedFileType): IFileProcessor {
    const processorId = this.typeToProcessorMap.get(fileType);
    
    if (!processorId) {
      throw new ProcessingError(
        `No processor registered for file type: ${fileType}`,
        ProcessingErrorCodes.UNSUPPORTED_FILE_TYPE,
        fileType
      );
    }

    // Verifica cache
    if (this.processorCache.has(processorId)) {
      return this.processorCache.get(processorId)!;
    }

    // Cria e cacheia
    const processor = this.createProcessorById(processorId);
    this.processorCache.set(processorId, processor);
    
    return processor;
  }

  /**
   * Verifica se um tipo de arquivo é suportado
   */
  isTypeSupported(fileType: string): boolean {
    return this.typeToProcessorMap.has(fileType as SupportedFileType);
  }

  /**
   * Obtém lista de tipos suportados
   */
  getSupportedTypes(): SupportedFileType[] {
    return Array.from(this.typeToProcessorMap.keys());
  }

  /**
   * Obtém lista de processadores registrados
   */
  getRegisteredProcessors(): Array<{ id: string; metadata: ProcessorMetadata }> {
    return Array.from(this.registry.entries()).map(([id, registration]) => ({
      id,
      metadata: registration.metadata
    }));
  }

  /**
   * Obtém capacidades de um processador
   */
  getProcessorCapabilities(fileType: SupportedFileType): ProcessorCapabilities {
    const processor = this.getProcessor(fileType);
    return processor.getCapabilities();
  }

  /**
   * Habilita/desabilita um processador
   */
  setProcessorEnabled(id: string, enabled: boolean): void {
    const registration = this.registry.get(id);
    if (!registration) {
      throw new Error(`No processor registered with id: ${id}`);
    }

    registration.metadata.enabled = enabled;
    
    // Limpa cache se desabilitado
    if (!enabled) {
      this.processorCache.delete(id);
    }
  }

  /**
   * Define configuração global para todos os processadores
   */
  setGlobalConfig(config: ProcessorConfig): void {
    this.globalConfig = { ...config };
    // Limpa cache para forçar recriação com nova configuração
    this.processorCache.clear();
  }

  /**
   * Obtém estatísticas do registry
   */
  getStatistics(): RegistryStatistics {
    const allRegistrations = Array.from(this.registry.values());
    const enabledRegistrations = allRegistrations.filter(r => r.metadata.enabled);
    
    const processorsByType: Record<string, string[]> = {};
    this.typeToProcessorMap.forEach((processorId, type) => {
      if (!processorsByType[type]) {
        processorsByType[type] = [];
      }
      processorsByType[type].push(processorId);
    });

    return {
      totalProcessors: allRegistrations.length,
      enabledProcessors: enabledRegistrations.length,
      supportedTypes: this.getSupportedTypes(),
      processorsByType
    };
  }

  /**
   * Limpa todos os caches
   */
  clearCache(): void {
    this.processorCache.clear();
  }

  /**
   * Reset factory para estado inicial
   */
  reset(): void {
    this.registry.clear();
    this.typeToProcessorMap.clear();
    this.processorCache.clear();
    this.globalConfig = {};
    this.initializeDefaultProcessors();
  }

  /**
   * Valida registration de processador
   */
  private validateRegistration(registration: ProcessorRegistration): void {
    if (!registration.factory) {
      throw new Error('Processor registration must include a factory function');
    }

    if (!registration.supportedTypes || registration.supportedTypes.length === 0) {
      throw new Error('Processor registration must specify supported file types');
    }

    if (!registration.metadata) {
      throw new Error('Processor registration must include metadata');
    }

    if (!registration.metadata.name || !registration.metadata.version) {
      throw new Error('Processor metadata must include name and version');
    }
  }

  /**
   * Mescla configurações com precedência
   */
  private mergeConfigs(...configs: ProcessorConfig[]): ProcessorConfig {
    return configs.reduce((merged, config) => ({
      ...merged,
      ...config,
      options: {
        ...merged.options,
        ...config.options
      }
    }), {});
  }
}

/**
 * Função de conveniência para obter instância singleton
 */
export function getFileProcessorFactory(): FileProcessorFactory {
  return FileProcessorFactory.getInstance();
}

/**
 * Função de conveniência para criar processador
 */
export function createFileProcessor(fileType: SupportedFileType, config?: ProcessorConfig): IFileProcessor {
  return getFileProcessorFactory().createProcessor(fileType, config);
}

/**
 * Função de conveniência para verificar suporte a tipo
 */
export function isFileTypeSupported(fileType: string): boolean {
  return getFileProcessorFactory().isTypeSupported(fileType);
}

/**
 * Função de conveniência para obter tipos suportados
 */
export function getSupportedFileTypes(): SupportedFileType[] {
  return getFileProcessorFactory().getSupportedTypes();
}

/**
 * Configuração padrão da factory
 */
export const FACTORY_DEFAULTS = {
  GLOBAL_MAX_FILE_SIZE: 100 * 1024 * 1024, // 100MB global
  GLOBAL_TIMEOUT_MS: 120000, // 2 minutos global
  CACHE_ENABLED: true,
  AUTO_REGISTER_DEFAULTS: true
} as const; 