/**
 * Decorator para adicionar validação automática aos processadores de arquivo
 * Implementa padrão Decorator seguindo princípios SOLID
 * 
 * @class ValidationDecorator
 * @author ClauseDiff Team
 * @version 1.0.0
 */

import { 
  IFileProcessor,
  SupportedFileType,
  ProcessingOptions,
  ProcessingResult,
  ProcessorCapabilities,
  ProcessingError,
  ProcessingErrorCodes
} from '../../domain/interfaces/IFileProcessor';

/**
 * Regras de validação para arquivos
 */
export interface ValidationRule {
  /** Nome único da regra */
  name: string;
  /** Descrição da regra */
  description: string;
  /** Função de validação */
  validate: (file: File) => Promise<ValidationResult>;
  /** Se a regra é obrigatória */
  required: boolean;
  /** Severidade da violação */
  severity: 'error' | 'warning' | 'info';
}

/**
 * Resultado de uma validação
 */
export interface ValidationResult {
  /** Se a validação passou */
  isValid: boolean;
  /** Mensagem descritiva */
  message: string;
  /** Detalhes adicionais */
  details?: Record<string, any>;
  /** Sugestões para correção */
  suggestions?: string[];
}

/**
 * Configurações do validador
 */
export interface ValidationConfig {
  /** Tamanho máximo de arquivo em bytes */
  maxFileSize: number;
  /** Tipos MIME permitidos */
  allowedMimeTypes: SupportedFileType[];
  /** Se deve validar estrutura do arquivo */
  validateStructure: boolean;
  /** Se deve validar conteúdo do arquivo */
  validateContent: boolean;
  /** Regras customizadas de validação */
  customRules: ValidationRule[];
  /** Se deve parar na primeira falha */
  stopOnFirstError: boolean;
  /** Timeout para validação em ms */
  validationTimeout: number;
}

/**
 * Resultado consolidado de validação
 */
export interface ValidationSummary {
  /** Se todas as validações passaram */
  isValid: boolean;
  /** Número total de regras executadas */
  totalRules: number;
  /** Número de regras que passaram */
  passedRules: number;
  /** Número de regras que falharam */
  failedRules: number;
  /** Resultados detalhados por regra */
  results: Array<ValidationResult & { ruleName: string }>;
  /** Duração total da validação em ms */
  duration: number;
  /** Erros críticos que impedem processamento */
  criticalErrors: string[];
  /** Avisos que não impedem processamento */
  warnings: string[];
}

/**
 * Decorator que adiciona validação automática aos processadores
 * Implementa o padrão Decorator preservando a interface original
 */
export class ValidationDecorator implements IFileProcessor {
  private readonly processor: IFileProcessor;
  private readonly config: ValidationConfig;
  private readonly builtInRules: ValidationRule[];

  constructor(
    processor: IFileProcessor,
    config: Partial<ValidationConfig> = {}
  ) {
    this.processor = processor;
    
    // Configurações padrão
    this.config = {
      maxFileSize: 100 * 1024 * 1024, // 100MB
      allowedMimeTypes: ['application/pdf', 'text/plain', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
      validateStructure: true,
      validateContent: false,
      customRules: [],
      stopOnFirstError: false,
      validationTimeout: 30000, // 30 segundos
      ...config
    };

    // Inicializa regras built-in
    this.builtInRules = this.createBuiltInRules();
  }

  /**
   * Verifica se pode processar o tipo de arquivo
   */
  canProcess(fileType: string): boolean {
    return this.processor.canProcess(fileType);
  }

  /**
   * Processa arquivo com validação automática
   */
  async process(file: File, options?: ProcessingOptions): Promise<ProcessingResult> {
    // Executa validação antes do processamento
    const validationSummary = await this.validateFile(file);
    
    if (!validationSummary.isValid) {
      const criticalErrors = validationSummary.criticalErrors;
      throw new ProcessingError(
        `File validation failed: ${criticalErrors.join(', ')}`,
        ProcessingErrorCodes.VALIDATION_FAILED,
        file.type
      );
    }

    // Se há avisos, eles são incluídos no resultado
    const result = await this.processor.process(file, options);
    
    // Adiciona avisos de validação ao resultado se existirem
    if (validationSummary.warnings.length > 0) {
      result.warnings = [...(result.warnings || []), ...validationSummary.warnings];
    }

    return result;
  }

  /**
   * Valida arquivo usando regras consolidadas
   */
  async validate(file: File): Promise<boolean> {
    const summary = await this.validateFile(file);
    return summary.isValid;
  }

  /**
   * Obtém capacidades do processador
   */
  getCapabilities(): ProcessorCapabilities {
    const capabilities = this.processor.getCapabilities();
    
    // Ajusta capacidades baseado nas regras de validação
    return {
      ...capabilities,
      maxFileSize: Math.min(capabilities.maxFileSize, this.config.maxFileSize),
      supportedTypes: capabilities.supportedTypes.filter(type => 
        this.config.allowedMimeTypes.includes(type)
      )
    };
  }

  /**
   * Cancela processamento (delega para processador)
   */
  async cancel?(processId: string): Promise<boolean> {
    return this.processor.cancel ? await this.processor.cancel(processId) : false;
  }

  /**
   * Executa validação completa do arquivo
   */
  async validateFile(file: File): Promise<ValidationSummary> {
    const startTime = Date.now();
    const allRules = [...this.builtInRules, ...this.config.customRules];
    const results: Array<ValidationResult & { ruleName: string }> = [];
    const criticalErrors: string[] = [];
    const warnings: string[] = [];

    let passedRules = 0;
    let failedRules = 0;

    for (const rule of allRules) {
      try {
        // Aplica timeout à regra
        const result = await Promise.race([
          rule.validate(file),
          this.createTimeoutPromise(this.config.validationTimeout)
        ]);

        const ruleResult = {
          ...result,
          ruleName: rule.name
        };

        results.push(ruleResult);

        if (result.isValid) {
          passedRules++;
        } else {
          failedRules++;
          
          // Categoriza por severidade
          if (rule.severity === 'error' && rule.required) {
            criticalErrors.push(`${rule.name}: ${result.message}`);
          } else if (rule.severity === 'warning') {
            warnings.push(`${rule.name}: ${result.message}`);
          }
        }

        // Para na primeira falha crítica se configurado
        if (this.config.stopOnFirstError && !result.isValid && rule.required) {
          break;
        }

      } catch (error) {
        failedRules++;
        const errorMessage = `${rule.name}: Validation failed with error: ${error}`;
        
        results.push({
          isValid: false,
          message: errorMessage,
          ruleName: rule.name
        });

        if (rule.required) {
          criticalErrors.push(errorMessage);
        }

        if (this.config.stopOnFirstError && rule.required) {
          break;
        }
      }
    }

    const duration = Date.now() - startTime;
    const isValid = criticalErrors.length === 0;

    return {
      isValid,
      totalRules: allRules.length,
      passedRules,
      failedRules,
      results,
      duration,
      criticalErrors,
      warnings
    };
  }

  /**
   * Adiciona regra customizada de validação
   */
  addValidationRule(rule: ValidationRule): void {
    // Verifica se regra já existe
    const existingRule = this.config.customRules.find(r => r.name === rule.name);
    if (existingRule) {
      throw new Error(`Validation rule '${rule.name}' already exists`);
    }

    this.config.customRules.push(rule);
  }

  /**
   * Remove regra customizada de validação
   */
  removeValidationRule(ruleName: string): boolean {
    const initialLength = this.config.customRules.length;
    this.config.customRules = this.config.customRules.filter(r => r.name !== ruleName);
    return this.config.customRules.length < initialLength;
  }

  /**
   * Obtém todas as regras de validação ativas
   */
  getValidationRules(): ValidationRule[] {
    return [...this.builtInRules, ...this.config.customRules];
  }

  /**
   * Atualiza configuração de validação
   */
  updateConfig(newConfig: Partial<ValidationConfig>): void {
    Object.assign(this.config, newConfig);
  }

  /**
   * Cria regras de validação built-in
   */
  private createBuiltInRules(): ValidationRule[] {
    return [
      {
        name: 'file-size',
        description: 'Validates file size is within limits',
        required: true,
        severity: 'error',
        validate: async (file: File): Promise<ValidationResult> => {
          const isValid = file.size <= this.config.maxFileSize;
          return {
            isValid,
            message: isValid 
              ? `File size ${file.size} bytes is within limit`
              : `File size ${file.size} bytes exceeds maximum ${this.config.maxFileSize} bytes`,
            details: {
              fileSize: file.size,
              maxAllowed: this.config.maxFileSize,
              exceedsBy: file.size - this.config.maxFileSize
            },
            suggestions: isValid ? [] : [
              'Reduce file size by compressing the document',
              'Split large document into smaller files',
              'Remove unnecessary images or attachments'
            ]
          };
        }
      },

      {
        name: 'mime-type',
        description: 'Validates file MIME type is supported',
        required: true,
        severity: 'error',
        validate: async (file: File): Promise<ValidationResult> => {
          const isValid = this.config.allowedMimeTypes.includes(file.type as SupportedFileType);
          return {
            isValid,
            message: isValid 
              ? `MIME type ${file.type} is supported`
              : `MIME type ${file.type} is not supported`,
            details: {
              fileMimeType: file.type,
              allowedTypes: this.config.allowedMimeTypes
            },
            suggestions: isValid ? [] : [
              'Convert file to a supported format',
              `Supported formats: ${this.config.allowedMimeTypes.join(', ')}`
            ]
          };
        }
      },

      {
        name: 'file-name',
        description: 'Validates file name is not empty and has valid characters',
        required: true,
        severity: 'error',
        validate: async (file: File): Promise<ValidationResult> => {
          const hasName = file.name && file.name.trim().length > 0;
          const hasValidChars = hasName && !/[<>:"/\\|?*]/.test(file.name);
          const isValid = hasName && hasValidChars;
          
          let message = 'File name is valid';
          if (!hasName) {
            message = 'File name is empty or missing';
          } else if (!hasValidChars) {
            message = 'File name contains invalid characters';
          }

          return {
            isValid,
            message,
            details: {
              fileName: file.name,
              hasName,
              hasValidChars
            },
            suggestions: isValid ? [] : [
              'Provide a valid file name',
              'Remove invalid characters: < > : " / \\ | ? *',
              'Use alphanumeric characters and common symbols'
            ]
          };
        }
      },

      {
        name: 'file-structure',
        description: 'Validates basic file structure integrity',
        required: false,
        severity: 'warning',
        validate: async (file: File): Promise<ValidationResult> => {
          // Para validação básica, verificamos se o arquivo não está vazio
          // e se o tipo corresponde à extensão
          const isEmpty = file.size === 0;
          const hasExtension = file.name.includes('.');
          
          let extensionMatches = true;
          if (hasExtension) {
            const extension = file.name.split('.').pop()?.toLowerCase();
            extensionMatches = this.isExtensionMatchingMimeType(extension, file.type);
          }

          const isValid = !isEmpty && extensionMatches;
          
          return {
            isValid,
            message: isValid 
              ? 'File structure appears valid'
              : 'File structure validation warnings found',
            details: {
              isEmpty,
              hasExtension,
              extensionMatches,
              fileSize: file.size
            },
                       suggestions: isValid ? [] : [
             ...(isEmpty ? ['File appears to be empty'] : []),
             ...(!extensionMatches ? ['File extension does not match MIME type'] : [])
           ]
          };
        }
      }
    ];
  }

  /**
   * Verifica se extensão corresponde ao MIME type
   */
  private isExtensionMatchingMimeType(extension: string | undefined, mimeType: string): boolean {
    if (!extension) return false;

    const mimeExtensionMap: Record<string, string[]> = {
      'application/pdf': ['pdf'],
      'text/plain': ['txt', 'text', 'log', 'md', 'markdown'],
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['docx']
    };

    const expectedExtensions = mimeExtensionMap[mimeType] || [];
    return expectedExtensions.includes(extension);
  }

  /**
   * Cria promise que rejeita após timeout
   */
  private createTimeoutPromise(timeoutMs: number): Promise<ValidationResult> {
    return new Promise((_, reject) => {
      setTimeout(() => {
        reject(new Error(`Validation timeout after ${timeoutMs}ms`));
      }, timeoutMs);
    });
  }
}

/**
 * Factory function para criar ValidationDecorator
 */
export function withValidation(
  processor: IFileProcessor,
  config?: Partial<ValidationConfig>
): ValidationDecorator {
  return new ValidationDecorator(processor, config);
}

/**
 * Configurações padrão do validador
 */
export const VALIDATION_DEFAULTS = {
  MAX_FILE_SIZE: 100 * 1024 * 1024, // 100MB
  VALIDATION_TIMEOUT: 30000, // 30 segundos
  STOP_ON_FIRST_ERROR: false,
  VALIDATE_STRUCTURE: true,
  VALIDATE_CONTENT: false
} as const; 