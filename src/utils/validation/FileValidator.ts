/**
 * Validador avançado de arquivos com configuração flexível
 * Implementa validação de tamanho, tipo MIME, estrutura e segurança
 * 
 * @author ClauseDiff Team
 * @version 1.0.0
 */

/**
 * Configuração de validação obtida de environment variables
 */
interface ValidationConfig {
  /** Tamanho máximo em bytes (padrão: 50MB) */
  maxFileSize: number;
  /** Tamanho mínimo em bytes (padrão: 1 byte) */
  minFileSize: number;
  /** Tipos MIME permitidos */
  allowedMimeTypes: string[];
  /** Extensões de arquivo permitidas */
  allowedExtensions: string[];
  /** Se deve validar magic numbers */
  validateMagicNumbers: boolean;
  /** Se deve verificar arquivos maliciosos */
  checkMaliciousContent: boolean;
  /** Limite de tempo para validação (ms) */
  validationTimeout: number;
  /** Se deve fazer validação rigorosa */
  strictValidation: boolean;
}

/**
 * Resultado de validação detalhado
 */
export interface ValidationResult {
  /** Se o arquivo é válido */
  isValid: boolean;
  /** Lista de erros encontrados */
  errors: ValidationError[];
  /** Lista de avisos */
  warnings: ValidationWarning[];
  /** Score de confiança (0-100) */
  confidenceScore: number;
  /** Tempo de validação em ms */
  validationTime: number;
  /** Metadados descobertos */
  metadata: FileValidationMetadata;
}

/**
 * Erro de validação
 */
export interface ValidationError {
  /** Código do erro */
  code: string;
  /** Mensagem de erro */
  message: string;
  /** Campo que causou o erro */
  field?: string;
  /** Valor que causou o erro */
  value?: any;
  /** Severidade do erro */
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** Sugestão de correção */
  suggestion?: string;
}

/**
 * Aviso de validação
 */
export interface ValidationWarning {
  /** Código do aviso */
  code: string;
  /** Mensagem do aviso */
  message: string;
  /** Contexto adicional */
  context?: Record<string, any>;
}

/**
 * Metadados descobertos durante validação
 */
export interface FileValidationMetadata {
  /** Tipo MIME detectado */
  detectedMimeType: string;
  /** Extensão detectada */
  detectedExtension: string;
  /** Magic number encontrado */
  magicNumber?: string;
  /** Se é arquivo binário */
  isBinary: boolean;
  /** Encoding detectado */
  encoding?: string;
  /** Estrutura do arquivo válida */
  hasValidStructure: boolean;
  /** Indicadores de segurança */
  securityFlags: string[];
}

/**
 * Regra de validação customizável
 */
export interface ValidationRule {
  /** Nome da regra */
  name: string;
  /** Descrição da regra */
  description: string;
  /** Função de validação */
  validate: (file: File, config: ValidationConfig) => Promise<ValidationRuleResult>;
  /** Prioridade da regra (0-100) */
  priority: number;
  /** Se a regra é obrigatória */
  required: boolean;
}

/**
 * Resultado de uma regra de validação
 */
export interface ValidationRuleResult {
  /** Se passou na validação */
  passed: boolean;
  /** Erro se não passou */
  error?: ValidationError;
  /** Avisos gerados */
  warnings?: ValidationWarning[];
  /** Metadados descobertos */
  metadata?: Partial<FileValidationMetadata>;
  /** Score de confiança (0-100) */
  confidence: number;
}

/**
 * Magic numbers para validação de tipo de arquivo
 */
const MAGIC_NUMBERS: Record<string, { signature: number[], mimeType: string, extension: string }> = {
  // PDF
  'PDF': { signature: [0x25, 0x50, 0x44, 0x46], mimeType: 'application/pdf', extension: 'pdf' },
  // DOCX (ZIP signature)
  'ZIP': { signature: [0x50, 0x4B, 0x03, 0x04], mimeType: 'application/zip', extension: 'zip' },
  // Plain text (UTF-8 BOM)
  'UTF8_BOM': { signature: [0xEF, 0xBB, 0xBF], mimeType: 'text/plain', extension: 'txt' },
  // JPEG
  'JPEG': { signature: [0xFF, 0xD8, 0xFF], mimeType: 'image/jpeg', extension: 'jpg' },
  // PNG
  'PNG': { signature: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], mimeType: 'image/png', extension: 'png' },
  // GIF
  'GIF87a': { signature: [0x47, 0x49, 0x46, 0x38, 0x37, 0x61], mimeType: 'image/gif', extension: 'gif' },
  'GIF89a': { signature: [0x47, 0x49, 0x46, 0x38, 0x39, 0x61], mimeType: 'image/gif', extension: 'gif' }
};

/**
 * Patterns suspeitos para detecção de conteúdo malicioso
 */
const MALICIOUS_PATTERNS = [
  // Scripts e códigos perigosos
  /<script[^>]*>.*?<\/script>/gi,
  /javascript:/gi,
  /vbscript:/gi,
  /onload\s*=/gi,
  /onerror\s*=/gi,
  /onclick\s*=/gi,
  
  // Comandos de sistema
  /exec\s*\(/gi,
  /eval\s*\(/gi,
  /system\s*\(/gi,
  /shell_exec/gi,
  /passthru/gi,
  
  // Injeções SQL
  /union\s+select/gi,
  /drop\s+table/gi,
  /insert\s+into/gi,
  /delete\s+from/gi,
  
  // Códigos maliciosos comuns
  /<?php/gi,
  /<\?=/gi,
  /<%/gi,
  /\$_GET\[/gi,
  /\$_POST\[/gi
];

/**
 * Classe principal para validação de arquivos
 */
export class FileValidator {
  private config: ValidationConfig;
  private rules: Map<string, ValidationRule> = new Map();

  constructor(customConfig?: Partial<ValidationConfig>) {
    this.config = this.loadConfiguration(customConfig);
    this.registerDefaultRules();
  }

  /**
   * Carrega configuração de environment variables ou usa padrões
   */
  private loadConfiguration(customConfig?: Partial<ValidationConfig>): ValidationConfig {
    const defaultConfig: ValidationConfig = {
      maxFileSize: parseInt(process.env.MAX_FILE_SIZE || '52428800'), // 50MB
      minFileSize: parseInt(process.env.MIN_FILE_SIZE || '1'),
      allowedMimeTypes: (process.env.ALLOWED_MIME_TYPES || 'text/plain,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document').split(','),
      allowedExtensions: (process.env.ALLOWED_EXTENSIONS || 'txt,pdf,docx,doc').split(','),
      validateMagicNumbers: process.env.VALIDATE_MAGIC_NUMBERS !== 'false',
      checkMaliciousContent: process.env.CHECK_MALICIOUS_CONTENT !== 'false',
      validationTimeout: parseInt(process.env.VALIDATION_TIMEOUT || '30000'), // 30s
      strictValidation: process.env.STRICT_VALIDATION === 'true'
    };

    return { ...defaultConfig, ...customConfig };
  }

  /**
   * Registra regras de validação padrão
   */
  private registerDefaultRules(): void {
    // Regra de validação de tamanho
    this.addRule({
      name: 'file-size',
      description: 'Validates file size within configured limits',
      priority: 100,
      required: true,
      validate: async (file: File, config: ValidationConfig): Promise<ValidationRuleResult> => {
        const { size } = file;
        
        if (size < config.minFileSize) {
          return {
            passed: false,
            error: {
              code: 'FILE_TOO_SMALL',
              message: `File size ${size} bytes is below minimum ${config.minFileSize} bytes`,
              field: 'size',
              value: size,
              severity: 'medium',
              suggestion: `Ensure file is at least ${config.minFileSize} bytes`
            },
            confidence: 100
          };
        }

        if (size > config.maxFileSize) {
          return {
            passed: false,
            error: {
              code: 'FILE_TOO_LARGE',
              message: `File size ${size} bytes exceeds maximum ${config.maxFileSize} bytes`,
              field: 'size',
              value: size,
              severity: 'high',
              suggestion: `Reduce file size to under ${Math.round(config.maxFileSize / 1024 / 1024)}MB`
            },
            confidence: 100
          };
        }

        return {
          passed: true,
          confidence: 100,
          metadata: { hasValidStructure: true }
        };
      }
    });

    // Regra de validação de tipo MIME
    this.addRule({
      name: 'mime-type',
      description: 'Validates MIME type against allowed types',
      priority: 90,
      required: true,
      validate: async (file: File, config: ValidationConfig): Promise<ValidationRuleResult> => {
        const { type } = file;
        
        if (!type) {
          return {
            passed: false,
            error: {
              code: 'MISSING_MIME_TYPE',
              message: 'File has no MIME type',
              field: 'type',
              value: type,
              severity: 'medium',
              suggestion: 'Ensure file has a valid MIME type'
            },
            confidence: 90
          };
        }

        if (!config.allowedMimeTypes.includes(type)) {
          return {
            passed: false,
            error: {
              code: 'INVALID_MIME_TYPE',
              message: `MIME type '${type}' is not allowed`,
              field: 'type',
              value: type,
              severity: 'high',
              suggestion: `Use one of: ${config.allowedMimeTypes.join(', ')}`
            },
            confidence: 95
          };
        }

        return {
          passed: true,
          confidence: 95,
          metadata: { detectedMimeType: type }
        };
      }
    });

    // Regra de validação de extensão
    this.addRule({
      name: 'file-extension',
      description: 'Validates file extension against allowed extensions',
      priority: 80,
      required: true,
      validate: async (file: File, config: ValidationConfig): Promise<ValidationRuleResult> => {
        const { name } = file;
        const extension = name.split('.').pop()?.toLowerCase() || '';
        
        if (!extension) {
          return {
            passed: false,
            error: {
              code: 'MISSING_EXTENSION',
              message: 'File has no extension',
              field: 'name',
              value: name,
              severity: 'medium',
              suggestion: 'Add a valid file extension'
            },
            confidence: 85
          };
        }

        if (!config.allowedExtensions.includes(extension)) {
          return {
            passed: false,
            error: {
              code: 'INVALID_EXTENSION',
              message: `Extension '${extension}' is not allowed`,
              field: 'name',
              value: extension,
              severity: 'high',
              suggestion: `Use one of: ${config.allowedExtensions.join(', ')}`
            },
            confidence: 90
          };
        }

        return {
          passed: true,
          confidence: 90,
          metadata: { detectedExtension: extension }
        };
      }
    });

    // Regra de validação de magic numbers
    this.addRule({
      name: 'magic-numbers',
      description: 'Validates file signature using magic numbers',
      priority: 70,
      required: false,
      validate: async (file: File, config: ValidationConfig): Promise<ValidationRuleResult> => {
        if (!config.validateMagicNumbers) {
          return { passed: true, confidence: 0 };
        }

        const buffer = await this.readFileHeader(file, 16);
        const detectedType = this.detectFileTypeByMagicNumber(buffer);
        
        const warnings: ValidationWarning[] = [];
        let confidence = 80;

        if (detectedType) {
          // Verifica se o tipo detectado corresponde ao MIME type declarado
          if (detectedType.mimeType !== file.type) {
            warnings.push({
              code: 'MIME_TYPE_MISMATCH',
              message: `Detected MIME type '${detectedType.mimeType}' differs from declared '${file.type}'`,
              context: { detected: detectedType.mimeType, declared: file.type }
            });
            confidence = 60;
          }

          return {
            passed: true,
            warnings,
            confidence,
            metadata: {
              detectedMimeType: detectedType.mimeType,
              detectedExtension: detectedType.extension,
              magicNumber: buffer.slice(0, 8).join(' ')
            }
          };
        }

        // Se não conseguiu detectar, pode ser texto plano
        if (this.isTextFile(buffer)) {
          return {
            passed: true,
            confidence: 70,
            metadata: {
              detectedMimeType: 'text/plain',
              isBinary: false,
              encoding: this.detectEncoding(buffer)
            }
          };
        }

        // Arquivo não reconhecido
        if (config.strictValidation) {
          return {
            passed: false,
            error: {
              code: 'UNRECOGNIZED_FILE_TYPE',
              message: 'Could not determine file type from content',
              field: 'content',
              severity: 'medium',
              suggestion: 'Ensure file is a valid document'
            },
            confidence: 30
          };
        }

        return {
          passed: true,
          warnings: [{
            code: 'UNKNOWN_FILE_TYPE',
            message: 'Could not determine file type from magic numbers',
            context: { magicNumber: buffer.slice(0, 8).join(' ') }
          }],
          confidence: 40
        };
      }
    });

    // Regra de detecção de conteúdo malicioso
    this.addRule({
      name: 'malicious-content',
      description: 'Scans file content for malicious patterns',
      priority: 60,
      required: false,
      validate: async (file: File, config: ValidationConfig): Promise<ValidationRuleResult> => {
        if (!config.checkMaliciousContent) {
          return { passed: true, confidence: 0 };
        }

        try {
          const content = await this.readFileAsText(file);
          const threats = this.scanForMaliciousPatterns(content);
          
          if (threats.length > 0) {
            return {
              passed: false,
              error: {
                code: 'MALICIOUS_CONTENT_DETECTED',
                message: `Detected ${threats.length} potential security threats`,
                field: 'content',
                severity: 'critical',
                suggestion: 'Remove suspicious content before uploading'
              },
              confidence: 95,
              metadata: { securityFlags: threats }
            };
          }

          return {
            passed: true,
            confidence: 90,
            metadata: { securityFlags: [] }
          };

        } catch (error) {
          // Se não conseguiu ler como texto, pode ser binário válido
          return {
            passed: true,
            warnings: [{
              code: 'BINARY_FILE_SKIP_SCAN',
              message: 'Skipped malicious content scan for binary file',
              context: { reason: 'Cannot read as text' }
            }],
            confidence: 70,
            metadata: { isBinary: true }
          };
        }
      }
    });
  }

  /**
   * Adiciona uma regra de validação customizada
   */
  public addRule(rule: ValidationRule): void {
    this.rules.set(rule.name, rule);
  }

  /**
   * Remove uma regra de validação
   */
  public removeRule(name: string): boolean {
    return this.rules.delete(name);
  }

  /**
   * Valida um arquivo usando todas as regras registradas
   */
  public async validate(file: File): Promise<ValidationResult> {
    const startTime = Date.now();
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];
    const metadata: FileValidationMetadata = {
      detectedMimeType: file.type,
      detectedExtension: file.name.split('.').pop()?.toLowerCase() || '',
      isBinary: false,
      hasValidStructure: false,
      securityFlags: []
    };

    // Ordena regras por prioridade
    const sortedRules = Array.from(this.rules.values())
      .sort((a, b) => b.priority - a.priority);

    let totalConfidence = 0;
    let ruleCount = 0;

    // Executa validação com timeout
    const validationPromise = this.executeRulesWithTimeout(
      sortedRules, 
      file, 
      this.config.validationTimeout
    );

    try {
      const results = await validationPromise;

      for (const result of results) {
        if (result.error) {
          errors.push(result.error);
        }
        
        if (result.warnings) {
          warnings.push(...result.warnings);
        }
        
        if (result.metadata) {
          Object.assign(metadata, result.metadata);
        }

        totalConfidence += result.confidence;
        ruleCount++;

        // Para em caso de erro crítico em regra obrigatória
        if (result.error && result.error.severity === 'critical') {
          break;
        }
      }

    } catch (error) {
      errors.push({
        code: 'VALIDATION_TIMEOUT',
        message: 'Validation timed out',
        severity: 'high',
        suggestion: 'Try with a smaller file or increase timeout'
      });
    }

    const validationTime = Date.now() - startTime;
    const confidenceScore = ruleCount > 0 ? Math.round(totalConfidence / ruleCount) : 0;
    const isValid = errors.length === 0;

    return {
      isValid,
      errors,
      warnings,
      confidenceScore,
      validationTime,
      metadata
    };
  }

  /**
   * Executa regras com timeout
   */
  private async executeRulesWithTimeout(
    rules: ValidationRule[],
    file: File,
    timeout: number
  ): Promise<ValidationRuleResult[]> {
    const results: ValidationRuleResult[] = [];

    for (const rule of rules) {
      const rulePromise = rule.validate(file, this.config);
      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error(`Rule '${rule.name}' timed out`)), timeout);
      });

      try {
        const result = await Promise.race([rulePromise, timeoutPromise]);
        results.push(result);

        // Para em caso de falha em regra obrigatória
        if (!result.passed && rule.required) {
          break;
        }
      } catch (error) {
        results.push({
          passed: false,
          error: {
            code: 'RULE_EXECUTION_ERROR',
            message: `Rule '${rule.name}' failed to execute: ${error}`,
            field: 'validation',
            severity: 'medium'
          },
          confidence: 0
        });
      }
    }

    return results;
  }

  /**
   * Lê header do arquivo para análise de magic numbers
   */
  private async readFileHeader(file: File, bytes: number): Promise<number[]> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      const slice = file.slice(0, bytes);
      
      reader.onload = () => {
        if (reader.result instanceof ArrayBuffer) {
          const array = new Uint8Array(reader.result);
          resolve(Array.from(array));
        } else {
          reject(new Error('Failed to read file as ArrayBuffer'));
        }
      };
      
      reader.onerror = () => reject(reader.error);
      reader.readAsArrayBuffer(slice);
    });
  }

  /**
   * Detecta tipo de arquivo por magic number
   */
  private detectFileTypeByMagicNumber(buffer: number[]): { signature: number[], mimeType: string, extension: string } | null {
    for (const [name, info] of Object.entries(MAGIC_NUMBERS)) {
      if (this.matchesSignature(buffer, info.signature)) {
        return info;
      }
    }
    return null;
  }

  /**
   * Verifica se buffer corresponde a uma assinatura
   */
  private matchesSignature(buffer: number[], signature: number[]): boolean {
    if (buffer.length < signature.length) return false;
    
    for (let i = 0; i < signature.length; i++) {
      if (buffer[i] !== signature[i]) return false;
    }
    
    return true;
  }

  /**
   * Verifica se é arquivo de texto
   */
  private isTextFile(buffer: number[]): boolean {
    // Verifica se todos os bytes são printable ASCII ou UTF-8
    for (const byte of buffer.slice(0, 1024)) { // Verifica primeiro 1KB
      if (byte === 0) return false; // Null byte indica binário
      if (byte > 127) continue; // Pode ser UTF-8
      if (byte < 32 && ![9, 10, 13].includes(byte)) return false; // Não é char de controle válido
    }
    return true;
  }

  /**
   * Detecta encoding do arquivo
   */
  private detectEncoding(buffer: number[]): string {
    // UTF-8 BOM
    if (buffer.length >= 3 && buffer[0] === 0xEF && buffer[1] === 0xBB && buffer[2] === 0xBF) {
      return 'utf-8-bom';
    }
    
    // UTF-16 LE BOM
    if (buffer.length >= 2 && buffer[0] === 0xFF && buffer[1] === 0xFE) {
      return 'utf-16le';
    }
    
    // UTF-16 BE BOM
    if (buffer.length >= 2 && buffer[0] === 0xFE && buffer[1] === 0xFF) {
      return 'utf-16be';
    }
    
    // Assume UTF-8 para texto
    return 'utf-8';
  }

  /**
   * Lê arquivo como texto para análise
   */
  private async readFileAsText(file: File): Promise<string> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      
      reader.onload = () => {
        if (typeof reader.result === 'string') {
          resolve(reader.result);
        } else {
          reject(new Error('Failed to read file as text'));
        }
      };
      
      reader.onerror = () => reject(reader.error);
      reader.readAsText(file);
    });
  }

  /**
   * Escaneia conteúdo em busca de padrões maliciosos
   */
  private scanForMaliciousPatterns(content: string): string[] {
    const threats: string[] = [];
    
    for (const pattern of MALICIOUS_PATTERNS) {
      if (pattern.test(content)) {
        threats.push(pattern.source);
      }
    }
    
    return threats;
  }

  /**
   * Atualiza configuração
   */
  public updateConfig(newConfig: Partial<ValidationConfig>): void {
    this.config = { ...this.config, ...newConfig };
  }

  /**
   * Obtém configuração atual
   */
  public getConfig(): Readonly<ValidationConfig> {
    return { ...this.config };
  }

  /**
   * Lista todas as regras registradas
   */
  public getRules(): ValidationRule[] {
    return Array.from(this.rules.values());
  }
}

/**
 * Factory function para criar validador com configuração padrão
 */
export function createFileValidator(config?: Partial<ValidationConfig>): FileValidator {
  return new FileValidator(config);
} 