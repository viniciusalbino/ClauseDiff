/**
 * Validador especializado de MIME types com whitelist configurável
 * Implementa detecção avançada, validação de conteúdo e anti-spoofing
 * 
 * @author ClauseDiff Team
 * @version 1.0.0
 */

/**
 * Configuração para validação de MIME types
 */
export interface MimeTypeValidationConfig {
  /** Lista de MIME types permitidos */
  allowedMimeTypes: string[];
  /** Lista de MIME types explicitamente bloqueados */
  blockedMimeTypes: string[];
  /** Se deve verificar consistência entre MIME type e extensão */
  validateConsistency: boolean;
  /** Se deve usar detecção por magic numbers */
  useMagicNumberDetection: boolean;
  /** Se deve permitir MIME types genéricos (application/octet-stream) */
  allowGenericTypes: boolean;
  /** Nível de rigor da validação */
  validationLevel: 'strict' | 'moderate' | 'lenient';
  /** Tamanho máximo para análise de conteúdo (bytes) */
  maxContentAnalysisSize: number;
}

/**
 * Resultado da validação de MIME type
 */
export interface MimeTypeValidationResult {
  /** Se o MIME type é válido */
  isValid: boolean;
  /** MIME type declarado */
  declaredMimeType: string;
  /** MIME type detectado por análise */
  detectedMimeType?: string;
  /** Se há inconsistência entre declarado e detectado */
  hasInconsistency: boolean;
  /** Score de confiança na detecção (0-100) */
  confidence: number;
  /** Detalhes da validação */
  details: MimeTypeValidationDetails;
  /** Erros encontrados */
  errors: string[];
  /** Avisos gerados */
  warnings: string[];
}

/**
 * Detalhes da validação de MIME type
 */
export interface MimeTypeValidationDetails {
  /** Extensão do arquivo */
  fileExtension: string;
  /** Magic number detectado */
  magicNumber?: string;
  /** Categoria do MIME type (text, image, application, etc.) */
  category: string;
  /** Se é tipo executável ou perigoso */
  isDangerous: boolean;
  /** Características detectadas do arquivo */
  characteristics: FileCharacteristics;
}

/**
 * Características detectadas do arquivo
 */
export interface FileCharacteristics {
  /** Se é arquivo binário */
  isBinary: boolean;
  /** Se é arquivo comprimido */
  isCompressed: boolean;
  /** Se é arquivo executável */
  isExecutable: boolean;
  /** Se contém scripts */
  hasScripts: boolean;
  /** Encoding detectado (para arquivos de texto) */
  encoding?: string;
  /** Estrutura do arquivo é válida */
  hasValidStructure: boolean;
}

/**
 * Mapeamento de extensões para MIME types válidos
 */
const EXTENSION_MIME_MAP: Record<string, string[]> = {
  // Documentos de texto
  'txt': ['text/plain'],
  'md': ['text/markdown', 'text/plain'],
  'rtf': ['application/rtf', 'text/rtf'],
  
  // Documentos do Office
  'doc': ['application/msword'],
  'docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
  'xls': ['application/vnd.ms-excel'],
  'xlsx': ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
  'ppt': ['application/vnd.ms-powerpoint'],
  'pptx': ['application/vnd.openxmlformats-officedocument.presentationml.presentation'],
  
  // PDFs
  'pdf': ['application/pdf'],
  
  // Imagens
  'jpg': ['image/jpeg'],
  'jpeg': ['image/jpeg'],
  'png': ['image/png'],
  'gif': ['image/gif'],
  'bmp': ['image/bmp'],
  'webp': ['image/webp'],
  'svg': ['image/svg+xml'],
  
  // Áudio
  'mp3': ['audio/mpeg'],
  'wav': ['audio/wav'],
  'ogg': ['audio/ogg'],
  
  // Vídeo
  'mp4': ['video/mp4'],
  'avi': ['video/x-msvideo'],
  'mov': ['video/quicktime'],
  
  // Arquivos comprimidos
  'zip': ['application/zip'],
  'rar': ['application/vnd.rar'],
  '7z': ['application/x-7z-compressed'],
  'tar': ['application/x-tar'],
  'gz': ['application/gzip'],
  
  // Código/Scripts
  'js': ['application/javascript', 'text/javascript'],
  'json': ['application/json'],
  'xml': ['application/xml', 'text/xml'],
  'html': ['text/html'],
  'css': ['text/css'],
  
  // Executáveis (geralmente bloqueados)
  'exe': ['application/x-msdownload'],
  'msi': ['application/x-msi'],
  'bat': ['application/x-bat'],
  'com': ['application/x-msdownload'],
  'scr': ['application/x-msdownload']
};

/**
 * Magic numbers para detecção de MIME types
 */
const MIME_MAGIC_SIGNATURES: Record<string, { signature: number[], mimeType: string, name: string }> = {
  // Documentos
  'PDF': { signature: [0x25, 0x50, 0x44, 0x46], mimeType: 'application/pdf', name: 'PDF Document' },
  'ZIP': { signature: [0x50, 0x4B, 0x03, 0x04], mimeType: 'application/zip', name: 'ZIP Archive' },
  'RAR': { signature: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07], mimeType: 'application/vnd.rar', name: 'RAR Archive' },
  
  // Imagens
  'JPEG': { signature: [0xFF, 0xD8, 0xFF], mimeType: 'image/jpeg', name: 'JPEG Image' },
  'PNG': { signature: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], mimeType: 'image/png', name: 'PNG Image' },
  'GIF87a': { signature: [0x47, 0x49, 0x46, 0x38, 0x37, 0x61], mimeType: 'image/gif', name: 'GIF Image' },
  'GIF89a': { signature: [0x47, 0x49, 0x46, 0x38, 0x39, 0x61], mimeType: 'image/gif', name: 'GIF Image' },
  'BMP': { signature: [0x42, 0x4D], mimeType: 'image/bmp', name: 'BMP Image' },
  'WEBP': { signature: [0x52, 0x49, 0x46, 0x46], mimeType: 'image/webp', name: 'WebP Image' },
  
  // Áudio/Vídeo
  'MP3': { signature: [0xFF, 0xFB], mimeType: 'audio/mpeg', name: 'MP3 Audio' },
  'MP4': { signature: [0x66, 0x74, 0x79, 0x70], mimeType: 'video/mp4', name: 'MP4 Video' },
  'AVI': { signature: [0x52, 0x49, 0x46, 0x46], mimeType: 'video/x-msvideo', name: 'AVI Video' },
  
  // Executáveis (perigosos)
  'EXE': { signature: [0x4D, 0x5A], mimeType: 'application/x-msdownload', name: 'Windows Executable' },
  'ELF': { signature: [0x7F, 0x45, 0x4C, 0x46], mimeType: 'application/x-executable', name: 'Linux Executable' },
  
  // Scripts
  'HTML': { signature: [0x3C, 0x68, 0x74, 0x6D, 0x6C], mimeType: 'text/html', name: 'HTML Document' },
  'XML': { signature: [0x3C, 0x3F, 0x78, 0x6D, 0x6C], mimeType: 'application/xml', name: 'XML Document' }
};

/**
 * MIME types considerados perigosos
 */
const DANGEROUS_MIME_TYPES = [
  'application/x-msdownload',
  'application/x-executable',
  'application/x-msi',
  'application/x-bat',
  'application/x-sh',
  'application/x-csh',
  'application/x-perl',
  'application/x-python',
  'application/javascript',
  'text/javascript',
  'application/x-php',
  'text/x-php'
];

/**
 * Classe principal para validação de MIME types
 */
export class MimeTypeValidator {
  private config: MimeTypeValidationConfig;

  constructor(config: Partial<MimeTypeValidationConfig> = {}) {
    this.config = {
      allowedMimeTypes: [
        'text/plain',
        'application/pdf',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/msword'
      ],
      blockedMimeTypes: [...DANGEROUS_MIME_TYPES],
      validateConsistency: true,
      useMagicNumberDetection: true,
      allowGenericTypes: false,
      validationLevel: 'strict',
      maxContentAnalysisSize: 1024 * 1024, // 1MB
      ...config
    };
  }

  /**
   * Valida MIME type de um arquivo
   */
  public async validate(file: File): Promise<MimeTypeValidationResult> {
    const declaredMimeType = file.type || 'application/octet-stream';
    const fileExtension = this.extractFileExtension(file.name);
    const errors: string[] = [];
    const warnings: string[] = [];

    // Verifica se MIME type está na lista de bloqueados
    if (this.config.blockedMimeTypes.includes(declaredMimeType)) {
      errors.push(`MIME type '${declaredMimeType}' is explicitly blocked`);
    }

    // Verifica se MIME type está na lista de permitidos
    if (!this.config.allowedMimeTypes.includes(declaredMimeType)) {
      errors.push(`MIME type '${declaredMimeType}' is not in the allowed list`);
    }

    // Verifica MIME types genéricos
    if (!this.config.allowGenericTypes && this.isGenericMimeType(declaredMimeType)) {
      errors.push(`Generic MIME type '${declaredMimeType}' is not allowed`);
    }

    // Detecta MIME type por análise de conteúdo
    let detectedMimeType: string | undefined;
    let confidence = 100;
    let hasInconsistency = false;

    if (this.config.useMagicNumberDetection) {
      try {
        const detectionResult = await this.detectMimeTypeByContent(file);
        detectedMimeType = detectionResult.mimeType;
        confidence = detectionResult.confidence;

        if (detectedMimeType && declaredMimeType !== detectedMimeType) {
          hasInconsistency = true;
          
          if (this.config.validationLevel === 'strict') {
            errors.push(`MIME type mismatch: declared '${declaredMimeType}' vs detected '${detectedMimeType}'`);
          } else {
            warnings.push(`MIME type mismatch: declared '${declaredMimeType}' vs detected '${detectedMimeType}'`);
          }
        }
      } catch (error) {
        warnings.push(`Failed to detect MIME type from content: ${error}`);
        confidence = 50;
      }
    }

    // Valida consistência com extensão
    if (this.config.validateConsistency) {
      const consistencyResult = this.validateExtensionConsistency(declaredMimeType, fileExtension);
      if (!consistencyResult.isConsistent) {
        if (this.config.validationLevel === 'strict') {
          errors.push(consistencyResult.message);
        } else {
          warnings.push(consistencyResult.message);
        }
      }
    }

    // Analisa características do arquivo
    const characteristics = await this.analyzeFileCharacteristics(file);
    
    // Verifica se é arquivo perigoso
    const isDangerous = this.isDangerousFile(declaredMimeType, detectedMimeType, characteristics);
    if (isDangerous) {
      errors.push('File appears to be dangerous or executable');
    }

    const details: MimeTypeValidationDetails = {
      fileExtension,
      category: this.getMimeTypeCategory(declaredMimeType),
      isDangerous,
      characteristics
    };

    const isValid = errors.length === 0;

    return {
      isValid,
      declaredMimeType,
      detectedMimeType,
      hasInconsistency,
      confidence,
      details,
      errors,
      warnings
    };
  }

  /**
   * Detecta MIME type por análise de conteúdo
   */
  private async detectMimeTypeByContent(file: File): Promise<{ mimeType: string, confidence: number }> {
    const header = await this.readFileHeader(file, 32);
    
    // Tenta detectar por magic numbers
    for (const [name, info] of Object.entries(MIME_MAGIC_SIGNATURES)) {
      if (this.matchesSignature(header, info.signature)) {
        return { mimeType: info.mimeType, confidence: 95 };
      }
    }

    // Verifica se é arquivo de texto
    if (this.isTextContent(header)) {
      // Para arquivos pequenos, lê todo o conteúdo
      if (file.size <= this.config.maxContentAnalysisSize) {
        const content = await this.readFileAsText(file);
        
        // Detecta tipo específico de texto
        if (content.includes('<!DOCTYPE html') || content.includes('<html')) {
          return { mimeType: 'text/html', confidence: 90 };
        }
        
        if (content.includes('<?xml')) {
          return { mimeType: 'application/xml', confidence: 90 };
        }
        
        if (this.isJSON(content)) {
          return { mimeType: 'application/json', confidence: 90 };
        }
      }
      
      return { mimeType: 'text/plain', confidence: 80 };
    }

    // Se não conseguiu detectar
    throw new Error('Could not determine MIME type from content');
  }

  /**
   * Valida consistência entre MIME type e extensão
   */
  private validateExtensionConsistency(mimeType: string, extension: string): { isConsistent: boolean, message: string } {
    const validMimeTypes = EXTENSION_MIME_MAP[extension.toLowerCase()];
    
    if (!validMimeTypes) {
      return {
        isConsistent: false,
        message: `Unknown file extension '${extension}'`
      };
    }

    if (!validMimeTypes.includes(mimeType)) {
      return {
        isConsistent: false,
        message: `MIME type '${mimeType}' is not valid for extension '${extension}'. Expected: ${validMimeTypes.join(', ')}`
      };
    }

    return { isConsistent: true, message: 'Extension and MIME type are consistent' };
  }

  /**
   * Analisa características do arquivo
   */
  private async analyzeFileCharacteristics(file: File): Promise<FileCharacteristics> {
    const header = await this.readFileHeader(file, 1024);
    const characteristics: FileCharacteristics = {
      isBinary: !this.isTextContent(header),
      isCompressed: this.isCompressedFile(header),
      isExecutable: this.isExecutableFile(header),
      hasScripts: false,
      hasValidStructure: true
    };

    // Para arquivos de texto, analisa conteúdo
    if (!characteristics.isBinary && file.size <= this.config.maxContentAnalysisSize) {
      try {
        const content = await this.readFileAsText(file);
        characteristics.hasScripts = this.hasScriptContent(content);
        characteristics.encoding = this.detectEncoding(header);
      } catch (error) {
        // Se falhou ao ler como texto, provavelmente é binário
        characteristics.isBinary = true;
      }
    }

    return characteristics;
  }

  /**
   * Verifica se arquivo é perigoso
   */
  private isDangerousFile(
    declaredMimeType: string, 
    detectedMimeType: string | undefined, 
    characteristics: FileCharacteristics
  ): boolean {
    // Verifica MIME types perigosos
    if (DANGEROUS_MIME_TYPES.includes(declaredMimeType)) {
      return true;
    }

    if (detectedMimeType && DANGEROUS_MIME_TYPES.includes(detectedMimeType)) {
      return true;
    }

    // Verifica características perigosas
    if (characteristics.isExecutable || characteristics.hasScripts) {
      return true;
    }

    return false;
  }

  /**
   * Utilitários de análise de arquivo
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
          reject(new Error('Failed to read file header'));
        }
      };
      
      reader.onerror = () => reject(reader.error);
      reader.readAsArrayBuffer(slice);
    });
  }

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

  private matchesSignature(buffer: number[], signature: number[]): boolean {
    if (buffer.length < signature.length) return false;
    
    for (let i = 0; i < signature.length; i++) {
      if (buffer[i] !== signature[i]) return false;
    }
    
    return true;
  }

  private isTextContent(buffer: number[]): boolean {
    // Verifica primeiros bytes para determinar se é texto
    for (let i = 0; i < Math.min(buffer.length, 512); i++) {
      const byte = buffer[i];
      
      // Null byte indica binário
      if (byte === 0) return false;
      
      // Bytes de controle não válidos para texto
      if (byte < 32 && ![9, 10, 13].includes(byte)) return false;
    }
    
    return true;
  }

  private isCompressedFile(buffer: number[]): boolean {
    // ZIP signature
    if (this.matchesSignature(buffer, [0x50, 0x4B, 0x03, 0x04])) return true;
    
    // RAR signature
    if (this.matchesSignature(buffer, [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07])) return true;
    
    // GZIP signature
    if (this.matchesSignature(buffer, [0x1F, 0x8B])) return true;
    
    // 7Z signature
    if (this.matchesSignature(buffer, [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C])) return true;
    
    return false;
  }

  private isExecutableFile(buffer: number[]): boolean {
    // Windows PE executable
    if (this.matchesSignature(buffer, [0x4D, 0x5A])) return true;
    
    // Linux ELF executable
    if (this.matchesSignature(buffer, [0x7F, 0x45, 0x4C, 0x46])) return true;
    
    // Mach-O executable (macOS)
    if (this.matchesSignature(buffer, [0xFE, 0xED, 0xFA, 0xCE])) return true;
    if (this.matchesSignature(buffer, [0xFE, 0xED, 0xFA, 0xCF])) return true;
    
    return false;
  }

  private hasScriptContent(content: string): boolean {
    const scriptPatterns = [
      /<script/gi,
      /javascript:/gi,
      /vbscript:/gi,
      /<\?php/gi,
      /<%/gi,
      /exec\s*\(/gi,
      /eval\s*\(/gi
    ];

    return scriptPatterns.some(pattern => pattern.test(content));
  }

  private isJSON(content: string): boolean {
    try {
      JSON.parse(content.trim());
      return true;
    } catch {
      return false;
    }
  }

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
    
    return 'utf-8';
  }

  private extractFileExtension(filename: string): string {
    const parts = filename.split('.');
    return parts.length > 1 ? parts.pop()!.toLowerCase() : '';
  }

  private isGenericMimeType(mimeType: string): boolean {
    const genericTypes = [
      'application/octet-stream',
      'text/plain',
      'application/unknown'
    ];
    
    return genericTypes.includes(mimeType);
  }

  private getMimeTypeCategory(mimeType: string): string {
    const category = mimeType.split('/')[0];
    return category || 'unknown';
  }

  /**
   * Atualiza configuração do validador
   */
  public updateConfig(newConfig: Partial<MimeTypeValidationConfig>): void {
    this.config = { ...this.config, ...newConfig };
  }

  /**
   * Obtém configuração atual
   */
  public getConfig(): Readonly<MimeTypeValidationConfig> {
    return { ...this.config };
  }

  /**
   * Adiciona MIME type à lista de permitidos
   */
  public addAllowedMimeType(mimeType: string): void {
    if (!this.config.allowedMimeTypes.includes(mimeType)) {
      this.config.allowedMimeTypes.push(mimeType);
    }
  }

  /**
   * Remove MIME type da lista de permitidos
   */
  public removeAllowedMimeType(mimeType: string): void {
    const index = this.config.allowedMimeTypes.indexOf(mimeType);
    if (index > -1) {
      this.config.allowedMimeTypes.splice(index, 1);
    }
  }

  /**
   * Adiciona MIME type à lista de bloqueados
   */
  public addBlockedMimeType(mimeType: string): void {
    if (!this.config.blockedMimeTypes.includes(mimeType)) {
      this.config.blockedMimeTypes.push(mimeType);
    }
  }

  /**
   * Remove MIME type da lista de bloqueados
   */
  public removeBlockedMimeType(mimeType: string): void {
    const index = this.config.blockedMimeTypes.indexOf(mimeType);
    if (index > -1) {
      this.config.blockedMimeTypes.splice(index, 1);
    }
  }
}

/**
 * Factory function para criar validador de MIME types
 */
export function createMimeTypeValidator(config?: Partial<MimeTypeValidationConfig>): MimeTypeValidator {
  return new MimeTypeValidator(config);
}

/**
 * Função utilitária para validação rápida de MIME type
 */
export async function validateMimeType(
  file: File, 
  allowedTypes: string[] = ['text/plain', 'application/pdf']
): Promise<boolean> {
  const validator = createMimeTypeValidator({ allowedMimeTypes: allowedTypes });
  const result = await validator.validate(file);
  return result.isValid;
} 