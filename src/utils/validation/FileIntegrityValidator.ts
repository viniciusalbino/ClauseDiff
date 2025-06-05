/**
 * Validador simples de integridade de arquivo
 * Verifica corrupção e consistência usando hashes
 */

export interface IntegrityCheckResult {
  isValid: boolean;
  hash: string;
  errors: string[];
  fileInfo: {
    size: number;
    lastModified: number;
    type: string;
  };
}

export class FileIntegrityValidator {
  
  /**
   * Verifica integridade do arquivo
   */
  async validateIntegrity(file: File, expectedHash?: string): Promise<IntegrityCheckResult> {
    const errors: string[] = [];
    
    // 1. Calcula hash do arquivo
    const hash = await this.calculateFileHash(file);
    
    // 2. Verifica se arquivo não está vazio
    if (file.size === 0) {
      errors.push('File is empty');
    }
    
    // 3. Verifica se arquivo não é muito grande (possível corrupção)
    if (file.size > 100 * 1024 * 1024) { // 100MB
      errors.push('File size exceeds safe limits');
    }
    
    // 4. Verifica hash esperado se fornecido
    if (expectedHash && hash !== expectedHash) {
      errors.push(`Hash mismatch: expected ${expectedHash}, got ${hash}`);
    }
    
    // 5. Tenta ler início do arquivo para verificar corrupção
    try {
      await this.readFileHeader(file);
    } catch (error) {
      errors.push('Unable to read file content - possibly corrupted');
    }
    
    return {
      isValid: errors.length === 0,
      hash,
      errors,
      fileInfo: {
        size: file.size,
        lastModified: file.lastModified,
        type: file.type
      }
    };
  }
  
  /**
   * Calcula hash SHA-256 do arquivo
   */
  async calculateFileHash(file: File): Promise<string> {
    const buffer = await this.fileToArrayBuffer(file);
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }
  
  /**
   * Verifica se arquivo mudou comparando com hash anterior
   */
  async hasFileChanged(file: File, previousHash: string): Promise<boolean> {
    const currentHash = await this.calculateFileHash(file);
    return currentHash !== previousHash;
  }
  
  /**
   * Utilitários
   */
  private async fileToArrayBuffer(file: File): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      
      reader.onload = () => {
        if (reader.result instanceof ArrayBuffer) {
          resolve(reader.result);
        } else {
          reject(new Error('Failed to read file as ArrayBuffer'));
        }
      };
      
      reader.onerror = () => reject(reader.error);
      reader.readAsArrayBuffer(file);
    });
  }
  
  private async readFileHeader(file: File): Promise<void> {
    const slice = file.slice(0, 1024); // Lê primeiro 1KB
    await this.fileToArrayBuffer(slice as File);
  }
}

/**
 * Função utilitária para verificação rápida
 */
export async function checkFileIntegrity(file: File, expectedHash?: string): Promise<IntegrityCheckResult> {
  const validator = new FileIntegrityValidator();
  return validator.validateIntegrity(file, expectedHash);
}

/**
 * Gera hash de arquivo para verificação futura
 */
export async function generateFileHash(file: File): Promise<string> {
  const validator = new FileIntegrityValidator();
  return validator.calculateFileHash(file);
} 