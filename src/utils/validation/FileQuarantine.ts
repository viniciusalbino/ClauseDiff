/**
 * Sistema simples de quarentena para arquivos suspeitos
 * Armazena arquivos temporariamente até decisão manual
 */

export interface QuarantinedFile {
  id: string;
  originalName: string;
  reason: string;
  timestamp: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  size: number;
  hash: string;
}

export interface QuarantineAction {
  action: 'quarantine' | 'release' | 'delete';
  reason: string;
}

export class FileQuarantine {
  private quarantinedFiles = new Map<string, QuarantinedFile>();
  private maxQuarantineSize = 50 * 1024 * 1024; // 50MB max
  private maxQuarantineTime = 24 * 60 * 60 * 1000; // 24 horas
  
  /**
   * Coloca arquivo em quarentena
   */
  async quarantineFile(
    file: File, 
    reason: string, 
    riskLevel: 'low' | 'medium' | 'high' | 'critical'
  ): Promise<string> {
    
    // Verifica limites de quarentena
    if (this.getTotalQuarantineSize() + file.size > this.maxQuarantineSize) {
      this.cleanupOldFiles();
    }
    
    const id = this.generateId();
    const hash = await this.calculateHash(file);
    
    const quarantinedFile: QuarantinedFile = {
      id,
      originalName: file.name,
      reason,
      timestamp: Date.now(),
      riskLevel,
      size: file.size,
      hash
    };
    
    this.quarantinedFiles.set(id, quarantinedFile);
    
    console.warn(`File quarantined: ${file.name} - ${reason}`);
    
    return id;
  }
  
  /**
   * Libera arquivo da quarentena
   */
  releaseFile(id: string): boolean {
    const file = this.quarantinedFiles.get(id);
    if (!file) return false;
    
    this.quarantinedFiles.delete(id);
    console.info(`File released from quarantine: ${file.originalName}`);
    
    return true;
  }
  
  /**
   * Remove arquivo permanentemente
   */
  deleteFile(id: string): boolean {
    const file = this.quarantinedFiles.get(id);
    if (!file) return false;
    
    this.quarantinedFiles.delete(id);
    console.info(`File permanently deleted: ${file.originalName}`);
    
    return true;
  }
  
  /**
   * Lista arquivos em quarentena
   */
  listQuarantinedFiles(): QuarantinedFile[] {
    return Array.from(this.quarantinedFiles.values());
  }
  
  /**
   * Verifica se arquivo está em quarentena
   */
  isFileQuarantined(hash: string): boolean {
    return Array.from(this.quarantinedFiles.values())
      .some(file => file.hash === hash);
  }
  
  /**
   * Obtém estatísticas da quarentena
   */
  getQuarantineStats() {
    const files = Array.from(this.quarantinedFiles.values());
    
    return {
      totalFiles: files.length,
      totalSize: files.reduce((sum, file) => sum + file.size, 0),
      riskLevels: {
        critical: files.filter(f => f.riskLevel === 'critical').length,
        high: files.filter(f => f.riskLevel === 'high').length,
        medium: files.filter(f => f.riskLevel === 'medium').length,
        low: files.filter(f => f.riskLevel === 'low').length
      }
    };
  }
  
  /**
   * Decide automaticamente baseado no risco
   */
  shouldQuarantine(riskLevel: 'low' | 'medium' | 'high' | 'critical'): boolean {
    return riskLevel === 'high' || riskLevel === 'critical';
  }
  
  /**
   * Limpeza automática de arquivos antigos
   */
  private cleanupOldFiles(): void {
    const now = Date.now();
    const filesToRemove: string[] = [];
    
    for (const [id, file] of this.quarantinedFiles) {
      if (now - file.timestamp > this.maxQuarantineTime) {
        filesToRemove.push(id);
      }
    }
    
    filesToRemove.forEach(id => {
      const file = this.quarantinedFiles.get(id);
      this.quarantinedFiles.delete(id);
      console.info(`Auto-cleanup: removed expired file ${file?.originalName}`);
    });
  }
  
  /**
   * Utilitários
   */
  private generateId(): string {
    return 'quar_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  }
  
  private getTotalQuarantineSize(): number {
    return Array.from(this.quarantinedFiles.values())
      .reduce((sum, file) => sum + file.size, 0);
  }
  
  private async calculateHash(file: File): Promise<string> {
    const buffer = await this.fileToArrayBuffer(file);
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }
  
  private async fileToArrayBuffer(file: File): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      
      reader.onload = () => {
        if (reader.result instanceof ArrayBuffer) {
          resolve(reader.result);
        } else {
          reject(new Error('Failed to read file'));
        }
      };
      
      reader.onerror = () => reject(reader.error);
      reader.readAsArrayBuffer(file);
    });
  }
}

// Instância global
export const fileQuarantine = new FileQuarantine();

/**
 * Função utilitária para quarentena rápida
 */
export async function quarantineIfNeeded(
  file: File,
  threats: string[],
  riskLevel: 'low' | 'medium' | 'high' | 'critical'
): Promise<string | null> {
  
  if (fileQuarantine.shouldQuarantine(riskLevel)) {
    const reason = `Risk level: ${riskLevel}. Threats: ${threats.join(', ')}`;
    return await fileQuarantine.quarantineFile(file, reason, riskLevel);
  }
  
  return null;
} 