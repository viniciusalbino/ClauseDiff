/**
 * Detector simples de conteúdo malicioso
 * Foca nos padrões mais comuns e perigosos
 */

export interface ThreatScanResult {
  isMalicious: boolean;
  threats: string[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
}

/**
 * Padrões maliciosos mais comuns
 */
const THREAT_PATTERNS = {
  // Scripts perigosos
  SCRIPT_INJECTION: [
    /<script[^>]*>.*?<\/script>/gi,
    /javascript:/gi,
    /vbscript:/gi,
    /onload\s*=/gi,
    /onerror\s*=/gi
  ],
  
  // Comandos de sistema
  SYSTEM_COMMANDS: [
    /exec\s*\(/gi,
    /eval\s*\(/gi,
    /system\s*\(/gi,
    /shell_exec/gi
  ],
  
  // Injeções SQL
  SQL_INJECTION: [
    /union\s+select/gi,
    /drop\s+table/gi,
    /delete\s+from/gi
  ],
  
  // Executáveis suspeitos
  EXECUTABLES: [
    /\.exe$/gi,
    /\.bat$/gi,
    /\.scr$/gi,
    /\.com$/gi
  ]
};

/**
 * Assinaturas de arquivos perigosos (magic numbers)
 */
const DANGEROUS_SIGNATURES = [
  { name: 'Windows EXE', signature: [0x4D, 0x5A], risk: 'critical' as const },
  { name: 'Linux ELF', signature: [0x7F, 0x45, 0x4C, 0x46], risk: 'critical' as const },
  { name: 'Windows MSI', signature: [0xD0, 0xCF, 0x11, 0xE0], risk: 'high' as const }
];

export class MaliciousContentDetector {
  
  /**
   * Escaneia arquivo em busca de conteúdo malicioso
   */
  async scanFile(file: File): Promise<ThreatScanResult> {
    const threats: string[] = [];
    
    // 1. Verifica magic numbers perigosos
    const binaryThreats = await this.scanBinarySignatures(file);
    threats.push(...binaryThreats);
    
    // 2. Para arquivos de texto, escaneia conteúdo
    if (this.isTextFile(file) && file.size < 5 * 1024 * 1024) { // Máx 5MB
      const textThreats = await this.scanTextContent(file);
      threats.push(...textThreats);
    }
    
    // 3. Verifica nome do arquivo
    const nameThreats = this.scanFileName(file.name);
    threats.push(...nameThreats);
    
    const riskLevel = this.calculateRiskLevel(threats);
    
    return {
      isMalicious: threats.length > 0,
      threats: [...new Set(threats)], // Remove duplicatas
      riskLevel
    };
  }
  
  /**
   * Escaneia assinaturas binárias perigosas
   */
  private async scanBinarySignatures(file: File): Promise<string[]> {
    const threats: string[] = [];
    
    try {
      const header = await this.readFileHeader(file, 16);
      
      for (const sig of DANGEROUS_SIGNATURES) {
        if (this.matchesSignature(header, sig.signature)) {
          threats.push(`Dangerous executable: ${sig.name}`);
        }
      }
    } catch (error) {
      // Falha ao ler header não é necessariamente malicioso
    }
    
    return threats;
  }
  
  /**
   * Escaneia conteúdo de texto
   */
  private async scanTextContent(file: File): Promise<string[]> {
    const threats: string[] = [];
    
    try {
      const content = await this.readFileAsText(file);
      
      // Verifica cada categoria de ameaças
      for (const [category, patterns] of Object.entries(THREAT_PATTERNS)) {
        for (const pattern of patterns) {
          if (pattern.test(content)) {
            threats.push(`${category.toLowerCase()}: ${pattern.source.substring(0, 50)}...`);
          }
        }
      }
    } catch (error) {
      // Se não conseguiu ler como texto, não é ameaça de script
    }
    
    return threats;
  }
  
  /**
   * Verifica nome do arquivo
   */
  private scanFileName(filename: string): string[] {
    const threats: string[] = [];
    const ext = filename.split('.').pop()?.toLowerCase();
    
    // Extensões perigosas
    const dangerousExts = ['exe', 'bat', 'com', 'scr', 'pif', 'vbs', 'js'];
    if (ext && dangerousExts.includes(ext)) {
      threats.push(`Dangerous file extension: .${ext}`);
    }
    
    // Nomes suspeitos
    const suspiciousNames = ['autorun', 'setup', 'install', 'update'];
    if (suspiciousNames.some(name => filename.toLowerCase().includes(name))) {
      threats.push('Suspicious filename pattern');
    }
    
    return threats;
  }
  
  /**
   * Calcula nível de risco baseado nas ameaças
   */
  private calculateRiskLevel(threats: string[]): 'low' | 'medium' | 'high' | 'critical' {
    if (threats.length === 0) return 'low';
    
    const hasExecutable = threats.some(t => t.includes('executable') || t.includes('.exe'));
    const hasScripts = threats.some(t => t.includes('script') || t.includes('javascript'));
    const hasSystemCmds = threats.some(t => t.includes('system') || t.includes('exec'));
    
    if (hasExecutable) return 'critical';
    if (hasSystemCmds) return 'high';
    if (hasScripts || threats.length > 2) return 'medium';
    
    return 'low';
  }
  
  /**
   * Utilitários
   */
  private isTextFile(file: File): boolean {
    const textTypes = ['text/', 'application/json', 'application/xml'];
    return textTypes.some(type => file.type.startsWith(type));
  }
  
  private async readFileHeader(file: File, bytes: number): Promise<number[]> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      const slice = file.slice(0, bytes);
      
      reader.onload = () => {
        if (reader.result instanceof ArrayBuffer) {
          const array = new Uint8Array(reader.result);
          resolve(Array.from(array));
        } else {
          reject(new Error('Failed to read header'));
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
          reject(new Error('Failed to read as text'));
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
}

/**
 * Função utilitária para escaneamento rápido
 */
export async function scanForThreats(file: File): Promise<ThreatScanResult> {
  const detector = new MaliciousContentDetector();
  return detector.scanFile(file);
} 