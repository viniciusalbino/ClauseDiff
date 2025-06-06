export interface CompressionConfig {
  algorithm: 'lz4' | 'gzip' | 'deflate' | 'simple';
  level: number; // 1-9, onde 9 é máxima compressão
  threshold: number; // Tamanho mínimo para aplicar compressão (bytes)
}

export interface CompressedData {
  data: string;
  originalSize: number;
  compressedSize: number;
  algorithm: string;
  compressionRatio: number;
  timestamp: number;
}

export class DiffCompressor {
  private readonly config: CompressionConfig;

  constructor(config: Partial<CompressionConfig> = {}) {
    this.config = {
      algorithm: config.algorithm || 'simple',
      level: config.level || 6,
      threshold: config.threshold || 1024, // 1KB
      ...config
    };
  }

  /**
   * Comprime dados de diff
   */
  public compress(data: string): CompressedData {
    const originalSize = new Blob([data]).size;

    // Se for menor que o threshold, não comprimir
    if (originalSize < this.config.threshold) {
      return {
        data,
        originalSize,
        compressedSize: originalSize,
        algorithm: 'none',
        compressionRatio: 1,
        timestamp: Date.now()
      };
    }

    let compressedData: string;
    let algorithm: string;

    switch (this.config.algorithm) {
      case 'simple':
        compressedData = this.simpleCompress(data);
        algorithm = 'simple';
        break;
      case 'lz4':
        compressedData = this.lz4Compress(data);
        algorithm = 'lz4';
        break;
      case 'gzip':
        compressedData = this.gzipCompress(data);
        algorithm = 'gzip';
        break;
      case 'deflate':
        compressedData = this.deflateCompress(data);
        algorithm = 'deflate';
        break;
      default:
        compressedData = this.simpleCompress(data);
        algorithm = 'simple';
    }

    const compressedSize = new Blob([compressedData]).size;
    const compressionRatio = originalSize / compressedSize;

    return {
      data: compressedData,
      originalSize,
      compressedSize,
      algorithm,
      compressionRatio,
      timestamp: Date.now()
    };
  }

  /**
   * Descomprime dados
   */
  public decompress(compressedData: CompressedData): string {
    if (compressedData.algorithm === 'none') {
      return compressedData.data;
    }

    switch (compressedData.algorithm) {
      case 'simple':
        return this.simpleDecompress(compressedData.data);
      case 'lz4':
        return this.lz4Decompress(compressedData.data);
      case 'gzip':
        return this.gzipDecompress(compressedData.data);
      case 'deflate':
        return this.deflateDecompress(compressedData.data);
      default:
        return compressedData.data;
    }
  }

  /**
   * Compressão simples baseada em repetições
   */
  private simpleCompress(data: string): string {
    // Substituir sequências repetidas por tokens
    const patterns = [
      { pattern: /\s+/g, token: '§S§' },
      { pattern: /\n+/g, token: '§N§' },
      { pattern: /\.\.\.+/g, token: '§D§' },
      { pattern: /===+/g, token: '§E§' },
      { pattern: /---+/g, token: '§H§' }
    ];

    let compressed = data;
    
    patterns.forEach(({ pattern, token }) => {
      compressed = compressed.replace(pattern, (match) => {
        if (match.length > 3) {
          return `${token}${match.length}${token}`;
        }
        return match;
      });
    });

    // Compressão básica de caracteres repetidos
    compressed = compressed.replace(/(.)\1{2,}/g, (match, char) => {
      return `§R§${char}${match.length}§R§`;
    });

    return compressed;
  }

  /**
   * Descompressão simples
   */
  private simpleDecompress(data: string): string {
    let decompressed = data;

    // Restaurar caracteres repetidos
    decompressed = decompressed.replace(/§R§(.)(\d+)§R§/g, (_, char, count) => {
      return char.repeat(parseInt(count));
    });

    // Restaurar padrões
    const patterns = [
      { token: /§S§(\d+)§S§/g, char: ' ' },
      { token: /§N§(\d+)§N§/g, char: '\n' },
      { token: /§D§(\d+)§D§/g, char: '.' },
      { token: /§E§(\d+)§E§/g, char: '=' },
      { token: /§H§(\d+)§H§/g, char: '-' }
    ];

    patterns.forEach(({ token, char }) => {
      decompressed = decompressed.replace(token, (_, count) => {
        return char.repeat(parseInt(count));
      });
    });

    return decompressed;
  }

  /**
   * Simula compressão LZ4 (implementação simplificada)
   */
  private lz4Compress(data: string): string {
    // Implementação simplificada - na prática usaria uma biblioteca
    return this.simpleCompress(data);
  }

  private lz4Decompress(data: string): string {
    return this.simpleDecompress(data);
  }

  /**
   * Simula compressão GZIP (implementação simplificada)
   */
  private gzipCompress(data: string): string {
    // Implementação simplificada - na prática usaria compression streams
    return btoa(this.simpleCompress(data));
  }

  private gzipDecompress(data: string): string {
    return this.simpleDecompress(atob(data));
  }

  /**
   * Simula compressão Deflate (implementação simplificada)
   */
  private deflateCompress(data: string): string {
    return this.gzipCompress(data);
  }

  private deflateDecompress(data: string): string {
    return this.gzipDecompress(data);
  }

  /**
   * Obtém estatísticas de compressão
   */
  public getCompressionStats(results: CompressedData[]): {
    totalOriginalSize: number;
    totalCompressedSize: number;
    averageRatio: number;
    bestRatio: number;
    worstRatio: number;
    totalSaved: number;
  } {
    if (results.length === 0) {
      return {
        totalOriginalSize: 0,
        totalCompressedSize: 0,
        averageRatio: 1,
        bestRatio: 1,
        worstRatio: 1,
        totalSaved: 0
      };
    }

    const totalOriginalSize = results.reduce((sum, r) => sum + r.originalSize, 0);
    const totalCompressedSize = results.reduce((sum, r) => sum + r.compressedSize, 0);
    const ratios = results.map(r => r.compressionRatio);

    return {
      totalOriginalSize,
      totalCompressedSize,
      averageRatio: ratios.reduce((sum, r) => sum + r, 0) / ratios.length,
      bestRatio: Math.max(...ratios),
      worstRatio: Math.min(...ratios),
      totalSaved: totalOriginalSize - totalCompressedSize
    };
  }
} 