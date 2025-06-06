import { 
  IDiffEngine, 
  DiffEngineConfig, 
  CompareOptions, 
  VisualizationOptions, 
  VisualizationResult,
  EngineSummary 
} from '../../domain/interfaces/IDiffEngine';
import { DiffResult, DiffChunk, DiffStatistics } from '../../domain/entities/DiffResult';

// Import diff-match-patch
import DiffMatchPatch from 'diff-match-patch';

export interface DiffMatchPatchConfig extends DiffEngineConfig {
  matchThreshold?: number;
  matchDistance?: number; 
  deleteThreshold?: number;
  enableCleanupSemantic?: boolean;
  enableCleanupEfficiency?: boolean;
}

export class DiffMatchPatchEngineError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly details?: any
  ) {
    super(message);
    this.name = 'DiffMatchPatchEngineError';
  }
}

/**
 * Engine otimizado baseado na biblioteca diff-match-patch
 */
export class DiffMatchPatchEngine implements IDiffEngine {
  public readonly name = 'DiffMatchPatch';
  public readonly version = '1.0.0';
  
  public readonly defaultConfig: DiffMatchPatchConfig = {
    timeout: 30000,
    chunkSize: 10000,
    enableOptimizations: true,
    preserveWhitespace: false,
    semanticAnalysis: false,
    matchThreshold: 0.5,
    matchDistance: 1000,
    deleteThreshold: 0.5,
    enableCleanupSemantic: true,
    enableCleanupEfficiency: true
  };

  constructor(private config: DiffMatchPatchConfig = {}) {
    this.config = { ...this.defaultConfig, ...config };
  }

  /**
   * Inicializa instância do diff-match-patch
   */
  private getDMP(): any {
    // Check if we're in browser environment
    if (typeof window === 'undefined') {
      throw new DiffMatchPatchEngineError(
        'diff-match-patch só funciona no browser',
        'BROWSER_ONLY'
      );
    }

    if (!DiffMatchPatch) {
      throw new DiffMatchPatchEngineError(
        'diff-match-patch não está disponível',
        'LIBRARY_NOT_AVAILABLE'
      );
    }

    const dmp = new DiffMatchPatch();
    return dmp;
  }

  /**
   * Compara dois textos
   */
  public async compare(options: CompareOptions): Promise<DiffResult> {
    const startTime = performance.now();
    
    try {
      const dmp = this.getDMP();
      
      // Executar diff
      const diffs = dmp.diff_main(options.originalText, options.modifiedText);
      
      // Cleanup semântico
      if (this.config.enableCleanupSemantic) {
        dmp.diff_cleanupSemantic(diffs);
      }

      // Converter para chunks padronizados
      const chunks = this.convertToChunks(diffs);
      const statistics = this.calculateStatistics(chunks, performance.now() - startTime);

      const comparisonId = this.generateId();
      const resultId = this.generateId();

      return new DiffResult(
        resultId,
        comparisonId,
        'diff-match-patch',
        chunks,
        statistics,
        []
      );

    } catch (error) {
      throw new DiffMatchPatchEngineError(
        `Falha na comparação: ${error instanceof Error ? error.message : 'Erro desconhecido'}`,
        'COMPARISON_FAILED'
      );
    }
  }

  /**
   * Gera visualização
   */
  public async visualize(diffResult: DiffResult, options: VisualizationOptions): Promise<VisualizationResult> {
    let content = '';
    
    if (options.format === 'html') {
      content = '<div class="diff-result">';
      for (const chunk of diffResult.chunks) {
        const escapedText = this.escapeHtml(chunk.text);
        switch (chunk.operation) {
          case 'insert':
            content += `<span class="diff-insert">${escapedText}</span>`;
            break;
          case 'delete':
            content += `<span class="diff-delete">${escapedText}</span>`;
            break;
          case 'equal':
            content += escapedText;
            break;
        }
      }
      content += '</div>';
    } else if (options.format === 'text') {
      content = diffResult.chunks.map(c => c.text).join('');
    } else {
      content = JSON.stringify(diffResult.chunks, null, 2);
    }

    return {
      format: options.format,
      content,
      metadata: {
        totalLines: diffResult.chunks.length,
        changedLines: diffResult.chunks.filter(c => c.operation !== 'equal').length,
        theme: options.theme || 'light'
      }
    };
  }

  /**
   * Resumo do engine
   */
  public getSummary(): EngineSummary {
    return {
      engineName: this.name,
      algorithmType: 'diff-match-patch',
      version: this.version,
      complexity: {
        timeComplexity: 'O(n*m)',
        spaceComplexity: 'O(n*m)'
      },
      capabilities: {
        supportsLargeFiles: true,
        supportsSemanticAnalysis: true,
        supportsBlockMovement: false,
        supportsIncrementalDiff: false
      },
      recommendedFor: ['Documentos médios', 'Análise precisa', 'Casos gerais'],
      limitations: ['Performance limitada para arquivos >5MB', 'Requer biblioteca externa']
    };
  }

  /**
   * Valida se pode processar os textos
   */
  public canProcess(originalText: string, modifiedText: string, config?: DiffEngineConfig): boolean {
    try {
      if (!DiffMatchPatch) {
        return false;
      }
      
      const totalSize = originalText.length + modifiedText.length;
      return totalSize < 5000000; // 5MB limit
    } catch {
      return false;
    }
  }

  /**
   * Estima tempo de processamento
   */
  public estimateProcessingTime(originalSize: number, modifiedSize: number): number {
    const totalSize = originalSize + modifiedSize;
    
    if (totalSize < 10000) return 50;
    if (totalSize < 100000) return 200;
    if (totalSize < 500000) return 1000;
    if (totalSize < 1000000) return 3000;
    
    return Math.min(totalSize * 0.005, 30000);
  }

  /**
   * Configura o engine
   */
  public configure(config: Partial<DiffEngineConfig>): void {
    this.config = { ...this.config, ...config };
  }

  /**
   * Converte diffs para chunks
   */
  private convertToChunks(diffs: Array<[number, string]>): DiffChunk[] {
    const chunks: DiffChunk[] = [];
    let lineNumber = 1;

    for (const [operation, text] of diffs) {
      const diffOperation = this.convertOperation(operation);
      
      chunks.push({
        operation: diffOperation,
        text,
        lineNumber: lineNumber++,
        metadata: {
          source: 'diff-match-patch',
          confidence: 1.0
        }
      });
    }

    return chunks;
  }

  /**
   * Converte operações numéricas
   */
  private convertOperation(operation: number): 'insert' | 'delete' | 'equal' {
    switch (operation) {
      case 1: return 'insert';
      case -1: return 'delete';
      case 0: return 'equal';
      default: return 'equal';
    }
  }

  /**
   * Calcula estatísticas
   */
  private calculateStatistics(chunks: DiffChunk[], processingTime: number): DiffStatistics {
    const insertions = chunks.filter(c => c.operation === 'insert').length;
    const deletions = chunks.filter(c => c.operation === 'delete').length;
    const modifications = chunks.filter(c => c.operation === 'modify').length;
    
    const insertedChars = chunks
      .filter(c => c.operation === 'insert')
      .reduce((sum, c) => sum + c.text.length, 0);
    
    const deletedChars = chunks
      .filter(c => c.operation === 'delete')
      .reduce((sum, c) => sum + c.text.length, 0);

    const totalChars = chunks.reduce((sum, c) => sum + c.text.length, 0);
    const changedChars = insertedChars + deletedChars;
    const overallSimilarity = totalChars > 0 ? 1 - (changedChars / totalChars) : 1;

    const similarityMetrics = {
      jaccard: this.calculateJaccardSimilarity(chunks),
      levenshtein: overallSimilarity,
      cosine: this.calculateCosineSimilarity(chunks),
      overall: overallSimilarity
    };

    return {
      totalChanges: insertions + deletions + modifications,
      additions: insertions,
      deletions: deletions,
      modifications: modifications,
      charactersAdded: insertedChars,
      charactersDeleted: deletedChars,
      linesAdded: insertions,
      linesDeleted: deletions,
      similarity: similarityMetrics,
      processingTime
    };
  }

  // Métodos utilitários
  private calculateJaccardSimilarity(chunks: DiffChunk[]): number {
    const equalChunks = chunks.filter(c => c.operation === 'equal').length;
    const totalChunks = chunks.length;
    return totalChunks > 0 ? equalChunks / totalChunks : 1;
  }

  private calculateCosineSimilarity(chunks: DiffChunk[]): number {
    const equalText = chunks.filter(c => c.operation === 'equal').reduce((sum, c) => sum + c.text.length, 0);
    const totalText = chunks.reduce((sum, c) => sum + c.text.length, 0);
    return totalText > 0 ? equalText / totalText : 1;
  }

  private escapeHtml(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;');
  }

  private generateId(): string {
    return `id_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
} 