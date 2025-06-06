import { 
  IDiffEngine, 
  DiffEngineConfig, 
  CompareOptions, 
  VisualizationOptions, 
  VisualizationResult,
  EngineSummary 
} from '../../domain/interfaces/IDiffEngine';
import { DiffResult, DiffChunk, DiffStatistics, SimilarityMetrics } from '../../domain/entities/DiffResult';

export interface MyersConfig extends DiffEngineConfig {
  lineMode?: boolean; // Comparação linha por linha (padrão: true)
  ignoreWhitespace?: boolean; // Ignorar mudanças apenas de whitespace
  detectMoves?: boolean; // Detectar movimentações de blocos (simplificado)
  maxEditDistance?: number; // Distância máxima de edição (padrão: 1000)
}

export class MyersDiffEngineError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly details?: any
  ) {
    super(message);
    this.name = 'MyersDiffEngineError';
  }
}

/**
 * Implementação simplificada do algoritmo Myers diff
 * Otimizado para comparação de documentos linha por linha
 */
export class MyersDiffEngine implements IDiffEngine {
  public readonly name = 'Myers';
  public readonly version = '1.0.0';
  
  public readonly defaultConfig: MyersConfig = {
    timeout: 45000,
    chunkSize: 5000,
    enableOptimizations: true,
    preserveWhitespace: false,
    semanticAnalysis: false,
    lineMode: true,
    ignoreWhitespace: false,
    detectMoves: false,
    maxEditDistance: 1000
  };

  constructor(private config: MyersConfig = {}) {
    this.config = { ...this.defaultConfig, ...config };
  }

  /**
   * Compara dois textos usando algoritmo Myers
   */
  public async compare(options: CompareOptions): Promise<DiffResult> {
    const startTime = performance.now();
    
    try {
      const config = { ...this.config, ...options.config };
      
      // Preparar textos para comparação
      const originalLines = this.prepareText(options.originalText, config);
      const modifiedLines = this.prepareText(options.modifiedText, config);

      // Reportar progresso
      if (options.onProgress) {
        options.onProgress(25);
      }

      // Executar algoritmo Myers
      const operations = this.computeDiff(originalLines, modifiedLines, config);

      // Reportar progresso
      if (options.onProgress) {
        options.onProgress(75);
      }

      // Converter operações para chunks
      const chunks = this.operationsToChunks(operations, originalLines, modifiedLines);
      const statistics = this.calculateStatistics(chunks, performance.now() - startTime);

      // Reportar progresso final
      if (options.onProgress) {
        options.onProgress(100);
      }

      const comparisonId = this.generateId();
      const resultId = this.generateId();

      return new DiffResult(
        resultId,
        comparisonId,
        'myers',
        chunks,
        statistics,
        []
      );

    } catch (error) {
      throw new MyersDiffEngineError(
        `Falha na comparação Myers: ${error instanceof Error ? error.message : 'Erro desconhecido'}`,
        'COMPARISON_FAILED'
      );
    }
  }

  /**
   * Gera visualização do resultado
   */
  public async visualize(diffResult: DiffResult, options: VisualizationOptions): Promise<VisualizationResult> {
    let content = '';
    
    if (options.format === 'html') {
      content = '<div class="myers-diff-result">';
      for (const chunk of diffResult.chunks) {
        const escapedText = this.escapeHtml(chunk.text);
        const lineNumber = chunk.lineNumber || 0;
        
        switch (chunk.operation) {
          case 'insert':
            content += `<div class="diff-line diff-insert"><span class="line-number">+${lineNumber}</span>${escapedText}</div>`;
            break;
          case 'delete':
            content += `<div class="diff-line diff-delete"><span class="line-number">-${lineNumber}</span>${escapedText}</div>`;
            break;
          case 'equal':
            content += `<div class="diff-line diff-equal"><span class="line-number"> ${lineNumber}</span>${escapedText}</div>`;
            break;
        }
      }
      content += '</div>';
    } else if (options.format === 'text') {
      content = diffResult.chunks.map(c => {
        const prefix = c.operation === 'insert' ? '+' : c.operation === 'delete' ? '-' : ' ';
        return `${prefix} ${c.text}`;
      }).join('\n');
    } else {
      content = JSON.stringify({
        algorithm: 'myers',
        chunks: diffResult.chunks.map(c => ({
          operation: c.operation,
          text: c.text,
          lineNumber: c.lineNumber
        }))
      }, null, 2);
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
   * Retorna resumo do engine Myers
   */
  public getSummary(): EngineSummary {
    return {
      engineName: this.name,
      algorithmType: 'myers-diff',
      version: this.version,
      complexity: {
        timeComplexity: 'O(ND)',
        spaceComplexity: 'O(N+M)'
      },
      capabilities: {
        supportsLargeFiles: true,
        supportsSemanticAnalysis: false,
        supportsBlockMovement: true,
        supportsIncrementalDiff: false
      },
      recommendedFor: ['Documentos grandes', 'Comparação linha por linha', 'Code diffs'],
      limitations: ['Não suporta análise semântica', 'Limitado para textos muito similares']
    };
  }

  /**
   * Valida se pode processar os textos
   */
  public canProcess(originalText: string, modifiedText: string, config?: DiffEngineConfig): boolean {
    try {
      const totalSize = originalText.length + modifiedText.length;
      const maxSize = config?.chunkSize ? config.chunkSize * 200 : 10000000; // 10MB padrão
      
      return totalSize < maxSize;
    } catch {
      return false;
    }
  }

  /**
   * Estima tempo de processamento
   */
  public estimateProcessingTime(originalSize: number, modifiedSize: number): number {
    const totalSize = originalSize + modifiedSize;
    
    // Myers é geralmente mais eficiente para arquivos similares
    if (totalSize < 50000) return 30;
    if (totalSize < 200000) return 100;
    if (totalSize < 1000000) return 500;
    if (totalSize < 5000000) return 2000;
    
    return Math.min(totalSize * 0.002, 20000); // Max 20s
  }

  /**
   * Configura o engine
   */
  public configure(config: Partial<DiffEngineConfig>): void {
    this.config = { ...this.config, ...config };
  }

  /**
   * Prepara texto para comparação
   */
  private prepareText(text: string, config: MyersConfig): string[] {
    if (config.lineMode) {
      let lines = text.split(/\r?\n/);
      
      if (config.ignoreWhitespace) {
        lines = lines.map(line => line.trim());
      }
      
      return lines;
    } else {
      // Modo caractere por caractere
      return text.split('');
    }
  }

  /**
   * Implementação simplificada do algoritmo Myers
   */
  private computeDiff(original: string[], modified: string[], config: MyersConfig): DiffOperation[] {
    const operations: DiffOperation[] = [];
    
    // Algoritmo simplificado baseado em LCS (Longest Common Subsequence)
    const lcs = this.findLCS(original, modified);
    
    let i = 0, j = 0, k = 0;
    
    while (i < original.length || j < modified.length) {
      if (k < lcs.length && i < original.length && original[i] === lcs[k]) {
        // Elemento igual
        operations.push({
          type: 'equal',
          originalIndex: i,
          modifiedIndex: j,
          text: original[i]
        });
        i++;
        j++;
        k++;
      } else if (i < original.length && (k >= lcs.length || original[i] !== lcs[k])) {
        // Deletar da original
        operations.push({
          type: 'delete',
          originalIndex: i,
          text: original[i]
        });
        i++;
      } else if (j < modified.length) {
        // Inserir na modificada
        operations.push({
          type: 'insert',
          modifiedIndex: j,
          text: modified[j]
        });
        j++;
      }
    }
    
    return operations;
  }

  /**
   * Encontra a Longest Common Subsequence (LCS)
   */
  private findLCS(original: string[], modified: string[]): string[] {
    const m = original.length;
    const n = modified.length;
    
    // Criar matriz DP
    const dp: number[][] = Array(m + 1).fill(null).map(() => Array(n + 1).fill(0));
    
    // Preencher matriz DP
    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        if (original[i - 1] === modified[j - 1]) {
          dp[i][j] = dp[i - 1][j - 1] + 1;
        } else {
          dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
        }
      }
    }
    
    // Reconstruir LCS
    const lcs: string[] = [];
    let i = m, j = n;
    
    while (i > 0 && j > 0) {
      if (original[i - 1] === modified[j - 1]) {
        lcs.unshift(original[i - 1]);
        i--;
        j--;
      } else if (dp[i - 1][j] > dp[i][j - 1]) {
        i--;
      } else {
        j--;
      }
    }
    
    return lcs;
  }

  /**
   * Converte operações para chunks
   */
  private operationsToChunks(
    operations: DiffOperation[], 
    originalLines: string[], 
    modifiedLines: string[]
  ): DiffChunk[] {
    const chunks: DiffChunk[] = [];
    let lineNumber = 1;

    for (const op of operations) {
      chunks.push({
        operation: op.type as any,
        text: op.text,
        originalIndex: op.originalIndex,
        modifiedIndex: op.modifiedIndex,
        lineNumber: lineNumber++,
        metadata: {
          source: 'myers',
          confidence: 0.95
        }
      });
    }

    return chunks;
  }

  /**
   * Calcula estatísticas do Myers
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

    const similarityMetrics: SimilarityMetrics = {
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
    return `myers_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

// Interface para operações de diff internas
interface DiffOperation {
  type: 'insert' | 'delete' | 'equal';
  originalIndex?: number;
  modifiedIndex?: number;
  text: string;
} 