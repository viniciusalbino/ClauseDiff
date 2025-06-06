import { 
  IDiffEngine, 
  DiffEngineConfig, 
  CompareOptions, 
  VisualizationOptions, 
  VisualizationResult,
  EngineSummary 
} from '../../domain/interfaces/IDiffEngine';
import { DiffResult, DiffChunk, DiffStatistics, SimilarityMetrics } from '../../domain/entities/DiffResult';

export interface SemanticConfig extends DiffEngineConfig {
  structuralAnalysis?: boolean; // Analisar estrutura do documento
  sentimentAnalysis?: boolean; // Análise de sentimento básica  
  keywordAnalysis?: boolean; // Análise de palavras-chave
  paragraphLevel?: boolean; // Comparação nível de parágrafo
  minSemanticThreshold?: number; // Threshold mínimo para diferenças semânticas
}

export class SemanticDiffEngineError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly details?: any
  ) {
    super(message);
    this.name = 'SemanticDiffEngineError';
  }
}

/**
 * Engine de diff semântico para análise baseada em significado
 * Focado em detectar mudanças estruturais e de conteúdo
 */
export class SemanticDiffEngine implements IDiffEngine {
  public readonly name = 'SemanticDiff';
  public readonly version = '1.0.0';
  
  public readonly defaultConfig: SemanticConfig = {
    timeout: 60000,
    chunkSize: 2000,
    enableOptimizations: true,
    preserveWhitespace: true,
    semanticAnalysis: true,
    structuralAnalysis: true,
    sentimentAnalysis: false,
    keywordAnalysis: true,
    paragraphLevel: true,
    minSemanticThreshold: 0.3
  };

  constructor(private config: SemanticConfig = {}) {
    this.config = { ...this.defaultConfig, ...config };
  }

  /**
   * Compara dois textos usando análise semântica
   */
  public async compare(options: CompareOptions): Promise<DiffResult> {
    const startTime = performance.now();
    
    try {
      const config = { ...this.config, ...options.config };
      
      // Análise estrutural dos textos
      const originalStructure = this.analyzeStructure(options.originalText, config);
      const modifiedStructure = this.analyzeStructure(options.modifiedText, config);

      // Reportar progresso
      if (options.onProgress) {
        options.onProgress(25);
      }

      // Análise semântica
      const semanticChanges = this.analyzeSemanticChanges(
        originalStructure, 
        modifiedStructure, 
        config
      );

      // Reportar progresso
      if (options.onProgress) {
        options.onProgress(50);
      }

      // Análise de palavras-chave se habilitada
      let keywordChanges: SemanticChange[] = [];
      if (config.keywordAnalysis) {
        keywordChanges = this.analyzeKeywordChanges(originalStructure, modifiedStructure);
      }

      // Reportar progresso
      if (options.onProgress) {
        options.onProgress(75);
      }

      // Converter análises para chunks
      const chunks = this.createSemanticChunks(semanticChanges, keywordChanges);
      const statistics = this.calculateSemanticStatistics(chunks, performance.now() - startTime);

      // Reportar progresso final
      if (options.onProgress) {
        options.onProgress(100);
      }

      const comparisonId = this.generateId();
      const resultId = this.generateId();

      return new DiffResult(
        resultId,
        comparisonId,
        'semantic',
        chunks,
        statistics,
        []
      );

    } catch (error) {
      throw new SemanticDiffEngineError(
        `Falha na análise semântica: ${error instanceof Error ? error.message : 'Erro desconhecido'}`,
        'SEMANTIC_ANALYSIS_FAILED'
      );
    }
  }

  /**
   * Gera visualização semântica
   */
  public async visualize(diffResult: DiffResult, options: VisualizationOptions): Promise<VisualizationResult> {
    let content = '';
    
    if (options.format === 'html') {
      content = '<div class="semantic-diff-result">';
      content += '<div class="semantic-legend">';
      content += '<span class="semantic-structural">Estrutural</span>';
      content += '<span class="semantic-content">Conteúdo</span>';
      content += '<span class="semantic-keyword">Palavra-chave</span>';
      content += '</div>';
      
      for (const chunk of diffResult.chunks) {
        const escapedText = this.escapeHtml(chunk.text);
        const semanticType = chunk.metadata?.semanticType || 'content';
        const confidence = chunk.metadata?.confidence || 0.5;
        
        switch (chunk.operation) {
          case 'insert':
            content += `<div class="diff-line semantic-insert semantic-${semanticType}" data-confidence="${confidence}">`;
            content += `<span class="confidence-indicator">${Math.round(confidence * 100)}%</span>`;
            content += `<span class="semantic-content">+ ${escapedText}</span></div>`;
            break;
          case 'delete':
            content += `<div class="diff-line semantic-delete semantic-${semanticType}" data-confidence="${confidence}">`;
            content += `<span class="confidence-indicator">${Math.round(confidence * 100)}%</span>`;
            content += `<span class="semantic-content">- ${escapedText}</span></div>`;
            break;
          case 'modify':
            content += `<div class="diff-line semantic-modify semantic-${semanticType}" data-confidence="${confidence}">`;
            content += `<span class="confidence-indicator">${Math.round(confidence * 100)}%</span>`;
            content += `<span class="semantic-content">~ ${escapedText}</span></div>`;
            break;
          case 'equal':
            content += `<div class="diff-line semantic-equal">${escapedText}</div>`;
            break;
        }
      }
      content += '</div>';
    } else if (options.format === 'text') {
      content = diffResult.chunks.map(c => {
        const semanticType = c.metadata?.semanticType || 'content';
        const confidence = Math.round((c.metadata?.confidence || 0.5) * 100);
        const prefix = c.operation === 'insert' ? '+' : 
                     c.operation === 'delete' ? '-' : 
                     c.operation === 'modify' ? '~' : ' ';
        return `${prefix} [${semanticType}:${confidence}%] ${c.text}`;
      }).join('\n');
    } else {
      content = JSON.stringify({
        algorithm: 'semantic',
        chunks: diffResult.chunks.map(c => ({
          operation: c.operation,
          text: c.text,
          semanticType: c.metadata?.semanticType,
          confidence: c.metadata?.confidence,
          keywords: c.metadata?.keywords
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
   * Resumo do engine semântico
   */
  public getSummary(): EngineSummary {
    return {
      engineName: this.name,
      algorithmType: 'semantic-analysis',
      version: this.version,
      complexity: {
        timeComplexity: 'O(n²)',
        spaceComplexity: 'O(n)'
      },
      capabilities: {
        supportsLargeFiles: false,
        supportsSemanticAnalysis: true,
        supportsBlockMovement: true,
        supportsIncrementalDiff: false
      },
      recommendedFor: ['Documentos pequenos', 'Análise de conteúdo', 'Contratos legais', 'Artigos'],
      limitations: ['Performance limitada para arquivos grandes', 'Análise básica de semântica', 'Requer textos estruturados']
    };
  }

  /**
   * Valida se pode processar os textos
   */
  public canProcess(originalText: string, modifiedText: string, config?: DiffEngineConfig): boolean {
    try {
      const totalSize = originalText.length + modifiedText.length;
      // Limite menor para análise semântica (mais computacionalmente intensiva)
      return totalSize < 100000; // 100KB limit
    } catch {
      return false;
    }
  }

  /**
   * Estima tempo de processamento
   */
  public estimateProcessingTime(originalSize: number, modifiedSize: number): number {
    const totalSize = originalSize + modifiedSize;
    
    // Análise semântica é mais lenta
    if (totalSize < 5000) return 100;
    if (totalSize < 20000) return 500;
    if (totalSize < 50000) return 2000;
    if (totalSize < 100000) return 5000;
    
    return Math.min(totalSize * 0.1, 60000); // Max 60s
  }

  /**
   * Configura o engine
   */
  public configure(config: Partial<DiffEngineConfig>): void {
    this.config = { ...this.config, ...config };
  }

  /**
   * Analisa a estrutura do texto
   */
  private analyzeStructure(text: string, config: SemanticConfig): TextStructure {
    // Dividir em parágrafos
    const paragraphs = text.split(/\n\s*\n/).filter(p => p.trim().length > 0);
    
    // Dividir em sentenças
    const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 0);
    
    // Extrair palavras-chave simples
    const keywords = this.extractKeywords(text);
    
    // Analisar estrutura básica
    const hasHeadings = /^#+\s+/m.test(text); // Markdown headings
    const hasBulletPoints = /^[\*\-\+]\s+/m.test(text);
    const hasNumberedLists = /^\d+\.\s+/m.test(text);
    
    return {
      paragraphs,
      sentences,
      keywords,
      structure: {
        hasHeadings,
        hasBulletPoints,
        hasNumberedLists,
        wordCount: text.split(/\s+/).length,
        characterCount: text.length
      }
    };
  }

  /**
   * Extrai palavras-chave básicas
   */
  private extractKeywords(text: string): string[] {
    // Lista simples de stop words em português
    const stopWords = new Set([
      'o', 'a', 'os', 'as', 'um', 'uma', 'uns', 'umas',
      'de', 'do', 'da', 'dos', 'das', 'em', 'no', 'na', 'nos', 'nas',
      'para', 'por', 'com', 'sem', 'sob', 'sobre', 'entre',
      'e', 'ou', 'mas', 'que', 'se', 'quando', 'onde', 'como',
      'é', 'são', 'foi', 'foram', 'ser', 'estar', 'ter', 'haver'
    ]);

    const words = text.toLowerCase()
      .replace(/[^\w\sáàâãäéèêëíìîïóòôõöúùûüç]/g, ' ')
      .split(/\s+/)
      .filter(word => word.length > 3 && !stopWords.has(word));

    // Contar frequência
    const wordCount = new Map<string, number>();
    words.forEach(word => {
      wordCount.set(word, (wordCount.get(word) || 0) + 1);
    });

    // Retornar as 10 palavras mais frequentes
    return Array.from(wordCount.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([word]) => word);
  }

  /**
   * Analisa mudanças semânticas
   */
  private analyzeSemanticChanges(
    original: TextStructure, 
    modified: TextStructure, 
    config: SemanticConfig
  ): SemanticChange[] {
    const changes: SemanticChange[] = [];

    // Comparar parágrafos
    if (config.paragraphLevel) {
      const paragraphChanges = this.compareParagraphs(original.paragraphs, modified.paragraphs);
      changes.push(...paragraphChanges);
    }

    // Comparar estrutura
    if (config.structuralAnalysis) {
      const structuralChanges = this.compareStructure(original.structure, modified.structure);
      changes.push(...structuralChanges);
    }

    return changes;
  }

  /**
   * Compara parágrafos
   */
  private compareParagraphs(originalParagraphs: string[], modifiedParagraphs: string[]): SemanticChange[] {
    const changes: SemanticChange[] = [];
    const maxLength = Math.max(originalParagraphs.length, modifiedParagraphs.length);

    for (let i = 0; i < maxLength; i++) {
      const original = originalParagraphs[i] || '';
      const modified = modifiedParagraphs[i] || '';

      if (!original && modified) {
        changes.push({
          type: 'insert',
          text: modified,
          semanticType: 'paragraph',
          confidence: 0.9,
          index: i
        });
      } else if (original && !modified) {
        changes.push({
          type: 'delete',
          text: original,
          semanticType: 'paragraph',
          confidence: 0.9,
          index: i
        });
      } else if (original && modified && original !== modified) {
        const similarity = this.calculateTextSimilarity(original, modified);
        if (similarity < 0.8) {
          changes.push({
            type: 'modify',
            text: modified,
            originalText: original,
            semanticType: 'paragraph',
            confidence: 1 - similarity,
            index: i
          });
        }
      }
    }

    return changes;
  }

  /**
   * Compara estrutura
   */
  private compareStructure(original: DocumentStructure, modified: DocumentStructure): SemanticChange[] {
    const changes: SemanticChange[] = [];

    if (original.hasHeadings !== modified.hasHeadings) {
      changes.push({
        type: modified.hasHeadings ? 'insert' : 'delete',
        text: 'Estrutura de cabeçalhos',
        semanticType: 'structural',
        confidence: 0.8,
        index: -1
      });
    }

    if (original.hasBulletPoints !== modified.hasBulletPoints) {
      changes.push({
        type: modified.hasBulletPoints ? 'insert' : 'delete',
        text: 'Lista com marcadores',
        semanticType: 'structural',
        confidence: 0.8,
        index: -1
      });
    }

    if (original.hasNumberedLists !== modified.hasNumberedLists) {
      changes.push({
        type: modified.hasNumberedLists ? 'insert' : 'delete',
        text: 'Lista numerada',
        semanticType: 'structural',
        confidence: 0.8,
        index: -1
      });
    }

    return changes;
  }

  /**
   * Analisa mudanças de palavras-chave
   */
  private analyzeKeywordChanges(original: TextStructure, modified: TextStructure): SemanticChange[] {
    const changes: SemanticChange[] = [];
    
    const originalKeywords = new Set(original.keywords);
    const modifiedKeywords = new Set(modified.keywords);

    // Palavras-chave adicionadas
    for (const keyword of modifiedKeywords) {
      if (!originalKeywords.has(keyword)) {
        changes.push({
          type: 'insert',
          text: keyword,
          semanticType: 'keyword',
          confidence: 0.7,
          index: -1
        });
      }
    }

    // Palavras-chave removidas
    for (const keyword of originalKeywords) {
      if (!modifiedKeywords.has(keyword)) {
        changes.push({
          type: 'delete',
          text: keyword,
          semanticType: 'keyword',
          confidence: 0.7,
          index: -1
        });
      }
    }

    return changes;
  }

  /**
   * Cria chunks semânticos
   */
  private createSemanticChunks(
    semanticChanges: SemanticChange[], 
    keywordChanges: SemanticChange[]
  ): DiffChunk[] {
    const chunks: DiffChunk[] = [];
    let lineNumber = 1;

    const allChanges = [...semanticChanges, ...keywordChanges];

    for (const change of allChanges) {
      chunks.push({
        operation: change.type as any,
        text: change.text,
        lineNumber: lineNumber++,
        metadata: {
          source: 'semantic',
          semanticType: change.semanticType,
          confidence: change.confidence,
          originalText: change.originalText
        }
      });
    }

    return chunks;
  }

  /**
   * Calcula estatísticas semânticas
   */
  private calculateSemanticStatistics(chunks: DiffChunk[], processingTime: number): DiffStatistics {
    const insertions = chunks.filter(c => c.operation === 'insert').length;
    const deletions = chunks.filter(c => c.operation === 'delete').length;
    const modifications = chunks.filter(c => c.operation === 'modify').length;
    
    const structuralChanges = chunks.filter(c => c.metadata?.semanticType === 'structural').length;
    const contentChanges = chunks.filter(c => c.metadata?.semanticType === 'paragraph').length;
    const keywordChanges = chunks.filter(c => c.metadata?.semanticType === 'keyword').length;

    const avgConfidence = chunks.reduce((sum, c) => sum + (c.metadata?.confidence || 0.5), 0) / chunks.length;

    const similarityMetrics: SimilarityMetrics = {
      jaccard: this.calculateJaccardSimilarity(chunks),
      levenshtein: avgConfidence,
      cosine: this.calculateSemanticSimilarity(chunks),
      overall: avgConfidence
    };

    return {
      totalChanges: insertions + deletions + modifications,
      additions: insertions,
      deletions: deletions,
      modifications: modifications,
      charactersAdded: chunks.filter(c => c.operation === 'insert').reduce((sum, c) => sum + c.text.length, 0),
      charactersDeleted: chunks.filter(c => c.operation === 'delete').reduce((sum, c) => sum + c.text.length, 0),
      linesAdded: insertions,
      linesDeleted: deletions,
      similarity: similarityMetrics,
      processingTime
    };
  }

  // Métodos utilitários
  private calculateTextSimilarity(text1: string, text2: string): number {
    const words1 = new Set(text1.toLowerCase().split(/\s+/));
    const words2 = new Set(text2.toLowerCase().split(/\s+/));
    
    const intersection = new Set([...words1].filter(word => words2.has(word)));
    const union = new Set([...words1, ...words2]);
    
    return union.size > 0 ? intersection.size / union.size : 1;
  }

  private calculateJaccardSimilarity(chunks: DiffChunk[]): number {
    const equalChunks = chunks.filter(c => c.operation === 'equal').length;
    const totalChunks = chunks.length;
    return totalChunks > 0 ? equalChunks / totalChunks : 1;
  }

  private calculateSemanticSimilarity(chunks: DiffChunk[]): number {
    const confidences = chunks.map(c => c.metadata?.confidence || 0.5);
    return confidences.reduce((sum, conf) => sum + conf, 0) / confidences.length;
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
    return `semantic_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

// Interfaces para estrutura semântica
interface TextStructure {
  paragraphs: string[];
  sentences: string[];
  keywords: string[];
  structure: DocumentStructure;
}

interface DocumentStructure {
  hasHeadings: boolean;
  hasBulletPoints: boolean;
  hasNumberedLists: boolean;
  wordCount: number;
  characterCount: number;
}

interface SemanticChange {
  type: 'insert' | 'delete' | 'modify';
  text: string;
  originalText?: string;
  semanticType: 'structural' | 'paragraph' | 'keyword';
  confidence: number;
  index: number;
} 