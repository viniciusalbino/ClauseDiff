import { 
  DiffResult, 
  DiffChunk, 
  DiffStatistics, 
  SimilarityMetrics, 
  ChangeSection,
  DiffOperation 
} from '../../domain/entities/DiffResult';

/**
 * Formato bruto de resultado de algoritmos externos
 */
export interface RawDiffResult {
  algorithm: string;
  chunks?: any[];
  diffs?: any[];
  operations?: any[];
  statistics?: any;
  metadata?: Record<string, any>;
  processingTime?: number;
  version?: string;
}

/**
 * Formato específico do DiffMatchPatch
 */
export interface DiffMatchPatchResult {
  diffs: Array<[number, string]>; // [operation, text]
  statistics?: {
    additions: number;
    deletions: number;
    totalDifferences: number;
  };
  processingTime: number;
}

/**
 * Formato específico do algoritmo Myers
 */
export interface MyersResult {
  operations: Array<{
    type: 'insert' | 'delete' | 'equal';
    text: string;
    oldPos?: number;
    newPos?: number;
  }>;
  editDistance: number;
  similarity: number;
  processingTime: number;
}

/**
 * Formato específico do engine semântico
 */
export interface SemanticResult {
  semanticChunks: Array<{
    operation: string;
    content: string;
    semanticType: 'structural' | 'meaning' | 'formatting';
    confidence: number;
    originalRange?: [number, number];
    modifiedRange?: [number, number];
  }>;
  sentiment: 'positive' | 'negative' | 'neutral';
  complexityScore: number;
  processingTime: number;
}

export class DiffEngineAdapterError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly algorithm?: string
  ) {
    super(message);
    this.name = 'DiffEngineAdapterError';
  }
}

/**
 * Adapter principal para uniformizar saídas de diferentes engines
 */
export class DiffEngineAdapter {
  private readonly supportedAlgorithms = new Set([
    'diff-match-patch',
    'myers',
    'semantic'
  ]);

  /**
   * Converte resultado bruto para formato padronizado DiffResult
   */
  public adaptResult(
    rawResult: RawDiffResult,
    comparisonId: string,
    resultId?: string
  ): DiffResult {
    try {
      this.validateRawResult(rawResult);

      const algorithm = rawResult.algorithm.toLowerCase();
      
      if (!this.supportedAlgorithms.has(algorithm)) {
        throw new DiffEngineAdapterError(
          `Algoritmo não suportado: ${algorithm}`,
          'UNSUPPORTED_ALGORITHM',
          algorithm
        );
      }

      // Delegar para adapter específico baseado no algoritmo
      switch (algorithm) {
        case 'diff-match-patch':
          return this.adaptDiffMatchPatch(rawResult as any, comparisonId, resultId);
        case 'myers':
          return this.adaptMyers(rawResult as any, comparisonId, resultId);
        case 'semantic':
          return this.adaptSemantic(rawResult as any, comparisonId, resultId);
        default:
          return this.adaptGeneric(rawResult, comparisonId, resultId);
      }
    } catch (error) {
      if (error instanceof DiffEngineAdapterError) {
        throw error;
      }
      
      throw new DiffEngineAdapterError(
        `Falha na adaptação: ${error instanceof Error ? error.message : 'Erro desconhecido'}`,
        'ADAPTATION_FAILED',
        rawResult.algorithm
      );
    }
  }

  /**
   * Adapter específico para DiffMatchPatch
   */
  private adaptDiffMatchPatch(
    result: DiffMatchPatchResult & RawDiffResult,
    comparisonId: string,
    resultId?: string
  ): DiffResult {
    const chunks: DiffChunk[] = [];
    let lineNumber = 1;
    let originalIndex = 0;
    let modifiedIndex = 0;

    // Converter formato DiffMatchPatch [operation, text] para DiffChunk
    for (const [operation, text] of result.diffs) {
      const diffOperation = this.convertDMPOperation(operation);
      
      chunks.push({
        operation: diffOperation,
        text,
        originalIndex: diffOperation !== 'insert' ? originalIndex : undefined,
        modifiedIndex: diffOperation !== 'delete' ? modifiedIndex : undefined,
        lineNumber: lineNumber++,
        metadata: {
          source: 'diff-match-patch',
          confidence: 1.0
        }
      });

      // Atualizar índices
      if (diffOperation !== 'insert') originalIndex += text.length;
      if (diffOperation !== 'delete') modifiedIndex += text.length;
    }

    // Calcular estatísticas
    const statistics = this.calculateStatistics(chunks, result.processingTime || 0);
    
    // Identificar seções com mudanças
    const changeSections = this.identifyChangeSections(chunks);

    return new DiffResult(
      resultId || this.generateResultId(),
      comparisonId,
      'diff-match-patch',
      chunks,
      statistics,
      changeSections
    );
  }

  /**
   * Adapter específico para algoritmo Myers
   */
  private adaptMyers(
    result: MyersResult & RawDiffResult,
    comparisonId: string,
    resultId?: string
  ): DiffResult {
    const chunks: DiffChunk[] = [];
    let lineNumber = 1;

    // Converter operações Myers para DiffChunk
    for (const operation of result.operations) {
      chunks.push({
        operation: this.convertMyersOperation(operation.type),
        text: operation.text,
        originalIndex: operation.oldPos,
        modifiedIndex: operation.newPos,
        lineNumber: lineNumber++,
        metadata: {
          source: 'myers',
          editDistance: result.editDistance,
          confidence: 0.95
        }
      });
    }

    // Calcular estatísticas usando métricas do Myers
    const statistics = this.calculateStatisticsFromMyers(
      chunks, 
      result.editDistance, 
      result.similarity,
      result.processingTime || 0
    );
    
    const changeSections = this.identifyChangeSections(chunks);

    return new DiffResult(
      resultId || this.generateResultId(),
      comparisonId,
      'myers',
      chunks,
      statistics,
      changeSections
    );
  }

  /**
   * Adapter específico para engine semântico
   */
  private adaptSemantic(
    result: SemanticResult & RawDiffResult,
    comparisonId: string,
    resultId?: string
  ): DiffResult {
    const chunks: DiffChunk[] = [];
    let lineNumber = 1;

    // Converter chunks semânticos para DiffChunk
    for (const semanticChunk of result.semanticChunks) {
      chunks.push({
        operation: this.convertSemanticOperation(semanticChunk.operation),
        text: semanticChunk.content,
        originalIndex: semanticChunk.originalRange?.[0],
        modifiedIndex: semanticChunk.modifiedRange?.[0],
        lineNumber: lineNumber++,
        metadata: {
          source: 'semantic',
          semanticType: semanticChunk.semanticType,
          confidence: semanticChunk.confidence,
          sentiment: result.sentiment,
          complexityScore: result.complexityScore
        }
      });
    }

    // Calcular estatísticas com informações semânticas
    const statistics = this.calculateSemanticStatistics(
      chunks,
      result.complexityScore,
      result.processingTime || 0
    );
    
    const changeSections = this.identifySemanticChangeSections(chunks);

    return new DiffResult(
      resultId || this.generateResultId(),
      comparisonId,
      'semantic',
      chunks,
      statistics,
      changeSections
    );
  }

  /**
   * Adapter genérico para algoritmos não específicos
   */
  private adaptGeneric(
    result: RawDiffResult,
    comparisonId: string,
    resultId?: string
  ): DiffResult {
    // Tentar extrair chunks de diferentes possíveis formatos
    const rawChunks = result.chunks || result.diffs || result.operations || [];
    const chunks: DiffChunk[] = [];
    
    for (let i = 0; i < rawChunks.length; i++) {
      const rawChunk = rawChunks[i];
      chunks.push(this.normalizeChunk(rawChunk, i + 1));
    }

    const statistics = this.calculateStatistics(chunks, result.processingTime || 0);
    const changeSections = this.identifyChangeSections(chunks);

    return new DiffResult(
      resultId || this.generateResultId(),
      comparisonId,
      result.algorithm,
      chunks,
      statistics,
      changeSections
    );
  }

  /**
   * Normaliza chunk de formato desconhecido
   */
  private normalizeChunk(rawChunk: any, lineNumber: number): DiffChunk {
    return {
      operation: this.inferOperation(rawChunk),
      text: this.extractText(rawChunk),
      originalIndex: rawChunk.originalIndex || rawChunk.oldPos,
      modifiedIndex: rawChunk.modifiedIndex || rawChunk.newPos,
      lineNumber,
      metadata: {
        source: 'generic',
        rawData: rawChunk
      }
    };
  }

  /**
   * Converte operação DiffMatchPatch para formato padrão
   */
  private convertDMPOperation(operation: number): DiffOperation {
    switch (operation) {
      case 1: return 'insert';
      case -1: return 'delete';
      case 0: return 'equal';
      default: return 'equal';
    }
  }

  /**
   * Converte operação Myers para formato padrão
   */
  private convertMyersOperation(type: string): DiffOperation {
    switch (type.toLowerCase()) {
      case 'insert': return 'insert';
      case 'delete': return 'delete';
      case 'equal': return 'equal';
      default: return 'equal';
    }
  }

  /**
   * Converte operação semântica para formato padrão
   */
  private convertSemanticOperation(operation: string): DiffOperation {
    switch (operation.toLowerCase()) {
      case 'add':
      case 'insert': return 'insert';
      case 'remove':
      case 'delete': return 'delete';
      case 'modify':
      case 'change': return 'modify';
      case 'equal':
      case 'same': return 'equal';
      default: return 'equal';
    }
  }

  /**
   * Calcula estatísticas padrão baseado nos chunks
   */
  private calculateStatistics(chunks: DiffChunk[], processingTime: number): DiffStatistics {
    let additions = 0;
    let deletions = 0;
    let modifications = 0;
    let charactersAdded = 0;
    let charactersDeleted = 0;
    let linesAdded = 0;
    let linesDeleted = 0;

    for (const chunk of chunks) {
      switch (chunk.operation) {
        case 'insert':
          additions++;
          charactersAdded += chunk.text.length;
          linesAdded += this.countLines(chunk.text);
          break;
        case 'delete':
          deletions++;
          charactersDeleted += chunk.text.length;
          linesDeleted += this.countLines(chunk.text);
          break;
        case 'modify':
          modifications++;
          break;
      }
    }

    return {
      totalChanges: additions + deletions + modifications,
      additions,
      deletions,
      modifications,
      charactersAdded,
      charactersDeleted,
      linesAdded,
      linesDeleted,
      similarity: this.calculateSimilarityMetrics(chunks),
      processingTime
    };
  }

  /**
   * Calcula estatísticas específicas do Myers
   */
  private calculateStatisticsFromMyers(
    chunks: DiffChunk[], 
    editDistance: number, 
    similarity: number,
    processingTime: number
  ): DiffStatistics {
    const baseStats = this.calculateStatistics(chunks, processingTime);
    
    // Usar similaridade do algoritmo Myers
    baseStats.similarity.overall = similarity;
    baseStats.similarity.levenshtein = 1 - (editDistance / Math.max(
      baseStats.charactersAdded + baseStats.charactersDeleted, 1
    ));

    return baseStats;
  }

  /**
   * Calcula estatísticas semânticas
   */
  private calculateSemanticStatistics(
    chunks: DiffChunk[], 
    complexityScore: number,
    processingTime: number
  ): DiffStatistics {
    const baseStats = this.calculateStatistics(chunks, processingTime);
    
    // Ajustar métricas baseado na análise semântica
    const semanticWeight = Math.min(complexityScore / 100, 1);
    baseStats.similarity.overall *= (1 - semanticWeight * 0.2); // Reduzir similaridade se há mudanças semânticas significativas
    
    return baseStats;
  }

  /**
   * Calcula métricas de similaridade
   */
  private calculateSimilarityMetrics(chunks: DiffChunk[]): SimilarityMetrics {
    const totalChunks = chunks.length;
    const equalChunks = chunks.filter(c => c.operation === 'equal').length;
    const changedChunks = totalChunks - equalChunks;

    const jaccard = totalChunks > 0 ? equalChunks / totalChunks : 1;
    const levenshtein = totalChunks > 0 ? 1 - (changedChunks / totalChunks) : 1;
    const cosine = (jaccard + levenshtein) / 2; // Aproximação simples
    const overall = (jaccard + levenshtein + cosine) / 3;

    return { jaccard, levenshtein, cosine, overall };
  }

  /**
   * Identifica seções com mudanças
   */
  private identifyChangeSections(chunks: DiffChunk[]): ChangeSection[] {
    const sections: ChangeSection[] = [];
    let currentSection: Partial<ChangeSection> | null = null;

    for (let i = 0; i < chunks.length; i++) {
      const chunk = chunks[i];
      
      if (chunk.operation !== 'equal') {
        if (!currentSection) {
          currentSection = {
            startLine: chunk.lineNumber || i + 1,
            changeType: chunk.operation,
            intensity: 'low'
          };
        }
      } else if (currentSection) {
        // Finalizar seção atual
        currentSection.endLine = (chunk.lineNumber || i) - 1;
        currentSection.intensity = this.calculateIntensity(
          currentSection.endLine - currentSection.startLine! + 1
        );
        
        sections.push(currentSection as ChangeSection);
        currentSection = null;
      }
    }

    // Finalizar última seção se necessário
    if (currentSection) {
      currentSection.endLine = chunks.length;
      currentSection.intensity = this.calculateIntensity(
        currentSection.endLine - currentSection.startLine! + 1
      );
      sections.push(currentSection as ChangeSection);
    }

    return sections;
  }

  /**
   * Identifica seções semânticas especiais
   */
  private identifySemanticChangeSections(chunks: DiffChunk[]): ChangeSection[] {
    const sections = this.identifyChangeSections(chunks);
    
    // Ajustar intensidade baseado em metadados semânticos
    return sections.map(section => {
      const semanticChunks = chunks.slice(section.startLine - 1, section.endLine)
        .filter(chunk => chunk.metadata?.semanticType === 'meaning');
      
      if (semanticChunks.length > 0) {
        section.intensity = 'high'; // Mudanças de significado são sempre de alta intensidade
      }
      
      return section;
    });
  }

  private calculateIntensity(lineCount: number): 'low' | 'medium' | 'high' {
    if (lineCount < 3) return 'low';
    if (lineCount < 10) return 'medium';
    return 'high';
  }

  private countLines(text: string): number {
    return (text.match(/\n/g) || []).length + 1;
  }

  private inferOperation(rawChunk: any): DiffOperation {
    // Tentar inferir operação de diferentes propriedades possíveis
    const op = rawChunk.operation || rawChunk.type || rawChunk.op || 'equal';
    return this.convertSemanticOperation(op);
  }

  private extractText(rawChunk: any): string {
    return rawChunk.text || rawChunk.content || rawChunk.data || String(rawChunk);
  }

  private generateResultId(): string {
    return `result_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private validateRawResult(result: RawDiffResult): void {
    if (!result) {
      throw new DiffEngineAdapterError(
        'Resultado não pode ser nulo',
        'NULL_RESULT'
      );
    }

    if (!result.algorithm) {
      throw new DiffEngineAdapterError(
        'Algoritmo deve ser especificado',
        'MISSING_ALGORITHM'
      );
    }
  }

  /**
   * Retorna lista de algoritmos suportados
   */
  public getSupportedAlgorithms(): string[] {
    return Array.from(this.supportedAlgorithms);
  }

  /**
   * Verifica se um algoritmo é suportado
   */
  public isAlgorithmSupported(algorithm: string): boolean {
    return this.supportedAlgorithms.has(algorithm.toLowerCase());
  }
} 