import { IDiffEngine } from '../../domain/interfaces/IDiffEngine';
import { DiffMatchPatchEngine } from '../diff-engines/DiffMatchPatchEngine';
import { MyersDiffEngine } from '../diff-engines/MyersDiffEngine';
import { SemanticDiffEngine } from '../diff-engines/SemanticDiffEngine';

export interface DocumentCharacteristics {
  size: number; // Tamanho em caracteres
  lineCount: number; // Número de linhas
  wordCount: number; // Número de palavras
  complexity: 'low' | 'medium' | 'high'; // Complexidade baseada em estrutura
  type: 'code' | 'text' | 'legal' | 'technical' | 'unknown'; // Tipo de documento
  language: 'pt' | 'en' | 'auto'; // Idioma detectado
  hasStructure: boolean; // Tem estrutura (títulos, seções, etc.)
  averageLineLength: number; // Tamanho médio das linhas
  whitespaceRatio: number; // Proporção de whitespace
}

export interface EngineRecommendation {
  engine: IDiffEngine;
  engineType: 'diff-match-patch' | 'myers' | 'semantic';
  confidence: number; // Confiança na recomendação (0.0 - 1.0)
  reasoning: string[]; // Razões para a escolha
  estimatedPerformance: {
    speed: 'fast' | 'medium' | 'slow';
    memory: 'low' | 'medium' | 'high';
    accuracy: 'good' | 'better' | 'best';
  };
  limitations: string[]; // Limitações conhecidas
}

export interface StrategyConfig {
  preferSpeed?: boolean; // Priorizar velocidade
  preferAccuracy?: boolean; // Priorizar precisão
  memoryLimit?: number; // Limite de memória em MB
  timeLimit?: number; // Limite de tempo em ms
  customWeights?: {
    speed: number;
    accuracy: number;
    memory: number;
  };
}

/**
 * Estratégia para seleção automática do melhor engine de diff
 * baseado nas características dos documentos
 */
export class DiffEngineStrategy {
  private readonly engines: Map<string, IDiffEngine> = new Map();
  private readonly defaultConfig: Required<StrategyConfig> = {
    preferSpeed: false,
    preferAccuracy: true,
    memoryLimit: 256, // 256MB
    timeLimit: 30000, // 30 segundos
    customWeights: {
      speed: 0.3,
      accuracy: 0.5,
      memory: 0.2
    }
  };

  constructor(private config: StrategyConfig = {}) {
    this.config = { ...this.defaultConfig, ...config };
    this.initializeEngines();
  }

  /**
   * Seleciona o melhor engine baseado nas características dos documentos
   */
  public selectEngine(
    doc1Characteristics: DocumentCharacteristics,
    doc2Characteristics: DocumentCharacteristics,
    customConfig?: Partial<StrategyConfig>
  ): EngineRecommendation {
    const config = { ...this.config, ...customConfig } as Required<StrategyConfig>;
    const combinedCharacteristics = this.combineCharacteristics(doc1Characteristics, doc2Characteristics);

    // Avaliar cada engine
    const evaluations = this.evaluateEngines(combinedCharacteristics, config);

    // Selecionar o melhor baseado nos pesos
    const bestEvaluation = this.selectBestEngine(evaluations, config);

    return bestEvaluation;
  }

  /**
   * Analisa características de um documento
   */
  public analyzeDocument(text: string): DocumentCharacteristics {
    const size = text.length;
    const lines = text.split('\n');
    const lineCount = lines.length;
    const words = text.split(/\s+/).filter(word => word.length > 0);
    const wordCount = words.length;

    const averageLineLength = lineCount > 0 ? size / lineCount : 0;
    const whitespaceMatches = text.match(/\s/g) || [];
    const whitespaceRatio = whitespaceMatches.length / size;

    const complexity = this.determineComplexity(text, lines, words);
    const type = this.determineDocumentType(text);
    const language = this.detectLanguage(text);
    const hasStructure = this.detectStructure(text);

    return {
      size,
      lineCount,
      wordCount,
      complexity,
      type,
      language,
      hasStructure,
      averageLineLength,
      whitespaceRatio
    };
  }

  /**
   * Recomenda engine com base apenas no tamanho (método rápido)
   */
  public quickSelect(documentSize: number): EngineRecommendation {
    if (documentSize < 10000) {
      // Documentos pequenos - usar DiffMatchPatch para máxima precisão
      return {
        engine: this.engines.get('diff-match-patch')!,
        engineType: 'diff-match-patch',
        confidence: 0.9,
        reasoning: ['Document size < 10KB, optimal for DiffMatchPatch'],
        estimatedPerformance: {
          speed: 'fast',
          memory: 'low',
          accuracy: 'best'
        },
        limitations: []
      };
    } else if (documentSize < 1000000) {
      // Documentos médios - usar Myers
      return {
        engine: this.engines.get('myers')!,
        engineType: 'myers',
        confidence: 0.8,
        reasoning: ['Document size 10KB-1MB, optimal for Myers algorithm'],
        estimatedPerformance: {
          speed: 'medium',
          memory: 'medium',
          accuracy: 'better'
        },
        limitations: ['May be slower for highly similar documents']
      };
    } else {
      // Documentos grandes - usar Semantic
      return {
        engine: this.engines.get('semantic')!,
        engineType: 'semantic',
        confidence: 0.7,
        reasoning: ['Document size > 1MB, requires semantic analysis'],
        estimatedPerformance: {
          speed: 'slow',
          memory: 'high',
          accuracy: 'good'
        },
        limitations: ['Limited to 100KB for semantic analysis', 'May miss fine-grained changes']
      };
    }
  }

  /**
   * Obtém uma lista de todos os engines disponíveis
   */
  public getAvailableEngines(): Record<string, IDiffEngine> {
    return Object.fromEntries(this.engines);
  }

  // Métodos privados

  private initializeEngines(): void {
    this.engines.set('diff-match-patch', new DiffMatchPatchEngine());
    this.engines.set('myers', new MyersDiffEngine());
    this.engines.set('semantic', new SemanticDiffEngine());
  }

  private combineCharacteristics(
    doc1: DocumentCharacteristics,
    doc2: DocumentCharacteristics
  ): DocumentCharacteristics {
    return {
      size: Math.max(doc1.size, doc2.size),
      lineCount: Math.max(doc1.lineCount, doc2.lineCount),
      wordCount: Math.max(doc1.wordCount, doc2.wordCount),
      complexity: this.maxComplexity(doc1.complexity, doc2.complexity),
      type: doc1.type === doc2.type ? doc1.type : 'unknown',
      language: doc1.language === doc2.language ? doc1.language : 'auto',
      hasStructure: doc1.hasStructure || doc2.hasStructure,
      averageLineLength: (doc1.averageLineLength + doc2.averageLineLength) / 2,
      whitespaceRatio: (doc1.whitespaceRatio + doc2.whitespaceRatio) / 2
    };
  }

  private evaluateEngines(
    characteristics: DocumentCharacteristics,
    config: Required<StrategyConfig>
  ): Map<string, EngineEvaluation> {
    const evaluations = new Map<string, EngineEvaluation>();

    // Avaliar DiffMatchPatch
    evaluations.set('diff-match-patch', this.evaluateDiffMatchPatch(characteristics));

    // Avaliar Myers
    evaluations.set('myers', this.evaluateMyersDiff(characteristics));

    // Avaliar Semantic
    evaluations.set('semantic', this.evaluateSemanticDiff(characteristics));

    return evaluations;
  }

  private evaluateDiffMatchPatch(characteristics: DocumentCharacteristics): EngineEvaluation {
    const reasoning: string[] = [];
    let confidence = 0.8;
    let suitability = 0.7;

    // Vantagens
    if (characteristics.size < 50000) {
      reasoning.push('Optimal for documents < 50KB');
      confidence += 0.1;
      suitability += 0.2;
    }

    if (characteristics.complexity === 'high') {
      reasoning.push('Excellent for complex document structures');
      suitability += 0.1;
    }

    // Desvantagens
    if (characteristics.size > 5000000) {
      reasoning.push('May be slow for very large documents');
      confidence -= 0.3;
      suitability -= 0.4;
    }

    const limitations: string[] = [];
    if (characteristics.size > 5000000) {
      limitations.push('Performance degrades significantly for files > 5MB');
    }

    return {
      suitability: Math.max(0, Math.min(1, suitability)),
      confidence: Math.max(0, Math.min(1, confidence)),
      reasoning,
      limitations,
      performance: {
        speed: characteristics.size < 10000 ? 'fast' : characteristics.size < 1000000 ? 'medium' : 'slow',
        memory: characteristics.size < 100000 ? 'low' : 'medium',
        accuracy: 'best'
      }
    };
  }

  private evaluateMyersDiff(characteristics: DocumentCharacteristics): EngineEvaluation {
    const reasoning: string[] = [];
    let confidence = 0.7;
    let suitability = 0.8;

    // Vantagens
    if (characteristics.size >= 10000 && characteristics.size <= 10000000) {
      reasoning.push('Optimal for medium to large documents (10KB-10MB)');
      confidence += 0.1;
      suitability += 0.1;
    }

    if (characteristics.type === 'code') {
      reasoning.push('Excellent for code comparison');
      suitability += 0.2;
    }

    if (characteristics.hasStructure) {
      reasoning.push('Good for structured documents');
      suitability += 0.1;
    }

    // Desvantagens
    if (characteristics.size < 1000) {
      reasoning.push('May be overkill for very small documents');
      suitability -= 0.2;
    }

    const limitations: string[] = [];
    if (characteristics.complexity === 'high') {
      limitations.push('May miss semantic relationships in complex documents');
    }

    return {
      suitability: Math.max(0, Math.min(1, suitability)),
      confidence: Math.max(0, Math.min(1, confidence)),
      reasoning,
      limitations,
      performance: {
        speed: 'medium',
        memory: characteristics.size < 1000000 ? 'medium' : 'high',
        accuracy: 'better'
      }
    };
  }

  private evaluateSemanticDiff(characteristics: DocumentCharacteristics): EngineEvaluation {
    const reasoning: string[] = [];
    let confidence = 0.6;
    let suitability = 0.5;

    // Vantagens
    if (characteristics.type === 'legal' || characteristics.type === 'technical') {
      reasoning.push('Excellent for legal and technical documents');
      confidence += 0.2;
      suitability += 0.3;
    }

    if (characteristics.complexity === 'high' && characteristics.hasStructure) {
      reasoning.push('Good for complex structured documents');
      suitability += 0.2;
    }

    if (characteristics.size < 100000) {
      reasoning.push('Optimal for documents < 100KB');
      confidence += 0.1;
      suitability += 0.1;
    }

    // Desvantagens
    if (characteristics.size > 100000) {
      reasoning.push('Limited to 100KB for full semantic analysis');
      confidence -= 0.2;
      suitability -= 0.3;
    }

    const limitations: string[] = [
      'Limited to documents < 100KB',
      'May miss fine-grained formatting changes'
    ];

    return {
      suitability: Math.max(0, Math.min(1, suitability)),
      confidence: Math.max(0, Math.min(1, confidence)),
      reasoning,
      limitations,
      performance: {
        speed: characteristics.size < 50000 ? 'medium' : 'slow',
        memory: 'high',
        accuracy: characteristics.type === 'legal' ? 'best' : 'good'
      }
    };
  }

  private selectBestEngine(
    evaluations: Map<string, EngineEvaluation>,
    config: Required<StrategyConfig>
  ): EngineRecommendation {
    let bestScore = -1;
    let bestEngine = '';
    let bestEvaluation: EngineEvaluation | null = null;

    for (const [engineName, evaluation] of evaluations) {
      const score = this.calculateEngineScore(evaluation, config);
      
      if (score > bestScore) {
        bestScore = score;
        bestEngine = engineName;
        bestEvaluation = evaluation;
      }
    }

    if (!bestEvaluation) {
      // Fallback para DiffMatchPatch
      bestEngine = 'diff-match-patch';
      bestEvaluation = evaluations.get('diff-match-patch')!;
    }

    return {
      engine: this.engines.get(bestEngine)!,
      engineType: bestEngine as any,
      confidence: bestEvaluation.confidence,
      reasoning: bestEvaluation.reasoning,
      estimatedPerformance: bestEvaluation.performance,
      limitations: bestEvaluation.limitations
    };
  }

  private calculateEngineScore(evaluation: EngineEvaluation, config: Required<StrategyConfig>): number {
    const weights = config.customWeights;
    
    // Mapear performance para números
    const speedScore = evaluation.performance.speed === 'fast' ? 1 : 
                      evaluation.performance.speed === 'medium' ? 0.6 : 0.3;
    
    const memoryScore = evaluation.performance.memory === 'low' ? 1 : 
                       evaluation.performance.memory === 'medium' ? 0.6 : 0.3;
    
    const accuracyScore = evaluation.performance.accuracy === 'best' ? 1 : 
                         evaluation.performance.accuracy === 'better' ? 0.8 : 0.6;

    // Calcular score ponderado
    const score = (
      evaluation.suitability * 0.4 + // 40% adequação
      speedScore * weights.speed +
      memoryScore * weights.memory +
      accuracyScore * weights.accuracy
    ) * evaluation.confidence;

    return score;
  }

  // Métodos utilitários

  private determineComplexity(text: string, lines: string[], words: string[]): DocumentCharacteristics['complexity'] {
    let complexityScore = 0;

    // Fatores que aumentam complexidade
    if (text.includes('\n\n')) complexityScore += 1; // Parágrafos
    if (text.match(/[.!?]/g)?.length || 0 > lines.length * 0.5) complexityScore += 1; // Muitas sentenças
    if (text.match(/[{}[\]()]/g)?.length || 0 > text.length * 0.01) complexityScore += 1; // Estruturas
    if (words.length / lines.length > 15) complexityScore += 1; // Linhas longas
    if (text.match(/\d+/g)?.length || 0 > words.length * 0.1) complexityScore += 1; // Muitos números

    if (complexityScore >= 4) return 'high';
    if (complexityScore >= 2) return 'medium';
    return 'low';
  }

  private determineDocumentType(text: string): DocumentCharacteristics['type'] {
    const legalTerms = ['contrato', 'cláusula', 'artigo', 'parágrafo', 'contract', 'clause', 'legal'];
    const codeIndicators = ['{', '}', 'function', 'class', 'import', 'export', '=', '==='];
    const technicalTerms = ['API', 'sistema', 'configuração', 'documentation', 'specification'];

    const lowerText = text.toLowerCase();

    // Detectar código
    const codeScore = codeIndicators.reduce((score, indicator) => 
      score + (lowerText.includes(indicator.toLowerCase()) ? 1 : 0), 0);
    
    if (codeScore >= 3) return 'code';

    // Detectar documentos legais
    const legalScore = legalTerms.reduce((score, term) => 
      score + (lowerText.includes(term) ? 1 : 0), 0);
    
    if (legalScore >= 2) return 'legal';

    // Detectar documentos técnicos
    const techScore = technicalTerms.reduce((score, term) => 
      score + (lowerText.includes(term.toLowerCase()) ? 1 : 0), 0);
    
    if (techScore >= 2) return 'technical';

    return 'text';
  }

  private detectLanguage(text: string): DocumentCharacteristics['language'] {
    const portugueseIndicators = /[áàâãäéèêëíìîïóòôõöúùûüç]/gi;
    const portugueseMatches = (text.match(portugueseIndicators) || []).length;
    
    const commonPortugueseWords = ['que', 'de', 'para', 'com', 'em', 'por'];
    const portugueseWordMatches = commonPortugueseWords.filter(word => 
      text.toLowerCase().includes(word)
    ).length;

    if (portugueseMatches > 0 || portugueseWordMatches >= 2) {
      return 'pt';
    }

    // Detectar inglês (simplificado)
    const commonEnglishWords = ['the', 'and', 'for', 'with', 'that'];
    const englishWordMatches = commonEnglishWords.filter(word => 
      text.toLowerCase().includes(word)
    ).length;

    if (englishWordMatches >= 2) {
      return 'en';
    }

    return 'auto';
  }

  private detectStructure(text: string): boolean {
    // Detectar títulos, listas, numeração
    const structureIndicators = [
      /^#{1,6}\s/gm, // Markdown headers
      /^\d+\.\s/gm, // Numbered lists
      /^[-*+]\s/gm, // Bullet lists
      /^[IVX]+\.\s/gm, // Roman numerals
      /^\s*[A-Z][A-Z\s]*:$/gm // All caps titles
    ];

    return structureIndicators.some(pattern => pattern.test(text));
  }

  private maxComplexity(
    c1: DocumentCharacteristics['complexity'], 
    c2: DocumentCharacteristics['complexity']
  ): DocumentCharacteristics['complexity'] {
    const complexityOrder = { 'low': 0, 'medium': 1, 'high': 2 };
    return complexityOrder[c1] >= complexityOrder[c2] ? c1 : c2;
  }
}

interface EngineEvaluation {
  suitability: number; // 0.0 - 1.0
  confidence: number; // 0.0 - 1.0
  reasoning: string[];
  limitations: string[];
  performance: {
    speed: 'fast' | 'medium' | 'slow';
    memory: 'low' | 'medium' | 'high';
    accuracy: 'good' | 'better' | 'best';
  };
} 