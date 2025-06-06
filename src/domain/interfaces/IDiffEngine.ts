import { DiffResult, DiffChunk, DiffStatistics } from '../entities/DiffResult';

export interface DiffEngineConfig {
  timeout?: number;
  chunkSize?: number;
  enableOptimizations?: boolean;
  preserveWhitespace?: boolean;
  semanticAnalysis?: boolean;
}

export interface CompareOptions {
  originalText: string;
  modifiedText: string;
  config?: DiffEngineConfig;
  onProgress?: (progress: number) => void;
}

export interface VisualizationOptions {
  format: 'html' | 'json' | 'text';
  theme?: 'light' | 'dark';
  showLineNumbers?: boolean;
  highlightSyntax?: boolean;
  collapseUnchanged?: boolean;
}

export interface VisualizationResult {
  format: string;
  content: string;
  metadata?: {
    totalLines: number;
    changedLines: number;
    theme: string;
  };
}

export interface EngineSummary {
  engineName: string;
  algorithmType: string;
  version: string;
  complexity: {
    timeComplexity: string;
    spaceComplexity: string;
  };
  capabilities: {
    supportsLargeFiles: boolean;
    supportsSemanticAnalysis: boolean;
    supportsBlockMovement: boolean;
    supportsIncrementalDiff: boolean;
  };
  recommendedFor: string[];
  limitations: string[];
}

/**
 * Interface principal para engines de comparação de documentos.
 * Define o contrato que todos os algoritmos de diff devem implementar.
 */
export interface IDiffEngine {
  /**
   * Nome identificador do engine
   */
  readonly name: string;

  /**
   * Versão do engine
   */
  readonly version: string;

  /**
   * Configuração padrão do engine
   */
  readonly defaultConfig: DiffEngineConfig;

  /**
   * Compara dois textos e retorna o resultado da diferença
   * 
   * @param options - Opções de comparação incluindo textos e configurações
   * @returns Promise com o resultado da comparação
   * @throws Error se a comparação falhar ou timeout for excedido
   */
  compare(options: CompareOptions): Promise<DiffResult>;

  /**
   * Gera visualização formatada do resultado da comparação
   * 
   * @param diffResult - Resultado da comparação a ser visualizado
   * @param options - Opções de visualização (formato, tema, etc.)
   * @returns Promise com o resultado da visualização formatada
   */
  visualize(diffResult: DiffResult, options: VisualizationOptions): Promise<VisualizationResult>;

  /**
   * Retorna informações detalhadas sobre o engine
   * 
   * @returns Resumo completo das capacidades e características do engine
   */
  getSummary(): EngineSummary;

  /**
   * Valida se o engine pode processar os textos fornecidos
   * 
   * @param originalText - Texto original
   * @param modifiedText - Texto modificado
   * @param config - Configuração opcional
   * @returns true se o engine pode processar, false caso contrário
   */
  canProcess(originalText: string, modifiedText: string, config?: DiffEngineConfig): boolean;

  /**
   * Estima o tempo de processamento baseado no tamanho dos textos
   * 
   * @param originalSize - Tamanho do texto original em caracteres
   * @param modifiedSize - Tamanho do texto modificado em caracteres
   * @returns Estimativa de tempo em milissegundos
   */
  estimateProcessingTime(originalSize: number, modifiedSize: number): number;

  /**
   * Cancela uma operação de comparação em andamento
   * 
   * @param comparisonId - ID da comparação a ser cancelada
   * @returns Promise que resolve quando o cancelamento for completo
   */
  cancel?(comparisonId: string): Promise<void>;

  /**
   * Configura o engine com novos parâmetros
   * 
   * @param config - Nova configuração para o engine
   */
  configure(config: Partial<DiffEngineConfig>): void;
}

/**
 * Interface para engines que suportam processamento em chunks
 */
export interface IChunkableDiffEngine extends IDiffEngine {
  /**
   * Compara textos grandes dividindo em chunks
   * 
   * @param options - Opções de comparação
   * @param chunkSize - Tamanho dos chunks em caracteres
   * @returns Promise com o resultado da comparação
   */
  compareInChunks(options: CompareOptions, chunkSize: number): Promise<DiffResult>;

  /**
   * Define o tamanho ótimo de chunk baseado no tamanho dos textos
   * 
   * @param totalSize - Tamanho total dos textos
   * @returns Tamanho recomendado do chunk
   */
  getOptimalChunkSize(totalSize: number): number;
}

/**
 * Interface para engines que suportam análise semântica
 */
export interface ISemanticDiffEngine extends IDiffEngine {
  /**
   * Analisa mudanças semânticas entre os textos
   * 
   * @param options - Opções de comparação
   * @returns Promise com análise semântica das diferenças
   */
  analyzeSemanticChanges(options: CompareOptions): Promise<{
    meaningChanges: DiffChunk[];
    structuralChanges: DiffChunk[];
    sentiment: 'positive' | 'negative' | 'neutral';
  }>;
}

/**
 * Interface para engines que suportam diff incremental
 */
export interface IIncrementalDiffEngine extends IDiffEngine {
  /**
   * Atualiza um resultado de diff existente com novas mudanças
   * 
   * @param existingResult - Resultado de diff anterior
   * @param newText - Novo texto modificado
   * @returns Promise com o resultado atualizado
   */
  updateDiff(existingResult: DiffResult, newText: string): Promise<DiffResult>;
} 