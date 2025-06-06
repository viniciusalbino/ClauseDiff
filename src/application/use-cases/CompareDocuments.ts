import { DocumentComparison, DocumentMetadata, ComparisonConfig } from '../../domain/entities/DocumentComparison';
import { DiffResult } from '../../domain/entities/DiffResult';
import { IDiffEngine, CompareOptions } from '../../domain/interfaces/IDiffEngine';
import { ICacheService } from '../../domain/interfaces/IStorageService';

export interface CompareDocumentsRequest {
  originalDocument: {
    content: string;
    metadata: DocumentMetadata;
  };
  modifiedDocument: {
    content: string;
    metadata: DocumentMetadata;
  };
  config?: ComparisonConfig;
  useCache?: boolean;
}

export interface CompareDocumentsResponse {
  comparison: DocumentComparison;
  result: DiffResult;
  fromCache: boolean;
  processingTime: number;
}

export class CompareDocumentsError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly details?: any
  ) {
    super(message);
    this.name = 'CompareDocumentsError';
  }
}

export class CompareDocuments {
  constructor(
    private readonly diffEngineFactory: (algorithm: string) => IDiffEngine,
    private readonly cacheService?: ICacheService
  ) {}

  async execute(request: CompareDocumentsRequest): Promise<CompareDocumentsResponse> {
    const startTime = Date.now();
    
    try {
      // Validar entrada
      this.validateRequest(request);

      // Criar entidade de comparação
      const comparisonId = this.generateComparisonId(request);
      const comparison = new DocumentComparison(
        comparisonId,
        request.originalDocument.metadata,
        request.modifiedDocument.metadata,
        request.config || { algorithm: 'diff-match-patch' }
      );

      // Validar documentos
      if (!comparison.validateDocuments()) {
        throw new CompareDocumentsError(
          'Documentos inválidos: tamanho excede 5MB ou formato não suportado',
          'INVALID_DOCUMENTS'
        );
      }

      // Verificar cache se habilitado
      let result: DiffResult | null = null;
      let fromCache = false;

      if (request.useCache && this.cacheService) {
        const cacheKey = this.generateCacheKey(request);
        result = await this.cacheService.get<DiffResult>(cacheKey);
        fromCache = !!result;
      }

      // Se não encontrou no cache, processar comparação
      if (!result) {
        comparison.updateStatus('processing');
        result = await this.performComparison(comparison, request);
        
        // Armazenar no cache se habilitado
        if (request.useCache && this.cacheService) {
          const cacheKey = this.generateCacheKey(request);
          await this.cacheService.set(cacheKey, result, {
            ttl: 60 * 60 * 1000, // 1 hora
            tags: ['diff-results', comparison.config.algorithm]
          });
        }
      }

      comparison.updateStatus('completed');
      const processingTime = Date.now() - startTime;

      return {
        comparison,
        result,
        fromCache,
        processingTime
      };

    } catch (error) {
      const processingTime = Date.now() - startTime;
      
      if (error instanceof CompareDocumentsError) {
        throw error;
      }

      throw new CompareDocumentsError(
        `Falha na comparação: ${error instanceof Error ? error.message : 'Erro desconhecido'}`,
        'COMPARISON_FAILED',
        { originalError: error, processingTime }
      );
    }
  }

  private validateRequest(request: CompareDocumentsRequest): void {
    if (!request.originalDocument?.content || !request.modifiedDocument?.content) {
      throw new CompareDocumentsError(
        'Conteúdo dos documentos é obrigatório',
        'MISSING_CONTENT'
      );
    }

    if (!request.originalDocument?.metadata || !request.modifiedDocument?.metadata) {
      throw new CompareDocumentsError(
        'Metadados dos documentos são obrigatórios',
        'MISSING_METADATA'
      );
    }

    // Validar tamanho dos documentos
    const maxSize = 5 * 1024 * 1024; // 5MB
    if (request.originalDocument.content.length > maxSize || 
        request.modifiedDocument.content.length > maxSize) {
      throw new CompareDocumentsError(
        'Documento excede o tamanho máximo de 5MB',
        'DOCUMENT_TOO_LARGE'
      );
    }
  }

  private async performComparison(
    comparison: DocumentComparison,
    request: CompareDocumentsRequest
  ): Promise<DiffResult> {
    // Obter engine apropriado
    const engine = this.diffEngineFactory(comparison.config.algorithm);
    
    if (!engine) {
      throw new CompareDocumentsError(
        `Engine não encontrado para algoritmo: ${comparison.config.algorithm}`,
        'ENGINE_NOT_FOUND'
      );
    }

    // Verificar se o engine pode processar os documentos
    if (!engine.canProcess(
      request.originalDocument.content,
      request.modifiedDocument.content,
      comparison.config
    )) {
      throw new CompareDocumentsError(
        'Engine não pode processar os documentos fornecidos',
        'ENGINE_CANNOT_PROCESS'
      );
    }

    // Configurar opções de comparação
    const compareOptions: CompareOptions = {
      originalText: request.originalDocument.content,
      modifiedText: request.modifiedDocument.content,
      config: {
        timeout: comparison.config.timeout || 30000, // 30 segundos
        chunkSize: comparison.config.chunkSize,
        enableOptimizations: true,
        preserveWhitespace: false,
        semanticAnalysis: comparison.config.algorithm === 'semantic'
      },
      onProgress: (progress) => {
        comparison.updateProgress(progress);
      }
    };

    // Executar comparação
    try {
      const result = await engine.compare(compareOptions);
      comparison.updateProgress(100);
      return result;
    } catch (error) {
      comparison.setError(error instanceof Error ? error.message : 'Erro na comparação');
      throw error;
    }
  }

  private generateComparisonId(request: CompareDocumentsRequest): string {
    // Gerar ID único baseado em timestamp e hash dos documentos
    const timestamp = Date.now();
    const originalHash = this.simpleHash(request.originalDocument.content);
    const modifiedHash = this.simpleHash(request.modifiedDocument.content);
    return `comp_${timestamp}_${originalHash}_${modifiedHash}`;
  }

  private generateCacheKey(request: CompareDocumentsRequest): string {
    // Gerar chave de cache baseada no conteúdo e configuração
    const originalHash = this.simpleHash(request.originalDocument.content);
    const modifiedHash = this.simpleHash(request.modifiedDocument.content);
    const configHash = this.simpleHash(JSON.stringify(request.config || {}));
    return `diff_cache_${originalHash}_${modifiedHash}_${configHash}`;
  }

  private simpleHash(text: string): string {
    // Hash simples para gerar identificadores únicos
    let hash = 0;
    for (let i = 0; i < text.length; i++) {
      const char = text.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(36);
  }

  async estimateProcessingTime(request: CompareDocumentsRequest): Promise<number> {
    const algorithm = request.config?.algorithm || 'diff-match-patch';
    const engine = this.diffEngineFactory(algorithm);
    
    if (!engine) {
      return 0;
    }

    return engine.estimateProcessingTime(
      request.originalDocument.content.length,
      request.modifiedDocument.content.length
    );
  }

  async cancelComparison(comparisonId: string): Promise<boolean> {
    // Implementar cancelamento se suportado pelo engine
    // Por enquanto, retorna false (não implementado)
    return false;
  }
} 