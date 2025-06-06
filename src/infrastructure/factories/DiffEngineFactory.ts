import { IDiffEngine, DiffEngineConfig } from '../../domain/interfaces/IDiffEngine';

export type DiffEngineType = 'diff-match-patch' | 'myers' | 'semantic';

export interface EngineConfiguration {
  type: DiffEngineType;
  config?: DiffEngineConfig;
  priority?: number;
  maxFileSize?: number;
  recommendedFor?: string[];
}

export interface EngineRegistration {
  type: DiffEngineType;
  factory: (config?: DiffEngineConfig) => IDiffEngine;
  metadata: {
    name: string;
    version: string;
    description: string;
    complexity: {
      time: string;
      space: string;
    };
    capabilities: {
      supportsLargeFiles: boolean;
      supportsSemanticAnalysis: boolean;
      supportsBlockMovement: boolean;
      supportsIncrementalDiff: boolean;
    };
    maxRecommendedSize: number;
  };
}

export class DiffEngineFactoryError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly engineType?: string
  ) {
    super(message);
    this.name = 'DiffEngineFactoryError';
  }
}

/**
 * Factory para criação de engines de diff com registro dinâmico
 * Implementa Strategy Pattern + Factory Pattern
 */
export class DiffEngineFactory {
  private static instance: DiffEngineFactory;
  private readonly engineRegistry = new Map<DiffEngineType, EngineRegistration>();
  private readonly defaultConfigs = new Map<DiffEngineType, DiffEngineConfig>();

  private constructor() {
    // Configurações padrão para cada tipo de engine
    this.initializeDefaultConfigs();
  }

  /**
   * Singleton pattern para garantir única instância da factory
   */
  public static getInstance(): DiffEngineFactory {
    if (!DiffEngineFactory.instance) {
      DiffEngineFactory.instance = new DiffEngineFactory();
    }
    return DiffEngineFactory.instance;
  }

  /**
   * Registra um novo engine na factory
   */
  public registerEngine(registration: EngineRegistration): void {
    if (this.engineRegistry.has(registration.type)) {
      throw new DiffEngineFactoryError(
        `Engine ${registration.type} já está registrado`,
        'ENGINE_ALREADY_REGISTERED',
        registration.type
      );
    }

    this.engineRegistry.set(registration.type, registration);
  }

  /**
   * Remove um engine do registro
   */
  public unregisterEngine(type: DiffEngineType): boolean {
    return this.engineRegistry.delete(type);
  }

  /**
   * Cria uma instância do engine especificado
   */
  public createEngine(type: DiffEngineType, config?: DiffEngineConfig): IDiffEngine {
    const registration = this.engineRegistry.get(type);
    
    if (!registration) {
      throw new DiffEngineFactoryError(
        `Engine ${type} não encontrado no registro`,
        'ENGINE_NOT_FOUND',
        type
      );
    }

    try {
      // Mescla configuração padrão com configuração fornecida
      const mergedConfig = this.mergeConfigs(type, config);
      
      // Cria a instância do engine
      const engine = registration.factory(mergedConfig);
      
      // Valida se o engine foi criado corretamente
      this.validateEngine(engine, type);
      
      return engine;
    } catch (error) {
      throw new DiffEngineFactoryError(
        `Falha ao criar engine ${type}: ${error instanceof Error ? error.message : 'Erro desconhecido'}`,
        'ENGINE_CREATION_FAILED',
        type
      );
    }
  }

  /**
   * Seleciona automaticamente o melhor engine baseado no contexto
   */
  public selectOptimalEngine(
    originalSize: number,
    modifiedSize: number,
    options?: {
      requireSemanticAnalysis?: boolean;
      requireBlockMovement?: boolean;
      requireIncrementalDiff?: boolean;
      timeoutMs?: number;
    }
  ): DiffEngineType {
    const totalSize = originalSize + modifiedSize;
    const availableEngines = Array.from(this.engineRegistry.values());

    // Filtrar engines baseado nos requisitos
    let candidateEngines = availableEngines.filter(engine => {
      if (options?.requireSemanticAnalysis && !engine.metadata.capabilities.supportsSemanticAnalysis) {
        return false;
      }
      if (options?.requireBlockMovement && !engine.metadata.capabilities.supportsBlockMovement) {
        return false;
      }
      if (options?.requireIncrementalDiff && !engine.metadata.capabilities.supportsIncrementalDiff) {
        return false;
      }
      if (totalSize > engine.metadata.maxRecommendedSize && !engine.metadata.capabilities.supportsLargeFiles) {
        return false;
      }
      return true;
    });

    // Se nenhum engine atende aos requisitos, usar engines que suportam arquivos grandes
    if (candidateEngines.length === 0) {
      candidateEngines = availableEngines.filter(engine => 
        engine.metadata.capabilities.supportsLargeFiles || totalSize <= engine.metadata.maxRecommendedSize
      );
    }

    // Se ainda não há candidatos, usar qualquer engine disponível
    if (candidateEngines.length === 0) {
      candidateEngines = availableEngines;
    }

    // Aplicar lógica de seleção baseada no tamanho
    if (totalSize < 50000) { // < 50KB - usar engine mais preciso
      const semanticEngine = candidateEngines.find(e => e.type === 'semantic');
      if (semanticEngine) return semanticEngine.type;
    } else if (totalSize < 1000000) { // < 1MB - usar Myers para balancear precisão e performance
      const myersEngine = candidateEngines.find(e => e.type === 'myers');
      if (myersEngine) return myersEngine.type;
    }

    // Para arquivos grandes ou fallback - usar DiffMatchPatch
    const dmpEngine = candidateEngines.find(e => e.type === 'diff-match-patch');
    if (dmpEngine) return dmpEngine.type;

    // Último fallback - primeiro engine disponível
    return candidateEngines[0].type;
  }

  /**
   * Cria engine automaticamente selecionado
   */
  public createOptimalEngine(
    originalSize: number,
    modifiedSize: number,
    config?: DiffEngineConfig,
    options?: {
      requireSemanticAnalysis?: boolean;
      requireBlockMovement?: boolean;
      requireIncrementalDiff?: boolean;
      timeoutMs?: number;
    }
  ): IDiffEngine {
    const optimalType = this.selectOptimalEngine(originalSize, modifiedSize, options);
    return this.createEngine(optimalType, config);
  }

  /**
   * Lista todos os engines registrados
   */
  public getAvailableEngines(): EngineRegistration[] {
    return Array.from(this.engineRegistry.values());
  }

  /**
   * Obtém informações sobre um engine específico
   */
  public getEngineInfo(type: DiffEngineType): EngineRegistration | null {
    return this.engineRegistry.get(type) || null;
  }

  /**
   * Verifica se um engine está registrado
   */
  public hasEngine(type: DiffEngineType): boolean {
    return this.engineRegistry.has(type);
  }

  /**
   * Define configuração padrão para um tipo de engine
   */
  public setDefaultConfig(type: DiffEngineType, config: DiffEngineConfig): void {
    this.defaultConfigs.set(type, config);
  }

  /**
   * Obtém configuração padrão para um tipo de engine
   */
  public getDefaultConfig(type: DiffEngineType): DiffEngineConfig | null {
    return this.defaultConfigs.get(type) || null;
  }

  /**
   * Estima tempo de processamento para um engine específico
   */
  public estimateProcessingTime(
    type: DiffEngineType,
    originalSize: number,
    modifiedSize: number
  ): number {
    const registration = this.engineRegistry.get(type);
    if (!registration) {
      return 0;
    }

    // Criar instância temporária para estimativa
    try {
      const engine = registration.factory();
      return engine.estimateProcessingTime(originalSize, modifiedSize);
    } catch {
      // Se falhar, usar estimativa baseada na complexidade
      return this.fallbackEstimate(registration.metadata.complexity.time, originalSize, modifiedSize);
    }
  }

  /**
   * Valida todas as configurações da factory
   */
  public validateConfiguration(): {
    isValid: boolean;
    errors: string[];
    warnings: string[];
  } {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Verificar se há pelo menos um engine registrado
    if (this.engineRegistry.size === 0) {
      errors.push('Nenhum engine registrado na factory');
    }

    // Verificar se engines básicos estão disponíveis
    const basicEngines: DiffEngineType[] = ['diff-match-patch'];
    for (const engineType of basicEngines) {
      if (!this.hasEngine(engineType)) {
        warnings.push(`Engine básico ${engineType} não está registrado`);
      }
    }

    // Validar cada engine registrado
    for (const [type, registration] of this.engineRegistry) {
      try {
        // Tentar criar uma instância para validação
        const engine = registration.factory();
        this.validateEngine(engine, type);
      } catch (error) {
        errors.push(`Engine ${type} falhou na validação: ${error instanceof Error ? error.message : 'Erro desconhecido'}`);
      }
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings
    };
  }

  private initializeDefaultConfigs(): void {
    // Configuração padrão para DiffMatchPatch
    this.defaultConfigs.set('diff-match-patch', {
      timeout: 30000,
      chunkSize: 10000,
      enableOptimizations: true,
      preserveWhitespace: false,
      semanticAnalysis: false
    });

    // Configuração padrão para Myers
    this.defaultConfigs.set('myers', {
      timeout: 45000,
      chunkSize: 5000,
      enableOptimizations: true,
      preserveWhitespace: false,
      semanticAnalysis: false
    });

    // Configuração padrão para Semantic
    this.defaultConfigs.set('semantic', {
      timeout: 60000,
      chunkSize: 2000,
      enableOptimizations: true,
      preserveWhitespace: true,
      semanticAnalysis: true
    });
  }

  private mergeConfigs(type: DiffEngineType, userConfig?: DiffEngineConfig): DiffEngineConfig {
    const defaultConfig = this.defaultConfigs.get(type) || {};
    
    if (!userConfig) {
      return defaultConfig;
    }

    return {
      ...defaultConfig,
      ...userConfig
    };
  }

  private validateEngine(engine: IDiffEngine, expectedType: DiffEngineType): void {
    if (!engine) {
      throw new Error('Engine não pode ser nulo');
    }

    if (!engine.name || typeof engine.name !== 'string') {
      throw new Error('Engine deve ter um nome válido');
    }

    if (!engine.version || typeof engine.version !== 'string') {
      throw new Error('Engine deve ter uma versão válida');
    }

    if (!engine.compare || typeof engine.compare !== 'function') {
      throw new Error('Engine deve implementar método compare()');
    }

    if (!engine.visualize || typeof engine.visualize !== 'function') {
      throw new Error('Engine deve implementar método visualize()');
    }

    if (!engine.getSummary || typeof engine.getSummary !== 'function') {
      throw new Error('Engine deve implementar método getSummary()');
    }
  }

  private fallbackEstimate(complexity: string, originalSize: number, modifiedSize: number): number {
    const totalSize = originalSize + modifiedSize;
    
    switch (complexity.toLowerCase()) {
      case 'o(n)':
        return totalSize * 0.001; // 1ms per 1000 characters
      case 'o(n*m)':
        return (originalSize * modifiedSize) / 1000000; // More complex calculation
      case 'o(n*log(n))':
        return totalSize * Math.log(totalSize) * 0.0001;
      default:
        return totalSize * 0.01; // Conservative estimate
    }
  }
}

/**
 * Instância global da factory (singleton)
 */
export const diffEngineFactory = DiffEngineFactory.getInstance(); 