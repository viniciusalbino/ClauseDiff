import { DiffResult } from '../../domain/entities/DiffResult';

export interface CacheEntry<T = any> {
  key: string;
  value: T;
  timestamp: Date;
  accessCount: number;
  lastAccessed: Date;
  size: number; // Tamanho em bytes
  metadata?: Record<string, any>;
}

export interface CacheConfig {
  maxSize: number; // Tamanho máximo em bytes (padrão: 100MB)
  maxEntries: number; // Número máximo de entradas (padrão: 1000)
  ttl: number; // Time to live em milissegundos (padrão: 1 hora)
  cleanupInterval: number; // Intervalo de limpeza em milissegundos (padrão: 5 minutos)
}

export interface CacheStats {
  totalEntries: number;
  totalSize: number;
  maxSize: number;
  hitRate: number;
  missRate: number;
  averageEntrySize: number;
  oldestEntry?: Date;
  newestEntry?: Date;
  memoryUsagePercentage: number;
}

export class LRUCacheError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly details?: any
  ) {
    super(message);
    this.name = 'LRUCacheError';
  }
}

/**
 * Cache LRU (Least Recently Used) otimizado para resultados de diff
 */
export class LRUCache<T = any> {
  private cache = new Map<string, CacheEntry<T>>();
  private accessOrder: string[] = []; // Lista ordenada por acesso (mais recente no final)
  private config: CacheConfig;
  private stats = {
    hits: 0,
    misses: 0,
    evictions: 0,
    cleanups: 0
  };
  private cleanupTimer: NodeJS.Timeout | null = null;

  constructor(config: Partial<CacheConfig> = {}) {
    this.config = {
      maxSize: config.maxSize || 100 * 1024 * 1024, // 100MB padrão
      maxEntries: config.maxEntries || 1000,
      ttl: config.ttl || 60 * 60 * 1000, // 1 hora padrão
      cleanupInterval: config.cleanupInterval || 5 * 60 * 1000 // 5 minutos padrão
    };

    this.startCleanupTimer();
  }

  /**
   * Adiciona um item ao cache
   */
  public set(key: string, value: T, metadata?: Record<string, any>): void {
    try {
      const size = this.calculateSize(value);
      
      // Verificar se o item individual não excede o limite do cache
      if (size > this.config.maxSize) {
        throw new LRUCacheError(
          `Item muito grande para o cache: ${this.formatSize(size)}`,
          'ITEM_TOO_LARGE',
          { key, size, maxSize: this.config.maxSize }
        );
      }

      const now = new Date();
      const entry: CacheEntry<T> = {
        key,
        value,
        timestamp: now,
        accessCount: 1,
        lastAccessed: now,
        size,
        metadata
      };

      // Remover entrada existente se houver
      if (this.cache.has(key)) {
        this.remove(key);
      }

      // Garantir espaço suficiente
      this.ensureSpace(size);

      // Adicionar nova entrada
      this.cache.set(key, entry);
      this.accessOrder.push(key);

      // Verificar limites após inserção
      this.enforceConstraints();
    } catch (error) {
      if (error instanceof LRUCacheError) {
        throw error;
      }
      throw new LRUCacheError(
        `Falha ao adicionar item ao cache: ${error instanceof Error ? error.message : 'Erro desconhecido'}`,
        'SET_FAILED',
        { key }
      );
    }
  }

  /**
   * Recupera um item do cache
   */
  public get(key: string): T | undefined {
    const entry = this.cache.get(key);
    
    if (!entry) {
      this.stats.misses++;
      return undefined;
    }

    // Verificar TTL
    if (this.isExpired(entry)) {
      this.remove(key);
      this.stats.misses++;
      return undefined;
    }

    // Atualizar estatísticas de acesso
    entry.accessCount++;
    entry.lastAccessed = new Date();
    this.stats.hits++;

    // Mover para o final da lista (mais recente)
    this.moveToEnd(key);

    return entry.value;
  }

  /**
   * Verifica se uma chave existe no cache (sem afetar LRU)
   */
  public has(key: string): boolean {
    const entry = this.cache.get(key);
    return entry !== undefined && !this.isExpired(entry);
  }

  /**
   * Remove um item do cache
   */
  public remove(key: string): boolean {
    const entry = this.cache.get(key);
    if (!entry) {
      return false;
    }

    this.cache.delete(key);
    
    // Remover da lista de acesso
    const index = this.accessOrder.indexOf(key);
    if (index > -1) {
      this.accessOrder.splice(index, 1);
    }

    return true;
  }

  /**
   * Limpa todo o cache
   */
  public clear(): void {
    this.cache.clear();
    this.accessOrder = [];
    this.resetStats();
  }

  /**
   * Obtém estatísticas do cache
   */
  public getStats(): CacheStats {
    const totalEntries = this.cache.size;
    const totalSize = this.getTotalSize();
    const totalRequests = this.stats.hits + this.stats.misses;
    
    let oldestEntry: Date | undefined;
    let newestEntry: Date | undefined;

    if (totalEntries > 0) {
      const entries = Array.from(this.cache.values());
      oldestEntry = entries.reduce((oldest, entry) => 
        entry.timestamp < oldest ? entry.timestamp : oldest, 
        entries[0].timestamp
      );
      newestEntry = entries.reduce((newest, entry) => 
        entry.timestamp > newest ? entry.timestamp : newest, 
        entries[0].timestamp
      );
    }

    return {
      totalEntries,
      totalSize,
      maxSize: this.config.maxSize,
      hitRate: totalRequests > 0 ? (this.stats.hits / totalRequests) * 100 : 0,
      missRate: totalRequests > 0 ? (this.stats.misses / totalRequests) * 100 : 0,
      averageEntrySize: totalEntries > 0 ? totalSize / totalEntries : 0,
      oldestEntry,
      newestEntry,
      memoryUsagePercentage: (totalSize / this.config.maxSize) * 100
    };
  }

  /**
   * Obtém informações detalhadas de uma entrada
   */
  public getEntryInfo(key: string): CacheEntry<T> | undefined {
    const entry = this.cache.get(key);
    if (!entry || this.isExpired(entry)) {
      return undefined;
    }
    return { ...entry }; // Retornar cópia para evitar modificações externas
  }

  /**
   * Lista todas as chaves no cache (ordenadas por acesso)
   */
  public keys(): string[] {
    return [...this.accessOrder];
  }

  /**
   * Obtém o tamanho atual do cache em bytes
   */
  public size(): number {
    return this.getTotalSize();
  }

  /**
   * Força limpeza de itens expirados
   */
  public cleanup(): number {
    const initialSize = this.cache.size;
    const now = new Date();
    
    for (const [key, entry] of this.cache.entries()) {
      if (this.isExpired(entry, now)) {
        this.remove(key);
      }
    }

    const cleanedCount = initialSize - this.cache.size;
    this.stats.cleanups++;
    
    return cleanedCount;
  }

  /**
   * Atualiza a configuração do cache
   */
  public updateConfig(newConfig: Partial<CacheConfig>): void {
    const oldConfig = { ...this.config };
    this.config = { ...this.config, ...newConfig };

    // Se o tamanho máximo foi reduzido, aplicar imediatamente
    if (newConfig.maxSize && newConfig.maxSize < oldConfig.maxSize) {
      this.enforceConstraints();
    }

    // Reiniciar timer de limpeza se o intervalo mudou
    if (newConfig.cleanupInterval && newConfig.cleanupInterval !== oldConfig.cleanupInterval) {
      this.stopCleanupTimer();
      this.startCleanupTimer();
    }
  }

  /**
   * Exporta o cache para JSON (útil para persistência)
   */
  public export(): string {
    const exportData = {
      config: this.config,
      entries: Array.from(this.cache.entries()),
      accessOrder: this.accessOrder,
      stats: this.stats,
      timestamp: new Date().toISOString()
    };
    
    return JSON.stringify(exportData, (key, value) => {
      // Converter Dates para strings para serialização
      if (value instanceof Date) {
        return value.toISOString();
      }
      return value;
    });
  }

  /**
   * Importa cache de JSON
   */
  public import(jsonData: string): void {
    try {
      const data = JSON.parse(jsonData);
      
      this.clear();
      this.config = { ...this.config, ...data.config };
      
      // Restaurar entradas
      for (const [key, entry] of data.entries) {
        // Converter strings de volta para Dates
        entry.timestamp = new Date(entry.timestamp);
        entry.lastAccessed = new Date(entry.lastAccessed);
        
        this.cache.set(key, entry);
      }
      
      this.accessOrder = data.accessOrder || [];
      this.stats = { ...this.stats, ...data.stats };
      
    } catch (error) {
      throw new LRUCacheError(
        `Falha ao importar cache: ${error instanceof Error ? error.message : 'Erro desconhecido'}`,
        'IMPORT_FAILED'
      );
    }
  }

  /**
   * Finaliza o cache e limpa recursos
   */
  public destroy(): void {
    this.stopCleanupTimer();
    this.clear();
  }

  // Métodos privados

  private calculateSize(value: T): number {
    if (value === null || value === undefined) {
      return 0;
    }

    // Se for DiffResult, calcular tamanho baseado em chunks
    if (this.isDiffResult(value)) {
      return this.calculateDiffResultSize(value);
    }

    // Para outros tipos, usar JSON.stringify como aproximação
    try {
      return new Blob([JSON.stringify(value)]).size;
    } catch {
      // Fallback para estimativa simples
      return JSON.stringify(value).length * 2; // Assumir 2 bytes por caractere
    }
  }

  private isDiffResult(value: any): value is DiffResult {
    return value && 
           typeof value.id === 'string' && 
           typeof value.comparisonId === 'string' &&
           Array.isArray(value.chunks);
  }

  private calculateDiffResultSize(diffResult: DiffResult): number {
    let size = 0;
    
    // Tamanho básico da estrutura
    size += JSON.stringify({
      id: diffResult.id,
      comparisonId: diffResult.comparisonId,
      algorithm: diffResult.algorithm,
      version: diffResult.version
    }).length * 2;
    
    // Tamanho dos chunks
    for (const chunk of diffResult.chunks) {
      size += chunk.text.length * 2; // Texto é o maior componente
      size += 100; // Estimativa para outros campos do chunk
    }
    
    // Tamanho das estatísticas e seções
    size += 500; // Estimativa fixa para statistics e changeSections
    
    return size;
  }

  private getTotalSize(): number {
    let total = 0;
    for (const entry of this.cache.values()) {
      total += entry.size;
    }
    return total;
  }

  private isExpired(entry: CacheEntry<T>, now: Date = new Date()): boolean {
    return (now.getTime() - entry.timestamp.getTime()) > this.config.ttl;
  }

  private moveToEnd(key: string): void {
    const index = this.accessOrder.indexOf(key);
    if (index > -1) {
      this.accessOrder.splice(index, 1);
      this.accessOrder.push(key);
    }
  }

  private ensureSpace(requiredSize: number): void {
    while (this.shouldEvict(requiredSize)) {
      this.evictLeastRecentlyUsed();
    }
  }

  private shouldEvict(additionalSize: number): boolean {
    const currentSize = this.getTotalSize();
    const wouldExceedSize = (currentSize + additionalSize) > this.config.maxSize;
    const wouldExceedEntries = this.cache.size >= this.config.maxEntries;
    
    return wouldExceedSize || wouldExceedEntries;
  }

  private evictLeastRecentlyUsed(): void {
    if (this.accessOrder.length === 0) {
      return;
    }

    const lruKey = this.accessOrder[0];
    this.remove(lruKey);
    this.stats.evictions++;
  }

  private enforceConstraints(): void {
    // Remover itens expirados primeiro
    this.cleanup();
    
    // Então evitar baseado em tamanho e número de entradas
    while (this.shouldEvict(0)) {
      this.evictLeastRecentlyUsed();
    }
  }

  private startCleanupTimer(): void {
    this.cleanupTimer = setInterval(() => {
      this.cleanup();
    }, this.config.cleanupInterval);
  }

  private stopCleanupTimer(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
  }

  private resetStats(): void {
    this.stats = {
      hits: 0,
      misses: 0,
      evictions: 0,
      cleanups: 0
    };
  }

  private formatSize(bytes: number): string {
    const units = ['B', 'KB', 'MB', 'GB'];
    let size = bytes;
    let unitIndex = 0;
    
    while (size >= 1024 && unitIndex < units.length - 1) {
      size /= 1024;
      unitIndex++;
    }
    
    return `${size.toFixed(2)} ${units[unitIndex]}`;
  }
}

/**
 * Cache especializado para resultados de diff
 */
export class DiffResultCache extends LRUCache<DiffResult> {
  constructor(config: Partial<CacheConfig> = {}) {
    super({
      maxSize: 100 * 1024 * 1024, // 100MB padrão
      maxEntries: 500, // Menos entradas por serem maiores
      ttl: 2 * 60 * 60 * 1000, // 2 horas para resultados de diff
      cleanupInterval: 10 * 60 * 1000, // 10 minutos
      ...config
    });
  }

  /**
   * Gera chave de cache baseada nos parâmetros de comparação
   */
  public static generateKey(
    originalHash: string,
    modifiedHash: string,
    algorithm: string,
    options?: Record<string, any>
  ): string {
    const optionsHash = options ? JSON.stringify(options) : '';
    return `diff_${originalHash}_${modifiedHash}_${algorithm}_${this.simpleHash(optionsHash)}`;
  }

  /**
   * Hash simples para opções
   */
  private static simpleHash(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Converter para 32bit integer
    }
    return hash.toString(36);
  }

  /**
   * Adiciona resultado de diff com metadados específicos
   */
  public setDiffResult(
    originalHash: string,
    modifiedHash: string,
    algorithm: string,
    result: DiffResult,
    options?: Record<string, any>
  ): void {
    const key = DiffResultCache.generateKey(originalHash, modifiedHash, algorithm, options);
    const metadata = {
      algorithm,
      originalHash,
      modifiedHash,
      totalChanges: result.statistics.totalChanges,
      similarity: result.statistics.similarity.overall,
      options
    };
    
    this.set(key, result, metadata);
  }

  /**
   * Recupera resultado de diff
   */
  public getDiffResult(
    originalHash: string,
    modifiedHash: string,
    algorithm: string,
    options?: Record<string, any>
  ): DiffResult | undefined {
    const key = DiffResultCache.generateKey(originalHash, modifiedHash, algorithm, options);
    return this.get(key);
  }
}

/**
 * Instância global do cache de diff
 */
let globalDiffCache: DiffResultCache | null = null;

export function getDiffCache(): DiffResultCache {
  if (!globalDiffCache) {
    globalDiffCache = new DiffResultCache();
  }
  return globalDiffCache;
}

export function destroyDiffCache(): void {
  if (globalDiffCache) {
    globalDiffCache.destroy();
    globalDiffCache = null;
  }
} 