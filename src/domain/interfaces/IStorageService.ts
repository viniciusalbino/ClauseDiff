export interface StorageItem<T = any> {
  key: string;
  value: T;
  expiresAt?: Date;
  metadata?: Record<string, any>;
  size?: number;
}

export interface StorageOptions {
  ttl?: number; // Time to live in milliseconds
  compress?: boolean;
  encrypt?: boolean;
  tags?: string[];
}

export interface StorageStats {
  totalItems: number;
  totalSize: number;
  hitRate: number;
  missRate: number;
  lastAccessed: Date;
  memoryUsage: number;
}

/**
 * Interface base para serviços de armazenamento
 */
export interface IStorageService {
  /**
   * Armazena um item com chave específica
   * 
   * @param key - Chave única do item
   * @param value - Valor a ser armazenado
   * @param options - Opções de armazenamento (TTL, compressão, etc.)
   * @returns Promise que resolve quando o item for armazenado
   */
  set<T>(key: string, value: T, options?: StorageOptions): Promise<void>;

  /**
   * Recupera um item pela chave
   * 
   * @param key - Chave do item
   * @returns Promise com o valor ou null se não encontrado
   */
  get<T>(key: string): Promise<T | null>;

  /**
   * Remove um item específico
   * 
   * @param key - Chave do item a ser removido
   * @returns Promise que resolve quando o item for removido
   */
  delete(key: string): Promise<boolean>;

  /**
   * Verifica se uma chave existe
   * 
   * @param key - Chave a ser verificada
   * @returns Promise com true se existir, false caso contrário
   */
  exists(key: string): Promise<boolean>;

  /**
   * Remove todos os itens
   * 
   * @returns Promise que resolve quando todos os itens forem removidos
   */
  clear(): Promise<void>;

  /**
   * Lista todas as chaves disponíveis
   * 
   * @param pattern - Padrão opcional para filtrar chaves
   * @returns Promise com array de chaves
   */
  keys(pattern?: string): Promise<string[]>;

  /**
   * Retorna estatísticas do armazenamento
   * 
   * @returns Promise com estatísticas atuais
   */
  getStats(): Promise<StorageStats>;

  /**
   * Define evento de limpeza automática
   * 
   * @param callback - Função chamada quando itens expiram
   */
  onExpire?(callback: (key: string, value: any) => void): void;
}

/**
 * Interface para cache LRU específico
 */
export interface ICacheService extends IStorageService {
  /**
   * Tamanho máximo do cache em bytes
   */
  readonly maxSize: number;

  /**
   * Número máximo de itens no cache
   */
  readonly maxItems: number;

  /**
   * Política de eviction (LRU, LFU, FIFO)
   */
  readonly evictionPolicy: 'lru' | 'lfu' | 'fifo';

  /**
   * Armazena item com prioridade específica
   * 
   * @param key - Chave do item
   * @param value - Valor a ser armazenado
   * @param priority - Prioridade do item (maior = mais importante)
   * @param options - Opções de armazenamento
   */
  setWithPriority<T>(key: string, value: T, priority: number, options?: StorageOptions): Promise<void>;

  /**
   * Recupera e marca como recentemente usado
   * 
   * @param key - Chave do item
   * @returns Promise com o valor ou null
   */
  getAndTouch<T>(key: string): Promise<T | null>;

  /**
   * Pré-carrega itens no cache
   * 
   * @param items - Array de itens para pré-carregar
   * @returns Promise que resolve quando todos os itens forem carregados
   */
  preload<T>(items: Array<{ key: string; value: T; options?: StorageOptions }>): Promise<void>;

  /**
   * Remove itens baseado em tags
   * 
   * @param tags - Tags dos itens a serem removidos
   * @returns Promise com número de itens removidos
   */
  evictByTags(tags: string[]): Promise<number>;

  /**
   * Força limpeza de itens menos recentemente usados
   * 
   * @param percentage - Percentual do cache a ser limpo (0.1 = 10%)
   * @returns Promise com número de itens removidos
   */
  forceEviction(percentage: number): Promise<number>;

  /**
   * Retorna informações sobre uso de memória
   * 
   * @returns Informações detalhadas sobre memória
   */
  getMemoryInfo(): Promise<{
    used: number;
    available: number;
    percentage: number;
    oldestItem: Date;
    newestItem: Date;
  }>;
}

/**
 * Interface para armazenamento de arquivos
 */
export interface IFileStorageService {
  /**
   * Faz upload de um arquivo
   * 
   * @param file - Arquivo a ser enviado
   * @param path - Caminho de destino
   * @param options - Opções de upload
   * @returns Promise com informações do arquivo enviado
   */
  upload(
    file: File | Buffer,
    path: string,
    options?: {
      overwrite?: boolean;
      compress?: boolean;
      generateThumbnail?: boolean;
      metadata?: Record<string, any>;
    }
  ): Promise<{
    path: string;
    size: number;
    url: string;
    checksum: string;
  }>;

  /**
   * Faz download de um arquivo
   * 
   * @param path - Caminho do arquivo
   * @returns Promise com o conteúdo do arquivo
   */
  download(path: string): Promise<Buffer>;

  /**
   * Remove um arquivo
   * 
   * @param path - Caminho do arquivo
   * @returns Promise que resolve quando o arquivo for removido
   */
  deleteFile(path: string): Promise<boolean>;

  /**
   * Lista arquivos em um diretório
   * 
   * @param directory - Diretório a ser listado
   * @param options - Opções de listagem
   * @returns Promise com lista de arquivos
   */
  listFiles(
    directory: string,
    options?: {
      recursive?: boolean;
      filter?: string;
      maxResults?: number;
    }
  ): Promise<Array<{
    name: string;
    path: string;
    size: number;
    lastModified: Date;
    isDirectory: boolean;
  }>>;

  /**
   * Gera URL assinada para acesso temporário
   * 
   * @param path - Caminho do arquivo
   * @param expiresIn - Tempo de expiração em segundos
   * @returns Promise com URL assinada
   */
  getSignedUrl(path: string, expiresIn: number): Promise<string>;
}

/**
 * Interface para cache distribuído (Redis, etc.)
 */
export interface IDistributedCacheService extends ICacheService {
  /**
   * Nome da instância do cache
   */
  readonly instanceName: string;

  /**
   * Adiciona item ao cache com lock distribuído
   * 
   * @param key - Chave do item
   * @param value - Valor a ser armazenado
   * @param lockTimeout - Timeout do lock em ms
   * @param options - Opções de armazenamento
   */
  setWithLock<T>(key: string, value: T, lockTimeout: number, options?: StorageOptions): Promise<boolean>;

  /**
   * Remove lock de uma chave específica
   * 
   * @param key - Chave a ser desbloqueada
   * @returns Promise que resolve quando o lock for removido
   */
  releaseLock(key: string): Promise<boolean>;

  /**
   * Sincroniza cache com outras instâncias
   * 
   * @returns Promise que resolve quando a sincronização for completa
   */
  sync(): Promise<void>;

  /**
   * Invalida cache em todas as instâncias
   * 
   * @param pattern - Padrão de chaves a serem invalidadas
   * @returns Promise com número de itens invalidados
   */
  invalidateGlobal(pattern: string): Promise<number>;
} 