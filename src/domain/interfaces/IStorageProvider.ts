/**
 * Interface para abstração de storage seguindo princípios SOLID
 * Permite implementação de diferentes providers (Local, Supabase, AWS S3, etc.)
 * 
 * @interface IStorageProvider
 * @author ClauseDiff Team
 * @version 1.0.0
 */

/**
 * Tipos de provider de storage suportados
 */
export type StorageProviderType = 'local' | 'supabase' | 'aws-s3' | 'google-cloud' | 'azure-blob';

/**
 * Status de upload de arquivo
 */
export type UploadStatus = 'pending' | 'uploading' | 'paused' | 'completed' | 'failed' | 'cancelled';

/**
 * Configurações de upload
 */
export interface UploadOptions {
  /** Upload em chunks para arquivos grandes */
  useChunkedUpload?: boolean;
  /** Tamanho do chunk em bytes (padrão: 5MB) */
  chunkSize?: number;
  /** Número máximo de tentativas de retry */
  maxRetries?: number;
  /** Timeout por chunk em milissegundos */
  timeoutMs?: number;
  /** Habilitar criptografia client-side */
  enableEncryption?: boolean;
  /** Sobrescrever arquivo existente */
  overwrite?: boolean;
  /** Metadados customizados para anexar ao arquivo */
  metadata?: Record<string, string>;
  /** Callback para progresso de upload */
  onProgress?: (progress: UploadProgress) => void;
  /** Callback para retry de chunk */
  onRetry?: (chunkIndex: number, attempt: number) => void;
}

/**
 * Informações de progresso de upload
 */
export interface UploadProgress {
  /** Bytes enviados até agora */
  loaded: number;
  /** Total de bytes a enviar */
  total: number;
  /** Percentual concluído (0-100) */
  percentage: number;
  /** Velocidade atual em bytes/segundo */
  speed: number;
  /** Tempo estimado restante em milissegundos */
  estimatedTimeRemaining?: number;
  /** Chunk atual sendo enviado */
  currentChunk?: number;
  /** Total de chunks */
  totalChunks?: number;
}

/**
 * Resultado de upload
 */
export interface UploadResult {
  /** ID único do arquivo no storage */
  fileId: string;
  /** URL pública para acesso ao arquivo */
  publicUrl?: string;
  /** URL temporária com assinatura para acesso */
  signedUrl?: string;
  /** Hash MD5 para verificação de integridade */
  etag: string;
  /** Tamanho final do arquivo */
  size: number;
  /** Timestamp do upload */
  uploadedAt: number;
  /** Metadados do arquivo no storage */
  metadata: Record<string, string>;
  /** Provider utilizado para o upload */
  provider: StorageProviderType;
}

/**
 * Configurações de download
 */
export interface DownloadOptions {
  /** Usar cache local se disponível */
  useCache?: boolean;
  /** Timeout para download em milissegundos */
  timeoutMs?: number;
  /** Range de bytes para download parcial */
  range?: {
    start: number;
    end: number;
  };
  /** Callback para progresso de download */
  onProgress?: (progress: DownloadProgress) => void;
}

/**
 * Informações de progresso de download
 */
export interface DownloadProgress {
  /** Bytes baixados até agora */
  loaded: number;
  /** Total de bytes a baixar */
  total: number;
  /** Percentual concluído (0-100) */
  percentage: number;
  /** Velocidade atual em bytes/segundo */
  speed: number;
}

/**
 * Informações sobre um arquivo no storage
 */
export interface StorageFileInfo {
  /** ID único do arquivo */
  fileId: string;
  /** Nome original do arquivo */
  name: string;
  /** Tamanho em bytes */
  size: number;
  /** Tipo MIME */
  contentType: string;
  /** Hash MD5 para integridade */
  etag: string;
  /** Data de criação */
  createdAt: number;
  /** Data da última modificação */
  lastModified: number;
  /** Metadados customizados */
  metadata: Record<string, string>;
  /** URL pública se disponível */
  publicUrl?: string;
}

/**
 * Configurações do provider de storage
 */
export interface StorageProviderConfig {
  /** Tipo do provider */
  type: StorageProviderType;
  /** Bucket/container para armazenamento */
  bucket: string;
  /** Região do storage */
  region?: string;
  /** Credenciais de acesso */
  credentials?: {
    accessKey?: string;
    secretKey?: string;
    token?: string;
  };
  /** Configurações específicas do provider */
  options?: Record<string, any>;
  /** Limite de tamanho por arquivo */
  maxFileSize?: number;
  /** Prefixo para organização de arquivos */
  pathPrefix?: string;
}

/**
 * Capacidades do provider de storage
 */
export interface StorageCapabilities {
  /** Suporta upload em chunks */
  supportsChunkedUpload: boolean;
  /** Suporta retry automático */
  supportsRetry: boolean;
  /** Suporta criptografia client-side */
  supportsEncryption: boolean;
  /** Suporta URLs assinadas */
  supportsSignedUrls: boolean;
  /** Suporta URLs públicas */
  supportsPublicUrls: boolean;
  /** Suporta metadados customizados */
  supportsMetadata: boolean;
  /** Suporta versionamento de arquivos */
  supportsVersioning: boolean;
  /** Tamanho máximo por arquivo */
  maxFileSize: number;
  /** Tamanho máximo por chunk */
  maxChunkSize: number;
  /** Número máximo de chunks concorrentes */
  maxConcurrentChunks: number;
}

/**
 * Interface principal para providers de storage
 * Implementa o princípio da Inversão de Dependência (DIP) do SOLID
 */
export interface IStorageProvider {
  /**
   * Identifica o tipo do provider
   */
  readonly type: StorageProviderType;

  /**
   * Inicializa o provider com configurações
   * 
   * @param config - Configurações do provider
   * @returns Promise<void>
   * @throws StorageError em caso de falha na inicialização
   */
  initialize(config: StorageProviderConfig): Promise<void>;

  /**
   * Faz upload de um arquivo para o storage
   * 
   * @param file - Arquivo a ser enviado
   * @param path - Caminho de destino no storage
   * @param options - Opções de upload
   * @returns Promise com resultado do upload
   * @throws StorageError em caso de falha
   */
  upload(file: File | Buffer, path: string, options?: UploadOptions): Promise<UploadResult>;

  /**
   * Faz download de um arquivo do storage
   * 
   * @param fileId - ID do arquivo no storage
   * @param options - Opções de download
   * @returns Promise com o arquivo como Buffer
   * @throws StorageError em caso de falha
   */
  download(fileId: string, options?: DownloadOptions): Promise<Buffer>;

  /**
   * Obtém informações sobre um arquivo sem baixá-lo
   * 
   * @param fileId - ID do arquivo no storage
   * @returns Promise com informações do arquivo
   * @throws StorageError se arquivo não existir
   */
  getFileInfo(fileId: string): Promise<StorageFileInfo>;

  /**
   * Verifica se um arquivo existe no storage
   * 
   * @param fileId - ID do arquivo
   * @returns Promise<boolean> indicando se o arquivo existe
   */
  exists(fileId: string): Promise<boolean>;

  /**
   * Remove um arquivo do storage
   * 
   * @param fileId - ID do arquivo a ser removido
   * @returns Promise<boolean> indicando sucesso da operação
   * @throws StorageError em caso de falha
   */
  delete(fileId: string): Promise<boolean>;

  /**
   * Lista arquivos no storage com filtros opcionais
   * 
   * @param prefix - Prefixo para filtrar arquivos
   * @param limit - Limite de resultados
   * @param offset - Offset para paginação
   * @returns Promise com lista de arquivos
   */
  listFiles(prefix?: string, limit?: number, offset?: number): Promise<StorageFileInfo[]>;

  /**
   * Gera URL assinada para acesso temporário
   * 
   * @param fileId - ID do arquivo
   * @param expiresIn - Tempo de expiração em segundos
   * @param action - Ação permitida ('read' | 'write')
   * @returns Promise com URL assinada
   * @throws StorageError se não suportado
   */
  getSignedUrl(fileId: string, expiresIn: number, action?: 'read' | 'write'): Promise<string>;

  /**
   * Gera URL pública para acesso direto
   * 
   * @param fileId - ID do arquivo
   * @returns Promise com URL pública ou null se não suportado
   */
  getPublicUrl(fileId: string): Promise<string | null>;

  /**
   * Cancela um upload em andamento
   * 
   * @param uploadId - ID único do upload
   * @returns Promise<boolean> indicando se foi cancelado
   */
  cancelUpload?(uploadId: string): Promise<boolean>;

  /**
   * Pausa um upload em andamento
   * 
   * @param uploadId - ID único do upload
   * @returns Promise<boolean> indicando se foi pausado
   */
  pauseUpload?(uploadId: string): Promise<boolean>;

  /**
   * Resume um upload pausado
   * 
   * @param uploadId - ID único do upload
   * @returns Promise<boolean> indicando se foi resumido
   */
  resumeUpload?(uploadId: string): Promise<boolean>;

  /**
   * Obtém as capacidades do provider
   * 
   * @returns Objeto com capacidades suportadas
   */
  getCapabilities(): StorageCapabilities;

  /**
   * Limpa cache e recursos temporários
   * 
   * @returns Promise<void>
   */
  cleanup(): Promise<void>;

  /**
   * Testa conectividade com o storage
   * 
   * @returns Promise<boolean> indicando se o storage está acessível
   */
  healthCheck(): Promise<boolean>;
}

/**
 * Erro customizado para operações de storage
 */
export class StorageError extends Error {
  constructor(
    message: string,
    public readonly code: StorageErrorCode,
    public readonly provider: StorageProviderType,
    public readonly originalError?: Error
  ) {
    super(message);
    this.name = 'StorageError';
  }
}

/**
 * Códigos de erro padronizados para storage
 */
export const StorageErrorCodes = {
  INITIALIZATION_FAILED: 'INITIALIZATION_FAILED',
  UPLOAD_FAILED: 'UPLOAD_FAILED',
  DOWNLOAD_FAILED: 'DOWNLOAD_FAILED',
  FILE_NOT_FOUND: 'FILE_NOT_FOUND',
  FILE_TOO_LARGE: 'FILE_TOO_LARGE',
  INSUFFICIENT_PERMISSIONS: 'INSUFFICIENT_PERMISSIONS',
  QUOTA_EXCEEDED: 'QUOTA_EXCEEDED',
  CONNECTION_TIMEOUT: 'CONNECTION_TIMEOUT',
  INVALID_CONFIGURATION: 'INVALID_CONFIGURATION',
  UNSUPPORTED_OPERATION: 'UNSUPPORTED_OPERATION',
  CHUNK_UPLOAD_FAILED: 'CHUNK_UPLOAD_FAILED',
  RETRY_LIMIT_EXCEEDED: 'RETRY_LIMIT_EXCEEDED',
  CANCELLED_BY_USER: 'CANCELLED_BY_USER'
} as const;

export type StorageErrorCode = typeof StorageErrorCodes[keyof typeof StorageErrorCodes];

/**
 * Configurações de retry com exponential backoff
 */
export interface RetryConfig {
  /** Número máximo de tentativas */
  maxRetries: number;
  /** Delay inicial em milissegundos */
  initialDelay: number;
  /** Multiplicador para exponential backoff */
  backoffMultiplier: number;
  /** Delay máximo entre tentativas */
  maxDelay: number;
  /** Jitter para evitar thundering herd */
  jitter: boolean;
} 