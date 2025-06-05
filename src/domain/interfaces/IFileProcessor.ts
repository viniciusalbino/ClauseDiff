/**
 * Interface principal para processadores de arquivo seguindo princípio SOLID
 * Define o contrato que todos os processadores de arquivo devem implementar
 * 
 * @interface IFileProcessor
 * @author ClauseDiff Team
 * @version 1.0.0
 */

/**
 * Tipos de arquivo suportados pelo sistema
 */
export type SupportedFileType = 'application/pdf' | 'text/plain' | 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';

/**
 * Status do processamento de arquivo
 */
export type ProcessingStatus = 'pending' | 'processing' | 'completed' | 'failed' | 'cancelled';

/**
 * Metadados do arquivo sendo processado
 */
export interface FileMetadata {
  /** Nome do arquivo original */
  name: string;
  /** Tamanho do arquivo em bytes */
  size: number;
  /** Tipo MIME do arquivo */
  type: SupportedFileType;
  /** Data da última modificação */
  lastModified: number;
  /** Hash MD5 do arquivo para verificação de integridade */
  hash?: string;
  /** Encoding do arquivo (para arquivos de texto) */
  encoding?: string;
}

/**
 * Configurações para processamento de arquivo
 */
export interface ProcessingOptions {
  /** Extrair apenas texto sem formatação */
  extractTextOnly?: boolean;
  /** Preservar formatação original */
  preserveFormatting?: boolean;
  /** Limite máximo de caracteres a extrair */
  maxCharacters?: number;
  /** Timeout em milissegundos para processamento */
  timeoutMs?: number;
  /** Validar integridade do arquivo antes do processamento */
  validateIntegrity?: boolean;
}

/**
 * Resultado do processamento de arquivo
 */
export interface ProcessingResult {
  /** Status do processamento */
  status: ProcessingStatus;
  /** Conteúdo extraído do arquivo */
  content: string;
  /** Metadados do arquivo processado */
  metadata: FileMetadata;
  /** Timestamp do início do processamento */
  startTime: number;
  /** Timestamp do fim do processamento */
  endTime: number;
  /** Duração do processamento em milissegundos */
  duration: number;
  /** Número de páginas/seções processadas */
  pagesProcessed?: number;
  /** Mensagem de erro em caso de falha */
  error?: string;
  /** Stack trace detalhado para debugging */
  stackTrace?: string;
  /** Warnings gerados durante o processamento */
  warnings?: string[];
}

/**
 * Interface principal para processadores de arquivo
 * Implementa o princípio da Responsabilidade Única (SRP) do SOLID
 * 
 * @interface IFileProcessor
 */
export interface IFileProcessor {
  /**
   * Identifica se o processador pode processar o tipo de arquivo especificado
   * Implementa o princípio da Substituição de Liskov (LSP)
   * 
   * @param fileType - Tipo MIME do arquivo
   * @returns true se o processador suporta o tipo de arquivo
   */
  canProcess(fileType: string): boolean;

  /**
   * Processa um arquivo e extrai seu conteúdo
   * Método principal que implementa a lógica de processamento
   * 
   * @param file - Arquivo a ser processado
   * @param options - Opções de processamento (opcional)
   * @returns Promise com o resultado do processamento
   * @throws ProcessingError em caso de falha no processamento
   */
  process(file: File, options?: ProcessingOptions): Promise<ProcessingResult>;

  /**
   * Valida se o arquivo atende aos critérios mínimos para processamento
   * Verifica tamanho, tipo, integridade, etc.
   * 
   * @param file - Arquivo a ser validado
   * @returns Promise<boolean> indicando se o arquivo é válido
   */
  validate(file: File): Promise<boolean>;

  /**
   * Obtém informações sobre as capacidades do processador
   * Útil para interfaces que precisam mostrar limitações
   * 
   * @returns Objeto com capacidades e limitações do processador
   */
  getCapabilities(): ProcessorCapabilities;

  /**
   * Cancela um processamento em andamento
   * Implementa graceful shutdown do processamento
   * 
   * @param processId - ID único do processamento a ser cancelado
   * @returns Promise<boolean> indicando se o cancelamento foi bem-sucedido
   */
  cancel?(processId: string): Promise<boolean>;
}

/**
 * Capacidades e limitações de um processador
 */
export interface ProcessorCapabilities {
  /** Tipos de arquivo suportados */
  supportedTypes: SupportedFileType[];
  /** Tamanho máximo de arquivo suportado em bytes */
  maxFileSize: number;
  /** Indica se suporta processamento de múltiplas páginas */
  supportsMultiplePages: boolean;
  /** Indica se suporta extração de formatação */
  supportsFormatting: boolean;
  /** Indica se suporta processamento em streaming */
  supportsStreaming: boolean;
  /** Indica se suporta cancelamento de processamento */
  supportsCancellation: boolean;
  /** Versão do processador */
  version: string;
}

/**
 * Erro customizado para falhas de processamento
 */
export class ProcessingError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly fileType?: string,
    public readonly originalError?: Error
  ) {
    super(message);
    this.name = 'ProcessingError';
  }
}

/**
 * Códigos de erro padronizados para processamento
 */
export const ProcessingErrorCodes = {
  UNSUPPORTED_FILE_TYPE: 'UNSUPPORTED_FILE_TYPE',
  FILE_TOO_LARGE: 'FILE_TOO_LARGE',
  FILE_CORRUPTED: 'FILE_CORRUPTED',
  PROCESSING_TIMEOUT: 'PROCESSING_TIMEOUT',
  INVALID_FILE_FORMAT: 'INVALID_FILE_FORMAT',
  EXTRACTION_FAILED: 'EXTRACTION_FAILED',
  VALIDATION_FAILED: 'VALIDATION_FAILED',
  CANCELLED_BY_USER: 'CANCELLED_BY_USER'
} as const;

export type ProcessingErrorCode = typeof ProcessingErrorCodes[keyof typeof ProcessingErrorCodes]; 