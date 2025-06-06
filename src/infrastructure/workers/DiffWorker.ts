import { DiffEngineFactory } from '../factories/DiffEngineFactory';
import { DiffEngineAdapter, RawDiffResult } from '../adapters/DiffEngineAdapter';
import { DocumentComparison } from '../../domain/entities/DocumentComparison';
import { DiffResult } from '../../domain/entities/DiffResult';

export interface DiffWorkerMessage {
  id: string;
  type: 'DIFF_REQUEST' | 'DIFF_RESPONSE' | 'DIFF_ERROR' | 'DIFF_PROGRESS';
  payload?: any;
}

export interface DiffRequest {
  comparisonId: string;
  originalText: string;
  modifiedText: string;
  algorithm?: 'diff-match-patch' | 'myers' | 'semantic';
  options?: {
    chunkSize?: number;
    enableCache?: boolean;
    timeout?: number;
  };
}

export interface DiffResponse {
  comparisonId: string;
  result: DiffResult;
  processingTime: number;
}

export interface DiffProgress {
  comparisonId: string;
  progress: number;
  currentStep: string;
}

export interface DiffError {
  comparisonId: string;
  error: string;
  code: string;
}

/**
 * Web Worker para processamento de diff em background
 */
export class DiffWorker {
  private worker: Worker | null = null;
  private isInitialized = false;
  private pendingRequests = new Map<string, {
    resolve: (value: DiffResponse) => void;
    reject: (error: DiffError) => void;
    onProgress?: (progress: DiffProgress) => void;
  }>();

  constructor() {
    this.initializeWorker();
  }

  /**
   * Inicializa o Web Worker
   */
  private initializeWorker(): void {
    try {
      // Verificar se Web Workers são suportados
      if (typeof Worker === 'undefined') {
        console.warn('Web Workers não são suportados neste ambiente');
        return;
      }

      // Criar worker inline para evitar problemas de caminho
      const workerScript = this.getWorkerScript();
      const blob = new Blob([workerScript], { type: 'application/javascript' });
      const workerUrl = URL.createObjectURL(blob);

      this.worker = new Worker(workerUrl);
      this.worker.onmessage = this.handleWorkerMessage.bind(this);
      this.worker.onerror = this.handleWorkerError.bind(this);

      this.isInitialized = true;
      
      // Cleanup URL object
      URL.revokeObjectURL(workerUrl);
    } catch (error) {
      console.error('Falha ao inicializar Web Worker:', error);
      this.isInitialized = false;
    }
  }

  /**
   * Gera o script do worker como string
   */
  private getWorkerScript(): string {
    return `
      // Web Worker script for diff processing
      let diffEngineFactory = null;
      let diffEngineAdapter = null;

      // Import scripts would go here in a real implementation
      // For now, we'll implement basic diff functionality

      class SimpleDiffEngine {
        compare(originalText, modifiedText, options = {}) {
          const startTime = performance.now();
          
          // Simple word-based diff implementation
          const originalWords = originalText.split(/\\s+/);
          const modifiedWords = modifiedText.split(/\\s+/);
          
          const chunks = [];
          let i = 0, j = 0;
          let lineNumber = 1;
          
          while (i < originalWords.length || j < modifiedWords.length) {
            if (i < originalWords.length && j < modifiedWords.length) {
              if (originalWords[i] === modifiedWords[j]) {
                chunks.push({
                  operation: 'equal',
                  text: originalWords[i] + ' ',
                  originalIndex: i,
                  modifiedIndex: j,
                  lineNumber: lineNumber++
                });
                i++;
                j++;
              } else {
                // Look ahead to find common words
                let found = false;
                for (let k = j + 1; k < Math.min(j + 5, modifiedWords.length); k++) {
                  if (originalWords[i] === modifiedWords[k]) {
                    // Insert words from j to k-1
                    for (let l = j; l < k; l++) {
                      chunks.push({
                        operation: 'insert',
                        text: modifiedWords[l] + ' ',
                        modifiedIndex: l,
                        lineNumber: lineNumber++
                      });
                    }
                    j = k;
                    found = true;
                    break;
                  }
                }
                
                if (!found) {
                  // Check if this word was deleted
                  let foundInOriginal = false;
                  for (let k = i + 1; k < Math.min(i + 5, originalWords.length); k++) {
                    if (modifiedWords[j] === originalWords[k]) {
                      // Delete words from i to k-1
                      for (let l = i; l < k; l++) {
                        chunks.push({
                          operation: 'delete',
                          text: originalWords[l] + ' ',
                          originalIndex: l,
                          lineNumber: lineNumber++
                        });
                      }
                      i = k;
                      foundInOriginal = true;
                      break;
                    }
                  }
                  
                  if (!foundInOriginal) {
                    // Treat as modification
                    chunks.push({
                      operation: 'modify',
                      text: modifiedWords[j] + ' ',
                      originalIndex: i,
                      modifiedIndex: j,
                      lineNumber: lineNumber++
                    });
                    i++;
                    j++;
                  }
                }
              }
            } else if (i < originalWords.length) {
              // Remaining original words are deleted
              chunks.push({
                operation: 'delete',
                text: originalWords[i] + ' ',
                originalIndex: i,
                lineNumber: lineNumber++
              });
              i++;
            } else {
              // Remaining modified words are inserted
              chunks.push({
                operation: 'insert',
                text: modifiedWords[j] + ' ',
                modifiedIndex: j,
                lineNumber: lineNumber++
              });
              j++;
            }
          }
          
          const processingTime = performance.now() - startTime;
          
          // Calculate statistics
          const statistics = this.calculateStatistics(chunks, processingTime);
          
          return {
            algorithm: 'simple-diff',
            chunks,
            statistics,
            processingTime,
            version: '1.0'
          };
        }
        
        calculateStatistics(chunks, processingTime) {
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
                linesAdded++;
                break;
              case 'delete':
                deletions++;
                charactersDeleted += chunk.text.length;
                linesDeleted++;
                break;
              case 'modify':
                modifications++;
                break;
            }
          }
          
          const totalChunks = chunks.length;
          const equalChunks = chunks.filter(c => c.operation === 'equal').length;
          const changedChunks = totalChunks - equalChunks;
          
          const jaccard = totalChunks > 0 ? equalChunks / totalChunks : 1;
          const levenshtein = totalChunks > 0 ? 1 - (changedChunks / totalChunks) : 1;
          const cosine = (jaccard + levenshtein) / 2;
          const overall = (jaccard + levenshtein + cosine) / 3;
          
          return {
            totalChanges: additions + deletions + modifications,
            additions,
            deletions,
            modifications,
            charactersAdded,
            charactersDeleted,
            linesAdded,
            linesDeleted,
            similarity: { jaccard, levenshtein, cosine, overall },
            processingTime
          };
        }
      }

      const diffEngine = new SimpleDiffEngine();

      self.onmessage = function(e) {
        const message = e.data;
        
        if (message.type === 'DIFF_REQUEST') {
          try {
            const { comparisonId, originalText, modifiedText, algorithm, options } = message.payload;
            
            // Send progress update
            self.postMessage({
              id: message.id,
              type: 'DIFF_PROGRESS',
              payload: {
                comparisonId,
                progress: 10,
                currentStep: 'Inicializando processamento...'
              }
            });
            
            // Process diff
            self.postMessage({
              id: message.id,
              type: 'DIFF_PROGRESS',
              payload: {
                comparisonId,
                progress: 50,
                currentStep: 'Comparando documentos...'
              }
            });
            
            const result = diffEngine.compare(originalText, modifiedText, options);
            
            self.postMessage({
              id: message.id,
              type: 'DIFF_PROGRESS',
              payload: {
                comparisonId,
                progress: 90,
                currentStep: 'Finalizando processamento...'
              }
            });
            
            // Send final result
            self.postMessage({
              id: message.id,
              type: 'DIFF_RESPONSE',
              payload: {
                comparisonId,
                result,
                processingTime: result.processingTime
              }
            });
            
          } catch (error) {
            self.postMessage({
              id: message.id,
              type: 'DIFF_ERROR',
              payload: {
                comparisonId: message.payload.comparisonId,
                error: error.message || 'Erro desconhecido',
                code: 'PROCESSING_ERROR'
              }
            });
          }
        }
      };
    `;
  }

  /**
   * Processa uma solicitação de diff
   */
  public async processDiff(
    request: DiffRequest,
    onProgress?: (progress: DiffProgress) => void
  ): Promise<DiffResponse> {
    if (!this.isInitialized || !this.worker) {
      throw new Error('Web Worker não está disponível');
    }

    const messageId = this.generateMessageId();

    return new Promise<DiffResponse>((resolve, reject) => {
      // Armazenar callbacks da promessa
      this.pendingRequests.set(messageId, {
        resolve,
        reject,
        onProgress
      });

      // Enviar solicitação para o worker
      const message: DiffWorkerMessage = {
        id: messageId,
        type: 'DIFF_REQUEST',
        payload: request
      };

      this.worker!.postMessage(message);

      // Configurar timeout
      const timeout = request.options?.timeout || 30000; // 30 segundos padrão
      setTimeout(() => {
        if (this.pendingRequests.has(messageId)) {
          this.pendingRequests.delete(messageId);
          reject({
            comparisonId: request.comparisonId,
            error: 'Timeout na operação de diff',
            code: 'TIMEOUT'
          });
        }
      }, timeout);
    });
  }

  /**
   * Manipula mensagens do worker
   */
  private handleWorkerMessage(event: MessageEvent<DiffWorkerMessage>): void {
    const message = event.data;
    const pendingRequest = this.pendingRequests.get(message.id);

    if (!pendingRequest) {
      return; // Mensagem para request que já expirou ou foi processado
    }

    switch (message.type) {
      case 'DIFF_RESPONSE':
        this.pendingRequests.delete(message.id);
        pendingRequest.resolve(message.payload as DiffResponse);
        break;

      case 'DIFF_ERROR':
        this.pendingRequests.delete(message.id);
        pendingRequest.reject(message.payload as DiffError);
        break;

      case 'DIFF_PROGRESS':
        if (pendingRequest.onProgress) {
          pendingRequest.onProgress(message.payload as DiffProgress);
        }
        break;
    }
  }

  /**
   * Manipula erros do worker
   */
  private handleWorkerError(error: ErrorEvent): void {
    console.error('Erro no Web Worker:', error);
    
    // Rejeitar todas as requisições pendentes
    for (const [messageId, request] of this.pendingRequests.entries()) {
      request.reject({
        comparisonId: 'unknown',
        error: 'Falha crítica no Web Worker',
        code: 'WORKER_ERROR'
      });
    }
    
    this.pendingRequests.clear();
    this.terminateWorker();
  }

  /**
   * Verifica se Web Workers são suportados
   */
  public isSupported(): boolean {
    return this.isInitialized && this.worker !== null;
  }

  /**
   * Obtém estatísticas do worker
   */
  public getWorkerStats(): {
    isActive: boolean;
    pendingRequests: number;
    supportsWorkers: boolean;
  } {
    return {
      isActive: this.isInitialized && this.worker !== null,
      pendingRequests: this.pendingRequests.size,
      supportsWorkers: typeof Worker !== 'undefined'
    };
  }

  /**
   * Cancela uma operação em andamento
   */
  public cancelDiff(comparisonId: string): boolean {
    for (const [messageId, request] of this.pendingRequests.entries()) {
      // Note: Não temos o comparisonId diretamente, mas poderíamos implementar
      // um mapeamento se necessário
      if (messageId.includes(comparisonId.substring(0, 8))) {
        this.pendingRequests.delete(messageId);
        request.reject({
          comparisonId,
          error: 'Operação cancelada pelo usuário',
          code: 'CANCELLED'
        });
        return true;
      }
    }
    return false;
  }

  /**
   * Finaliza o worker
   */
  public terminateWorker(): void {
    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
      this.isInitialized = false;
    }

    // Rejeitar requisições pendentes
    for (const [, request] of this.pendingRequests.entries()) {
      request.reject({
        comparisonId: 'unknown',
        error: 'Worker finalizado',
        code: 'TERMINATED'
      });
    }
    
    this.pendingRequests.clear();
  }

  /**
   * Gera ID único para mensagens
   */
  private generateMessageId(): string {
    return `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Reinicializa o worker se necessário
   */
  public reinitialize(): void {
    this.terminateWorker();
    this.initializeWorker();
  }
}

/**
 * Singleton instance do DiffWorker
 */
let diffWorkerInstance: DiffWorker | null = null;

export function getDiffWorker(): DiffWorker {
  if (!diffWorkerInstance) {
    diffWorkerInstance = new DiffWorker();
  }
  return diffWorkerInstance;
}

/**
 * Cleanup function para finalizar o worker quando necessário
 */
export function cleanupDiffWorker(): void {
  if (diffWorkerInstance) {
    diffWorkerInstance.terminateWorker();
    diffWorkerInstance = null;
  }
} 