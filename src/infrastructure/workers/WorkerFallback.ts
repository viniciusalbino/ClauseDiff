import type { DiffWorkerMessage, DiffResponse, DiffRequest, DiffProgress, DiffError } from './DiffWorker';

/**
 * Fallback simples para browsers sem suporte a Web Workers
 * Executa as operações de diff na thread principal
 */
export class WorkerFallback {
  private isProcessing: boolean = false;

  /**
   * Simula processamento de diff sem Web Worker
   */
  public async processDiff(
    request: DiffRequest,
    onProgress?: (progress: DiffProgress) => void
  ): Promise<DiffResponse> {
    if (this.isProcessing) {
      throw new Error('Worker está ocupado processando outra tarefa');
    }

    this.isProcessing = true;

    try {
      const startTime = performance.now();
      
      // Reportar progresso inicial
      if (onProgress) {
        onProgress({
          comparisonId: request.comparisonId,
          progress: 0,
          currentStep: 'Iniciando comparação...'
        });
      }

      // Processar diff de forma simplificada
      const result = await this.performSimpleDiff(request, onProgress);
      
      const processingTime = performance.now() - startTime;

      return {
        comparisonId: request.comparisonId,
        result,
        processingTime
      };

    } finally {
      this.isProcessing = false;
    }
  }

  /**
   * Realiza diff simplificado
   */
  private async performSimpleDiff(
    request: DiffRequest,
    onProgress?: (progress: DiffProgress) => void
  ): Promise<any> {
    const { originalText, modifiedText } = request;
    
    // Quebrar em linhas para comparação
    const originalLines = originalText.split('\n');
    const modifiedLines = modifiedText.split('\n');
    
    const chunks = [];
    let similarity = 0;
    let totalChanges = 0;

    // Reportar progresso
    if (onProgress) {
      onProgress({
        comparisonId: request.comparisonId,
        progress: 25,
        currentStep: 'Processando linhas...'
      });
    }

    const maxLines = Math.max(originalLines.length, modifiedLines.length);
    
    for (let i = 0; i < maxLines; i++) {
      const originalLine = originalLines[i] || '';
      const modifiedLine = modifiedLines[i] || '';
      
      if (originalLine === modifiedLine) {
        similarity++;
        if (originalLine.trim()) {
          chunks.push({
            operation: 'equal',
            text: originalLine,
            lineNumber: i + 1
          });
        }
      } else {
        totalChanges++;
        
        if (originalLine && !modifiedLine) {
          chunks.push({
            operation: 'delete',
            text: originalLine,
            lineNumber: i + 1
          });
        } else if (!originalLine && modifiedLine) {
          chunks.push({
            operation: 'insert',
            text: modifiedLine,
            lineNumber: i + 1
          });
        } else {
          chunks.push({
            operation: 'modify',
            text: modifiedLine,
            oldText: originalLine,
            lineNumber: i + 1
          });
        }
      }

      // Permitir outras tarefas e reportar progresso
      if (i % 100 === 0) {
        await new Promise(resolve => setTimeout(resolve, 0));
        
        if (onProgress) {
          const progress = Math.min(25 + (i / maxLines) * 50, 75);
          onProgress({
            comparisonId: request.comparisonId,
            progress,
            currentStep: `Processando linha ${i}/${maxLines}...`
          });
        }
      }
    }

    // Finalizar
    if (onProgress) {
      onProgress({
        comparisonId: request.comparisonId,
        progress: 100,
        currentStep: 'Finalizando...'
      });
    }

    const similarityRatio = maxLines > 0 ? similarity / maxLines : 1;

    return {
      chunks,
      stats: {
        totalLines: maxLines,
        totalChanges,
        insertions: chunks.filter(c => c.operation === 'insert').length,
        deletions: chunks.filter(c => c.operation === 'delete').length,
        modifications: chunks.filter(c => c.operation === 'modify').length,
        similarity: similarityRatio,
        identical: similarityRatio === 1 && totalChanges === 0
      },
      algorithm: 'fallback-simple',
      metadata: {
        usedFallback: true,
        originalLength: originalText.length,
        modifiedLength: modifiedText.length
      }
    };
  }

  /**
   * Verifica se está processando
   */
  public isActive(): boolean {
    return this.isProcessing;
  }

  /**
   * Cancela processamento (não suportado no fallback)
   */
  public cancelDiff(comparisonId: string): boolean {
    // Fallback não suporta cancelamento
    return false;
  }

  /**
   * Obtém estatísticas do fallback
   */
  public getStats(): {
    isActive: boolean;
    supportsWorkers: boolean;
    isFallback: boolean;
  } {
    return {
      isActive: this.isProcessing,
      supportsWorkers: false,
      isFallback: true
    };
  }
}

/**
 * Detector de suporte a Web Workers
 */
export class WorkerSupport {
  /**
   * Verifica se o browser suporta Web Workers
   */
  public static isSupported(): boolean {
    return (
      typeof Worker !== 'undefined' &&
      typeof window !== 'undefined' &&
      'Worker' in window
    );
  }

  /**
   * Verifica se Shared Workers são suportados
   */
  public static isSharedWorkerSupported(): boolean {
    return (
      typeof SharedWorker !== 'undefined' &&
      typeof window !== 'undefined' &&
      'SharedWorker' in window
    );
  }

  /**
   * Obtém informações sobre capacidades do browser
   */
  public static getCapabilities(): {
    webWorkers: boolean;
    sharedWorkers: boolean;
    serviceWorkers: boolean;
    transferableObjects: boolean;
    memoryLimit: number;
  } {
    return {
      webWorkers: this.isSupported(),
      sharedWorkers: this.isSharedWorkerSupported(),
      serviceWorkers: 'serviceWorker' in navigator,
      transferableObjects: typeof ArrayBuffer !== 'undefined',
      memoryLimit: this.estimateMemoryLimit()
    };
  }

  /**
   * Estima limite de memória disponível
   */
  private static estimateMemoryLimit(): number {
    // @ts-ignore
    if ('memory' in performance && performance.memory) {
      // @ts-ignore
      return performance.memory.jsHeapSizeLimit || 0;
    }
    
    // Fallback: estimar baseado no user agent
    if (typeof navigator !== 'undefined') {
      const isMobile = /Mobile|Android|iPhone|iPad/.test(navigator.userAgent);
      return isMobile ? 256 * 1024 * 1024 : 1024 * 1024 * 1024; // 256MB mobile, 1GB desktop
    }
    
    return 512 * 1024 * 1024; // 512MB default
  }
} 