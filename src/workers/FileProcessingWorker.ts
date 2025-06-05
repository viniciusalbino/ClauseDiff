/**
 * Web Worker simples para processamento de arquivos
 * Evita bloquear a UI durante operações pesadas
 */

// Tipos para comunicação com o worker
export interface WorkerMessage {
  id: string;
  type: 'process' | 'cancel';
  file?: File;
  options?: any;
}

export interface WorkerResponse {
  id: string;
  type: 'progress' | 'complete' | 'error';
  data?: any;
  error?: string;
  progress?: number;
}

// Funções de processamento simples no worker
const processFile = async (file: File, id: string): Promise<void> => {
  try {
    // Simula processamento progressivo
    for (let progress = 0; progress <= 100; progress += 10) {
      // Simula delay de processamento
      await new Promise(resolve => setTimeout(resolve, 100));
      
      // Envia progresso
      self.postMessage({
        id,
        type: 'progress',
        progress
      } as WorkerResponse);
    }

    // Resultado final (simplificado)
    const result = {
      fileName: file.name,
      size: file.size,
      type: file.type,
      content: file.type.includes('text') ? await file.text() : '[Binary file]',
      processedAt: new Date().toISOString()
    };

    self.postMessage({
      id,
      type: 'complete',
      data: result
    } as WorkerResponse);

  } catch (error) {
    self.postMessage({
      id,
      type: 'error',
      error: (error as Error).message
    } as WorkerResponse);
  }
};

// Event listener principal do worker
self.addEventListener('message', async (event: MessageEvent<WorkerMessage>) => {
  const { id, type, file, options } = event.data;

  switch (type) {
    case 'process':
      if (file) {
        await processFile(file, id);
      }
      break;
    
    case 'cancel':
      // Implementação de cancelamento (simplificada)
      self.postMessage({
        id,
        type: 'error',
        error: 'Processing cancelled'
      } as WorkerResponse);
      break;
  }
});

// Export apenas para tipagem (não usado no worker)
export {} 