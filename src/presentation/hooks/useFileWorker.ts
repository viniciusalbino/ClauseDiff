/**
 * Hook simples para usar Web Worker de processamento
 * Abstrai complexidade do worker e fornece interface React
 */

import { useState, useCallback, useRef, useEffect } from 'react';
import { WorkerMessage, WorkerResponse } from '../../workers/FileProcessingWorker';

export interface ProcessingJob {
  id: string;
  file: File;
  status: 'pending' | 'processing' | 'complete' | 'error';
  progress: number;
  result?: any;
  error?: string;
}

export function useFileWorker() {
  const [jobs, setJobs] = useState<ProcessingJob[]>([]);
  const [isWorkerReady, setIsWorkerReady] = useState(false);
  const workerRef = useRef<Worker | null>(null);

  // Inicializa worker
  useEffect(() => {
    try {
      // Cria worker a partir do arquivo
      workerRef.current = new Worker(
        new URL('../../workers/FileProcessingWorker.ts', import.meta.url),
        { type: 'module' }
      );

      workerRef.current.onmessage = (event: MessageEvent<WorkerResponse>) => {
        const { id, type, data, error, progress } = event.data;

        setJobs(prev => prev.map(job => {
          if (job.id !== id) return job;

          switch (type) {
            case 'progress':
              return { ...job, progress: progress || 0 };
            
            case 'complete':
              return { 
                ...job, 
                status: 'complete', 
                progress: 100, 
                result: data 
              };
            
            case 'error':
              return { 
                ...job, 
                status: 'error', 
                error: error || 'Processing failed' 
              };
            
            default:
              return job;
          }
        }));
      };

      workerRef.current.onerror = (error) => {
        console.error('Worker error:', error);
        setIsWorkerReady(false);
      };

      setIsWorkerReady(true);

    } catch (error) {
      console.error('Failed to create worker:', error);
      setIsWorkerReady(false);
    }

    return () => {
      workerRef.current?.terminate();
    };
  }, []);

  // Processa arquivo
  const processFile = useCallback((file: File): string => {
    if (!workerRef.current || !isWorkerReady) {
      throw new Error('Worker not ready');
    }

    const id = `job_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    // Adiciona job à lista
    setJobs(prev => [...prev, {
      id,
      file,
      status: 'pending',
      progress: 0
    }]);

    // Envia para worker
    const message: WorkerMessage = {
      id,
      type: 'process',
      file
    };

    workerRef.current.postMessage(message);

    // Atualiza status
    setJobs(prev => prev.map(job => 
      job.id === id ? { ...job, status: 'processing' } : job
    ));

    return id;
  }, [isWorkerReady]);

  // Cancela processamento
  const cancelJob = useCallback((id: string) => {
    if (!workerRef.current) return;

    const message: WorkerMessage = {
      id,
      type: 'cancel'
    };

    workerRef.current.postMessage(message);

    setJobs(prev => prev.map(job => 
      job.id === id ? { ...job, status: 'error', error: 'Cancelled' } : job
    ));
  }, []);

  // Remove job da lista
  const removeJob = useCallback((id: string) => {
    setJobs(prev => prev.filter(job => job.id !== id));
  }, []);

  // Limpa todos os jobs
  const clearJobs = useCallback(() => {
    setJobs([]);
  }, []);

  // Estatísticas simples
  const stats = {
    total: jobs.length,
    pending: jobs.filter(j => j.status === 'pending').length,
    processing: jobs.filter(j => j.status === 'processing').length,
    complete: jobs.filter(j => j.status === 'complete').length,
    error: jobs.filter(j => j.status === 'error').length,
    isWorking: jobs.some(j => j.status === 'processing')
  };

  return {
    jobs,
    stats,
    isWorkerReady,
    processFile,
    cancelJob,
    removeJob,
    clearJobs
  };
} 