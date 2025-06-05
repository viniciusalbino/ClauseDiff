/**
 * Hook simples para upload de arquivos
 * Gerencia estado e lógica de upload de forma reutilizável
 */

import { useState, useCallback } from 'react';

export interface UploadFile {
  file: File;
  id: string;
  status: 'pending' | 'uploading' | 'success' | 'error';
  progress: number;
  error?: string;
}

export interface UseFileUploadOptions {
  maxFiles?: number;
  maxSize?: number; // bytes
  allowedTypes?: string[];
  onUploadComplete?: (files: UploadFile[]) => void;
  onError?: (error: string) => void;
}

export function useFileUpload(options: UseFileUploadOptions = {}) {
  const {
    maxFiles = 5,
    maxSize = 50 * 1024 * 1024, // 50MB
    allowedTypes = ['application/pdf', 'text/plain', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
    onUploadComplete,
    onError
  } = options;

  const [files, setFiles] = useState<UploadFile[]>([]);
  const [isUploading, setIsUploading] = useState(false);

  // Adiciona arquivos à lista
  const addFiles = useCallback((newFiles: FileList | File[]) => {
    const fileArray = Array.from(newFiles);
    
    // Validações simples
    if (files.length + fileArray.length > maxFiles) {
      onError?.(`Máximo de ${maxFiles} arquivos permitidos`);
      return;
    }

    const validFiles: UploadFile[] = [];
    
    for (const file of fileArray) {
      // Verifica tamanho
      if (file.size > maxSize) {
        onError?.(`Arquivo ${file.name} excede tamanho máximo`);
        continue;
      }

      // Verifica tipo
      if (!allowedTypes.includes(file.type)) {
        onError?.(`Tipo de arquivo ${file.type} não permitido`);
        continue;
      }

      // Verifica duplicatas
      if (files.some(f => f.file.name === file.name && f.file.size === file.size)) {
        onError?.(`Arquivo ${file.name} já adicionado`);
        continue;
      }

      validFiles.push({
        file,
        id: `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        status: 'pending',
        progress: 0
      });
    }

    if (validFiles.length > 0) {
      setFiles(prev => [...prev, ...validFiles]);
    }
  }, [files, maxFiles, maxSize, allowedTypes, onError]);

  // Remove arquivo
  const removeFile = useCallback((id: string) => {
    setFiles(prev => prev.filter(f => f.id !== id));
  }, []);

  // Limpa todos os arquivos
  const clearFiles = useCallback(() => {
    setFiles([]);
  }, []);

  // Simula upload (mock implementation)
  const uploadFiles = useCallback(async () => {
    if (files.length === 0) return;

    setIsUploading(true);

    try {
      // Atualiza status para uploading
      setFiles(prev => prev.map(f => ({ ...f, status: 'uploading' as const })));

      // Simula upload progressivo
      for (const uploadFile of files) {
        await new Promise<void>((resolve) => {
          let progress = 0;
          const interval = setInterval(() => {
            progress += Math.random() * 30;
            
            setFiles(prev => prev.map(f => 
              f.id === uploadFile.id 
                ? { ...f, progress: Math.min(progress, 100) }
                : f
            ));

            if (progress >= 100) {
              clearInterval(interval);
              setFiles(prev => prev.map(f => 
                f.id === uploadFile.id 
                  ? { ...f, status: 'success', progress: 100 }
                  : f
              ));
              resolve();
            }
          }, 100);
        });
      }

      onUploadComplete?.(files);
      
    } catch (error) {
      setFiles(prev => prev.map(f => ({ 
        ...f, 
        status: 'error',
        error: 'Falha no upload'
      })));
      onError?.('Erro durante o upload');
    } finally {
      setIsUploading(false);
    }
  }, [files, onUploadComplete, onError]);

  // Estatísticas
  const stats = {
    total: files.length,
    pending: files.filter(f => f.status === 'pending').length,
    uploading: files.filter(f => f.status === 'uploading').length,
    success: files.filter(f => f.status === 'success').length,
    error: files.filter(f => f.status === 'error').length,
    canUpload: files.length > 0 && !isUploading
  };

  return {
    files,
    isUploading,
    stats,
    addFiles,
    removeFile,
    clearFiles,
    uploadFiles
  };
} 