/**
 * Hook avançado para upload com sistema de storage
 * Integra com providers de storage e upload em chunks
 */

import { useState, useCallback } from 'react';
import { StorageFactory } from '../../infrastructure/storage/StorageFactory';
import { ChunkedUploadManager } from '../../infrastructure/storage/ChunkedUploadManager';
import { IStorageProvider, UploadProgress, UploadResult } from '../../domain/interfaces/IStorageProvider';

export interface AdvancedUploadFile {
  file: File;
  id: string;
  status: 'pending' | 'uploading' | 'success' | 'error';
  progress: number;
  error?: string;
  result?: UploadResult;
  isLargeFile: boolean;
}

export interface UseAdvancedFileUploadOptions {
  maxFiles?: number;
  maxSize?: number;
  allowedTypes?: string[];
  storageProvider?: 'local' | 'supabase';
  onUploadComplete?: (files: AdvancedUploadFile[]) => void;
  onError?: (error: string) => void;
}

export function useAdvancedFileUpload(options: UseAdvancedFileUploadOptions = {}) {
  const {
    maxFiles = 5,
    maxSize = 50 * 1024 * 1024, // 50MB
    allowedTypes = ['application/pdf', 'text/plain', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
    storageProvider = 'local',
    onUploadComplete,
    onError
  } = options;

  const [files, setFiles] = useState<AdvancedUploadFile[]>([]);
  const [isUploading, setIsUploading] = useState(false);
  const [provider, setProvider] = useState<IStorageProvider | null>(null);
  const [chunkManager] = useState(() => new ChunkedUploadManager());

  // Inicializa provider
  const initializeProvider = useCallback(async () => {
    if (!provider) {
      try {
        const newProvider = await StorageFactory.createProvider({
          provider: storageProvider,
          bucket: 'clausediff-uploads',
          maxFileSize: maxSize
        });
        setProvider(newProvider);
        return newProvider;
      } catch (error) {
        onError?.(`Erro ao inicializar storage: ${(error as Error).message}`);
        throw error;
      }
    }
    return provider;
  }, [provider, storageProvider, maxSize, onError]);

  // Adiciona arquivos
  const addFiles = useCallback((newFiles: FileList | File[]) => {
    const fileArray = Array.from(newFiles);
    
    if (files.length + fileArray.length > maxFiles) {
      onError?.(`Máximo de ${maxFiles} arquivos permitidos`);
      return;
    }

    const validFiles: AdvancedUploadFile[] = [];
    
    for (const file of fileArray) {
      if (file.size > maxSize) {
        onError?.(`Arquivo ${file.name} excede tamanho máximo`);
        continue;
      }

      if (!allowedTypes.includes(file.type)) {
        onError?.(`Tipo de arquivo ${file.type} não permitido`);
        continue;
      }

      if (files.some(f => f.file.name === file.name && f.file.size === file.size)) {
        onError?.(`Arquivo ${file.name} já adicionado`);
        continue;
      }

      const isLargeFile = file.size > 10 * 1024 * 1024; // > 10MB

      validFiles.push({
        file,
        id: `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        status: 'pending',
        progress: 0,
        isLargeFile
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

  // Upload individual
  const uploadSingleFile = useCallback(async (uploadFile: AdvancedUploadFile): Promise<void> => {
    try {
      const storageProvider = await initializeProvider();
      
      // Atualiza status para uploading
      setFiles(prev => prev.map(f => 
        f.id === uploadFile.id 
          ? { ...f, status: 'uploading', progress: 0 }
          : f
      ));

      const onProgress = (progress: UploadProgress) => {
        setFiles(prev => prev.map(f => 
          f.id === uploadFile.id 
            ? { ...f, progress: progress.percentage }
            : f
        ));
      };

      const result = await chunkManager.upload(
        storageProvider,
        uploadFile.file,
        'uploads',
        { onProgress }
      );

      setFiles(prev => prev.map(f => 
        f.id === uploadFile.id 
          ? { ...f, status: 'success', progress: 100, result }
          : f
      ));

    } catch (error) {
      setFiles(prev => prev.map(f => 
        f.id === uploadFile.id 
          ? { ...f, status: 'error', error: (error as Error).message }
          : f
      ));
    }
  }, [initializeProvider, chunkManager]);

  // Upload todos os arquivos
  const uploadFiles = useCallback(async () => {
    if (files.length === 0) return;

    setIsUploading(true);

    try {
      // Upload sequencial para evitar sobrecarga
      for (const file of files) {
        if (file.status === 'pending') {
          await uploadSingleFile(file);
        }
      }

      onUploadComplete?.(files);
      
    } finally {
      setIsUploading(false);
    }
  }, [files, uploadSingleFile, onUploadComplete]);

  // Limpa arquivos
  const clearFiles = useCallback(() => {
    setFiles([]);
  }, []);

  // Estatísticas
  const stats = {
    total: files.length,
    pending: files.filter(f => f.status === 'pending').length,
    uploading: files.filter(f => f.status === 'uploading').length,
    success: files.filter(f => f.status === 'success').length,
    error: files.filter(f => f.status === 'error').length,
    largeFiles: files.filter(f => f.isLargeFile).length,
    canUpload: files.length > 0 && !isUploading,
    totalSize: files.reduce((sum, f) => sum + f.file.size, 0)
  };

  return {
    files,
    isUploading,
    stats,
    provider,
    addFiles,
    removeFile,
    clearFiles,
    uploadFiles,
    uploadSingleFile
  };
} 