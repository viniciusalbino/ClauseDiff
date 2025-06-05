/**
 * Versão otimizada do FileUpload com memoização
 * Evita re-renders desnecessários e melhora performance
 */

import React, { memo, useMemo, useCallback } from 'react';
import { useFileUpload } from '../../hooks/useFileUpload';
import { useFileWorker } from '../../hooks/useFileWorker';

interface OptimizedFileUploadProps {
  maxFiles?: number;
  maxSize?: number;
  allowedTypes?: string[];
  onUploadComplete?: (files: any[]) => void;
  className?: string;
}

// Componente de arquivo individual otimizado
const FileItem = memo(({ 
  file, 
  progress, 
  status, 
  onRemove 
}: {
  file: File;
  progress: number;
  status: string;
  onRemove: () => void;
}) => {
  // Memoriza formatação de tamanho
  const formattedSize = useMemo(() => {
    const mb = file.size / (1024 * 1024);
    return mb > 1 ? `${mb.toFixed(1)}MB` : `${(file.size / 1024).toFixed(0)}KB`;
  }, [file.size]);

  // Memoriza status visual
  const statusIcon = useMemo(() => {
    switch (status) {
      case 'success': return '✅';
      case 'error': return '❌';
      case 'uploading': return '⏳';
      default: return '📄';
    }
  }, [status]);

  return (
    <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
      <div className="flex items-center gap-3">
        <span className="text-xl">{statusIcon}</span>
        <div>
          <p className="font-medium text-sm">{file.name}</p>
          <p className="text-gray-500 text-xs">{formattedSize}</p>
        </div>
      </div>
      
      <div className="flex items-center gap-3">
        {status === 'uploading' && (
          <div className="w-20 bg-gray-200 rounded-full h-2">
            <div 
              className="bg-blue-500 h-2 rounded-full transition-all"
              style={{ width: `${progress}%` }}
            />
          </div>
        )}
        
        <button 
          onClick={onRemove}
          className="text-red-500 hover:text-red-700 text-sm"
        >
          ×
        </button>
      </div>
    </div>
  );
});

FileItem.displayName = 'FileItem';

// Componente de estatísticas otimizado
const UploadStats = memo(({ stats }: { stats: any }) => {
  const formattedStats = useMemo(() => {
    const totalSizeMB = (stats.totalSize / (1024 * 1024)).toFixed(1);
    return {
      ...stats,
      totalSizeMB: parseFloat(totalSizeMB)
    };
  }, [stats]);

  return (
    <div className="bg-blue-50 p-3 rounded-lg">
      <div className="grid grid-cols-2 gap-2 text-sm">
        <span>Arquivos: {formattedStats.total}</span>
        <span>Enviados: {formattedStats.success}</span>
        <span>Falhas: {formattedStats.error}</span>
        <span>Tamanho: {formattedStats.totalSizeMB}MB</span>
      </div>
    </div>
  );
});

UploadStats.displayName = 'UploadStats';

// Componente principal otimizado
export const OptimizedFileUpload = memo(({
  maxFiles = 5,
  maxSize = 50 * 1024 * 1024,
  allowedTypes = ['application/pdf', 'text/plain'],
  onUploadComplete,
  className = ''
}: OptimizedFileUploadProps) => {
  
  const { 
    files, 
    isUploading, 
    stats, 
    addFiles, 
    removeFile, 
    uploadFiles, 
    clearFiles 
  } = useFileUpload({ 
    maxFiles, 
    maxSize, 
    allowedTypes,
    onUploadComplete 
  });

  const { 
    isWorkerReady, 
    processFile,
    stats: workerStats 
  } = useFileWorker();

  // Callback otimizado para arrastar arquivos
  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    const droppedFiles = Array.from(e.dataTransfer.files);
    addFiles(droppedFiles);
  }, [addFiles]);

  // Callback otimizado para selecionar arquivos
  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      addFiles(Array.from(e.target.files));
    }
  }, [addFiles]);

  // Upload otimizado
  const handleUpload = useCallback(async () => {
    if (!isWorkerReady) {
      await uploadFiles(); // Fallback sem worker
      return;
    }

    // Usa worker para processamento
    for (const file of files) {
      try {
        processFile(file.file);
      } catch (error) {
        console.error('Worker processing failed:', error);
      }
    }
  }, [files, isWorkerReady, uploadFiles, processFile]);

  // Memoriza lista de arquivos renderizada
  const fileList = useMemo(() => 
    files.map(uploadFile => (
      <FileItem
        key={uploadFile.id}
        file={uploadFile.file}
        progress={uploadFile.progress}
        status={uploadFile.status}
        onRemove={() => removeFile(uploadFile.id)}
      />
    )), 
    [files, removeFile]
  );

  // Memoriza controles
  const controls = useMemo(() => (
    <div className="flex gap-2">
      <button
        onClick={handleUpload}
        disabled={!stats.canUpload}
        className="px-4 py-2 bg-blue-500 text-white rounded disabled:opacity-50"
      >
        {isUploading ? 'Enviando...' : 'Enviar Arquivos'}
      </button>
      
      <button
        onClick={clearFiles}
        className="px-4 py-2 bg-gray-500 text-white rounded"
      >
        Limpar
      </button>
    </div>
  ), [handleUpload, stats.canUpload, isUploading, clearFiles]);

  return (
    <div className={`space-y-4 ${className}`}>
      {/* Área de Drop */}
      <div
        onDrop={handleDrop}
        onDragOver={(e) => e.preventDefault()}
        className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center hover:border-blue-400 transition-colors"
      >
        <input
          type="file"
          multiple
          accept={allowedTypes.join(',')}
          onChange={handleFileSelect}
          className="hidden"
          id="file-input"
        />
        <label htmlFor="file-input" className="cursor-pointer">
          <div className="space-y-2">
            <p className="text-lg">📎 Arraste arquivos ou clique para selecionar</p>
            <p className="text-sm text-gray-500">
              Máximo {maxFiles} arquivos, {(maxSize / (1024*1024)).toFixed(0)}MB cada
            </p>
            {isWorkerReady && (
              <p className="text-xs text-green-600">⚡ Worker ativo - processamento otimizado</p>
            )}
          </div>
        </label>
      </div>

      {/* Estatísticas */}
      {stats.total > 0 && <UploadStats stats={stats} />}

      {/* Lista de Arquivos */}
      {fileList.length > 0 && (
        <div className="space-y-2">
          {fileList}
        </div>
      )}

      {/* Controles */}
      {stats.total > 0 && controls}

      {/* Stats do Worker */}
      {workerStats.total > 0 && (
        <div className="text-xs text-gray-500">
          Worker: {workerStats.processing} processando, {workerStats.complete} completos
        </div>
      )}
    </div>
  );
});

OptimizedFileUpload.displayName = 'OptimizedFileUpload'; 