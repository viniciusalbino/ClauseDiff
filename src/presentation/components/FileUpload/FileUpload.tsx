/**
 * Componente simples de upload com drag and drop
 * Usa react-dropzone e react-hook-form para funcionalidade completa
 */

import React, { useState } from 'react';
import { useDropzone } from 'react-dropzone';
import { useForm } from 'react-hook-form';
import { useFileUpload, UploadFile } from '../../hooks/useFileUpload';
import { FilePreview } from './FilePreview';

export interface FileUploadProps {
  maxFiles?: number;
  maxSize?: number;
  allowedTypes?: string[];
  onUploadComplete?: (files: UploadFile[]) => void;
  onError?: (error: string) => void;
}

export function FileUpload(props: FileUploadProps) {
  const { handleSubmit } = useForm();
  const [previewFile, setPreviewFile] = useState<File | null>(null);
  
  const {
    files,
    isUploading,
    stats,
    addFiles,
    removeFile,
    clearFiles,
    uploadFiles
  } = useFileUpload(props);

  // Configuração do dropzone
  const {
    getRootProps,
    getInputProps,
    isDragActive,
    isDragReject
  } = useDropzone({
    onDrop: addFiles,
    maxFiles: props.maxFiles,
    maxSize: props.maxSize,
    accept: props.allowedTypes ? {
      'application/pdf': ['.pdf'],
      'text/plain': ['.txt'],
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx']
    } : undefined,
    disabled: isUploading
  });

  // Renderiza item de arquivo
  const renderFileItem = (uploadFile: UploadFile) => (
    <div key={uploadFile.id} className="file-item">
      <div className="file-info">
        <span 
          className="file-name clickable"
          onClick={() => setPreviewFile(uploadFile.file)}
          title="Clique para visualizar"
        >
          {uploadFile.file.name}
        </span>
        <span className="file-size">
          {(uploadFile.file.size / 1024 / 1024).toFixed(2)} MB
        </span>
      </div>
      
      {/* Progress bar simples */}
      {uploadFile.status === 'uploading' && (
        <div className="progress-bar">
          <div 
            className="progress-fill"
            style={{ width: `${uploadFile.progress}%` }}
          />
          <span className="progress-text">{uploadFile.progress.toFixed(0)}%</span>
        </div>
      )}
      
      {/* Status */}
      <div className={`file-status ${uploadFile.status}`}>
        {uploadFile.status === 'pending' && '⏳'}
        {uploadFile.status === 'uploading' && '📤'}
        {uploadFile.status === 'success' && '✅'}
        {uploadFile.status === 'error' && '❌'}
      </div>
      
      {/* Botões */}
      {uploadFile.status !== 'uploading' && (
        <div className="file-actions">
          <button 
            type="button"
            onClick={() => setPreviewFile(uploadFile.file)}
            className="preview-btn"
            title="Visualizar arquivo"
          >
            👁️
          </button>
          <button 
            type="button"
            onClick={() => removeFile(uploadFile.id)}
            className="remove-btn"
            title="Remover arquivo"
          >
            ✕
          </button>
        </div>
      )}
    </div>
  );

  return (
    <div className="file-upload">
      {/* Área de drop */}
      <div 
        {...getRootProps()} 
        className={`dropzone ${isDragActive ? 'active' : ''} ${isDragReject ? 'reject' : ''}`}
      >
        <input {...getInputProps()} />
        
        {isDragActive ? (
          isDragReject ? (
            <p>❌ Tipo de arquivo não permitido</p>
          ) : (
            <p>📁 Solte os arquivos aqui...</p>
          )
        ) : (
          <div className="dropzone-content">
            <p>📁 Arraste arquivos aqui ou clique para selecionar</p>
            <p className="dropzone-info">
              Máximo {props.maxFiles || 5} arquivos • 
              Tamanho máximo {Math.round((props.maxSize || 50 * 1024 * 1024) / 1024 / 1024)}MB
            </p>
          </div>
        )}
      </div>

      {/* Lista de arquivos */}
      {files.length > 0 && (
        <div className="file-list">
          <div className="file-list-header">
            <h3>Arquivos ({stats.total})</h3>
            <button 
              type="button" 
              onClick={clearFiles}
              className="clear-btn"
              disabled={isUploading}
            >
              Limpar todos
            </button>
          </div>
          
          {files.map(renderFileItem)}
        </div>
      )}

      {/* Estatísticas simples */}
      {files.length > 0 && (
        <div className="upload-stats">
          <span>✅ {stats.success}</span>
          <span>⏳ {stats.pending}</span>
          <span>📤 {stats.uploading}</span>
          {stats.error > 0 && <span>❌ {stats.error}</span>}
        </div>
      )}

      {/* Botão de upload */}
      {stats.canUpload && (
        <form onSubmit={handleSubmit(uploadFiles)}>
          <button 
            type="submit" 
            className="upload-btn"
            disabled={isUploading}
          >
            {isUploading ? 'Enviando...' : `Enviar ${stats.total} arquivo(s)`}
          </button>
        </form>
      )}

      {/* Modal de preview */}
      {previewFile && (
        <FilePreview 
          file={previewFile} 
          onClose={() => setPreviewFile(null)} 
        />
      )}

      <style jsx>{`
        .file-upload {
          max-width: 600px;
          margin: 0 auto;
        }

        .dropzone {
          border: 2px dashed #ccc;
          border-radius: 8px;
          padding: 40px;
          text-align: center;
          cursor: pointer;
          transition: all 0.2s;
        }

        .dropzone:hover {
          border-color: #007bff;
          background-color: #f8f9fa;
        }

        .dropzone.active {
          border-color: #007bff;
          background-color: #e3f2fd;
        }

        .dropzone.reject {
          border-color: #dc3545;
          background-color: #f8d7da;
        }

        .dropzone-info {
          font-size: 0.9em;
          color: #666;
          margin-top: 8px;
        }

        .file-list {
          margin-top: 20px;
        }

        .file-list-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 10px;
        }

        .file-item {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 12px;
          border: 1px solid #e9ecef;
          border-radius: 6px;
          margin-bottom: 8px;
          background: white;
        }

        .file-info {
          flex: 1;
          min-width: 0;
        }

        .file-name {
          display: block;
          font-weight: 500;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }

        .file-name.clickable {
          cursor: pointer;
          color: #007bff;
        }

        .file-name.clickable:hover {
          text-decoration: underline;
        }

        .file-size {
          display: block;
          font-size: 0.9em;
          color: #666;
        }

        .progress-bar {
          flex: 0 0 120px;
          height: 20px;
          background: #e9ecef;
          border-radius: 4px;
          overflow: hidden;
          position: relative;
          display: flex;
          align-items: center;
          justify-content: center;
        }

        .progress-fill {
          position: absolute;
          left: 0;
          top: 0;
          height: 100%;
          background: #007bff;
          transition: width 0.3s;
          border-radius: 4px;
        }

        .progress-text {
          position: relative;
          z-index: 1;
          font-size: 0.8em;
          font-weight: 500;
          color: #333;
        }

        .file-status {
          flex: 0 0 auto;
          font-size: 1.2em;
        }

        .file-actions {
          display: flex;
          gap: 8px;
          flex: 0 0 auto;
        }

        .preview-btn, .remove-btn {
          background: none;
          border: none;
          font-size: 1.2em;
          cursor: pointer;
          padding: 4px;
          border-radius: 4px;
          transition: background-color 0.2s;
        }

        .preview-btn {
          color: #007bff;
        }

        .preview-btn:hover {
          background: #e3f2fd;
        }

        .remove-btn {
          color: #dc3545;
        }

        .remove-btn:hover {
          background: #f8d7da;
        }

        .upload-stats {
          display: flex;
          gap: 16px;
          margin: 16px 0;
          font-size: 0.9em;
        }

        .upload-btn {
          width: 100%;
          padding: 12px;
          background: #007bff;
          color: white;
          border: none;
          border-radius: 6px;
          font-size: 1.1em;
          cursor: pointer;
          margin-top: 16px;
        }

        .upload-btn:hover {
          background: #0056b3;
        }

        .upload-btn:disabled {
          background: #6c757d;
          cursor: not-allowed;
        }

        .clear-btn {
          background: #6c757d;
          color: white;
          border: none;
          padding: 6px 12px;
          border-radius: 4px;
          font-size: 0.9em;
          cursor: pointer;
        }

        .clear-btn:hover {
          background: #5a6268;
        }
      `}</style>
    </div>
  );
} 