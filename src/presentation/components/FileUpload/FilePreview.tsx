/**
 * Componente simples para preview de arquivos
 * Mostra informações básicas e preview quando possível
 */

import React, { useState, useEffect } from 'react';

export interface FilePreviewProps {
  file: File;
  onClose: () => void;
}

export function FilePreview({ file, onClose }: FilePreviewProps) {
  const [preview, setPreview] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (file.type.startsWith('text/') || file.type === 'application/json') {
      // Preview para arquivos de texto
      const reader = new FileReader();
      reader.onload = (e) => {
        const text = e.target?.result as string;
        setPreview(text.substring(0, 2000)); // Primeiros 2000 caracteres
        setLoading(false);
      };
      reader.readAsText(file);
    } else {
      // Para outros tipos, apenas mostra info
      setPreview(null);
      setLoading(false);
    }
  }, [file]);

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const getFileIcon = (type: string) => {
    if (type.includes('pdf')) return '📄';
    if (type.includes('text')) return '📝';
    if (type.includes('word')) return '📃';
    if (type.includes('image')) return '🖼️';
    return '📁';
  };

  return (
    <div className="file-preview-overlay" onClick={onClose}>
      <div className="file-preview-modal" onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div className="preview-header">
          <div className="file-icon">{getFileIcon(file.type)}</div>
          <div className="file-details">
            <h3 className="file-name">{file.name}</h3>
            <div className="file-meta">
              <span>{file.type || 'Tipo desconhecido'}</span>
              <span>{formatFileSize(file.size)}</span>
              <span>{new Date(file.lastModified).toLocaleDateString()}</span>
            </div>
          </div>
          <button className="close-btn" onClick={onClose}>✕</button>
        </div>

        {/* Content */}
        <div className="preview-content">
          {loading ? (
            <div className="loading">Carregando preview...</div>
          ) : preview ? (
            <div className="text-preview">
              <pre>{preview}</pre>
              {preview.length >= 2000 && (
                <div className="truncated-notice">
                  ... (preview limitado aos primeiros 2000 caracteres)
                </div>
              )}
            </div>
          ) : (
            <div className="no-preview">
              <p>Preview não disponível para este tipo de arquivo.</p>
              <div className="file-info">
                <h4>Informações do arquivo:</h4>
                <ul>
                  <li><strong>Nome:</strong> {file.name}</li>
                  <li><strong>Tamanho:</strong> {formatFileSize(file.size)}</li>
                  <li><strong>Tipo:</strong> {file.type || 'Desconhecido'}</li>
                  <li><strong>Modificado:</strong> {new Date(file.lastModified).toLocaleString()}</li>
                </ul>
              </div>
            </div>
          )}
        </div>

        <style jsx>{`
          .file-preview-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.7);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1000;
          }

          .file-preview-modal {
            background: white;
            border-radius: 8px;
            max-width: 90vw;
            max-height: 90vh;
            width: 600px;
            height: 500px;
            display: flex;
            flex-direction: column;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
          }

          .preview-header {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 16px;
            border-bottom: 1px solid #e9ecef;
            flex-shrink: 0;
          }

          .file-icon {
            font-size: 2em;
            flex-shrink: 0;
          }

          .file-details {
            flex: 1;
            min-width: 0;
          }

          .file-name {
            margin: 0;
            font-size: 1.1em;
            font-weight: 600;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
          }

          .file-meta {
            display: flex;
            gap: 16px;
            font-size: 0.9em;
            color: #666;
            margin-top: 4px;
          }

          .close-btn {
            background: none;
            border: none;
            font-size: 1.5em;
            cursor: pointer;
            color: #666;
            padding: 4px;
            flex-shrink: 0;
          }

          .close-btn:hover {
            color: #000;
          }

          .preview-content {
            flex: 1;
            overflow: auto;
            padding: 16px;
          }

          .loading {
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100%;
            color: #666;
          }

          .text-preview {
            height: 100%;
          }

          .text-preview pre {
            background: #f8f9fa;
            padding: 16px;
            border-radius: 4px;
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.9em;
            line-height: 1.4;
            white-space: pre-wrap;
            word-wrap: break-word;
            margin: 0;
            overflow: auto;
            max-height: 100%;
          }

          .truncated-notice {
            margin-top: 12px;
            padding: 8px;
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 4px;
            font-size: 0.9em;
            color: #856404;
          }

          .no-preview {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100%;
            text-align: center;
          }

          .file-info {
            margin-top: 20px;
            text-align: left;
          }

          .file-info h4 {
            margin-bottom: 12px;
            color: #333;
          }

          .file-info ul {
            list-style: none;
            padding: 0;
            margin: 0;
          }

          .file-info li {
            padding: 4px 0;
            color: #666;
          }

          .file-info strong {
            color: #333;
          }
        `}</style>
      </div>
    </div>
  );
} 