import React, { useState, useCallback, useRef, useEffect } from 'react';
import { DocxProcessor } from '../../../infrastructure/processors/DocxProcessor';
import { TxtProcessor } from '../../../infrastructure/processors/TxtProcessor';

export interface FileUploadProps {
  onFilesSelected?: (files: UploadedFile[]) => void;
  onFileRemove?: (fileId: string) => void;
  onUploadProgress?: (fileId: string, progress: number) => void;
  onUploadComplete?: (fileId: string, result: any) => void;
  onUploadError?: (fileId: string, error: string) => void;
  
  // Validation options
  maxFileSize?: number; // in bytes
  allowedTypes?: string[];
  maxFiles?: number;
  
  // UI options
  disabled?: boolean;
  compact?: boolean;
  theme?: 'light' | 'dark';
  showPreview?: boolean;
  showProgress?: boolean;
  
  // Labels and text
  uploadText?: string;
  dragText?: string;
  browseText?: string;
  
  className?: string;
}

export interface UploadedFile {
  id: string;
  file: File;
  name: string;
  size: number;
  type: string;
  lastModified: number;
  status: 'pending' | 'uploading' | 'completed' | 'error';
  progress: number;
  error?: string;
  preview?: string;
  content?: string;
}

/**
 * Componente de upload de arquivos com drag & drop avançado
 * Suporta validação, preview, progresso e tratamento de erros
 */
export const FileUpload: React.FC<FileUploadProps> = ({
  onFilesSelected,
  onFileRemove,
  onUploadProgress,
  onUploadComplete,
  onUploadError,
  
  maxFileSize = 10 * 1024 * 1024, // 10MB default
  allowedTypes = [
    'text/plain',
    'text/markdown',
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/rtf'
  ],
  maxFiles = 2,
  
  disabled = false,
  compact = false,
  theme = 'light',
  showPreview = true,
  showProgress = true,
  
  uploadText = 'Upload files to compare',
  dragText = 'Drag and drop files here',
  browseText = 'or browse files',
  
  className = ''
}) => {
  const [uploadedFiles, setUploadedFiles] = useState<UploadedFile[]>([]);
  const [isDragging, setIsDragging] = useState(false);
  const [dragCounter, setDragCounter] = useState(0);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Generate unique file ID
  const generateFileId = useCallback(() => {
    return `file-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }, []);

  // Validate file
  const validateFile = useCallback((file: File): string | null => {
    if (file.size > maxFileSize) {
      return `File size exceeds ${formatFileSize(maxFileSize)} limit`;
    }
    
    if (allowedTypes.length > 0 && !allowedTypes.includes(file.type)) {
      return `File type ${file.type} is not supported`;
    }
    
    return null;
  }, [maxFileSize, allowedTypes]);

  // Process files
  const processFiles = useCallback(async (fileList: FileList | File[]) => {
    const files = Array.from(fileList);
    
    if (uploadedFiles.length + files.length > maxFiles) {
      alert(`Maximum ${maxFiles} files allowed`);
      return;
    }

    const newFiles: UploadedFile[] = [];

    for (const file of files) {
      const fileId = generateFileId();
      const error = validateFile(file);
      
      const uploadedFile: UploadedFile = {
        id: fileId,
        file,
        name: file.name,
        size: file.size,
        type: file.type,
        lastModified: file.lastModified,
        status: error ? 'error' : 'pending',
        progress: 0,
        error: error || undefined
      };

      // Generate preview and extract content based on file type
      if (!error) {
        try {
          let content: string | undefined;
          
          if (file.type.startsWith('text/')) {
            // Handle text files
            content = await readFileAsText(file);
          } else if (file.type === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
            // Handle DOCX files
            const processor = new DocxProcessor();
            const result = await processor.process(file);
            if (result.status === 'completed') {
              content = result.content;
            } else {
              throw new Error(result.error || 'Failed to process DOCX file');
            }
          }
          
          if (content) {
            uploadedFile.content = content;
            uploadedFile.preview = content.substring(0, 200) + (content.length > 200 ? '...' : '');
          }
        } catch (err) {
          uploadedFile.error = err instanceof Error ? err.message : 'Failed to read file content';
          uploadedFile.status = 'error';
        }
      }

      newFiles.push(uploadedFile);
    }

    setUploadedFiles(prev => [...prev, ...newFiles]);
    onFilesSelected?.(newFiles);

    // Start processing valid files
    newFiles.forEach(file => {
      if (file.status === 'pending') {
        processFile(file);
      }
    });
  }, [uploadedFiles.length, maxFiles, generateFileId, validateFile, onFilesSelected]);

  // Process individual file
  const processFile = useCallback(async (uploadedFile: UploadedFile) => {
    try {
      // Update status to uploading
      setUploadedFiles(prev => 
        prev.map(f => f.id === uploadedFile.id ? { ...f, status: 'uploading' } : f)
      );

      // Simulate processing with progress updates
      for (let progress = 0; progress <= 100; progress += 10) {
        await new Promise(resolve => setTimeout(resolve, 100));
        
        setUploadedFiles(prev => 
          prev.map(f => f.id === uploadedFile.id ? { ...f, progress } : f)
        );
        
        onUploadProgress?.(uploadedFile.id, progress);
      }

      // Mark as completed
      setUploadedFiles(prev => 
        prev.map(f => f.id === uploadedFile.id ? { ...f, status: 'completed' } : f)
      );

      onUploadComplete?.(uploadedFile.id, { success: true });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Upload failed';
      
      setUploadedFiles(prev => 
        prev.map(f => f.id === uploadedFile.id ? { 
          ...f, 
          status: 'error', 
          error: errorMessage 
        } : f)
      );

      onUploadError?.(uploadedFile.id, errorMessage);
    }
  }, [onUploadProgress, onUploadComplete, onUploadError]);

  // Remove file
  const removeFile = useCallback((fileId: string) => {
    setUploadedFiles(prev => prev.filter(f => f.id !== fileId));
    onFileRemove?.(fileId);
  }, [onFileRemove]);

  // Drag handlers
  const handleDragEnter = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragCounter(prev => prev + 1);
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragCounter(prev => {
      const newCount = prev - 1;
      if (newCount === 0) {
        setIsDragging(false);
      }
      return newCount;
    });
  }, []);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    setDragCounter(0);

    if (disabled) return;

    const files = e.dataTransfer.files;
    if (files.length > 0) {
      processFiles(files);
    }
  }, [disabled, processFiles]);

  // File input handler
  const handleFileInputChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      processFiles(e.target.files);
    }
    // Reset input value to allow same file selection
    e.target.value = '';
  }, [processFiles]);

  // Browse files
  const handleBrowseClick = useCallback(() => {
    if (disabled) return;
    fileInputRef.current?.click();
  }, [disabled]);

  // Keyboard accessibility
  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      handleBrowseClick();
    }
  }, [handleBrowseClick]);

  // Render file item
  const renderFileItem = (file: UploadedFile) => (
    <div key={file.id} className={`file-item ${file.status}`}>
      <div className="file-info">
        <div className="file-header">
          <span className="file-name">{file.name}</span>
          <button
            className="remove-btn"
            onClick={() => removeFile(file.id)}
            title="Remove file"
          >
            ✕
          </button>
        </div>
        
        <div className="file-meta">
          <span className="file-size">{formatFileSize(file.size)}</span>
          <span className="file-type">{file.type}</span>
          <span className={`file-status ${file.status}`}>
            {file.status === 'pending' && '⏳ Pending'}
            {file.status === 'uploading' && '📤 Uploading'}
            {file.status === 'completed' && '✅ Ready'}
            {file.status === 'error' && '❌ Error'}
          </span>
        </div>

        {file.error && (
          <div className="file-error">{file.error}</div>
        )}

        {showProgress && file.status === 'uploading' && (
          <div className="progress-bar">
            <div 
              className="progress-fill"
              style={{ width: `${file.progress}%` }}
            />
          </div>
        )}

        {showPreview && file.preview && file.status === 'completed' && (
          <div className="file-preview">
            <div className="preview-label">Preview:</div>
            <div className="preview-content">{file.preview}</div>
          </div>
        )}
      </div>
    </div>
  );

  return (
    <div className={`file-upload ${theme} ${compact ? 'compact' : ''} ${className}`}>
      <div
        className={`upload-zone ${isDragging ? 'dragging' : ''} ${disabled ? 'disabled' : ''}`}
        onDragEnter={handleDragEnter}
        onDragLeave={handleDragLeave}
        onDragOver={handleDragOver}
        onDrop={handleDrop}
        onClick={handleBrowseClick}
        onKeyDown={handleKeyDown}
        tabIndex={disabled ? -1 : 0}
        role="button"
        aria-label="Upload files"
      >
        <div className="upload-icon">📁</div>
        <div className="upload-text">
          <div className="upload-title">{uploadText}</div>
          <div className="upload-subtitle">
            {dragText} {browseText && <span className="browse-link">{browseText}</span>}
          </div>
        </div>
        
        <div className="upload-limits">
          <div>📁 Maximum {maxFiles} files for comparison • Up to {formatFileSize(maxFileSize)} each</div>
          <div>📋 Supported: Text files (.txt, .md), PDFs, Word documents</div>
        </div>
      </div>

      <input
        ref={fileInputRef}
        type="file"
        multiple={maxFiles > 1}
        accept={allowedTypes.join(',')}
        onChange={handleFileInputChange}
        style={{ display: 'none' }}
        disabled={disabled}
      />

      {uploadedFiles.length > 0 && (
        <div className="files-list">
          <div className="files-header">
            <h3>Selected Files ({uploadedFiles.length}/{maxFiles})</h3>
            {uploadedFiles.length > 0 && (
              <button
                className="clear-all-btn"
                onClick={() => {
                  setUploadedFiles([]);
                  uploadedFiles.forEach(file => onFileRemove?.(file.id));
                }}
              >
                Clear All
              </button>
            )}
          </div>
          
          <div className="files-container">
            {uploadedFiles.map(renderFileItem)}
          </div>
        </div>
      )}

      <style jsx>{`
        .file-upload {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          font-size: 14px;
        }

        .upload-zone {
          border: 2px dashed #d0d7de;
          border-radius: 8px;
          padding: 32px;
          text-align: center;
          cursor: pointer;
          transition: all 0.2s ease;
          background-color: #f6f8fa;
          position: relative;
        }

        .upload-zone:hover:not(.disabled) {
          border-color: #0969da;
          background-color: #f0f6fc;
        }

        .upload-zone.dragging {
          border-color: #0969da;
          background-color: #dbeafe;
          border-style: solid;
        }

        .upload-zone.disabled {
          opacity: 0.5;
          cursor: not-allowed;
          background-color: #f1f3f4;
        }

        .file-upload.dark .upload-zone {
          background-color: #161b22;
          border-color: #30363d;
          color: #f0f6fc;
        }

        .file-upload.dark .upload-zone:hover:not(.disabled) {
          border-color: #58a6ff;
          background-color: #0d1117;
        }

        .file-upload.dark .upload-zone.dragging {
          border-color: #58a6ff;
          background-color: #1c2128;
        }

        .upload-icon {
          font-size: 48px;
          margin-bottom: 16px;
          opacity: 0.7;
        }

        .upload-title {
          font-size: 18px;
          font-weight: 600;
          margin-bottom: 8px;
          color: #24292f;
        }

        .file-upload.dark .upload-title {
          color: #f0f6fc;
        }

        .upload-subtitle {
          color: #656d76;
          margin-bottom: 16px;
        }

        .file-upload.dark .upload-subtitle {
          color: #8b949e;
        }

        .browse-link {
          color: #0969da;
          text-decoration: underline;
          cursor: pointer;
        }

        .file-upload.dark .browse-link {
          color: #58a6ff;
        }

        .upload-limits {
          font-size: 12px;
          color: #656d76;
          line-height: 1.4;
        }

        .file-upload.dark .upload-limits {
          color: #8b949e;
        }

        .files-list {
          margin-top: 24px;
        }

        .files-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 16px;
          padding-bottom: 8px;
          border-bottom: 1px solid #e1e4e8;
        }

        .file-upload.dark .files-header {
          border-bottom-color: #30363d;
        }

        .files-header h3 {
          margin: 0;
          font-size: 16px;
          font-weight: 600;
          color: #24292f;
        }

        .file-upload.dark .files-header h3 {
          color: #f0f6fc;
        }

        .clear-all-btn {
          background: none;
          border: 1px solid #d0d7de;
          border-radius: 4px;
          padding: 4px 8px;
          font-size: 12px;
          cursor: pointer;
          color: #cf222e;
          transition: all 0.15s ease;
        }

        .clear-all-btn:hover {
          background-color: #cf222e;
          color: white;
        }

        .file-upload.dark .clear-all-btn {
          border-color: #30363d;
          color: #f85149;
        }

        .file-upload.dark .clear-all-btn:hover {
          background-color: #f85149;
          color: #0d1117;
        }

        .files-container {
          display: flex;
          flex-direction: column;
          gap: 12px;
        }

        .file-item {
          border: 1px solid #e1e4e8;
          border-radius: 6px;
          padding: 16px;
          background-color: #ffffff;
          transition: all 0.15s ease;
        }

        .file-item.error {
          border-color: #f85149;
          background-color: #fff5f5;
        }

        .file-item.completed {
          border-color: #3fb950;
          background-color: #f6ffed;
        }

        .file-upload.dark .file-item {
          background-color: #0d1117;
          border-color: #30363d;
          color: #f0f6fc;
        }

        .file-upload.dark .file-item.error {
          border-color: #f85149;
          background-color: #1a1212;
        }

        .file-upload.dark .file-item.completed {
          border-color: #3fb950;
          background-color: #0f1419;
        }

        .file-header {
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
          margin-bottom: 8px;
        }

        .file-name {
          font-weight: 500;
          flex: 1;
          word-break: break-all;
        }

        .remove-btn {
          background: none;
          border: none;
          color: #656d76;
          cursor: pointer;
          padding: 0;
          font-size: 16px;
          line-height: 1;
          margin-left: 8px;
          transition: color 0.15s ease;
        }

        .remove-btn:hover {
          color: #cf222e;
        }

        .file-upload.dark .remove-btn {
          color: #8b949e;
        }

        .file-upload.dark .remove-btn:hover {
          color: #f85149;
        }

        .file-meta {
          display: flex;
          gap: 12px;
          font-size: 12px;
          color: #656d76;
          margin-bottom: 8px;
        }

        .file-upload.dark .file-meta {
          color: #8b949e;
        }

        .file-status.completed {
          color: #1a7f37;
        }

        .file-status.error {
          color: #cf222e;
        }

        .file-status.uploading {
          color: #9a6700;
        }

        .file-upload.dark .file-status.completed {
          color: #3fb950;
        }

        .file-upload.dark .file-status.error {
          color: #f85149;
        }

        .file-upload.dark .file-status.uploading {
          color: #e3b341;
        }

        .file-error {
          color: #cf222e;
          font-size: 12px;
          margin-top: 4px;
          padding: 4px 8px;
          background-color: #fff5f5;
          border-radius: 4px;
        }

        .file-upload.dark .file-error {
          color: #f85149;
          background-color: #1a1212;
        }

        .progress-bar {
          width: 100%;
          height: 4px;
          background-color: #e1e4e8;
          border-radius: 2px;
          overflow: hidden;
          margin-top: 8px;
        }

        .file-upload.dark .progress-bar {
          background-color: #30363d;
        }

        .progress-fill {
          height: 100%;
          background-color: #0969da;
          transition: width 0.3s ease;
        }

        .file-upload.dark .progress-fill {
          background-color: #58a6ff;
        }

        .file-preview {
          margin-top: 12px;
          padding: 8px;
          background-color: #f6f8fa;
          border-radius: 4px;
          font-size: 12px;
        }

        .file-upload.dark .file-preview {
          background-color: #161b22;
        }

        .preview-label {
          font-weight: 500;
          margin-bottom: 4px;
          color: #24292f;
        }

        .file-upload.dark .preview-label {
          color: #f0f6fc;
        }

        .preview-content {
          font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
          white-space: pre-wrap;
          color: #656d76;
        }

        .file-upload.dark .preview-content {
          color: #8b949e;
        }

        .file-upload.compact .upload-zone {
          padding: 16px;
        }

        .file-upload.compact .upload-icon {
          font-size: 32px;
          margin-bottom: 8px;
        }

        .file-upload.compact .upload-title {
          font-size: 16px;
        }
      `}</style>
    </div>
  );
};

// Helper functions
function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function readFileAsText(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = (e) => resolve(e.target?.result as string);
    reader.onerror = (e) => reject(new Error('Failed to read file'));
    reader.readAsText(file);
  });
}

export default FileUpload; 