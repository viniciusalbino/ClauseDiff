import React, { useState, useCallback } from 'react';
import { UploadIcon } from './icons/UploadIcon';

interface FileUploadProps {
  onFileUpload: (file: File) => void;
  label: string;
  id: string;
  disabled?: boolean;
  uploadedFileName?: string | null;
}

export const FileUpload: React.FC<FileUploadProps> = ({ onFileUpload, label, id, disabled, uploadedFileName }) => {
  const [isDragging, setIsDragging] = useState(false);

  const allowedMimeTypes = [
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document", // .docx
    "application/pdf", // .pdf
    "text/plain" // .txt
  ];

  const allowedFileExtensions = ".docx, .pdf, .txt";
  const userFriendlyFileTypesMessage = "Por favor, envie apenas arquivos .docx, .pdf ou .txt.";
  const displayedAllowedTypes = "Apenas arquivos .docx, .pdf, .txt";

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files && event.target.files[0]) {
      const file = event.target.files[0];
      if (allowedMimeTypes.includes(file.type)) {
        onFileUpload(file);
      } else {
        alert(userFriendlyFileTypesMessage);
      }
    }
  };

  const handleDragEnter = useCallback((event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.stopPropagation();
    if (!disabled) setIsDragging(true);
  }, [disabled]);

  const handleDragLeave = useCallback((event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.stopPropagation();
    if (!disabled) setIsDragging(false);
  }, [disabled]);

  const handleDragOver = useCallback((event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.stopPropagation();
    if (!disabled && event.dataTransfer) {
      event.dataTransfer.dropEffect = 'copy';
    }
  }, [disabled]);

  const handleDrop = useCallback((event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.stopPropagation();
    if (disabled) return;
    setIsDragging(false);
    if (event.dataTransfer.files && event.dataTransfer.files[0]) {
      const file = event.dataTransfer.files[0];
       if (allowedMimeTypes.includes(file.type)) {
        onFileUpload(file);
      } else {
        alert(userFriendlyFileTypesMessage);
      }
    }
  }, [onFileUpload, disabled, allowedMimeTypes, userFriendlyFileTypesMessage]);

  const borderClass = isDragging ? 'border-blue-500' : 'border-slate-300';
  const bgColorClass = isDragging ? 'bg-blue-50' : 'bg-white';

  return (
    <div
      className={`w-full p-4 border-2 ${borderClass} border-dashed rounded-lg transition-colors duration-200 ease-in-out ${bgColorClass} ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}
      onDragEnter={handleDragEnter}
      onDragLeave={handleDragLeave}
      onDragOver={handleDragOver}
      onDrop={handleDrop}
      onClick={() => !disabled && document.getElementById(id)?.click()}
    >
      <input
        type="file"
        id={id}
        accept={allowedFileExtensions}
        onChange={handleFileChange}
        className="hidden"
        disabled={disabled}
      />
      <div className="flex flex-col items-center justify-center space-y-2">
        <UploadIcon size={40} className={isDragging ? 'text-blue-500' : 'text-gray-700'} />
        {uploadedFileName ? (
           <p className="text-sm font-semibold text-green-600 truncate max-w-full px-2">{uploadedFileName}</p>
        ) : (
          <p className="text-sm text-gray-700 font-semibold">{label}</p>
        )}
        {!uploadedFileName && <p className="text-xs text-gray-500">Arraste e solte ou clique para selecionar</p>}
        <p className="text-xs text-gray-400">{displayedAllowedTypes}</p>
      </div>
    </div>
  );
};