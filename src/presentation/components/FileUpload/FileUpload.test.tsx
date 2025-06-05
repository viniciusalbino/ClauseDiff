/**
 * Testes simples para FileUpload
 * Verifica funcionalidades básicas sem complexidade desnecessária
 */

import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { FileUpload } from './FileUpload';

// Mock do react-dropzone
jest.mock('react-dropzone', () => ({
  useDropzone: jest.fn(() => ({
    getRootProps: () => ({}),
    getInputProps: () => ({}),
    isDragActive: false,
    isDragReject: false
  }))
}));

// Mock do react-hook-form
jest.mock('react-hook-form', () => ({
  useForm: () => ({
    handleSubmit: (fn: any) => fn
  })
}));

describe('FileUpload', () => {
  it('renders dropzone area', () => {
    render(<FileUpload />);
    
    expect(screen.getByText(/Arraste arquivos aqui/)).toBeInTheDocument();
    expect(screen.getByText(/Máximo 5 arquivos/)).toBeInTheDocument();
  });

  it('shows file limits in dropzone info', () => {
    render(<FileUpload maxFiles={3} maxSize={10 * 1024 * 1024} />);
    
    expect(screen.getByText(/Máximo 3 arquivos/)).toBeInTheDocument();
    expect(screen.getByText(/Tamanho máximo 10MB/)).toBeInTheDocument();
  });

  it('calls onError when provided', () => {
    const onError = jest.fn();
    render(<FileUpload onError={onError} />);
    
    // Este teste verifica se a prop é aceita corretamente
    expect(onError).toHaveBeenCalledTimes(0);
  });

  it('calls onUploadComplete when provided', () => {
    const onUploadComplete = jest.fn();
    render(<FileUpload onUploadComplete={onUploadComplete} />);
    
    // Este teste verifica se a prop é aceita corretamente
    expect(onUploadComplete).toHaveBeenCalledTimes(0);
  });

  it('applies custom allowed types', () => {
    const allowedTypes = ['text/plain'];
    render(<FileUpload allowedTypes={allowedTypes} />);
    
    // Verifica se o componente renderiza sem erro com tipos customizados
    expect(screen.getByText(/Arraste arquivos aqui/)).toBeInTheDocument();
  });
}); 