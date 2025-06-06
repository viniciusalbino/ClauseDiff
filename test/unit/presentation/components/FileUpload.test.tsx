/**
 * Testes unitários para componente FileUpload
 * Testando componente de upload implementado na Seção 3.0
 */

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { FileUpload } from '../../../../src/presentation/components/FileUpload/FileUpload';

// Mock do react-dropzone
jest.mock('react-dropzone', () => ({
  useDropzone: jest.fn(() => ({
    getRootProps: () => ({ 'data-testid': 'dropzone' }),
    getInputProps: () => ({ 'data-testid': 'file-input' }),
    isDragActive: false,
    isDragAccept: false,
    isDragReject: false,
    acceptedFiles: [],
    rejectedFiles: []
  }))
}));

// Mock do react-hook-form
jest.mock('react-hook-form', () => ({
  useForm: () => ({
    register: jest.fn(),
    handleSubmit: jest.fn((fn) => fn),
    formState: { errors: {} },
    setValue: jest.fn(),
    watch: jest.fn(() => []),
    reset: jest.fn()
  })
}));

describe('FileUpload Component', () => {
  const mockOnUpload = jest.fn();
  const mockOnError = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Renderização', () => {
    it('deve renderizar componente básico', () => {
      render(
        <FileUpload 
          onUpload={mockOnUpload}
          onError={mockOnError}
        />
      );

      expect(screen.getByTestId('dropzone')).toBeInTheDocument();
      expect(screen.getByTestId('file-input')).toBeInTheDocument();
    });

    it('deve mostrar texto de instrução', () => {
      render(
        <FileUpload 
          onUpload={mockOnUpload}
          onError={mockOnError}
        />
      );

      expect(screen.getByText(/arraste arquivos/i)).toBeInTheDocument();
    });

    it('deve aceitar props customizadas', () => {
      render(
        <FileUpload 
          onUpload={mockOnUpload}
          onError={mockOnError}
          maxFiles={5}
          maxSize={10 * 1024 * 1024}
          accept={{ 'text/plain': ['.txt'] }}
        />
      );

      // Componente deve renderizar sem erros
      expect(screen.getByTestId('dropzone')).toBeInTheDocument();
    });
  });

  describe('Interação com Arquivos', () => {
    it('deve chamar onUpload quando arquivo é selecionado', async () => {
      const user = userEvent.setup();
      
      render(
        <FileUpload 
          onUpload={mockOnUpload}
          onError={mockOnError}
        />
      );

      const input = screen.getByTestId('file-input');
      const file = new File(['test content'], 'test.txt', { type: 'text/plain' });

      await user.upload(input, file);

      await waitFor(() => {
        expect(mockOnUpload).toHaveBeenCalled();
      });
    });

    it('deve mostrar preview de arquivos selecionados', async () => {
      const user = userEvent.setup();
      
      render(
        <FileUpload 
          onUpload={mockOnUpload}
          onError={mockOnError}
          showPreview={true}
        />
      );

      const input = screen.getByTestId('file-input');
      const file = new File(['test content'], 'test.txt', { type: 'text/plain' });

      await user.upload(input, file);

      await waitFor(() => {
        expect(screen.getByText('test.txt')).toBeInTheDocument();
      });
    });
  });

  describe('Validação', () => {
    it('deve chamar onError para arquivos inválidos', async () => {
      const user = userEvent.setup();
      
      render(
        <FileUpload 
          onUpload={mockOnUpload}
          onError={mockOnError}
          accept={{ 'text/plain': ['.txt'] }}
        />
      );

      const input = screen.getByTestId('file-input');
      const invalidFile = new File(['content'], 'test.pdf', { type: 'application/pdf' });

      await user.upload(input, invalidFile);

      await waitFor(() => {
        expect(mockOnError).toHaveBeenCalled();
      });
    });

    it('deve validar tamanho máximo de arquivo', async () => {
      const user = userEvent.setup();
      
      render(
        <FileUpload 
          onUpload={mockOnUpload}
          onError={mockOnError}
          maxSize={100} // 100 bytes
        />
      );

      const input = screen.getByTestId('file-input');
      const largeFile = new File(['x'.repeat(200)], 'large.txt', { type: 'text/plain' });

      await user.upload(input, largeFile);

      await waitFor(() => {
        expect(mockOnError).toHaveBeenCalled();
      });
    });
  });

  describe('Estados de Loading', () => {
    it('deve mostrar estado de carregamento', () => {
      render(
        <FileUpload 
          onUpload={mockOnUpload}
          onError={mockOnError}
          isLoading={true}
        />
      );

      expect(screen.getByText(/carregando/i)).toBeInTheDocument();
    });

    it('deve desabilitar input durante carregamento', () => {
      render(
        <FileUpload 
          onUpload={mockOnUpload}
          onError={mockOnError}
          isLoading={true}
        />
      );

      const input = screen.getByTestId('file-input');
      expect(input).toBeDisabled();
    });
  });

  describe('Múltiplos Arquivos', () => {
    it('deve permitir seleção de múltiplos arquivos', async () => {
      const user = userEvent.setup();
      
      render(
        <FileUpload 
          onUpload={mockOnUpload}
          onError={mockOnError}
          multiple={true}
          maxFiles={3}
        />
      );

      const input = screen.getByTestId('file-input');
      const files = [
        new File(['content1'], 'file1.txt', { type: 'text/plain' }),
        new File(['content2'], 'file2.txt', { type: 'text/plain' })
      ];

      await user.upload(input, files);

      await waitFor(() => {
        expect(mockOnUpload).toHaveBeenCalledWith(
          expect.arrayContaining([
            expect.objectContaining({ name: 'file1.txt' }),
            expect.objectContaining({ name: 'file2.txt' })
          ])
        );
      });
    });

    it('deve limitar número máximo de arquivos', async () => {
      const user = userEvent.setup();
      
      render(
        <FileUpload 
          onUpload={mockOnUpload}
          onError={mockOnError}
          multiple={true}
          maxFiles={2}
        />
      );

      const input = screen.getByTestId('file-input');
      const files = [
        new File(['content1'], 'file1.txt', { type: 'text/plain' }),
        new File(['content2'], 'file2.txt', { type: 'text/plain' }),
        new File(['content3'], 'file3.txt', { type: 'text/plain' })
      ];

      await user.upload(input, files);

      await waitFor(() => {
        expect(mockOnError).toHaveBeenCalled();
      });
    });
  });

  describe('Acessibilidade', () => {
    it('deve ter labels apropriados', () => {
      render(
        <FileUpload 
          onUpload={mockOnUpload}
          onError={mockOnError}
        />
      );

      const input = screen.getByTestId('file-input');
      expect(input).toHaveAttribute('aria-label');
    });

    it('deve ser navegável por teclado', () => {
      render(
        <FileUpload 
          onUpload={mockOnUpload}
          onError={mockOnError}
        />
      );

      const dropzone = screen.getByTestId('dropzone');
      expect(dropzone).toHaveAttribute('tabIndex');
    });
  });

  describe('Customização', () => {
    it('deve aceitar className customizada', () => {
      render(
        <FileUpload 
          onUpload={mockOnUpload}
          onError={mockOnError}
          className="custom-upload"
        />
      );

      const dropzone = screen.getByTestId('dropzone');
      expect(dropzone).toHaveClass('custom-upload');
    });

    it('deve renderizar children customizados', () => {
      render(
        <FileUpload 
          onUpload={mockOnUpload}
          onError={mockOnError}
        >
          <div data-testid="custom-content">Upload personalizado</div>
        </FileUpload>
      );

      expect(screen.getByTestId('custom-content')).toBeInTheDocument();
    });
  });
}); 