import React from 'react';
import { render, fireEvent, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { FileUpload } from '../../../src/components/FileUpload';

const DOCX_FILE = new File([new ArrayBuffer(1)], 'test.docx', { type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' });
const PDF_FILE = new File([new ArrayBuffer(1)], 'test.pdf', { type: 'application/pdf' });
const TXT_FILE = new File([new ArrayBuffer(1)], 'test.txt', { type: 'text/plain' });
const INVALID_FILE = new File([new ArrayBuffer(1)], 'test.png', { type: 'image/png' });

describe('FileUpload', () => {
  const baseProps = {
    onFileUpload: jest.fn(),
    label: 'Upload your file',
    id: 'file-upload',
    disabled: false,
    uploadedFileName: null,
  };

  beforeEach(() => {
    jest.clearAllMocks();
    jest.spyOn(window, 'alert').mockImplementation(() => {});
  });

  it('renders with label and allowed types', () => {
    render(<FileUpload {...baseProps} />);
    expect(screen.getByText('Upload your file')).toBeInTheDocument();
    expect(screen.getByText('Apenas arquivos .docx, .pdf, .txt')).toBeInTheDocument();
    expect(screen.getByText('Arraste e solte ou clique para selecionar')).toBeInTheDocument();
  });

  it('calls onFileUpload when allowed file is selected', () => {
    render(<FileUpload {...baseProps} />);
    const fileInput = screen.getByTestId('file-upload-input') as HTMLInputElement;
    fireEvent.change(fileInput, { target: { files: [DOCX_FILE] } });
    expect(baseProps.onFileUpload).toHaveBeenCalledWith(DOCX_FILE);
  });

  it('alerts when disallowed file is selected', () => {
    render(<FileUpload {...baseProps} />);
    const fileInput = screen.getByTestId('file-upload-input') as HTMLInputElement;
    fireEvent.change(fileInput, { target: { files: [INVALID_FILE] } });
    expect(window.alert).toHaveBeenCalledWith(expect.stringMatching(/Por favor, envie apenas arquivos/));
    expect(baseProps.onFileUpload).not.toHaveBeenCalled();
  });

  it('calls onFileUpload on drag-and-drop of allowed file', () => {
    render(<FileUpload {...baseProps} />);
    const dropZone = screen.getByTestId('file-upload-dropzone');
    fireEvent.dragEnter(dropZone);
    fireEvent.dragOver(dropZone);
    fireEvent.drop(dropZone, {
      dataTransfer: {
        files: [PDF_FILE],
        items: [],
        types: ['Files'],
      },
    });
    expect(baseProps.onFileUpload).toHaveBeenCalledWith(PDF_FILE);
  });

  it('alerts on drag-and-drop of disallowed file', () => {
    render(<FileUpload {...baseProps} />);
    const dropZone = screen.getByTestId('file-upload-dropzone');
    fireEvent.dragEnter(dropZone);
    fireEvent.dragOver(dropZone);
    fireEvent.drop(dropZone, {
      dataTransfer: {
        files: [INVALID_FILE],
        items: [],
        types: ['Files'],
      },
    });
    expect(window.alert).toHaveBeenCalledWith(expect.stringMatching(/Por favor, envie apenas arquivos/));
    expect(baseProps.onFileUpload).not.toHaveBeenCalled();
  });

  it('shows uploaded file name if provided', () => {
    render(<FileUpload {...baseProps} uploadedFileName="myfile.pdf" />);
    expect(screen.getByText('myfile.pdf')).toBeInTheDocument();
  });

  it('is disabled when disabled prop is true', () => {
    render(<FileUpload {...baseProps} disabled={true} />);
    const dropZone = screen.getByTestId('file-upload-dropzone');
    expect(dropZone).toHaveClass('opacity-50');
    expect(dropZone).toHaveClass('cursor-not-allowed');
    // Try to click or drop
    fireEvent.click(dropZone);
    fireEvent.drop(dropZone, {
      dataTransfer: {
        files: [DOCX_FILE],
        items: [],
        types: ['Files'],
      },
    });
    expect(baseProps.onFileUpload).not.toHaveBeenCalled();
  });

  it('shows drag-over style when dragging', () => {
    render(<FileUpload {...baseProps} />);
    const dropZone = screen.getByTestId('file-upload-dropzone');
    fireEvent.dragEnter(dropZone);
    expect(dropZone).toHaveClass('border-blue-500');
    expect(dropZone).toHaveClass('bg-blue-50');
    fireEvent.dragLeave(dropZone);
    expect(dropZone).toHaveClass('border-slate-300');
    expect(dropZone).toHaveClass('bg-white');
  });

  // Additional tests to reach 100% coverage
  describe('Edge Cases and Complete Coverage', () => {
    it('handles file input change without files', () => {
      render(<FileUpload {...baseProps} />);
      const fileInput = screen.getByTestId('file-upload-input') as HTMLInputElement;
      
      // Simulate change event with no files
      fireEvent.change(fileInput, { target: { files: null } });
      expect(baseProps.onFileUpload).not.toHaveBeenCalled();
      
      // Simulate change event with empty files array
      fireEvent.change(fileInput, { target: { files: [] } });
      expect(baseProps.onFileUpload).not.toHaveBeenCalled();
    });

    it('handles drag events when disabled', () => {
      render(<FileUpload {...baseProps} disabled={true} />);
      const dropZone = screen.getByTestId('file-upload-dropzone');
      
      // Drag events should not change state when disabled
      fireEvent.dragEnter(dropZone);
      expect(dropZone).not.toHaveClass('border-blue-500');
      expect(dropZone).not.toHaveClass('bg-blue-50');
      
      fireEvent.dragOver(dropZone);
      fireEvent.dragLeave(dropZone);
      expect(dropZone).toHaveClass('border-slate-300');
      expect(dropZone).toHaveClass('bg-white');
    });

    it('handles drag over with dataTransfer properly', () => {
      render(<FileUpload {...baseProps} />);
      const dropZone = screen.getByTestId('file-upload-dropzone');
      
      // Create mock dataTransfer object
      const mockDataTransfer = {
        dropEffect: '',
        files: [DOCX_FILE],
        items: [],
        types: ['Files'],
      };
      
      fireEvent.dragOver(dropZone, { dataTransfer: mockDataTransfer });
      expect(mockDataTransfer.dropEffect).toBe('copy');
    });

    it('handles drag over without dataTransfer', () => {
      render(<FileUpload {...baseProps} />);
      const dropZone = screen.getByTestId('file-upload-dropzone');
      
      // Test dragOver without dataTransfer (should not crash)
      fireEvent.dragOver(dropZone, { dataTransfer: null });
      // No error should be thrown
    });

    it('handles drag over when disabled with dataTransfer', () => {
      render(<FileUpload {...baseProps} disabled={true} />);
      const dropZone = screen.getByTestId('file-upload-dropzone');
      
      const mockDataTransfer = {
        dropEffect: '',
        files: [DOCX_FILE],
        items: [],
        types: ['Files'],
      };
      
      fireEvent.dragOver(dropZone, { dataTransfer: mockDataTransfer });
      // dropEffect should not be set when disabled
      expect(mockDataTransfer.dropEffect).toBe('');
    });

    it('handles drop with no files in dataTransfer', () => {
      render(<FileUpload {...baseProps} />);
      const dropZone = screen.getByTestId('file-upload-dropzone');
      
      // First set dragging state
      fireEvent.dragEnter(dropZone);
      expect(dropZone).toHaveClass('bg-blue-50');
      
      // Drop with no files
      fireEvent.drop(dropZone, {
        dataTransfer: {
          files: [],
          items: [],
          types: [],
        },
      });
      
      // Should reset dragging state but not call onFileUpload
      expect(dropZone).toHaveClass('bg-white');
      expect(baseProps.onFileUpload).not.toHaveBeenCalled();
    });

    it('handles drop with null files in dataTransfer', () => {
      render(<FileUpload {...baseProps} />);
      const dropZone = screen.getByTestId('file-upload-dropzone');
      
      // First set dragging state
      fireEvent.dragEnter(dropZone);
      
      // Drop with null files
      fireEvent.drop(dropZone, {
        dataTransfer: {
          files: null,
          items: [],
          types: [],
        },
      });
      
      // Should reset dragging state but not call onFileUpload
      expect(dropZone).toHaveClass('bg-white');
      expect(baseProps.onFileUpload).not.toHaveBeenCalled();
    });

    it('handles click to open file dialog', () => {
      const mockClick = jest.fn();
      const mockGetElementById = jest.spyOn(document, 'getElementById').mockReturnValue({
        click: mockClick,
      } as any);

      render(<FileUpload {...baseProps} />);
      const dropZone = screen.getByTestId('file-upload-dropzone');
      
      fireEvent.click(dropZone);
      
      expect(mockGetElementById).toHaveBeenCalledWith('file-upload');
      expect(mockClick).toHaveBeenCalled();
      
      mockGetElementById.mockRestore();
    });

    it('handles click when element not found', () => {
      const mockGetElementById = jest.spyOn(document, 'getElementById').mockReturnValue(null);

      render(<FileUpload {...baseProps} />);
      const dropZone = screen.getByTestId('file-upload-dropzone');
      
      // Should not throw error when element is not found
      fireEvent.click(dropZone);
      
      expect(mockGetElementById).toHaveBeenCalledWith('file-upload');
      
      mockGetElementById.mockRestore();
    });

    it('handles click when disabled', () => {
      const mockClick = jest.fn();
      const mockGetElementById = jest.spyOn(document, 'getElementById').mockReturnValue({
        click: mockClick,
      } as any);

      render(<FileUpload {...baseProps} disabled={true} />);
      const dropZone = screen.getByTestId('file-upload-dropzone');
      
      fireEvent.click(dropZone);
      
      // Should not trigger click when disabled
      expect(mockGetElementById).not.toHaveBeenCalled();
      expect(mockClick).not.toHaveBeenCalled();
      
      mockGetElementById.mockRestore();
    });

    it('renders correct className combinations', () => {
      const { rerender } = render(<FileUpload {...baseProps} />);
      const dropZone = screen.getByTestId('file-upload-dropzone');
      
      // Default state
      expect(dropZone).toHaveClass('border-slate-300', 'bg-white', 'cursor-pointer');
      expect(dropZone).not.toHaveClass('opacity-50', 'cursor-not-allowed');
      
      // Disabled state
      rerender(<FileUpload {...baseProps} disabled={true} />);
      expect(dropZone).toHaveClass('border-slate-300', 'bg-white', 'opacity-50', 'cursor-not-allowed');
      expect(dropZone).not.toHaveClass('cursor-pointer');
      
      // Dragging state (not disabled)
      rerender(<FileUpload {...baseProps} disabled={false} />);
      fireEvent.dragEnter(dropZone);
      expect(dropZone).toHaveClass('border-blue-500', 'bg-blue-50', 'cursor-pointer');
      expect(dropZone).not.toHaveClass('border-slate-300', 'bg-white');
    });

    it('renders UploadIcon with correct props in different states', () => {
      render(<FileUpload {...baseProps} />);
      const dropZone = screen.getByTestId('file-upload-dropzone');
      
      // Default state - UploadIcon should have only gray color class
      let uploadIcon = dropZone.querySelector('svg');
      expect(uploadIcon).toHaveClass('text-gray-700');
      expect(uploadIcon).not.toHaveClass('text-blue-500');
      
      // Dragging state - UploadIcon should have both classes (blue overrides gray via CSS specificity)
      fireEvent.dragEnter(dropZone);
      uploadIcon = dropZone.querySelector('svg');
      expect(uploadIcon).toHaveClass('text-blue-500');
      expect(uploadIcon).toHaveClass('text-gray-700'); // Default class is still present
      
      // Back to default - only gray class should be present
      fireEvent.dragLeave(dropZone);
      uploadIcon = dropZone.querySelector('svg');
      expect(uploadIcon).toHaveClass('text-gray-700');
      expect(uploadIcon).not.toHaveClass('text-blue-500');
    });

    it('renders all allowed file types correctly', () => {
      render(<FileUpload {...baseProps} />);
      
      // Test all allowed MIME types
      const fileInput = screen.getByTestId('file-upload-input') as HTMLInputElement;
      
      // Test DOCX file
      fireEvent.change(fileInput, { target: { files: [DOCX_FILE] } });
      expect(baseProps.onFileUpload).toHaveBeenCalledWith(DOCX_FILE);
      
      // Reset mock
      baseProps.onFileUpload.mockClear();
      
      // Test PDF file
      fireEvent.change(fileInput, { target: { files: [PDF_FILE] } });
      expect(baseProps.onFileUpload).toHaveBeenCalledWith(PDF_FILE);
      
      // Reset mock
      baseProps.onFileUpload.mockClear();
      
      // Test TXT file
      fireEvent.change(fileInput, { target: { files: [TXT_FILE] } });
      expect(baseProps.onFileUpload).toHaveBeenCalledWith(TXT_FILE);
    });

    it('handles all text content variations correctly', () => {
      const { rerender } = render(<FileUpload {...baseProps} />);
      
      // Default state - should show label and help text
      expect(screen.getByText('Upload your file')).toBeInTheDocument();
      expect(screen.getByText('Arraste e solte ou clique para selecionar')).toBeInTheDocument();
      expect(screen.getByText('Apenas arquivos .docx, .pdf, .txt')).toBeInTheDocument();
      
      // With uploaded file - should show filename instead of label and hide help text
      rerender(<FileUpload {...baseProps} uploadedFileName="my-document.pdf" />);
      expect(screen.getByText('my-document.pdf')).toBeInTheDocument();
      expect(screen.queryByText('Upload your file')).not.toBeInTheDocument();
      expect(screen.queryByText('Arraste e solte ou clique para selecionar')).not.toBeInTheDocument();
      expect(screen.getByText('Apenas arquivos .docx, .pdf, .txt')).toBeInTheDocument(); // This should still be visible
      
      // With long filename (test truncation classes)
      const longFilename = 'this-is-a-very-long-filename-that-should-be-truncated-properly.docx';
      rerender(<FileUpload {...baseProps} uploadedFileName={longFilename} />);
      const filenameElement = screen.getByText(longFilename);
      expect(filenameElement).toHaveClass('truncate', 'max-w-full', 'px-2');
    });

    it('has correct input element attributes', () => {
      const { unmount } = render(<FileUpload {...baseProps} />);
      const fileInput = screen.getByTestId('file-upload-input') as HTMLInputElement;
      
      expect(fileInput).toHaveAttribute('type', 'file');
      expect(fileInput).toHaveAttribute('id', 'file-upload');
      expect(fileInput).toHaveAttribute('accept', '.docx, .pdf, .txt');
      expect(fileInput).toHaveClass('hidden');
      expect(fileInput).not.toBeDisabled();
      
      // Unmount and render disabled version
      unmount();
      render(<FileUpload {...baseProps} disabled={true} />);
      const disabledInput = screen.getByTestId('file-upload-input') as HTMLInputElement;
      expect(disabledInput).toBeDisabled();
    });
  });
}); 