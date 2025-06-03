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
}); 