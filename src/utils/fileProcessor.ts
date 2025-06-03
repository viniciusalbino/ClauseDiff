import { DocumentData } from '../../types';

export const processDocxFile = async (file: File): Promise<DocumentData> => {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = async (event) => {
      if (event.target && event.target.result) {
        const arrayBuffer = event.target.result as ArrayBuffer;
        try {
          const result = await window.mammoth.extractRawText({ arrayBuffer });
          resolve({
            name: file.name,
            content: result.value,
            type: file.type,
            originalFile: file
          });
        } catch (error) {
          console.error("Error processing DOCX with Mammoth:", error);
          reject(new Error("Falha ao processar o arquivo .docx."));
        }
      } else {
        reject(new Error("Falha ao ler o arquivo."));
      }
    };
    reader.onerror = (error) => {
      console.error("FileReader error:", error);
      reject(new Error("Erro ao ler o arquivo."));
    };
    reader.readAsArrayBuffer(file);
  });
};

export const processTxtFile = async (file: File): Promise<DocumentData> => {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = (event) => {
      if (event.target && event.target.result) {
        const text = event.target.result as string;
        resolve({
          name: file.name,
          content: text,
          type: file.type,
          originalFile: file
        });
      } else {
        reject(new Error("Falha ao ler o arquivo."));
      }
    };
    reader.onerror = (error) => {
      console.error("FileReader error:", error);
      reject(new Error("Erro ao ler o arquivo."));
    };
    reader.readAsText(file);
  });
};

export const processPdfFile = async (file: File): Promise<DocumentData> => {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = async (event) => {
      if (event.target && event.target.result) {
        const arrayBuffer = event.target.result as ArrayBuffer;
        try {
          // Ensure PDF.js worker is configured (might be better to do this once in App.tsx)
          if (!window.pdfjsLib.GlobalWorkerOptions.workerSrc) {
            window.pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';
          }
          
          const pdfDoc = await window.pdfjsLib.getDocument({ data: arrayBuffer }).promise;
          let fullText = '';
          for (let i = 1; i <= pdfDoc.numPages; i++) {
            const page = await pdfDoc.getPage(i);
            const textContent = await page.getTextContent();
            fullText += textContent.items.map((item: any) => item.str).join(' ') + '\n';
          }
          
          resolve({
            name: file.name,
            content: fullText.trim(),
            type: file.type,
            originalFile: file
          });
        } catch (error) {
          console.error("Error processing PDF with PDF.js:", error);
          reject(new Error("Falha ao processar o arquivo .pdf."));
        }
      } else {
        reject(new Error("Falha ao ler o arquivo."));
      }
    };
    reader.onerror = (error) => {
      console.error("FileReader error:", error);
      reject(new Error("Erro ao ler o arquivo."));
    };
    reader.readAsArrayBuffer(file);
  });
};
