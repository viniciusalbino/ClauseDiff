import React, { useState, useCallback, useEffect } from 'react';
import { FileUpload } from './components/FileUpload';
import { ComparisonView } from './components/ComparisonView';
import { DifferenceSummary } from './components/DifferenceSummary';
import { Toolbar } from './components/Toolbar';
import { LoadingSpinner } from './components/LoadingSpinner';
import { InfoIcon } from './components/icons/InfoIcon';
import { processDocxFile, processPdfFile, processTxtFile } from './utils/fileProcessor';
import { exportToPdf, exportToCsv } from './utils/exportHandler';
import { DocumentData, ComparisonResult } from '../types';
import { compareDocuments } from './services/api';

const App: React.FC = () => {
  const [doc1, setDoc1] = useState<DocumentData | null>(null);
  const [doc2, setDoc2] = useState<DocumentData | null>(null);
  const [comparisonResult, setComparisonResult] = useState<ComparisonResult | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [showSummary, setShowSummary] = useState<boolean>(true);

  // Initialize PDF.js worker
  useEffect(() => {
    if (window.pdfjsLib) {
       window.pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';
    }
  }, []);

  const handleFileUpload = useCallback(async (file: File, docNumber: 1 | 2) => {
    setIsLoading(true);
    setError(null);
    try {
      let documentData: DocumentData;
      
      console.log('File MIME type:', file.type); // For debugging

      if (file.type === "application/vnd.openxmlformats-officedocument.wordprocessingml.document") {
        documentData = await processDocxFile(file);
      } else if (file.type === "application/pdf") {
        documentData = await processPdfFile(file);
      } else if (file.type === "text/plain") {
        documentData = await processTxtFile(file);
      } else {
        // Fallback for .txt if MIME type is unusual (e.g. application/octet-stream for a .txt)
        if (file.name.toLowerCase().endsWith(".txt")) {
            console.warn(`Received file ${file.name} with type ${file.type}, processing as TXT due to extension.`);
            documentData = await processTxtFile(file);
        } else {
            throw new Error(`Tipo de arquivo não suportado: ${file.type || file.name}. Por favor, envie .docx, .pdf ou .txt.`);
        }
      }
      
      if (docNumber === 1) {
        setDoc1(documentData);
      } else {
        setDoc2(documentData);
      }
      setComparisonResult(null); 
    } catch (err) {
      console.error(err);
      setError(err instanceof Error ? err.message : 'Ocorreu um erro desconhecido ao processar o arquivo.');
    } finally {
      setIsLoading(false);
    }
  }, []);

  const handleCompare = useCallback(async () => {
    if (!doc1 || !doc2) {
      setError('Por favor, carregue ambos os documentos para comparar.');
      return;
    }
    setIsLoading(true);
    setError(null);

    try {
      const result = await compareDocuments(doc1, doc2);
      setComparisonResult(result);
      setShowSummary(true);
    } catch (err) {
      console.error(err);
      setError(err instanceof Error ? err.message : 'Erro ao realizar a comparação.');
      setComparisonResult(null);
    } finally {
      setIsLoading(false);
    }
  }, [doc1, doc2]);

  const handleExportPdf = useCallback(async () => {
    if (!comparisonResult) {
      setError('Nenhuma comparação para exportar. Por favor, compare os documentos primeiro.');
      return;
    }
    setIsLoading(true);
    try {
      await exportToPdf('comparison-pane-1', 'comparison-pane-2', `comparacao_${doc1?.name}_vs_${doc2?.name}.pdf`);
    } catch (err) {
      console.error(err);
      setError('Falha ao exportar PDF.');
    } finally {
      setIsLoading(false);
    }
  }, [comparisonResult, doc1?.name, doc2?.name]);

  const handleExportCsv = useCallback(() => {
    if (!comparisonResult || !comparisonResult.rawDiffs) {
      setError('Nenhuma alteração para exportar. Por favor, compare os documentos primeiro.');
      return;
    }
    setIsLoading(true);
    try {
      exportToCsv(comparisonResult.rawDiffs, `alteracoes_${doc1?.name}_vs_${doc2?.name}.csv`);
    } catch (err) {
      console.error(err);
      setError('Falha ao exportar CSV.');
    } finally {
      setIsLoading(false);
    }
  }, [comparisonResult, doc1?.name, doc2?.name]);
  
  useEffect(() => {
    if (error) {
      const timer = setTimeout(() => {
        setError(null);
      }, 5000); // Error messages disappear after 5 seconds
      return () => clearTimeout(timer);
    }
  }, [error]);

  return (
    <div className="min-h-screen flex flex-col bg-gray-100 font-sans">
      {isLoading && <LoadingSpinner />}
      <Toolbar
        onCompare={handleCompare}
        onExportPdf={handleExportPdf}
        onExportCsv={handleExportCsv}
        canCompare={!!doc1 && !!doc2 && !isLoading}
        canExport={!!comparisonResult && !isLoading}
        isComparing={isLoading && (!doc1 || !doc2) } // More accurate isComparing
      />

      {error && (
        <div className="m-4 p-3 bg-red-100 border border-red-600 text-red-600 rounded-md flex items-center space-x-2">
          <InfoIcon className="text-red-600" size={20} />
          <span>{error}</span>
        </div>
      )}

      <main className="flex-1 flex flex-col md:flex-row p-4 gap-4 overflow-hidden">
        <div className="flex-1 flex flex-col gap-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <FileUpload
              id="file-upload-1"
              label="Documento Original (ex: Contrato Antigo)"
              onFileUpload={(file) => handleFileUpload(file, 1)}
              disabled={isLoading}
              uploadedFileName={doc1?.name}
            />
            <FileUpload
              id="file-upload-2"
              label="Documento Modificado (ex: Nova Versão)"
              onFileUpload={(file) => handleFileUpload(file, 2)}
              disabled={isLoading}
              uploadedFileName={doc2?.name}
            />
          </div>
          <ComparisonView
            htmlContent1={comparisonResult ? comparisonResult.html1 : doc1?.content || null}
            htmlContent2={comparisonResult ? comparisonResult.html2 : doc2?.content || null}
            docName1={doc1?.name}
            docName2={doc2?.name}
          />
        </div>
        {comparisonResult && showSummary && (
          <div className="md:w-auto md:max-w-sm lg:max-w-md xl:max-w-lg"> {/* Consider responsive widths for summary */}
             <DifferenceSummary summary={comparisonResult.summary} rawDiffs={comparisonResult.rawDiffs} />
          </div>
        )}
      </main>
      <footer className="text-center p-3 bg-gray-700 text-gray-100 text-xs">
        ClauseDiff MVP - Clareza Contratual Simplificada. Documentos são processados no seu navegador e não são enviados para servidores.
      </footer>
    </div>
  );
};

export default App;