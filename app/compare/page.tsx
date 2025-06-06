"use client";

import React, { useState, useCallback, useEffect } from 'react';
import { motion } from 'framer-motion';
import { DiffMatchPatchEngine } from '../../src/infrastructure/diff-engines/DiffMatchPatchEngine';
import { MyersDiffEngine } from '../../src/infrastructure/diff-engines/MyersDiffEngine';
import { SemanticDiffEngine } from '../../src/infrastructure/diff-engines/SemanticDiffEngine';
import { IDiffEngine } from '../../src/domain/interfaces/IDiffEngine';
import { DiffResult } from '../../src/domain/entities/DiffResult';
import FileUpload from '../../src/presentation/components/diff/FileUpload';
import { ModernButton } from '../../src/components/ui/modern-button';
import { ModernCard } from '../../src/components/ui/modern-card';

interface ComparePageProps {
  searchParams?: {
    engine?: string;
    mode?: string;
    theme?: string;
  };
}

type EngineType = 'diff-match-patch' | 'myers' | 'semantic' | 'auto';

export default function ComparePage({ searchParams }: ComparePageProps) {
  // State management
  const [selectedEngine] = useState<EngineType>(
    (searchParams?.engine as EngineType) || 'auto'
  );
  const [diffEngine, setDiffEngine] = useState<IDiffEngine | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [diffResult, setDiffResult] = useState<DiffResult | null>(null);
  const [showMetrics, setShowMetrics] = useState(false);

  // Initialize diff engine (client-side only)
  useEffect(() => {
    // Only run on client side
    if (typeof window === 'undefined') return;

    const initializeEngine = async () => {
      setIsLoading(true);
      setError(null);

      try {
        let engine: IDiffEngine;

        switch (selectedEngine) {
          case 'diff-match-patch':
            engine = new DiffMatchPatchEngine();
            break;
          case 'myers':
            engine = new MyersDiffEngine();
            break;
          case 'semantic':
            engine = new SemanticDiffEngine();
            break;
          case 'auto':
          default:
            engine = new DiffMatchPatchEngine(); // Default fallback
            break;
        }

        setDiffEngine(engine);
      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : 'Failed to initialize diff engine';
        setError(errorMessage);
      } finally {
        setIsLoading(false);
      }
    };

    // Add a small delay to ensure the page is fully loaded
    const timer = setTimeout(initializeEngine, 100);
    return () => clearTimeout(timer);
  }, [selectedEngine]);

  // Handle file upload and comparison
  const handleFilesSelected = useCallback(async (files: any[]) => {
    if (files.length !== 2 || !diffEngine) return;

    const [file1, file2] = files;
    if (!file1.content || !file2.content) return;

    setIsLoading(true);
    setError(null);

    try {
      const result = await diffEngine.compare({
        originalText: file1.content,
        modifiedText: file2.content
      });

      setDiffResult(result);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to compare documents';
      setError(errorMessage);
    } finally {
      setIsLoading(false);
    }
  }, [diffEngine]);

  // Render diff content with simplified view
  const renderDiffContent = () => {
    if (!diffResult) return null;

    return (
      <div className="diff-content">
                 <div className="diff-header">
           <motion.h2 
             className="diff-title"
             initial={{ opacity: 0, x: -20 }}
             animate={{ opacity: 1, x: 0 }}
             transition={{ duration: 0.5 }}
           >
             Comparação de Documentos
           </motion.h2>
           <ModernButton
             variant="outline"
             size="md"
             icon={showMetrics ? '👁️' : '📊'}
             onClick={() => setShowMetrics(!showMetrics)}
           >
             {showMetrics ? 'Ocultar Detalhes' : 'Ver Detalhes'}
           </ModernButton>
         </div>

                 {showMetrics && (
           <motion.div 
             className="metrics-panel"
             initial={{ opacity: 0, height: 0 }}
             animate={{ opacity: 1, height: 'auto' }}
             exit={{ opacity: 0, height: 0 }}
             transition={{ duration: 0.3 }}
           >
             <ModernCard variant="glass" padding="md" className="metric-card">
               <span className="metric-label">Inserções</span>
               <motion.span 
                 className="metric-value green"
                 initial={{ scale: 0 }}
                 animate={{ scale: 1 }}
                 transition={{ delay: 0.1, type: 'spring' }}
               >
                 {diffResult.statistics.additions}
               </motion.span>
             </ModernCard>
             <ModernCard variant="glass" padding="md" className="metric-card">
               <span className="metric-label">Deletions</span>
               <motion.span 
                 className="metric-value red"
                 initial={{ scale: 0 }}
                 animate={{ scale: 1 }}
                 transition={{ delay: 0.2, type: 'spring' }}
               >
                 {diffResult.statistics.deletions}
               </motion.span>
             </ModernCard>
             <ModernCard variant="glass" padding="md" className="metric-card">
               <span className="metric-label">Modificações</span>
               <motion.span 
                 className="metric-value blue"
                 initial={{ scale: 0 }}
                 animate={{ scale: 1 }}
                 transition={{ delay: 0.3, type: 'spring' }}
               >
                 {diffResult.statistics.modifications}
               </motion.span>
             </ModernCard>
           </motion.div>
         )}

        <div className="diff-view">
          {diffResult.chunks.map((chunk, index) => (
            <div 
              key={index} 
              className={`diff-line ${chunk.operation}`}
            >
              <span className="line-indicator">
                {chunk.operation === 'insert' && '+'}
                {chunk.operation === 'delete' && '-'}
                {chunk.operation === 'equal' && ' '}
              </span>
              <span className="line-content">{chunk.text}</span>
            </div>
          ))}
        </div>
      </div>
    );
  };

  return (
    <div className="compare-page">
             {/* Modern Header */}
       <header className="page-header">
         <div className="header-content">
           <motion.h1 
             className="page-title"
             initial={{ opacity: 0, x: -50 }}
             animate={{ opacity: 1, x: 0 }}
             transition={{ duration: 0.8, type: 'spring' }}
           >
             <motion.span 
               className="title-icon"
               animate={{ rotate: [0, 5, -5, 0] }}
               transition={{ duration: 2, repeat: Infinity, repeatDelay: 3 }}
             >
               ⚖️
             </motion.span>
             ClauseDiff
           </motion.h1>
           <motion.span 
             className="page-subtitle"
             initial={{ opacity: 0, y: 20 }}
             animate={{ opacity: 1, y: 0 }}
             transition={{ delay: 0.3, duration: 0.6 }}
           >
             Comparação Jurídica de Documentos
           </motion.span>
         </div>
       </header>

      {/* Main Content */}
      <main className="page-main">
                 {!diffResult && (
           <div className="upload-section">
             <ModernCard variant="glass" padding="xl" className="upload-card" gradient>
               <motion.div
                 initial={{ opacity: 0, y: 30 }}
                 animate={{ opacity: 1, y: 0 }}
                 transition={{ duration: 0.6 }}
               >
                 <h2 className="upload-title">Comparar Documentos</h2>
                 <motion.p 
                   className="upload-description"
                   initial={{ opacity: 0 }}
                   animate={{ opacity: 1 }}
                   transition={{ delay: 0.2, duration: 0.6 }}
                 >
                   Arraste e solte dois documentos para comparar suas diferenças
                 </motion.p>
                 
                 {diffEngine && (
                   <motion.div
                     initial={{ opacity: 0, scale: 0.9 }}
                     animate={{ opacity: 1, scale: 1 }}
                     transition={{ delay: 0.4, duration: 0.4 }}
                   >
                     <FileUpload
                       onFilesSelected={handleFilesSelected}
                       maxFiles={2}
                       allowedTypes={[
                         'text/plain',
                         'text/markdown', 
                         'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
                       ]}
                       dragText="Arraste 2 documentos aqui"
                       browseText="ou clique para selecionar"
                     />
                   </motion.div>
                 )}

                 {isLoading && (
                   <motion.div 
                     className="loading-state"
                     initial={{ opacity: 0 }}
                     animate={{ opacity: 1 }}
                     transition={{ duration: 0.3 }}
                   >
                     <motion.div 
                       className="spinner"
                       animate={{ rotate: 360 }}
                       transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
                     />
                     <p>Processando documentos...</p>
                   </motion.div>
                 )}

                 {error && (
                   <motion.div 
                     className="error-state"
                     initial={{ opacity: 0, scale: 0.9 }}
                     animate={{ opacity: 1, scale: 1 }}
                     transition={{ duration: 0.3 }}
                   >
                     <p className="error-message">{error}</p>
                     <ModernButton
                       variant="secondary"
                       onClick={() => setError(null)}
                       icon="🔄"
                     >
                       Tentar Novamente
                     </ModernButton>
                   </motion.div>
                 )}
               </motion.div>
             </ModernCard>
           </div>
         )}

                 {diffResult && (
           <motion.div
             initial={{ opacity: 0, y: 30 }}
             animate={{ opacity: 1, y: 0 }}
             transition={{ duration: 0.5 }}
           >
             {renderDiffContent()}
             
             {/* Botão para nova comparação */}
             <motion.div 
               className="new-comparison-section"
               initial={{ opacity: 0 }}
               animate={{ opacity: 1 }}
               transition={{ delay: 0.5, duration: 0.5 }}
             >
               <ModernButton
                 variant="outline"
                 size="lg"
                 icon="🔄"
                 onClick={() => {
                   setDiffResult(null);
                   setError(null);
                 }}
               >
                 Nova Comparação
               </ModernButton>
             </motion.div>
           </motion.div>
         )}
      </main>

      <style jsx>{`
        .compare-page {
          min-height: 100vh;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        }

        .page-header {
          background: rgba(255, 255, 255, 0.1);
          backdrop-filter: blur(10px);
          border-bottom: 1px solid rgba(255, 255, 255, 0.2);
          padding: 1.5rem 2rem;
        }

        .header-content {
          max-width: 1200px;
          margin: 0 auto;
          display: flex;
          align-items: center;
          gap: 1rem;
        }

        .page-title {
          font-size: 2rem;
          font-weight: 700;
          color: white;
          margin: 0;
          display: flex;
          align-items: center;
          gap: 0.5rem;
        }

        .title-icon {
          font-size: 2.5rem;
        }

        .page-subtitle {
          color: rgba(255, 255, 255, 0.8);
          font-size: 1rem;
          margin-left: 0.5rem;
        }

        .page-main {
          max-width: 1200px;
          margin: 0 auto;
          padding: 2rem;
        }

        .upload-section {
          display: flex;
          justify-content: center;
          align-items: center;
          min-height: 60vh;
        }

        .upload-card {
          background: rgba(255, 255, 255, 0.95);
          backdrop-filter: blur(10px);
          border-radius: 20px;
          padding: 3rem;
          text-align: center;
          box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
          border: 1px solid rgba(255, 255, 255, 0.3);
          max-width: 500px;
          width: 100%;
        }

        .upload-title {
          font-size: 2rem;
          font-weight: 600;
          color: #1a202c;
          margin-bottom: 1rem;
        }

        .upload-description {
          color: #4a5568;
          font-size: 1.1rem;
          margin-bottom: 2rem;
          line-height: 1.6;
        }

        .loading-state {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 1rem;
          padding: 2rem;
        }

        .spinner {
          width: 40px;
          height: 40px;
          border: 3px solid #e2e8f0;
          border-top: 3px solid #667eea;
          border-radius: 50%;
          animation: spin 1s linear infinite;
        }

        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }

        .error-state {
          background: rgba(254, 202, 202, 0.9);
          border: 1px solid #fc8181;
          border-radius: 12px;
          padding: 1.5rem;
          margin-top: 1rem;
        }

        .error-message {
          color: #c53030;
          margin-bottom: 1rem;
        }

        .retry-button {
          background: #e53e3e;
          color: white;
          border: none;
          padding: 0.5rem 1rem;
          border-radius: 8px;
          cursor: pointer;
          font-weight: 500;
          transition: background 0.2s;
        }

        .retry-button:hover {
          background: #c53030;
        }

        .diff-content {
          background: rgba(255, 255, 255, 0.95);
          backdrop-filter: blur(10px);
          border-radius: 20px;
          padding: 2rem;
          box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
          border: 1px solid rgba(255, 255, 255, 0.3);
        }

        .diff-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 2rem;
          padding-bottom: 1rem;
          border-bottom: 1px solid #e2e8f0;
        }

        .diff-title {
          font-size: 1.8rem;
          font-weight: 600;
          color: #1a202c;
          margin: 0;
        }

        .metrics-toggle {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          border: none;
          padding: 0.75rem 1.5rem;
          border-radius: 12px;
          cursor: pointer;
          font-weight: 500;
          transition: transform 0.2s;
        }

        .metrics-toggle:hover {
          transform: translateY(-2px);
        }

        .metrics-panel {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
          gap: 1rem;
          margin-bottom: 2rem;
        }

        .metric-card {
          background: rgba(255, 255, 255, 0.8);
          border-radius: 12px;
          padding: 1.5rem;
          text-align: center;
          box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
          border: 1px solid rgba(255, 255, 255, 0.5);
        }

        .metric-label {
          display: block;
          color: #4a5568;
          font-size: 0.9rem;
          margin-bottom: 0.5rem;
        }

        .metric-value {
          display: block;
          font-size: 2rem;
          font-weight: 700;
        }

        .metric-value.green {
          color: #38a169;
        }

        .metric-value.red {
          color: #e53e3e;
        }

        .metric-value.blue {
          color: #3182ce;
        }

        .diff-view {
          background: #1a202c;
          border-radius: 12px;
          padding: 1.5rem;
          font-family: 'Monaco', 'Menlo', monospace;
          font-size: 0.9rem;
          line-height: 1.6;
          overflow-x: auto;
        }

        .diff-line {
          display: flex;
          align-items: flex-start;
          margin-bottom: 0.25rem;
          padding: 0.25rem 0.5rem;
          border-radius: 4px;
        }

        .diff-line.insert {
          background: rgba(56, 161, 105, 0.2);
          border-left: 3px solid #38a169;
        }

        .diff-line.delete {
          background: rgba(229, 62, 62, 0.2);
          border-left: 3px solid #e53e3e;
        }

        .diff-line.equal {
          color: #e2e8f0;
        }

        .line-indicator {
          width: 20px;
          font-weight: bold;
          margin-right: 0.5rem;
          flex-shrink: 0;
        }

        .diff-line.insert .line-indicator {
          color: #38a169;
        }

        .diff-line.delete .line-indicator {
          color: #e53e3e;
        }

        .line-content {
          color: #f7fafc;
          white-space: pre-wrap;
          word-break: break-word;
        }

        .diff-line.insert .line-content {
          color: #c6f6d5;
        }

                 .diff-line.delete .line-content {
           color: #fed7d7;
         }

         .new-comparison-section {
           display: flex;
           justify-content: center;
           margin-top: 3rem;
           padding-top: 2rem;
           border-top: 1px solid rgba(255, 255, 255, 0.2);
         }

         .upload-card {
           backdrop-filter: blur(20px);
           border: 1px solid rgba(255, 255, 255, 0.18);
           box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
         }

         .metric-card {
           backdrop-filter: blur(16px);
           border: 1px solid rgba(255, 255, 255, 0.18);
           box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
         }

         /* Animação de gradiente no fundo */
         @keyframes gradientShift {
           0% { background-position: 0% 50%; }
           50% { background-position: 100% 50%; }
           100% { background-position: 0% 50%; }
         }

         .compare-page {
           background-size: 400% 400%;
           animation: gradientShift 15s ease infinite;
         }

         /* Melhorar a responsividade */
         @media (max-width: 768px) {
           .page-header {
             padding: 1rem;
           }
           
           .page-main {
             padding: 1rem;
           }
           
           .upload-card {
             max-width: 100%;
           }
           
           .metrics-panel {
             grid-template-columns: 1fr;
           }
           
           .diff-header {
             flex-direction: column;
             gap: 1rem;
             text-align: center;
           }
         }
      `}</style>
    </div>
  );
} 