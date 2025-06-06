import React, { useState, useCallback, useMemo, useEffect } from 'react';
import { DiffResult } from '../../../domain/entities/DiffResult';
import { IDiffEngine } from '../../../domain/interfaces/IDiffEngine';
import DiffSideBySide from './DiffSideBySide';
import DiffInline from './DiffInline';
import DiffNavigation from './DiffNavigation';
import DiffStats from './DiffStats';
import DiffControls from './DiffControls';
import FileUpload, { UploadedFile } from './FileUpload';
import ErrorBoundary from '../ErrorBoundary';
import LoadingState from '../LoadingState';
import useSynchronizedScrolling from '../../hooks/useSynchronizedScrolling';
import useCollapsibleSections from '../../hooks/useCollapsibleSections';
import useErrorHandler from '../../hooks/useErrorHandler';

export interface DiffViewerProps {
  // Core diff data
  diffEngine?: IDiffEngine;
  originalText?: string;
  modifiedText?: string;
  diffResult?: DiffResult;
  
  // View options
  initialViewMode?: 'side-by-side' | 'inline' | 'unified';
  showControls?: boolean;
  showStats?: boolean;
  showNavigation?: boolean;
  showFileUpload?: boolean;
  
  // Layout options
  layout?: 'horizontal' | 'vertical';
  compactMode?: boolean;
  fullHeight?: boolean;
  
  // Theme
  theme?: 'light' | 'dark' | 'auto';
  
  // Event handlers
  onViewModeChange?: (mode: 'side-by-side' | 'inline' | 'unified') => void;
  onDiffComplete?: (result: DiffResult) => void;
  onError?: (error: string) => void;
  onExport?: (format: 'html' | 'pdf' | 'json', data: any) => void;
  
  className?: string;
}

interface ViewerState {
  isLoading: boolean;
  error: string | null;
  currentDiffResult: DiffResult | null;
  uploadedFiles: UploadedFile[];
  processingProgress: number;
}

/**
 * Componente principal de visualização de diff
 * Integra todos os componentes de diff em uma interface coesa
 */
export const DiffViewer: React.FC<DiffViewerProps> = ({
  diffEngine,
  originalText = '',
  modifiedText = '',
  diffResult: propDiffResult,
  
  initialViewMode = 'side-by-side',
  showControls = true,
  showStats = true,
  showNavigation = true,
  showFileUpload = true,
  
  layout = 'horizontal',
  compactMode = false,
  fullHeight = false,
  
  theme = 'light',
  
  onViewModeChange,
  onDiffComplete,
  onError,
  onExport,
  
  className = ''
}) => {
  // Enhanced error handling
  const errorHandler = useErrorHandler({
    maxRetries: 3,
    enableAutoRetry: true,
    logErrors: true,
    onError: (errorInfo) => {
      onError?.(errorInfo.message);
    },
    onRecover: () => {
      console.log('Error recovered successfully');
    }
  });

  // State management
  const [state, setState] = useState<ViewerState>({
    isLoading: false,
    error: null,
    currentDiffResult: propDiffResult || null,
    uploadedFiles: [],
    processingProgress: 0
  });

  // View controls state
  const [viewMode, setViewMode] = useState(initialViewMode);
  const [showLineNumbers, setShowLineNumbers] = useState(true);
  const [showWhitespace, setShowWhitespace] = useState(false);
  const [syntaxHighlighting, setSyntaxHighlighting] = useState(true);
  const [semanticHighlighting, setSemanticHighlighting] = useState(true);
  const [showOnlyChanges, setShowOnlyChanges] = useState(false);
  const [hideUnchanged, setHideUnchanged] = useState(false);
  const [contextLines, setContextLines] = useState(3);
  const [autoCollapse, setAutoCollapse] = useState(true);
  const [collapseThreshold, setCollapseThreshold] = useState(20);
  const [syncScrolling, setSyncScrolling] = useState(true);
  const [smoothScrolling, setSmoothScrolling] = useState(true);
  const [currentTheme, setCurrentTheme] = useState(theme);

  // Hooks for advanced functionality
  const synchronizedScrolling = useSynchronizedScrolling({
    enabled: syncScrolling,
    smoothScrolling,
    syncHorizontal: true,
    syncVertical: true
  });

  const collapsibleSections = useCollapsibleSections(
    state.currentDiffResult || { chunks: [], algorithm: 'none' } as any,
    {
      autoCollapseThreshold: collapseThreshold,
      enableKeyboardShortcuts: true
    }
  );

  // Memoized processed texts
  const processedTexts = useMemo(() => {
    if (state.uploadedFiles.length >= 2) {
      const originalFile = state.uploadedFiles[0];
      const modifiedFile = state.uploadedFiles[1];
      return {
        original: originalFile?.content || '',
        modified: modifiedFile?.content || ''
      };
    }
    return {
      original: originalText,
      modified: modifiedText
    };
  }, [state.uploadedFiles, originalText, modifiedText]);

  // Process diff when texts change
  useEffect(() => {
    if (propDiffResult) {
      setState(prev => ({ ...prev, currentDiffResult: propDiffResult }));
      return;
    }

    if (!diffEngine || !processedTexts.original || !processedTexts.modified) {
      return;
    }

    const processDiff = async () => {
      setState(prev => ({ ...prev, isLoading: true, error: null, processingProgress: 0 }));

      try {
        // Simulate progress updates
        const progressInterval = setInterval(() => {
          setState(prev => ({
            ...prev,
            processingProgress: Math.min(prev.processingProgress + 10, 90)
          }));
        }, 100);

        const result = await diffEngine.compare({
          originalText: processedTexts.original,
          modifiedText: processedTexts.modified
        });

        clearInterval(progressInterval);

        setState(prev => ({
          ...prev,
          isLoading: false,
          currentDiffResult: result,
          processingProgress: 100
        }));

        onDiffComplete?.(result);
      } catch (error) {
        const err = error instanceof Error ? error : new Error('Failed to process diff');
        
        // Use enhanced error handling
        const errorInfo = errorHandler.handleError(err, {
          originalLength: processedTexts.original.length,
          modifiedLength: processedTexts.modified.length,
          engine: diffEngine.constructor.name
        }, 'document_comparison');

        setState(prev => ({
          ...prev,
          isLoading: false,
          error: errorInfo.message,
          processingProgress: 0
        }));
      }
    };

    processDiff();
  }, [diffEngine, processedTexts, propDiffResult, onDiffComplete, onError]);

  // Handle view mode change
  const handleViewModeChange = useCallback((mode: 'side-by-side' | 'inline' | 'unified') => {
    setViewMode(mode);
    onViewModeChange?.(mode);
  }, [onViewModeChange]);

  // Handle file upload
  const handleFilesSelected = useCallback((files: UploadedFile[]) => {
    setState(prev => {
      const newFiles = [...prev.uploadedFiles, ...files];
      return {
        ...prev,
        uploadedFiles: newFiles
      };
    });
  }, []);

  const handleFileRemove = useCallback((fileId: string) => {
    setState(prev => ({
      ...prev,
      uploadedFiles: prev.uploadedFiles.filter(f => f.id !== fileId),
      currentDiffResult: null // Clear diff when files change
    }));
  }, []);

  // Auto-process diff when exactly 2 files are uploaded and completed
  useEffect(() => {
    const completedFiles = state.uploadedFiles.filter(f => f.status === 'completed');
    
    console.log('DiffViewer: Checking files for auto-processing', {
      totalFiles: state.uploadedFiles.length,
      completedFiles: completedFiles.length,
      filesWithContent: completedFiles.filter(f => f.content).length,
      isLoading: state.isLoading,
      hasDiffResult: !!state.currentDiffResult,
      hasDiffEngine: !!diffEngine,
      files: completedFiles.map(f => ({ name: f.name, hasContent: !!f.content, contentLength: f.content?.length || 0 }))
    });
    
    if (completedFiles.length === 2 && !state.isLoading && !state.currentDiffResult && diffEngine) {
      const [file1, file2] = completedFiles;
      
      // Check if both files have content (for text files) or are ready for processing
      const canProcess = (file1.content && file2.content) || 
                        (file1.status === 'completed' && file2.status === 'completed');
      
      if (canProcess) {
        console.log('DiffViewer: Starting auto-processing', { file1: file1.name, file2: file2.name });
        
        // Process diff automatically
        const processDiff = async () => {
          setState(prev => ({ ...prev, isLoading: true, error: null, processingProgress: 0 }));
          
          try {
            // For non-text files, show a message that they need manual processing
            if (!file1.content || !file2.content) {
              setState(prev => ({
                ...prev,
                isLoading: false,
                error: 'Document files (.docx, .pdf) are uploaded but content extraction is not yet implemented. Please use text files (.txt) for now.',
                processingProgress: 0
              }));
              return;
            }
            
            // Simulate progress updates
            const progressInterval = setInterval(() => {
              setState(prev => ({
                ...prev,
                processingProgress: Math.min(prev.processingProgress + 10, 90)
              }));
            }, 100);

            const result = await diffEngine!.compare({
              originalText: file1.content || '',
              modifiedText: file2.content || ''
            });

            clearInterval(progressInterval);

            setState(prev => ({
              ...prev,
              isLoading: false,
              currentDiffResult: result,
              processingProgress: 100
            }));

            onDiffComplete?.(result);
            console.log('DiffViewer: Auto-processing completed successfully');
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Failed to process diff';
            setState(prev => ({
              ...prev,
              isLoading: false,
              error: errorMessage,
              processingProgress: 0
            }));
            errorHandler.handleError(error as Error, { files: completedFiles.map(f => f.name) }, 'auto_diff_processing');
            console.error('DiffViewer: Auto-processing failed', error);
          }
        };

        processDiff();
      } else {
        console.log('DiffViewer: Files not ready for processing', {
          file1HasContent: !!file1.content,
          file2HasContent: !!file2.content
        });
      }
    }
  }, [state.uploadedFiles, state.isLoading, state.currentDiffResult, diffEngine, onDiffComplete, errorHandler]);

  // Handle export
  const handleExport = useCallback((format: 'html' | 'pdf' | 'json') => {
    if (!state.currentDiffResult) return;

    const exportData = {
      diffResult: state.currentDiffResult,
      viewMode,
      settings: {
        showLineNumbers,
        showWhitespace,
        syntaxHighlighting,
        semanticHighlighting,
        contextLines
      },
      metadata: {
        exportedAt: new Date().toISOString(),
        format,
        version: '1.0'
      }
    };

    onExport?.(format, exportData);
  }, [state.currentDiffResult, viewMode, showLineNumbers, showWhitespace, syntaxHighlighting, semanticHighlighting, contextLines, onExport]);

  // Handle reset
  const handleReset = useCallback(() => {
    setState(prev => ({
      ...prev,
      uploadedFiles: [],
      currentDiffResult: null,
      error: null,
      processingProgress: 0
    }));
    
    // Reset to defaults
    setViewMode(initialViewMode);
    setShowLineNumbers(true);
    setShowWhitespace(false);
    setSyntaxHighlighting(true);
    setSemanticHighlighting(true);
    setShowOnlyChanges(false);
    setHideUnchanged(false);
    setContextLines(3);
    setAutoCollapse(true);
    setCollapseThreshold(20);
    setSyncScrolling(true);
    setSmoothScrolling(true);
  }, [initialViewMode]);

  // Handle fullscreen toggle
  const handleToggleFullscreen = useCallback(() => {
    if (document.fullscreenElement) {
      document.exitFullscreen();
    } else {
      document.documentElement.requestFullscreen();
    }
  }, []);

  // Render loading state
  const renderLoadingState = () => (
    <LoadingState
      variant="progress"
      size="medium"
      text="Processing diff..."
      subtext="Analyzing document differences"
      progress={state.processingProgress}
      showProgress={true}
      theme={currentTheme === 'auto' ? 'light' : currentTheme as 'light' | 'dark'}
      fullHeight={true}
    />
  );

  // Render error state
  const renderErrorState = () => (
    <div className="error-state">
      <div className="error-icon">⚠️</div>
      <div className="error-message">{state.error}</div>
      <button className="retry-btn" onClick={handleReset}>
        Try Again
      </button>
    </div>
  );

  // Render empty state
  const renderEmptyState = () => (
    <div className="empty-state">
      <div className="empty-icon">📄</div>
      <div className="empty-title">No files to compare</div>
      <div className="empty-subtitle">
        {showFileUpload ? 'Upload files above to get started' : 'Provide text content to compare'}
      </div>
    </div>
  );

  // Render diff content
  const renderDiffContent = () => {
    if (!state.currentDiffResult) return renderEmptyState();

    const commonProps = {
      diffResult: state.currentDiffResult,
      showLineNumbers,
      showWhitespace,
      syntaxHighlighting,
      semanticHighlighting,
      theme: currentTheme,
      onLineClick: (lineNumber: number) => {
        console.log('Line clicked:', lineNumber);
      }
    };

    switch (viewMode) {
      case 'side-by-side':
        return (
          <DiffSideBySide
            {...commonProps}
            syncScrolling={syncScrolling}
            collapsibleSections={collapsibleSections}
          />
        );
      
      case 'inline':
        return (
          <DiffInline
            {...commonProps}
            showOnlyChanges={showOnlyChanges}
            contextLines={contextLines}
            collapsibleSections={collapsibleSections}
          />
        );
      
      case 'unified':
        return (
          <div className="unified-view">
            <pre className="unified-content">
              {state.currentDiffResult.chunks.map((chunk, index) => 
                `${chunk.operation === 'insert' ? '+' : chunk.operation === 'delete' ? '-' : ' '}${chunk.text}`
              ).join('\n')}
            </pre>
          </div>
        );
      
      default:
        return renderEmptyState();
    }
  };

  return (
    <ErrorBoundary
      level="section"
      enableRetry={true}
      maxRetries={3}
      onError={(error, errorInfo) => {
        errorHandler.handleError(error, { component: 'DiffViewer' }, 'render_error');
      }}
    >
      <div className={`diff-viewer ${currentTheme} ${layout} ${compactMode ? 'compact' : ''} ${fullHeight ? 'full-height' : ''} ${className}`}>
      {showFileUpload && (
        <div className="file-upload-section">
          <FileUpload
            onFilesSelected={handleFilesSelected}
            onFileRemove={handleFileRemove}
            maxFiles={2}
            theme={currentTheme}
            compact={compactMode}
            uploadText="Select files to compare"
            dragText="Drag files here"
            browseText="or browse"
          />
        </div>
      )}

      <div className="viewer-main">
        {showControls && (
          <div className="controls-panel">
            <DiffControls
              viewMode={viewMode}
              onViewModeChange={handleViewModeChange}
              showLineNumbers={showLineNumbers}
              onShowLineNumbersChange={setShowLineNumbers}
              showWhitespace={showWhitespace}
              onShowWhitespaceChange={setShowWhitespace}
              syntaxHighlighting={syntaxHighlighting}
              onSyntaxHighlightingChange={setSyntaxHighlighting}
              semanticHighlighting={semanticHighlighting}
              onSemanticHighlightingChange={setSemanticHighlighting}
              showOnlyChanges={showOnlyChanges}
              onShowOnlyChangesChange={setShowOnlyChanges}
              hideUnchanged={hideUnchanged}
              onHideUnchangedChange={setHideUnchanged}
              contextLines={contextLines}
              onContextLinesChange={setContextLines}
              autoCollapse={autoCollapse}
              onAutoCollapseChange={setAutoCollapse}
              collapseThreshold={collapseThreshold}
              onCollapseThresholdChange={setCollapseThreshold}
              syncScrolling={syncScrolling}
              onSyncScrollingChange={setSyncScrolling}
              smoothScrolling={smoothScrolling}
              onSmoothScrollingChange={setSmoothScrolling}
              theme={currentTheme}
              onThemeChange={setCurrentTheme}
              compact={compactMode}
              onExport={handleExport}
              onReset={handleReset}
              onToggleFullscreen={handleToggleFullscreen}
            />
          </div>
        )}

        <div className="content-area">
          <div className="diff-content">
            {state.isLoading && renderLoadingState()}
            {state.error && renderErrorState()}
            {!state.isLoading && !state.error && renderDiffContent()}
          </div>

          {showNavigation && state.currentDiffResult && (
            <div className="navigation-panel">
              <DiffNavigation
                diffResult={state.currentDiffResult}
                theme={currentTheme}
                compact={compactMode}
                onNavigateToChange={(change) => {
                  synchronizedScrolling.scrollToElement(
                    `[data-line="${change.lineNumber}"]`
                  );
                }}
              />
            </div>
          )}
        </div>

        {showStats && state.currentDiffResult && (
          <div className="stats-panel">
            <DiffStats
              diffResult={state.currentDiffResult}
              theme={currentTheme}
              compact={compactMode}
              onMetricClick={(metric, value) => {
                console.log('Metric clicked:', metric, value);
              }}
            />
          </div>
        )}
      </div>

      <style jsx>{`
        .diff-viewer {
          display: flex;
          flex-direction: column;
          height: 100%;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          background-color: #ffffff;
          color: #24292f;
        }

        .diff-viewer.dark {
          background-color: #0d1117;
          color: #f0f6fc;
        }

        .diff-viewer.full-height {
          height: 100vh;
        }

        .file-upload-section {
          padding: 16px;
          border-bottom: 1px solid #e1e4e8;
        }

        .diff-viewer.dark .file-upload-section {
          border-bottom-color: #30363d;
        }

        .viewer-main {
          display: flex;
          flex: 1;
          overflow: hidden;
        }

        .diff-viewer.vertical .viewer-main {
          flex-direction: column;
        }

        .controls-panel {
          flex-shrink: 0;
          border-right: 1px solid #e1e4e8;
          overflow-y: auto;
        }

        .diff-viewer.vertical .controls-panel {
          border-right: none;
          border-bottom: 1px solid #e1e4e8;
        }

        .diff-viewer.dark .controls-panel {
          border-right-color: #30363d;
        }

        .diff-viewer.dark.vertical .controls-panel {
          border-bottom-color: #30363d;
        }

        .content-area {
          display: flex;
          flex: 1;
          overflow: hidden;
        }

        .diff-viewer.vertical .content-area {
          flex-direction: column;
        }

        .diff-content {
          flex: 1;
          overflow: auto;
          position: relative;
        }

        .navigation-panel {
          flex-shrink: 0;
          border-left: 1px solid #e1e4e8;
          overflow-y: auto;
        }

        .diff-viewer.vertical .navigation-panel {
          border-left: none;
          border-top: 1px solid #e1e4e8;
        }

        .diff-viewer.dark .navigation-panel {
          border-left-color: #30363d;
        }

        .diff-viewer.dark.vertical .navigation-panel {
          border-top-color: #30363d;
        }

        .stats-panel {
          flex-shrink: 0;
          border-left: 1px solid #e1e4e8;
          overflow-y: auto;
          width: 300px;
        }

        .diff-viewer.vertical .stats-panel {
          border-left: none;
          border-top: 1px solid #e1e4e8;
          width: auto;
          height: 200px;
        }

        .diff-viewer.dark .stats-panel {
          border-left-color: #30363d;
        }

        .diff-viewer.dark.vertical .stats-panel {
          border-top-color: #30363d;
        }

        .loading-state,
        .error-state,
        .empty-state {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          height: 300px;
          text-align: center;
          padding: 32px;
        }

        .loading-spinner {
          width: 32px;
          height: 32px;
          border: 3px solid #e1e4e8;
          border-top: 3px solid #0969da;
          border-radius: 50%;
          animation: spin 1s linear infinite;
          margin-bottom: 16px;
        }

        .diff-viewer.dark .loading-spinner {
          border-color: #30363d;
          border-top-color: #58a6ff;
        }

        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }

        .loading-text {
          font-size: 16px;
          color: #656d76;
          margin-bottom: 16px;
        }

        .diff-viewer.dark .loading-text {
          color: #8b949e;
        }

        .progress-bar {
          width: 200px;
          height: 4px;
          background-color: #e1e4e8;
          border-radius: 2px;
          overflow: hidden;
        }

        .diff-viewer.dark .progress-bar {
          background-color: #30363d;
        }

        .progress-fill {
          height: 100%;
          background-color: #0969da;
          transition: width 0.3s ease;
        }

        .diff-viewer.dark .progress-fill {
          background-color: #58a6ff;
        }

        .error-icon,
        .empty-icon {
          font-size: 48px;
          margin-bottom: 16px;
          opacity: 0.7;
        }

        .error-message,
        .empty-title {
          font-size: 18px;
          font-weight: 600;
          margin-bottom: 8px;
          color: #24292f;
        }

        .diff-viewer.dark .error-message,
        .diff-viewer.dark .empty-title {
          color: #f0f6fc;
        }

        .empty-subtitle {
          color: #656d76;
          margin-bottom: 16px;
        }

        .diff-viewer.dark .empty-subtitle {
          color: #8b949e;
        }

        .retry-btn {
          background-color: #0969da;
          color: white;
          border: none;
          border-radius: 6px;
          padding: 8px 16px;
          cursor: pointer;
          font-size: 14px;
          transition: background-color 0.15s ease;
        }

        .retry-btn:hover {
          background-color: #0860ca;
        }

        .diff-viewer.dark .retry-btn {
          background-color: #58a6ff;
          color: #0d1117;
        }

        .diff-viewer.dark .retry-btn:hover {
          background-color: #4493f8;
        }

        .unified-view {
          padding: 16px;
          height: 100%;
          overflow: auto;
        }

        .unified-content {
          font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
          font-size: 12px;
          line-height: 1.5;
          white-space: pre-wrap;
          margin: 0;
          color: #24292f;
        }

        .diff-viewer.dark .unified-content {
          color: #f0f6fc;
        }

        .diff-viewer.compact .file-upload-section {
          padding: 12px;
        }

        .diff-viewer.compact .loading-state,
        .diff-viewer.compact .error-state,
        .diff-viewer.compact .empty-state {
          height: 200px;
          padding: 16px;
        }

        .diff-viewer.compact .stats-panel {
          width: 250px;
        }

        .diff-viewer.compact.vertical .stats-panel {
          height: 150px;
        }
      `}</style>
    </div>
    </ErrorBoundary>
  );
};

export default DiffViewer; 