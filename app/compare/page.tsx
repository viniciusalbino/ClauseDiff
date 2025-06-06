"use client";

import React, { useState, useCallback, useEffect } from 'react';
import DiffViewer from '../../src/presentation/components/diff/DiffViewer';
import { DiffMatchPatchEngine } from '../../src/infrastructure/diff-engines/DiffMatchPatchEngine';
import { MyersDiffEngine } from '../../src/infrastructure/diff-engines/MyersDiffEngine';
import { SemanticDiffEngine } from '../../src/infrastructure/diff-engines/SemanticDiffEngine';
// import { DiffEngineFactory } from '../../src/infrastructure/factories/DiffEngineFactory';
import { IDiffEngine } from '../../src/domain/interfaces/IDiffEngine';
import { DiffResult } from '../../src/domain/entities/DiffResult';

interface ComparePageProps {
  searchParams?: {
    engine?: string;
    mode?: string;
    theme?: string;
  };
}

type EngineType = 'diff-match-patch' | 'myers' | 'semantic' | 'auto';
type ViewMode = 'side-by-side' | 'inline' | 'unified';
type ThemeMode = 'light' | 'dark' | 'auto';

export default function ComparePage({ searchParams }: ComparePageProps) {
  // State management
  const [selectedEngine, setSelectedEngine] = useState<EngineType>(
    (searchParams?.engine as EngineType) || 'auto'
  );
  const [viewMode, setViewMode] = useState<ViewMode>(
    (searchParams?.mode as ViewMode) || 'side-by-side'
  );
  const [theme, setTheme] = useState<ThemeMode>(
    (searchParams?.theme as ThemeMode) || 'light'
  );
  const [diffEngine, setDiffEngine] = useState<IDiffEngine | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showWelcome, setShowWelcome] = useState(true);
  const [isFullscreen, setIsFullscreen] = useState(false);

  // Initialize diff engine (client-side only)
  useEffect(() => {
    // Only run on client side
    if (typeof window === 'undefined') return;

    const initializeEngine = async () => {
      setIsLoading(true);
      setError(null);
      console.log('Initializing engine:', selectedEngine);

      try {
        let engine: IDiffEngine;

        // Create engines directly since the factory needs registration first
        switch (selectedEngine) {
          case 'diff-match-patch':
            console.log('Creating DiffMatchPatchEngine...');
            engine = new DiffMatchPatchEngine();
            break;
          case 'myers':
            console.log('Creating MyersDiffEngine...');
            engine = new MyersDiffEngine();
            break;
          case 'semantic':
            console.log('Creating SemanticDiffEngine...');
            engine = new SemanticDiffEngine();
            break;
          case 'auto':
          default:
            console.log('Creating default DiffMatchPatchEngine...');
            engine = new DiffMatchPatchEngine(); // Default fallback
            break;
        }

        console.log('Engine created successfully:', engine.name);
        setDiffEngine(engine);
        setShowWelcome(false); // Hide welcome screen once engine is ready
      } catch (err) {
        console.error('Engine initialization failed:', err);
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

  // Handle theme changes
  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'dark') {
      root.classList.add('dark');
    } else if (theme === 'light') {
      root.classList.remove('dark');
    } else {
      // Auto theme - detect system preference
      const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
      const updateTheme = () => {
        if (mediaQuery.matches) {
          root.classList.add('dark');
        } else {
          root.classList.remove('dark');
        }
      };

      updateTheme();
      mediaQuery.addEventListener('change', updateTheme);
      return () => mediaQuery.removeEventListener('change', updateTheme);
    }
  }, [theme]);

  // Handle fullscreen
  useEffect(() => {
    const handleFullscreenChange = () => {
      setIsFullscreen(!!document.fullscreenElement);
    };

    document.addEventListener('fullscreenchange', handleFullscreenChange);
    return () => document.removeEventListener('fullscreenchange', handleFullscreenChange);
  }, []);

  // Event handlers
  const handleEngineChange = useCallback((engine: EngineType) => {
    setSelectedEngine(engine);
    setShowWelcome(false);
  }, []);

  const handleViewModeChange = useCallback((mode: ViewMode) => {
    setViewMode(mode);
  }, []);

  const handleThemeChange = useCallback((newTheme: ThemeMode) => {
    setTheme(newTheme);
  }, []);

  const handleDiffComplete = useCallback((result: DiffResult) => {
    setShowWelcome(false);
    console.log('Diff completed:', result);
  }, []);

  const handleError = useCallback((errorMessage: string) => {
    setError(errorMessage);
  }, []);

  const handleExport = useCallback((format: 'html' | 'pdf' | 'json', data: any) => {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `diff-export-${timestamp}.${format}`;

    switch (format) {
      case 'json':
        const jsonBlob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        downloadBlob(jsonBlob, filename);
        break;
      case 'html':
        const htmlContent = generateHtmlExport(data);
        const htmlBlob = new Blob([htmlContent], { type: 'text/html' });
        downloadBlob(htmlBlob, filename);
        break;
      case 'pdf':
        // In a real implementation, you'd use a library like jsPDF
        alert('PDF export will be implemented with jsPDF library');
        break;
    }
  }, []);

  // Helper function to download blob
  const downloadBlob = (blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Generate HTML export
  const generateHtmlExport = (data: any) => {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Diff Export - ClauseDiff</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 20px; }
        .header { border-bottom: 1px solid #e1e4e8; padding-bottom: 16px; margin-bottom: 24px; }
        .metadata { color: #656d76; font-size: 14px; margin-bottom: 16px; }
        .diff-content { font-family: 'SFMono-Regular', Consolas, monospace; font-size: 12px; line-height: 1.5; }
        .addition { background-color: #d4ffe0; color: #1a7f37; }
        .deletion { background-color: #ffe0e0; color: #cf222e; }
        .modification { background-color: #fff8dc; color: #9a6700; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Document Comparison Report</h1>
        <div class="metadata">
            <p>Generated: ${data.metadata?.exportedAt || new Date().toISOString()}</p>
            <p>Algorithm: ${data.diffResult?.algorithm || 'Unknown'}</p>
            <p>View Mode: ${data.viewMode || 'Unknown'}</p>
        </div>
    </div>
    <div class="diff-content">
        <!-- Diff content would be rendered here -->
        <p>Diff results exported successfully</p>
    </div>
</body>
</html>`;
  };

  // Render welcome screen
  const renderWelcome = () => (
    <div className="welcome-screen">
      <div className="welcome-content">
        <div className="welcome-hero">
          <h1>Document Comparison Tool</h1>
          <p>
            Compare documents with advanced algorithms and beautiful visualizations.
            Perfect for legal documents, contracts, and technical documentation.
          </p>
        </div>

        <div className="welcome-features">
          <div className="feature-grid">
            <div className="feature-item">
              <div className="feature-icon">🔍</div>
              <h3>Advanced Algorithms</h3>
              <p>Choose from multiple diff algorithms optimized for different content types</p>
            </div>
            
            <div className="feature-item">
              <div className="feature-icon">📊</div>
              <h3>Rich Visualizations</h3>
              <p>Side-by-side, inline, and unified views with syntax highlighting</p>
            </div>
            
            <div className="feature-item">
              <div className="feature-icon">⚡</div>
              <h3>High Performance</h3>
              <p>Optimized for large documents with intelligent caching and chunking</p>
            </div>
            
            <div className="feature-item">
              <div className="feature-icon">🎨</div>
              <h3>Beautiful UI</h3>
              <p>Modern, responsive design with light and dark themes</p>
            </div>
          </div>
        </div>

        <div className="welcome-actions">
          <div className="engine-selector">
            <h3>Choose Algorithm</h3>
            <div className="engine-options">
              <button
                className={`engine-btn ${selectedEngine === 'auto' ? 'active' : ''}`}
                onClick={() => handleEngineChange('auto')}
              >
                🤖 Auto Select
              </button>
              <button
                className={`engine-btn ${selectedEngine === 'diff-match-patch' ? 'active' : ''}`}
                onClick={() => handleEngineChange('diff-match-patch')}
              >
                ⚡ Fast (DMP)
              </button>
              <button
                className={`engine-btn ${selectedEngine === 'myers' ? 'active' : ''}`}
                onClick={() => handleEngineChange('myers')}
              >
                🎯 Precise (Myers)
              </button>
              <button
                className={`engine-btn ${selectedEngine === 'semantic' ? 'active' : ''}`}
                onClick={() => handleEngineChange('semantic')}
              >
                🧠 Smart (Semantic)
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  // Render error state
  const renderError = () => (
    <div className="error-state">
      <div className="error-content">
        <div className="error-icon">⚠️</div>
        <h2>Something went wrong</h2>
        <p>{error}</p>
        <button 
          className="retry-btn"
          onClick={() => {
            setError(null);
            setSelectedEngine('auto');
          }}
        >
          Try Again
        </button>
      </div>
    </div>
  );

  // Render loading state
  const renderLoading = () => (
    <div className="loading-state">
      <div className="loading-spinner"></div>
      <p>Initializing diff engine...</p>
    </div>
  );

  // Main render
  return (
    <div className={`compare-page ${theme} ${isFullscreen ? 'fullscreen' : ''}`}>
      <header className="page-header">
        <div className="header-content">
          <div className="header-left">
            <h1 className="page-title">
              <span className="title-icon">🔍</span>
              ClauseDiff
            </h1>
            <span className="page-subtitle">Document Comparison Tool</span>
          </div>
          
          <div className="header-right">
            <div className="theme-toggle">
              <button
                className={`theme-btn ${theme === 'light' ? 'active' : ''}`}
                onClick={() => handleThemeChange('light')}
                title="Light theme"
              >
                ☀️
              </button>
              <button
                className={`theme-btn ${theme === 'dark' ? 'active' : ''}`}
                onClick={() => handleThemeChange('dark')}
                title="Dark theme"
              >
                🌙
              </button>
              <button
                className={`theme-btn ${theme === 'auto' ? 'active' : ''}`}
                onClick={() => handleThemeChange('auto')}
                title="Auto theme"
              >
                🔄
              </button>
            </div>
          </div>
        </div>
      </header>

      <main className="page-main">
        <div style={{ padding: '10px', background: '#f0f0f0', margin: '10px', fontSize: '12px' }}>
          <strong>Debug State:</strong> Loading: {isLoading.toString()}, Error: {error || 'None'}, Engine: {diffEngine?.name || 'None'}, ShowWelcome: {(!diffEngine).toString()}
        </div>
        
        {isLoading && renderLoading()}
        {error && renderError()}
        
        {!isLoading && !error && !diffEngine && renderWelcome()}
        
        {!isLoading && !error && diffEngine && (
          <div style={{ padding: '20px' }}>
            <h2>Debug Info:</h2>
            <p>Engine: {diffEngine?.name || 'Unknown'}</p>
            <p>Loading: {isLoading.toString()}</p>
            <p>Error: {error || 'None'}</p>
            <p>Theme: {theme}</p>
            
            <div style={{ marginTop: '20px', border: '1px solid #ccc', padding: '10px' }}>
              <h3>DiffViewer Component:</h3>
              <DiffViewer
                diffEngine={diffEngine}
                initialViewMode={viewMode}
                showControls={true}
                showStats={true}
                showNavigation={true}
                showFileUpload={true}
                layout="horizontal"
                compactMode={false}
                fullHeight={false}
                theme={theme === 'auto' ? 'light' : theme}
                onViewModeChange={handleViewModeChange}
                onDiffComplete={handleDiffComplete}
                onError={(err) => {
                  console.error('DiffViewer Error:', err);
                  handleError(err);
                }}
                onExport={handleExport}
                className="main-diff-viewer"
              />
            </div>
          </div>
        )}
      </main>

      <style jsx>{`
        .compare-page {
          min-height: 100vh;
          display: flex;
          flex-direction: column;
          background-color: #ffffff;
          color: #24292f;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        }

        .compare-page.dark {
          background-color: #0d1117;
          color: #f0f6fc;
        }

        .compare-page.fullscreen {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          z-index: 9999;
        }

        .page-header {
          background-color: #f6f8fa;
          border-bottom: 1px solid #e1e4e8;
          padding: 16px 24px;
          flex-shrink: 0;
        }

        .compare-page.dark .page-header {
          background-color: #161b22;
          border-bottom-color: #30363d;
        }

        .header-content {
          display: flex;
          justify-content: space-between;
          align-items: center;
          max-width: 1200px;
          margin: 0 auto;
        }

        .header-left {
          display: flex;
          align-items: center;
          gap: 12px;
        }

        .page-title {
          margin: 0;
          font-size: 24px;
          font-weight: 700;
          color: #24292f;
          display: flex;
          align-items: center;
          gap: 8px;
        }

        .compare-page.dark .page-title {
          color: #f0f6fc;
        }

        .title-icon {
          font-size: 28px;
        }

        .page-subtitle {
          color: #656d76;
          font-size: 14px;
        }

        .compare-page.dark .page-subtitle {
          color: #8b949e;
        }

        .theme-toggle {
          display: flex;
          gap: 4px;
          background-color: #ffffff;
          border: 1px solid #d0d7de;
          border-radius: 6px;
          padding: 4px;
        }

        .compare-page.dark .theme-toggle {
          background-color: #21262d;
          border-color: #30363d;
        }

        .theme-btn {
          background: none;
          border: none;
          padding: 6px 10px;
          border-radius: 4px;
          cursor: pointer;
          font-size: 16px;
          transition: background-color 0.15s ease;
        }

        .theme-btn:hover {
          background-color: #f3f4f6;
        }

        .theme-btn.active {
          background-color: #0969da;
        }

        .compare-page.dark .theme-btn:hover {
          background-color: #30363d;
        }

        .compare-page.dark .theme-btn.active {
          background-color: #58a6ff;
        }

        .page-main {
          flex: 1;
          display: flex;
          flex-direction: column;
          overflow: hidden;
        }

        .welcome-screen {
          flex: 1;
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 32px;
          text-align: center;
        }

        .welcome-content {
          max-width: 800px;
          width: 100%;
        }

        .welcome-hero h1 {
          font-size: 48px;
          font-weight: 700;
          margin: 0 0 16px 0;
          background: linear-gradient(135deg, #0969da, #7c3aed);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          background-clip: text;
        }

        .welcome-hero p {
          font-size: 18px;
          color: #656d76;
          margin-bottom: 48px;
          line-height: 1.6;
        }

        .compare-page.dark .welcome-hero p {
          color: #8b949e;
        }

        .feature-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 24px;
          margin-bottom: 48px;
        }

        .feature-item {
          padding: 24px;
          background-color: #f6f8fa;
          border: 1px solid #e1e4e8;
          border-radius: 8px;
          transition: transform 0.15s ease, box-shadow 0.15s ease;
        }

        .feature-item:hover {
          transform: translateY(-2px);
          box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }

        .compare-page.dark .feature-item {
          background-color: #161b22;
          border-color: #30363d;
        }

        .feature-icon {
          font-size: 32px;
          margin-bottom: 12px;
        }

        .feature-item h3 {
          margin: 0 0 8px 0;
          font-size: 16px;
          font-weight: 600;
        }

        .feature-item p {
          margin: 0;
          font-size: 14px;
          color: #656d76;
          line-height: 1.5;
        }

        .compare-page.dark .feature-item p {
          color: #8b949e;
        }

        .engine-selector h3 {
          margin: 0 0 16px 0;
          font-size: 18px;
          font-weight: 600;
        }

        .engine-options {
          display: flex;
          gap: 12px;
          justify-content: center;
          flex-wrap: wrap;
        }

        .engine-btn {
          background-color: #ffffff;
          border: 2px solid #d0d7de;
          border-radius: 8px;
          padding: 12px 20px;
          cursor: pointer;
          font-size: 14px;
          font-weight: 500;
          transition: all 0.15s ease;
          display: flex;
          align-items: center;
          gap: 8px;
        }

        .engine-btn:hover {
          border-color: #0969da;
          box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }

        .engine-btn.active {
          background-color: #0969da;
          border-color: #0969da;
          color: white;
        }

        .compare-page.dark .engine-btn {
          background-color: #21262d;
          border-color: #30363d;
          color: #f0f6fc;
        }

        .compare-page.dark .engine-btn:hover {
          border-color: #58a6ff;
        }

        .compare-page.dark .engine-btn.active {
          background-color: #58a6ff;
          border-color: #58a6ff;
          color: #0d1117;
        }

        .loading-state,
        .error-state {
          flex: 1;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
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

        .compare-page.dark .loading-spinner {
          border-color: #30363d;
          border-top-color: #58a6ff;
        }

        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }

        .error-icon {
          font-size: 48px;
          margin-bottom: 16px;
        }

        .error-content h2 {
          margin: 0 0 8px 0;
          font-size: 24px;
          color: #cf222e;
        }

        .compare-page.dark .error-content h2 {
          color: #f85149;
        }

        .retry-btn {
          background-color: #0969da;
          color: white;
          border: none;
          border-radius: 6px;
          padding: 8px 16px;
          cursor: pointer;
          font-size: 14px;
          margin-top: 16px;
          transition: background-color 0.15s ease;
        }

        .retry-btn:hover {
          background-color: #0860ca;
        }

        .compare-page.dark .retry-btn {
          background-color: #58a6ff;
          color: #0d1117;
        }

        .compare-page.dark .retry-btn:hover {
          background-color: #4493f8;
        }

        .main-diff-viewer {
          flex: 1;
          height: 100%;
        }

        @media (max-width: 768px) {
          .header-content {
            flex-direction: column;
            gap: 16px;
            text-align: center;
          }

          .welcome-hero h1 {
            font-size: 36px;
          }

          .feature-grid {
            grid-template-columns: 1fr;
            gap: 16px;
          }

          .engine-options {
            flex-direction: column;
            align-items: center;
          }

          .engine-btn {
            width: 200px;
            justify-content: center;
          }
        }

        @media (max-width: 480px) {
          .page-header {
            padding: 12px 16px;
          }

          .welcome-screen {
            padding: 16px;
          }

          .welcome-hero h1 {
            font-size: 28px;
          }

          .welcome-hero p {
            font-size: 16px;
          }
        }
      `}</style>
    </div>
  );
} 