import React, { useState, useCallback } from 'react';

export interface DiffControlsProps {
  // View options
  viewMode?: 'side-by-side' | 'inline' | 'unified';
  onViewModeChange?: (mode: 'side-by-side' | 'inline' | 'unified') => void;
  
  // Display options
  showLineNumbers?: boolean;
  onShowLineNumbersChange?: (show: boolean) => void;
  
  showWhitespace?: boolean;
  onShowWhitespaceChange?: (show: boolean) => void;
  
  syntaxHighlighting?: boolean;
  onSyntaxHighlightingChange?: (enabled: boolean) => void;
  
  semanticHighlighting?: boolean;
  onSemanticHighlightingChange?: (enabled: boolean) => void;
  
  // Filter options
  showOnlyChanges?: boolean;
  onShowOnlyChangesChange?: (show: boolean) => void;
  
  hideUnchanged?: boolean;
  onHideUnchangedChange?: (hide: boolean) => void;
  
  // Context options
  contextLines?: number;
  onContextLinesChange?: (lines: number) => void;
  
  // Collapse options
  autoCollapse?: boolean;
  onAutoCollapseChange?: (enabled: boolean) => void;
  
  collapseThreshold?: number;
  onCollapseThresholdChange?: (threshold: number) => void;
  
  // Sync options
  syncScrolling?: boolean;
  onSyncScrollingChange?: (sync: boolean) => void;
  
  smoothScrolling?: boolean;
  onSmoothScrollingChange?: (smooth: boolean) => void;
  
  // Theme
  theme?: 'light' | 'dark' | 'auto';
  onThemeChange?: (theme: 'light' | 'dark' | 'auto') => void;
  
  // Layout
  compact?: boolean;
  orientation?: 'horizontal' | 'vertical';
  className?: string;
  
  // Actions
  onExport?: (format: 'html' | 'pdf' | 'json') => void;
  onReset?: () => void;
  onToggleFullscreen?: () => void;
}

interface ControlSection {
  id: string;
  title: string;
  icon: string;
  expanded: boolean;
}

/**
 * Componente de controles avançados para visualização de diff
 * Oferece controle fino sobre todas as opções de exibição e comportamento
 */
export const DiffControls: React.FC<DiffControlsProps> = ({
  viewMode = 'side-by-side',
  onViewModeChange,
  
  showLineNumbers = true,
  onShowLineNumbersChange,
  
  showWhitespace = false,
  onShowWhitespaceChange,
  
  syntaxHighlighting = true,
  onSyntaxHighlightingChange,
  
  semanticHighlighting = true,
  onSemanticHighlightingChange,
  
  showOnlyChanges = false,
  onShowOnlyChangesChange,
  
  hideUnchanged = false,
  onHideUnchangedChange,
  
  contextLines = 3,
  onContextLinesChange,
  
  autoCollapse = true,
  onAutoCollapseChange,
  
  collapseThreshold = 20,
  onCollapseThresholdChange,
  
  syncScrolling = true,
  onSyncScrollingChange,
  
  smoothScrolling = true,
  onSmoothScrollingChange,
  
  theme = 'light',
  onThemeChange,
  
  compact = false,
  orientation = 'vertical',
  className = '',
  
  onExport,
  onReset,
  onToggleFullscreen
}) => {
  const [expandedSections, setExpandedSections] = useState<Set<string>>(
    new Set(['view', 'display'])
  );

  const [showAdvanced, setShowAdvanced] = useState(false);

  const toggleSection = useCallback((sectionId: string) => {
    setExpandedSections(prev => {
      const newSet = new Set(prev);
      if (newSet.has(sectionId)) {
        newSet.delete(sectionId);
      } else {
        newSet.add(sectionId);
      }
      return newSet;
    });
  }, []);

  const isSectionExpanded = (sectionId: string) => expandedSections.has(sectionId);

  const renderViewModeControls = () => (
    <div className="control-section view-mode">
      <div 
        className="section-header"
        onClick={() => toggleSection('view')}
      >
        <span className="section-icon">👁️</span>
        <span className="section-title">View Mode</span>
        <span className="section-toggle">
          {isSectionExpanded('view') ? '▼' : '▶'}
        </span>
      </div>
      
      {isSectionExpanded('view') && (
        <div className="section-content">
          <div className="button-group">
            <button
              className={`mode-btn ${viewMode === 'side-by-side' ? 'active' : ''}`}
              onClick={() => onViewModeChange?.('side-by-side')}
              title="Side by side comparison"
            >
              <span className="btn-icon">⏸️</span>
              Side by Side
            </button>
            
            <button
              className={`mode-btn ${viewMode === 'inline' ? 'active' : ''}`}
              onClick={() => onViewModeChange?.('inline')}
              title="Inline unified view"
            >
              <span className="btn-icon">📄</span>
              Inline
            </button>
            
            <button
              className={`mode-btn ${viewMode === 'unified' ? 'active' : ''}`}
              onClick={() => onViewModeChange?.('unified')}
              title="Unified diff format"
            >
              <span className="btn-icon">📋</span>
              Unified
            </button>
          </div>
        </div>
      )}
    </div>
  );

  const renderDisplayControls = () => (
    <div className="control-section display">
      <div 
        className="section-header"
        onClick={() => toggleSection('display')}
      >
        <span className="section-icon">🎨</span>
        <span className="section-title">Display</span>
        <span className="section-toggle">
          {isSectionExpanded('display') ? '▼' : '▶'}
        </span>
      </div>
      
      {isSectionExpanded('display') && (
        <div className="section-content">
          <div className="toggle-controls">
            <label className="toggle-item">
              <input
                type="checkbox"
                checked={showLineNumbers}
                onChange={(e) => onShowLineNumbersChange?.(e.target.checked)}
              />
              <span className="toggle-label">Line Numbers</span>
            </label>
            
            <label className="toggle-item">
              <input
                type="checkbox"
                checked={showWhitespace}
                onChange={(e) => onShowWhitespaceChange?.(e.target.checked)}
              />
              <span className="toggle-label">Show Whitespace</span>
            </label>
            
            <label className="toggle-item">
              <input
                type="checkbox"
                checked={syntaxHighlighting}
                onChange={(e) => onSyntaxHighlightingChange?.(e.target.checked)}
              />
              <span className="toggle-label">Syntax Highlighting</span>
            </label>
            
            <label className="toggle-item">
              <input
                type="checkbox"
                checked={semanticHighlighting}
                onChange={(e) => onSemanticHighlightingChange?.(e.target.checked)}
              />
              <span className="toggle-label">Semantic Highlighting</span>
            </label>
          </div>
        </div>
      )}
    </div>
  );

  const renderFilterControls = () => (
    <div className="control-section filters">
      <div 
        className="section-header"
        onClick={() => toggleSection('filters')}
      >
        <span className="section-icon">🔍</span>
        <span className="section-title">Filters</span>
        <span className="section-toggle">
          {isSectionExpanded('filters') ? '▼' : '▶'}
        </span>
      </div>
      
      {isSectionExpanded('filters') && (
        <div className="section-content">
          <div className="toggle-controls">
            <label className="toggle-item">
              <input
                type="checkbox"
                checked={showOnlyChanges}
                onChange={(e) => onShowOnlyChangesChange?.(e.target.checked)}
              />
              <span className="toggle-label">Show Only Changes</span>
            </label>
            
            <label className="toggle-item">
              <input
                type="checkbox"
                checked={hideUnchanged}
                onChange={(e) => onHideUnchangedChange?.(e.target.checked)}
              />
              <span className="toggle-label">Hide Unchanged Lines</span>
            </label>
          </div>
          
          <div className="range-control">
            <label className="range-label">
              Context Lines: {contextLines}
            </label>
            <input
              type="range"
              min="0"
              max="10"
              value={contextLines}
              onChange={(e) => onContextLinesChange?.(parseInt(e.target.value))}
              className="range-slider"
            />
            <div className="range-marks">
              <span>0</span>
              <span>5</span>
              <span>10</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );

  const renderCollapseControls = () => (
    <div className="control-section collapse">
      <div 
        className="section-header"
        onClick={() => toggleSection('collapse')}
      >
        <span className="section-icon">📁</span>
        <span className="section-title">Collapse</span>
        <span className="section-toggle">
          {isSectionExpanded('collapse') ? '▼' : '▶'}
        </span>
      </div>
      
      {isSectionExpanded('collapse') && (
        <div className="section-content">
          <div className="toggle-controls">
            <label className="toggle-item">
              <input
                type="checkbox"
                checked={autoCollapse}
                onChange={(e) => onAutoCollapseChange?.(e.target.checked)}
              />
              <span className="toggle-label">Auto Collapse Large Sections</span>
            </label>
          </div>
          
          <div className="range-control">
            <label className="range-label">
              Collapse Threshold: {collapseThreshold} lines
            </label>
            <input
              type="range"
              min="5"
              max="100"
              value={collapseThreshold}
              onChange={(e) => onCollapseThresholdChange?.(parseInt(e.target.value))}
              className="range-slider"
              disabled={!autoCollapse}
            />
            <div className="range-marks">
              <span>5</span>
              <span>50</span>
              <span>100</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );

  const renderScrollControls = () => (
    <div className="control-section scroll">
      <div 
        className="section-header"
        onClick={() => toggleSection('scroll')}
      >
        <span className="section-icon">🔄</span>
        <span className="section-title">Scrolling</span>
        <span className="section-toggle">
          {isSectionExpanded('scroll') ? '▼' : '▶'}
        </span>
      </div>
      
      {isSectionExpanded('scroll') && (
        <div className="section-content">
          <div className="toggle-controls">
            <label className="toggle-item">
              <input
                type="checkbox"
                checked={syncScrolling}
                onChange={(e) => onSyncScrollingChange?.(e.target.checked)}
              />
              <span className="toggle-label">Synchronized Scrolling</span>
            </label>
            
            <label className="toggle-item">
              <input
                type="checkbox"
                checked={smoothScrolling}
                onChange={(e) => onSmoothScrollingChange?.(e.target.checked)}
              />
              <span className="toggle-label">Smooth Scrolling</span>
            </label>
          </div>
        </div>
      )}
    </div>
  );

  const renderThemeControls = () => (
    <div className="control-section theme">
      <div 
        className="section-header"
        onClick={() => toggleSection('theme')}
      >
        <span className="section-icon">🌓</span>
        <span className="section-title">Theme</span>
        <span className="section-toggle">
          {isSectionExpanded('theme') ? '▼' : '▶'}
        </span>
      </div>
      
      {isSectionExpanded('theme') && (
        <div className="section-content">
          <div className="button-group">
            <button
              className={`theme-btn ${theme === 'light' ? 'active' : ''}`}
              onClick={() => onThemeChange?.('light')}
            >
              ☀️ Light
            </button>
            
            <button
              className={`theme-btn ${theme === 'dark' ? 'active' : ''}`}
              onClick={() => onThemeChange?.('dark')}
            >
              🌙 Dark
            </button>
            
            <button
              className={`theme-btn ${theme === 'auto' ? 'active' : ''}`}
              onClick={() => onThemeChange?.('auto')}
            >
              🔄 Auto
            </button>
          </div>
        </div>
      )}
    </div>
  );

  const renderActionControls = () => (
    <div className="control-section actions">
      <div 
        className="section-header"
        onClick={() => toggleSection('actions')}
      >
        <span className="section-icon">⚡</span>
        <span className="section-title">Actions</span>
        <span className="section-toggle">
          {isSectionExpanded('actions') ? '▼' : '▶'}
        </span>
      </div>
      
      {isSectionExpanded('actions') && (
        <div className="section-content">
          <div className="action-buttons">
            {onExport && (
              <div className="export-group">
                <span className="group-label">Export:</span>
                <button 
                  className="action-btn"
                  onClick={() => onExport('html')}
                  title="Export as HTML"
                >
                  📄 HTML
                </button>
                <button 
                  className="action-btn"
                  onClick={() => onExport('pdf')}
                  title="Export as PDF"
                >
                  📕 PDF
                </button>
                <button 
                  className="action-btn"
                  onClick={() => onExport('json')}
                  title="Export as JSON"
                >
                  📊 JSON
                </button>
              </div>
            )}
            
            {onToggleFullscreen && (
              <button 
                className="action-btn fullscreen"
                onClick={onToggleFullscreen}
                title="Toggle fullscreen"
              >
                🔳 Fullscreen
              </button>
            )}
            
            {onReset && (
              <button 
                className="action-btn reset"
                onClick={onReset}
                title="Reset all settings"
              >
                🔄 Reset
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );

  return (
    <div className={`diff-controls ${theme} ${compact ? 'compact' : ''} ${orientation} ${className}`}>
      <div className="controls-header">
        <h3 className="controls-title">Diff Controls</h3>
        <button
          className="advanced-toggle"
          onClick={() => setShowAdvanced(!showAdvanced)}
          title={showAdvanced ? 'Hide advanced options' : 'Show advanced options'}
        >
          {showAdvanced ? '🔧' : '⚙️'}
        </button>
      </div>

      <div className="controls-content">
        {renderViewModeControls()}
        {renderDisplayControls()}
        {renderFilterControls()}
        
        {showAdvanced && (
          <>
            {renderCollapseControls()}
            {renderScrollControls()}
            {renderThemeControls()}
            {renderActionControls()}
          </>
        )}
      </div>

      <style jsx>{`
        .diff-controls {
          display: flex;
          flex-direction: column;
          background-color: #f6f8fa;
          border: 1px solid #e1e4e8;
          border-radius: 8px;
          padding: 16px;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          font-size: 14px;
          width: 280px;
          max-height: 600px;
          overflow-y: auto;
        }

        .diff-controls.dark {
          background-color: #161b22;
          border-color: #30363d;
          color: #f0f6fc;
        }

        .diff-controls.compact {
          padding: 12px;
          width: 250px;
        }

        .diff-controls.horizontal {
          flex-direction: row;
          width: auto;
          max-width: 100%;
          height: auto;
          max-height: none;
        }

        .controls-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 16px;
          padding-bottom: 12px;
          border-bottom: 1px solid #e1e4e8;
        }

        .diff-controls.dark .controls-header {
          border-bottom-color: #30363d;
        }

        .controls-title {
          margin: 0;
          font-size: 16px;
          font-weight: 600;
          color: #24292f;
        }

        .diff-controls.dark .controls-title {
          color: #f0f6fc;
        }

        .advanced-toggle {
          background: none;
          border: 1px solid #d0d7de;
          border-radius: 4px;
          padding: 4px 8px;
          cursor: pointer;
          font-size: 16px;
          transition: all 0.15s ease;
        }

        .advanced-toggle:hover {
          background-color: #f3f4f6;
        }

        .diff-controls.dark .advanced-toggle {
          border-color: #30363d;
          color: #f0f6fc;
        }

        .diff-controls.dark .advanced-toggle:hover {
          background-color: #21262d;
        }

        .controls-content {
          display: flex;
          flex-direction: column;
          gap: 12px;
        }

        .control-section {
          border: 1px solid #e1e4e8;
          border-radius: 6px;
          overflow: hidden;
        }

        .diff-controls.dark .control-section {
          border-color: #30363d;
        }

        .section-header {
          display: flex;
          align-items: center;
          padding: 12px;
          background-color: #ffffff;
          cursor: pointer;
          transition: background-color 0.15s ease;
        }

        .section-header:hover {
          background-color: #f6f8fa;
        }

        .diff-controls.dark .section-header {
          background-color: #0d1117;
        }

        .diff-controls.dark .section-header:hover {
          background-color: #161b22;
        }

        .section-icon {
          margin-right: 8px;
          font-size: 16px;
        }

        .section-title {
          flex: 1;
          font-weight: 500;
          color: #24292f;
        }

        .diff-controls.dark .section-title {
          color: #f0f6fc;
        }

        .section-toggle {
          color: #656d76;
          font-size: 12px;
        }

        .diff-controls.dark .section-toggle {
          color: #8b949e;
        }

        .section-content {
          padding: 12px;
          background-color: #f6f8fa;
          border-top: 1px solid #e1e4e8;
        }

        .diff-controls.dark .section-content {
          background-color: #161b22;
          border-top-color: #30363d;
        }

        .button-group {
          display: flex;
          flex-direction: column;
          gap: 4px;
        }

        .mode-btn,
        .theme-btn {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 8px 12px;
          background-color: #ffffff;
          border: 1px solid #d0d7de;
          border-radius: 4px;
          cursor: pointer;
          transition: all 0.15s ease;
          font-size: 13px;
        }

        .mode-btn:hover,
        .theme-btn:hover {
          background-color: #f3f4f6;
          border-color: #8b949e;
        }

        .mode-btn.active,
        .theme-btn.active {
          background-color: #0969da;
          border-color: #0969da;
          color: white;
        }

        .diff-controls.dark .mode-btn,
        .diff-controls.dark .theme-btn {
          background-color: #21262d;
          border-color: #30363d;
          color: #f0f6fc;
        }

        .diff-controls.dark .mode-btn:hover,
        .diff-controls.dark .theme-btn:hover {
          background-color: #30363d;
        }

        .btn-icon {
          font-size: 14px;
        }

        .toggle-controls {
          display: flex;
          flex-direction: column;
          gap: 8px;
        }

        .toggle-item {
          display: flex;
          align-items: center;
          gap: 8px;
          cursor: pointer;
          padding: 4px 0;
        }

        .toggle-item input[type="checkbox"] {
          margin: 0;
        }

        .toggle-label {
          font-size: 13px;
          color: #24292f;
        }

        .diff-controls.dark .toggle-label {
          color: #f0f6fc;
        }

        .range-control {
          margin-top: 12px;
        }

        .range-label {
          display: block;
          font-size: 13px;
          color: #656d76;
          margin-bottom: 8px;
        }

        .diff-controls.dark .range-label {
          color: #8b949e;
        }

        .range-slider {
          width: 100%;
          margin-bottom: 4px;
        }

        .range-marks {
          display: flex;
          justify-content: space-between;
          font-size: 11px;
          color: #656d76;
        }

        .diff-controls.dark .range-marks {
          color: #8b949e;
        }

        .action-buttons {
          display: flex;
          flex-direction: column;
          gap: 12px;
        }

        .export-group {
          display: flex;
          flex-direction: column;
          gap: 4px;
        }

        .group-label {
          font-size: 12px;
          color: #656d76;
          margin-bottom: 4px;
        }

        .diff-controls.dark .group-label {
          color: #8b949e;
        }

        .action-btn {
          padding: 6px 12px;
          background-color: #ffffff;
          border: 1px solid #d0d7de;
          border-radius: 4px;
          cursor: pointer;
          font-size: 12px;
          transition: all 0.15s ease;
        }

        .action-btn:hover {
          background-color: #f3f4f6;
        }

        .action-btn.fullscreen {
          background-color: #0969da;
          border-color: #0969da;
          color: white;
        }

        .action-btn.reset {
          background-color: #cf222e;
          border-color: #cf222e;
          color: white;
        }

        .diff-controls.dark .action-btn {
          background-color: #21262d;
          border-color: #30363d;
          color: #f0f6fc;
        }

        .diff-controls.dark .action-btn:hover {
          background-color: #30363d;
        }
      `}</style>
    </div>
  );
};

export default DiffControls; 