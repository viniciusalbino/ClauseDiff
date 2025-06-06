import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { DiffResult, DiffChunk } from '../../../domain/entities/DiffResult';

export interface DiffNavigationProps {
  diffResult: DiffResult;
  currentChangeIndex?: number;
  onChangeNavigation?: (changeIndex: number, chunk: DiffChunk) => void;
  onScrollToChange?: (changeIndex: number) => void;
  showMinimap?: boolean;
  showStats?: boolean;
  showKeyboardHelp?: boolean;
  theme?: 'light' | 'dark';
  className?: string;
}

interface NavigableChange {
  index: number;
  chunkIndex: number;
  chunk: DiffChunk;
  type: 'insert' | 'delete' | 'modify';
  lineStart: number;
  lineEnd: number;
  description: string;
  severity: 'low' | 'medium' | 'high';
}

/**
 * Componente de navegação entre alterações em diffs
 * Oferece navegação via teclado, minimap e estatísticas
 */
export const DiffNavigation: React.FC<DiffNavigationProps> = ({
  diffResult,
  currentChangeIndex = 0,
  onChangeNavigation,
  onScrollToChange,
  showMinimap = true,
  showStats = true,
  showKeyboardHelp = false,
  theme = 'light',
  className = ''
}) => {
  const [activeIndex, setActiveIndex] = useState(currentChangeIndex);
  const [isKeyboardHelpVisible, setIsKeyboardHelpVisible] = useState(showKeyboardHelp);

  // Processar mudanças navegáveis
  const navigableChanges = useMemo(() => 
    processNavigableChanges(diffResult), [diffResult]
  );

  const totalChanges = navigableChanges.length;
  const hasChanges = totalChanges > 0;

  // Navegação via teclado
  const handleKeyboardNavigation = useCallback((event: KeyboardEvent) => {
    if (!hasChanges) return;

    switch (event.key) {
      case 'ArrowDown':
      case 'j': // Vim-style
        event.preventDefault();
        navigateToNext();
        break;
      case 'ArrowUp':
      case 'k': // Vim-style
        event.preventDefault();
        navigateToPrevious();
        break;
      case 'Home':
      case 'g': // Vim-style
        event.preventDefault();
        navigateToFirst();
        break;
      case 'End':
      case 'G': // Vim-style (uppercase)
        event.preventDefault();
        navigateToLast();
        break;
      case '?':
        event.preventDefault();
        setIsKeyboardHelpVisible(!isKeyboardHelpVisible);
        break;
      case 'Escape':
        event.preventDefault();
        setIsKeyboardHelpVisible(false);
        break;
    }
  }, [hasChanges, activeIndex, isKeyboardHelpVisible]);

  // Registrar event listeners de teclado
  useEffect(() => {
    document.addEventListener('keydown', handleKeyboardNavigation);
    return () => {
      document.removeEventListener('keydown', handleKeyboardNavigation);
    };
  }, [handleKeyboardNavigation]);

  // Sincronizar com props
  useEffect(() => {
    setActiveIndex(currentChangeIndex);
  }, [currentChangeIndex]);

  const navigateToNext = () => {
    if (!hasChanges) return;
    const nextIndex = Math.min(activeIndex + 1, totalChanges - 1);
    navigateToChange(nextIndex);
  };

  const navigateToPrevious = () => {
    if (!hasChanges) return;
    const prevIndex = Math.max(activeIndex - 1, 0);
    navigateToChange(prevIndex);
  };

  const navigateToFirst = () => {
    if (!hasChanges) return;
    navigateToChange(0);
  };

  const navigateToLast = () => {
    if (!hasChanges) return;
    navigateToChange(totalChanges - 1);
  };

  const navigateToChange = (index: number) => {
    if (index < 0 || index >= totalChanges) return;
    
    setActiveIndex(index);
    const change = navigableChanges[index];
    
    onChangeNavigation?.(index, change.chunk);
    onScrollToChange?.(index);
  };

  const renderNavigationControls = () => (
    <div className="diff-nav-controls">
      <button
        className={`nav-btn prev ${activeIndex === 0 ? 'disabled' : ''}`}
        onClick={navigateToPrevious}
        disabled={!hasChanges || activeIndex === 0}
        title="Previous change (↑ or k)"
      >
        ⬆
      </button>
      
      <div className="nav-indicator">
        {hasChanges ? (
          <span>{activeIndex + 1} / {totalChanges}</span>
        ) : (
          <span>No changes</span>
        )}
      </div>
      
      <button
        className={`nav-btn next ${activeIndex === totalChanges - 1 ? 'disabled' : ''}`}
        onClick={navigateToNext}
        disabled={!hasChanges || activeIndex === totalChanges - 1}
        title="Next change (↓ or j)"
      >
        ⬇
      </button>
    </div>
  );

  const renderQuickJump = () => (
    <div className="diff-quick-jump">
      <button
        className="jump-btn first"
        onClick={navigateToFirst}
        disabled={!hasChanges}
        title="First change (Home or g)"
      >
        ⤴ First
      </button>
      
      <button
        className="jump-btn last"
        onClick={navigateToLast}
        disabled={!hasChanges}
        title="Last change (End or G)"
      >
        ⤵ Last
      </button>
    </div>
  );

  const renderMinimap = () => {
    if (!showMinimap || !hasChanges) return null;

    const minimapHeight = 200;
    const changeHeight = minimapHeight / totalChanges;

    return (
      <div className="diff-minimap">
        <div className="minimap-title">Changes</div>
        <div className="minimap-container" style={{ height: minimapHeight }}>
          {navigableChanges.map((change, index) => (
            <div
              key={index}
              className={`minimap-change ${change.type} ${index === activeIndex ? 'active' : ''}`}
              style={{
                top: index * changeHeight,
                height: Math.max(changeHeight, 2)
              }}
              onClick={() => navigateToChange(index)}
              title={`${change.type}: ${change.description}`}
            />
          ))}
          <div
            className="minimap-viewport"
            style={{
              top: activeIndex * changeHeight,
              height: changeHeight
            }}
          />
        </div>
      </div>
    );
  };

  const renderStats = () => {
    if (!showStats) return null;

    const stats = {
      additions: navigableChanges.filter(c => c.type === 'insert').length,
      deletions: navigableChanges.filter(c => c.type === 'delete').length,
      modifications: navigableChanges.filter(c => c.type === 'modify').length,
      similarity: diffResult.getOverallSimilarity()
    };

    return (
      <div className="diff-stats">
        <div className="stat-item">
          <span className="stat-label">Additions:</span>
          <span className="stat-value additions">{stats.additions}</span>
        </div>
        <div className="stat-item">
          <span className="stat-label">Deletions:</span>
          <span className="stat-value deletions">{stats.deletions}</span>
        </div>
        <div className="stat-item">
          <span className="stat-label">Modifications:</span>
          <span className="stat-value modifications">{stats.modifications}</span>
        </div>
        <div className="stat-item">
          <span className="stat-label">Similarity:</span>
          <span className="stat-value similarity">{(stats.similarity * 100).toFixed(1)}%</span>
        </div>
      </div>
    );
  };

  const renderCurrentChangeInfo = () => {
    if (!hasChanges) return null;

    const currentChange = navigableChanges[activeIndex];
    
    return (
      <div className="current-change-info">
        <div className="change-header">
          <span className={`change-type ${currentChange.type}`}>
            {currentChange.type.toUpperCase()}
          </span>
          <span className={`change-severity ${currentChange.severity}`}>
            {currentChange.severity}
          </span>
        </div>
        <div className="change-description">
          {currentChange.description}
        </div>
        <div className="change-location">
          Lines {currentChange.lineStart}-{currentChange.lineEnd}
        </div>
      </div>
    );
  };

  const renderKeyboardHelp = () => {
    if (!isKeyboardHelpVisible) return null;

    return (
      <div className="keyboard-help-overlay">
        <div className="keyboard-help">
          <div className="help-header">
            <h3>Keyboard Shortcuts</h3>
            <button 
              className="close-btn"
              onClick={() => setIsKeyboardHelpVisible(false)}
            >
              ×
            </button>
          </div>
          <div className="help-content">
            <div className="help-section">
              <h4>Navigation</h4>
              <div className="help-item">
                <kbd>↓</kbd> or <kbd>j</kbd> - Next change
              </div>
              <div className="help-item">
                <kbd>↑</kbd> or <kbd>k</kbd> - Previous change
              </div>
              <div className="help-item">
                <kbd>Home</kbd> or <kbd>g</kbd> - First change
              </div>
              <div className="help-item">
                <kbd>End</kbd> or <kbd>G</kbd> - Last change
              </div>
            </div>
            <div className="help-section">
              <h4>Other</h4>
              <div className="help-item">
                <kbd>?</kbd> - Toggle this help
              </div>
              <div className="help-item">
                <kbd>Esc</kbd> - Close dialogs
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className={`diff-navigation ${theme} ${className}`}>
      {/* Main Navigation */}
      <div className="diff-nav-main">
        {renderNavigationControls()}
        {renderQuickJump()}
        
        <button
          className="help-btn"
          onClick={() => setIsKeyboardHelpVisible(!isKeyboardHelpVisible)}
          title="Keyboard shortcuts (?)"
        >
          ?
        </button>
      </div>

      {/* Current Change Info */}
      {renderCurrentChangeInfo()}

      {/* Stats */}
      {renderStats()}

      {/* Minimap */}
      {renderMinimap()}

      {/* Keyboard Help */}
      {renderKeyboardHelp()}

      <style jsx>{`
        .diff-navigation {
          display: flex;
          flex-direction: column;
          gap: 16px;
          padding: 16px;
          background-color: #f6f8fa;
          border: 1px solid #e1e4e8;
          border-radius: 6px;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          font-size: 14px;
          min-width: 280px;
        }

        .diff-navigation.dark {
          background-color: #161b22;
          border-color: #30363d;
          color: #f0f6fc;
        }

        .diff-nav-main {
          display: flex;
          flex-direction: column;
          gap: 12px;
        }

        .diff-nav-controls {
          display: flex;
          align-items: center;
          gap: 8px;
        }

        .nav-btn {
          background-color: #ffffff;
          border: 1px solid #d0d7de;
          border-radius: 4px;
          padding: 6px 10px;
          cursor: pointer;
          font-size: 16px;
          transition: all 0.15s ease;
        }

        .nav-btn:hover:not(.disabled) {
          background-color: #f3f4f6;
          border-color: #8b949e;
        }

        .nav-btn.disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }

        .diff-navigation.dark .nav-btn {
          background-color: #21262d;
          border-color: #30363d;
          color: #f0f6fc;
        }

        .diff-navigation.dark .nav-btn:hover:not(.disabled) {
          background-color: #30363d;
        }

        .nav-indicator {
          flex: 1;
          text-align: center;
          font-weight: 500;
          color: #656d76;
        }

        .diff-navigation.dark .nav-indicator {
          color: #8b949e;
        }

        .diff-quick-jump {
          display: flex;
          gap: 8px;
        }

        .jump-btn {
          flex: 1;
          background-color: #ffffff;
          border: 1px solid #d0d7de;
          border-radius: 4px;
          padding: 6px 12px;
          cursor: pointer;
          font-size: 12px;
          transition: all 0.15s ease;
        }

        .jump-btn:hover:not(:disabled) {
          background-color: #f3f4f6;
        }

        .jump-btn:disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }

        .diff-navigation.dark .jump-btn {
          background-color: #21262d;
          border-color: #30363d;
          color: #f0f6fc;
        }

        .help-btn {
          background-color: #0969da;
          border: 1px solid #0969da;
          border-radius: 50%;
          width: 28px;
          height: 28px;
          color: white;
          cursor: pointer;
          font-weight: bold;
          font-size: 12px;
        }

        .help-btn:hover {
          background-color: #0550ae;
        }

        .current-change-info {
          padding: 12px;
          background-color: #ffffff;
          border: 1px solid #e1e4e8;
          border-radius: 4px;
        }

        .diff-navigation.dark .current-change-info {
          background-color: #0d1117;
          border-color: #30363d;
        }

        .change-header {
          display: flex;
          gap: 8px;
          margin-bottom: 8px;
        }

        .change-type {
          padding: 2px 6px;
          border-radius: 3px;
          font-size: 11px;
          font-weight: 600;
          text-transform: uppercase;
        }

        .change-type.insert {
          background-color: #dafbe1;
          color: #1a7f37;
        }

        .change-type.delete {
          background-color: #ffebe9;
          color: #cf222e;
        }

        .change-type.modify {
          background-color: #fff8c5;
          color: #9a6700;
        }

        .diff-navigation.dark .change-type.insert {
          background-color: #033a16;
          color: #3fb950;
        }

        .diff-navigation.dark .change-type.delete {
          background-color: #67060c;
          color: #f85149;
        }

        .diff-navigation.dark .change-type.modify {
          background-color: #7c3d00;
          color: #e3b341;
        }

        .change-severity {
          padding: 2px 6px;
          border-radius: 3px;
          font-size: 11px;
          font-weight: 500;
        }

        .change-severity.low {
          background-color: #f0f9ff;
          color: #0369a1;
        }

        .change-severity.medium {
          background-color: #fef3c7;
          color: #d97706;
        }

        .change-severity.high {
          background-color: #fee2e2;
          color: #dc2626;
        }

        .change-description {
          font-size: 13px;
          line-height: 1.4;
          margin-bottom: 6px;
        }

        .change-location {
          font-size: 11px;
          color: #656d76;
        }

        .diff-navigation.dark .change-location {
          color: #8b949e;
        }

        .diff-stats {
          display: flex;
          flex-direction: column;
          gap: 6px;
          padding: 12px;
          background-color: #ffffff;
          border: 1px solid #e1e4e8;
          border-radius: 4px;
        }

        .diff-navigation.dark .diff-stats {
          background-color: #0d1117;
          border-color: #30363d;
        }

        .stat-item {
          display: flex;
          justify-content: space-between;
          font-size: 12px;
        }

        .stat-label {
          color: #656d76;
        }

        .diff-navigation.dark .stat-label {
          color: #8b949e;
        }

        .stat-value {
          font-weight: 500;
        }

        .stat-value.additions {
          color: #1a7f37;
        }

        .stat-value.deletions {
          color: #cf222e;
        }

        .stat-value.modifications {
          color: #9a6700;
        }

        .diff-minimap {
          display: flex;
          flex-direction: column;
          gap: 8px;
        }

        .minimap-title {
          font-size: 12px;
          font-weight: 600;
          color: #656d76;
        }

        .diff-navigation.dark .minimap-title {
          color: #8b949e;
        }

        .minimap-container {
          position: relative;
          background-color: #f6f8fa;
          border: 1px solid #e1e4e8;
          border-radius: 3px;
        }

        .diff-navigation.dark .minimap-container {
          background-color: #21262d;
          border-color: #30363d;
        }

        .minimap-change {
          position: absolute;
          width: 100%;
          cursor: pointer;
          opacity: 0.7;
          transition: opacity 0.15s ease;
        }

        .minimap-change:hover {
          opacity: 1;
        }

        .minimap-change.active {
          opacity: 1;
          border: 1px solid #0969da;
        }

        .minimap-change.insert {
          background-color: #1a7f37;
        }

        .minimap-change.delete {
          background-color: #cf222e;
        }

        .minimap-change.modify {
          background-color: #9a6700;
        }

        .minimap-viewport {
          position: absolute;
          width: 100%;
          border: 2px solid #0969da;
          border-radius: 2px;
          box-sizing: border-box;
          pointer-events: none;
        }

        .keyboard-help-overlay {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background-color: rgba(0, 0, 0, 0.5);
          display: flex;
          justify-content: center;
          align-items: center;
          z-index: 1000;
        }

        .keyboard-help {
          background-color: #ffffff;
          border-radius: 8px;
          padding: 24px;
          max-width: 400px;
          width: 90%;
          box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
        }

        .diff-navigation.dark .keyboard-help {
          background-color: #161b22;
          color: #f0f6fc;
        }

        .help-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 16px;
        }

        .help-header h3 {
          margin: 0;
          font-size: 18px;
        }

        .close-btn {
          background: none;
          border: none;
          font-size: 24px;
          cursor: pointer;
          color: #656d76;
        }

        .diff-navigation.dark .close-btn {
          color: #8b949e;
        }

        .help-content {
          display: flex;
          flex-direction: column;
          gap: 16px;
        }

        .help-section h4 {
          margin: 0 0 8px 0;
          font-size: 14px;
          color: #656d76;
        }

        .diff-navigation.dark .help-section h4 {
          color: #8b949e;
        }

        .help-item {
          display: flex;
          justify-content: space-between;
          margin-bottom: 4px;
          font-size: 13px;
        }

        kbd {
          background-color: #f6f8fa;
          border: 1px solid #d0d7de;
          border-radius: 3px;
          padding: 2px 6px;
          font-family: monospace;
          font-size: 11px;
        }

        .diff-navigation.dark kbd {
          background-color: #21262d;
          border-color: #30363d;
          color: #f0f6fc;
        }
      `}</style>
    </div>
  );
};

/**
 * Processa chunks para criar lista de mudanças navegáveis
 */
function processNavigableChanges(diffResult: DiffResult): NavigableChange[] {
  const changes: NavigableChange[] = [];
  let lineNumber = 1;

  diffResult.chunks.forEach((chunk, chunkIndex) => {
    if (chunk.operation === 'equal') {
      // Pular chunks iguais para navegação
      lineNumber += chunk.text.split('\n').length;
      return;
    }

    const lines = chunk.text.split('\n');
    const lineStart = lineNumber;
    const lineEnd = lineNumber + lines.length - 1;

    const change: NavigableChange = {
      index: changes.length,
      chunkIndex,
      chunk,
      type: chunk.operation === 'insert' ? 'insert' : 
            chunk.operation === 'delete' ? 'delete' : 'modify',
      lineStart,
      lineEnd,
      description: generateChangeDescription(chunk, lines.length),
      severity: calculateChangeSeverity(chunk, lines.length)
    };

    changes.push(change);
    lineNumber += lines.length;
  });

  return changes;
}

/**
 * Gera descrição legível para uma mudança
 */
function generateChangeDescription(chunk: DiffChunk, lineCount: number): string {
  const preview = chunk.text.slice(0, 50);
  const truncated = chunk.text.length > 50 ? '...' : '';
  
  switch (chunk.operation) {
    case 'insert':
      return `Added ${lineCount} line${lineCount > 1 ? 's' : ''}: "${preview}${truncated}"`;
    case 'delete':
      return `Deleted ${lineCount} line${lineCount > 1 ? 's' : ''}: "${preview}${truncated}"`;
    case 'modify':
      return `Modified ${lineCount} line${lineCount > 1 ? 's' : ''}: "${preview}${truncated}"`;
    default:
      return `Changed ${lineCount} line${lineCount > 1 ? 's' : ''}`;
  }
}

/**
 * Calcula severidade de uma mudança
 */
function calculateChangeSeverity(chunk: DiffChunk, lineCount: number): 'low' | 'medium' | 'high' {
  // Baseado no tamanho da mudança e tipo
  if (lineCount === 1 && chunk.text.length < 20) return 'low';
  if (lineCount <= 3 && chunk.text.length < 100) return 'medium';
  return 'high';
}

export default DiffNavigation; 