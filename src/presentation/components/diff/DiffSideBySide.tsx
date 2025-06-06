import React, { useRef, useEffect, useState, useMemo } from 'react';
import { DiffResult, DiffChunk } from '../../../domain/entities/DiffResult';

export interface DiffSideBySideProps {
  diffResult: DiffResult;
  originalTitle?: string;
  modifiedTitle?: string;
  showLineNumbers?: boolean;
  highlightSyntax?: boolean;
  theme?: 'light' | 'dark';
  onLineClick?: (line: number, side: 'original' | 'modified') => void;
  onChunkClick?: (chunk: DiffChunk, index: number) => void;
  className?: string;
  collapsedSections?: Set<number>;
  onToggleSection?: (sectionIndex: number) => void;
}

interface ProcessedLine {
  number: number;
  content: string;
  type: 'unchanged' | 'added' | 'deleted' | 'modified';
  originalNumber?: number;
  modifiedNumber?: number;
  chunkIndex?: number;
  isEmpty?: boolean;
}

interface SideBySideData {
  originalLines: ProcessedLine[];
  modifiedLines: ProcessedLine[];
  maxLines: number;
}

/**
 * Componente de visualização lado a lado para diferenças de texto
 * Oferece visualização sincronizada com destaque de alterações
 */
export const DiffSideBySide: React.FC<DiffSideBySideProps> = ({
  diffResult,
  originalTitle = 'Original',
  modifiedTitle = 'Modified',
  showLineNumbers = true,
  highlightSyntax = false,
  theme = 'light',
  onLineClick,
  onChunkClick,
  className = '',
  collapsedSections = new Set(),
  onToggleSection
}) => {
  const originalPanelRef = useRef<HTMLDivElement>(null);
  const modifiedPanelRef = useRef<HTMLDivElement>(null);
  const [isScrollingSynced, setIsScrollingSynced] = useState(true);

  // Processar dados do diff para visualização lado a lado
  const { originalLines, modifiedLines, maxLines } = useMemo(() => 
    processDiffData(diffResult), [diffResult]
  );

  // Sincronização de scroll
  useEffect(() => {
    if (!isScrollingSynced) return;

    const originalPanel = originalPanelRef.current;
    const modifiedPanel = modifiedPanelRef.current;

    if (!originalPanel || !modifiedPanel) return;

    const syncScroll = (sourceElement: HTMLElement, targetElement: HTMLElement) => {
      targetElement.scrollTop = sourceElement.scrollTop;
      targetElement.scrollLeft = sourceElement.scrollLeft;
    };

    const handleOriginalScroll = () => {
      if (isScrollingSynced && originalPanel && modifiedPanel) {
        syncScroll(originalPanel, modifiedPanel);
      }
    };

    const handleModifiedScroll = () => {
      if (isScrollingSynced && originalPanel && modifiedPanel) {
        syncScroll(modifiedPanel, originalPanel);
      }
    };

    originalPanel.addEventListener('scroll', handleOriginalScroll);
    modifiedPanel.addEventListener('scroll', handleModifiedScroll);

    return () => {
      originalPanel?.removeEventListener('scroll', handleOriginalScroll);
      modifiedPanel?.removeEventListener('scroll', handleModifiedScroll);
    };
  }, [isScrollingSynced]);

  const handleLineClick = (lineNumber: number, side: 'original' | 'modified') => {
    onLineClick?.(lineNumber, side);
  };

  const handleChunkClick = (line: ProcessedLine) => {
    if (line.chunkIndex !== undefined && diffResult.chunks[line.chunkIndex]) {
      onChunkClick?.(diffResult.chunks[line.chunkIndex], line.chunkIndex);
    }
  };

  const renderLineNumber = (line: ProcessedLine, side: 'original' | 'modified') => {
    if (!showLineNumbers) return null;

    const lineNum = side === 'original' ? line.originalNumber : line.modifiedNumber;
    
    return (
      <div 
        className={`diff-line-number ${theme === 'dark' ? 'dark' : 'light'} ${line.type}`}
        onClick={() => lineNum && handleLineClick(lineNum, side)}
      >
        {lineNum || ''}
      </div>
    );
  };

  const renderLine = (line: ProcessedLine, side: 'original' | 'modified', index: number) => {
    const isCollapsed = line.chunkIndex !== undefined && collapsedSections.has(line.chunkIndex);
    
    if (isCollapsed) return null;

    return (
      <div 
        key={`${side}-${index}`}
        className={`diff-line ${line.type} ${theme === 'dark' ? 'dark' : 'light'}`}
        onClick={() => handleChunkClick(line)}
      >
        {renderLineNumber(line, side)}
        <div className={`diff-line-content ${highlightSyntax ? 'syntax-highlighted' : ''}`}>
          <code>{line.content || '\u00A0'}</code>
        </div>
      </div>
    );
  };

  const renderCollapseButton = (chunkIndex: number, isCollapsed: boolean) => {
    if (!onToggleSection) return null;

    return (
      <button
        className={`diff-collapse-btn ${theme === 'dark' ? 'dark' : 'light'}`}
        onClick={() => onToggleSection(chunkIndex)}
        title={isCollapsed ? 'Expand section' : 'Collapse section'}
      >
        {isCollapsed ? '▶' : '▼'}
      </button>
    );
  };

  const lines = Array.from({ length: maxLines }, (_, index) => {
    const originalLine = originalLines[index];
    const modifiedLine = modifiedLines[index];
    
    // Verificar se alguma das linhas está collapsed
    const originalCollapsed = originalLine?.chunkIndex !== undefined && 
                             collapsedSections.has(originalLine.chunkIndex);
    const modifiedCollapsed = modifiedLine?.chunkIndex !== undefined && 
                             collapsedSections.has(modifiedLine.chunkIndex);

    if (originalCollapsed && modifiedCollapsed) {
      // Renderizar botão de collapse apenas uma vez por seção
      const chunkIndex = originalLine?.chunkIndex ?? modifiedLine?.chunkIndex;
      if (chunkIndex !== undefined && index === 0) {
        return (
          <div key={`collapsed-${chunkIndex}`} className="diff-collapsed-section">
            {renderCollapseButton(chunkIndex, true)}
            <span className="diff-collapsed-text">
              Section collapsed ({diffResult.chunks[chunkIndex]?.text.split('\n').length || 0} lines)
            </span>
          </div>
        );
      }
      return null;
    }

    return (
      <div key={index} className="diff-line-pair">
        <div className="diff-original-side">
          {originalLine && renderLine(originalLine, 'original', index)}
        </div>
        <div className="diff-modified-side">
          {modifiedLine && renderLine(modifiedLine, 'modified', index)}
        </div>
      </div>
    );
  });

  return (
    <div className={`diff-side-by-side ${theme} ${className}`}>
      {/* Header */}
      <div className="diff-header">
        <div className="diff-title-section">
          <div className="diff-original-title">
            <h3>{originalTitle}</h3>
            <div className="diff-stats">
              {diffResult.getDeletions().length} deletions
            </div>
          </div>
          <div className="diff-controls">
            <button
              className={`diff-sync-btn ${isScrollingSynced ? 'active' : ''}`}
              onClick={() => setIsScrollingSynced(!isScrollingSynced)}
              title={isScrollingSynced ? 'Disable scroll sync' : 'Enable scroll sync'}
            >
              🔗
            </button>
          </div>
          <div className="diff-modified-title">
            <h3>{modifiedTitle}</h3>
            <div className="diff-stats">
              {diffResult.getAdditions().length} additions
            </div>
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="diff-content">
        <div className="diff-panels">
          <div 
            ref={originalPanelRef}
            className="diff-panel diff-original-panel"
          >
            {lines}
          </div>
          <div 
            ref={modifiedPanelRef}
            className="diff-panel diff-modified-panel"
          >
            {lines}
          </div>
        </div>
      </div>

      {/* Footer */}
      <div className="diff-footer">
        <div className="diff-summary">
          <span className="diff-similarity">
            Similarity: {(diffResult.getOverallSimilarity() * 100).toFixed(1)}%
          </span>
          <span className="diff-total-changes">
            Total changes: {diffResult.getTotalChangeCount()}
          </span>
        </div>
      </div>

      <style jsx>{`
        .diff-side-by-side {
          display: flex;
          flex-direction: column;
          height: 100%;
          border: 1px solid #e1e4e8;
          border-radius: 6px;
          overflow: hidden;
          font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
          font-size: 14px;
        }

        .diff-side-by-side.dark {
          border-color: #30363d;
          background-color: #0d1117;
          color: #f0f6fc;
        }

        .diff-header {
          background-color: #f6f8fa;
          border-bottom: 1px solid #e1e4e8;
          padding: 12px 16px;
        }

        .diff-side-by-side.dark .diff-header {
          background-color: #161b22;
          border-bottom-color: #30363d;
        }

        .diff-title-section {
          display: grid;
          grid-template-columns: 1fr auto 1fr;
          gap: 16px;
          align-items: center;
        }

        .diff-original-title,
        .diff-modified-title {
          display: flex;
          flex-direction: column;
          gap: 4px;
        }

        .diff-original-title h3,
        .diff-modified-title h3 {
          margin: 0;
          font-size: 16px;
          font-weight: 600;
        }

        .diff-stats {
          font-size: 12px;
          color: #656d76;
        }

        .diff-side-by-side.dark .diff-stats {
          color: #8b949e;
        }

        .diff-controls {
          display: flex;
          gap: 8px;
        }

        .diff-sync-btn {
          background: transparent;
          border: 1px solid #d0d7de;
          border-radius: 4px;
          padding: 4px 8px;
          cursor: pointer;
          font-size: 16px;
        }

        .diff-sync-btn.active {
          background-color: #0969da;
          border-color: #0969da;
          color: white;
        }

        .diff-side-by-side.dark .diff-sync-btn {
          border-color: #30363d;
          color: #f0f6fc;
        }

        .diff-content {
          flex: 1;
          overflow: hidden;
        }

        .diff-panels {
          display: grid;
          grid-template-columns: 1fr 1fr;
          height: 100%;
        }

        .diff-panel {
          overflow: auto;
          border-right: 1px solid #e1e4e8;
        }

        .diff-panel:last-child {
          border-right: none;
        }

        .diff-side-by-side.dark .diff-panel {
          border-right-color: #30363d;
        }

        .diff-line-pair {
          display: contents;
        }

        .diff-line {
          display: flex;
          min-height: 20px;
          line-height: 20px;
          border-bottom: 1px solid #f6f8fa;
        }

        .diff-side-by-side.dark .diff-line {
          border-bottom-color: #21262d;
        }

        .diff-line.added {
          background-color: #e6ffed;
        }

        .diff-line.deleted {
          background-color: #ffebe9;
        }

        .diff-line.modified {
          background-color: #fff8c5;
        }

        .diff-side-by-side.dark .diff-line.added {
          background-color: #033a16;
        }

        .diff-side-by-side.dark .diff-line.deleted {
          background-color: #67060c;
        }

        .diff-side-by-side.dark .diff-line.modified {
          background-color: #7c3d00;
        }

        .diff-line-number {
          width: 60px;
          text-align: right;
          padding: 0 8px;
          color: #656d76;
          background-color: #f6f8fa;
          border-right: 1px solid #e1e4e8;
          cursor: pointer;
          user-select: none;
        }

        .diff-side-by-side.dark .diff-line-number {
          color: #8b949e;
          background-color: #161b22;
          border-right-color: #30363d;
        }

        .diff-line-content {
          flex: 1;
          padding: 0 8px;
          white-space: pre;
          overflow-x: auto;
        }

        .diff-line-content code {
          background: transparent;
          padding: 0;
          font-family: inherit;
        }

        .diff-collapsed-section {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 8px 16px;
          background-color: #f6f8fa;
          border-bottom: 1px solid #e1e4e8;
          color: #656d76;
          font-style: italic;
        }

        .diff-side-by-side.dark .diff-collapsed-section {
          background-color: #161b22;
          border-bottom-color: #30363d;
          color: #8b949e;
        }

        .diff-collapse-btn {
          background: none;
          border: none;
          cursor: pointer;
          font-size: 12px;
          color: #656d76;
        }

        .diff-side-by-side.dark .diff-collapse-btn {
          color: #8b949e;
        }

        .diff-footer {
          background-color: #f6f8fa;
          border-top: 1px solid #e1e4e8;
          padding: 8px 16px;
        }

        .diff-side-by-side.dark .diff-footer {
          background-color: #161b22;
          border-top-color: #30363d;
        }

        .diff-summary {
          display: flex;
          justify-content: space-between;
          font-size: 12px;
          color: #656d76;
        }

        .diff-side-by-side.dark .diff-summary {
          color: #8b949e;
        }

        .syntax-highlighted {
          /* Placeholder for syntax highlighting */
        }
      `}</style>
    </div>
  );
};

/**
 * Processa os dados do diff para visualização lado a lado
 */
function processDiffData(diffResult: DiffResult): SideBySideData {
  const originalLines: ProcessedLine[] = [];
  const modifiedLines: ProcessedLine[] = [];
  
  let originalLineNumber = 1;
  let modifiedLineNumber = 1;

  diffResult.chunks.forEach((chunk, chunkIndex) => {
    const lines = chunk.text.split('\n');
    
    switch (chunk.operation) {
      case 'equal':
        lines.forEach(line => {
          originalLines.push({
            number: originalLines.length + 1,
            content: line,
            type: 'unchanged',
            originalNumber: originalLineNumber++,
            modifiedNumber: modifiedLineNumber++,
            chunkIndex
          });
          modifiedLines.push({
            number: modifiedLines.length + 1,
            content: line,
            type: 'unchanged',
            originalNumber: originalLineNumber - 1,
            modifiedNumber: modifiedLineNumber - 1,
            chunkIndex
          });
        });
        break;

      case 'delete':
        lines.forEach(line => {
          originalLines.push({
            number: originalLines.length + 1,
            content: line,
            type: 'deleted',
            originalNumber: originalLineNumber++,
            chunkIndex
          });
          modifiedLines.push({
            number: modifiedLines.length + 1,
            content: '',
            type: 'deleted',
            isEmpty: true,
            chunkIndex
          });
        });
        break;

      case 'insert':
        lines.forEach(line => {
          originalLines.push({
            number: originalLines.length + 1,
            content: '',
            type: 'added',
            isEmpty: true,
            chunkIndex
          });
          modifiedLines.push({
            number: modifiedLines.length + 1,
            content: line,
            type: 'added',
            modifiedNumber: modifiedLineNumber++,
            chunkIndex
          });
        });
        break;

      case 'modify':
        lines.forEach(line => {
          originalLines.push({
            number: originalLines.length + 1,
            content: line,
            type: 'modified',
            originalNumber: originalLineNumber++,
            chunkIndex
          });
          modifiedLines.push({
            number: modifiedLines.length + 1,
            content: line,
            type: 'modified',
            modifiedNumber: modifiedLineNumber++,
            chunkIndex
          });
        });
        break;
    }
  });

  const maxLines = Math.max(originalLines.length, modifiedLines.length);

  return {
    originalLines,
    modifiedLines,
    maxLines
  };
}

export default DiffSideBySide; 