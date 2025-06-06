import React, { useState, useMemo } from 'react';
import { DiffResult, DiffChunk } from '../../../domain/entities/DiffResult';

export interface DiffInlineProps {
  diffResult: DiffResult;
  showLineNumbers?: boolean;
  highlightSyntax?: boolean;
  theme?: 'light' | 'dark';
  contextLines?: number; // Number of context lines to show around changes
  showOnlyChanges?: boolean; // Show only changed sections
  onLineClick?: (line: number, chunk: DiffChunk) => void;
  onChunkClick?: (chunk: DiffChunk, index: number) => void;
  className?: string;
  collapsedSections?: Set<number>;
  onToggleSection?: (sectionIndex: number) => void;
}

interface InlineLine {
  number: number;
  content: string;
  type: 'context' | 'added' | 'deleted' | 'modified' | 'separator';
  originalLineNumber?: number;
  modifiedLineNumber?: number;
  chunkIndex?: number;
  isContextExpanded?: boolean;
  contextLineCount?: number;
}

/**
 * Componente de visualização inline para diferenças de texto
 * Mostra alterações em formato unificado com contexto configurável
 */
export const DiffInline: React.FC<DiffInlineProps> = ({
  diffResult,
  showLineNumbers = true,
  highlightSyntax = false,
  theme = 'light',
  contextLines = 3,
  showOnlyChanges = false,
  onLineClick,
  onChunkClick,
  className = '',
  collapsedSections = new Set(),
  onToggleSection
}) => {
  const [expandedContexts, setExpandedContexts] = useState<Set<number>>(new Set());

  // Processar dados do diff para visualização inline
  const inlineLines = useMemo(() => 
    processInlineData(diffResult, contextLines, showOnlyChanges), 
    [diffResult, contextLines, showOnlyChanges]
  );

  const handleLineClick = (line: InlineLine) => {
    if (line.chunkIndex !== undefined && diffResult.chunks[line.chunkIndex]) {
      const chunk = diffResult.chunks[line.chunkIndex];
      onLineClick?.(line.number, chunk);
      onChunkClick?.(chunk, line.chunkIndex);
    }
  };

  const handleToggleContext = (lineNumber: number) => {
    const newExpanded = new Set(expandedContexts);
    if (newExpanded.has(lineNumber)) {
      newExpanded.delete(lineNumber);
    } else {
      newExpanded.add(lineNumber);
    }
    setExpandedContexts(newExpanded);
  };

  const renderLineNumber = (line: InlineLine) => {
    if (!showLineNumbers) return null;

    const getLineNumber = () => {
      switch (line.type) {
        case 'added':
          return line.modifiedLineNumber ? `+${line.modifiedLineNumber}` : '';
        case 'deleted':
          return line.originalLineNumber ? `-${line.originalLineNumber}` : '';
        case 'modified':
          return line.originalLineNumber && line.modifiedLineNumber 
            ? `${line.originalLineNumber}/${line.modifiedLineNumber}` 
            : '';
        case 'context':
          return line.originalLineNumber || line.modifiedLineNumber || '';
        default:
          return '';
      }
    };

    return (
      <div className={`diff-line-number ${line.type} ${theme}`}>
        {getLineNumber()}
      </div>
    );
  };

  const renderPrefix = (line: InlineLine) => {
    const prefixMap = {
      'context': ' ',
      'added': '+',
      'deleted': '-',
      'modified': '~',
      'separator': ''
    };

    return (
      <div className={`diff-prefix ${line.type} ${theme}`}>
        {prefixMap[line.type]}
      </div>
    );
  };

  const renderContextExpander = (line: InlineLine) => {
    if (line.type !== 'separator' || !line.contextLineCount) return null;

    const isExpanded = expandedContexts.has(line.number);

    return (
      <div className={`diff-context-expander ${theme}`}>
        <button
          className="diff-expand-btn"
          onClick={() => handleToggleContext(line.number)}
        >
          <span className="expand-icon">{isExpanded ? '▼' : '▶'}</span>
          <span className="expand-text">
            {isExpanded 
              ? 'Hide context' 
              : `Show ${line.contextLineCount} more lines`
            }
          </span>
        </button>
      </div>
    );
  };

  const renderCollapseButton = (chunkIndex: number) => {
    if (!onToggleSection) return null;

    const isCollapsed = collapsedSections.has(chunkIndex);

    return (
      <button
        className={`diff-collapse-btn ${theme}`}
        onClick={() => onToggleSection(chunkIndex)}
        title={isCollapsed ? 'Expand section' : 'Collapse section'}
      >
        {isCollapsed ? '▶' : '▼'}
      </button>
    );
  };

  const renderLine = (line: InlineLine, index: number) => {
    // Verificar se a seção está collapsed
    if (line.chunkIndex !== undefined && collapsedSections.has(line.chunkIndex)) {
      // Mostrar apenas a primeira linha collapsed de cada chunk
      const isFirstLineOfChunk = index === 0 || 
        inlineLines[index - 1]?.chunkIndex !== line.chunkIndex;
      
      if (!isFirstLineOfChunk) return null;

      const chunk = diffResult.chunks[line.chunkIndex];
      const lineCount = chunk.text.split('\n').length;

      return (
        <div key={`collapsed-${line.chunkIndex}`} className={`diff-collapsed-section ${theme}`}>
          {renderCollapseButton(line.chunkIndex)}
          <span className="diff-collapsed-text">
            Section collapsed ({lineCount} lines)
          </span>
        </div>
      );
    }

    // Renderizar expansor de contexto
    if (line.type === 'separator') {
      return (
        <div key={`separator-${index}`} className={`diff-separator ${theme}`}>
          {renderContextExpander(line)}
        </div>
      );
    }

    return (
      <div 
        key={`line-${index}`}
        className={`diff-line ${line.type} ${theme} ${highlightSyntax ? 'syntax-highlighted' : ''}`}
        onClick={() => handleLineClick(line)}
      >
        {renderLineNumber(line)}
        {renderPrefix(line)}
        <div className="diff-line-content">
          <code>{line.content || '\u00A0'}</code>
        </div>
        {line.chunkIndex !== undefined && onToggleSection && (
          <div className="diff-line-controls">
            {renderCollapseButton(line.chunkIndex)}
          </div>
        )}
      </div>
    );
  };

  const stats = {
    additions: diffResult.getAdditions().length,
    deletions: diffResult.getDeletions().length,
    modifications: diffResult.getModifications().length,
    similarity: diffResult.getOverallSimilarity()
  };

  return (
    <div className={`diff-inline ${theme} ${className}`}>
      {/* Header com estatísticas */}
      <div className="diff-header">
        <div className="diff-stats-row">
          <div className="diff-stats">
            <span className="stat-item added">+{stats.additions}</span>
            <span className="stat-item deleted">-{stats.deletions}</span>
            {stats.modifications > 0 && (
              <span className="stat-item modified">~{stats.modifications}</span>
            )}
          </div>
          <div className="diff-similarity">
            Similarity: {(stats.similarity * 100).toFixed(1)}%
          </div>
        </div>
        
        {/* Opções de visualização */}
        <div className="diff-options">
          <label className="option-toggle">
            <input
              type="checkbox"
              checked={showOnlyChanges}
              onChange={() => {/* This would be controlled by parent */}}
              disabled
            />
            Show only changes
          </label>
        </div>
      </div>

      {/* Conteúdo principal */}
      <div className="diff-content">
        <div className="diff-lines">
          {inlineLines.map((line, index) => renderLine(line, index))}
        </div>
      </div>

      {/* Footer */}
      <div className="diff-footer">
        <div className="diff-summary">
          <span>Total changes: {diffResult.getTotalChangeCount()}</span>
          <span>Processing time: {diffResult.getProcessingTime()}ms</span>
        </div>
      </div>

      <style jsx>{`
        .diff-inline {
          display: flex;
          flex-direction: column;
          height: 100%;
          border: 1px solid #e1e4e8;
          border-radius: 6px;
          overflow: hidden;
          font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
          font-size: 14px;
          background-color: #ffffff;
        }

        .diff-inline.dark {
          border-color: #30363d;
          background-color: #0d1117;
          color: #f0f6fc;
        }

        .diff-header {
          background-color: #f6f8fa;
          border-bottom: 1px solid #e1e4e8;
          padding: 12px 16px;
        }

        .diff-inline.dark .diff-header {
          background-color: #161b22;
          border-bottom-color: #30363d;
        }

        .diff-stats-row {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 8px;
        }

        .diff-stats {
          display: flex;
          gap: 12px;
        }

        .stat-item {
          font-weight: 600;
          padding: 2px 6px;
          border-radius: 3px;
          font-size: 12px;
        }

        .stat-item.added {
          color: #1a7f37;
          background-color: #dafbe1;
        }

        .stat-item.deleted {
          color: #cf222e;
          background-color: #ffebe9;
        }

        .stat-item.modified {
          color: #9a6700;
          background-color: #fff8c5;
        }

        .diff-inline.dark .stat-item.added {
          color: #3fb950;
          background-color: #033a16;
        }

        .diff-inline.dark .stat-item.deleted {
          color: #f85149;
          background-color: #67060c;
        }

        .diff-inline.dark .stat-item.modified {
          color: #e3b341;
          background-color: #7c3d00;
        }

        .diff-similarity {
          font-size: 12px;
          color: #656d76;
        }

        .diff-inline.dark .diff-similarity {
          color: #8b949e;
        }

        .diff-options {
          display: flex;
          gap: 16px;
        }

        .option-toggle {
          display: flex;
          align-items: center;
          gap: 6px;
          font-size: 12px;
          color: #656d76;
          cursor: pointer;
        }

        .diff-inline.dark .option-toggle {
          color: #8b949e;
        }

        .diff-content {
          flex: 1;
          overflow: auto;
        }

        .diff-lines {
          display: flex;
          flex-direction: column;
        }

        .diff-line {
          display: flex;
          align-items: flex-start;
          min-height: 20px;
          line-height: 20px;
          border-bottom: 1px solid #f6f8fa;
          cursor: pointer;
          transition: background-color 0.15s ease;
        }

        .diff-line:hover {
          background-color: #f6f8fa;
        }

        .diff-inline.dark .diff-line {
          border-bottom-color: #21262d;
        }

        .diff-inline.dark .diff-line:hover {
          background-color: #21262d;
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

        .diff-inline.dark .diff-line.added {
          background-color: #033a16;
        }

        .diff-inline.dark .diff-line.deleted {
          background-color: #67060c;
        }

        .diff-inline.dark .diff-line.modified {
          background-color: #7c3d00;
        }

        .diff-line-number {
          width: 60px;
          text-align: right;
          padding: 0 8px;
          color: #656d76;
          background-color: #f6f8fa;
          border-right: 1px solid #e1e4e8;
          user-select: none;
          font-size: 12px;
        }

        .diff-inline.dark .diff-line-number {
          color: #8b949e;
          background-color: #161b22;
          border-right-color: #30363d;
        }

        .diff-prefix {
          width: 20px;
          text-align: center;
          color: #656d76;
          font-weight: bold;
          user-select: none;
        }

        .diff-prefix.added {
          color: #1a7f37;
        }

        .diff-prefix.deleted {
          color: #cf222e;
        }

        .diff-prefix.modified {
          color: #9a6700;
        }

        .diff-inline.dark .diff-prefix.added {
          color: #3fb950;
        }

        .diff-inline.dark .diff-prefix.deleted {
          color: #f85149;
        }

        .diff-inline.dark .diff-prefix.modified {
          color: #e3b341;
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

        .diff-line-controls {
          padding: 0 8px;
          display: flex;
          align-items: center;
        }

        .diff-collapse-btn {
          background: none;
          border: none;
          cursor: pointer;
          font-size: 12px;
          color: #656d76;
          padding: 2px 4px;
        }

        .diff-inline.dark .diff-collapse-btn {
          color: #8b949e;
        }

        .diff-separator {
          background-color: #f6f8fa;
          border-bottom: 1px solid #e1e4e8;
          padding: 8px 16px;
        }

        .diff-inline.dark .diff-separator {
          background-color: #161b22;
          border-bottom-color: #30363d;
        }

        .diff-context-expander {
          display: flex;
          justify-content: center;
        }

        .diff-expand-btn {
          background: none;
          border: 1px solid #d0d7de;
          border-radius: 6px;
          padding: 4px 8px;
          cursor: pointer;
          font-size: 12px;
          color: #656d76;
          display: flex;
          align-items: center;
          gap: 6px;
        }

        .diff-expand-btn:hover {
          background-color: #f3f4f6;
        }

        .diff-inline.dark .diff-expand-btn {
          border-color: #30363d;
          color: #8b949e;
        }

        .diff-inline.dark .diff-expand-btn:hover {
          background-color: #21262d;
        }

        .expand-icon {
          font-size: 10px;
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

        .diff-inline.dark .diff-collapsed-section {
          background-color: #161b22;
          border-bottom-color: #30363d;
          color: #8b949e;
        }

        .diff-footer {
          background-color: #f6f8fa;
          border-top: 1px solid #e1e4e8;
          padding: 8px 16px;
        }

        .diff-inline.dark .diff-footer {
          background-color: #161b22;
          border-top-color: #30363d;
        }

        .diff-summary {
          display: flex;
          justify-content: space-between;
          font-size: 12px;
          color: #656d76;
        }

        .diff-inline.dark .diff-summary {
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
 * Processa os dados do diff para visualização inline
 */
function processInlineData(
  diffResult: DiffResult, 
  contextLines: number,
  showOnlyChanges: boolean
): InlineLine[] {
  const lines: InlineLine[] = [];
  let originalLineNumber = 1;
  let modifiedLineNumber = 1;
  let lineNumber = 1;

  diffResult.chunks.forEach((chunk, chunkIndex) => {
    const chunkLines = chunk.text.split('\n');
    
    switch (chunk.operation) {
      case 'equal':
        if (showOnlyChanges) {
          // Mostrar apenas contexto limitado
          if (chunkLines.length > contextLines * 2) {
            // Mostrar início do contexto
            for (let i = 0; i < contextLines; i++) {
              if (chunkLines[i] !== undefined) {
                lines.push({
                  number: lineNumber++,
                  content: chunkLines[i],
                  type: 'context',
                  originalLineNumber: originalLineNumber++,
                  modifiedLineNumber: modifiedLineNumber++,
                  chunkIndex
                });
              }
            }

            // Adicionar separador
            lines.push({
              number: lineNumber++,
              content: '',
              type: 'separator',
              contextLineCount: chunkLines.length - (contextLines * 2),
              chunkIndex
            });

            // Mostrar final do contexto
            for (let i = chunkLines.length - contextLines; i < chunkLines.length; i++) {
              if (chunkLines[i] !== undefined) {
                lines.push({
                  number: lineNumber++,
                  content: chunkLines[i],
                  type: 'context',
                  originalLineNumber: originalLineNumber++,
                  modifiedLineNumber: modifiedLineNumber++,
                  chunkIndex
                });
              }
            }
          } else {
            // Mostrar todas as linhas se forem poucas
            chunkLines.forEach(line => {
              lines.push({
                number: lineNumber++,
                content: line,
                type: 'context',
                originalLineNumber: originalLineNumber++,
                modifiedLineNumber: modifiedLineNumber++,
                chunkIndex
              });
            });
          }
        } else {
          // Mostrar todas as linhas sem mudanças
          chunkLines.forEach(line => {
            lines.push({
              number: lineNumber++,
              content: line,
              type: 'context',
              originalLineNumber: originalLineNumber++,
              modifiedLineNumber: modifiedLineNumber++,
              chunkIndex
            });
          });
        }
        break;

      case 'delete':
        chunkLines.forEach(line => {
          lines.push({
            number: lineNumber++,
            content: line,
            type: 'deleted',
            originalLineNumber: originalLineNumber++,
            chunkIndex
          });
        });
        break;

      case 'insert':
        chunkLines.forEach(line => {
          lines.push({
            number: lineNumber++,
            content: line,
            type: 'added',
            modifiedLineNumber: modifiedLineNumber++,
            chunkIndex
          });
        });
        break;

      case 'modify':
        chunkLines.forEach(line => {
          lines.push({
            number: lineNumber++,
            content: line,
            type: 'modified',
            originalLineNumber: originalLineNumber++,
            modifiedLineNumber: modifiedLineNumber++,
            chunkIndex
          });
        });
        break;
    }
  });

  return lines;
}

export default DiffInline; 