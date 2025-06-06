import React, { useMemo, useState } from 'react';
import { DiffResult, DiffChunk } from '../../../domain/entities/DiffResult';

export interface DiffStatsProps {
  diffResult: DiffResult;
  showCharts?: boolean;
  showDetailedMetrics?: boolean;
  showPerformanceInfo?: boolean;
  showFileInfo?: boolean;
  showDistribution?: boolean;
  compact?: boolean;
  theme?: 'light' | 'dark';
  className?: string;
  onMetricClick?: (metric: string, value: any) => void;
}

interface DetailedMetrics {
  additions: number;
  deletions: number;
  modifications: number;
  unchanged: number;
  totalLines: number;
  totalCharacters: number;
  addedCharacters: number;
  deletedCharacters: number;
  similarity: number;
  complexity: 'low' | 'medium' | 'high';
  changeIntensity: number;
  avgChunkSize: number;
  largestChunk: number;
  smallestChunk: number;
}

interface ChangeDistribution {
  byType: { type: string; count: number; percentage: number }[];
  bySize: { range: string; count: number; percentage: number }[];
  byPosition: { section: string; count: number; percentage: number }[];
}

/**
 * Componente de estatísticas detalhadas para resultados de diff
 * Oferece métricas abrangentes, gráficos e insights sobre as mudanças
 */
export const DiffStats: React.FC<DiffStatsProps> = ({
  diffResult,
  showCharts = true,
  showDetailedMetrics = true,
  showPerformanceInfo = true,
  showFileInfo = true,
  showDistribution = true,
  compact = false,
  theme = 'light',
  className = '',
  onMetricClick
}) => {
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set());

  // Calcular métricas detalhadas
  const metrics = useMemo(() => 
    calculateDetailedMetrics(diffResult), [diffResult]
  );

  // Calcular distribuição de mudanças
  const distribution = useMemo(() => 
    calculateChangeDistribution(diffResult), [diffResult]
  );

  const toggleSection = (section: string) => {
    setExpandedSections(prev => {
      const newSet = new Set(prev);
      if (newSet.has(section)) {
        newSet.delete(section);
      } else {
        newSet.add(section);
      }
      return newSet;
    });
  };

  const handleMetricClick = (metric: string, value: any) => {
    onMetricClick?.(metric, value);
  };

  const renderBasicStats = () => (
    <div className="stats-section basic-stats">
      <h3 className="section-title">Overview</h3>
      <div className="stats-grid">
        <div 
          className="stat-item additions"
          onClick={() => handleMetricClick('additions', metrics.additions)}
        >
          <div className="stat-value">+{metrics.additions}</div>
          <div className="stat-label">Additions</div>
        </div>
        
        <div 
          className="stat-item deletions"
          onClick={() => handleMetricClick('deletions', metrics.deletions)}
        >
          <div className="stat-value">-{metrics.deletions}</div>
          <div className="stat-label">Deletions</div>
        </div>
        
        <div 
          className="stat-item modifications"
          onClick={() => handleMetricClick('modifications', metrics.modifications)}
        >
          <div className="stat-value">~{metrics.modifications}</div>
          <div className="stat-label">Modifications</div>
        </div>
        
        <div 
          className="stat-item similarity"
          onClick={() => handleMetricClick('similarity', metrics.similarity)}
        >
          <div className="stat-value">{(metrics.similarity * 100).toFixed(1)}%</div>
          <div className="stat-label">Similarity</div>
        </div>
      </div>
    </div>
  );

  const renderDetailedMetrics = () => {
    if (!showDetailedMetrics) return null;

    return (
      <div className="stats-section detailed-metrics">
        <div 
          className="section-header"
          onClick={() => toggleSection('detailed')}
        >
          <h3 className="section-title">Detailed Metrics</h3>
          <span className="toggle-icon">
            {expandedSections.has('detailed') ? '▼' : '▶'}
          </span>
        </div>
        
        {(expandedSections.has('detailed') || !compact) && (
          <div className="metrics-content">
            <div className="metrics-row">
              <div className="metric-group">
                <h4>Content Analysis</h4>
                <div className="metric-item">
                  <span className="metric-label">Total Lines:</span>
                  <span className="metric-value">{metrics.totalLines.toLocaleString()}</span>
                </div>
                <div className="metric-item">
                  <span className="metric-label">Total Characters:</span>
                  <span className="metric-value">{metrics.totalCharacters.toLocaleString()}</span>
                </div>
                <div className="metric-item">
                  <span className="metric-label">Added Characters:</span>
                  <span className="metric-value additions">{metrics.addedCharacters.toLocaleString()}</span>
                </div>
                <div className="metric-item">
                  <span className="metric-label">Deleted Characters:</span>
                  <span className="metric-value deletions">{metrics.deletedCharacters.toLocaleString()}</span>
                </div>
              </div>

              <div className="metric-group">
                <h4>Change Analysis</h4>
                <div className="metric-item">
                  <span className="metric-label">Complexity:</span>
                  <span className={`metric-value complexity-${metrics.complexity}`}>
                    {metrics.complexity.toUpperCase()}
                  </span>
                </div>
                <div className="metric-item">
                  <span className="metric-label">Change Intensity:</span>
                  <span className="metric-value">{(metrics.changeIntensity * 100).toFixed(1)}%</span>
                </div>
                <div className="metric-item">
                  <span className="metric-label">Avg Chunk Size:</span>
                  <span className="metric-value">{metrics.avgChunkSize.toFixed(1)} lines</span>
                </div>
                <div className="metric-item">
                  <span className="metric-label">Largest Chunk:</span>
                  <span className="metric-value">{metrics.largestChunk} lines</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  };

  const renderPerformanceInfo = () => {
    if (!showPerformanceInfo) return null;

    const processingTime = diffResult.getProcessingTime();
    const totalChanges = diffResult.getTotalChangeCount();

    return (
      <div className="stats-section performance-info">
        <div 
          className="section-header"
          onClick={() => toggleSection('performance')}
        >
          <h3 className="section-title">Performance</h3>
          <span className="toggle-icon">
            {expandedSections.has('performance') ? '▼' : '▶'}
          </span>
        </div>
        
        {(expandedSections.has('performance') || !compact) && (
          <div className="performance-content">
            <div className="metric-item">
              <span className="metric-label">Processing Time:</span>
              <span className="metric-value">{processingTime}ms</span>
            </div>
            <div className="metric-item">
              <span className="metric-label">Algorithm:</span>
              <span className="metric-value">{diffResult.algorithm}</span>
            </div>
            <div className="metric-item">
              <span className="metric-label">Chunks Processed:</span>
              <span className="metric-value">{diffResult.chunks.length}</span>
            </div>
            <div className="metric-item">
              <span className="metric-label">Changes per Second:</span>
              <span className="metric-value">
                {processingTime > 0 ? ((totalChanges / processingTime) * 1000).toFixed(1) : 'N/A'}
              </span>
            </div>
          </div>
        )}
      </div>
    );
  };

  const renderDistribution = () => {
    if (!showDistribution) return null;

    return (
      <div className="stats-section distribution">
        <div 
          className="section-header"
          onClick={() => toggleSection('distribution')}
        >
          <h3 className="section-title">Change Distribution</h3>
          <span className="toggle-icon">
            {expandedSections.has('distribution') ? '▼' : '▶'}
          </span>
        </div>
        
        {(expandedSections.has('distribution') || !compact) && (
          <div className="distribution-content">
            <div className="distribution-group">
              <h4>By Type</h4>
              {distribution.byType.map(item => (
                <div key={item.type} className="distribution-item">
                  <div className="distribution-bar">
                    <div 
                      className={`bar-fill ${item.type}`}
                      style={{ width: `${item.percentage}%` }}
                    />
                  </div>
                  <div className="distribution-label">
                    <span className="type-name">{item.type}</span>
                    <span className="type-count">{item.count} ({item.percentage.toFixed(1)}%)</span>
                  </div>
                </div>
              ))}
            </div>

            <div className="distribution-group">
              <h4>By Size</h4>
              {distribution.bySize.map(item => (
                <div key={item.range} className="distribution-item">
                  <div className="distribution-bar">
                    <div 
                      className="bar-fill size"
                      style={{ width: `${item.percentage}%` }}
                    />
                  </div>
                  <div className="distribution-label">
                    <span className="type-name">{item.range}</span>
                    <span className="type-count">{item.count} ({item.percentage.toFixed(1)}%)</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  };

  const renderSimilarityChart = () => {
    if (!showCharts) return null;

    const similarity = metrics.similarity;
    const circumference = 2 * Math.PI * 45;
    const strokeDasharray = circumference;
    const strokeDashoffset = circumference - (similarity * circumference);

    return (
      <div className="stats-section similarity-chart">
        <h3 className="section-title">Similarity Score</h3>
        <div className="chart-container">
          <svg className="similarity-circle" width="120" height="120">
            <circle
              cx="60"
              cy="60"
              r="45"
              fill="none"
              stroke="#e5e7eb"
              strokeWidth="8"
            />
            <circle
              cx="60"
              cy="60"
              r="45"
              fill="none"
              stroke="#10b981"
              strokeWidth="8"
              strokeLinecap="round"
              strokeDasharray={strokeDasharray}
              strokeDashoffset={strokeDashoffset}
              transform="rotate(-90 60 60)"
              className="similarity-progress"
            />
            <text
              x="60"
              y="60"
              textAnchor="middle"
              dominantBaseline="middle"
              className="similarity-text"
            >
              {(similarity * 100).toFixed(0)}%
            </text>
          </svg>
          <div className="similarity-description">
            <span className="similarity-level">
              {similarity > 0.8 ? 'High' : similarity > 0.5 ? 'Medium' : 'Low'} Similarity
            </span>
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className={`diff-stats ${theme} ${compact ? 'compact' : ''} ${className}`}>
      {renderBasicStats()}
      {renderSimilarityChart()}
      {renderDetailedMetrics()}
      {renderPerformanceInfo()}
      {renderDistribution()}

      <style jsx>{`
        .diff-stats {
          display: flex;
          flex-direction: column;
          gap: 16px;
          padding: 16px;
          background-color: #ffffff;
          border: 1px solid #e1e4e8;
          border-radius: 8px;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          font-size: 14px;
        }

        .diff-stats.dark {
          background-color: #0d1117;
          border-color: #30363d;
          color: #f0f6fc;
        }

        .diff-stats.compact {
          padding: 12px;
          gap: 12px;
        }

        .stats-section {
          background-color: #f6f8fa;
          border: 1px solid #e1e4e8;
          border-radius: 6px;
          padding: 16px;
        }

        .diff-stats.dark .stats-section {
          background-color: #161b22;
          border-color: #30363d;
        }

        .section-title {
          margin: 0 0 12px 0;
          font-size: 16px;
          font-weight: 600;
          color: #24292f;
        }

        .diff-stats.dark .section-title {
          color: #f0f6fc;
        }

        .section-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          cursor: pointer;
          margin-bottom: 12px;
        }

        .toggle-icon {
          color: #656d76;
          font-size: 12px;
        }

        .diff-stats.dark .toggle-icon {
          color: #8b949e;
        }

        .stats-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
          gap: 12px;
        }

        .stat-item {
          display: flex;
          flex-direction: column;
          align-items: center;
          padding: 12px;
          background-color: #ffffff;
          border: 1px solid #d0d7de;
          border-radius: 6px;
          cursor: pointer;
          transition: all 0.15s ease;
        }

        .stat-item:hover {
          border-color: #0969da;
          box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }

        .diff-stats.dark .stat-item {
          background-color: #0d1117;
          border-color: #30363d;
        }

        .diff-stats.dark .stat-item:hover {
          border-color: #58a6ff;
        }

        .stat-value {
          font-size: 24px;
          font-weight: 700;
          margin-bottom: 4px;
        }

        .stat-label {
          font-size: 12px;
          color: #656d76;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }

        .diff-stats.dark .stat-label {
          color: #8b949e;
        }

        .stat-item.additions .stat-value {
          color: #1a7f37;
        }

        .stat-item.deletions .stat-value {
          color: #cf222e;
        }

        .stat-item.modifications .stat-value {
          color: #9a6700;
        }

        .stat-item.similarity .stat-value {
          color: #0969da;
        }

        .diff-stats.dark .stat-item.additions .stat-value {
          color: #3fb950;
        }

        .diff-stats.dark .stat-item.deletions .stat-value {
          color: #f85149;
        }

        .diff-stats.dark .stat-item.modifications .stat-value {
          color: #e3b341;
        }

        .diff-stats.dark .stat-item.similarity .stat-value {
          color: #58a6ff;
        }

        .metrics-content {
          margin-top: 12px;
        }

        .metrics-row {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
          gap: 20px;
        }

        .metric-group h4 {
          margin: 0 0 12px 0;
          font-size: 14px;
          font-weight: 600;
          color: #656d76;
          border-bottom: 1px solid #e1e4e8;
          padding-bottom: 6px;
        }

        .diff-stats.dark .metric-group h4 {
          color: #8b949e;
          border-bottom-color: #30363d;
        }

        .metric-item {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 6px 0;
          border-bottom: 1px solid #f6f8fa;
        }

        .metric-item:last-child {
          border-bottom: none;
        }

        .diff-stats.dark .metric-item {
          border-bottom-color: #21262d;
        }

        .metric-label {
          color: #656d76;
          font-size: 13px;
        }

        .diff-stats.dark .metric-label {
          color: #8b949e;
        }

        .metric-value {
          font-weight: 500;
          font-size: 13px;
        }

        .metric-value.additions {
          color: #1a7f37;
        }

        .metric-value.deletions {
          color: #cf222e;
        }

        .metric-value.complexity-low {
          color: #1a7f37;
        }

        .metric-value.complexity-medium {
          color: #9a6700;
        }

        .metric-value.complexity-high {
          color: #cf222e;
        }

        .chart-container {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 12px;
        }

        .similarity-circle {
          transform: rotate(-90deg);
        }

        .similarity-progress {
          transition: stroke-dashoffset 0.5s ease;
        }

        .similarity-text {
          font-size: 18px;
          font-weight: 600;
          fill: #24292f;
        }

        .diff-stats.dark .similarity-text {
          fill: #f0f6fc;
        }

        .similarity-description {
          text-align: center;
        }

        .similarity-level {
          font-size: 12px;
          color: #656d76;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }

        .diff-stats.dark .similarity-level {
          color: #8b949e;
        }

        .distribution-content {
          display: flex;
          flex-direction: column;
          gap: 20px;
        }

        .distribution-group h4 {
          margin: 0 0 12px 0;
          font-size: 14px;
          font-weight: 600;
          color: #656d76;
        }

        .diff-stats.dark .distribution-group h4 {
          color: #8b949e;
        }

        .distribution-item {
          margin-bottom: 8px;
        }

        .distribution-bar {
          height: 6px;
          background-color: #e1e4e8;
          border-radius: 3px;
          overflow: hidden;
          margin-bottom: 4px;
        }

        .diff-stats.dark .distribution-bar {
          background-color: #30363d;
        }

        .bar-fill {
          height: 100%;
          transition: width 0.3s ease;
        }

        .bar-fill.insert {
          background-color: #1a7f37;
        }

        .bar-fill.delete {
          background-color: #cf222e;
        }

        .bar-fill.modify {
          background-color: #9a6700;
        }

        .bar-fill.equal {
          background-color: #656d76;
        }

        .bar-fill.size {
          background-color: #0969da;
        }

        .distribution-label {
          display: flex;
          justify-content: space-between;
          font-size: 12px;
        }

        .type-name {
          text-transform: capitalize;
          color: #24292f;
        }

        .diff-stats.dark .type-name {
          color: #f0f6fc;
        }

        .type-count {
          color: #656d76;
        }

        .diff-stats.dark .type-count {
          color: #8b949e;
        }

        .performance-content {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 12px;
        }
      `}</style>
    </div>
  );
};

/**
 * Calcula métricas detalhadas do resultado do diff
 */
function calculateDetailedMetrics(diffResult: DiffResult): DetailedMetrics {
  let totalLines = 0;
  let totalCharacters = 0;
  let addedCharacters = 0;
  let deletedCharacters = 0;
  let additions = 0;
  let deletions = 0;
  let modifications = 0;
  let unchanged = 0;

  const chunkSizes: number[] = [];

  diffResult.chunks.forEach(chunk => {
    const lines = chunk.text.split('\n');
    const lineCount = lines.length;
    const charCount = chunk.text.length;

    chunkSizes.push(lineCount);
    totalLines += lineCount;
    totalCharacters += charCount;

    switch (chunk.operation) {
      case 'insert':
        additions += lineCount;
        addedCharacters += charCount;
        break;
      case 'delete':
        deletions += lineCount;
        deletedCharacters += charCount;
        break;
      case 'modify':
        modifications += lineCount;
        break;
      case 'equal':
        unchanged += lineCount;
        break;
    }
  });

  const totalChangedLines = additions + deletions + modifications;
  const changeIntensity = totalLines > 0 ? totalChangedLines / totalLines : 0;
  
  const complexity: 'low' | 'medium' | 'high' = 
    changeIntensity < 0.1 ? 'low' :
    changeIntensity < 0.3 ? 'medium' : 'high';

  const avgChunkSize = chunkSizes.length > 0 
    ? chunkSizes.reduce((sum, size) => sum + size, 0) / chunkSizes.length 
    : 0;

  return {
    additions,
    deletions,
    modifications,
    unchanged,
    totalLines,
    totalCharacters,
    addedCharacters,
    deletedCharacters,
    similarity: diffResult.getOverallSimilarity(),
    complexity,
    changeIntensity,
    avgChunkSize,
    largestChunk: Math.max(...chunkSizes, 0),
    smallestChunk: Math.min(...chunkSizes, 0)
  };
}

/**
 * Calcula distribuição de mudanças
 */
function calculateChangeDistribution(diffResult: DiffResult): ChangeDistribution {
  const typeCount: Record<string, number> = {};
  const sizeRanges = {
    'Small (1-5)': 0,
    'Medium (6-20)': 0,
    'Large (21-50)': 0,
    'XLarge (50+)': 0
  };

  diffResult.chunks.forEach(chunk => {
    // Contar por tipo
    typeCount[chunk.operation] = (typeCount[chunk.operation] || 0) + 1;

    // Contar por tamanho
    const lineCount = chunk.text.split('\n').length;
    if (lineCount <= 5) sizeRanges['Small (1-5)']++;
    else if (lineCount <= 20) sizeRanges['Medium (6-20)']++;
    else if (lineCount <= 50) sizeRanges['Large (21-50)']++;
    else sizeRanges['XLarge (50+)']++;
  });

  const totalChunks = diffResult.chunks.length;

  const byType = Object.entries(typeCount).map(([type, count]) => ({
    type,
    count,
    percentage: totalChunks > 0 ? (count / totalChunks) * 100 : 0
  }));

  const bySize = Object.entries(sizeRanges).map(([range, count]) => ({
    range,
    count,
    percentage: totalChunks > 0 ? (count / totalChunks) * 100 : 0
  }));

  return {
    byType,
    bySize,
    byPosition: [] // Simplified for now
  };
}

export default DiffStats; 