import { DiffResult, DiffChunk } from '../../domain/entities/DiffResult';
import { DocumentComparison } from '../../domain/entities/DocumentComparison';

export type ExportFormat = 'pdf' | 'docx' | 'csv' | 'json' | 'html' | 'txt';

export interface ExportOptions {
  format: ExportFormat;
  includeMetadata?: boolean;
  includeStatistics?: boolean;
  template?: 'minimal' | 'detailed' | 'executive';
  styling?: {
    theme: 'light' | 'dark';
    fontSize: number;
    fontFamily: string;
    showLineNumbers: boolean;
    highlightChanges: boolean;
  };
  filters?: {
    includeAdditions: boolean;
    includeDeletions: boolean;
    includeModifications: boolean;
    minChangeSize: number;
  };
}

export interface ExportResult {
  fileName: string;
  mimeType: string;
  content: Buffer | string;
  size: number;
  generatedAt: Date;
  metadata: {
    format: ExportFormat;
    totalChanges: number;
    exportDuration: number;
  };
}

export interface ExportComparisonRequest {
  comparison: DocumentComparison;
  diffResult: DiffResult;
  options: ExportOptions;
  outputFileName?: string;
}

export class ExportComparisonError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly details?: any
  ) {
    super(message);
    this.name = 'ExportComparisonError';
  }
}

export class ExportComparison {
  private readonly supportedFormats: Set<ExportFormat> = new Set([
    'pdf', 'docx', 'csv', 'json', 'html', 'txt'
  ]);

  async execute(request: ExportComparisonRequest): Promise<ExportResult> {
    const startTime = Date.now();

    try {
      // Validar entrada
      this.validateRequest(request);

      // Gerar conteúdo baseado no formato
      const result = await this.generateExport(request);
      
      const exportDuration = Date.now() - startTime;
      
      return {
        ...result,
        generatedAt: new Date(),
        metadata: {
          format: request.options.format,
          totalChanges: request.diffResult.getTotalChangeCount(),
          exportDuration
        }
      };

    } catch (error) {
      if (error instanceof ExportComparisonError) {
        throw error;
      }

      throw new ExportComparisonError(
        `Falha na exportação: ${error instanceof Error ? error.message : 'Erro desconhecido'}`,
        'EXPORT_FAILED',
        { originalError: error }
      );
    }
  }

  private validateRequest(request: ExportComparisonRequest): void {
    if (!request.comparison || !request.diffResult) {
      throw new ExportComparisonError(
        'Comparação e resultado são obrigatórios',
        'MISSING_DATA'
      );
    }

    if (!this.supportedFormats.has(request.options.format)) {
      throw new ExportComparisonError(
        `Formato não suportado: ${request.options.format}`,
        'UNSUPPORTED_FORMAT'
      );
    }

    if (request.diffResult.chunks.length === 0) {
      throw new ExportComparisonError(
        'Resultado da comparação deve estar completo para exportação',
        'INCOMPLETE_RESULT'
      );
    }
  }

  private async generateExport(request: ExportComparisonRequest): Promise<Omit<ExportResult, 'generatedAt' | 'metadata'>> {
    const { format } = request.options;
    const fileName = this.generateFileName(request);

    switch (format) {
      case 'json':
        return this.exportToJson(request, fileName);
      case 'csv':
        return this.exportToCsv(request, fileName);
      case 'html':
        return this.exportToHtml(request, fileName);
      case 'txt':
        return this.exportToText(request, fileName);
      case 'pdf':
        return this.exportToPdf(request, fileName);
      case 'docx':
        return this.exportToDocx(request, fileName);
      default:
        throw new ExportComparisonError(
          `Formato não implementado: ${format}`,
          'FORMAT_NOT_IMPLEMENTED'
        );
    }
  }

  private exportToJson(request: ExportComparisonRequest, fileName: string): Omit<ExportResult, 'generatedAt' | 'metadata'> {
    const { comparison, diffResult, options } = request;
    
    const exportData = {
      comparison: {
        id: comparison.id,
        originalDocument: comparison.originalDocument,
        modifiedDocument: comparison.modifiedDocument,
        config: comparison.config,
        createdAt: comparison.createdAt,
        status: comparison.status
      },
      result: diffResult.toJSON(),
      ...(options.includeStatistics && {
        statistics: diffResult.statistics
      }),
      ...(options.includeMetadata && {
        metadata: {
          exportedAt: new Date().toISOString(),
          format: options.format,
          template: options.template || 'detailed'
        }
      })
    };

    const content = JSON.stringify(exportData, null, 2);
    
    return {
      fileName,
      mimeType: 'application/json',
      content,
      size: Buffer.byteLength(content, 'utf8')
    };
  }

  private exportToCsv(request: ExportComparisonRequest, fileName: string): Omit<ExportResult, 'generatedAt' | 'metadata'> {
    const { diffResult, options } = request;
    const chunks = this.filterChunks(diffResult.chunks, options.filters);
    
    const headers = [
      'Linha',
      'Tipo',
      'Conteúdo',
      'Índice Original',
      'Índice Modificado'
    ];
    
    const rows = chunks.map(chunk => [
      chunk.lineNumber?.toString() || '',
      this.translateOperation(chunk.operation),
      `"${chunk.text.replace(/"/g, '""')}"`, // Escape quotes
      chunk.originalIndex?.toString() || '',
      chunk.modifiedIndex?.toString() || ''
    ]);

    const csvContent = [
      headers.join(','),
      ...rows.map(row => row.join(','))
    ].join('\n');

    return {
      fileName,
      mimeType: 'text/csv',
      content: csvContent,
      size: Buffer.byteLength(csvContent, 'utf8')
    };
  }

  private exportToHtml(request: ExportComparisonRequest, fileName: string): Omit<ExportResult, 'generatedAt' | 'metadata'> {
    const { comparison, diffResult, options } = request;
    const styling = options.styling || {
      theme: 'light',
      fontSize: 14,
      fontFamily: 'Arial, sans-serif',
      showLineNumbers: true,
      highlightChanges: true
    };

    const chunks = this.filterChunks(diffResult.chunks, options.filters);
    
    const htmlContent = `
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Comparação de Documentos - ${comparison.id}</title>
    <style>
        body {
            font-family: ${styling.fontFamily};
            font-size: ${styling.fontSize}px;
            background-color: ${styling.theme === 'dark' ? '#1a1a1a' : '#ffffff'};
            color: ${styling.theme === 'dark' ? '#ffffff' : '#000000'};
            margin: 20px;
            line-height: 1.6;
        }
        .header {
            border-bottom: 2px solid #ccc;
            padding-bottom: 15px;
            margin-bottom: 20px;
        }
        .metadata {
            background-color: ${styling.theme === 'dark' ? '#2a2a2a' : '#f5f5f5'};
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .statistics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .stat-item {
            background-color: ${styling.theme === 'dark' ? '#2a2a2a' : '#f9f9f9'};
            padding: 10px;
            border-radius: 5px;
            text-align: center;
        }
        .diff-content {
            border: 1px solid #ccc;
            border-radius: 5px;
            overflow-x: auto;
        }
        .diff-line {
            padding: 5px 10px;
            border-bottom: 1px solid #eee;
        }
        ${styling.showLineNumbers ? `
        .line-number {
            display: inline-block;
            width: 50px;
            color: #666;
            font-family: monospace;
        }
        ` : ''}
        ${styling.highlightChanges ? `
        .insert { background-color: #d4edda; color: #155724; }
        .delete { background-color: #f8d7da; color: #721c24; text-decoration: line-through; }
        .modify { background-color: #fff3cd; color: #856404; }
        ` : ''}
    </style>
</head>
<body>
    <div class="header">
        <h1>Comparação de Documentos</h1>
        <p>ID: ${comparison.id}</p>
        <p>Gerado em: ${new Date().toLocaleString('pt-BR')}</p>
    </div>

    ${options.includeMetadata ? `
    <div class="metadata">
        <h2>Informações dos Documentos</h2>
        <p><strong>Original:</strong> ${comparison.originalDocument.name} (${this.formatFileSize(comparison.originalDocument.size)})</p>
        <p><strong>Modificado:</strong> ${comparison.modifiedDocument.name} (${this.formatFileSize(comparison.modifiedDocument.size)})</p>
        <p><strong>Algoritmo:</strong> ${comparison.config.algorithm}</p>
    </div>
    ` : ''}

    ${options.includeStatistics ? `
    <div class="statistics">
        <div class="stat-item">
            <h3>Total de Alterações</h3>
            <p>${diffResult.statistics.totalChanges}</p>
        </div>
        <div class="stat-item">
            <h3>Adições</h3>
            <p>${diffResult.statistics.additions}</p>
        </div>
        <div class="stat-item">
            <h3>Remoções</h3>
            <p>${diffResult.statistics.deletions}</p>
        </div>
        <div class="stat-item">
            <h3>Similaridade</h3>
            <p>${(diffResult.statistics.similarity.overall * 100).toFixed(1)}%</p>
        </div>
    </div>
    ` : ''}

    <div class="diff-content">
        ${chunks.map((chunk, index) => `
            <div class="diff-line ${chunk.operation}">
                ${styling.showLineNumbers ? `<span class="line-number">${index + 1}</span>` : ''}
                <span>${this.escapeHtml(chunk.text)}</span>
            </div>
        `).join('')}
    </div>
</body>
</html>`;

    return {
      fileName,
      mimeType: 'text/html',
      content: htmlContent,
      size: Buffer.byteLength(htmlContent, 'utf8')
    };
  }

  private exportToText(request: ExportComparisonRequest, fileName: string): Omit<ExportResult, 'generatedAt' | 'metadata'> {
    const { comparison, diffResult, options } = request;
    const chunks = this.filterChunks(diffResult.chunks, options.filters);
    
    const lines = [
      '==========================================',
      'RELATÓRIO DE COMPARAÇÃO DE DOCUMENTOS',
      '==========================================',
      '',
      `ID da Comparação: ${comparison.id}`,
      `Data: ${new Date().toLocaleString('pt-BR')}`,
      '',
      'DOCUMENTOS:',
      `Original: ${comparison.originalDocument.name}`,
      `Modificado: ${comparison.modifiedDocument.name}`,
      `Algoritmo: ${comparison.config.algorithm}`,
      ''
    ];

    if (options.includeStatistics) {
      lines.push(
        'ESTATÍSTICAS:',
        `Total de alterações: ${diffResult.statistics.totalChanges}`,
        `Adições: ${diffResult.statistics.additions}`,
        `Remoções: ${diffResult.statistics.deletions}`,
        `Modificações: ${diffResult.statistics.modifications}`,
        `Similaridade: ${(diffResult.statistics.similarity.overall * 100).toFixed(1)}%`,
        ''
      );
    }

    lines.push('ALTERAÇÕES:');
    lines.push(''.padEnd(40, '-'));

    chunks.forEach((chunk, index) => {
      const prefix = this.getTextPrefix(chunk.operation);
      lines.push(`${index + 1}. ${prefix} ${chunk.text.trim()}`);
    });

    const content = lines.join('\n');
    
    return {
      fileName,
      mimeType: 'text/plain',
      content,
      size: Buffer.byteLength(content, 'utf8')
    };
  }

  private async exportToPdf(request: ExportComparisonRequest, fileName: string): Promise<ExportResult> {
    // Por enquanto, gerar HTML e indicar que precisa de conversão para PDF
    const htmlResult = this.exportToHtml(request, fileName.replace('.pdf', '.html'));
    
    // Em uma implementação real, aqui usaríamos uma biblioteca como puppeteer ou jsPDF
    throw new ExportComparisonError(
      'Exportação para PDF não implementada ainda. Use HTML como alternativa.',
      'PDF_NOT_IMPLEMENTED'
    );
  }

  private async exportToDocx(request: ExportComparisonRequest, fileName: string): Promise<ExportResult> {
    // Em uma implementação real, usaríamos uma biblioteca como docx ou officegen
    throw new ExportComparisonError(
      'Exportação para DOCX não implementada ainda. Use HTML como alternativa.',
      'DOCX_NOT_IMPLEMENTED'
    );
  }

  private filterChunks(chunks: DiffChunk[], filters?: ExportOptions['filters']): DiffChunk[] {
    if (!filters) return chunks;

    return chunks.filter(chunk => {
      if (!filters.includeAdditions && chunk.operation === 'insert') return false;
      if (!filters.includeDeletions && chunk.operation === 'delete') return false;
      if (!filters.includeModifications && chunk.operation === 'modify') return false;
      if (filters.minChangeSize && chunk.text.length < filters.minChangeSize) return false;
      return true;
    });
  }

  private generateFileName(request: ExportComparisonRequest): string {
    if (request.outputFileName) {
      return request.outputFileName;
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').split('T')[0];
    const format = request.options.format;
    return `comparacao_${request.comparison.id}_${timestamp}.${format}`;
  }

  private translateOperation(operation: string): string {
    const translations = {
      'insert': 'Adição',
      'delete': 'Remoção',
      'modify': 'Modificação',
      'equal': 'Inalterado'
    };
    return translations[operation as keyof typeof translations] || operation;
  }

  private getTextPrefix(operation: string): string {
    const prefixes = {
      'insert': '[+]',
      'delete': '[-]',
      'modify': '[~]',
      'equal': '[ ]'
    };
    return prefixes[operation as keyof typeof prefixes] || '[?]';
  }

  private escapeHtml(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  private formatFileSize(bytes: number): string {
    const units = ['B', 'KB', 'MB', 'GB'];
    let size = bytes;
    let unitIndex = 0;
    
    while (size >= 1024 && unitIndex < units.length - 1) {
      size /= 1024;
      unitIndex++;
    }
    
    return `${size.toFixed(1)} ${units[unitIndex]}`;
  }

  getSupportedFormats(): ExportFormat[] {
    return Array.from(this.supportedFormats);
  }
} 