export interface ChunkConfig {
  maxChunkSize: number; // Tamanho máximo do chunk em caracteres (padrão: 50000)
  minChunkSize: number; // Tamanho mínimo do chunk em caracteres (padrão: 10000)
  overlapSize: number; // Sobreposição entre chunks em caracteres (padrão: 1000)
  chunkingStrategy: 'paragraph' | 'sentence' | 'word' | 'character' | 'semantic';
  enableSmartBoundaries: boolean; // Quebrar apenas em limites semânticos (padrão: true)
  preserveFormatting: boolean; // Preservar formatação durante chunking (padrão: true)
  maxChunks: number; // Número máximo de chunks (padrão: 1000)
}

export interface DocumentChunk {
  id: string;
  index: number;
  startPosition: number;
  endPosition: number;
  content: string;
  size: number;
  type: 'header' | 'paragraph' | 'list' | 'table' | 'other';
  metadata: {
    originalLength: number;
    hasOverlap: boolean;
    boundaryType: 'natural' | 'forced';
    semanticLevel?: number;
    formatting?: Record<string, any>;
  };
  hash: string;
}

export interface ChunkingResult {
  chunks: DocumentChunk[];
  totalChunks: number;
  totalSize: number;
  strategy: string;
  config: ChunkConfig;
  processingTime: number;
  metadata: {
    originalSize: number;
    compressionRatio: number;
    averageChunkSize: number;
    overlapTotal: number;
  };
}

export class DocumentChunkerError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly details?: any
  ) {
    super(message);
    this.name = 'DocumentChunkerError';
  }
}

/**
 * Sistema avançado de chunking para documentos grandes
 */
export class DocumentChunker {
  private readonly config: ChunkConfig;
  private readonly patterns = {
    paragraph: /\n\s*\n/g,
    sentence: /[.!?]+\s+/g,
    word: /\s+/g,
    header: /^#{1,6}\s+.+$/gm,
    listItem: /^[\s]*[-*+]\s+.+$/gm,
    numberedList: /^[\s]*\d+\.\s+.+$/gm,
    table: /^\|.+\|$/gm
  };

  constructor(config: Partial<ChunkConfig> = {}) {
    this.config = {
      maxChunkSize: config.maxChunkSize || 50000,
      minChunkSize: config.minChunkSize || 10000,
      overlapSize: config.overlapSize || 1000,
      chunkingStrategy: config.chunkingStrategy || 'paragraph',
      enableSmartBoundaries: config.enableSmartBoundaries ?? true,
      preserveFormatting: config.preserveFormatting ?? true,
      maxChunks: config.maxChunks || 1000
    };

    this.validateConfig();
  }

  /**
   * Chunka um documento em partes menores
   */
  public chunkDocument(content: string, documentId?: string): ChunkingResult {
    const startTime = performance.now();

    try {
      this.validateInput(content);

      // Se o documento for pequeno, retornar como chunk único
      if (content.length <= this.config.maxChunkSize) {
        return this.createSingleChunkResult(content, startTime);
      }

      let chunks: DocumentChunk[];

      // Aplicar estratégia de chunking apropriada
      switch (this.config.chunkingStrategy) {
        case 'paragraph':
          chunks = this.chunkByParagraphs(content);
          break;
        case 'sentence':
          chunks = this.chunkBySentences(content);
          break;
        case 'word':
          chunks = this.chunkByWords(content);
          break;
        case 'character':
          chunks = this.chunkByCharacters(content);
          break;
        case 'semantic':
          chunks = this.chunkSemanticly(content);
          break;
        default:
          throw new DocumentChunkerError(
            `Estratégia de chunking não suportada: ${this.config.chunkingStrategy}`,
            'UNSUPPORTED_STRATEGY'
          );
      }

      // Pós-processamento dos chunks
      chunks = this.postProcessChunks(chunks, content);

      // Aplicar sobreposição se configurada
      if (this.config.overlapSize > 0) {
        chunks = this.applyOverlap(chunks, content);
      }

      // Validar resultado
      this.validateChunks(chunks, content);

      const processingTime = performance.now() - startTime;

      return this.createChunkingResult(chunks, content, processingTime);

    } catch (error) {
      if (error instanceof DocumentChunkerError) {
        throw error;
      }
      throw new DocumentChunkerError(
        `Falha no chunking: ${error instanceof Error ? error.message : 'Erro desconhecido'}`,
        'CHUNKING_FAILED',
        { contentLength: content.length, strategy: this.config.chunkingStrategy }
      );
    }
  }

  /**
   * Otimiza chunks existentes para melhor performance
   */
  public optimizeChunks(chunks: DocumentChunk[]): DocumentChunk[] {
    const optimized = [...chunks];

    // Combinar chunks muito pequenos
    for (let i = 0; i < optimized.length - 1; i++) {
      const current = optimized[i];
      const next = optimized[i + 1];

      if (current.size < this.config.minChunkSize && 
          next.size < this.config.minChunkSize &&
          current.size + next.size <= this.config.maxChunkSize) {
        
        // Combinar chunks
        const combined: DocumentChunk = {
          id: this.generateChunkId(i),
          index: i,
          startPosition: current.startPosition,
          endPosition: next.endPosition,
          content: current.content + '\n' + next.content,
          size: current.size + next.size + 1,
          type: current.type === next.type ? current.type : 'other',
          metadata: {
            originalLength: current.metadata.originalLength + next.metadata.originalLength,
            hasOverlap: current.metadata.hasOverlap || next.metadata.hasOverlap,
            boundaryType: 'forced',
            semanticLevel: Math.min(
              current.metadata.semanticLevel || 0,
              next.metadata.semanticLevel || 0
            )
          },
          hash: this.generateHash(current.content + '\n' + next.content)
        };

        optimized[i] = combined;
        optimized.splice(i + 1, 1);

        // Atualizar índices dos chunks subsequentes
        for (let j = i + 1; j < optimized.length; j++) {
          optimized[j].index = j;
        }
      }
    }

    return optimized;
  }

  /**
   * Reconstrói o documento original a partir dos chunks
   */
  public reconstructDocument(chunks: DocumentChunk[]): string {
    // Ordenar chunks por posição
    const sortedChunks = [...chunks].sort((a, b) => a.startPosition - b.startPosition);
    
    let reconstructed = '';
    let lastEndPosition = 0;

    for (const chunk of sortedChunks) {
      // Verificar se há lacuna (isso não deveria acontecer normalmente)
      if (chunk.startPosition > lastEndPosition) {
        console.warn(`Lacuna detectada entre chunks: ${lastEndPosition} - ${chunk.startPosition}`);
      }

      // Adicionar conteúdo do chunk (removendo sobreposição se houver)
      if (chunk.metadata.hasOverlap && lastEndPosition > chunk.startPosition) {
        const overlapStart = lastEndPosition - chunk.startPosition;
        reconstructed += chunk.content.substring(overlapStart);
      } else {
        reconstructed += chunk.content;
      }

      lastEndPosition = chunk.endPosition;
    }

    return reconstructed;
  }

  /**
   * Calcula métricas de chunking
   */
  public calculateMetrics(result: ChunkingResult): {
    efficiency: number;
    balance: number;
    overhead: number;
    coverage: number;
  } {
    const { chunks, metadata } = result;
    
    // Eficiência: quão próximo os chunks estão do tamanho ideal
    const idealSize = (this.config.maxChunkSize + this.config.minChunkSize) / 2;
    const sizeVariance = chunks.reduce((sum, chunk) => {
      return sum + Math.pow(chunk.size - idealSize, 2);
    }, 0) / chunks.length;
    const efficiency = Math.max(0, 1 - (sizeVariance / (idealSize * idealSize)));

    // Balanceamento: quão uniforme são os tamanhos dos chunks
    const avgSize = metadata.averageChunkSize;
    const maxDeviation = Math.max(...chunks.map(chunk => Math.abs(chunk.size - avgSize)));
    const balance = Math.max(0, 1 - (maxDeviation / avgSize));

    // Overhead: custo adicional da sobreposição
    const overhead = metadata.overlapTotal / metadata.originalSize;

    // Cobertura: percentual do documento original coberto
    const coverage = chunks.reduce((sum, chunk) => sum + chunk.metadata.originalLength, 0) / metadata.originalSize;

    return {
      efficiency: Math.round(efficiency * 100) / 100,
      balance: Math.round(balance * 100) / 100,
      overhead: Math.round(overhead * 100) / 100,
      coverage: Math.round(coverage * 100) / 100
    };
  }

  // Métodos privados de chunking

  private chunkByParagraphs(content: string): DocumentChunk[] {
    const paragraphs = content.split(this.patterns.paragraph);
    const chunks: DocumentChunk[] = [];
    let currentChunk = '';
    let startPosition = 0;
    let chunkIndex = 0;

    for (const paragraph of paragraphs) {
      if (!paragraph.trim()) continue;

      const potentialChunk = currentChunk + (currentChunk ? '\n\n' : '') + paragraph;

      if (potentialChunk.length <= this.config.maxChunkSize) {
        currentChunk = potentialChunk;
      } else {
        // Finalizar chunk atual se não estiver vazio
        if (currentChunk) {
          chunks.push(this.createChunk(currentChunk, chunkIndex++, startPosition, 'paragraph'));
          startPosition += currentChunk.length;
          currentChunk = '';
        }

        // Se o parágrafo individual for muito grande, quebrá-lo
        if (paragraph.length > this.config.maxChunkSize) {
          const subChunks = this.chunkBySentences(paragraph);
          chunks.push(...subChunks.map(subChunk => ({
            ...subChunk,
            index: chunkIndex++,
            startPosition: startPosition + subChunk.startPosition
          })));
          startPosition += paragraph.length;
        } else {
          currentChunk = paragraph;
        }
      }
    }

    // Adicionar último chunk se houver conteúdo
    if (currentChunk) {
      chunks.push(this.createChunk(currentChunk, chunkIndex, startPosition, 'paragraph'));
    }

    return chunks;
  }

  private chunkBySentences(content: string): DocumentChunk[] {
    const sentences = content.split(this.patterns.sentence);
    const chunks: DocumentChunk[] = [];
    let currentChunk = '';
    let startPosition = 0;
    let chunkIndex = 0;

    for (const sentence of sentences) {
      if (!sentence.trim()) continue;

      const potentialChunk = currentChunk + (currentChunk ? ' ' : '') + sentence;

      if (potentialChunk.length <= this.config.maxChunkSize) {
        currentChunk = potentialChunk;
      } else {
        if (currentChunk) {
          chunks.push(this.createChunk(currentChunk, chunkIndex++, startPosition, 'paragraph'));
          startPosition += currentChunk.length;
        }
        currentChunk = sentence;
      }
    }

    if (currentChunk) {
      chunks.push(this.createChunk(currentChunk, chunkIndex, startPosition, 'paragraph'));
    }

    return chunks;
  }

  private chunkByWords(content: string): DocumentChunk[] {
    const words = content.split(this.patterns.word);
    const chunks: DocumentChunk[] = [];
    let currentChunk = '';
    let startPosition = 0;
    let chunkIndex = 0;

    for (const word of words) {
      if (!word.trim()) continue;

      const potentialChunk = currentChunk + (currentChunk ? ' ' : '') + word;

      if (potentialChunk.length <= this.config.maxChunkSize) {
        currentChunk = potentialChunk;
      } else {
        if (currentChunk) {
          chunks.push(this.createChunk(currentChunk, chunkIndex++, startPosition, 'paragraph'));
          startPosition += currentChunk.length;
        }
        currentChunk = word;
      }
    }

    if (currentChunk) {
      chunks.push(this.createChunk(currentChunk, chunkIndex, startPosition, 'paragraph'));
    }

    return chunks;
  }

  private chunkByCharacters(content: string): DocumentChunk[] {
    const chunks: DocumentChunk[] = [];
    let chunkIndex = 0;

    for (let i = 0; i < content.length; i += this.config.maxChunkSize) {
      const endPos = Math.min(i + this.config.maxChunkSize, content.length);
      const chunkContent = content.substring(i, endPos);
      
      chunks.push(this.createChunk(chunkContent, chunkIndex++, i, 'other'));
    }

    return chunks;
  }

  private chunkSemanticly(content: string): DocumentChunk[] {
    // Chunking semântico - identifica estruturas como cabeçalhos, listas, etc.
    const chunks: DocumentChunk[] = [];
    const lines = content.split('\n');
    let currentChunk = '';
    let currentType: DocumentChunk['type'] = 'other';
    let startPosition = 0;
    let chunkIndex = 0;

    for (const line of lines) {
      const lineType = this.identifyLineType(line);
      
      // Se mudou o tipo semântico ou excedeu o tamanho, finalizar chunk atual
      if ((lineType !== currentType && currentChunk) || 
          (currentChunk + '\n' + line).length > this.config.maxChunkSize) {
        
        if (currentChunk) {
          chunks.push(this.createChunk(currentChunk, chunkIndex++, startPosition, currentType));
          startPosition += currentChunk.length + 1; // +1 para \n
        }
        currentChunk = '';
      }

      currentChunk += (currentChunk ? '\n' : '') + line;
      currentType = lineType;
    }

    if (currentChunk) {
      chunks.push(this.createChunk(currentChunk, chunkIndex, startPosition, currentType));
    }

    return chunks;
  }

  private identifyLineType(line: string): DocumentChunk['type'] {
    if (this.patterns.header.test(line)) return 'header';
    if (this.patterns.listItem.test(line) || this.patterns.numberedList.test(line)) return 'list';
    if (this.patterns.table.test(line)) return 'table';
    if (line.trim() && !line.trim().match(/^\s*$/)) return 'paragraph';
    return 'other';
  }

  private postProcessChunks(chunks: DocumentChunk[], originalContent: string): DocumentChunk[] {
    if (!this.config.enableSmartBoundaries) {
      return chunks;
    }

    // Melhorar limites dos chunks para não quebrar no meio de palavras/sentenças
    const processed: DocumentChunk[] = [];

    for (let i = 0; i < chunks.length; i++) {
      const chunk = chunks[i];
      let content = chunk.content;
      let endPosition = chunk.endPosition;

      // Se não é o último chunk, tentar melhorar o limite final
      if (i < chunks.length - 1) {
        const nextChunkStart = chunks[i + 1].startPosition;
        const availableText = originalContent.substring(chunk.endPosition, nextChunkStart);
        
        // Procurar por uma quebra natural próxima
        const naturalBreak = this.findNaturalBreak(availableText, 100); // Procurar nos próximos 100 caracteres
        
        if (naturalBreak > 0) {
          content += availableText.substring(0, naturalBreak);
          endPosition += naturalBreak;
        }
      }

      processed.push({
        ...chunk,
        content,
        endPosition,
        size: content.length,
        metadata: {
          ...chunk.metadata,
          boundaryType: 'natural'
        }
      });
    }

    return processed;
  }

  private findNaturalBreak(text: string, maxDistance: number): number {
    const searchText = text.substring(0, Math.min(maxDistance, text.length));
    
    // Procurar por quebras naturais em ordem de preferência
    const breakPatterns = [
      /\n\s*\n/, // Parágrafo duplo
      /[.!?]\s+/, // Final de sentença
      /\n/, // Quebra de linha
      /[,;]\s+/, // Vírgula ou ponto e vírgula
      /\s+/ // Espaço
    ];

    for (const pattern of breakPatterns) {
      const matches = [...searchText.matchAll(new RegExp(pattern, 'g'))];
      if (matches.length > 0) {
        const lastMatch = matches[matches.length - 1];
        return (lastMatch.index || 0) + lastMatch[0].length;
      }
    }

    return 0; // Nenhuma quebra natural encontrada
  }

  private applyOverlap(chunks: DocumentChunk[], originalContent: string): DocumentChunk[] {
    if (chunks.length <= 1) return chunks;

    const overlappedChunks: DocumentChunk[] = [chunks[0]];

    for (let i = 1; i < chunks.length; i++) {
      const currentChunk = chunks[i];
      const previousChunk = chunks[i - 1];
      
      // Calcular sobreposição do chunk anterior
      const overlapStart = Math.max(0, previousChunk.endPosition - this.config.overlapSize);
      const overlapContent = originalContent.substring(overlapStart, previousChunk.endPosition);
      
      const overlappedChunk: DocumentChunk = {
        ...currentChunk,
        content: overlapContent + currentChunk.content,
        startPosition: overlapStart,
        size: overlapContent.length + currentChunk.size,
        metadata: {
          ...currentChunk.metadata,
          hasOverlap: true,
          originalLength: currentChunk.size
        }
      };

      overlappedChunks.push(overlappedChunk);
    }

    return overlappedChunks;
  }

  private createChunk(
    content: string, 
    index: number, 
    startPosition: number, 
    type: DocumentChunk['type']
  ): DocumentChunk {
    return {
      id: this.generateChunkId(index),
      index,
      startPosition,
      endPosition: startPosition + content.length,
      content,
      size: content.length,
      type,
      metadata: {
        originalLength: content.length,
        hasOverlap: false,
        boundaryType: 'natural',
        semanticLevel: this.calculateSemanticLevel(content)
      },
      hash: this.generateHash(content)
    };
  }

  private createSingleChunkResult(content: string, startTime: number): ChunkingResult {
    const chunk = this.createChunk(content, 0, 0, 'other');
    const processingTime = performance.now() - startTime;

    return {
      chunks: [chunk],
      totalChunks: 1,
      totalSize: content.length,
      strategy: 'single',
      config: this.config,
      processingTime,
      metadata: {
        originalSize: content.length,
        compressionRatio: 1,
        averageChunkSize: content.length,
        overlapTotal: 0
      }
    };
  }

  private createChunkingResult(chunks: DocumentChunk[], originalContent: string, processingTime: number): ChunkingResult {
    const totalSize = chunks.reduce((sum, chunk) => sum + chunk.size, 0);
    const overlapTotal = chunks.reduce((sum, chunk) => 
      sum + (chunk.metadata.hasOverlap ? chunk.size - chunk.metadata.originalLength : 0), 0);

    return {
      chunks,
      totalChunks: chunks.length,
      totalSize,
      strategy: this.config.chunkingStrategy,
      config: this.config,
      processingTime,
      metadata: {
        originalSize: originalContent.length,
        compressionRatio: totalSize / originalContent.length,
        averageChunkSize: totalSize / chunks.length,
        overlapTotal
      }
    };
  }

  private calculateSemanticLevel(content: string): number {
    // Nível semântico simples baseado em padrões
    let level = 0;
    
    if (this.patterns.header.test(content)) level += 3;
    if (this.patterns.listItem.test(content)) level += 2;
    if (this.patterns.table.test(content)) level += 2;
    if (content.includes('\n\n')) level += 1;
    
    return level;
  }

  private generateChunkId(index: number): string {
    return `chunk_${Date.now()}_${index.toString().padStart(4, '0')}`;
  }

  private generateHash(content: string): string {
    // Hash simples para identificação de conteúdo
    let hash = 0;
    for (let i = 0; i < content.length; i++) {
      const char = content.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Converter para 32bit integer
    }
    return hash.toString(36);
  }

  private validateConfig(): void {
    if (this.config.maxChunkSize <= 0) {
      throw new DocumentChunkerError('maxChunkSize deve ser maior que 0', 'INVALID_CONFIG');
    }
    
    if (this.config.minChunkSize <= 0) {
      throw new DocumentChunkerError('minChunkSize deve ser maior que 0', 'INVALID_CONFIG');
    }
    
    if (this.config.minChunkSize >= this.config.maxChunkSize) {
      throw new DocumentChunkerError('minChunkSize deve ser menor que maxChunkSize', 'INVALID_CONFIG');
    }
    
    if (this.config.overlapSize < 0) {
      throw new DocumentChunkerError('overlapSize deve ser maior ou igual a 0', 'INVALID_CONFIG');
    }
    
    if (this.config.overlapSize >= this.config.minChunkSize) {
      throw new DocumentChunkerError('overlapSize deve ser menor que minChunkSize', 'INVALID_CONFIG');
    }
  }

  private validateInput(content: string): void {
    if (!content || typeof content !== 'string') {
      throw new DocumentChunkerError('Conteúdo deve ser uma string não vazia', 'INVALID_INPUT');
    }
  }

  private validateChunks(chunks: DocumentChunk[], originalContent: string): void {
    if (chunks.length === 0) {
      throw new DocumentChunkerError('Nenhum chunk foi gerado', 'NO_CHUNKS_GENERATED');
    }
    
    if (chunks.length > this.config.maxChunks) {
      throw new DocumentChunkerError(
        `Muitos chunks gerados: ${chunks.length} > ${this.config.maxChunks}`,
        'TOO_MANY_CHUNKS'
      );
    }
    
    // Verificar se todos os chunks estão dentro dos limites de tamanho
    for (const chunk of chunks) {
      if (chunk.size > this.config.maxChunkSize * 1.1) { // 10% de tolerância
        console.warn(`Chunk ${chunk.id} excede o tamanho máximo: ${chunk.size} > ${this.config.maxChunkSize}`);
      }
    }
  }
} 