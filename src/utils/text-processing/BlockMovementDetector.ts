export interface BlockMovementConfig {
  minBlockSize?: number; // Tamanho mínimo do bloco em caracteres (padrão: 50)
  similarityThreshold?: number; // Threshold de similaridade para considerar movimento (padrão: 0.8)
  maxSearchDistance?: number; // Distância máxima para buscar blocos movidos (padrão: 5000)
  detectParagraphMoves?: boolean; // Detectar movimentação de parágrafos (padrão: true)
  detectSentenceMoves?: boolean; // Detectar movimentação de sentenças (padrão: false)
  ignoreWhitespace?: boolean; // Ignorar whitespace na comparação (padrão: true)
}

export interface MovedBlock {
  originalText: string;
  normalizedText: string;
  originalPosition: {
    start: number;
    end: number;
    line: number;
  };
  newPosition: {
    start: number;
    end: number;
    line: number;
  };
  similarity: number;
  confidence: number;
  type: 'paragraph' | 'sentence' | 'block';
  metadata: {
    wordCount: number;
    characterCount: number;
    hasStructuralElements: boolean;
  };
}

export interface BlockMovementResult {
  movedBlocks: MovedBlock[];
  statistics: {
    totalMovedBlocks: number;
    totalMovedCharacters: number;
    averageSimilarity: number;
    processingTime: number;
  };
  remainingChanges: {
    deletions: TextBlock[];
    insertions: TextBlock[];
  };
}

export interface TextBlock {
  text: string;
  position: {
    start: number;
    end: number;
    line: number;
  };
  hash: string;
  normalizedHash: string;
}

/**
 * Detector de movimentação de blocos de texto
 * Identifica quando blocos foram movidos ao invés de deletados/inseridos
 */
export class BlockMovementDetector {
  private readonly defaultConfig: Required<BlockMovementConfig> = {
    minBlockSize: 50,
    similarityThreshold: 0.8,
    maxSearchDistance: 5000,
    detectParagraphMoves: true,
    detectSentenceMoves: false,
    ignoreWhitespace: true
  };

  constructor(private config: BlockMovementConfig = {}) {
    this.config = { ...this.defaultConfig, ...config };
  }

  /**
   * Detecta movimentações de blocos entre dois textos
   */
  public detectMovements(
    originalText: string, 
    modifiedText: string, 
    customConfig?: Partial<BlockMovementConfig>
  ): BlockMovementResult {
    const startTime = performance.now();
    const config = { ...this.config, ...customConfig };

    // 1. Extrair blocos dos textos
    const originalBlocks = this.extractBlocks(originalText, config);
    const modifiedBlocks = this.extractBlocks(modifiedText, config);

    // 2. Detectar movimentações
    const movedBlocks = this.findMovedBlocks(originalBlocks, modifiedBlocks, config);

    // 3. Identificar blocos não movidos (deletions/insertions)
    const remainingChanges = this.identifyRemainingChanges(
      originalBlocks, 
      modifiedBlocks, 
      movedBlocks
    );

    // 4. Calcular estatísticas
    const statistics = this.calculateStatistics(movedBlocks, performance.now() - startTime);

    return {
      movedBlocks,
      statistics,
      remainingChanges
    };
  }

  /**
   * Detecta apenas movimentações de parágrafos (método rápido)
   */
  public detectParagraphMovements(originalText: string, modifiedText: string): MovedBlock[] {
    return this.detectMovements(originalText, modifiedText, {
      detectParagraphMoves: true,
      detectSentenceMoves: false,
      minBlockSize: 30
    }).movedBlocks;
  }

  /**
   * Verifica se dois blocos são similares o suficiente para serem considerados o mesmo
   */
  public areBlocksSimilar(block1: string, block2: string, threshold: number = 0.8): boolean {
    const similarity = this.calculateTextSimilarity(block1, block2);
    return similarity >= threshold;
  }

  // Métodos privados

  private extractBlocks(text: string, config: BlockMovementConfig): TextBlock[] {
    const blocks: TextBlock[] = [];

    // Extrair parágrafos se habilitado
    if (config.detectParagraphMoves) {
      const paragraphBlocks = this.extractParagraphs(text, config);
      blocks.push(...paragraphBlocks);
    }

    // Extrair sentenças se habilitado
    if (config.detectSentenceMoves) {
      const sentenceBlocks = this.extractSentences(text, config);
      blocks.push(...sentenceBlocks);
    }

    // Filtrar blocos muito pequenos
    return blocks.filter(block => 
      block.text.length >= (config.minBlockSize || 50)
    );
  }

  private extractParagraphs(text: string, config: BlockMovementConfig): TextBlock[] {
    const blocks: TextBlock[] = [];
    const paragraphs = text.split(/\n\s*\n/);
    let currentPosition = 0;
    let lineNumber = 1;

    for (const paragraph of paragraphs) {
      const trimmedParagraph = paragraph.trim();
      if (trimmedParagraph) {
        const startPos = text.indexOf(paragraph, currentPosition);
        const endPos = startPos + paragraph.length;

        const normalizedText = config.ignoreWhitespace 
          ? this.normalizeWhitespace(trimmedParagraph)
          : trimmedParagraph;

        blocks.push({
          text: trimmedParagraph,
          position: {
            start: startPos,
            end: endPos,
            line: lineNumber
          },
          hash: this.createHash(trimmedParagraph),
          normalizedHash: this.createHash(normalizedText)
        });

        currentPosition = endPos;
        lineNumber += paragraph.split('\n').length;
      }
    }

    return blocks;
  }

  private extractSentences(text: string, config: BlockMovementConfig): TextBlock[] {
    const blocks: TextBlock[] = [];
    const sentenceRegex = /[.!?]+(?:\s|$)/g;
    let lastIndex = 0;
    let match;
    let lineNumber = 1;

    while ((match = sentenceRegex.exec(text)) !== null) {
      const sentenceText = text.slice(lastIndex, match.index + match[0].length).trim();
      
      if (sentenceText && sentenceText.length >= (config.minBlockSize || 50)) {
        const normalizedText = config.ignoreWhitespace 
          ? this.normalizeWhitespace(sentenceText)
          : sentenceText;

        blocks.push({
          text: sentenceText,
          position: {
            start: lastIndex,
            end: match.index + match[0].length,
            line: lineNumber
          },
          hash: this.createHash(sentenceText),
          normalizedHash: this.createHash(normalizedText)
        });

        lineNumber += sentenceText.split('\n').length - 1;
      }

      lastIndex = match.index + match[0].length;
    }

    return blocks;
  }

  private findMovedBlocks(
    originalBlocks: TextBlock[], 
    modifiedBlocks: TextBlock[], 
    config: BlockMovementConfig
  ): MovedBlock[] {
    const movedBlocks: MovedBlock[] = [];
    const usedOriginalIndices = new Set<number>();
    const usedModifiedIndices = new Set<number>();

    // Primeiro, procurar correspondências exatas por hash
    for (let i = 0; i < originalBlocks.length; i++) {
      if (usedOriginalIndices.has(i)) continue;

      for (let j = 0; j < modifiedBlocks.length; j++) {
        if (usedModifiedIndices.has(j)) continue;

        const originalBlock = originalBlocks[i];
        const modifiedBlock = modifiedBlocks[j];

        // Correspondência exata
        if (originalBlock.normalizedHash === modifiedBlock.normalizedHash) {
          // Verificar se houve mudança de posição
          if (Math.abs(originalBlock.position.start - modifiedBlock.position.start) > 10) {
            movedBlocks.push({
              originalText: originalBlock.text,
              normalizedText: this.normalizeWhitespace(originalBlock.text),
              originalPosition: originalBlock.position,
              newPosition: modifiedBlock.position,
              similarity: 1.0,
              confidence: 1.0,
              type: this.determineBlockType(originalBlock.text),
              metadata: this.createBlockMetadata(originalBlock.text)
            });

            usedOriginalIndices.add(i);
            usedModifiedIndices.add(j);
            break;
          }
        }
      }
    }

    // Segundo, procurar correspondências por similaridade
    for (let i = 0; i < originalBlocks.length; i++) {
      if (usedOriginalIndices.has(i)) continue;

      for (let j = 0; j < modifiedBlocks.length; j++) {
        if (usedModifiedIndices.has(j)) continue;

        const originalBlock = originalBlocks[i];
        const modifiedBlock = modifiedBlocks[j];

        // Verificar distância de busca
        const distance = Math.abs(originalBlock.position.start - modifiedBlock.position.start);
        if (distance > (config.maxSearchDistance || 5000)) continue;

        const similarity = this.calculateTextSimilarity(originalBlock.text, modifiedBlock.text);
        
        if (similarity >= (config.similarityThreshold || 0.8)) {
          const confidence = this.calculateMoveConfidence(similarity, distance, config);

          movedBlocks.push({
            originalText: originalBlock.text,
            normalizedText: this.normalizeWhitespace(originalBlock.text),
            originalPosition: originalBlock.position,
            newPosition: modifiedBlock.position,
            similarity,
            confidence,
            type: this.determineBlockType(originalBlock.text),
            metadata: this.createBlockMetadata(originalBlock.text)
          });

          usedOriginalIndices.add(i);
          usedModifiedIndices.add(j);
          break;
        }
      }
    }

    return movedBlocks;
  }

  private identifyRemainingChanges(
    originalBlocks: TextBlock[], 
    modifiedBlocks: TextBlock[], 
    movedBlocks: MovedBlock[]
  ): BlockMovementResult['remainingChanges'] {
    const movedOriginalHashes = new Set(movedBlocks.map(mb => this.createHash(mb.originalText)));
    const movedModifiedHashes = new Set(movedBlocks.map(mb => this.createHash(mb.originalText)));

    const deletions = originalBlocks.filter(block => 
      !movedOriginalHashes.has(block.hash)
    );

    const insertions = modifiedBlocks.filter(block => 
      !movedModifiedHashes.has(block.hash)
    );

    return { deletions, insertions };
  }

  private calculateStatistics(movedBlocks: MovedBlock[], processingTime: number): BlockMovementResult['statistics'] {
    const totalMovedCharacters = movedBlocks.reduce((sum, block) => sum + block.originalText.length, 0);
    const averageSimilarity = movedBlocks.length > 0 
      ? movedBlocks.reduce((sum, block) => sum + block.similarity, 0) / movedBlocks.length 
      : 0;

    return {
      totalMovedBlocks: movedBlocks.length,
      totalMovedCharacters,
      averageSimilarity,
      processingTime
    };
  }

  // Métodos utilitários

  private calculateTextSimilarity(text1: string, text2: string): number {
    // Similaridade baseada em palavras (Jaccard)
    const words1 = new Set(this.normalizeWhitespace(text1).toLowerCase().split(/\s+/));
    const words2 = new Set(this.normalizeWhitespace(text2).toLowerCase().split(/\s+/));
    
    const intersection = new Set([...words1].filter(word => words2.has(word)));
    const union = new Set([...words1, ...words2]);
    
    return union.size > 0 ? intersection.size / union.size : 0;
  }

  private calculateMoveConfidence(
    similarity: number, 
    distance: number, 
    config: BlockMovementConfig
  ): number {
    // Confiança baseada na similaridade e distância
    const maxDistance = config.maxSearchDistance || 5000;
    const distancePenalty = distance / maxDistance;
    
    return similarity * (1 - distancePenalty * 0.3);
  }

  private determineBlockType(text: string): MovedBlock['type'] {
    if (text.includes('\n\n') || text.length > 200) {
      return 'paragraph';
    } else if (/[.!?]\s*$/.test(text.trim())) {
      return 'sentence';
    } else {
      return 'block';
    }
  }

  private createBlockMetadata(text: string): MovedBlock['metadata'] {
    const wordCount = text.split(/\s+/).length;
    const characterCount = text.length;
    const hasStructuralElements = /[.!?:;]/.test(text) || text.includes('\n');

    return {
      wordCount,
      characterCount,
      hasStructuralElements
    };
  }

  private normalizeWhitespace(text: string): string {
    return text
      .replace(/\s+/g, ' ')
      .trim();
  }

  private createHash(text: string): string {
    // Hash simples para comparação rápida
    let hash = 0;
    for (let i = 0; i < text.length; i++) {
      const char = text.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return hash.toString();
  }
}

/**
 * Função utilitária para detecção rápida de movimentação de parágrafos
 */
export function detectParagraphMovements(originalText: string, modifiedText: string): MovedBlock[] {
  const detector = new BlockMovementDetector({
    detectParagraphMoves: true,
    detectSentenceMoves: false,
    minBlockSize: 30,
    similarityThreshold: 0.8
  });

  return detector.detectParagraphMovements(originalText, modifiedText);
}

/**
 * Função utilitária para verificar se dois textos têm blocos similares
 */
export function hasMovedBlocks(originalText: string, modifiedText: string, threshold: number = 0.8): boolean {
  const detector = new BlockMovementDetector({ similarityThreshold: threshold });
  const result = detector.detectMovements(originalText, modifiedText);
  return result.movedBlocks.length > 0;
} 