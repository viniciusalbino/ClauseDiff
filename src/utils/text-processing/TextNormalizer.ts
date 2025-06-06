export interface NormalizationConfig {
  removeAccents?: boolean; // Remove acentos (café -> cafe)
  normalizeWhitespace?: boolean; // Normalizar espaços e quebras de linha
  removeLineNumbers?: boolean; // Remove numeração de linhas
  removeTimestamps?: boolean; // Remove timestamps e datas
  removeUrls?: boolean; // Remove URLs
  removeEmails?: boolean; // Remove endereços de email
  normalizePunctuation?: boolean; // Normalizar pontuação
  convertToLowercase?: boolean; // Converter para minúsculas
  removeExtraSpaces?: boolean; // Remove espaços múltiplos
  normalizeQuotes?: boolean; // Normalizar tipos de aspas
  removeBomMarks?: boolean; // Remove BOM (Byte Order Mark)
  preserveStructure?: boolean; // Preservar estrutura de parágrafos
}

export interface NormalizationResult {
  originalText: string;
  normalizedText: string;
  appliedTransformations: string[];
  preservedElements: PreservedElement[];
  statistics: {
    originalLength: number;
    normalizedLength: number;
    reductionPercentage: number;
    transformationCount: number;
  };
}

export interface PreservedElement {
  type: 'url' | 'email' | 'timestamp' | 'line_number' | 'special_format';
  originalText: string;
  position: number;
  placeholder: string;
}

/**
 * Utilitário avançado para normalização e pré-processamento de texto
 * Otimizado para melhorar a qualidade da comparação de documentos
 */
export class TextNormalizer {
  private readonly defaultConfig: Required<NormalizationConfig> = {
    removeAccents: false,
    normalizeWhitespace: true,
    removeLineNumbers: false,
    removeTimestamps: false,
    removeUrls: false,
    removeEmails: false,
    normalizePunctuation: false,
    convertToLowercase: false,
    removeExtraSpaces: true,
    normalizeQuotes: true,
    removeBomMarks: true,
    preserveStructure: true
  };

  constructor(private config: NormalizationConfig = {}) {
    this.config = { ...this.defaultConfig, ...config };
  }

  /**
   * Normaliza um texto aplicando todas as transformações configuradas
   */
  public normalize(text: string, customConfig?: Partial<NormalizationConfig>): NormalizationResult {
    const config = { ...this.config, ...customConfig };
    const originalText = text;
    const appliedTransformations: string[] = [];
    const preservedElements: PreservedElement[] = [];
    
    let normalizedText = text;
    let transformationCount = 0;

    // 1. Remover BOM se presente
    if (config.removeBomMarks && normalizedText.charCodeAt(0) === 0xFEFF) {
      normalizedText = normalizedText.slice(1);
      appliedTransformations.push('BOM removed');
      transformationCount++;
    }

    // 2. Preservar elementos especiais se necessário
    if (config.removeUrls) {
      const urlResult = this.preserveAndRemove(normalizedText, 'url', this.getUrlRegex());
      normalizedText = urlResult.text;
      preservedElements.push(...urlResult.preserved);
      if (urlResult.preserved.length > 0) {
        appliedTransformations.push(`URLs removed (${urlResult.preserved.length})`);
        transformationCount++;
      }
    }

    if (config.removeEmails) {
      const emailResult = this.preserveAndRemove(normalizedText, 'email', this.getEmailRegex());
      normalizedText = emailResult.text;
      preservedElements.push(...emailResult.preserved);
      if (emailResult.preserved.length > 0) {
        appliedTransformations.push(`Emails removed (${emailResult.preserved.length})`);
        transformationCount++;
      }
    }

    if (config.removeTimestamps) {
      const timestampResult = this.preserveAndRemove(normalizedText, 'timestamp', this.getTimestampRegex());
      normalizedText = timestampResult.text;
      preservedElements.push(...timestampResult.preserved);
      if (timestampResult.preserved.length > 0) {
        appliedTransformations.push(`Timestamps removed (${timestampResult.preserved.length})`);
        transformationCount++;
      }
    }

    if (config.removeLineNumbers) {
      const lineNumberResult = this.removeLineNumbers(normalizedText);
      normalizedText = lineNumberResult.text;
      preservedElements.push(...lineNumberResult.preserved);
      if (lineNumberResult.preserved.length > 0) {
        appliedTransformations.push(`Line numbers removed (${lineNumberResult.preserved.length})`);
        transformationCount++;
      }
    }

    // 3. Normalizar espaços em branco
    if (config.normalizeWhitespace) {
      const beforeLength = normalizedText.length;
      normalizedText = this.normalizeWhitespace(normalizedText, config.preserveStructure || false);
      if (normalizedText.length !== beforeLength) {
        appliedTransformations.push('Whitespace normalized');
        transformationCount++;
      }
    }

    // 4. Remover espaços extras
    if (config.removeExtraSpaces) {
      const beforeLength = normalizedText.length;
      normalizedText = normalizedText.replace(/[ \t]+/g, ' ');
      if (normalizedText.length !== beforeLength) {
        appliedTransformations.push('Extra spaces removed');
        transformationCount++;
      }
    }

    // 5. Normalizar aspas
    if (config.normalizeQuotes) {
      const beforeText = normalizedText;
      normalizedText = this.normalizeQuotes(normalizedText);
      if (normalizedText !== beforeText) {
        appliedTransformations.push('Quotes normalized');
        transformationCount++;
      }
    }

    // 6. Normalizar pontuação
    if (config.normalizePunctuation) {
      const beforeText = normalizedText;
      normalizedText = this.normalizePunctuation(normalizedText);
      if (normalizedText !== beforeText) {
        appliedTransformations.push('Punctuation normalized');
        transformationCount++;
      }
    }

    // 7. Remover acentos
    if (config.removeAccents) {
      const beforeText = normalizedText;
      normalizedText = this.removeAccents(normalizedText);
      if (normalizedText !== beforeText) {
        appliedTransformations.push('Accents removed');
        transformationCount++;
      }
    }

    // 8. Converter para minúsculas (por último)
    if (config.convertToLowercase) {
      const beforeText = normalizedText;
      normalizedText = normalizedText.toLowerCase();
      if (normalizedText !== beforeText) {
        appliedTransformations.push('Converted to lowercase');
        transformationCount++;
      }
    }

    // Calcular estatísticas
    const reductionPercentage = originalText.length > 0 
      ? ((originalText.length - normalizedText.length) / originalText.length) * 100 
      : 0;

    return {
      originalText,
      normalizedText,
      appliedTransformations,
      preservedElements,
      statistics: {
        originalLength: originalText.length,
        normalizedLength: normalizedText.length,
        reductionPercentage: Math.round(reductionPercentage * 100) / 100,
        transformationCount
      }
    };
  }

  /**
   * Normaliza apenas espaços em branco
   */
  public normalizeWhitespaceOnly(text: string, preserveStructure: boolean = true): string {
    return this.normalizeWhitespace(text, preserveStructure);
  }

  /**
   * Remove apenas acentos do texto
   */
  public removeAccentsOnly(text: string): string {
    return this.removeAccents(text);
  }

  /**
   * Normaliza apenas pontuação
   */
  public normalizePunctuationOnly(text: string): string {
    return this.normalizePunctuation(text);
  }

  /**
   * Restaura elementos preservados no texto
   */
  public restorePreservedElements(text: string, preservedElements: PreservedElement[]): string {
    let restoredText = text;
    
    // Restaurar em ordem reversa para manter posições corretas
    const sortedElements = [...preservedElements].sort((a, b) => b.position - a.position);
    
    for (const element of sortedElements) {
      restoredText = restoredText.replace(element.placeholder, element.originalText);
    }
    
    return restoredText;
  }

  // Métodos privados de normalização

  private normalizeWhitespace(text: string, preserveStructure: boolean): string {
    if (preserveStructure) {
      // Preservar estrutura de parágrafos, normalizar apenas dentro das linhas
      return text
        .split('\n')
        .map(line => line.replace(/\s+/g, ' ').trim())
        .join('\n')
        .replace(/\n{3,}/g, '\n\n'); // Máximo 2 quebras consecutivas
    } else {
      // Normalizar todo o whitespace
      return text
        .replace(/\r\n/g, '\n')      // Windows -> Unix
        .replace(/\r/g, '\n')        // Mac -> Unix
        .replace(/\t/g, ' ')         // Tabs -> Espaços
        .replace(/\s+/g, ' ')        // Múltiplos espaços -> Um espaço
        .trim();
    }
  }

  private removeAccents(text: string): string {
    const accentMap: { [key: string]: string } = {
      'áàâãäå': 'a', 'ÁÀÂÃÄÅ': 'A',
      'éèêë': 'e', 'ÉÈÊË': 'E',
      'íìîï': 'i', 'ÍÌÎÏ': 'I',
      'óòôõöø': 'o', 'ÓÒÔÕÖØ': 'O',
      'úùûü': 'u', 'ÚÙÛÜ': 'U',
      'ç': 'c', 'Ç': 'C',
      'ñ': 'n', 'Ñ': 'N',
      'ý': 'y', 'Ý': 'Y'
    };

    let result = text;
    for (const [accented, plain] of Object.entries(accentMap)) {
      const regex = new RegExp(`[${accented}]`, 'g');
      result = result.replace(regex, plain);
    }

    return result;
  }

  private normalizeQuotes(text: string): string {
    return text
      .replace(/[""]/g, '"')        // Smart quotes -> Straight quotes
      .replace(/['']/g, "'")        // Smart apostrophes -> Straight apostrophes
      .replace(/[«»]/g, '"')        // Guillemets -> Straight quotes
      .replace(/[‹›]/g, "'");       // Single guillemets -> Straight apostrophes
  }

  private normalizePunctuation(text: string): string {
    return text
      .replace(/…/g, '...')         // Ellipsis -> Three dots
      .replace(/–/g, '-')           // En dash -> Hyphen
      .replace(/—/g, '-')           // Em dash -> Hyphen
      .replace(/[¡¿]/g, '')         // Remove inverted punctuation
      .replace(/\s*([,.;:!?])\s*/g, '$1 ') // Normalize spacing around punctuation
      .replace(/\s+([,.;:!?])/g, '$1'); // Remove space before punctuation
  }

  private removeLineNumbers(text: string): { text: string; preserved: PreservedElement[] } {
    const preserved: PreservedElement[] = [];
    let position = 0;
    
    // Regex para detectar numeração de linhas no início das linhas
    const lineNumberRegex = /^(\s*\d+[\.\)\]\|:\s]+)/gm;
    
    const processedText = text.replace(lineNumberRegex, (match, group, offset) => {
      const placeholder = `__LINENUM_${preserved.length}__`;
      preserved.push({
        type: 'line_number',
        originalText: group,
        position: offset,
        placeholder
      });
      return '';
    });

    return { text: processedText, preserved };
  }

  private preserveAndRemove(
    text: string, 
    type: PreservedElement['type'], 
    regex: RegExp
  ): { text: string; preserved: PreservedElement[] } {
    const preserved: PreservedElement[] = [];
    
    const processedText = text.replace(regex, (match, offset) => {
      const placeholder = `__${type.toUpperCase()}_${preserved.length}__`;
      preserved.push({
        type,
        originalText: match,
        position: offset,
        placeholder
      });
      return placeholder;
    });

    return { text: processedText, preserved };
  }

  // Regex patterns
  private getUrlRegex(): RegExp {
    return /https?:\/\/[^\s<>"{}|\\^`[\]]+/gi;
  }

  private getEmailRegex(): RegExp {
    return /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi;
  }

  private getTimestampRegex(): RegExp {
    // Detecta vários formatos de data/hora
    return /\b(?:\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}|\d{2,4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2})\b|\b\d{1,2}:\d{2}(?::\d{2})?\s*(?:AM|PM)?\b/gi;
  }
}

/**
 * Função utilitária para normalização rápida com configuração padrão
 */
export function quickNormalize(text: string): string {
  const normalizer = new TextNormalizer({
    normalizeWhitespace: true,
    removeExtraSpaces: true,
    normalizeQuotes: true,
    removeBomMarks: true
  });
  
  return normalizer.normalize(text).normalizedText;
}

/**
 * Função utilitária para normalização agressiva (remove tudo)
 */
export function aggressiveNormalize(text: string): string {
  const normalizer = new TextNormalizer({
    removeAccents: true,
    normalizeWhitespace: true,
    removeLineNumbers: true,
    removeTimestamps: true,
    removeUrls: true,
    removeEmails: true,
    normalizePunctuation: true,
    convertToLowercase: true,
    removeExtraSpaces: true,
    normalizeQuotes: true,
    removeBomMarks: true,
    preserveStructure: false
  });
  
  return normalizer.normalize(text).normalizedText;
} 