export interface TokenizationConfig {
  tokenizeByWords?: boolean; // Tokenizar por palavras
  tokenizeBySentences?: boolean; // Tokenizar por sentenças
  tokenizeByParagraphs?: boolean; // Tokenizar por parágrafos
  preserveWhitespace?: boolean; // Preservar whitespace como tokens
  identifyEntities?: boolean; // Identificar entidades (nomes, datas, números)
  classifyTokens?: boolean; // Classificar tipos de tokens
  minTokenLength?: number; // Tamanho mínimo do token (padrão: 1)
  maxTokenLength?: number; // Tamanho máximo do token (padrão: 1000)
  language?: 'pt' | 'en' | 'auto'; // Idioma para processamento (padrão: 'auto')
}

export interface SemanticToken {
  text: string;
  type: TokenType;
  position: {
    start: number;
    end: number;
    line: number;
    column: number;
  };
  metadata: {
    confidence: number;
    language?: string;
    category?: string;
    semanticWeight: number; // Peso semântico (0.0 - 1.0)
    isStructural?: boolean;
    isPunctuation?: boolean;
    isStopWord?: boolean;
  };
  relations?: TokenRelation[];
}

export type TokenType = 
  | 'word' 
  | 'sentence' 
  | 'paragraph' 
  | 'punctuation' 
  | 'whitespace'
  | 'number'
  | 'date'
  | 'email'
  | 'url'
  | 'proper_noun'
  | 'common_noun'
  | 'verb'
  | 'adjective'
  | 'connector'
  | 'structural'
  | 'legal_term'
  | 'technical_term'
  | 'unknown';

export interface TokenRelation {
  type: 'dependency' | 'semantic_similarity' | 'structural_parent' | 'sequence';
  targetToken: number; // Index do token relacionado
  strength: number; // Força da relação (0.0 - 1.0)
}

export interface TokenizationResult {
  tokens: SemanticToken[];
  statistics: {
    totalTokens: number;
    tokensByType: Record<TokenType, number>;
    averageSemanticWeight: number;
    structuralTokensRatio: number;
    processingTime: number;
  };
  metadata: {
    language: string;
    confidence: number;
    method: string;
  };
}

/**
 * Tokenizador semântico inteligente para análise avançada de texto
 * Identifica unidades semânticas e suas relações para melhor comparação
 */
export class SemanticTokenizer {
  private readonly defaultConfig: Required<TokenizationConfig> = {
    tokenizeByWords: true,
    tokenizeBySentences: true,
    tokenizeByParagraphs: true,
    preserveWhitespace: false,
    identifyEntities: true,
    classifyTokens: true,
    minTokenLength: 1,
    maxTokenLength: 1000,
    language: 'auto'
  };

  // Stop words em português
  private readonly stopWordsPortuguese = new Set([
    'o', 'a', 'os', 'as', 'um', 'uma', 'uns', 'umas',
    'de', 'do', 'da', 'dos', 'das', 'em', 'no', 'na', 'nos', 'nas',
    'para', 'por', 'com', 'sem', 'sob', 'sobre', 'entre', 'até',
    'e', 'ou', 'mas', 'que', 'se', 'quando', 'onde', 'como', 'porque',
    'é', 'são', 'foi', 'foram', 'ser', 'estar', 'ter', 'haver',
    'este', 'esta', 'isto', 'esse', 'essa', 'isso', 'aquele', 'aquela', 'aquilo',
    'meu', 'minha', 'meus', 'minhas', 'seu', 'sua', 'seus', 'suas',
    'nosso', 'nossa', 'nossos', 'nossas'
  ]);

  // Stop words em inglês
  private readonly stopWordsEnglish = new Set([
    'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
    'of', 'with', 'by', 'from', 'up', 'about', 'into', 'through', 'during',
    'before', 'after', 'above', 'below', 'between', 'among', 'under', 'over',
    'is', 'am', 'are', 'was', 'were', 'be', 'been', 'being', 'have', 'has', 'had',
    'this', 'that', 'these', 'those', 'my', 'your', 'his', 'her', 'its', 'our', 'their'
  ]);

  // Termos legais comuns
  private readonly legalTerms = new Set([
    'contrato', 'cláusula', 'artigo', 'parágrafo', 'inciso', 'alínea',
    'réu', 'autor', 'testemunha', 'advogado', 'juiz', 'tribunal',
    'processo', 'ação', 'recurso', 'sentença', 'decisão', 'acórdão',
    'constitucional', 'legal', 'jurídico', 'jurisprudência', 'doutrina',
    'contract', 'clause', 'article', 'paragraph', 'section', 'subsection',
    'plaintiff', 'defendant', 'witness', 'attorney', 'judge', 'court',
    'lawsuit', 'action', 'appeal', 'judgment', 'decision', 'ruling'
  ]);

  constructor(private config: TokenizationConfig = {}) {
    this.config = { ...this.defaultConfig, ...config };
  }

  /**
   * Tokeniza um texto em unidades semânticas
   */
  public tokenize(text: string, customConfig?: Partial<TokenizationConfig>): TokenizationResult {
    const startTime = performance.now();
    const config = { ...this.config, ...customConfig };
    
    const language = this.detectLanguage(text, config.language || 'auto');
    const tokens: SemanticToken[] = [];
    
    // 1. Tokenização por parágrafos (se habilitada)
    if (config.tokenizeByParagraphs) {
      const paragraphTokens = this.tokenizeByParagraphs(text);
      tokens.push(...paragraphTokens);
    }

    // 2. Tokenização por sentenças (se habilitada)
    if (config.tokenizeBySentences) {
      const sentenceTokens = this.tokenizeBySentences(text);
      tokens.push(...sentenceTokens);
    }

    // 3. Tokenização por palavras (se habilitada)
    if (config.tokenizeByWords) {
      const wordTokens = this.tokenizeByWords(text, language, config);
      tokens.push(...wordTokens);
    }

    // 4. Classificar tokens se habilitado
    if (config.classifyTokens) {
      this.classifyTokens(tokens, language);
    }

    // 5. Identificar entidades se habilitado
    if (config.identifyEntities) {
      this.identifyEntities(tokens);
    }

    // 6. Filtrar por tamanho
    const filteredTokens = tokens.filter(token => 
      token.text.length >= (config.minTokenLength || 1) &&
      token.text.length <= (config.maxTokenLength || 1000)
    );

    // 7. Calcular estatísticas
    const statistics = this.calculateStatistics(filteredTokens, performance.now() - startTime);

    return {
      tokens: filteredTokens,
      statistics,
      metadata: {
        language,
        confidence: this.calculateLanguageConfidence(text, language),
        method: 'semantic-tokenization'
      }
    };
  }

  /**
   * Tokeniza apenas por palavras (método rápido)
   */
  public tokenizeWords(text: string): SemanticToken[] {
    return this.tokenizeByWords(text, 'auto', this.config);
  }

  /**
   * Identifica tokens mais importantes semanticamente
   */
  public getSemanticKeyTokens(tokens: SemanticToken[], limit: number = 10): SemanticToken[] {
    return tokens
      .filter(token => !token.metadata.isStopWord && !token.metadata.isPunctuation)
      .sort((a, b) => b.metadata.semanticWeight - a.metadata.semanticWeight)
      .slice(0, limit);
  }

  /**
   * Agrupa tokens por tipo semântico
   */
  public groupTokensByType(tokens: SemanticToken[]): Record<TokenType, SemanticToken[]> {
    const groups: Record<TokenType, SemanticToken[]> = {} as any;
    
    for (const token of tokens) {
      if (!groups[token.type]) {
        groups[token.type] = [];
      }
      groups[token.type].push(token);
    }
    
    return groups;
  }

  // Métodos privados de tokenização

  private tokenizeByParagraphs(text: string): SemanticToken[] {
    const paragraphs = text.split(/\n\s*\n/);
    const tokens: SemanticToken[] = [];
    let currentPosition = 0;
    let lineNumber = 1;

    for (const paragraph of paragraphs) {
      if (paragraph.trim()) {
        const startPos = text.indexOf(paragraph, currentPosition);
        const endPos = startPos + paragraph.length;

        tokens.push({
          text: paragraph.trim(),
          type: 'paragraph',
          position: {
            start: startPos,
            end: endPos,
            line: lineNumber,
            column: 0
          },
          metadata: {
            confidence: 1.0,
            semanticWeight: 0.8,
            isStructural: true,
            isPunctuation: false,
            isStopWord: false
          }
        });

        currentPosition = endPos;
        lineNumber += paragraph.split('\n').length;
      }
    }

    return tokens;
  }

  private tokenizeBySentences(text: string): SemanticToken[] {
    // Regex para detectar final de sentenças (simplificado)
    const sentenceRegex = /[.!?]+(?:\s|$)/g;
    const tokens: SemanticToken[] = [];
    let lastIndex = 0;
    let match;
    let lineNumber = 1;

    while ((match = sentenceRegex.exec(text)) !== null) {
      const sentenceText = text.slice(lastIndex, match.index + match[0].length).trim();
      
      if (sentenceText) {
        tokens.push({
          text: sentenceText,
          type: 'sentence',
          position: {
            start: lastIndex,
            end: match.index + match[0].length,
            line: lineNumber,
            column: 0
          },
          metadata: {
            confidence: 0.9,
            semanticWeight: 0.7,
            isStructural: true,
            isPunctuation: false,
            isStopWord: false
          }
        });

        lineNumber += sentenceText.split('\n').length - 1;
      }

      lastIndex = match.index + match[0].length;
    }

    // Adicionar último fragmento se existir
    if (lastIndex < text.length) {
      const remainingText = text.slice(lastIndex).trim();
      if (remainingText) {
        tokens.push({
          text: remainingText,
          type: 'sentence',
          position: {
            start: lastIndex,
            end: text.length,
            line: lineNumber,
            column: 0
          },
          metadata: {
            confidence: 0.8,
            semanticWeight: 0.7,
            isStructural: true,
            isPunctuation: false,
            isStopWord: false
          }
        });
      }
    }

    return tokens;
  }

  private tokenizeByWords(text: string, language: string, config: TokenizationConfig): SemanticToken[] {
    const tokens: SemanticToken[] = [];
    const wordRegex = /\b[\w\u00C0-\u024F\u1E00-\u1EFF]+\b/g;
    let match;
    let lineNumber = 1;
    let lineStart = 0;

    while ((match = wordRegex.exec(text)) !== null) {
      const word = match[0];
      const start = match.index;
      const end = start + word.length;

      // Calcular linha e coluna
      const textUpToMatch = text.slice(0, start);
      const newLineCount = (textUpToMatch.match(/\n/g) || []).length;
      if (newLineCount > lineNumber - 1) {
        lineNumber = newLineCount + 1;
        lineStart = textUpToMatch.lastIndexOf('\n') + 1;
      }
      const column = start - lineStart;

      const isStopWord = this.isStopWord(word.toLowerCase(), language);
      const semanticWeight = this.calculateSemanticWeight(word, language);

      tokens.push({
        text: word,
        type: 'word',
        position: {
          start,
          end,
          line: lineNumber,
          column
        },
        metadata: {
          confidence: 0.95,
          language,
          semanticWeight,
          isStructural: false,
          isPunctuation: false,
          isStopWord
        }
      });
    }

    return tokens;
  }

  private classifyTokens(tokens: SemanticToken[], language: string): void {
    for (const token of tokens) {
      if (token.type === 'word') {
        token.type = this.classifyWord(token.text, language);
        token.metadata.category = this.getCategoryForType(token.type);
      }
    }
  }

  private classifyWord(word: string, language: string): TokenType {
    const lowerWord = word.toLowerCase();

    // Verificar termos legais
    if (this.legalTerms.has(lowerWord)) {
      return 'legal_term';
    }

    // Verificar números
    if (/^\d+$/.test(word)) {
      return 'number';
    }

    // Verificar datas
    if (this.isDate(word)) {
      return 'date';
    }

    // Verificar emails
    if (this.isEmail(word)) {
      return 'email';
    }

    // Verificar URLs
    if (this.isUrl(word)) {
      return 'url';
    }

    // Verificar nomes próprios (heurística simples)
    if (/^[A-ZÀ-Ü][a-zà-ü]+$/.test(word)) {
      return 'proper_noun';
    }

    // Verificar conectores
    if (this.isConnector(lowerWord, language)) {
      return 'connector';
    }

    // Verificar termos técnicos (heurística simples)
    if (word.length > 8 && /[A-Z]/.test(word)) {
      return 'technical_term';
    }

    return 'common_noun';
  }

  private identifyEntities(tokens: SemanticToken[]): void {
    // Identificação simples de entidades
    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i];
      
      if (token.type === 'proper_noun') {
        // Verificar se é parte de nome composto
        if (i + 1 < tokens.length && tokens[i + 1].type === 'proper_noun') {
          token.metadata.category = 'compound_name';
          token.metadata.semanticWeight += 0.2;
        }
      }
    }
  }

  private calculateStatistics(tokens: SemanticToken[], processingTime: number): TokenizationResult['statistics'] {
    const tokensByType: Record<TokenType, number> = {} as any;
    let totalSemanticWeight = 0;
    let structuralTokens = 0;

    for (const token of tokens) {
      if (!tokensByType[token.type]) {
        tokensByType[token.type] = 0;
      }
      tokensByType[token.type]++;
      totalSemanticWeight += token.metadata.semanticWeight;
      
      if (token.metadata.isStructural) {
        structuralTokens++;
      }
    }

    return {
      totalTokens: tokens.length,
      tokensByType,
      averageSemanticWeight: tokens.length > 0 ? totalSemanticWeight / tokens.length : 0,
      structuralTokensRatio: tokens.length > 0 ? structuralTokens / tokens.length : 0,
      processingTime
    };
  }

  // Métodos utilitários
  private detectLanguage(text: string, configLanguage: string): string {
    if (configLanguage !== 'auto') {
      return configLanguage;
    }

    // Detecção simples baseada em caracteres comuns
    const portugueseIndicators = /[áàâãäéèêëíìîïóòôõöúùûüç]/gi;
    const portugueseMatches = (text.match(portugueseIndicators) || []).length;
    
    const commonPortugueseWords = ['que', 'de', 'para', 'com', 'em', 'por'];
    const portugueseWordMatches = commonPortugueseWords.filter(word => 
      text.toLowerCase().includes(word)
    ).length;

    // Se tem acentos ou palavras comuns em português, provavelmente é português
    if (portugueseMatches > 0 || portugueseWordMatches >= 2) {
      return 'pt';
    }

    return 'en';
  }

  private calculateLanguageConfidence(text: string, detectedLanguage: string): number {
    // Cálculo simples de confiança baseado em indicadores do idioma
    if (detectedLanguage === 'pt') {
      const indicators = /[áàâãäéèêëíìîïóòôõöúùûüç]/gi;
      const matches = (text.match(indicators) || []).length;
      return Math.min(matches / (text.length * 0.05), 1.0);
    }
    
    return 0.8; // Confiança padrão para inglês
  }

  private isStopWord(word: string, language: string): boolean {
    const stopWords = language === 'pt' ? this.stopWordsPortuguese : this.stopWordsEnglish;
    return stopWords.has(word);
  }

  private calculateSemanticWeight(word: string, language: string): number {
    const lowerWord = word.toLowerCase();
    
    // Stop words têm peso baixo
    if (this.isStopWord(lowerWord, language)) {
      return 0.1;
    }
    
    // Termos legais têm peso alto
    if (this.legalTerms.has(lowerWord)) {
      return 0.9;
    }
    
    // Palavras longas tendem a ser mais específicas
    if (word.length > 10) {
      return 0.8;
    }
    
    if (word.length > 6) {
      return 0.6;
    }
    
    return 0.4;
  }

  private isConnector(word: string, language: string): boolean {
    const connectors = language === 'pt' 
      ? ['e', 'ou', 'mas', 'porém', 'contudo', 'entretanto', 'todavia']
      : ['and', 'or', 'but', 'however', 'nevertheless', 'therefore', 'moreover'];
    
    return connectors.includes(word);
  }

  private isDate(word: string): boolean {
    return /^\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}$/.test(word);
  }

  private isEmail(word: string): boolean {
    return /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(word);
  }

  private isUrl(word: string): boolean {
    return /^https?:\/\//.test(word);
  }

  private getCategoryForType(type: TokenType): string {
    const categoryMap: Record<TokenType, string> = {
      'word': 'lexical',
      'sentence': 'structural',
      'paragraph': 'structural',
      'punctuation': 'syntactic',
      'whitespace': 'formatting',
      'number': 'numeric',
      'date': 'temporal',
      'email': 'contact',
      'url': 'reference',
      'proper_noun': 'entity',
      'common_noun': 'lexical',
      'verb': 'lexical',
      'adjective': 'lexical',
      'connector': 'syntactic',
      'structural': 'structural',
      'legal_term': 'domain',
      'technical_term': 'domain',
      'unknown': 'unknown'
    };
    
    return categoryMap[type] || 'unknown';
  }
} 