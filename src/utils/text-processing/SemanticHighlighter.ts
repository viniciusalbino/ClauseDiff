import { DiffChunk, DiffOperation } from '../../domain/entities/DiffResult';

export type HighlightType = 
  | 'code-syntax'          // Programming language syntax
  | 'legal-term'           // Legal terminology
  | 'technical-term'       // Technical jargon
  | 'number-change'        // Numeric values
  | 'date-change'          // Date modifications
  | 'url-change'           // URL modifications
  | 'email-change'         // Email modifications
  | 'structural-change'    // Document structure
  | 'content-change'       // Regular content
  | 'whitespace-change'    // Whitespace modifications
  | 'case-change'          // Case modifications only
  | 'punctuation-change'   // Punctuation changes
  | 'semantic-move'        // Text that was moved
  | 'semantic-replace';    // Semantic replacement

export interface HighlightSegment {
  start: number;
  end: number;
  type: HighlightType;
  intensity: 'low' | 'medium' | 'high';
  confidence: number; // 0-1 confidence in the classification
  metadata?: {
    originalValue?: string;
    newValue?: string;
    language?: string;
    category?: string;
    description?: string;
  };
}

export interface SemanticHighlightConfig {
  enableCodeDetection?: boolean;
  enableLegalTerms?: boolean;
  enableTechnicalTerms?: boolean;
  enableNumberHighlight?: boolean;
  enableDateHighlight?: boolean;
  enableUrlHighlight?: boolean;
  enableEmailHighlight?: boolean;
  enableMoveDetection?: boolean;
  enableCaseChangeDetection?: boolean;
  language?: 'pt' | 'en' | 'auto';
  codeLanguage?: string;
  confidenceThreshold?: number;
}

/**
 * Sistema de destaque semântico para diferenças de texto
 * Identifica e classifica diferentes tipos de alterações
 */
export class SemanticHighlighter {
  private config: Required<SemanticHighlightConfig>;

  // Padrões regex para diferentes tipos de conteúdo
  private static readonly PATTERNS = {
    // Números
    NUMBER: /\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b/g,
    CURRENCY: /\$\d+(?:\.\d{2})?|\d+(?:\.\d{2})?\s*(?:USD|EUR|BRL|R\$)/gi,
    PERCENTAGE: /\d+(?:\.\d+)?%/g,
    
    // Datas
    DATE_ISO: /\d{4}-\d{2}-\d{2}/g,
    DATE_BR: /\d{1,2}\/\d{1,2}\/\d{4}/g,
    DATE_US: /\d{1,2}\/\d{1,2}\/\d{4}|\d{1,2}-\d{1,2}-\d{4}/g,
    
    // URLs e Emails
    URL: /https?:\/\/[^\s<>"{}|\\^`[\]]+/gi,
    EMAIL: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    
    // Código
    CODE_VARIABLE: /\b[a-zA-Z_$][a-zA-Z0-9_$]*\s*[=:]/g,
    CODE_FUNCTION: /\b[a-zA-Z_$][a-zA-Z0-9_$]*\s*\(/g,
    CODE_COMMENT: /\/\/.*$|\/\*[\s\S]*?\*\/|#.*$/gm,
    HTML_TAG: /<\/?[a-zA-Z][a-zA-Z0-9]*[^<>]*>/g,
    
    // Estrutura de documento
    HEADING: /^#{1,6}\s+.+$|^.+\n[=-]+$/gm,
    LIST_ITEM: /^\s*[-*+]\s+|^\s*\d+\.\s+/gm,
    
    // Termos legais (português e inglês)
    LEGAL_TERMS: /\b(?:contrato|cláusula|artigo|parágrafo|inciso|lei|decreto|portaria|resolução|acordo|termo|condição|obrigação|direito|dever|responsabilidade|liability|contract|clause|article|section|law|agreement|obligation|right|duty)\b/gi,
    
    // Termos técnicos
    TECH_TERMS: /\b(?:API|SDK|URL|HTTP|HTTPS|JSON|XML|CSS|HTML|JavaScript|TypeScript|React|Vue|Angular|Node\.js|Docker|Kubernetes|microservice|database|server|client|frontend|backend|algorithm|function|method|class|interface|component)\b/gi,
    
    // Mudanças de caso
    CASE_CHANGE: /\b[a-z]+\b|\b[A-Z]+\b|\b[A-Z][a-z]+\b/g,
    
    // Pontuação
    PUNCTUATION: /[.,;:!?()[\]{}"'`~@#$%^&*+=|\\<>/-]/g
  };

  // Palavras-chave por linguagem de programação
  private static readonly CODE_KEYWORDS = {
    javascript: ['function', 'const', 'let', 'var', 'class', 'if', 'else', 'for', 'while', 'return', 'import', 'export'],
    typescript: ['interface', 'type', 'enum', 'public', 'private', 'protected', 'readonly'],
    python: ['def', 'class', 'if', 'elif', 'else', 'for', 'while', 'import', 'from', 'return', 'lambda'],
    java: ['public', 'private', 'protected', 'class', 'interface', 'extends', 'implements', 'void', 'int', 'String'],
    css: ['color', 'background', 'margin', 'padding', 'border', 'width', 'height', 'display', 'position'],
    html: ['div', 'span', 'p', 'h1', 'h2', 'h3', 'img', 'a', 'ul', 'li', 'table']
  };

  constructor(config: SemanticHighlightConfig = {}) {
    this.config = {
      enableCodeDetection: true,
      enableLegalTerms: true,
      enableTechnicalTerms: true,
      enableNumberHighlight: true,
      enableDateHighlight: true,
      enableUrlHighlight: true,
      enableEmailHighlight: true,
      enableMoveDetection: true,
      enableCaseChangeDetection: true,
      language: 'auto',
      codeLanguage: 'auto',
      confidenceThreshold: 0.6,
      ...config
    };
  }

  /**
   * Analisa um chunk e retorna segmentos com destacamento semântico
   */
  public highlightChunk(chunk: DiffChunk): HighlightSegment[] {
    const segments: HighlightSegment[] = [];
    const text = chunk.text;

    if (!text || text.length === 0) return segments;

    // Aplicar diferentes tipos de análise baseado na configuração
    if (this.config.enableNumberHighlight) {
      segments.push(...this.detectNumbers(text));
    }

    if (this.config.enableDateHighlight) {
      segments.push(...this.detectDates(text));
    }

    if (this.config.enableUrlHighlight) {
      segments.push(...this.detectUrls(text));
    }

    if (this.config.enableEmailHighlight) {
      segments.push(...this.detectEmails(text));
    }

    if (this.config.enableCodeDetection) {
      segments.push(...this.detectCode(text));
    }

    if (this.config.enableLegalTerms) {
      segments.push(...this.detectLegalTerms(text));
    }

    if (this.config.enableTechnicalTerms) {
      segments.push(...this.detectTechnicalTerms(text));
    }

    if (this.config.enableCaseChangeDetection && chunk.operation === 'modify') {
      segments.push(...this.detectCaseChanges(text));
    }

    segments.push(...this.detectStructuralChanges(text));
    segments.push(...this.detectPunctuationChanges(text));

    // Remover sobreposições e filtrar por confiança
    return this.consolidateSegments(segments);
  }

  /**
   * Detecta mudanças em números
   */
  private detectNumbers(text: string): HighlightSegment[] {
    const segments: HighlightSegment[] = [];

    // Números simples
    this.matchPattern(text, SemanticHighlighter.PATTERNS.NUMBER, (match, start, end) => {
      segments.push({
        start,
        end,
        type: 'number-change',
        intensity: 'medium',
        confidence: 0.9,
        metadata: { originalValue: match }
      });
    });

    // Moeda
    this.matchPattern(text, SemanticHighlighter.PATTERNS.CURRENCY, (match, start, end) => {
      segments.push({
        start,
        end,
        type: 'number-change',
        intensity: 'high',
        confidence: 0.95,
        metadata: { originalValue: match, category: 'currency' }
      });
    });

    // Porcentagens
    this.matchPattern(text, SemanticHighlighter.PATTERNS.PERCENTAGE, (match, start, end) => {
      segments.push({
        start,
        end,
        type: 'number-change',
        intensity: 'high',
        confidence: 0.9,
        metadata: { originalValue: match, category: 'percentage' }
      });
    });

    return segments;
  }

  /**
   * Detecta mudanças em datas
   */
  private detectDates(text: string): HighlightSegment[] {
    const segments: HighlightSegment[] = [];

    // Data ISO
    this.matchPattern(text, SemanticHighlighter.PATTERNS.DATE_ISO, (match, start, end) => {
      segments.push({
        start,
        end,
        type: 'date-change',
        intensity: 'high',
        confidence: 0.95,
        metadata: { originalValue: match, category: 'iso-date' }
      });
    });

    // Data brasileira
    this.matchPattern(text, SemanticHighlighter.PATTERNS.DATE_BR, (match, start, end) => {
      segments.push({
        start,
        end,
        type: 'date-change',
        intensity: 'high',
        confidence: 0.85,
        metadata: { originalValue: match, category: 'br-date' }
      });
    });

    return segments;
  }

  /**
   * Detecta mudanças em URLs
   */
  private detectUrls(text: string): HighlightSegment[] {
    const segments: HighlightSegment[] = [];

    this.matchPattern(text, SemanticHighlighter.PATTERNS.URL, (match, start, end) => {
      segments.push({
        start,
        end,
        type: 'url-change',
        intensity: 'high',
        confidence: 0.95,
        metadata: { originalValue: match }
      });
    });

    return segments;
  }

  /**
   * Detecta mudanças em emails
   */
  private detectEmails(text: string): HighlightSegment[] {
    const segments: HighlightSegment[] = [];

    this.matchPattern(text, SemanticHighlighter.PATTERNS.EMAIL, (match, start, end) => {
      segments.push({
        start,
        end,
        type: 'email-change',
        intensity: 'high',
        confidence: 0.9,
        metadata: { originalValue: match }
      });
    });

    return segments;
  }

  /**
   * Detecta código
   */
  private detectCode(text: string): HighlightSegment[] {
    const segments: HighlightSegment[] = [];

    // Detectar linguagem automaticamente se configurado
    const language = this.config.codeLanguage === 'auto' 
      ? this.detectCodeLanguage(text) 
      : this.config.codeLanguage;

    // Variáveis
    this.matchPattern(text, SemanticHighlighter.PATTERNS.CODE_VARIABLE, (match, start, end) => {
      segments.push({
        start,
        end,
        type: 'code-syntax',
        intensity: 'medium',
        confidence: 0.8,
        metadata: { category: 'variable', language }
      });
    });

    // Funções
    this.matchPattern(text, SemanticHighlighter.PATTERNS.CODE_FUNCTION, (match, start, end) => {
      segments.push({
        start,
        end,
        type: 'code-syntax',
        intensity: 'medium',
        confidence: 0.8,
        metadata: { category: 'function', language }
      });
    });

    // Comentários
    this.matchPattern(text, SemanticHighlighter.PATTERNS.CODE_COMMENT, (match, start, end) => {
      segments.push({
        start,
        end,
        type: 'code-syntax',
        intensity: 'low',
        confidence: 0.9,
        metadata: { category: 'comment', language }
      });
    });

    // Tags HTML
    this.matchPattern(text, SemanticHighlighter.PATTERNS.HTML_TAG, (match, start, end) => {
      segments.push({
        start,
        end,
        type: 'code-syntax',
        intensity: 'medium',
        confidence: 0.9,
        metadata: { category: 'html-tag', language: 'html' }
      });
    });

    return segments;
  }

  /**
   * Detecta termos legais
   */
  private detectLegalTerms(text: string): HighlightSegment[] {
    const segments: HighlightSegment[] = [];

    this.matchPattern(text, SemanticHighlighter.PATTERNS.LEGAL_TERMS, (match, start, end) => {
      segments.push({
        start,
        end,
        type: 'legal-term',
        intensity: 'high',
        confidence: 0.85,
        metadata: { originalValue: match }
      });
    });

    return segments;
  }

  /**
   * Detecta termos técnicos
   */
  private detectTechnicalTerms(text: string): HighlightSegment[] {
    const segments: HighlightSegment[] = [];

    this.matchPattern(text, SemanticHighlighter.PATTERNS.TECH_TERMS, (match, start, end) => {
      segments.push({
        start,
        end,
        type: 'technical-term',
        intensity: 'medium',
        confidence: 0.8,
        metadata: { originalValue: match }
      });
    });

    return segments;
  }

  /**
   * Detecta mudanças estruturais
   */
  private detectStructuralChanges(text: string): HighlightSegment[] {
    const segments: HighlightSegment[] = [];

    // Cabeçalhos
    this.matchPattern(text, SemanticHighlighter.PATTERNS.HEADING, (match, start, end) => {
      segments.push({
        start,
        end,
        type: 'structural-change',
        intensity: 'high',
        confidence: 0.9,
        metadata: { category: 'heading' }
      });
    });

    // Itens de lista
    this.matchPattern(text, SemanticHighlighter.PATTERNS.LIST_ITEM, (match, start, end) => {
      segments.push({
        start,
        end,
        type: 'structural-change',
        intensity: 'medium',
        confidence: 0.8,
        metadata: { category: 'list-item' }
      });
    });

    return segments;
  }

  /**
   * Detecta mudanças de caso
   */
  private detectCaseChanges(text: string): HighlightSegment[] {
    const segments: HighlightSegment[] = [];

    this.matchPattern(text, SemanticHighlighter.PATTERNS.CASE_CHANGE, (match, start, end) => {
      const caseType = this.determineCaseType(match);
      segments.push({
        start,
        end,
        type: 'case-change',
        intensity: 'low',
        confidence: 0.7,
        metadata: { originalValue: match, category: caseType }
      });
    });

    return segments;
  }

  /**
   * Detecta mudanças de pontuação
   */
  private detectPunctuationChanges(text: string): HighlightSegment[] {
    const segments: HighlightSegment[] = [];

    this.matchPattern(text, SemanticHighlighter.PATTERNS.PUNCTUATION, (match, start, end) => {
      segments.push({
        start,
        end,
        type: 'punctuation-change',
        intensity: 'low',
        confidence: 0.6,
        metadata: { originalValue: match }
      });
    });

    return segments;
  }

  /**
   * Detecta a linguagem de programação automaticamente
   */
  private detectCodeLanguage(text: string): string {
    const languages = Object.keys(SemanticHighlighter.CODE_KEYWORDS);
    const scores: Record<string, number> = {};

    languages.forEach(lang => {
      scores[lang] = 0;
      const keywords = SemanticHighlighter.CODE_KEYWORDS[lang as keyof typeof SemanticHighlighter.CODE_KEYWORDS];
      keywords.forEach(keyword => {
        const regex = new RegExp(`\\b${keyword}\\b`, 'gi');
        const matches = text.match(regex);
        if (matches) {
          scores[lang] += matches.length;
        }
      });
    });

    const detectedLang = Object.keys(scores).reduce((a, b) => scores[a] > scores[b] ? a : b);
    return scores[detectedLang] > 0 ? detectedLang : 'text';
  }

  /**
   * Determina o tipo de caso de uma string
   */
  private determineCaseType(text: string): string {
    if (text === text.toLowerCase()) return 'lowercase';
    if (text === text.toUpperCase()) return 'uppercase';
    if (text[0] === text[0].toUpperCase() && text.slice(1) === text.slice(1).toLowerCase()) return 'titlecase';
    return 'mixedcase';
  }

  /**
   * Aplica um padrão regex e executa callback para cada match
   */
  private matchPattern(
    text: string, 
    pattern: RegExp, 
    callback: (match: string, start: number, end: number) => void
  ): void {
    let match;
    const regex = new RegExp(pattern.source, pattern.flags);
    
    while ((match = regex.exec(text)) !== null) {
      callback(match[0], match.index, match.index + match[0].length);
      
      // Prevenir loop infinito em regex sem flag global
      if (!pattern.global) break;
    }
  }

  /**
   * Consolida segmentos removendo sobreposições e filtrando por confiança
   */
  private consolidateSegments(segments: HighlightSegment[]): HighlightSegment[] {
    // Filtrar por confiança
    const filtered = segments.filter(s => s.confidence >= this.config.confidenceThreshold);
    
    // Ordenar por posição
    filtered.sort((a, b) => a.start - b.start);
    
    // Remover sobreposições (manter o de maior confiança)
    const consolidated: HighlightSegment[] = [];
    
    for (const segment of filtered) {
      const lastSegment = consolidated[consolidated.length - 1];
      
      if (!lastSegment || segment.start >= lastSegment.end) {
        // Não há sobreposição
        consolidated.push(segment);
      } else if (segment.confidence > lastSegment.confidence) {
        // Substituir por segmento de maior confiança
        consolidated[consolidated.length - 1] = segment;
      }
      // Caso contrário, manter o segmento existente
    }
    
    return consolidated;
  }

  /**
   * Gera CSS classes para diferentes tipos de destaque
   */
  public generateCssClasses(): string {
    return `
      .semantic-highlight-code-syntax { background-color: #f1f8ff; color: #0366d6; }
      .semantic-highlight-legal-term { background-color: #fff5b4; color: #6a5d00; font-weight: 600; }
      .semantic-highlight-technical-term { background-color: #e3f2fd; color: #1565c0; }
      .semantic-highlight-number-change { background-color: #ffeef0; color: #d73a49; font-weight: 500; }
      .semantic-highlight-date-change { background-color: #f0fff4; color: #28a745; font-weight: 500; }
      .semantic-highlight-url-change { background-color: #f8f9fa; color: #0366d6; text-decoration: underline; }
      .semantic-highlight-email-change { background-color: #f8f9fa; color: #0366d6; }
      .semantic-highlight-structural-change { background-color: #ffeaa7; color: #2d3748; font-weight: 600; }
      .semantic-highlight-content-change { background-color: transparent; }
      .semantic-highlight-whitespace-change { background-color: #ff6b6b; opacity: 0.3; }
      .semantic-highlight-case-change { background-color: #74b9ff; color: #2d3748; }
      .semantic-highlight-punctuation-change { background-color: #fd79a8; color: #2d3748; }
      .semantic-highlight-semantic-move { background-color: #a29bfe; color: #2d3748; }
      .semantic-highlight-semantic-replace { background-color: #fd8f56; color: #2d3748; }
      
      .dark .semantic-highlight-code-syntax { background-color: #1f2937; color: #60a5fa; }
      .dark .semantic-highlight-legal-term { background-color: #374151; color: #fbbf24; }
      .dark .semantic-highlight-technical-term { background-color: #1e3a8a; color: #93c5fd; }
      .dark .semantic-highlight-number-change { background-color: #7f1d1d; color: #fca5a5; }
      .dark .semantic-highlight-date-change { background-color: #14532d; color: #86efac; }
      .dark .semantic-highlight-url-change { background-color: #1f2937; color: #60a5fa; }
      .dark .semantic-highlight-email-change { background-color: #1f2937; color: #60a5fa; }
      .dark .semantic-highlight-structural-change { background-color: #44403c; color: #fbbf24; }
      .dark .semantic-highlight-case-change { background-color: #1e40af; color: #bfdbfe; }
      .dark .semantic-highlight-punctuation-change { background-color: #be185d; color: #fce7f3; }
    `;
  }
}

export default SemanticHighlighter; 