import { useState, useCallback, useMemo, useEffect } from 'react';
import { DiffResult, DiffChunk } from '../../domain/entities/DiffResult';

export interface CollapsibleSection {
  id: string;
  chunkIndex: number;
  startLine: number;
  endLine: number;
  lineCount: number;
  type: 'unchanged' | 'changed' | 'mixed';
  isCollapsed: boolean;
  canCollapse: boolean;
  preview: string;
}

export interface CollapseOptions {
  minUnchangedLines?: number; // Minimum lines to allow collapse
  maxPreviewLength?: number;  // Maximum characters in preview
  autoCollapseThreshold?: number; // Auto-collapse sections larger than this
  persistCollapsedState?: boolean; // Remember collapsed state
  storageKey?: string; // Key for localStorage persistence
  enableKeyboardShortcuts?: boolean;
}

/**
 * Hook para gerenciar seções colapsáveis em visualizações de diff
 * Oferece controle fino sobre seções inalteradas e grandes mudanças
 */
export const useCollapsibleSections = (
  diffResult: DiffResult,
  options: CollapseOptions = {}
) => {
  const {
    minUnchangedLines = 5,
    maxPreviewLength = 100,
    autoCollapseThreshold = 50,
    persistCollapsedState = true,
    storageKey = 'diff-collapsed-sections',
    enableKeyboardShortcuts = true
  } = options;

  // Estado das seções colapsadas
  const [collapsedSections, setCollapsedSections] = useState<Set<string>>(new Set());
  const [isInitialized, setIsInitialized] = useState(false);

  // Processar seções colapsáveis dos chunks
  const sections = useMemo(() => 
    processSections(diffResult, minUnchangedLines, maxPreviewLength), 
    [diffResult, minUnchangedLines, maxPreviewLength]
  );

  // Carregar estado persistido
  useEffect(() => {
    if (!persistCollapsedState || isInitialized) return;

    try {
      const stored = localStorage.getItem(storageKey);
      if (stored) {
        const collapsedIds = JSON.parse(stored) as string[];
        setCollapsedSections(new Set(collapsedIds));
      }

      // Auto-colapsar seções grandes
      if (autoCollapseThreshold > 0) {
        const autoCollapse = sections
          .filter(section => 
            section.canCollapse && 
            section.lineCount >= autoCollapseThreshold &&
            section.type === 'unchanged'
          )
          .map(section => section.id);

        if (autoCollapse.length > 0) {
          setCollapsedSections(prev => {
            const newSet = new Set(prev);
            autoCollapse.forEach(id => newSet.add(id));
            return newSet;
          });
        }
      }

      setIsInitialized(true);
    } catch (error) {
      console.warn('Failed to load collapsed sections state:', error);
      setIsInitialized(true);
    }
  }, [persistCollapsedState, storageKey, autoCollapseThreshold, sections, isInitialized]);

  // Salvar estado quando mudança ocorrer
  useEffect(() => {
    if (!persistCollapsedState || !isInitialized) return;

    try {
      const collapsedArray = Array.from(collapsedSections);
      localStorage.setItem(storageKey, JSON.stringify(collapsedArray));
    } catch (error) {
      console.warn('Failed to save collapsed sections state:', error);
    }
  }, [collapsedSections, persistCollapsedState, storageKey, isInitialized]);

  /**
   * Alterna estado de colapso de uma seção
   */
  const toggleSection = useCallback((sectionId: string) => {
    setCollapsedSections(prev => {
      const newSet = new Set(prev);
      if (newSet.has(sectionId)) {
        newSet.delete(sectionId);
      } else {
        newSet.add(sectionId);
      }
      return newSet;
    });
  }, []);

  /**
   * Colapsa uma seção específica
   */
  const collapseSection = useCallback((sectionId: string) => {
    setCollapsedSections(prev => new Set(prev).add(sectionId));
  }, []);

  /**
   * Expande uma seção específica
   */
  const expandSection = useCallback((sectionId: string) => {
    setCollapsedSections(prev => {
      const newSet = new Set(prev);
      newSet.delete(sectionId);
      return newSet;
    });
  }, []);

  /**
   * Colapsa todas as seções possíveis
   */
  const collapseAll = useCallback(() => {
    const collapsibleIds = sections
      .filter(section => section.canCollapse)
      .map(section => section.id);
    
    setCollapsedSections(new Set(collapsibleIds));
  }, [sections]);

  /**
   * Expande todas as seções
   */
  const expandAll = useCallback(() => {
    setCollapsedSections(new Set());
  }, []);

  /**
   * Colapsa apenas seções inalteradas
   */
  const collapseUnchanged = useCallback(() => {
    const unchangedIds = sections
      .filter(section => section.canCollapse && section.type === 'unchanged')
      .map(section => section.id);
    
    setCollapsedSections(prev => {
      const newSet = new Set(prev);
      unchangedIds.forEach(id => newSet.add(id));
      return newSet;
    });
  }, [sections]);

  /**
   * Colapsa seções grandes automaticamente
   */
  const collapseAutomatic = useCallback((threshold: number = autoCollapseThreshold) => {
    const largeIds = sections
      .filter(section => 
        section.canCollapse && 
        section.lineCount >= threshold
      )
      .map(section => section.id);
    
    setCollapsedSections(prev => {
      const newSet = new Set(prev);
      largeIds.forEach(id => newSet.add(id));
      return newSet;
    });
  }, [sections, autoCollapseThreshold]);

  /**
   * Verifica se uma seção está colapsada
   */
  const isSectionCollapsed = useCallback((sectionId: string): boolean => {
    return collapsedSections.has(sectionId);
  }, [collapsedSections]);

  /**
   * Obtém seção por ID
   */
  const getSectionById = useCallback((sectionId: string): CollapsibleSection | undefined => {
    return sections.find(section => section.id === sectionId);
  }, [sections]);

  /**
   * Obtém seções por tipo
   */
  const getSectionsByType = useCallback((type: CollapsibleSection['type']): CollapsibleSection[] => {
    return sections.filter(section => section.type === type);
  }, [sections]);

  /**
   * Navega para próxima seção colapsada
   */
  const navigateToNextCollapsed = useCallback((): string | null => {
    const collapsedIds = Array.from(collapsedSections);
    if (collapsedIds.length === 0) return null;
    
    // Ordenar por linha
    const sortedCollapsed = collapsedIds
      .map(id => sections.find(s => s.id === id))
      .filter(Boolean)
      .sort((a, b) => a!.startLine - b!.startLine);
    
    return sortedCollapsed[0]?.id || null;
  }, [collapsedSections, sections]);

  /**
   * Keyboard shortcuts handler
   */
  const handleKeyboard = useCallback((event: KeyboardEvent) => {
    if (!enableKeyboardShortcuts) return;

    const { key, ctrlKey, metaKey, shiftKey } = event;
    const modKey = ctrlKey || metaKey;

    switch (key) {
      case 'c':
        if (modKey && shiftKey) {
          event.preventDefault();
          collapseAll();
        } else if (modKey) {
          event.preventDefault();
          collapseUnchanged();
        }
        break;
      case 'e':
        if (modKey) {
          event.preventDefault();
          expandAll();
        }
        break;
      case 'a':
        if (modKey && shiftKey) {
          event.preventDefault();
          collapseAutomatic();
        }
        break;
    }
  }, [enableKeyboardShortcuts, collapseAll, collapseUnchanged, expandAll, collapseAutomatic]);

  // Registrar keyboard shortcuts
  useEffect(() => {
    if (!enableKeyboardShortcuts) return;

    document.addEventListener('keydown', handleKeyboard);
    return () => document.removeEventListener('keydown', handleKeyboard);
  }, [handleKeyboard, enableKeyboardShortcuts]);

  // Estatísticas computadas
  const stats = useMemo(() => {
    const total = sections.length;
    const collapsible = sections.filter(s => s.canCollapse).length;
    const collapsed = sections.filter(s => collapsedSections.has(s.id)).length;
    const unchanged = sections.filter(s => s.type === 'unchanged').length;
    const unchangedCollapsed = sections.filter(s => 
      s.type === 'unchanged' && collapsedSections.has(s.id)
    ).length;

    return {
      total,
      collapsible,
      collapsed,
      unchanged,
      unchangedCollapsed,
      collapsedPercentage: collapsible > 0 ? (collapsed / collapsible) * 100 : 0
    };
  }, [sections, collapsedSections]);

  // Informações sobre linha visível
  const getVisibleLineCount = useCallback((): number => {
    return sections.reduce((count, section) => {
      if (collapsedSections.has(section.id)) {
        return count + 1; // Linha de preview
      }
      return count + section.lineCount;
    }, 0);
  }, [sections, collapsedSections]);

  return {
    // Seções
    sections,
    collapsedSections: Array.from(collapsedSections),
    
    // Controles básicos
    toggleSection,
    collapseSection,
    expandSection,
    isSectionCollapsed,
    
    // Controles em massa
    collapseAll,
    expandAll,
    collapseUnchanged,
    collapseAutomatic,
    
    // Navegação
    navigateToNextCollapsed,
    getSectionById,
    getSectionsByType,
    
    // Estatísticas
    stats,
    getVisibleLineCount,
    
    // Estado
    isInitialized
  };
};

/**
 * Processa chunks do diff para criar seções colapsáveis
 */
function processSections(
  diffResult: DiffResult, 
  minUnchangedLines: number,
  maxPreviewLength: number
): CollapsibleSection[] {
  const sections: CollapsibleSection[] = [];
  let currentLine = 1;

  diffResult.chunks.forEach((chunk, chunkIndex) => {
    const lines = chunk.text.split('\n');
    const lineCount = lines.length;
    const startLine = currentLine;
    const endLine = currentLine + lineCount - 1;

    // Determinar tipo da seção
    const type: CollapsibleSection['type'] = 
      chunk.operation === 'equal' ? 'unchanged' :
      chunk.operation === 'modify' ? 'mixed' : 'changed';

    // Verificar se pode ser colapsada
    const canCollapse = type === 'unchanged' && lineCount >= minUnchangedLines;

    // Gerar preview
    const preview = generatePreview(chunk.text, maxPreviewLength);

    const section: CollapsibleSection = {
      id: `section-${chunkIndex}`,
      chunkIndex,
      startLine,
      endLine,
      lineCount,
      type,
      isCollapsed: false, // Será controlado pelo estado
      canCollapse,
      preview
    };

    sections.push(section);
    currentLine += lineCount;
  });

  return sections;
}

/**
 * Gera preview truncado para uma seção
 */
function generatePreview(text: string, maxLength: number): string {
  const trimmed = text.trim();
  if (trimmed.length <= maxLength) return trimmed;
  
  const truncated = trimmed.slice(0, maxLength);
  const lastSpace = truncated.lastIndexOf(' ');
  
  // Tentar quebrar em palavra completa
  if (lastSpace > maxLength * 0.7) {
    return truncated.slice(0, lastSpace) + '...';
  }
  
  return truncated + '...';
}

export default useCollapsibleSections; 