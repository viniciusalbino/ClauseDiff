import { useState, useCallback, useEffect, useRef, useMemo } from 'react';
import { DiffResult, DiffChunk } from '../../domain/entities/DiffResult';

export interface NavigableChange {
  id: string;
  type: 'addition' | 'deletion' | 'modification' | 'move';
  chunkIndex: number;
  lineNumber: number;
  originalLineNumber?: number;
  modifiedLineNumber?: number;
  content: string;
  severity: 'low' | 'medium' | 'high';
  description: string;
  context?: string;
}

export interface NavigationOptions {
  enableKeyboardShortcuts?: boolean;
  enableCycling?: boolean; // Return to first when reaching last
  autoScroll?: boolean;
  scrollOffset?: number; // Offset from top when scrolling
  scrollBehavior?: 'auto' | 'smooth';
  trackVisitedChanges?: boolean;
  highlightDuration?: number; // ms to highlight current change
}

export interface NavigationState {
  changes: NavigableChange[];
  currentIndex: number;
  visitedChanges: Set<string>;
  isNavigating: boolean;
  highlightedChangeId: string | null;
  totalChanges: number;
  statistics: {
    additions: number;
    deletions: number;
    modifications: number;
    moves: number;
  };
}

export interface UseDiffNavigationReturn {
  // State
  state: NavigationState;
  
  // Navigation actions
  goToNext: () => void;
  goToPrevious: () => void;
  goToFirst: () => void;
  goToLast: () => void;
  goToChange: (changeId: string) => void;
  goToIndex: (index: number) => void;
  
  // Query methods
  getCurrentChange: () => NavigableChange | null;
  getChangeAt: (index: number) => NavigableChange | null;
  getChangesOfType: (type: NavigableChange['type']) => NavigableChange[];
  getChangesBySeverity: (severity: NavigableChange['severity']) => NavigableChange[];
  
  // Status
  canGoNext: boolean;
  canGoPrevious: boolean;
  isAtFirst: boolean;
  isAtLast: boolean;
  
  // Utilities
  reset: () => void;
  clearVisited: () => void;
  markAsVisited: (changeId: string) => void;
}

/**
 * Hook para navegação avançada em diferenças
 * Oferece navegação por teclado, rastreamento de mudanças e scroll inteligente
 */
export const useDiffNavigation = (
  diffResult: DiffResult | null,
  options: NavigationOptions = {}
): UseDiffNavigationReturn => {
  const {
    enableKeyboardShortcuts = true,
    enableCycling = true,
    autoScroll = true,
    scrollOffset = 100,
    scrollBehavior = 'smooth',
    trackVisitedChanges = true,
    highlightDuration = 1000
  } = options;

  const [state, setState] = useState<NavigationState>({
    changes: [],
    currentIndex: -1,
    visitedChanges: new Set(),
    isNavigating: false,
    highlightedChangeId: null,
    totalChanges: 0,
    statistics: {
      additions: 0,
      deletions: 0,
      modifications: 0,
      moves: 0
    }
  });

  const highlightTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  // Process diff result into navigable changes
  const processChanges = useCallback((result: DiffResult): NavigableChange[] => {
    const changes: NavigableChange[] = [];
    let originalLine = 1;
    let modifiedLine = 1;

    result.chunks.forEach((chunk, chunkIndex) => {
      if (chunk.operation !== 'equal') {
        const lines = chunk.text.split('\n');
        const lineCount = lines.length;

        const change: NavigableChange = {
          id: `change-${chunkIndex}`,
          type: getChangeType(chunk),
          chunkIndex,
          lineNumber: chunk.operation === 'delete' ? originalLine : modifiedLine,
          originalLineNumber: chunk.operation !== 'insert' ? originalLine : undefined,
          modifiedLineNumber: chunk.operation !== 'delete' ? modifiedLine : undefined,
          content: chunk.text.length > 100 ? chunk.text.substring(0, 100) + '...' : chunk.text,
          severity: calculateSeverity(chunk),
          description: generateDescription(chunk),
          context: generateContext(result.chunks, chunkIndex)
        };

        changes.push(change);
      }

      // Update line counters
      const lineCount = chunk.text.split('\n').length;
      if (chunk.operation !== 'insert') {
        originalLine += lineCount;
      }
      if (chunk.operation !== 'delete') {
        modifiedLine += lineCount;
      }
    });

    return changes;
  }, []);

  // Calculate statistics
  const calculateStatistics = useCallback((changes: NavigableChange[]) => {
    const stats = {
      additions: 0,
      deletions: 0,
      modifications: 0,
      moves: 0
    };

    changes.forEach(change => {
      switch (change.type) {
        case 'addition':
          stats.additions++;
          break;
        case 'deletion':
          stats.deletions++;
          break;
        case 'modification':
          stats.modifications++;
          break;
        case 'move':
          stats.moves++;
          break;
      }
    });

    return stats;
  }, []);

  // Update state when diffResult changes
  useEffect(() => {
    if (!diffResult) {
      setState(prev => ({
        ...prev,
        changes: [],
        currentIndex: -1,
        totalChanges: 0,
        statistics: { additions: 0, deletions: 0, modifications: 0, moves: 0 }
      }));
      return;
    }

    const changes = processChanges(diffResult);
    const statistics = calculateStatistics(changes);

    setState(prev => ({
      ...prev,
      changes,
      currentIndex: changes.length > 0 ? 0 : -1,
      totalChanges: changes.length,
      statistics
    }));
  }, [diffResult, processChanges, calculateStatistics]);

  // Navigation functions
  const goToNext = useCallback(() => {
    setState(prev => {
      if (prev.changes.length === 0) return prev;
      
      let nextIndex = prev.currentIndex + 1;
      
      if (nextIndex >= prev.changes.length) {
        if (enableCycling) {
          nextIndex = 0;
        } else {
          return prev;
        }
      }

      return { ...prev, currentIndex: nextIndex };
    });
  }, [enableCycling]);

  const goToPrevious = useCallback(() => {
    setState(prev => {
      if (prev.changes.length === 0) return prev;
      
      let prevIndex = prev.currentIndex - 1;
      
      if (prevIndex < 0) {
        if (enableCycling) {
          prevIndex = prev.changes.length - 1;
        } else {
          return prev;
        }
      }

      return { ...prev, currentIndex: prevIndex };
    });
  }, [enableCycling]);

  const goToFirst = useCallback(() => {
    setState(prev => {
      if (prev.changes.length === 0) return prev;
      return { ...prev, currentIndex: 0 };
    });
  }, []);

  const goToLast = useCallback(() => {
    setState(prev => {
      if (prev.changes.length === 0) return prev;
      return { ...prev, currentIndex: prev.changes.length - 1 };
    });
  }, []);

  const goToChange = useCallback((changeId: string) => {
    setState(prev => {
      const index = prev.changes.findIndex(change => change.id === changeId);
      if (index === -1) return prev;
      return { ...prev, currentIndex: index };
    });
  }, []);

  const goToIndex = useCallback((index: number) => {
    setState(prev => {
      if (index < 0 || index >= prev.changes.length) return prev;
      return { ...prev, currentIndex: index };
    });
  }, []);

  // Scroll to current change
  const scrollToCurrentChange = useCallback(() => {
    if (!autoScroll || state.currentIndex === -1) return;

    const currentChange = state.changes[state.currentIndex];
    if (!currentChange) return;

    // Find element by data attribute or class
    const element = document.querySelector(`[data-change-id="${currentChange.id}"]`) ||
                   document.querySelector(`[data-line="${currentChange.lineNumber}"]`);

    if (element) {
      const elementRect = element.getBoundingClientRect();
      const scrollTop = window.pageYOffset + elementRect.top - scrollOffset;

      window.scrollTo({
        top: scrollTop,
        behavior: scrollBehavior
      });

      // Highlight the change
      if (highlightDuration > 0) {
        setState(prev => ({ ...prev, highlightedChangeId: currentChange.id }));
        
        if (highlightTimeoutRef.current) {
          clearTimeout(highlightTimeoutRef.current);
        }
        
        highlightTimeoutRef.current = setTimeout(() => {
          setState(prev => ({ ...prev, highlightedChangeId: null }));
        }, highlightDuration);
      }
    }
  }, [autoScroll, state.currentIndex, state.changes, scrollOffset, scrollBehavior, highlightDuration]);

  // Mark change as visited
  const markAsVisited = useCallback((changeId: string) => {
    if (!trackVisitedChanges) return;

    setState(prev => ({
      ...prev,
      visitedChanges: new Set(prev.visitedChanges).add(changeId)
    }));
  }, [trackVisitedChanges]);

  // Track current change as visited
  useEffect(() => {
    if (state.currentIndex >= 0 && state.changes[state.currentIndex]) {
      const currentChange = state.changes[state.currentIndex];
      markAsVisited(currentChange.id);
      scrollToCurrentChange();
    }
  }, [state.currentIndex, state.changes, markAsVisited, scrollToCurrentChange]);

  // Keyboard shortcuts
  useEffect(() => {
    if (!enableKeyboardShortcuts) return;

    const handleKeyDown = (event: KeyboardEvent) => {
      // Only handle if not typing in input/textarea
      if (event.target instanceof HTMLInputElement || 
          event.target instanceof HTMLTextAreaElement ||
          event.target instanceof HTMLSelectElement) {
        return;
      }

      const { key, ctrlKey, metaKey, shiftKey } = event;
      const modKey = ctrlKey || metaKey;

      switch (key) {
        case 'ArrowDown':
        case 'j':
          if (!modKey) {
            event.preventDefault();
            goToNext();
          }
          break;
        case 'ArrowUp':
        case 'k':
          if (!modKey) {
            event.preventDefault();
            goToPrevious();
          }
          break;
        case 'Home':
        case 'g':
          if (!shiftKey) {
            event.preventDefault();
            goToFirst();
          }
          break;
        case 'End':
        case 'G':
          event.preventDefault();
          goToLast();
          break;
        case 'n':
          if (modKey) {
            event.preventDefault();
            goToNext();
          }
          break;
        case 'p':
          if (modKey) {
            event.preventDefault();
            goToPrevious();
          }
          break;
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [enableKeyboardShortcuts, goToNext, goToPrevious, goToFirst, goToLast]);

  // Query methods
  const getCurrentChange = useCallback((): NavigableChange | null => {
    return state.currentIndex >= 0 ? state.changes[state.currentIndex] || null : null;
  }, [state.currentIndex, state.changes]);

  const getChangeAt = useCallback((index: number): NavigableChange | null => {
    return state.changes[index] || null;
  }, [state.changes]);

  const getChangesOfType = useCallback((type: NavigableChange['type']): NavigableChange[] => {
    return state.changes.filter(change => change.type === type);
  }, [state.changes]);

  const getChangesBySeverity = useCallback((severity: NavigableChange['severity']): NavigableChange[] => {
    return state.changes.filter(change => change.severity === severity);
  }, [state.changes]);

  // Reset function
  const reset = useCallback(() => {
    setState(prev => ({
      ...prev,
      currentIndex: prev.changes.length > 0 ? 0 : -1,
      visitedChanges: new Set(),
      isNavigating: false,
      highlightedChangeId: null
    }));
  }, []);

  // Clear visited changes
  const clearVisited = useCallback(() => {
    setState(prev => ({ ...prev, visitedChanges: new Set() }));
  }, []);

  // Computed values
  const canGoNext = useMemo(() => {
    return state.changes.length > 0 && (state.currentIndex < state.changes.length - 1 || enableCycling);
  }, [state.changes.length, state.currentIndex, enableCycling]);

  const canGoPrevious = useMemo(() => {
    return state.changes.length > 0 && (state.currentIndex > 0 || enableCycling);
  }, [state.changes.length, state.currentIndex, enableCycling]);

  const isAtFirst = useMemo(() => {
    return state.currentIndex === 0;
  }, [state.currentIndex]);

  const isAtLast = useMemo(() => {
    return state.currentIndex === state.changes.length - 1;
  }, [state.currentIndex, state.changes.length]);

  // Cleanup
  useEffect(() => {
    return () => {
      if (highlightTimeoutRef.current) {
        clearTimeout(highlightTimeoutRef.current);
      }
    };
  }, []);

  return {
    state,
    goToNext,
    goToPrevious,
    goToFirst,
    goToLast,
    goToChange,
    goToIndex,
    getCurrentChange,
    getChangeAt,
    getChangesOfType,
    getChangesBySeverity,
    canGoNext,
    canGoPrevious,
    isAtFirst,
    isAtLast,
    reset,
    clearVisited,
    markAsVisited
  };
};

// Helper functions
function getChangeType(chunk: DiffChunk): NavigableChange['type'] {
  switch (chunk.operation) {
    case 'insert': return 'addition';
    case 'delete': return 'deletion';
    case 'modify': return 'modification';
    default: return 'modification';
  }
}

function calculateSeverity(chunk: DiffChunk): NavigableChange['severity'] {
  const lineCount = chunk.text.split('\n').length;
  const charCount = chunk.text.length;
  
  if (lineCount > 50 || charCount > 1000) return 'high';
  if (lineCount > 10 || charCount > 200) return 'medium';
  return 'low';
}

function generateDescription(chunk: DiffChunk): string {
  const lineCount = chunk.text.split('\n').length;
  const operation = chunk.operation === 'insert' ? 'Added' :
                   chunk.operation === 'delete' ? 'Deleted' : 'Modified';
  
  return `${operation} ${lineCount} line${lineCount !== 1 ? 's' : ''}`;
}

function generateContext(chunks: DiffChunk[], currentIndex: number): string {
  const prevChunk = chunks[currentIndex - 1];
  const nextChunk = chunks[currentIndex + 1];
  
  let context = '';
  if (prevChunk && prevChunk.operation === 'equal') {
    const lines = prevChunk.text.split('\n');
    context += lines.slice(-2).join(' ').trim();
  }
  
  if (nextChunk && nextChunk.operation === 'equal') {
    const lines = nextChunk.text.split('\n');
    context += ' ' + lines.slice(0, 2).join(' ').trim();
  }
  
  return context.length > 100 ? context.substring(0, 100) + '...' : context;
}

export default useDiffNavigation; 