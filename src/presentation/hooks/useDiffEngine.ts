import { useState, useCallback, useEffect, useRef, useMemo } from 'react';
import { DiffResult } from '../../domain/entities/DiffResult';
import { IDiffEngine } from '../../domain/interfaces/IDiffEngine';

export interface DiffEngineOptions {
  autoProcess?: boolean;
  debounceMs?: number;
  cacheResults?: boolean;
  maxCacheSize?: number;
  enableWorker?: boolean;
  retryAttempts?: number;
  onProgress?: (progress: number) => void;
  onError?: (error: string) => void;
  onComplete?: (result: DiffResult) => void;
}

export interface DiffEngineState {
  isProcessing: boolean;
  progress: number;
  error: string | null;
  result: DiffResult | null;
  lastProcessTime: number;
  cacheHits: number;
  processedComparisons: number;
}

export interface UseDiffEngineReturn {
  // State
  state: DiffEngineState;
  
  // Actions
  compare: (originalText: string, modifiedText: string) => Promise<DiffResult | null>;
  reset: () => void;
  clearCache: () => void;
  retry: () => void;
  
  // Cache management
  getCacheStats: () => { size: number; hits: number; misses: number };
  preloadComparison: (originalText: string, modifiedText: string) => void;
  
  // Status
  isReady: boolean;
  canRetry: boolean;
}

interface CachedResult {
  key: string;
  result: DiffResult;
  timestamp: number;
  accessCount: number;
  lastAccessed: number;
}

/**
 * Hook para gerenciar operações do motor de diff
 * Oferece cache inteligente, processamento assíncrono e tratamento de erros
 */
export const useDiffEngine = (
  diffEngine: IDiffEngine | null,
  options: DiffEngineOptions = {}
): UseDiffEngineReturn => {
  const {
    autoProcess = true,
    debounceMs = 500,
    cacheResults = true,
    maxCacheSize = 50,
    enableWorker = true,
    retryAttempts = 3,
    onProgress,
    onError,
    onComplete
  } = options;

  // State
  const [state, setState] = useState<DiffEngineState>({
    isProcessing: false,
    progress: 0,
    error: null,
    result: null,
    lastProcessTime: 0,
    cacheHits: 0,
    processedComparisons: 0
  });

  // Refs for stable references
  const cacheRef = useRef<Map<string, CachedResult>>(new Map());
  const debounceRef = useRef<NodeJS.Timeout | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);
  const retryCountRef = useRef<number>(0);
  const lastComparisonRef = useRef<{ original: string; modified: string } | null>(null);

  // Generate cache key
  const generateCacheKey = useCallback((originalText: string, modifiedText: string): string => {
    const content = `${originalText}||${modifiedText}`;
    // Simple hash function for cache key
    let hash = 0;
    for (let i = 0; i < content.length; i++) {
      const char = content.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32bit integer
    }
    return `diff_${Math.abs(hash)}_${originalText.length}_${modifiedText.length}`;
  }, []);

  // Cache management
  const getCachedResult = useCallback((key: string): DiffResult | null => {
    if (!cacheResults) return null;
    
    const cached = cacheRef.current.get(key);
    if (!cached) return null;

    // Update access statistics
    cached.accessCount++;
    cached.lastAccessed = Date.now();
    
    setState(prev => ({ ...prev, cacheHits: prev.cacheHits + 1 }));
    return cached.result;
  }, [cacheResults]);

  const setCachedResult = useCallback((key: string, result: DiffResult) => {
    if (!cacheResults) return;

    const cache = cacheRef.current;
    
    // Remove oldest entries if cache is full
    if (cache.size >= maxCacheSize) {
      const entries = Array.from(cache.entries());
      entries.sort((a, b) => a[1].lastAccessed - b[1].lastAccessed);
      
      // Remove oldest 20% of entries
      const toRemove = Math.ceil(maxCacheSize * 0.2);
      for (let i = 0; i < toRemove; i++) {
        cache.delete(entries[i][0]);
      }
    }

    cache.set(key, {
      key,
      result,
      timestamp: Date.now(),
      accessCount: 1,
      lastAccessed: Date.now()
    });
  }, [cacheResults, maxCacheSize]);

  // Progress simulation for better UX
  const simulateProgress = useCallback((duration: number) => {
    const startTime = Date.now();
    const interval = setInterval(() => {
      const elapsed = Date.now() - startTime;
      const progress = Math.min(Math.round((elapsed / duration) * 90), 90); // Max 90% until actual completion
      
      setState(prev => ({ ...prev, progress }));
      onProgress?.(progress);
      
      if (progress >= 90) {
        clearInterval(interval);
      }
    }, 50);

    return () => clearInterval(interval);
  }, [onProgress]);

  // Main compare function
  const compare = useCallback(async (
    originalText: string, 
    modifiedText: string
  ): Promise<DiffResult | null> => {
    if (!diffEngine) {
      const error = 'Diff engine not available';
      setState(prev => ({ ...prev, error }));
      onError?.(error);
      return null;
    }

    // Cancel any existing operation
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    abortControllerRef.current = new AbortController();

    // Generate cache key and check cache
    const cacheKey = generateCacheKey(originalText, modifiedText);
    const cachedResult = getCachedResult(cacheKey);
    
    if (cachedResult) {
      setState(prev => ({
        ...prev,
        result: cachedResult,
        error: null,
        progress: 100,
        isProcessing: false
      }));
      onComplete?.(cachedResult);
      return cachedResult;
    }

    setState(prev => ({
      ...prev,
      isProcessing: true,
      progress: 0,
      error: null
    }));

    // Store for retry attempts
    lastComparisonRef.current = { original: originalText, modified: modifiedText };
    retryCountRef.current = 0;

    try {
      const startTime = Date.now();
      
      // Start progress simulation
      const stopProgress = simulateProgress(2000); // Estimate 2 seconds

      // Perform diff comparison
      const result = await diffEngine.compare({
        originalText,
        modifiedText
      });

      stopProgress();
      
      const processTime = Date.now() - startTime;

      // Cache the result
      setCachedResult(cacheKey, result);

      setState(prev => ({
        ...prev,
        isProcessing: false,
        progress: 100,
        result,
        lastProcessTime: processTime,
        processedComparisons: prev.processedComparisons + 1,
        error: null
      }));

      onProgress?.(100);
      onComplete?.(result);
      
      return result;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Diff processing failed';
      
      setState(prev => ({
        ...prev,
        isProcessing: false,
        progress: 0,
        error: errorMessage
      }));

      onError?.(errorMessage);
      return null;
    }
  }, [diffEngine, generateCacheKey, getCachedResult, setCachedResult, simulateProgress, onProgress, onComplete, onError]);

  // Debounced compare for auto-processing
  const debouncedCompare = useCallback((originalText: string, modifiedText: string) => {
    if (debounceRef.current) {
      clearTimeout(debounceRef.current);
    }

    debounceRef.current = setTimeout(() => {
      compare(originalText, modifiedText);
    }, debounceMs);
  }, [compare, debounceMs]);

  // Retry function
  const retry = useCallback(async () => {
    if (!lastComparisonRef.current || retryCountRef.current >= retryAttempts) {
      return;
    }

    retryCountRef.current++;
    const { original, modified } = lastComparisonRef.current;
    await compare(original, modified);
  }, [compare, retryAttempts]);

  // Reset function
  const reset = useCallback(() => {
    // Cancel any ongoing operations
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    
    // Clear debounce
    if (debounceRef.current) {
      clearTimeout(debounceRef.current);
      debounceRef.current = null;
    }

    setState({
      isProcessing: false,
      progress: 0,
      error: null,
      result: null,
      lastProcessTime: 0,
      cacheHits: 0,
      processedComparisons: 0
    });

    retryCountRef.current = 0;
    lastComparisonRef.current = null;
  }, []);

  // Clear cache
  const clearCache = useCallback(() => {
    cacheRef.current.clear();
    setState(prev => ({ ...prev, cacheHits: 0 }));
  }, []);

  // Preload comparison for better UX
  const preloadComparison = useCallback((originalText: string, modifiedText: string) => {
    // Check if already cached
    const cacheKey = generateCacheKey(originalText, modifiedText);
    if (getCachedResult(cacheKey)) return;

    // Preload in background if not processing
    if (!state.isProcessing && originalText && modifiedText) {
      setTimeout(() => {
        compare(originalText, modifiedText);
      }, 100);
    }
  }, [generateCacheKey, getCachedResult, state.isProcessing, compare]);

  // Get cache statistics
  const getCacheStats = useCallback(() => {
    const cache = cacheRef.current;
    const totalRequests = state.processedComparisons + state.cacheHits;
    
    return {
      size: cache.size,
      hits: state.cacheHits,
      misses: state.processedComparisons,
      hitRate: totalRequests > 0 ? (state.cacheHits / totalRequests) * 100 : 0,
      totalRequests
    };
  }, [state.cacheHits, state.processedComparisons]);

  // Computed values
  const isReady = useMemo(() => {
    return !!diffEngine && !state.isProcessing;
  }, [diffEngine, state.isProcessing]);

  const canRetry = useMemo(() => {
    return !!state.error && !!lastComparisonRef.current && retryCountRef.current < retryAttempts;
  }, [state.error, retryAttempts]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
      if (debounceRef.current) {
        clearTimeout(debounceRef.current);
      }
    };
  }, []);

  return {
    state,
    compare,
    reset,
    clearCache,
    retry,
    getCacheStats,
    preloadComparison,
    isReady,
    canRetry
  };
};

export default useDiffEngine; 