import { useState, useCallback, useRef, useEffect } from 'react';

export interface AsyncState<T> {
  data: T | null;
  loading: boolean;
  error: Error | null;
  progress: number;
  retryCount: number;
  aborted: boolean;
}

export interface AsyncStateOptions {
  initialData?: any;
  maxRetries?: number;
  retryDelay?: number;
  timeout?: number;
  enableProgress?: boolean;
  onError?: (error: Error) => void;
  onSuccess?: (data: any) => void;
  onProgress?: (progress: number) => void;
}

export interface UseAsyncStateReturn<T> {
  state: AsyncState<T>;
  execute: (asyncFn: () => Promise<T>) => Promise<T | null>;
  retry: () => Promise<T | null>;
  abort: () => void;
  reset: () => void;
  setProgress: (progress: number) => void;
  setData: (data: T | null) => void;
  setError: (error: Error | null) => void;
}

/**
 * Hook for managing async operations with comprehensive state management
 */
export function useAsyncState<T = any>(
  options: AsyncStateOptions = {}
): UseAsyncStateReturn<T> {
  const {
    initialData = null,
    maxRetries = 3,
    retryDelay = 1000,
    timeout = 30000,
    enableProgress = false,
    onError,
    onSuccess,
    onProgress,
  } = options;

  const [state, setState] = useState<AsyncState<T>>({
    data: initialData,
    loading: false,
    error: null,
    progress: 0,
    retryCount: 0,
    aborted: false,
  });

  const abortControllerRef = useRef<AbortController | null>(null);
  const lastAsyncFnRef = useRef<(() => Promise<T>) | null>(null);
  const timeoutRef = useRef<NodeJS.Timeout | null>(null);
  const retryTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  // Progress simulation for operations without native progress
  const simulateProgress = useCallback(() => {
    if (!enableProgress) return;

    const progressInterval = setInterval(() => {
      setState(prev => {
        if (prev.loading && prev.progress < 90) {
          const newProgress = Math.min(prev.progress + Math.random() * 10, 90);
          onProgress?.(newProgress);
          return { ...prev, progress: newProgress };
        }
        return prev;
      });
    }, 500);

    return () => clearInterval(progressInterval);
  }, [enableProgress, onProgress]);

  const setProgress = useCallback((progress: number) => {
    setState(prev => ({ ...prev, progress: Math.max(0, Math.min(100, progress)) }));
    onProgress?.(progress);
  }, [onProgress]);

  const setData = useCallback((data: T | null) => {
    setState(prev => ({ ...prev, data }));
  }, []);

  const setError = useCallback((error: Error | null) => {
    setState(prev => ({ ...prev, error }));
  }, []);

  const abort = useCallback(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
    }
    if (retryTimeoutRef.current) {
      clearTimeout(retryTimeoutRef.current);
    }
    setState(prev => ({ ...prev, loading: false, aborted: true }));
  }, []);

  const reset = useCallback(() => {
    abort();
    setState({
      data: initialData,
      loading: false,
      error: null,
      progress: 0,
      retryCount: 0,
      aborted: false,
    });
    lastAsyncFnRef.current = null;
  }, [initialData, abort]);

  const execute = useCallback(async (asyncFn: () => Promise<T>): Promise<T | null> => {
    // Store the function for potential retries
    lastAsyncFnRef.current = asyncFn;

    // Create new abort controller
    abortControllerRef.current = new AbortController();
    const { signal } = abortControllerRef.current;

    setState(prev => ({
      ...prev,
      loading: true,
      error: null,
      progress: enableProgress ? 0 : prev.progress,
      aborted: false,
    }));

    // Start progress simulation if enabled
    const stopProgressSimulation = enableProgress ? simulateProgress() : undefined;

    // Set timeout
    if (timeout > 0) {
      timeoutRef.current = setTimeout(() => {
        abort();
        const timeoutError = new Error(`Operation timed out after ${timeout}ms`);
        setState(prev => ({ ...prev, error: timeoutError, loading: false }));
        onError?.(timeoutError);
      }, timeout);
    }

    try {
      // Check if already aborted
      if (signal.aborted) {
        throw new Error('Operation was aborted');
      }

      // Execute the async function
      const result = await asyncFn();

      // Check again if aborted during execution
      if (signal.aborted) {
        throw new Error('Operation was aborted');
      }

      // Success
      setState(prev => ({
        ...prev,
        data: result,
        loading: false,
        error: null,
        progress: enableProgress ? 100 : prev.progress,
        retryCount: 0,
      }));

      onSuccess?.(result);
      return result;

    } catch (error) {
      const errorObj = error instanceof Error ? error : new Error(String(error));
      
      setState(prev => ({
        ...prev,
        error: errorObj,
        loading: false,
        progress: enableProgress ? 0 : prev.progress,
      }));

      onError?.(errorObj);
      return null;

    } finally {
      // Cleanup
      stopProgressSimulation?.();
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
    }
  }, [enableProgress, timeout, simulateProgress, onError, onSuccess, abort]);

  const retry = useCallback(async (): Promise<T | null> => {
    const { retryCount } = state;
    
    if (retryCount >= maxRetries) {
      const maxRetriesError = new Error(`Maximum retry attempts (${maxRetries}) exceeded`);
      setState(prev => ({ ...prev, error: maxRetriesError }));
      onError?.(maxRetriesError);
      return null;
    }

    if (!lastAsyncFnRef.current) {
      const noFunctionError = new Error('No function to retry');
      setState(prev => ({ ...prev, error: noFunctionError }));
      onError?.(noFunctionError);
      return null;
    }

    // Increment retry count
    setState(prev => ({ ...prev, retryCount: prev.retryCount + 1 }));

    // Add delay before retry
    if (retryDelay > 0) {
      await new Promise(resolve => {
        retryTimeoutRef.current = setTimeout(resolve, retryDelay * (retryCount + 1));
      });
    }

    return execute(lastAsyncFnRef.current);
  }, [state, maxRetries, retryDelay, execute, onError]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      abort();
    };
  }, [abort]);

  return {
    state,
    execute,
    retry,
    abort,
    reset,
    setProgress,
    setData,
    setError,
  };
}

/**
 * Hook for managing multiple async operations
 */
export function useAsyncQueue<T = any>(
  options: AsyncStateOptions = {}
): {
  states: Record<string, AsyncState<T>>;
  execute: (key: string, asyncFn: () => Promise<T>) => Promise<T | null>;
  retry: (key: string) => Promise<T | null>;
  abort: (key: string) => void;
  abortAll: () => void;
  reset: (key: string) => void;
  resetAll: () => void;
  getState: (key: string) => AsyncState<T>;
} {
  const [states, setStates] = useState<Record<string, AsyncState<T>>>({});
  const asyncRefs = useRef<Record<string, UseAsyncStateReturn<T>>>({});

  const getAsyncState = useCallback((key: string) => {
    if (!asyncRefs.current[key]) {
      const asyncState = useAsyncState<T>(options);
      asyncRefs.current[key] = asyncState;
      setStates(prev => ({ ...prev, [key]: asyncState.state }));
    }
    return asyncRefs.current[key];
  }, [options]);

  const execute = useCallback(async (key: string, asyncFn: () => Promise<T>) => {
    const asyncState = getAsyncState(key);
    const result = await asyncState.execute(asyncFn);
    setStates(prev => ({ ...prev, [key]: asyncState.state }));
    return result;
  }, [getAsyncState]);

  const retry = useCallback(async (key: string) => {
    const asyncState = asyncRefs.current[key];
    if (!asyncState) return null;
    
    const result = await asyncState.retry();
    setStates(prev => ({ ...prev, [key]: asyncState.state }));
    return result;
  }, []);

  const abort = useCallback((key: string) => {
    const asyncState = asyncRefs.current[key];
    if (asyncState) {
      asyncState.abort();
      setStates(prev => ({ ...prev, [key]: asyncState.state }));
    }
  }, []);

  const abortAll = useCallback(() => {
    Object.values(asyncRefs.current).forEach(asyncState => asyncState.abort());
    setStates(prev => {
      const newStates = { ...prev };
      Object.keys(newStates).forEach(key => {
        const asyncState = asyncRefs.current[key];
        if (asyncState) {
          newStates[key] = asyncState.state;
        }
      });
      return newStates;
    });
  }, []);

  const reset = useCallback((key: string) => {
    const asyncState = asyncRefs.current[key];
    if (asyncState) {
      asyncState.reset();
      setStates(prev => ({ ...prev, [key]: asyncState.state }));
    }
  }, []);

  const resetAll = useCallback(() => {
    Object.values(asyncRefs.current).forEach(asyncState => asyncState.reset());
    setStates({});
    asyncRefs.current = {};
  }, []);

  const getState = useCallback((key: string) => {
    return states[key] || {
      data: null,
      loading: false,
      error: null,
      progress: 0,
      retryCount: 0,
      aborted: false,
    };
  }, [states]);

  return {
    states,
    execute,
    retry,
    abort,
    abortAll,
    reset,
    resetAll,
    getState,
  };
}

/**
 * Hook for debounced async operations
 */
export function useDebouncedAsyncState<T = any>(
  debounceDelay: number = 300,
  options: AsyncStateOptions = {}
): UseAsyncStateReturn<T> & { debouncedExecute: (asyncFn: () => Promise<T>) => void } {
  const asyncState = useAsyncState<T>(options);
  const debounceTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  const debouncedExecute = useCallback((asyncFn: () => Promise<T>) => {
    if (debounceTimeoutRef.current) {
      clearTimeout(debounceTimeoutRef.current);
    }

    debounceTimeoutRef.current = setTimeout(() => {
      asyncState.execute(asyncFn);
    }, debounceDelay);
  }, [asyncState, debounceDelay]);

  useEffect(() => {
    return () => {
      if (debounceTimeoutRef.current) {
        clearTimeout(debounceTimeoutRef.current);
      }
    };
  }, []);

  return {
    ...asyncState,
    debouncedExecute,
  };
}

export default useAsyncState; 