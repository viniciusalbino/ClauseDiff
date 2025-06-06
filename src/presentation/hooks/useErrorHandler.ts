import { useState, useCallback, useRef, useEffect } from 'react';

export interface ErrorInfo {
  id: string;
  type: ErrorType;
  severity: ErrorSeverity;
  message: string;
  originalError: Error;
  timestamp: Date;
  context?: Record<string, any>;
  retryCount: number;
  maxRetries: number;
  retryable: boolean;
  userAction?: string;
}

export type ErrorType = 
  | 'network'
  | 'validation'
  | 'permission'
  | 'processing'
  | 'timeout'
  | 'resource'
  | 'unknown';

export type ErrorSeverity = 'low' | 'medium' | 'high' | 'critical';

export interface ErrorHandlerOptions {
  maxRetries?: number;
  retryDelay?: number;
  enableAutoRetry?: boolean;
  logErrors?: boolean;
  showUserNotification?: boolean;
  onError?: (error: ErrorInfo) => void;
  onRetry?: (error: ErrorInfo) => void;
  onRecover?: (error: ErrorInfo) => void;
}

export interface ErrorHandlerState {
  errors: ErrorInfo[];
  currentError: ErrorInfo | null;
  isRetrying: boolean;
  retryProgress: number;
}

/**
 * Comprehensive error handling hook with classification, retry logic, and recovery
 */
export const useErrorHandler = (options: ErrorHandlerOptions = {}) => {
  const {
    maxRetries = 3,
    retryDelay = 1000,
    enableAutoRetry = true,
    logErrors = true,
    showUserNotification = true,
    onError,
    onRetry,
    onRecover
  } = options;

  const [state, setState] = useState<ErrorHandlerState>({
    errors: [],
    currentError: null,
    isRetrying: false,
    retryProgress: 0
  });

  const retryTimeouts = useRef<Map<string, NodeJS.Timeout>>(new Map());
  const errorCount = useRef<Map<string, number>>(new Map());

  // Cleanup timeouts on unmount
  useEffect(() => {
    return () => {
      retryTimeouts.current.forEach(timeout => clearTimeout(timeout));
      retryTimeouts.current.clear();
    };
  }, []);

  // Error classification
  const classifyError = (error: Error): { type: ErrorType; severity: ErrorSeverity; retryable: boolean } => {
    const message = error.message.toLowerCase();
    const stack = error.stack?.toLowerCase() || '';

    // Network errors
    if (
      message.includes('network') ||
      message.includes('fetch') ||
      message.includes('connection') ||
      message.includes('timeout') ||
      error.name === 'NetworkError'
    ) {
      return {
        type: 'network',
        severity: message.includes('timeout') ? 'medium' : 'high',
        retryable: true
      };
    }

    // Validation errors
    if (
      message.includes('validation') ||
      message.includes('invalid') ||
      message.includes('required') ||
      message.includes('format') ||
      error.name === 'ValidationError'
    ) {
      return {
        type: 'validation',
        severity: 'low',
        retryable: false
      };
    }

    // Permission errors
    if (
      message.includes('permission') ||
      message.includes('unauthorized') ||
      message.includes('forbidden') ||
      message.includes('401') ||
      message.includes('403')
    ) {
      return {
        type: 'permission',
        severity: 'medium',
        retryable: false
      };
    }

    // Processing errors
    if (
      message.includes('processing') ||
      message.includes('calculation') ||
      message.includes('diff') ||
      message.includes('comparison') ||
      stack.includes('diffengine') ||
      stack.includes('processor')
    ) {
      return {
        type: 'processing',
        severity: 'medium',
        retryable: true
      };
    }

    // Timeout errors
    if (
      message.includes('timeout') ||
      message.includes('timed out') ||
      error.name === 'TimeoutError'
    ) {
      return {
        type: 'timeout',
        severity: 'medium',
        retryable: true
      };
    }

    // Resource errors
    if (
      message.includes('memory') ||
      message.includes('resource') ||
      message.includes('limit') ||
      message.includes('quota') ||
      message.includes('size')
    ) {
      return {
        type: 'resource',
        severity: 'high',
        retryable: false
      };
    }

    // Default to unknown
    return {
      type: 'unknown',
      severity: 'medium',
      retryable: true
    };
  };

  // Generate user-friendly error messages
  const getUserMessage = (errorInfo: ErrorInfo): string => {
    const { type, severity, originalError } = errorInfo;

    const messages = {
      network: {
        low: 'Network connection issue. Please check your connection.',
        medium: 'Connection timeout. Please try again.',
        high: 'Network error occurred. Please check your internet connection.',
        critical: 'Severe network issue. Please contact support.'
      },
      validation: {
        low: 'Please check your input and try again.',
        medium: 'Invalid data format. Please correct and retry.',
        high: 'Data validation failed. Please review your input.',
        critical: 'Critical validation error. Please contact support.'
      },
      permission: {
        low: 'You may not have permission for this action.',
        medium: 'Access denied. Please check your permissions.',
        high: 'Unauthorized access. Please log in again.',
        critical: 'Permission denied. Please contact an administrator.'
      },
      processing: {
        low: 'Processing issue occurred. Please try again.',
        medium: 'Document processing failed. Please retry.',
        high: 'Comparison processing error. Please try with different files.',
        critical: 'Critical processing error. Please contact support.'
      },
      timeout: {
        low: 'Operation took longer than expected.',
        medium: 'Request timed out. Please try again.',
        high: 'Operation timeout. Please try with smaller files.',
        critical: 'Severe timeout issue. Please contact support.'
      },
      resource: {
        low: 'System resources temporarily unavailable.',
        medium: 'Resource limit reached. Please try with smaller files.',
        high: 'Insufficient resources. Please reduce file size.',
        critical: 'Critical resource error. Please contact support.'
      },
      unknown: {
        low: 'An unexpected issue occurred.',
        medium: 'Something went wrong. Please try again.',
        high: 'Unexpected error occurred. Please retry or contact support.',
        critical: 'Critical error. Please contact support immediately.'
      }
    };

    return messages[type][severity] || 'An error occurred. Please try again.';
  };

  // Handle error with classification and retry logic
  const handleError = useCallback((
    error: Error,
    context?: Record<string, any>,
    userAction?: string
  ): ErrorInfo => {
    const classification = classifyError(error);
    const errorId = `error-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    const errorInfo: ErrorInfo = {
      id: errorId,
      type: classification.type,
      severity: classification.severity,
      message: getUserMessage({
        id: errorId,
        type: classification.type,
        severity: classification.severity,
        originalError: error,
        timestamp: new Date(),
        retryCount: 0,
        maxRetries,
        retryable: classification.retryable,
        message: '', // Will be set by getUserMessage
        context,
        userAction
      }),
      originalError: error,
      timestamp: new Date(),
      context,
      retryCount: 0,
      maxRetries,
      retryable: classification.retryable,
      userAction
    };

    // Update error message with proper context
    errorInfo.message = getUserMessage(errorInfo);

    // Log error if enabled
    if (logErrors) {
      console.error('Error handled:', {
        id: errorInfo.id,
        type: errorInfo.type,
        severity: errorInfo.severity,
        message: error.message,
        stack: error.stack,
        context,
        userAction
      });
    }

    // Update state
    setState(prev => ({
      ...prev,
      errors: [...prev.errors, errorInfo],
      currentError: errorInfo
    }));

    // Call error callback
    onError?.(errorInfo);

    // Auto-retry if enabled and error is retryable
    if (enableAutoRetry && classification.retryable && errorInfo.retryCount < maxRetries) {
      scheduleRetry(errorInfo);
    }

    return errorInfo;
  }, [maxRetries, enableAutoRetry, logErrors, onError]);

  // Schedule automatic retry
  const scheduleRetry = useCallback((errorInfo: ErrorInfo) => {
    if (errorInfo.retryCount >= errorInfo.maxRetries) return;

    setState(prev => ({ ...prev, isRetrying: true, retryProgress: 0 }));

    // Calculate delay with exponential backoff
    const delay = retryDelay * Math.pow(2, errorInfo.retryCount);
    
    // Simulate progress
    const progressInterval = setInterval(() => {
      setState(prev => ({
        ...prev,
        retryProgress: Math.min(prev.retryProgress + 10, 90)
      }));
    }, delay / 10);

    const timeoutId = setTimeout(() => {
      clearInterval(progressInterval);
      setState(prev => ({ ...prev, isRetrying: false, retryProgress: 100 }));
      onRetry?.(errorInfo);
    }, delay);

    retryTimeouts.current.set(errorInfo.id, timeoutId);
  }, [retryDelay, onRetry]);

  // Manual retry
  const retryError = useCallback((errorId: string) => {
    const errorInfo = state.errors.find(e => e.id === errorId);
    if (!errorInfo || errorInfo.retryCount >= errorInfo.maxRetries) return false;

    const updatedError: ErrorInfo = {
      ...errorInfo,
      retryCount: errorInfo.retryCount + 1
    };

    setState(prev => ({
      ...prev,
      errors: prev.errors.map(e => e.id === errorId ? updatedError : e),
      currentError: prev.currentError?.id === errorId ? updatedError : prev.currentError
    }));

    scheduleRetry(updatedError);
    return true;
  }, [state.errors, scheduleRetry]);

  // Clear error
  const clearError = useCallback((errorId: string) => {
    // Clear retry timeout if exists
    const timeout = retryTimeouts.current.get(errorId);
    if (timeout) {
      clearTimeout(timeout);
      retryTimeouts.current.delete(errorId);
    }

    setState(prev => ({
      ...prev,
      errors: prev.errors.filter(e => e.id !== errorId),
      currentError: prev.currentError?.id === errorId ? null : prev.currentError,
      isRetrying: prev.currentError?.id === errorId ? false : prev.isRetrying
    }));
  }, []);

  // Clear all errors
  const clearAllErrors = useCallback(() => {
    // Clear all timeouts
    retryTimeouts.current.forEach(timeout => clearTimeout(timeout));
    retryTimeouts.current.clear();

    setState({
      errors: [],
      currentError: null,
      isRetrying: false,
      retryProgress: 0
    });
  }, []);

  // Mark error as recovered
  const markRecovered = useCallback((errorId: string) => {
    const errorInfo = state.errors.find(e => e.id === errorId);
    if (errorInfo) {
      onRecover?.(errorInfo);
      clearError(errorId);
    }
  }, [state.errors, onRecover, clearError]);

  // Get errors by type
  const getErrorsByType = useCallback((type: ErrorType) => {
    return state.errors.filter(e => e.type === type);
  }, [state.errors]);

  // Get errors by severity
  const getErrorsBySeverity = useCallback((severity: ErrorSeverity) => {
    return state.errors.filter(e => e.severity === severity);
  }, [state.errors]);

  // Check if error type has occurred recently
  const hasRecentError = useCallback((type: ErrorType, timeframe: number = 60000) => {
    const cutoff = Date.now() - timeframe;
    return state.errors.some(e => e.type === type && e.timestamp.getTime() > cutoff);
  }, [state.errors]);

  return {
    // State
    ...state,
    
    // Actions
    handleError,
    retryError,
    clearError,
    clearAllErrors,
    markRecovered,
    
    // Queries
    getErrorsByType,
    getErrorsBySeverity,
    hasRecentError,
    
    // Computed
    hasErrors: state.errors.length > 0,
    hasRetryableErrors: state.errors.some(e => e.retryable && e.retryCount < e.maxRetries),
    hasCriticalErrors: state.errors.some(e => e.severity === 'critical'),
    errorCount: state.errors.length
  };
};

export default useErrorHandler; 