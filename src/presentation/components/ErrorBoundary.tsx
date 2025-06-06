import React, { Component, ReactNode, ErrorInfo } from 'react';

export interface ErrorBoundaryProps {
  children: ReactNode;
  fallback?: ReactNode | ((error: Error, retry: () => void) => ReactNode);
  onError?: (error: Error, errorInfo: ErrorInfo) => void;
  enableRetry?: boolean;
  maxRetries?: number;
  retryDelay?: number;
  isolate?: boolean;
  level?: 'page' | 'section' | 'component';
  className?: string;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
  errorId: string | null;
  retryCount: number;
  isRetrying: boolean;
}

/**
 * Production-ready Error Boundary with retry mechanisms and error reporting
 */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  private retryTimeoutId: NodeJS.Timeout | null = null;

  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorId: null,
      retryCount: 0,
      isRetrying: false
    };
  }

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    // Generate unique error ID for tracking
    const errorId = `error-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    return {
      hasError: true,
      error,
      errorId,
      isRetrying: false
    };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    const { onError, level = 'component' } = this.props;

    // Enhance error with additional context
    const enhancedError = {
      ...error,
      level,
      errorId: this.state.errorId,
      componentStack: errorInfo.componentStack,
      timestamp: new Date().toISOString(),
      userAgent: typeof navigator !== 'undefined' ? navigator.userAgent : 'unknown',
      url: typeof window !== 'undefined' ? window.location.href : 'unknown'
    };

    // Report error to monitoring service
    this.reportError(enhancedError, errorInfo);

    // Call custom error handler
    onError?.(error, errorInfo);

    // Auto-retry if enabled and within limits
    if (this.props.enableRetry && this.state.retryCount < (this.props.maxRetries || 3)) {
      this.scheduleRetry();
    }
  }

  componentWillUnmount() {
    if (this.retryTimeoutId) {
      clearTimeout(this.retryTimeoutId);
    }
  }

  private reportError = (error: any, errorInfo: ErrorInfo) => {
    // In production, send to error monitoring service
    if (process.env.NODE_ENV === 'production') {
      // Example: Sentry, LogRocket, or custom error service
      console.error('Error Boundary caught an error:', {
        error: error.message,
        stack: error.stack,
        componentStack: errorInfo.componentStack,
        errorId: this.state.errorId,
        level: this.props.level,
        timestamp: new Date().toISOString()
      });
    } else {
      console.error('Error Boundary caught an error:', error, errorInfo);
    }
  };

  private scheduleRetry = () => {
    const delay = this.props.retryDelay || 1000;
    
    this.setState({ isRetrying: true });
    
    this.retryTimeoutId = setTimeout(() => {
      this.handleRetry();
    }, delay);
  };

  private handleRetry = () => {
    if (this.retryTimeoutId) {
      clearTimeout(this.retryTimeoutId);
      this.retryTimeoutId = null;
    }

    this.setState(prevState => ({
      hasError: false,
      error: null,
      errorId: null,
      retryCount: prevState.retryCount + 1,
      isRetrying: false
    }));
  };

  private handleManualRetry = () => {
    if (this.state.retryCount < (this.props.maxRetries || 3)) {
      this.handleRetry();
    }
  };

  private renderErrorFallback = () => {
    const { fallback, level = 'component', enableRetry = true, maxRetries = 3 } = this.props;
    const { error, retryCount, isRetrying } = this.state;

    if (fallback) {
      if (typeof fallback === 'function') {
        return fallback(error!, this.handleManualRetry);
      }
      return fallback;
    }

    const canRetry = enableRetry && retryCount < maxRetries;

    return (
      <div className={`error-boundary error-boundary--${level} ${this.props.className || ''}`}>
        <div className="error-boundary__content">
          <div className="error-boundary__icon">
            {level === 'page' ? '🚫' : level === 'section' ? '⚠️' : '❌'}
          </div>
          
          <div className="error-boundary__message">
            <h3 className="error-boundary__title">
              {level === 'page' ? 'Page Error' : level === 'section' ? 'Section Error' : 'Component Error'}
            </h3>
            
            <p className="error-boundary__description">
              {this.getErrorMessage(error, level)}
            </p>

            {process.env.NODE_ENV === 'development' && (
              <details className="error-boundary__details">
                <summary>Error Details</summary>
                <pre className="error-boundary__stack">
                  {error?.stack}
                </pre>
              </details>
            )}
          </div>

          <div className="error-boundary__actions">
            {canRetry && (
              <button
                className="error-boundary__retry-btn"
                onClick={this.handleManualRetry}
                disabled={isRetrying}
              >
                {isRetrying ? 'Retrying...' : `Retry ${retryCount > 0 ? `(${retryCount}/${maxRetries})` : ''}`}
              </button>
            )}

            <button
              className="error-boundary__reload-btn"
              onClick={() => window.location.reload()}
            >
              Reload Page
            </button>
          </div>

          {retryCount > 0 && (
            <div className="error-boundary__retry-info">
              Retry attempts: {retryCount}/{maxRetries}
            </div>
          )}
        </div>

        <style jsx>{`
          .error-boundary {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem;
            text-align: center;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            color: #24292f;
            background-color: #f8f9fa;
            border: 1px solid #e1e4e8;
            border-radius: 8px;
          }

          .error-boundary--page {
            min-height: 50vh;
            background-color: #fff5f5;
            border-color: #feb2b2;
          }

          .error-boundary--section {
            min-height: 200px;
            background-color: #fffbeb;
            border-color: #fed7aa;
          }

          .error-boundary--component {
            min-height: 100px;
            background-color: #f0f9ff;
            border-color: #bae6fd;
          }

          .error-boundary__content {
            max-width: 500px;
            width: 100%;
          }

          .error-boundary__icon {
            font-size: 3rem;
            margin-bottom: 1rem;
          }

          .error-boundary__title {
            font-size: 1.5rem;
            font-weight: 600;
            margin: 0 0 0.5rem 0;
            color: #991b1b;
          }

          .error-boundary--section .error-boundary__title {
            color: #92400e;
          }

          .error-boundary--component .error-boundary__title {
            color: #1e40af;
          }

          .error-boundary__description {
            margin: 0 0 1.5rem 0;
            color: #6b7280;
            line-height: 1.6;
          }

          .error-boundary__details {
            margin: 1rem 0;
            text-align: left;
          }

          .error-boundary__stack {
            background-color: #f3f4f6;
            border: 1px solid #d1d5db;
            border-radius: 4px;
            padding: 1rem;
            font-size: 0.875rem;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-word;
          }

          .error-boundary__actions {
            display: flex;
            gap: 0.75rem;
            justify-content: center;
            flex-wrap: wrap;
          }

          .error-boundary__retry-btn,
          .error-boundary__reload-btn {
            padding: 0.5rem 1rem;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.875rem;
            font-weight: 500;
            transition: all 0.15s ease;
          }

          .error-boundary__retry-btn {
            background-color: #3b82f6;
            color: white;
          }

          .error-boundary__retry-btn:hover:not(:disabled) {
            background-color: #2563eb;
          }

          .error-boundary__retry-btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
          }

          .error-boundary__reload-btn {
            background-color: #6b7280;
            color: white;
          }

          .error-boundary__reload-btn:hover {
            background-color: #4b5563;
          }

          .error-boundary__retry-info {
            margin-top: 1rem;
            font-size: 0.75rem;
            color: #9ca3af;
          }
        `}</style>
      </div>
    );
  };

  private getErrorMessage = (error: Error | null, level: string): string => {
    if (!error) return 'An unknown error occurred';

    // Categorize errors and provide user-friendly messages
    const errorMessages = {
      page: {
        default: 'The page encountered an unexpected error. Please try refreshing or contact support if the problem persists.',
        network: 'Network connection failed. Please check your internet connection and try again.',
        permission: 'You don\'t have permission to access this resource.',
        notFound: 'The requested resource was not found.'
      },
      section: {
        default: 'This section encountered an error. You can try refreshing or continue using other parts of the application.',
        processing: 'Failed to process your request. Please try again.',
        validation: 'Invalid data provided. Please check your input and try again.'
      },
      component: {
        default: 'This component failed to load. You can try refreshing the page.',
        render: 'Failed to display content. Please try again.',
        interaction: 'Action failed. Please try again.'
      }
    };

    const levelMessages = errorMessages[level as keyof typeof errorMessages] || errorMessages.component;

    // Match error types with proper type checking
    if (error.message.includes('Network') || error.message.includes('fetch')) {
      return (levelMessages as any).network || levelMessages.default;
    }
    if (error.message.includes('permission') || error.message.includes('authorized')) {
      return (levelMessages as any).permission || levelMessages.default;
    }
    if (error.message.includes('not found') || error.message.includes('404')) {
      return (levelMessages as any).notFound || levelMessages.default;
    }
    if (error.message.includes('validation') || error.message.includes('invalid')) {
      return (levelMessages as any).validation || levelMessages.default;
    }

    return levelMessages.default;
  };

  render() {
    if (this.state.hasError) {
      return this.renderErrorFallback();
    }

    return this.props.children;
  }
}

export default ErrorBoundary; 