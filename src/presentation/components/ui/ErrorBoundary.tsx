import React, { Component, ErrorInfo, ReactNode } from 'react';

export interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
  errorId: string;
  retryCount: number;
}

export interface ErrorBoundaryProps {
  /** Fallback component to render when error occurs */
  fallback?: React.ComponentType<ErrorFallbackProps>;
  /** Callback when error occurs */
  onError?: (error: Error, errorInfo: ErrorInfo, errorId: string) => void;
  /** Maximum number of retry attempts */
  maxRetries?: number;
  /** Enable error reporting to external service */
  enableReporting?: boolean;
  /** Custom error message */
  errorMessage?: string;
  /** Show retry button */
  showRetry?: boolean;
  /** Show error details in development */
  showDetails?: boolean;
  /** Custom CSS class */
  className?: string;
  children: ReactNode;
}

export interface ErrorFallbackProps {
  error: Error | null;
  errorInfo: ErrorInfo | null;
  errorId: string;
  retryCount: number;
  onRetry: () => void;
  onReport: () => void;
  canRetry: boolean;
  maxRetries: number;
  customMessage?: string;
  showDetails: boolean;
}

export interface LoadingStateProps {
  /** Loading state variant */
  variant?: 'spinner' | 'skeleton' | 'pulse' | 'dots' | 'bar' | 'circular';
  /** Loading size */
  size?: 'sm' | 'md' | 'lg' | 'xl';
  /** Loading message */
  message?: string;
  /** Show progress percentage */
  progress?: number;
  /** Custom color */
  color?: string;
  /** Full screen overlay */
  overlay?: boolean;
  /** Custom CSS class */
  className?: string;
}

export interface ErrorDisplayProps {
  /** Error type */
  type?: 'error' | 'warning' | 'info' | 'success';
  /** Error title */
  title: string;
  /** Error description */
  description?: string;
  /** Show retry action */
  showRetry?: boolean;
  /** Show report action */
  showReport?: boolean;
  /** Show details toggle */
  showDetails?: boolean;
  /** Error details */
  details?: string;
  /** Custom icon */
  icon?: ReactNode;
  /** Action buttons */
  actions?: Array<{
    label: string;
    onClick: () => void;
    variant?: 'primary' | 'secondary' | 'danger';
  }>;
  /** Custom CSS class */
  className?: string;
}

/**
 * Default Error Fallback Component
 */
const DefaultErrorFallback: React.FC<ErrorFallbackProps> = ({
  error,
  errorInfo,
  errorId,
  retryCount,
  onRetry,
  onReport,
  canRetry,
  maxRetries,
  customMessage,
  showDetails,
}) => {
  const [showDetailsToggle, setShowDetailsToggle] = React.useState(false);
  const isDevelopment = process.env.NODE_ENV === 'development';

  return (
    <div className="error-fallback">
      <div className="error-content">
        <div className="error-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
            <circle cx="12" cy="12" r="10" />
            <line x1="12" y1="8" x2="12" y2="12" />
            <line x1="12" y1="16" x2="12.01" y2="16" />
          </svg>
        </div>
        
        <h2 className="error-title">Something went wrong</h2>
        
        <p className="error-description">
          {customMessage || 'An unexpected error occurred. Please try again.'}
        </p>

        {retryCount > 0 && (
          <p className="retry-info">
            Retry attempt {retryCount} of {maxRetries}
          </p>
        )}

        <div className="error-actions">
          {canRetry && (
            <button
              className="btn btn-primary"
              onClick={onRetry}
            >
              Try Again
            </button>
          )}
          
          <button
            className="btn btn-secondary"
            onClick={onReport}
          >
            Report Issue
          </button>

          {(showDetails || isDevelopment) && (
            <button
              className="btn btn-ghost"
              onClick={() => setShowDetailsToggle(!showDetailsToggle)}
            >
              {showDetailsToggle ? 'Hide' : 'Show'} Details
            </button>
          )}
        </div>

        {showDetailsToggle && (showDetails || isDevelopment) && (
          <div className="error-details">
            <div className="error-details-section">
              <h4>Error ID</h4>
              <code>{errorId}</code>
            </div>
            
            {error && (
              <div className="error-details-section">
                <h4>Error Message</h4>
                <code>{error.message}</code>
              </div>
            )}
            
            {error?.stack && isDevelopment && (
              <div className="error-details-section">
                <h4>Stack Trace</h4>
                <pre>{error.stack}</pre>
              </div>
            )}
            
            {errorInfo?.componentStack && isDevelopment && (
              <div className="error-details-section">
                <h4>Component Stack</h4>
                <pre>{errorInfo.componentStack}</pre>
              </div>
            )}
          </div>
        )}
      </div>

      <style jsx>{`
        .error-fallback {
          display: flex;
          align-items: center;
          justify-content: center;
          min-height: 300px;
          padding: 2rem;
          background-color: #fafafa;
          border: 1px solid #e5e7eb;
          border-radius: 8px;
        }

        .error-content {
          text-align: center;
          max-width: 500px;
        }

        .error-icon {
          width: 64px;
          height: 64px;
          margin: 0 auto 1.5rem;
          color: #ef4444;
        }

        .error-icon svg {
          width: 100%;
          height: 100%;
        }

        .error-title {
          font-size: 1.5rem;
          font-weight: 600;
          color: #111827;
          margin: 0 0 0.5rem;
        }

        .error-description {
          color: #6b7280;
          margin: 0 0 1rem;
          line-height: 1.5;
        }

        .retry-info {
          font-size: 0.875rem;
          color: #9ca3af;
          margin: 0 0 1.5rem;
        }

        .error-actions {
          display: flex;
          gap: 0.75rem;
          justify-content: center;
          flex-wrap: wrap;
          margin-bottom: 1.5rem;
        }

        .error-details {
          text-align: left;
          background-color: #f9fafb;
          border: 1px solid #e5e7eb;
          border-radius: 6px;
          padding: 1rem;
          margin-top: 1rem;
        }

        .error-details-section {
          margin-bottom: 1rem;
        }

        .error-details-section:last-child {
          margin-bottom: 0;
        }

        .error-details h4 {
          font-size: 0.875rem;
          font-weight: 600;
          color: #374151;
          margin: 0 0 0.5rem;
        }

        .error-details code {
          display: block;
          background-color: #f3f4f6;
          border: 1px solid #e5e7eb;
          border-radius: 4px;
          padding: 0.5rem;
          font-family: 'SFMono-Regular', Consolas, monospace;
          font-size: 0.75rem;
          color: #1f2937;
          word-break: break-all;
        }

        .error-details pre {
          background-color: #f3f4f6;
          border: 1px solid #e5e7eb;
          border-radius: 4px;
          padding: 0.5rem;
          font-family: 'SFMono-Regular', Consolas, monospace;
          font-size: 0.75rem;
          color: #1f2937;
          overflow-x: auto;
          white-space: pre-wrap;
          word-break: break-word;
        }

        /* Dark theme */
        :global(.dark) .error-fallback {
          background-color: #1f2937;
          border-color: #374151;
        }

        :global(.dark) .error-title {
          color: #f9fafb;
        }

        :global(.dark) .error-description {
          color: #d1d5db;
        }

        :global(.dark) .retry-info {
          color: #9ca3af;
        }

        :global(.dark) .error-details {
          background-color: #111827;
          border-color: #374151;
        }

        :global(.dark) .error-details h4 {
          color: #e5e7eb;
        }

        :global(.dark) .error-details code,
        :global(.dark) .error-details pre {
          background-color: #1f2937;
          border-color: #374151;
          color: #e5e7eb;
        }
      `}</style>
    </div>
  );
};

/**
 * Loading State Component
 */
export const LoadingState: React.FC<LoadingStateProps> = ({
  variant = 'spinner',
  size = 'md',
  message,
  progress,
  color = '#3b82f6',
  overlay = false,
  className = '',
}) => {
  const sizeClasses = {
    sm: 'w-4 h-4',
    md: 'w-8 h-8',
    lg: 'w-12 h-12',
    xl: 'w-16 h-16',
  };

  const renderSpinner = () => (
    <div className={`loading-spinner ${sizeClasses[size]}`} style={{ borderTopColor: color }}>
      <div className="sr-only">Loading...</div>
    </div>
  );

  const renderDots = () => (
    <div className="loading-dots">
      <div className="loading-dot" style={{ backgroundColor: color }} />
      <div className="loading-dot" style={{ backgroundColor: color }} />
      <div className="loading-dot" style={{ backgroundColor: color }} />
    </div>
  );

  const renderBar = () => (
    <div className="loading-bar">
      <div className="loading-bar-fill" style={{ backgroundColor: color }} />
    </div>
  );

  const renderCircular = () => (
    <div className={`loading-circular ${sizeClasses[size]}`}>
      <svg viewBox="0 0 50 50" className="loading-circular-svg">
        <circle
          className="loading-circular-path"
          cx="25"
          cy="25"
          r="20"
          fill="none"
          stroke={color}
          strokeWidth="4"
          strokeLinecap="round"
          strokeDasharray="31.416"
          strokeDashoffset="31.416"
        />
      </svg>
    </div>
  );

  const renderPulse = () => (
    <div className={`loading-pulse ${sizeClasses[size]}`} style={{ backgroundColor: color }} />
  );

  const renderSkeleton = () => (
    <div className="loading-skeleton">
      <div className="skeleton-line skeleton-line-long" />
      <div className="skeleton-line skeleton-line-medium" />
      <div className="skeleton-line skeleton-line-short" />
    </div>
  );

  const renderLoader = () => {
    switch (variant) {
      case 'dots':
        return renderDots();
      case 'bar':
        return renderBar();
      case 'circular':
        return renderCircular();
      case 'pulse':
        return renderPulse();
      case 'skeleton':
        return renderSkeleton();
      default:
        return renderSpinner();
    }
  };

  const content = (
    <div className={`loading-state ${overlay ? 'loading-overlay' : ''} ${className}`}>
      <div className="loading-content">
        {renderLoader()}
        {message && <p className="loading-message">{message}</p>}
        {progress !== undefined && (
          <div className="loading-progress">
            <div className="loading-progress-bar">
              <div
                className="loading-progress-fill"
                style={{ width: `${progress}%`, backgroundColor: color }}
              />
            </div>
            <span className="loading-progress-text">{Math.round(progress)}%</span>
          </div>
        )}
      </div>

      <style jsx>{`
        .loading-state {
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 1rem;
        }

        .loading-overlay {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background-color: rgba(255, 255, 255, 0.9);
          z-index: 1000;
        }

        .loading-content {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 1rem;
        }

        .loading-spinner {
          border: 2px solid #e5e7eb;
          border-radius: 50%;
          border-top: 2px solid;
          animation: spin 1s linear infinite;
        }

        .loading-dots {
          display: flex;
          gap: 0.25rem;
        }

        .loading-dot {
          width: 0.5rem;
          height: 0.5rem;
          border-radius: 50%;
          animation: bounce 1.4s ease-in-out infinite both;
        }

        .loading-dot:nth-child(1) { animation-delay: -0.32s; }
        .loading-dot:nth-child(2) { animation-delay: -0.16s; }

        .loading-bar {
          width: 200px;
          height: 4px;
          background-color: #e5e7eb;
          border-radius: 2px;
          overflow: hidden;
        }

        .loading-bar-fill {
          height: 100%;
          width: 30%;
          border-radius: 2px;
          animation: loading-bar 2s ease-in-out infinite;
        }

        .loading-circular {
          animation: rotate 2s linear infinite;
        }

        .loading-circular-svg {
          width: 100%;
          height: 100%;
        }

        .loading-circular-path {
          animation: dash 1.5s ease-in-out infinite;
        }

        .loading-pulse {
          border-radius: 50%;
          animation: pulse 2s ease-in-out infinite;
        }

        .loading-skeleton {
          width: 100%;
          max-width: 300px;
        }

        .skeleton-line {
          height: 12px;
          background-color: #e5e7eb;
          border-radius: 6px;
          margin-bottom: 8px;
          animation: skeleton 1.5s ease-in-out infinite;
        }

        .skeleton-line-long { width: 100%; }
        .skeleton-line-medium { width: 75%; }
        .skeleton-line-short { width: 50%; }

        .loading-message {
          font-size: 0.875rem;
          color: #6b7280;
          margin: 0;
          text-align: center;
        }

        .loading-progress {
          display: flex;
          align-items: center;
          gap: 0.75rem;
          width: 100%;
          max-width: 200px;
        }

        .loading-progress-bar {
          flex: 1;
          height: 6px;
          background-color: #e5e7eb;
          border-radius: 3px;
          overflow: hidden;
        }

        .loading-progress-fill {
          height: 100%;
          border-radius: 3px;
          transition: width 0.3s ease;
        }

        .loading-progress-text {
          font-size: 0.75rem;
          color: #6b7280;
          min-width: 3rem;
          text-align: right;
        }

        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }

        @keyframes bounce {
          0%, 80%, 100% {
            transform: scale(0);
          }
          40% {
            transform: scale(1);
          }
        }

        @keyframes loading-bar {
          0% { transform: translateX(-100%); }
          50% { transform: translateX(0); }
          100% { transform: translateX(250%); }
        }

        @keyframes rotate {
          100% { transform: rotate(360deg); }
        }

        @keyframes dash {
          0% {
            stroke-dasharray: 1, 150;
            stroke-dashoffset: 0;
          }
          50% {
            stroke-dasharray: 90, 150;
            stroke-dashoffset: -35;
          }
          100% {
            stroke-dasharray: 90, 150;
            stroke-dashoffset: -124;
          }
        }

        @keyframes pulse {
          0% { transform: scale(1); opacity: 1; }
          50% { transform: scale(1.1); opacity: 0.7; }
          100% { transform: scale(1); opacity: 1; }
        }

        @keyframes skeleton {
          0% { opacity: 1; }
          50% { opacity: 0.4; }
          100% { opacity: 1; }
        }

        /* Dark theme */
        :global(.dark) .loading-overlay {
          background-color: rgba(0, 0, 0, 0.8);
        }

        :global(.dark) .loading-spinner {
          border-color: #374151;
        }

        :global(.dark) .loading-bar {
          background-color: #374151;
        }

        :global(.dark) .skeleton-line {
          background-color: #374151;
        }

        :global(.dark) .loading-message {
          color: #d1d5db;
        }

        :global(.dark) .loading-progress-bar {
          background-color: #374151;
        }

        :global(.dark) .loading-progress-text {
          color: #d1d5db;
        }
      `}</style>
    </div>
  );

  return overlay ? content : <div className="loading-wrapper">{content}</div>;
};

/**
 * Error Display Component
 */
export const ErrorDisplay: React.FC<ErrorDisplayProps> = ({
  type = 'error',
  title,
  description,
  showRetry = true,
  showReport = false,
  showDetails = false,
  details,
  icon,
  actions = [],
  className = '',
}) => {
  const [showDetailsToggle, setShowDetailsToggle] = React.useState(false);

  const typeIcons = {
    error: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
        <circle cx="12" cy="12" r="10" />
        <line x1="15" y1="9" x2="9" y2="15" />
        <line x1="9" y1="9" x2="15" y2="15" />
      </svg>
    ),
    warning: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
        <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
        <line x1="12" y1="9" x2="12" y2="13" />
        <line x1="12" y1="17" x2="12.01" y2="17" />
      </svg>
    ),
    info: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
        <circle cx="12" cy="12" r="10" />
        <line x1="12" y1="16" x2="12" y2="12" />
        <line x1="12" y1="8" x2="12.01" y2="8" />
      </svg>
    ),
    success: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
        <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
        <polyline points="22,4 12,14.01 9,11.01" />
      </svg>
    ),
  };

  const typeClasses = {
    error: 'error-display-error',
    warning: 'error-display-warning',
    info: 'error-display-info',
    success: 'error-display-success',
  };

  return (
    <div className={`error-display ${typeClasses[type]} ${className}`}>
      <div className="error-display-icon">
        {icon || typeIcons[type]}
      </div>
      
      <div className="error-display-content">
        <h3 className="error-display-title">{title}</h3>
        {description && (
          <p className="error-display-description">{description}</p>
        )}
        
        <div className="error-display-actions">
          {showRetry && (
            <button className="btn btn-primary btn-sm">
              Try Again
            </button>
          )}
          {showReport && (
            <button className="btn btn-secondary btn-sm">
              Report Issue
            </button>
          )}
          {showDetails && details && (
            <button
              className="btn btn-ghost btn-sm"
              onClick={() => setShowDetailsToggle(!showDetailsToggle)}
            >
              {showDetailsToggle ? 'Hide' : 'Show'} Details
            </button>
          )}
          {actions.map((action, index) => (
            <button
              key={index}
              className={`btn btn-${action.variant || 'secondary'} btn-sm`}
              onClick={action.onClick}
            >
              {action.label}
            </button>
          ))}
        </div>

        {showDetailsToggle && details && (
          <div className="error-display-details">
            <pre>{details}</pre>
          </div>
        )}
      </div>

      <style jsx>{`
        .error-display {
          display: flex;
          gap: 1rem;
          padding: 1rem;
          border-radius: 6px;
          border: 1px solid;
        }

        .error-display-error {
          background-color: #fef2f2;
          border-color: #fecaca;
          color: #991b1b;
        }

        .error-display-warning {
          background-color: #fffbeb;
          border-color: #fde68a;
          color: #92400e;
        }

        .error-display-info {
          background-color: #eff6ff;
          border-color: #bfdbfe;
          color: #1e40af;
        }

        .error-display-success {
          background-color: #f0fdf4;
          border-color: #bbf7d0;
          color: #166534;
        }

        .error-display-icon {
          width: 20px;
          height: 20px;
          flex-shrink: 0;
          margin-top: 0.125rem;
        }

        .error-display-icon svg {
          width: 100%;
          height: 100%;
        }

        .error-display-content {
          flex: 1;
        }

        .error-display-title {
          font-size: 0.875rem;
          font-weight: 600;
          margin: 0 0 0.25rem;
        }

        .error-display-description {
          font-size: 0.75rem;
          margin: 0 0 0.75rem;
          opacity: 0.8;
        }

        .error-display-actions {
          display: flex;
          gap: 0.5rem;
          flex-wrap: wrap;
        }

        .error-display-details {
          margin-top: 0.75rem;
          padding: 0.5rem;
          background-color: rgba(0, 0, 0, 0.05);
          border-radius: 4px;
        }

        .error-display-details pre {
          margin: 0;
          font-family: 'SFMono-Regular', Consolas, monospace;
          font-size: 0.75rem;
          white-space: pre-wrap;
          word-break: break-word;
        }

        /* Dark theme */
        :global(.dark) .error-display-error {
          background-color: #7f1d1d;
          border-color: #991b1b;
          color: #fecaca;
        }

        :global(.dark) .error-display-warning {
          background-color: #78350f;
          border-color: #92400e;
          color: #fde68a;
        }

        :global(.dark) .error-display-info {
          background-color: #1e3a8a;
          border-color: #1e40af;
          color: #bfdbfe;
        }

        :global(.dark) .error-display-success {
          background-color: #14532d;
          border-color: #166534;
          color: #bbf7d0;
        }

        :global(.dark) .error-display-details {
          background-color: rgba(255, 255, 255, 0.1);
        }
      `}</style>
    </div>
  );
};

/**
 * Error Boundary Class Component
 */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  private retryTimeoutId: number | null = null;

  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
      errorId: '',
      retryCount: 0,
    };
  }

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    const errorId = `error_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    return {
      hasError: true,
      error,
      errorId,
    };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    const { onError, enableReporting } = this.props;
    const { errorId } = this.state;

    this.setState({ errorInfo });

    // Call error callback
    if (onError) {
      onError(error, errorInfo, errorId);
    }

    // Report error to external service
    if (enableReporting) {
      this.reportError(error, errorInfo, errorId);
    }

    // Log error in development
    if (process.env.NODE_ENV === 'development') {
      console.group('🚨 Error Boundary Caught Error');
      console.error('Error:', error);
      console.error('Error Info:', errorInfo);
      console.error('Error ID:', errorId);
      console.groupEnd();
    }
  }

  private reportError = async (error: Error, errorInfo: ErrorInfo, errorId: string) => {
    try {
      // In a real implementation, you would send this to your error reporting service
      // Example: Sentry, Bugsnag, LogRocket, etc.
      const errorReport = {
        errorId,
        message: error.message,
        stack: error.stack,
        componentStack: errorInfo.componentStack,
        timestamp: new Date().toISOString(),
        userAgent: navigator.userAgent,
        url: window.location.href,
      };

      console.log('Error report:', errorReport);
      // await errorReportingService.report(errorReport);
    } catch (reportingError) {
      console.error('Failed to report error:', reportingError);
    }
  };

  private handleRetry = () => {
    const { maxRetries = 3 } = this.props;
    const { retryCount } = this.state;

    if (retryCount < maxRetries) {
      this.setState(prevState => ({
        hasError: false,
        error: null,
        errorInfo: null,
        errorId: '',
        retryCount: prevState.retryCount + 1,
      }));
    }
  };

  private handleReport = () => {
    const { error, errorInfo, errorId } = this.state;
    if (error && errorInfo) {
      this.reportError(error, errorInfo, errorId);
    }
  };

  componentWillUnmount() {
    if (this.retryTimeoutId) {
      clearTimeout(this.retryTimeoutId);
    }
  }

  render() {
    const { hasError, error, errorInfo, errorId, retryCount } = this.state;
    const {
      children,
      fallback: FallbackComponent = DefaultErrorFallback,
      maxRetries = 3,
      errorMessage,
      showRetry = true,
      showDetails = false,
      className = '',
    } = this.props;

    if (hasError) {
      const canRetry = showRetry && retryCount < maxRetries;

      return (
        <div className={`error-boundary ${className}`}>
          <FallbackComponent
            error={error}
            errorInfo={errorInfo}
            errorId={errorId}
            retryCount={retryCount}
            onRetry={this.handleRetry}
            onReport={this.handleReport}
            canRetry={canRetry}
            maxRetries={maxRetries}
            customMessage={errorMessage}
            showDetails={showDetails}
          />
        </div>
      );
    }

    return children;
  }
}

export default ErrorBoundary; 