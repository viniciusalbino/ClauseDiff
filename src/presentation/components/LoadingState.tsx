import React from 'react';

export interface LoadingStateProps {
  variant?: 'spinner' | 'progress' | 'skeleton' | 'pulse' | 'dots';
  size?: 'small' | 'medium' | 'large';
  text?: string;
  subtext?: string;
  progress?: number;
  showProgress?: boolean;
  showCancel?: boolean;
  onCancel?: () => void;
  theme?: 'light' | 'dark';
  className?: string;
  fullHeight?: boolean;
  inline?: boolean;
}

/**
 * Enhanced loading state component with multiple variants and progress tracking
 */
export const LoadingState: React.FC<LoadingStateProps> = ({
  variant = 'spinner',
  size = 'medium',
  text = 'Loading...',
  subtext,
  progress = 0,
  showProgress = false,
  showCancel = false,
  onCancel,
  theme = 'light',
  className = '',
  fullHeight = false,
  inline = false
}) => {
  const renderSpinner = () => (
    <div className={`loading-spinner loading-spinner--${size}`}>
      <div className="spinner-circle"></div>
    </div>
  );

  const renderProgress = () => (
    <div className={`loading-progress loading-progress--${size}`}>
      <div className="progress-circle">
        <svg viewBox="0 0 36 36" className="progress-svg">
          <path
            className="progress-bg"
            d="m18,2.0845 a 15.9155,15.9155 0 0,1 0,31.831 a 15.9155,15.9155 0 0,1 0,-31.831"
          />
          <path
            className="progress-bar"
            d="m18,2.0845 a 15.9155,15.9155 0 0,1 0,31.831 a 15.9155,15.9155 0 0,1 0,-31.831"
            style={{
              strokeDasharray: `${progress}, 100`
            }}
          />
        </svg>
        <div className="progress-text">{Math.round(progress)}%</div>
      </div>
    </div>
  );

  const renderSkeleton = () => (
    <div className={`loading-skeleton loading-skeleton--${size}`}>
      <div className="skeleton-lines">
        <div className="skeleton-line skeleton-line--title"></div>
        <div className="skeleton-line skeleton-line--content"></div>
        <div className="skeleton-line skeleton-line--content short"></div>
        <div className="skeleton-line skeleton-line--content"></div>
      </div>
    </div>
  );

  const renderPulse = () => (
    <div className={`loading-pulse loading-pulse--${size}`}>
      <div className="pulse-dot"></div>
      <div className="pulse-dot"></div>
      <div className="pulse-dot"></div>
    </div>
  );

  const renderDots = () => (
    <div className={`loading-dots loading-dots--${size}`}>
      <div className="dot"></div>
      <div className="dot"></div>
      <div className="dot"></div>
    </div>
  );

  const renderLoader = () => {
    switch (variant) {
      case 'progress':
        return renderProgress();
      case 'skeleton':
        return renderSkeleton();
      case 'pulse':
        return renderPulse();
      case 'dots':
        return renderDots();
      case 'spinner':
      default:
        return renderSpinner();
    }
  };

  return (
    <div 
      className={`
        loading-state 
        loading-state--${theme} 
        loading-state--${size}
        ${fullHeight ? 'loading-state--full-height' : ''} 
        ${inline ? 'loading-state--inline' : ''} 
        ${className}
      `}
    >
      <div className="loading-content">
        {renderLoader()}
        
        {text && (
          <div className="loading-text">
            <div className="loading-main-text">{text}</div>
            {subtext && <div className="loading-subtext">{subtext}</div>}
          </div>
        )}

        {showProgress && variant !== 'progress' && (
          <div className="loading-progress-bar">
            <div className="progress-track">
              <div 
                className="progress-fill"
                style={{ width: `${progress}%` }}
              />
            </div>
            <div className="progress-percentage">{Math.round(progress)}%</div>
          </div>
        )}

        {showCancel && onCancel && (
          <button className="loading-cancel-btn" onClick={onCancel}>
            Cancel
          </button>
        )}
      </div>

      <style jsx>{`
        .loading-state {
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 2rem;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        }

        .loading-state--light {
          background-color: #ffffff;
          color: #24292f;
        }

        .loading-state--dark {
          background-color: #0d1117;
          color: #f0f6fc;
        }

        .loading-state--full-height {
          min-height: 200px;
        }

        .loading-state--inline {
          padding: 0.5rem;
          display: inline-flex;
        }

        .loading-content {
          display: flex;
          flex-direction: column;
          align-items: center;
          text-align: center;
          max-width: 300px;
        }

        /* Spinner Styles */
        .loading-spinner {
          margin-bottom: 1rem;
        }

        .loading-spinner--small .spinner-circle {
          width: 20px;
          height: 20px;
        }

        .loading-spinner--medium .spinner-circle {
          width: 32px;
          height: 32px;
        }

        .loading-spinner--large .spinner-circle {
          width: 48px;
          height: 48px;
        }

        .spinner-circle {
          border: 3px solid #e1e4e8;
          border-top: 3px solid #0969da;
          border-radius: 50%;
          animation: spin 1s linear infinite;
        }

        .loading-state--dark .spinner-circle {
          border-color: #30363d;
          border-top-color: #58a6ff;
        }

        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }

        /* Progress Circle Styles */
        .loading-progress {
          margin-bottom: 1rem;
        }

        .loading-progress--small .progress-svg {
          width: 40px;
          height: 40px;
        }

        .loading-progress--medium .progress-svg {
          width: 64px;
          height: 64px;
        }

        .loading-progress--large .progress-svg {
          width: 96px;
          height: 96px;
        }

        .progress-circle {
          position: relative;
          display: inline-block;
        }

        .progress-svg {
          transform: rotate(-90deg);
        }

        .progress-bg {
          fill: none;
          stroke: #e1e4e8;
          stroke-width: 2;
        }

        .loading-state--dark .progress-bg {
          stroke: #30363d;
        }

        .progress-bar {
          fill: none;
          stroke: #0969da;
          stroke-width: 2;
          stroke-linecap: round;
          transition: stroke-dasharray 0.3s ease;
        }

        .loading-state--dark .progress-bar {
          stroke: #58a6ff;
        }

        .progress-text {
          position: absolute;
          top: 50%;
          left: 50%;
          transform: translate(-50%, -50%);
          font-size: 0.75rem;
          font-weight: 600;
        }

        /* Skeleton Styles */
        .loading-skeleton {
          margin-bottom: 1rem;
        }

        .loading-skeleton--small {
          width: 150px;
        }

        .loading-skeleton--medium {
          width: 250px;
        }

        .loading-skeleton--large {
          width: 350px;
        }

        .skeleton-lines {
          display: flex;
          flex-direction: column;
          gap: 0.5rem;
        }

        .skeleton-line {
          height: 1rem;
          background: linear-gradient(
            90deg,
            #f0f0f0 25%,
            #e0e0e0 50%,
            #f0f0f0 75%
          );
          background-size: 200% 100%;
          animation: shimmer 2s infinite;
          border-radius: 4px;
        }

        .loading-state--dark .skeleton-line {
          background: linear-gradient(
            90deg,
            #30363d 25%,
            #21262d 50%,
            #30363d 75%
          );
          background-size: 200% 100%;
        }

        .skeleton-line--title {
          height: 1.5rem;
          width: 60%;
        }

        .skeleton-line--content {
          height: 1rem;
          width: 100%;
        }

        .skeleton-line--content.short {
          width: 75%;
        }

        @keyframes shimmer {
          0% { background-position: -200% 0; }
          100% { background-position: 200% 0; }
        }

        /* Pulse Styles */
        .loading-pulse {
          display: flex;
          gap: 0.5rem;
          margin-bottom: 1rem;
        }

        .pulse-dot {
          background-color: #0969da;
          border-radius: 50%;
          animation: pulse 1.5s ease-in-out infinite;
        }

        .loading-state--dark .pulse-dot {
          background-color: #58a6ff;
        }

        .loading-pulse--small .pulse-dot {
          width: 8px;
          height: 8px;
        }

        .loading-pulse--medium .pulse-dot {
          width: 12px;
          height: 12px;
        }

        .loading-pulse--large .pulse-dot {
          width: 16px;
          height: 16px;
        }

        .pulse-dot:nth-child(2) {
          animation-delay: 0.2s;
        }

        .pulse-dot:nth-child(3) {
          animation-delay: 0.4s;
        }

        @keyframes pulse {
          0%, 80%, 100% {
            transform: scale(0.6);
            opacity: 0.5;
          }
          40% {
            transform: scale(1);
            opacity: 1;
          }
        }

        /* Dots Styles */
        .loading-dots {
          display: flex;
          gap: 0.25rem;
          margin-bottom: 1rem;
        }

        .dot {
          background-color: #0969da;
          border-radius: 50%;
          animation: bounce 1.4s ease-in-out infinite both;
        }

        .loading-state--dark .dot {
          background-color: #58a6ff;
        }

        .loading-dots--small .dot {
          width: 6px;
          height: 6px;
        }

        .loading-dots--medium .dot {
          width: 8px;
          height: 8px;
        }

        .loading-dots--large .dot {
          width: 12px;
          height: 12px;
        }

        .dot:nth-child(1) { animation-delay: -0.32s; }
        .dot:nth-child(2) { animation-delay: -0.16s; }

        @keyframes bounce {
          0%, 80%, 100% {
            transform: scale(0);
          }
          40% {
            transform: scale(1);
          }
        }

        /* Text Styles */
        .loading-text {
          margin-bottom: 1rem;
        }

        .loading-main-text {
          font-size: 1rem;
          font-weight: 500;
          margin-bottom: 0.25rem;
        }

        .loading-state--small .loading-main-text {
          font-size: 0.875rem;
        }

        .loading-state--large .loading-main-text {
          font-size: 1.125rem;
        }

        .loading-subtext {
          font-size: 0.875rem;
          color: #656d76;
        }

        .loading-state--dark .loading-subtext {
          color: #8b949e;
        }

        /* Progress Bar Styles */
        .loading-progress-bar {
          width: 100%;
          margin-bottom: 1rem;
        }

        .progress-track {
          width: 100%;
          height: 4px;
          background-color: #e1e4e8;
          border-radius: 2px;
          overflow: hidden;
          margin-bottom: 0.5rem;
        }

        .loading-state--dark .progress-track {
          background-color: #30363d;
        }

        .progress-fill {
          height: 100%;
          background-color: #0969da;
          transition: width 0.3s ease;
        }

        .loading-state--dark .progress-fill {
          background-color: #58a6ff;
        }

        .progress-percentage {
          font-size: 0.75rem;
          text-align: center;
          color: #656d76;
        }

        .loading-state--dark .progress-percentage {
          color: #8b949e;
        }

        /* Cancel Button */
        .loading-cancel-btn {
          background-color: #6b7280;
          color: white;
          border: none;
          border-radius: 6px;
          padding: 0.5rem 1rem;
          cursor: pointer;
          font-size: 0.875rem;
          transition: background-color 0.15s ease;
        }

        .loading-cancel-btn:hover {
          background-color: #4b5563;
        }

        .loading-state--dark .loading-cancel-btn {
          background-color: #8b949e;
          color: #0d1117;
        }

        .loading-state--dark .loading-cancel-btn:hover {
          background-color: #a1a7ad;
        }
      `}</style>
    </div>
  );
};

export default LoadingState; 