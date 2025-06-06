import React, { useState, useEffect, useCallback } from 'react';

export interface ProgressBarProps {
  /** Current progress value (0-100) */
  value: number;
  /** Maximum value (default: 100) */
  max?: number;
  /** Progress bar size */
  size?: 'sm' | 'md' | 'lg';
  /** Progress bar variant */
  variant?: 'default' | 'success' | 'warning' | 'error' | 'gradient';
  /** Show percentage text */
  showPercentage?: boolean;
  /** Show progress value text */
  showValue?: boolean;
  /** Custom label text */
  label?: string;
  /** Enable smooth animation */
  animated?: boolean;
  /** Enable striped pattern */
  striped?: boolean;
  /** Enable indeterminate loading state */
  indeterminate?: boolean;
  /** Custom className */
  className?: string;
  /** Accessibility label */
  'aria-label'?: string;
  /** Progress description for screen readers */
  'aria-describedby'?: string;
  /** Callback when progress completes */
  onComplete?: () => void;
}

export interface ProgressStepProps {
  /** Step label */
  label: string;
  /** Step description */
  description?: string;
  /** Step status */
  status: 'pending' | 'active' | 'completed' | 'error';
  /** Step progress (0-100) */
  progress?: number;
}

export interface MultiStepProgressProps {
  /** Array of progress steps */
  steps: ProgressStepProps[];
  /** Current active step index */
  currentStep: number;
  /** Show step indicators */
  showStepIndicators?: boolean;
  /** Show step labels */
  showStepLabels?: boolean;
  /** Custom className */
  className?: string;
}

/**
 * ProgressBar Component
 * Displays progress with various styles and features
 */
export const ProgressBar: React.FC<ProgressBarProps> = ({
  value,
  max = 100,
  size = 'md',
  variant = 'default',
  showPercentage = false,
  showValue = false,
  label,
  animated = true,
  striped = false,
  indeterminate = false,
  className = '',
  'aria-label': ariaLabel,
  'aria-describedby': ariaDescribedBy,
  onComplete,
}) => {
  const [currentValue, setCurrentValue] = useState(0);
  const [hasCompleted, setHasCompleted] = useState(false);

  // Animate progress value changes
  useEffect(() => {
    if (!animated) {
      setCurrentValue(value);
      return;
    }

    const targetValue = Math.min(Math.max(value, 0), max);
    const duration = 300;
    const steps = 30;
    const stepValue = (targetValue - currentValue) / steps;

    if (Math.abs(stepValue) < 0.1) {
      setCurrentValue(targetValue);
      return;
    }

    const interval = setInterval(() => {
      setCurrentValue(prev => {
        const next = prev + stepValue;
        if (
          (stepValue > 0 && next >= targetValue) ||
          (stepValue < 0 && next <= targetValue)
        ) {
          clearInterval(interval);
          return targetValue;
        }
        return next;
      });
    }, duration / steps);

    return () => clearInterval(interval);
  }, [value, max, animated, currentValue]);

  // Handle completion callback
  useEffect(() => {
    if (currentValue >= max && !hasCompleted && onComplete) {
      setHasCompleted(true);
      onComplete();
    } else if (currentValue < max) {
      setHasCompleted(false);
    }
  }, [currentValue, max, hasCompleted, onComplete]);

  const percentage = indeterminate ? 0 : (currentValue / max) * 100;
  const displayValue = showValue ? Math.round(currentValue) : null;
  const displayPercentage = showPercentage ? `${Math.round(percentage)}%` : null;

  const sizeClasses = {
    sm: 'h-1',
    md: 'h-2',
    lg: 'h-3'
  };

  const variantClasses = {
    default: 'bg-blue-500',
    success: 'bg-green-500',
    warning: 'bg-yellow-500',
    error: 'bg-red-500',
    gradient: 'bg-gradient-to-r from-blue-500 to-purple-600'
  };

  return (
    <div className={`progress-container ${className}`}>
      {(label || displayValue || displayPercentage) && (
        <div className="progress-header">
          {label && (
            <span className="progress-label text-sm font-medium text-gray-700">
              {label}
            </span>
          )}
          {(displayValue || displayPercentage) && (
            <span className="progress-value text-sm text-gray-500">
              {displayValue && `${displayValue}/${max}`}
              {displayValue && displayPercentage && ' • '}
              {displayPercentage}
            </span>
          )}
        </div>
      )}
      
      <div
        className={`progress-track w-full bg-gray-200 rounded-full overflow-hidden ${sizeClasses[size]}`}
        role="progressbar"
        aria-label={ariaLabel || label || 'Progress'}
        aria-valuenow={indeterminate ? undefined : currentValue}
        aria-valuemin={0}
        aria-valuemax={max}
        aria-describedby={ariaDescribedBy}
      >
        <div
          className={`
            progress-fill h-full transition-all duration-300 ease-out
            ${variantClasses[variant]}
            ${striped ? 'bg-striped' : ''}
            ${indeterminate ? 'progress-indeterminate' : ''}
          `}
          style={{
            width: indeterminate ? '100%' : `${percentage}%`,
          }}
        />
      </div>

      <style jsx>{`
        .progress-container {
          width: 100%;
        }

        .progress-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 0.5rem;
        }

        .progress-track {
          position: relative;
        }

        .progress-fill {
          transform-origin: left;
        }

        .bg-striped {
          background-image: linear-gradient(
            45deg,
            rgba(255, 255, 255, 0.15) 25%,
            transparent 25%,
            transparent 50%,
            rgba(255, 255, 255, 0.15) 50%,
            rgba(255, 255, 255, 0.15) 75%,
            transparent 75%,
            transparent
          );
          background-size: 1rem 1rem;
          animation: ${striped ? 'progress-stripes 1s linear infinite' : 'none'};
        }

        .progress-indeterminate {
          animation: progress-indeterminate 2s ease-in-out infinite;
          background: linear-gradient(
            90deg,
            transparent 0%,
            var(--color-primary-500) 50%,
            transparent 100%
          );
          width: 40% !important;
        }

        @keyframes progress-stripes {
          0% {
            background-position: 0 0;
          }
          100% {
            background-position: 1rem 0;
          }
        }

        @keyframes progress-indeterminate {
          0% {
            transform: translateX(-100%);
          }
          50% {
            transform: translateX(0);
          }
          100% {
            transform: translateX(250%);
          }
        }

        /* Dark theme support */
        :global(.dark) .progress-track {
          background-color: #374151;
        }

        :global(.dark) .progress-label {
          color: #e5e7eb;
        }

        :global(.dark) .progress-value {
          color: #9ca3af;
        }
      `}</style>
    </div>
  );
};

/**
 * MultiStepProgress Component
 * Displays progress across multiple steps
 */
export const MultiStepProgress: React.FC<MultiStepProgressProps> = ({
  steps,
  currentStep,
  showStepIndicators = true,
  showStepLabels = true,
  className = '',
}) => {
  const totalSteps = steps.length;
  const overallProgress = totalSteps > 0 ? ((currentStep + 1) / totalSteps) * 100 : 0;

  return (
    <div className={`multi-step-progress ${className}`}>
      {/* Overall progress bar */}
      <ProgressBar
        value={overallProgress}
        variant="default"
        animated
        className="mb-4"
      />

      {/* Step indicators */}
      {showStepIndicators && (
        <div className="step-indicators">
          {steps.map((step, index) => {
            const isActive = index === currentStep;
            const isCompleted = step.status === 'completed';
            const isError = step.status === 'error';
            const isPending = step.status === 'pending';

            return (
              <div key={index} className="step-indicator">
                <div className="step-line-container">
                  {index > 0 && (
                    <div
                      className={`step-line ${
                        steps[index - 1].status === 'completed' 
                          ? 'step-line-completed' 
                          : 'step-line-pending'
                      }`}
                    />
                  )}
                </div>
                
                <div
                  className={`
                    step-circle
                    ${isActive ? 'step-circle-active' : ''}
                    ${isCompleted ? 'step-circle-completed' : ''}
                    ${isError ? 'step-circle-error' : ''}
                    ${isPending ? 'step-circle-pending' : ''}
                  `}
                >
                  {isCompleted && (
                    <svg className="step-check" viewBox="0 0 20 20" fill="currentColor">
                      <path
                        fillRule="evenodd"
                        d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
                        clipRule="evenodd"
                      />
                    </svg>
                  )}
                  {isError && (
                    <svg className="step-error" viewBox="0 0 20 20" fill="currentColor">
                      <path
                        fillRule="evenodd"
                        d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z"
                        clipRule="evenodd"
                      />
                    </svg>
                  )}
                  {!isCompleted && !isError && (
                    <span className="step-number">{index + 1}</span>
                  )}
                </div>

                {showStepLabels && (
                  <div className="step-content">
                    <div className={`step-label ${isActive ? 'step-label-active' : ''}`}>
                      {step.label}
                    </div>
                    {step.description && (
                      <div className="step-description">
                        {step.description}
                      </div>
                    )}
                    {step.progress !== undefined && isActive && (
                      <ProgressBar
                        value={step.progress}
                        size="sm"
                        variant={isError ? 'error' : 'default'}
                        showPercentage
                        className="mt-2"
                      />
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      <style jsx>{`
        .multi-step-progress {
          width: 100%;
        }

        .step-indicators {
          display: flex;
          flex-direction: column;
          gap: 1rem;
        }

        .step-indicator {
          display: flex;
          align-items: flex-start;
          gap: 1rem;
          position: relative;
        }

        .step-line-container {
          position: absolute;
          left: 1rem;
          top: 0;
          bottom: 0;
          transform: translateX(-50%);
          width: 2px;
        }

        .step-line {
          width: 100%;
          height: 100%;
          background-color: #e5e7eb;
          position: relative;
          top: 2rem;
        }

        .step-line-completed {
          background-color: #10b981;
        }

        .step-circle {
          width: 2rem;
          height: 2rem;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 0.875rem;
          font-weight: 500;
          flex-shrink: 0;
          z-index: 1;
          position: relative;
        }

        .step-circle-pending {
          background-color: #f3f4f6;
          color: #6b7280;
          border: 2px solid #e5e7eb;
        }

        .step-circle-active {
          background-color: #3b82f6;
          color: white;
          border: 2px solid #3b82f6;
          box-shadow: 0 0 0 4px rgba(59, 130, 246, 0.1);
        }

        .step-circle-completed {
          background-color: #10b981;
          color: white;
          border: 2px solid #10b981;
        }

        .step-circle-error {
          background-color: #ef4444;
          color: white;
          border: 2px solid #ef4444;
        }

        .step-check,
        .step-error {
          width: 1rem;
          height: 1rem;
        }

        .step-number {
          font-size: 0.75rem;
        }

        .step-content {
          flex: 1;
          padding-top: 0.125rem;
        }

        .step-label {
          font-size: 0.875rem;
          font-weight: 500;
          color: #374151;
          margin-bottom: 0.25rem;
        }

        .step-label-active {
          color: #3b82f6;
        }

        .step-description {
          font-size: 0.75rem;
          color: #6b7280;
          line-height: 1.4;
        }

        /* Dark theme support */
        :global(.dark) .step-line {
          background-color: #4b5563;
        }

        :global(.dark) .step-line-completed {
          background-color: #10b981;
        }

        :global(.dark) .step-circle-pending {
          background-color: #374151;
          color: #9ca3af;
          border-color: #4b5563;
        }

        :global(.dark) .step-label {
          color: #e5e7eb;
        }

        :global(.dark) .step-label-active {
          color: #60a5fa;
        }

        :global(.dark) .step-description {
          color: #9ca3af;
        }

        /* Responsive design */
        @media (max-width: 768px) {
          .step-indicator {
            gap: 0.75rem;
          }

          .step-circle {
            width: 1.5rem;
            height: 1.5rem;
            font-size: 0.75rem;
          }

          .step-line-container {
            left: 0.75rem;
          }

          .step-check,
          .step-error {
            width: 0.875rem;
            height: 0.875rem;
          }
        }
      `}</style>
    </div>
  );
};

export default ProgressBar; 