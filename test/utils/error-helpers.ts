/**
 * Error Testing Helpers
 * 
 * Provides utilities for testing error boundaries, error states,
 * error handling scenarios, and error recovery mechanisms.
 */

import React from 'react';
import { render, RenderResult, waitFor } from '@testing-library/react';
import { promiseUtils } from './async-helpers';

// Error types for testing
export interface TestError extends Error {
  code?: string;
  statusCode?: number;
  cause?: Error;
  context?: Record<string, any>;
}

export interface ErrorBoundaryState {
  hasError: boolean;
  error?: Error;
  errorInfo?: React.ErrorInfo;
  errorId?: string;
  retryCount?: number;
}

export interface ErrorTestOptions {
  errorType?: 'sync' | 'async' | 'render' | 'network' | 'validation';
  shouldRecover?: boolean;
  retryAttempts?: number;
  delay?: number;
  context?: Record<string, any>;
}

/**
 * Create test errors with specific properties
 */
export const createTestError = {
  /**
   * Create a basic test error
   */
  basic: (message: string = 'Test error', options: Partial<TestError> = {}): TestError => {
    const error = new Error(message) as TestError;
    Object.assign(error, options);
    return error;
  },

  /**
   * Create a network error
   */
  network: (message: string = 'Network error', statusCode: number = 500): TestError => {
    const error = createTestError.basic(message, {
      code: 'NETWORK_ERROR',
      statusCode,
      context: { type: 'network', statusCode }
    });
    return error;
  },

  /**
   * Create a validation error
   */
  validation: (message: string = 'Validation failed', field?: string): TestError => {
    const error = createTestError.basic(message, {
      code: 'VALIDATION_ERROR',
      context: { type: 'validation', field }
    });
    return error;
  },

  /**
   * Create an authentication error
   */
  auth: (message: string = 'Authentication failed'): TestError => {
    const error = createTestError.basic(message, {
      code: 'AUTH_ERROR',
      statusCode: 401,
      context: { type: 'authentication' }
    });
    return error;
  },

  /**
   * Create an authorization error
   */
  permission: (message: string = 'Permission denied'): TestError => {
    const error = createTestError.basic(message, {
      code: 'PERMISSION_ERROR',
      statusCode: 403,
      context: { type: 'authorization' }
    });
    return error;
  },

  /**
   * Create a timeout error
   */
  timeout: (message: string = 'Operation timed out'): TestError => {
    const error = createTestError.basic(message, {
      code: 'TIMEOUT_ERROR',
      context: { type: 'timeout' }
    });
    return error;
  },

  /**
   * Create an async error
   */
  async: (message: string = 'Async operation failed'): TestError => {
    const error = createTestError.basic(message, {
      code: 'ASYNC_ERROR',
      context: { type: 'async' }
    });
    return error;
  }
};

/**
 * Error throwing utilities
 */
export const errorThrowers = {
  /**
   * Function that throws synchronously
   */
  throwSync: (error: Error = createTestError.basic()): (() => never) => {
    return () => {
      throw error;
    };
  },

  /**
   * Function that throws asynchronously
   */
  throwAsync: (error: Error = createTestError.basic(), delay: number = 0): (() => Promise<never>) => {
    return async () => {
      if (delay > 0) {
        await promiseUtils.delay(delay);
      }
      throw error;
    };
  },

  /**
   * Component that throws during render
   */
  ThrowingComponent: ({ error, shouldThrow = true }: { error?: Error; shouldThrow?: boolean }) => {
    if (shouldThrow) {
      throw error || createTestError.basic('Component render error');
    }
    return React.createElement('div', { 'data-testid': 'throwing-component' }, 'No error');
  },

  /**
   * Component that throws during useEffect
   */
  ThrowingEffectComponent: ({ error, shouldThrow = true }: { error?: Error; shouldThrow?: boolean }) => {
    React.useEffect(() => {
      if (shouldThrow) {
        throw error || createTestError.basic('Component effect error');
      }
    }, [shouldThrow, error]);

    return React.createElement('div', { 'data-testid': 'throwing-effect-component' }, 'Component loaded');
  },

  /**
   * Component that throws on user interaction
   */
  ThrowingInteractionComponent: ({ error, onError }: { error?: Error; onError?: (e: Error) => void }) => {
    const handleClick = () => {
      const errorToThrow = error || createTestError.basic('Interaction error');
      if (onError) {
        onError(errorToThrow);
      } else {
        throw errorToThrow;
      }
    };

    return React.createElement(
      'button',
      {
        'data-testid': 'throwing-button',
        onClick: handleClick
      },
      'Click to throw error'
    );
  }
};

/**
 * Enhanced error boundary for testing
 */
export class TestErrorBoundary extends React.Component<
  {
    children: React.ReactNode;
    onError?: (error: Error, errorInfo: React.ErrorInfo) => void;
    fallback?: React.ComponentType<{ error: Error; retry: () => void }>;
    shouldRecover?: boolean;
    maxRetries?: number;
  },
  ErrorBoundaryState
> {
  private retryTimeoutId?: NodeJS.Timeout;

  constructor(props: any) {
    super(props);
    this.state = {
      hasError: false,
      retryCount: 0
    };
  }

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return {
      hasError: true,
      error,
      errorId: `error-${Date.now()}-${Math.random().toString(36).substring(2)}`
    };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    this.setState({ errorInfo });
    this.props.onError?.(error, errorInfo);
    
    // Auto-retry if configured
    if (this.props.shouldRecover && (this.state.retryCount || 0) < (this.props.maxRetries || 3)) {
      this.retryTimeoutId = setTimeout(() => {
        this.handleRetry();
      }, 1000);
    }
  }

  componentWillUnmount() {
    if (this.retryTimeoutId) {
      clearTimeout(this.retryTimeoutId);
    }
  }

  handleRetry = () => {
    this.setState(prevState => ({
      hasError: false,
      error: undefined,
      errorInfo: undefined,
      retryCount: (prevState.retryCount || 0) + 1
    }));
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return React.createElement(this.props.fallback, {
          error: this.state.error!,
          retry: this.handleRetry
        });
      }

      return React.createElement(
        'div',
        { 'data-testid': 'error-boundary' },
        React.createElement('h2', null, 'Something went wrong'),
        React.createElement('details', null,
          React.createElement('summary', null, 'Error details'),
          React.createElement('pre', null, this.state.error?.message),
          React.createElement('pre', null, this.state.error?.stack)
        ),
        React.createElement(
          'button',
          {
            'data-testid': 'retry-button',
            onClick: this.handleRetry
          },
          'Retry'
        ),
        React.createElement('div', { 'data-testid': 'retry-count' }, `Retry count: ${this.state.retryCount}`)
      );
    }

    return this.props.children;
  }
}

/**
 * Error testing patterns
 */
export const errorPatterns = {
  /**
   * Test error boundary catches errors
   */
  testErrorBoundary: async (
    component: React.ReactElement,
    triggerError: () => void | Promise<void>,
    options: { onError?: (error: Error) => void; shouldRecover?: boolean } = {}
  ): Promise<RenderResult> => {
    const onError = jest.fn(options.onError);
    
    const result = render(
      React.createElement(
        TestErrorBoundary,
        { onError, shouldRecover: options.shouldRecover },
        component
      )
    );

    // Trigger the error
    const errorResult = triggerError();
    if (errorResult instanceof Promise) {
      await errorResult;
    }

    // Wait for error boundary to catch and render error
    await waitFor(() => {
      expect(result.getByTestId('error-boundary')).toBeInTheDocument();
    });

    // Verify error was caught
    expect(onError).toHaveBeenCalled();

    return result;
  },

  /**
   * Test error recovery
   */
  testErrorRecovery: async (
    component: React.ReactElement,
    triggerError: () => void,
    recoverFunction: () => void
  ): Promise<RenderResult> => {
    const result = render(
      React.createElement(
        TestErrorBoundary,
        { shouldRecover: true },
        component
      )
    );

    // Trigger error
    triggerError();

    // Wait for error state
    await waitFor(() => {
      expect(result.getByTestId('error-boundary')).toBeInTheDocument();
    });

    // Trigger recovery
    recoverFunction();

    // Wait for recovery
    await waitFor(() => {
      expect(result.queryByTestId('error-boundary')).not.toBeInTheDocument();
    });

    return result;
  },

  /**
   * Test async error handling
   */
  testAsyncError: async (
    asyncFunction: () => Promise<any>,
    expectedError?: string | Error | RegExp
  ): Promise<Error> => {
    try {
      await asyncFunction();
      throw new Error('Expected function to throw, but it resolved');
    } catch (error) {
      const err = error as Error;
      
      if (expectedError) {
        if (typeof expectedError === 'string') {
          expect(err.message).toContain(expectedError);
        } else if (expectedError instanceof RegExp) {
          expect(err.message).toMatch(expectedError);
        } else if (expectedError instanceof Error) {
          expect(err.message).toBe(expectedError.message);
        }
      }
      
      return err;
    }
  },

  /**
   * Test error propagation
   */
  testErrorPropagation: async (
    nestedComponents: React.ReactElement[],
    errorLevel: number = 0
  ): Promise<RenderResult> => {
    const onError = jest.fn();
    
    // Wrap each component level with error boundary
    let wrappedComponent = nestedComponents[0];
    for (let i = 1; i < nestedComponents.length; i++) {
      wrappedComponent = React.createElement(
        TestErrorBoundary,
        { onError },
        nestedComponents[i],
        wrappedComponent
      );
    }

    const result = render(wrappedComponent);

    return result;
  }
};

/**
 * Error state testing utilities
 */
export const errorStateUtils = {
  /**
   * Mock error states
   */
  mockErrorState: (error: Error, context?: Record<string, any>) => ({
    isError: true,
    error,
    context,
    timestamp: new Date(),
    retryCount: 0
  }),

  /**
   * Mock loading error state
   */
  mockLoadingErrorState: (error: Error) => ({
    isLoading: false,
    isError: true,
    error,
    data: null
  }),

  /**
   * Mock network error state
   */
  mockNetworkErrorState: (statusCode: number = 500, message?: string) => ({
    isError: true,
    error: createTestError.network(message, statusCode),
    networkError: true,
    statusCode
  }),

  /**
   * Verify error state structure
   */
  expectErrorState: (errorState: any, expectedError?: Error) => {
    expect(errorState.isError).toBe(true);
    expect(errorState.error).toBeDefined();
    
    if (expectedError) {
      expect(errorState.error.message).toBe(expectedError.message);
    }
  }
};

/**
 * Error mock utilities
 */
export const errorMocks = {
  /**
   * Mock console.error to capture error logs
   */
  mockConsoleError: (): jest.SpyInstance => {
    return jest.spyOn(console, 'error').mockImplementation(() => {});
  },

  /**
   * Mock fetch to return errors
   */
  mockFetchError: (error: Error, delay: number = 0): jest.SpyInstance => {
    return jest.spyOn(global, 'fetch').mockImplementation(
      () => promiseUtils.delayedReject(error, delay)
    );
  },

  /**
   * Mock API response errors
   */
  mockApiError: (statusCode: number = 500, message: string = 'Server Error'): jest.SpyInstance => {
    return jest.spyOn(global, 'fetch').mockResolvedValue({
      ok: false,
      status: statusCode,
      statusText: message,
      json: () => Promise.resolve({ error: message })
    } as Response);
  },

  /**
   * Restore all error mocks
   */
  restoreErrorMocks: (): void => {
    jest.restoreAllMocks();
  }
};

/**
 * Comprehensive error testing utilities
 */
export const errorTestUtils = {
  createTestError,
  errorThrowers,
  TestErrorBoundary,
  errorPatterns,
  errorStateUtils,
  errorMocks,

  /**
   * Setup error testing environment
   */
  setupErrorTests: (): void => {
    beforeEach(() => {
      // Suppress React error boundary logs in tests
      jest.spyOn(console, 'error').mockImplementation(() => {});
    });

    afterEach(() => {
      jest.restoreAllMocks();
    });
  },

  /**
   * Create error testing scenario
   */
  createErrorScenario: (
    name: string,
    error: Error,
    options: ErrorTestOptions = {}
  ) => ({
    name,
    error,
    options,
    test: async (component: React.ReactElement) => {
      return errorPatterns.testErrorBoundary(
        component,
        () => { throw error; },
        options
      );
    }
  })
};

export default errorTestUtils; 