/**
 * Async Testing Utilities
 * 
 * Provides utilities for testing asynchronous operations, promises,
 * timers, and time-dependent behavior in components and functions.
 */

import { act, waitFor, waitForElementToBeRemoved } from '@testing-library/react';

// Timer management
export interface TimerControls {
  advanceByTime: (ms: number) => void;
  advanceToNextTimer: () => void;
  advanceToNextTimers: (steps: number) => void;
  runAllTimers: () => void;
  runOnlyPendingTimers: () => void;
  clearAllTimers: () => void;
  getTimerCount: () => number;
}

/**
 * Setup fake timers for testing
 */
export function setupFakeTimers(): TimerControls {
  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.runOnlyPendingTimers();
    jest.useRealTimers();
  });

  return {
    advanceByTime: (ms: number) => {
      act(() => {
        jest.advanceTimersByTime(ms);
      });
    },

    advanceToNextTimer: () => {
      act(() => {
        jest.advanceTimersToNextTimer();
      });
    },

    advanceToNextTimers: (steps: number) => {
      act(() => {
        jest.advanceTimersToNextTimer(steps);
      });
    },

    runAllTimers: () => {
      act(() => {
        jest.runAllTimers();
      });
    },

    runOnlyPendingTimers: () => {
      act(() => {
        jest.runOnlyPendingTimers();
      });
    },

    clearAllTimers: () => {
      act(() => {
        jest.clearAllTimers();
      });
    },

    getTimerCount: () => jest.getTimerCount()
  };
}

/**
 * Promise utilities for testing
 */
export const promiseUtils = {
  /**
   * Create a promise that resolves after a delay
   */
  delay: (ms: number = 0): Promise<void> => 
    new Promise(resolve => setTimeout(resolve, ms)),

  /**
   * Create a promise that resolves with a value after a delay
   */
  delayedResolve: <T>(value: T, ms: number = 0): Promise<T> =>
    new Promise(resolve => setTimeout(() => resolve(value), ms)),

  /**
   * Create a promise that rejects with an error after a delay
   */
  delayedReject: (error: Error | string, ms: number = 0): Promise<never> =>
    new Promise((_, reject) => 
      setTimeout(() => reject(typeof error === 'string' ? new Error(error) : error), ms)
    ),

  /**
   * Create a promise that never resolves (for testing timeouts)
   */
  neverResolve: (): Promise<never> => new Promise(() => {}),

  /**
   * Create a controllable promise
   */
  controllable: <T>(): {
    promise: Promise<T>;
    resolve: (value: T) => void;
    reject: (error: Error) => void;
  } => {
    let resolve!: (value: T) => void;
    let reject!: (error: Error) => void;
    
    const promise = new Promise<T>((res, rej) => {
      resolve = res;
      reject = rej;
    });

    return { promise, resolve, reject };
  },

  /**
   * Wait for a condition to be true
   */
  waitForCondition: async (
    condition: () => boolean,
    timeout: number = 5000,
    interval: number = 50
  ): Promise<void> => {
    const startTime = Date.now();
    
    while (!condition()) {
      if (Date.now() - startTime > timeout) {
        throw new Error(`Condition not met within ${timeout}ms timeout`);
      }
      await promiseUtils.delay(interval);
    }
  }
};

/**
 * Async testing patterns
 */
export const asyncPatterns = {
  /**
   * Test that a promise resolves with expected value
   */
  expectToResolve: async <T>(
    promise: Promise<T>,
    expectedValue?: T
  ): Promise<T> => {
    const result = await promise;
    if (expectedValue !== undefined) {
      expect(result).toEqual(expectedValue);
    }
    return result;
  },

  /**
   * Test that a promise rejects with expected error
   */
  expectToReject: async (
    promise: Promise<any>,
    expectedError?: string | RegExp | Error
  ): Promise<Error> => {
    try {
      await promise;
      throw new Error('Expected promise to reject, but it resolved');
    } catch (error) {
      const err = error as Error;
      if (expectedError !== undefined) {
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
   * Test promise with timeout
   */
  expectWithTimeout: async <T>(
    promise: Promise<T>,
    timeout: number = 5000
  ): Promise<T> => {
    return await Promise.race([
      promise,
      promiseUtils.delayedReject(new Error(`Promise timeout after ${timeout}ms`), timeout)
    ]);
  },

  /**
   * Test multiple promises in parallel
   */
  expectAllToResolve: async <T>(
    promises: Promise<T>[],
    timeout?: number
  ): Promise<T[]> => {
    const promise = Promise.all(promises);
    return timeout ? asyncPatterns.expectWithTimeout(promise, timeout) : promise;
  },

  /**
   * Test that at least one promise resolves
   */
  expectAnyToResolve: async <T>(
    promises: Promise<T>[],
    timeout?: number
  ): Promise<T> => {
    const promise = Promise.race(promises);
    return timeout ? asyncPatterns.expectWithTimeout(promise, timeout) : promise;
  }
};

/**
 * Loading state testing utilities
 */
export const loadingUtils = {
  /**
   * Wait for loading state to appear and disappear
   */
  waitForLoadingCycle: async (
    getByTestId: (id: string) => HTMLElement,
    loadingTestId: string = 'loading',
    timeout: number = 5000
  ): Promise<void> => {
    // Wait for loading to appear
    await waitFor(() => {
      expect(getByTestId(loadingTestId)).toBeInTheDocument();
    }, { timeout });

    // Wait for loading to disappear
    await waitForElementToBeRemoved(() => getByTestId(loadingTestId), { timeout });
  },

  /**
   * Assert loading state is present
   */
  expectLoadingState: (
    getByTestId: (id: string) => HTMLElement,
    loadingTestId: string = 'loading'
  ): void => {
    expect(getByTestId(loadingTestId)).toBeInTheDocument();
  },

  /**
   * Assert loading state is not present
   */
  expectNotLoadingState: (
    queryByTestId: (id: string) => HTMLElement | null,
    loadingTestId: string = 'loading'
  ): void => {
    expect(queryByTestId(loadingTestId)).not.toBeInTheDocument();
  }
};

/**
 * Error handling testing utilities
 */
export const errorUtils = {
  /**
   * Test error boundary behavior
   */
  testErrorBoundary: async (
    renderFunction: () => any,
    triggerError: () => void | Promise<void>
  ): Promise<void> => {
    const { getByTestId } = renderFunction();
    
    // Trigger the error
    if (typeof triggerError === 'function') {
      const result = triggerError();
      if (result instanceof Promise) {
        await result;
      }
    }

    // Wait for error boundary to catch the error
    await waitFor(() => {
      expect(getByTestId('error-boundary')).toBeInTheDocument();
    });
  },

  /**
   * Test async error handling
   */
  testAsyncError: async (
    asyncFunction: () => Promise<any>,
    expectedError?: string | RegExp | Error
  ): Promise<void> => {
    await asyncPatterns.expectToReject(asyncFunction(), expectedError);
  }
};

/**
 * Network request testing utilities
 */
export const networkUtils = {
  /**
   * Mock successful API response
   */
  mockSuccessfulResponse: <T>(data: T, delay: number = 100): Promise<T> => {
    return promiseUtils.delayedResolve(data, delay);
  },

  /**
   * Mock failed API response
   */
  mockFailedResponse: (error: string, delay: number = 100): Promise<never> => {
    return promiseUtils.delayedReject(new Error(error), delay);
  },

  /**
   * Mock network timeout
   */
  mockNetworkTimeout: (timeoutMs: number = 5000): Promise<never> => {
    return promiseUtils.delayedReject(new Error('Network timeout'), timeoutMs);
  },

  /**
   * Test retry logic
   */
  testRetryLogic: async (
    retryFunction: () => Promise<any>,
    maxRetries: number,
    expectedAttempts: number
  ): Promise<void> => {
    let attemptCount = 0;
    const originalFetch = global.fetch;
    
    global.fetch = jest.fn().mockImplementation(() => {
      attemptCount++;
      if (attemptCount <= maxRetries) {
        return Promise.reject(new Error('Network error'));
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
    });

    try {
      await retryFunction();
      expect(attemptCount).toBe(expectedAttempts);
    } finally {
      global.fetch = originalFetch;
    }
  }
};

/**
 * Debounce and throttle testing utilities
 */
export const timingUtils = {
  /**
   * Test debounced function behavior
   */
  testDebounce: async (
    debouncedFunction: (...args: any[]) => void,
    delay: number,
    timerControls: TimerControls
  ): Promise<void> => {
    const mockCallback = jest.fn();
    
    // Call function multiple times rapidly
    debouncedFunction(mockCallback);
    debouncedFunction(mockCallback);
    debouncedFunction(mockCallback);
    
    // Should not have been called yet
    expect(mockCallback).not.toHaveBeenCalled();
    
    // Fast forward through the debounce delay
    timerControls.advanceByTime(delay);
    
    // Should have been called only once
    expect(mockCallback).toHaveBeenCalledTimes(1);
  },

  /**
   * Test throttled function behavior
   */
  testThrottle: async (
    throttledFunction: (...args: any[]) => void,
    delay: number,
    timerControls: TimerControls
  ): Promise<void> => {
    const mockCallback = jest.fn();
    
    // Call function multiple times rapidly
    throttledFunction(mockCallback);
    throttledFunction(mockCallback);
    throttledFunction(mockCallback);
    
    // Should have been called once immediately
    expect(mockCallback).toHaveBeenCalledTimes(1);
    
    // Fast forward through the throttle delay
    timerControls.advanceByTime(delay);
    
    // Should still be only one call
    expect(mockCallback).toHaveBeenCalledTimes(1);
  }
};

/**
 * Comprehensive async test utilities
 */
export const asyncTestUtils = {
  setupFakeTimers,
  promiseUtils,
  asyncPatterns,
  loadingUtils,
  errorUtils,
  networkUtils,
  timingUtils,

  /**
   * Wait for next tick
   */
  nextTick: (): Promise<void> => promiseUtils.delay(0),

  /**
   * Flush all promises
   */
  flushPromises: (): Promise<void> => act(async () => {
    await promiseUtils.delay(0);
  }),

  /**
   * Wait for component to update
   */
  waitForUpdate: async (timeout: number = 1000): Promise<void> => {
    await act(async () => {
      await promiseUtils.delay(0);
    });
  }
};

export default asyncTestUtils; 