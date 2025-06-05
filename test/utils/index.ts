/**
 * Test Utilities Central Export
 * 
 * Provides a unified interface to all test utilities and helpers,
 * making it easy to import and use testing tools across the test suite.
 */

// Render utilities
export {
  renderWithProviders,
  renderWithAuth,
  renderWithoutAuth,
  renderWithLoadingAuth,
  renderWithAdmin,
  renderWithRouter,
  renderWithErrorBoundary,
  renderWithAllProviders,
  createCustomRender,
  TestErrorBoundary,
  baseRender
} from './render';

// Authentication testing utilities
export {
  auth,
  authAssertions,
  authFlows,
  authTestScenarios,
  authHelpers,
  getAuthStateFromSession
} from './auth-helpers';

// Async testing utilities
export {
  asyncTestUtils,
  setupFakeTimers,
  promiseUtils,
  asyncPatterns,
  loadingUtils,
  errorUtils,
  networkUtils,
  timingUtils
} from './async-helpers';

// Custom matchers
export {
  setupCustomMatchers,
  authenticationMatchers,
  errorMatchers,
  domMatchers,
  arrayObjectMatchers,
  asyncMatchers,
  timeMatchers,
  businessLogicMatchers
} from './custom-matchers';

// Error testing utilities
export {
  errorTestUtils,
  createTestError,
  errorThrowers,
  TestErrorBoundary as ErrorBoundary,
  errorPatterns,
  errorStateUtils,
  errorMocks
} from './error-helpers';

// Re-export commonly used testing library functions
export {
  render,
  screen,
  fireEvent,
  waitFor,
  waitForElementToBeRemoved,
  act,
  cleanup
} from '@testing-library/react';

/**
 * Test Kit - Main interface for all test utilities
 */
export const testKit = {
  // Render utilities
  render: {
    withProviders: async () => (await import('./render')).renderWithProviders,
    withAuth: async () => (await import('./render')).renderWithAuth,
    withoutAuth: async () => (await import('./render')).renderWithoutAuth,
    withLoadingAuth: async () => (await import('./render')).renderWithLoadingAuth,
    withAdmin: async () => (await import('./render')).renderWithAdmin,
    withRouter: async () => (await import('./render')).renderWithRouter,
    withErrorBoundary: async () => (await import('./render')).renderWithErrorBoundary,
    withAllProviders: async () => (await import('./render')).renderWithAllProviders,
    createCustom: async () => (await import('./render')).createCustomRender
  },

  // Authentication utilities
  auth: async () => (await import('./auth-helpers')).auth,

  // Async utilities
  async: async () => (await import('./async-helpers')).asyncTestUtils,

  // Error utilities
  errors: async () => (await import('./error-helpers')).errorTestUtils,

  // Setup functions
  setup: {
    customMatchers: async () => (await import('./custom-matchers')).setupCustomMatchers,
    fakeTimers: async () => (await import('./async-helpers')).setupFakeTimers,
    errorTests: async () => (await import('./error-helpers')).errorTestUtils.setupErrorTests,
    authTests: async () => (await import('./auth-helpers')).authHelpers.setupAuthTests
  }
};

/**
 * Quick access utilities for common testing patterns
 */
export const testUtils = {
  // Quick render functions
  renderAuth: async (ui: React.ReactElement, sessionData?: any) => {
    const { renderWithAuth } = await import('./render');
    return renderWithAuth(ui, sessionData);
  },

  renderAdmin: async (ui: React.ReactElement, sessionData?: any) => {
    const { renderWithAdmin } = await import('./render');
    return renderWithAdmin(ui, sessionData);
  },

  renderGuest: async (ui: React.ReactElement) => {
    const { renderWithoutAuth } = await import('./render');
    return renderWithoutAuth(ui);
  },

  // Quick error testing
  expectError: async (asyncFn: () => Promise<any>, expectedMessage?: string) => {
    const { errorPatterns } = await import('./error-helpers');
    return errorPatterns.testAsyncError(asyncFn, expectedMessage);
  },

  // Quick async testing
  delay: async (ms: number) => {
    const { promiseUtils } = await import('./async-helpers');
    return promiseUtils.delay(ms);
  },

  // Quick auth testing
  createAuthSession: async (role: 'USER' | 'ADMIN' | 'MODERATOR' = 'USER') => {
    const { authHelpers } = await import('./auth-helpers');
    return authHelpers.createTestSession(role);
  }
};

/**
 * Test scenarios for common use cases
 */
export const testScenarios = {
  // Authentication scenarios
  auth: {
    authenticatedUser: async () => {
      const { authTestScenarios } = await import('./auth-helpers');
      return authTestScenarios.regularUser();
    },
    authenticatedAdmin: async () => {
      const { authTestScenarios } = await import('./auth-helpers');
      return authTestScenarios.adminUser();
    },
    unauthenticated: async () => {
      const { authTestScenarios } = await import('./auth-helpers');
      return authTestScenarios.unauthenticated();
    },
    expiredSession: async () => {
      const { authTestScenarios } = await import('./auth-helpers');
      return authTestScenarios.expiredSession();
    }
  },

  // Error scenarios
  errors: {
    networkError: async (statusCode: number = 500) => {
      const { createTestError } = await import('./error-helpers');
      return createTestError.network('Network error', statusCode);
    },
    validationError: async (field?: string) => {
      const { createTestError } = await import('./error-helpers');
      return createTestError.validation('Validation failed', field);
    },
    authError: async () => {
      const { createTestError } = await import('./error-helpers');
      return createTestError.auth();
    },
    permissionError: async () => {
      const { createTestError } = await import('./error-helpers');
      return createTestError.permission();
    }
  },

  // Loading scenarios
  loading: {
    async: async (data: any, delay: number = 100) => {
      const { networkUtils } = await import('./async-helpers');
      return networkUtils.mockSuccessfulResponse(data, delay);
    },
    error: async (error: string, delay: number = 100) => {
      const { networkUtils } = await import('./async-helpers');
      return networkUtils.mockFailedResponse(error, delay);
    },
    timeout: async (timeoutMs: number = 5000) => {
      const { networkUtils } = await import('./async-helpers');
      return networkUtils.mockNetworkTimeout(timeoutMs);
    }
  }
};

/**
 * Test helpers for setup and teardown
 */
export const testHelpers = {
  /**
   * Setup comprehensive test environment
   */
  setupTestEnvironment: async (): Promise<void> => {
    const [
      { setupCustomMatchers },
      { errorTestUtils },
      { authHelpers }
    ] = await Promise.all([
      import('./custom-matchers'),
      import('./error-helpers'),
      import('./auth-helpers')
    ]);

    setupCustomMatchers();
    errorTestUtils.setupErrorTests();
    authHelpers.setupAuthTests();
  },

  /**
   * Create test suite with common setup
   */
  createTestSuite: (name: string, tests: () => void, options?: {
    useAuth?: boolean;
    useTimers?: boolean;
    useErrors?: boolean;
  }): void => {
    describe(name, () => {
      beforeAll(async () => {
        await testHelpers.setupTestEnvironment();
        
        if (options?.useTimers) {
          const { setupFakeTimers } = await import('./async-helpers');
          setupFakeTimers();
        }
      });

      tests();
    });
  }
};

/**
 * Default export with most commonly used utilities
 */
export default {
  testKit,
  testUtils,
  testScenarios,
  testHelpers,
  
  // Direct access to most used functions
  renderWithAuth: async () => (await import('./render')).renderWithAuth,
  renderWithAdmin: async () => (await import('./render')).renderWithAdmin,
  renderWithoutAuth: async () => (await import('./render')).renderWithoutAuth,
  auth: async () => (await import('./auth-helpers')).auth,
  errors: async () => (await import('./error-helpers')).errorTestUtils,
  async: async () => (await import('./async-helpers')).asyncTestUtils
};

/**
 * Type exports for test utilities
 */
export type {
  MockSession,
  MockSessionOptions
} from '../__mocks__/nextauth/session';

export type {
  MockSessionProviderProps
} from '../__mocks__/nextauth/provider';

export type {
  AuthTestState
} from './auth-helpers';

export type {
  TimerControls as AsyncTimerControls
} from './async-helpers';

export type {
  TestError as ErrorHelperTestError,
  ErrorBoundaryState as ErrorHelperBoundaryState,
  ErrorTestOptions as ErrorHelperTestOptions
} from './error-helpers';