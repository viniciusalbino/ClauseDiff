/**
 * NextAuth Mocking Utilities Index
 * 
 * Central export point for all NextAuth mocking utilities
 * used in testing the ClauseDiff application.
 */

// Session mocking utilities
export {
  createMockSession,
  createMockJWT,
  sessionScenarios,
  sessionTransitions,
  type MockSession,
  type MockSessionOptions
} from './session';

// Provider mocking utilities
export {
  MockSessionProvider,
  createMockUseSession,
  mockSignIn,
  mockSignOut,
  createMockGetSession,
  mockGetCsrfToken,
  mockGetProviders,
  nextAuthMocks,
  resetNextAuthMocks,
  authProviderScenarios,
  type MockSessionProviderProps
} from './provider';

// JWT mocking utilities
export {
  createMockToken,
  createMockGetToken,
  mockJWTEncode,
  mockJWTDecode,
  jwtScenarios,
  jwtOperations,
  resetJWTMocks,
  createMockJWTMiddleware,
  jwtTestUtils,
  type MockJWTOptions
} from './jwt';

// Testing helper utilities
export {
  renderWithAuth,
  setupAuthMocks,
  authTestScenarios,
  authAssertions,
  authMockFactories,
  authFlowHelpers,
  cleanupAuthTests,
  authTestHooks,
  type AuthTestRenderOptions
} from './utils';

// Re-export commonly used defaults
import sessionDefault from './session';
import providerDefault from './provider';
import jwtDefault from './jwt';
import utilsDefault from './utils';

export {
  sessionDefault as sessionMocks,
  providerDefault as providerMocks,
  jwtDefault as jwtMocks,
  utilsDefault as testUtils
};

// Import functions for the test kit
import { setupAuthMocks, authAssertions, authMockFactories, renderWithAuth, cleanupAuthTests } from './utils';

// Convenience exports for common scenarios
export const nextAuthTestKit = {
  // Quick setup functions
  setupUser: () => setupAuthMocks({ isAuthenticated: true, role: 'USER' }),
  setupAdmin: () => setupAuthMocks({ isAuthenticated: true, role: 'ADMIN' }),
  setupUnauthenticated: () => setupAuthMocks({ isAuthenticated: false }),
  
  // Common assertions
  assertions: authAssertions,
  
  // Mock data factories
  factories: authMockFactories,
  
  // Test utilities
  render: renderWithAuth,
  cleanup: cleanupAuthTests
};

export default nextAuthTestKit; 