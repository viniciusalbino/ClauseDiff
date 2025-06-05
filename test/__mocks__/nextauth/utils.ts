/**
 * NextAuth Testing Helper Utilities
 * 
 * Common utilities and helpers for testing authentication-related
 * functionality in the ClauseDiff application.
 */

import { render, RenderOptions } from '@testing-library/react';
import React from 'react';
import { MockSessionProvider, MockSessionProviderProps } from './provider';
import { MockSessionOptions } from './session';
import { resetNextAuthMocks } from './provider';
import { resetJWTMocks } from './jwt';

export interface AuthTestRenderOptions extends Omit<RenderOptions, 'wrapper'> {
  sessionOptions?: MockSessionOptions;
  providerProps?: Partial<MockSessionProviderProps>;
}

/**
 * Custom render function for testing components that use NextAuth
 */
export function renderWithAuth(
  ui: React.ReactElement,
  options: AuthTestRenderOptions = {}
) {
  const { sessionOptions, providerProps, ...renderOptions } = options;

  const Wrapper = ({ children }: { children: React.ReactNode }) => 
    React.createElement(MockSessionProvider, { sessionOptions, children, ...providerProps });

  return render(ui, { wrapper: Wrapper, ...renderOptions });
}

/**
 * Helper function to setup authentication mocks for tests
 */
export function setupAuthMocks(options: MockSessionOptions = {}) {
  // Reset all mocks before setting up new ones
  resetNextAuthMocks();
  resetJWTMocks();

  // Return mock functions for further customization
  return {
    renderWithAuth: (ui: React.ReactElement, renderOptions?: AuthTestRenderOptions) =>
      renderWithAuth(ui, { sessionOptions: options, ...renderOptions })
  };
}

/**
 * Test scenario helpers for common authentication states
 */
export const authTestScenarios = {
  // Authenticated scenarios
  withAuthenticatedUser: (customOptions: Partial<MockSessionOptions> = {}) => 
    setupAuthMocks({ isAuthenticated: true, role: 'USER', ...customOptions }),

  withAuthenticatedAdmin: (customOptions: Partial<MockSessionOptions> = {}) =>
    setupAuthMocks({ isAuthenticated: true, role: 'ADMIN', ...customOptions }),

  withAuthenticatedModerator: (customOptions: Partial<MockSessionOptions> = {}) =>
    setupAuthMocks({ isAuthenticated: true, role: 'MODERATOR', ...customOptions }),

  // Unauthenticated scenarios
  withUnauthenticatedUser: () =>
    setupAuthMocks({ isAuthenticated: false }),

  // Special scenarios
  withExpiredSession: () =>
    setupAuthMocks({ isAuthenticated: true, sessionExpired: true }),

  withUnverifiedEmail: () =>
    setupAuthMocks({ isAuthenticated: true, emailVerified: false }),

  withCustomPermissions: (permissions: string[]) =>
    setupAuthMocks({ isAuthenticated: true, permissions })
};

/**
 * Assertion helpers for authentication testing
 */
export const authAssertions = {
  // Session state assertions
  expectUserToBeAuthenticated: (component: HTMLElement) => {
    expect(component).not.toHaveTextContent('Sign in');
    expect(component).not.toHaveTextContent('Login');
  },

  expectUserToBeUnauthenticated: (component: HTMLElement) => {
    const loginRegex = /sign in|login/i;
    expect(component).toHaveTextContent(loginRegex);
  },

  // Role-based assertions
  expectUserToHaveRole: (component: HTMLElement, role: string) => {
    // This would depend on how role is displayed in your UI
    expect(component).toHaveAttribute('data-user-role', role);
  },

  expectUserToHavePermission: (component: HTMLElement, permission: string) => {
    // This would depend on how permissions are reflected in your UI
    expect(component).toHaveAttribute('data-user-permissions', expect.stringContaining(permission));
  },

  // Navigation assertions
  expectRedirectToLogin: () => {
    // Mock window.location or Next.js router for redirect assertions
    expect(window.location.href).toContain('/login');
  },

  expectRedirectToDashboard: () => {
    expect(window.location.href).toContain('/dashboard');
  }
};

/**
 * Mock data factories for authentication testing
 */
export const authMockFactories = {
  // User data factories
  createTestUser: (overrides: Record<string, any> = {}) => ({
    id: 'test-user-1',
    email: 'test@example.com',
    name: 'Test User',
    firstName: 'Test',
    lastName: 'User',
    role: 'USER',
    emailVerified: new Date(),
    createdAt: new Date(),
    image: null,
    ...overrides
  }),

  createTestAdmin: (overrides: Record<string, any> = {}) => ({
    id: 'test-admin-1',
    email: 'admin@example.com',
    name: 'Test Admin',
    firstName: 'Test',
    lastName: 'Admin',
    role: 'ADMIN',
    emailVerified: new Date(),
    createdAt: new Date(),
    image: null,
    ...overrides
  }),

  // Authentication flow data
  createLoginCredentials: (overrides: Record<string, any> = {}) => ({
    email: 'test@example.com',
    password: 'password123',
    ...overrides
  }),

  createSignupData: (overrides: Record<string, any> = {}) => ({
    firstName: 'Test',
    lastName: 'User',
    email: 'test@example.com',
    password: 'password123',
    confirmPassword: 'password123',
    ...overrides
  })
};

/**
 * Integration test helpers for authentication flows
 */
export const authFlowHelpers = {
  // Simulate login flow
  simulateLogin: async (credentials = authMockFactories.createLoginCredentials()) => {
    // Mock the login process
    return {
      success: true,
      user: authMockFactories.createTestUser({ email: credentials.email })
    };
  },

  // Simulate logout flow
  simulateLogout: async () => {
    return { success: true };
  },

  // Simulate registration flow
  simulateRegistration: async (userData = authMockFactories.createSignupData()) => {
    return {
      success: true,
      user: authMockFactories.createTestUser({ 
        email: userData.email,
        firstName: userData.firstName,
        lastName: userData.lastName
      })
    };
  },

  // Simulate password reset flow
  simulatePasswordReset: async (email: string) => {
    return {
      success: true,
      message: 'Password reset email sent'
    };
  }
};

/**
 * Helper to clean up after authentication tests
 */
export function cleanupAuthTests() {
  resetNextAuthMocks();
  resetJWTMocks();
  
  // Reset any global state if needed
  if (typeof window !== 'undefined') {
    // Reset localStorage/sessionStorage if your app uses it
    localStorage.clear();
    sessionStorage.clear();
  }
}

/**
 * Custom hooks for testing authentication behavior
 */
export const authTestHooks = {
  // Hook to test component behavior on auth state changes
  useAuthStateTransition: (
    component: React.ReactElement,
    fromState: MockSessionOptions
  ) => {
    const { rerender } = renderWithAuth(component, { sessionOptions: fromState });
    
    return {
      transitionTo: (newState: MockSessionOptions) => {
        const wrapper = React.createElement(MockSessionProvider, { sessionOptions: newState, children: component });
        rerender(wrapper);
      }
    };
  }
};

export default {
  renderWithAuth,
  setupAuthMocks,
  authTestScenarios,
  authAssertions,
  authMockFactories,
  authFlowHelpers,
  cleanupAuthTests,
  authTestHooks
}; 