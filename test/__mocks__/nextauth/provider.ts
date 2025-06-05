/**
 * NextAuth Provider Mocking Utilities
 * 
 * Provides mock implementations of NextAuth providers and hooks
 * for testing components that depend on authentication.
 */

import React from 'react';
import { SessionProvider } from 'next-auth/react';
import { MockSession, MockSessionOptions, createMockSession } from './session';

export interface MockSessionProviderProps {
  children: React.ReactNode;
  session?: MockSession | null;
  sessionOptions?: MockSessionOptions;
}

/**
 * Mock SessionProvider for testing
 */
export function MockSessionProvider({ 
  children, 
  session, 
  sessionOptions 
}: MockSessionProviderProps) {
  const mockSession = session ?? createMockSession(sessionOptions);
  
  return React.createElement(
    SessionProvider,
    { 
      session: mockSession,
      basePath: '/api/auth',
      refetchInterval: 0,
      refetchOnWindowFocus: false,
      children
    }
  );
}

/**
 * Mock useSession hook for testing
 */
export function createMockUseSession(options: MockSessionOptions = {}) {
  const mockSession = createMockSession(options);
  
  return jest.fn(() => ({
    data: mockSession,
    status: mockSession ? 'authenticated' : 'unauthenticated',
    update: jest.fn(),
  }));
}

/**
 * Mock signIn function for testing
 */
export const mockSignIn = jest.fn().mockImplementation((provider?: string, options?: any) => {
  return Promise.resolve({
    error: null,
    status: 200,
    ok: true,
    url: options?.callbackUrl || '/dashboard'
  });
});

/**
 * Mock signOut function for testing
 */
export const mockSignOut = jest.fn().mockImplementation((options?: any) => {
  return Promise.resolve({
    url: options?.callbackUrl || '/login'
  });
});

/**
 * Mock getSession function for testing
 */
export function createMockGetSession(options: MockSessionOptions = {}) {
  const mockSession = createMockSession(options);
  
  return jest.fn().mockResolvedValue(mockSession);
}

/**
 * Mock getCsrfToken function for testing
 */
export const mockGetCsrfToken = jest.fn().mockResolvedValue('mock-csrf-token');

/**
 * Mock getProviders function for testing
 */
export const mockGetProviders = jest.fn().mockResolvedValue({
  credentials: {
    id: 'credentials',
    name: 'Credentials',
    type: 'credentials',
    signinUrl: '/api/auth/signin/credentials',
    callbackUrl: '/api/auth/callback/credentials'
  },
  google: {
    id: 'google',
    name: 'Google',
    type: 'oauth',
    signinUrl: '/api/auth/signin/google',
    callbackUrl: '/api/auth/callback/google'
  }
});

/**
 * Complete NextAuth mocks for jest.mock()
 */
export const nextAuthMocks = {
  useSession: createMockUseSession(),
  signIn: mockSignIn,
  signOut: mockSignOut,
  getSession: createMockGetSession(),
  getCsrfToken: mockGetCsrfToken,
  getProviders: mockGetProviders,
  SessionProvider: MockSessionProvider
};

/**
 * Helper function to reset all NextAuth mocks
 */
export function resetNextAuthMocks() {
  mockSignIn.mockClear();
  mockSignOut.mockClear();
  mockGetCsrfToken.mockClear();
  mockGetProviders.mockClear();
}

/**
 * Common test scenarios for NextAuth mocking
 */
export const authProviderScenarios = {
  // Basic authentication scenarios
  authenticatedUser: () => ({
    useSession: createMockUseSession({ isAuthenticated: true, role: 'USER' }),
    getSession: createMockGetSession({ isAuthenticated: true, role: 'USER' })
  }),
  
  authenticatedAdmin: () => ({
    useSession: createMockUseSession({ isAuthenticated: true, role: 'ADMIN' }),
    getSession: createMockGetSession({ isAuthenticated: true, role: 'ADMIN' })
  }),
  
  unauthenticated: () => ({
    useSession: createMockUseSession({ isAuthenticated: false }),
    getSession: createMockGetSession({ isAuthenticated: false })
  }),
  
  // Error scenarios
  sessionExpired: () => ({
    useSession: createMockUseSession({ isAuthenticated: true, sessionExpired: true }),
    getSession: createMockGetSession({ isAuthenticated: true, sessionExpired: true })
  }),
  
  // Sign in/out scenarios
  successfulSignIn: () => {
    mockSignIn.mockResolvedValueOnce({
      error: null,
      status: 200,
      ok: true,
      url: '/dashboard'
    });
  },
  
  failedSignIn: () => {
    mockSignIn.mockResolvedValueOnce({
      error: 'CredentialsSignin',
      status: 401,
      ok: false,
      url: null
    });
  },
  
  successfulSignOut: () => {
    mockSignOut.mockResolvedValueOnce({
      url: '/login'
    });
  }
};

export default {
  MockSessionProvider,
  createMockUseSession,
  mockSignIn,
  mockSignOut,
  createMockGetSession,
  mockGetCsrfToken,
  mockGetProviders,
  nextAuthMocks,
  resetNextAuthMocks,
  authProviderScenarios
}; 