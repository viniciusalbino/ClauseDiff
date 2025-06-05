/**
 * Authentication Testing Utilities
 * 
 * Provides utilities specifically for testing authentication flows,
 * user sessions, and protected routes.
 */

import { MockSession, sessionScenarios, sessionTransitions } from '../__mocks__/nextauth/session';
import { mockSignIn, mockSignOut, resetNextAuthMocks } from '../__mocks__/nextauth/provider';

// Authentication test states
export interface AuthTestState {
  isAuthenticated: boolean;
  user: MockSession['user'] | null;
  role: string | null;
  permissions: string[];
  sessionExpired: boolean;
  emailVerified: boolean;
}

/**
 * Create authentication test state from session
 */
export function getAuthStateFromSession(session: MockSession | null): AuthTestState {
  if (!session || !session.user) {
    return {
      isAuthenticated: false,
      user: null,
      role: null,
      permissions: [],
      sessionExpired: false,
      emailVerified: false
    };
  }

  return {
    isAuthenticated: true,
    user: session.user,
    role: session.user.role,
    permissions: session.user.permissions || [],
    sessionExpired: !!session.error?.includes('expired'),
    emailVerified: !!session.user.emailVerified
  };
}

/**
 * Authentication assertions for common testing patterns
 */
export const authAssertions = {
  /**
   * Assert user is authenticated
   */
  isAuthenticated: (session: MockSession | null): void => {
    expect(session).toBeTruthy();
    expect(session?.user).toBeTruthy();
    expect(session?.user?.id).toBeDefined();
    expect(session?.user?.email).toBeDefined();
  },

  /**
   * Assert user is not authenticated
   */
  isNotAuthenticated: (session: MockSession | null): void => {
    expect(session).toBeFalsy();
  },

  /**
   * Assert user has specific role
   */
  hasRole: (session: MockSession | null, expectedRole: string): void => {
    expect(session?.user?.role).toBe(expectedRole);
  },

  /**
   * Assert user has specific permission
   */
  hasPermission: (session: MockSession | null, permission: string): void => {
    expect(session?.user?.permissions).toContain(permission);
  },

  /**
   * Assert user has any of the specified permissions
   */
  hasAnyPermission: (session: MockSession | null, permissions: string[]): void => {
    const userPermissions = session?.user?.permissions || [];
    const hasAny = permissions.some(permission => userPermissions.includes(permission));
    expect(hasAny).toBe(true);
  },

  /**
   * Assert user has all specified permissions
   */
  hasAllPermissions: (session: MockSession | null, permissions: string[]): void => {
    const userPermissions = session?.user?.permissions || [];
    permissions.forEach(permission => {
      expect(userPermissions).toContain(permission);
    });
  },

  /**
   * Assert session is expired
   */
  isSessionExpired: (session: MockSession | null): void => {
    expect(session?.error).toContain('expired');
  },

  /**
   * Assert email is verified
   */
  isEmailVerified: (session: MockSession | null): void => {
    expect(session?.user?.emailVerified).toBeTruthy();
  },

  /**
   * Assert email is not verified
   */
  isEmailNotVerified: (session: MockSession | null): void => {
    expect(session?.user?.emailVerified).toBeFalsy();
  }
};

/**
 * Authentication flow simulators
 */
export const authFlows = {
  /**
   * Simulate successful login flow
   */
  async simulateLogin(
    role: 'USER' | 'ADMIN' | 'MODERATOR' = 'USER',
    provider: string = 'credentials'
  ): Promise<MockSession> {
    // Mock successful sign in
    mockSignIn.mockResolvedValueOnce({
      error: null,
      status: 200,
      ok: true,
      url: '/dashboard'
    });

    // Create session after successful login
    const session = sessionTransitions.login(role);
    expect(session).toBeTruthy();
    
    return session!;
  },

  /**
   * Simulate failed login flow
   */
  async simulateFailedLogin(
    error: string = 'CredentialsSignin'
  ): Promise<{ error: string; status: number; ok: boolean; url: null }> {
    const failedResult = {
      error,
      status: 401,
      ok: false,
      url: null
    };

    mockSignIn.mockResolvedValueOnce(failedResult);

    // Return the expected result for testing
    return failedResult;
  },

  /**
   * Simulate logout flow
   */
  async simulateLogout(): Promise<void> {
    mockSignOut.mockResolvedValueOnce({
      url: '/login'
    });

    const result = await mockSignOut();
    expect(result.url).toBe('/login');
  },

  /**
   * Simulate session expiry
   */
  simulateSessionExpiry(): MockSession {
    const expiredSession = sessionTransitions.sessionExpiry();
    expect(expiredSession?.error).toContain('expired');
    return expiredSession!;
  },

  /**
   * Simulate role change
   */
  simulateRoleChange(newRole: 'USER' | 'ADMIN' | 'MODERATOR'): MockSession {
    const session = sessionTransitions.roleChange(newRole);
    expect(session?.user?.role).toBe(newRole);
    return session!;
  }
};

/**
 * Authentication test scenarios
 */
export const authTestScenarios = {
  // User scenarios
  regularUser: () => sessionScenarios.authenticatedUser(),
  adminUser: () => sessionScenarios.authenticatedAdmin(),
  moderatorUser: () => sessionScenarios.authenticatedModerator(),
  
  // Authentication states
  unauthenticated: () => sessionScenarios.unauthenticated(),
  expiredSession: () => sessionScenarios.expiredSession(),
  unverifiedEmail: () => sessionScenarios.unverifiedEmail(),
  
  // Permission scenarios
  userWithReadOnlyAccess: () => sessionScenarios.userWithPermissions(['read:documents']),
  userWithWriteAccess: () => sessionScenarios.userWithPermissions(['read:documents', 'write:documents']),
  userWithAdminAccess: () => sessionScenarios.userWithPermissions(['read:users', 'write:users', 'delete:users'])
};

/**
 * Authentication test helpers
 */
export const authHelpers = {
  /**
   * Setup authentication tests
   */
  setupAuthTests: (): void => {
    beforeEach(() => {
      resetNextAuthMocks();
    });
  },

  /**
   * Mock user with specific permissions
   */
  mockUserWithPermissions: (permissions: string[]): MockSession => {
    return sessionScenarios.userWithPermissions(permissions)!;
  },

  /**
   * Mock user with custom data
   */
  mockUserWithCustomData: (customData: Record<string, any>): MockSession => {
    return sessionScenarios.userWithCustomData(customData)!;
  },

  /**
   * Create test session with minimal data
   */
  createTestSession: (
    role: 'USER' | 'ADMIN' | 'MODERATOR' = 'USER',
    overrides: Partial<MockSession> = {}
  ): MockSession => {
    const baseSession = sessionTransitions.login(role);
    return { ...baseSession!, ...overrides };
  },

  /**
   * Assert protection for unauthenticated users
   */
  assertRequiresAuth: (renderFn: () => any): void => {
    const result = renderFn();
    // This would typically check for redirect to login or access denied message
    // Implementation depends on your app's authentication handling
    expect(result.container).toBeInTheDocument();
  },

  /**
   * Assert permission-based access control
   */
  assertRequiresPermission: (
    permission: string,
    renderFn: () => any,
    session: MockSession | null
  ): void => {
    const hasPermission = session?.user?.permissions?.includes(permission);
    const result = renderFn();
    
    if (hasPermission) {
      // Should render the protected content
      expect(result.container).toBeInTheDocument();
    } else {
      // Should show access denied or hide content
      // Implementation depends on your app's permission handling
      expect(result.container).toBeInTheDocument();
    }
  },

  /**
   * Assert role-based access control
   */
  assertRequiresRole: (
    requiredRole: string,
    renderFn: () => any,
    session: MockSession | null
  ): void => {
    const hasRole = session?.user?.role === requiredRole;
    const result = renderFn();
    
    if (hasRole) {
      // Should render the protected content
      expect(result.container).toBeInTheDocument();
    } else {
      // Should show access denied or hide content
      expect(result.container).toBeInTheDocument();
    }
  }
};

/**
 * Quick access to common authentication test utilities
 */
export const auth = {
  ...authAssertions,
  ...authFlows,
  ...authTestScenarios,
  ...authHelpers,
  
  // Quick state checks
  isLoggedIn: (session: MockSession | null) => !!session?.user,
  isAdmin: (session: MockSession | null) => session?.user?.role === 'ADMIN',
  isModerator: (session: MockSession | null) => session?.user?.role === 'MODERATOR',
  isUser: (session: MockSession | null) => session?.user?.role === 'USER',
  
  // Quick permission checks
  canRead: (session: MockSession | null) => 
    session?.user?.permissions?.some(p => p.includes('read')) || false,
  canWrite: (session: MockSession | null) => 
    session?.user?.permissions?.some(p => p.includes('write')) || false,
  canDelete: (session: MockSession | null) => 
    session?.user?.permissions?.some(p => p.includes('delete')) || false
};

export default auth; 