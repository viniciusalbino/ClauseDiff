/**
 * NextAuth Session Mocking Utilities
 * 
 * Provides utilities for mocking NextAuth sessions in tests,
 * including different user states, roles, and authentication scenarios.
 */

import { Session } from 'next-auth';
import { JWT } from 'next-auth/jwt';
import { generateMockUser } from '../api/utils';

export interface MockSessionOptions {
  role?: 'USER' | 'ADMIN' | 'MODERATOR';
  isAuthenticated?: boolean;
  sessionExpired?: boolean;
  emailVerified?: boolean;
  permissions?: string[];
  customData?: Record<string, any>;
}

export interface MockSession extends Session {
  user: {
    id: string;
    email: string;
    name: string;
    firstName?: string;
    lastName?: string;
    role: string;
    image?: string;
    emailVerified?: Date | null;
    permissions?: string[];
  };
  expires: string;
  accessToken?: string;
  error?: string;
}

/**
 * Creates a mock NextAuth session for testing
 */
export function createMockSession(options: MockSessionOptions = {}): MockSession | null {
  const {
    role = 'USER',
    isAuthenticated = true,
    sessionExpired = false,
    emailVerified = true,
    permissions = [],
    customData = {}
  } = options;

  if (!isAuthenticated) {
    return null;
  }

  const mockUser = generateMockUser({ 
    role: role.toLowerCase(),
    emailVerified: emailVerified ? new Date() : null,
    ...customData 
  });

  const expiryDate = sessionExpired 
    ? new Date(Date.now() - 60 * 60 * 1000).toISOString() // 1 hour ago
    : new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(); // 30 days from now

  return {
    user: {
      id: mockUser.id,
      email: mockUser.email,
      name: mockUser.name,
      firstName: mockUser.firstName,
      lastName: mockUser.lastName,
      role,
      image: mockUser.image || undefined,
      emailVerified: mockUser.emailVerified || undefined,
      permissions: permissions.length > 0 ? permissions : getDefaultPermissions(role)
    },
    expires: expiryDate,
    accessToken: 'mock-access-token',
    ...(sessionExpired && { error: 'Session expired' })
  };
}

/**
 * Creates a mock JWT token for testing
 */
export function createMockJWT(options: MockSessionOptions = {}): JWT {
  const session = createMockSession(options);
  
  if (!session) {
    return {} as JWT;
  }

  return {
    name: session.user.name,
    email: session.user.email,
    picture: session.user.image,
    sub: session.user.id,
    id: session.user.id,
    role: session.user.role,
    permissions: session.user.permissions,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(new Date(session.expires).getTime() / 1000),
    jti: 'mock-jwt-id'
  };
}

/**
 * Gets default permissions for a role
 */
function getDefaultPermissions(role: string): string[] {
  switch (role) {
    case 'ADMIN':
      return [
        'read:users',
        'write:users',
        'delete:users',
        'read:audit',
        'write:audit',
        'read:documents',
        'write:documents',
        'delete:documents',
        'manage:system'
      ];
    case 'MODERATOR':
      return [
        'read:users',
        'read:audit',
        'read:documents',
        'write:documents',
        'moderate:content'
      ];
    case 'USER':
    default:
      return [
        'read:documents',
        'write:documents',
        'read:profile',
        'write:profile'
      ];
  }
}

/**
 * Session state factories for common testing scenarios
 */
export const sessionScenarios = {
  // Authenticated user scenarios
  authenticatedUser: () => createMockSession({ isAuthenticated: true, role: 'USER' }),
  authenticatedAdmin: () => createMockSession({ isAuthenticated: true, role: 'ADMIN' }),
  authenticatedModerator: () => createMockSession({ isAuthenticated: true, role: 'MODERATOR' }),
  
  // Unauthenticated scenarios
  unauthenticated: () => createMockSession({ isAuthenticated: false }),
  
  // Session issues
  expiredSession: () => createMockSession({ isAuthenticated: true, sessionExpired: true }),
  unverifiedEmail: () => createMockSession({ isAuthenticated: true, emailVerified: false }),
  
  // Custom scenarios
  userWithPermissions: (permissions: string[]) => 
    createMockSession({ isAuthenticated: true, permissions }),
  
  userWithCustomData: (customData: Record<string, any>) =>
    createMockSession({ isAuthenticated: true, customData })
};

/**
 * Session transition utilities for testing authentication flows
 */
export const sessionTransitions = {
  login: (role: 'USER' | 'ADMIN' | 'MODERATOR' = 'USER') => 
    createMockSession({ isAuthenticated: true, role }),
  
  logout: () => null,
  
  sessionExpiry: () => 
    createMockSession({ isAuthenticated: true, sessionExpired: true }),
  
  roleChange: (newRole: 'USER' | 'ADMIN' | 'MODERATOR') =>
    createMockSession({ isAuthenticated: true, role: newRole }),
  
  permissionUpdate: (permissions: string[]) =>
    createMockSession({ isAuthenticated: true, permissions })
};

export default {
  createMockSession,
  createMockJWT,
  sessionScenarios,
  sessionTransitions
}; 