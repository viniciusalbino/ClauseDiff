/**
 * NextAuth JWT Token Mocking Utilities
 * 
 * Provides utilities for mocking JWT tokens and JWT-related
 * operations in NextAuth testing scenarios.
 */

import { JWT } from 'next-auth/jwt';
import { createMockJWT, MockSessionOptions } from './session';

export interface MockJWTOptions extends MockSessionOptions {
  issuer?: string;
  audience?: string;
  algorithm?: string;
  secret?: string;
}

/**
 * Creates a mock JWT token with custom options
 */
export function createMockToken(options: MockJWTOptions = {}): JWT {
  const {
    issuer = 'test-issuer',
    audience = 'test-audience',
    algorithm = 'HS256',
    secret = 'test-secret',
    ...sessionOptions
  } = options;

  const baseToken = createMockJWT(sessionOptions);

  return {
    ...baseToken,
    iss: issuer,
    aud: audience,
    alg: algorithm,
    secret,
    // Additional JWT claims
    nbf: Math.floor(Date.now() / 1000),
    azp: 'test-client-id',
    scope: 'openid profile email'
  };
}

/**
 * Mock getToken function from next-auth/jwt
 */
export function createMockGetToken(options: MockJWTOptions = {}) {
  const mockToken = createMockToken(options);
  
  return jest.fn().mockResolvedValue(mockToken);
}

/**
 * Mock JWT encoding function
 */
export const mockJWTEncode = jest.fn().mockImplementation(async (params: any) => {
  const { token, secret } = params;
  return `mock.jwt.token.${Buffer.from(JSON.stringify(token)).toString('base64')}`;
});

/**
 * Mock JWT decoding function
 */
export const mockJWTDecode = jest.fn().mockImplementation(async (params: any) => {
  const { token } = params;
  
  if (!token || !token.includes('mock.jwt.token.')) {
    return null;
  }
  
  try {
    const payload = token.split('.')[3];
    return JSON.parse(Buffer.from(payload, 'base64').toString());
  } catch {
    return null;
  }
});

/**
 * JWT token scenarios for testing
 */
export const jwtScenarios = {
  // Valid tokens
  validUserToken: () => createMockToken({ 
    isAuthenticated: true, 
    role: 'USER' 
  }),
  
  validAdminToken: () => createMockToken({ 
    isAuthenticated: true, 
    role: 'ADMIN' 
  }),
  
  // Expired tokens
  expiredToken: () => createMockToken({ 
    isAuthenticated: true, 
    sessionExpired: true 
  }),
  
  // Invalid tokens
  invalidToken: () => null,
  
  // Tokens with custom claims
  tokenWithPermissions: (permissions: string[]) => createMockToken({
    isAuthenticated: true,
    permissions
  }),
  
  tokenWithCustomClaims: (customData: Record<string, any>) => createMockToken({
    isAuthenticated: true,
    customData
  })
};

/**
 * JWT operation mocks for testing token flows
 */
export const jwtOperations = {
  encode: mockJWTEncode,
  decode: mockJWTDecode,
  getToken: createMockGetToken(),
  
  // Token validation scenarios
  validateToken: jest.fn().mockImplementation((token: string) => {
    return token && token.includes('mock.jwt.token.');
  }),
  
  // Token refresh scenarios
  refreshToken: jest.fn().mockImplementation(async (token: JWT) => {
    return {
      ...token,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600 // 1 hour from now
    };
  }),
  
  // Token verification scenarios
  verifyToken: jest.fn().mockImplementation(async (token: string) => {
    if (!token || !token.includes('mock.jwt.token.')) {
      throw new Error('Invalid token');
    }
    return true;
  })
};

/**
 * Helper function to reset all JWT mocks
 */
export function resetJWTMocks() {
  mockJWTEncode.mockClear();
  mockJWTDecode.mockClear();
  jwtOperations.getToken.mockClear();
  jwtOperations.validateToken.mockClear();
  jwtOperations.refreshToken.mockClear();
  jwtOperations.verifyToken.mockClear();
}

/**
 * Mock JWT middleware for testing protected routes
 */
export function createMockJWTMiddleware(options: MockJWTOptions = {}) {
  return jest.fn().mockImplementation(async (req: any, res: any, next: any) => {
    const token = createMockToken(options);
    
    if (token && !options.sessionExpired) {
      req.user = token;
      req.token = token;
      return next();
    } else {
      return res.status(401).json({ error: 'Unauthorized' });
    }
  });
}

/**
 * JWT test utilities for specific scenarios
 */
export const jwtTestUtils = {
  // Create tokens for different user types
  createUserToken: () => createMockToken({ role: 'USER' }),
  createAdminToken: () => createMockToken({ role: 'ADMIN' }),
  createModeratorToken: () => createMockToken({ role: 'MODERATOR' }),
  
  // Create tokens with specific expiration
  createExpiringToken: (expiresInSeconds: number) => {
    const token = createMockToken();
    return {
      ...token,
      exp: Math.floor(Date.now() / 1000) + expiresInSeconds
    };
  },
  
  // Create tokens with custom permissions
  createTokenWithPermissions: (permissions: string[]) => 
    createMockToken({ permissions }),
  
  // Token validation helpers
  isTokenExpired: (token: JWT) => {
    return typeof token.exp === 'number' && token.exp < Math.floor(Date.now() / 1000);
  },
  
  hasPermission: (token: JWT, permission: string) => {
    return Array.isArray(token.permissions) && token.permissions.includes(permission);
  },
  
  hasRole: (token: JWT, role: string) => {
    return token.role === role;
  }
};

export default {
  createMockToken,
  createMockGetToken,
  mockJWTEncode,
  mockJWTDecode,
  jwtScenarios,
  jwtOperations,
  resetJWTMocks,
  createMockJWTMiddleware,
  jwtTestUtils
}; 