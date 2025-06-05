/**
 * NextAuth Mocking Utilities Tests
 * 
 * Comprehensive tests to verify that our NextAuth mocking utilities
 * work correctly and provide the expected functionality.
 */

import { 
  createMockSession, 
  createMockJWT,
  sessionScenarios,
  createMockToken,
  jwtScenarios,
  nextAuthTestKit
} from '../../__mocks__/nextauth';

describe('NextAuth Mocking Utilities', () => {
  describe('Session Mocking', () => {
    it('should create a basic authenticated session', () => {
      const session = createMockSession({ isAuthenticated: true, role: 'USER' });
      
      expect(session).toBeTruthy();
      expect(session?.user.role).toBe('USER');
      expect(session?.user.email).toMatch(/@example\.com$/);
      expect(session?.expires).toBeTruthy();
    });

    it('should return null for unauthenticated session', () => {
      const session = createMockSession({ isAuthenticated: false });
      
      expect(session).toBeNull();
    });

    it('should create session with custom permissions', () => {
      const permissions = ['read:users', 'write:documents'];
      const session = createMockSession({ 
        isAuthenticated: true, 
        permissions 
      });
      
      expect(session?.user.permissions).toEqual(permissions);
    });

    it('should create expired session', () => {
      const session = createMockSession({ 
        isAuthenticated: true, 
        sessionExpired: true 
      });
      
      expect(session?.error).toBe('Session expired');
      expect(new Date(session?.expires || '').getTime()).toBeLessThan(Date.now());
    });

    it('should handle unverified email', () => {
      const session = createMockSession({ 
        isAuthenticated: true, 
        emailVerified: false 
      });
      
      expect(session?.user.emailVerified).toBeUndefined();
    });
  });

  describe('Session Scenarios', () => {
    it('should provide authenticated user scenario', () => {
      const session = sessionScenarios.authenticatedUser();
      
      expect(session?.user.role).toBe('USER');
      expect(session).toBeTruthy();
    });

    it('should provide authenticated admin scenario', () => {
      const session = sessionScenarios.authenticatedAdmin();
      
      expect(session?.user.role).toBe('ADMIN');
      expect(session?.user.permissions).toContain('manage:system');
    });

    it('should provide unauthenticated scenario', () => {
      const session = sessionScenarios.unauthenticated();
      
      expect(session).toBeNull();
    });

    it('should provide expired session scenario', () => {
      const session = sessionScenarios.expiredSession();
      
      expect(session?.error).toBe('Session expired');
    });
  });

  describe('JWT Token Mocking', () => {
    it('should create a basic JWT token', () => {
      const token = createMockToken({ isAuthenticated: true, role: 'USER' });
      
      expect(token.sub).toBeTruthy();
      expect(token.email).toMatch(/@example\.com$/);
      expect(token.role).toBe('USER');
      expect(token.iat).toBeTruthy();
      expect(token.exp).toBeTruthy();
    });

    it('should create JWT with custom claims', () => {
      const permissions = ['read:admin', 'write:users'];
      const token = createMockToken({ 
        isAuthenticated: true, 
        permissions,
        customData: { department: 'IT' }
      });
      
      expect(token.permissions).toEqual(permissions);
             expect(typeof token.exp === 'number' ? token.exp : 0).toBeGreaterThan(typeof token.iat === 'number' ? token.iat : 0);
    });

    it('should create expired JWT token', () => {
      const token = createMockToken({ 
        isAuthenticated: true, 
        sessionExpired: true 
      });
      
      expect(token.exp).toBeLessThan(Math.floor(Date.now() / 1000));
    });
  });

  describe('JWT Scenarios', () => {
    it('should provide valid user token', () => {
      const token = jwtScenarios.validUserToken();
      
      expect(token.role).toBe('USER');
      expect(token.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
    });

    it('should provide valid admin token', () => {
      const token = jwtScenarios.validAdminToken();
      
      expect(token.role).toBe('ADMIN');
      expect(token.permissions).toContain('manage:system');
    });

    it('should provide expired token', () => {
      const token = jwtScenarios.expiredToken();
      
      expect(token.exp).toBeLessThan(Math.floor(Date.now() / 1000));
    });

    it('should provide invalid token scenario', () => {
      const token = jwtScenarios.invalidToken();
      
      expect(token).toBeNull();
    });
  });

  describe('NextAuth Test Kit', () => {
    it('should provide quick setup functions', () => {
      expect(typeof nextAuthTestKit.setupUser).toBe('function');
      expect(typeof nextAuthTestKit.setupAdmin).toBe('function');
      expect(typeof nextAuthTestKit.setupUnauthenticated).toBe('function');
    });

    it('should provide test utilities', () => {
      expect(typeof nextAuthTestKit.render).toBe('function');
      expect(typeof nextAuthTestKit.cleanup).toBe('function');
      expect(nextAuthTestKit.assertions).toBeTruthy();
      expect(nextAuthTestKit.factories).toBeTruthy();
    });

    it('should setup user authentication correctly', () => {
      const { renderWithAuth } = nextAuthTestKit.setupUser();
      
      expect(typeof renderWithAuth).toBe('function');
    });
  });

  describe('Mock Data Factories', () => {
    it('should create test user data', () => {
      const user = nextAuthTestKit.factories.createTestUser();
      
      expect(user.id).toBe('test-user-1');
      expect(user.email).toBe('test@example.com');
      expect(user.role).toBe('USER');
    });

    it('should create test admin data', () => {
      const admin = nextAuthTestKit.factories.createTestAdmin();
      
      expect(admin.role).toBe('ADMIN');
      expect(admin.email).toBe('admin@example.com');
    });

    it('should create login credentials', () => {
      const credentials = nextAuthTestKit.factories.createLoginCredentials();
      
      expect(credentials.email).toBe('test@example.com');
      expect(credentials.password).toBe('password123');
    });

    it('should create signup data', () => {
      const signupData = nextAuthTestKit.factories.createSignupData();
      
      expect(signupData.firstName).toBe('Test');
      expect(signupData.lastName).toBe('User');
      expect(signupData.email).toBe('test@example.com');
      expect(signupData.password).toBe('password123');
      expect(signupData.confirmPassword).toBe('password123');
    });

    it('should allow overrides in factory functions', () => {
      const customUser = nextAuthTestKit.factories.createTestUser({
        email: 'custom@example.com',
        name: 'Custom User'
      });
      
      expect(customUser.email).toBe('custom@example.com');
      expect(customUser.name).toBe('Custom User');
      expect(customUser.id).toBe('test-user-1'); // Default value preserved
    });
  });

  describe('Permission System Integration', () => {
    it('should create sessions with default permissions for roles', () => {
      const userSession = createMockSession({ role: 'USER' });
      const adminSession = createMockSession({ role: 'ADMIN' });
      
      expect(userSession?.user.permissions).toContain('read:documents');
      expect(userSession?.user.permissions).toContain('write:documents');
      expect(userSession?.user.permissions).not.toContain('manage:system');
      
      expect(adminSession?.user.permissions).toContain('read:documents');
      expect(adminSession?.user.permissions).toContain('manage:system');
      expect(adminSession?.user.permissions).toContain('read:users');
    });

    it('should override default permissions when specified', () => {
      const customPermissions = ['custom:permission', 'special:access'];
      const session = createMockSession({ 
        role: 'USER', 
        permissions: customPermissions 
      });
      
      expect(session?.user.permissions).toEqual(customPermissions);
    });
  });

  describe('Error Scenarios', () => {
    it('should handle session creation with invalid data gracefully', () => {
      const session = createMockSession({ 
        isAuthenticated: true,
        customData: { invalidField: undefined }
      });
      
      expect(session).toBeTruthy();
      expect(session?.user).toBeTruthy();
    });

    it('should handle JWT creation for unauthenticated users', () => {
      const jwt = createMockJWT({ isAuthenticated: false });
      
      expect(Object.keys(jwt).length).toBe(0);
    });
  });
}); 