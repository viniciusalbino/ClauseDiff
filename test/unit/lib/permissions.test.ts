/**
 * Comprehensive Unit Tests for Server-Side Permission Utilities
 */

import { getServerSession } from 'next-auth/next';
import { getToken } from 'next-auth/jwt';

// Mock NextAuth functions
jest.mock('next-auth/next', () => ({
  getServerSession: jest.fn(),
}));

jest.mock('next-auth/jwt', () => ({
  getToken: jest.fn(),
}));

jest.mock('../../../src/lib/auth-config', () => ({
  authOptions: {}
}));

// Import functions after mocking
import {
  ROLES,
  PERMISSIONS,
  getUserPermissions,
  roleHasPermission,
  userHasPermission,
  userHasRole,
  getCurrentUser,
  requireAuthentication,
  type Role,
  type Permission
} from '../../../src/lib/permissions';

const mockGetServerSession = getServerSession as jest.MockedFunction<typeof getServerSession>;

describe('Server-Side Permission Utilities', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    process.env.NEXTAUTH_SECRET = 'test-secret';
  });

  describe('Basic Permission Functions', () => {
    describe('getUserPermissions', () => {
      it('should return empty array for null role', () => {
        const permissions = getUserPermissions(null);
        expect(permissions).toEqual([]);
      });

      it('should return correct permissions for USER role', () => {
        const permissions = getUserPermissions(ROLES.USER);
        
        expect(permissions).toContain(PERMISSIONS.DOCUMENT_READ);
        expect(permissions).toContain(PERMISSIONS.DOCUMENT_WRITE);
        expect(permissions).not.toContain(PERMISSIONS.ADMIN_PANEL);
      });

      it('should return all permissions for ADMIN role', () => {
        const permissions = getUserPermissions(ROLES.ADMIN);
        const allPermissions = Object.values(PERMISSIONS);
        
        allPermissions.forEach(permission => {
          expect(permissions).toContain(permission);
        });
      });
    });

    describe('roleHasPermission', () => {
      it('should return false for null role', () => {
        const result = roleHasPermission(null, PERMISSIONS.DOCUMENT_READ);
        expect(result).toBe(false);
      });

      it('should validate USER permissions correctly', () => {
        expect(roleHasPermission(ROLES.USER, PERMISSIONS.DOCUMENT_READ)).toBe(true);
        expect(roleHasPermission(ROLES.USER, PERMISSIONS.ADMIN_PANEL)).toBe(false);
      });

      it('should validate ADMIN permissions correctly', () => {
        const allPermissions = Object.values(PERMISSIONS);
        
        allPermissions.forEach(permission => {
          expect(roleHasPermission(ROLES.ADMIN, permission)).toBe(true);
        });
      });
    });
  });

  describe('Server-Side Session Functions', () => {
    describe('userHasPermission', () => {
      it('should return false when no session exists', async () => {
        mockGetServerSession.mockResolvedValue(null);
        
        const result = await userHasPermission(PERMISSIONS.DOCUMENT_READ);
        expect(result).toBe(false);
      });

      it('should return true when user has required permission', async () => {
        mockGetServerSession.mockResolvedValue({
          user: { id: '1', email: 'test@example.com', role: 'USER' }
        } as any);
        
        const result = await userHasPermission(PERMISSIONS.DOCUMENT_READ);
        expect(result).toBe(true);
      });

      it('should return false when user lacks required permission', async () => {
        mockGetServerSession.mockResolvedValue({
          user: { id: '1', email: 'test@example.com', role: 'USER' }
        } as any);
        
        const result = await userHasPermission(PERMISSIONS.ADMIN_PANEL);
        expect(result).toBe(false);
      });
    });

    describe('userHasRole', () => {
      it('should return false when no session exists', async () => {
        mockGetServerSession.mockResolvedValue(null);
        
        const result = await userHasRole(ROLES.USER);
        expect(result).toBe(false);
      });

      it('should return true for matching role', async () => {
        mockGetServerSession.mockResolvedValue({
          user: { id: '1', email: 'test@example.com', role: 'USER' }
        } as any);
        
        const result = await userHasRole(ROLES.USER);
        expect(result).toBe(true);
      });

      it('should return false for non-matching role', async () => {
        mockGetServerSession.mockResolvedValue({
          user: { id: '1', email: 'test@example.com', role: 'USER' }
        } as any);
        
        const result = await userHasRole(ROLES.ADMIN);
        expect(result).toBe(false);
      });
    });

    describe('getCurrentUser', () => {
      it('should return null when no session exists', async () => {
        mockGetServerSession.mockResolvedValue(null);
        
        const result = await getCurrentUser();
        expect(result).toBeNull();
      });

      it('should return user with permissions for valid session', async () => {
        mockGetServerSession.mockResolvedValue({
          user: { 
            id: '1', 
            email: 'test@example.com', 
            name: 'Test User',
            role: 'USER' 
          }
        } as any);
        
        const result = await getCurrentUser();
        
        expect(result).toEqual({
          id: '1',
          email: 'test@example.com',
          name: 'Test User',
          role: 'USER',
          permissions: expect.arrayContaining([
            PERMISSIONS.DOCUMENT_READ,
            PERMISSIONS.DOCUMENT_WRITE
          ])
        });
      });
    });

    describe('requireAuthentication', () => {
      it('should return null when user is authenticated', async () => {
        mockGetServerSession.mockResolvedValue({
          user: { id: '1', email: 'test@example.com', role: 'USER' }
        } as any);

        const result = await requireAuthentication();
        expect(result).toBeNull();
      });

      it('should return 401 response when no session exists', async () => {
        mockGetServerSession.mockResolvedValue(null);

        const result = await requireAuthentication();
        
        expect(result).toBeInstanceOf(Response);
        expect(result?.status).toBe(401);
        
        const body = await result?.json();
        expect(body.error).toBe('Unauthorized');
        expect(body.code).toBe('AUTH_REQUIRED');
      });
    });
  });

  describe('Edge Cases', () => {
    it('should handle invalid role gracefully', () => {
      const permissions = getUserPermissions('INVALID' as Role);
      expect(permissions).toEqual([]);
    });

    it('should handle invalid permission gracefully', () => {
      const result = roleHasPermission(ROLES.USER, 'invalid:permission' as Permission);
      expect(result).toBe(false);
    });

    it('should handle malformed session data', async () => {
      mockGetServerSession.mockResolvedValue({
        user: { email: 'test@example.com' }
      } as any);

      const user = await getCurrentUser();
      
      expect(user).toEqual({
        id: undefined,
        email: 'test@example.com',
        name: undefined,
        role: undefined,
        permissions: []
      });
    });
  });

  describe('Constants Validation', () => {
    it('should have correct role definitions', () => {
      expect(ROLES.USER).toBe('USER');
      expect(ROLES.ADMIN).toBe('ADMIN');
    });

    it('should have all required permissions defined', () => {
      const expectedPermissions = [
        'document:read',
        'document:write', 
        'document:delete',
        'document:share',
        'user:read',
        'user:write',
        'user:delete',
        'admin:panel',
        'audit:read',
        'system:config'
      ];

      const actualPermissions = Object.values(PERMISSIONS);
      
      expectedPermissions.forEach(permission => {
        expect(actualPermissions).toContain(permission);
      });
    });

    it('should ensure permissions follow naming convention', () => {
      const allPermissions = Object.values(PERMISSIONS);
      
      allPermissions.forEach(permission => {
        expect(permission).toMatch(/^[a-z]+:[a-z]+$/);
      });
    });
  });
}); 