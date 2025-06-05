/**
 * Comprehensive Unit Tests for Server-Side Permission Utilities
 * 
 * Tests all permission validation functions, role checking, authentication
 * decorators, and server-side permission utilities.
 */

import { NextRequest } from 'next/server';
import { getServerSession } from 'next-auth/next';
import { getToken } from 'next-auth/jwt';

// Mock NextAuth functions
jest.mock('next-auth/next', () => ({
  getServerSession: jest.fn(),
}));

jest.mock('next-auth/jwt', () => ({
  getToken: jest.fn(),
}));

// Mock auth config
jest.mock('../../src/lib/auth-config', () => ({
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
  checkRequestPermission,
  requirePermission,
  requireRole,
  requireAuthentication,
  requireAuthAndPermission,
  requireAuthAndRole,
  type Role,
  type Permission
} from '../../src/lib/permissions';

const mockGetServerSession = getServerSession as jest.MockedFunction<typeof getServerSession>;
const mockGetToken = getToken as jest.MockedFunction<typeof getToken>;

describe('Server-Side Permission Utilities', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    process.env.NEXTAUTH_SECRET = 'test-secret';
  });

  afterEach(() => {
    jest.restoreAllMocks();
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
        expect(permissions).toContain(PERMISSIONS.DOCUMENT_DELETE);
        expect(permissions).toContain(PERMISSIONS.DOCUMENT_SHARE);
        
        // Users should NOT have admin permissions
        expect(permissions).not.toContain(PERMISSIONS.USER_READ);
        expect(permissions).not.toContain(PERMISSIONS.ADMIN_PANEL);
        expect(permissions).not.toContain(PERMISSIONS.AUDIT_LOG_READ);
      });

      it('should return all permissions for ADMIN role', () => {
        const permissions = getUserPermissions(ROLES.ADMIN);
        const allPermissions = Object.values(PERMISSIONS);
        
        // Admin should have all permissions
        allPermissions.forEach(permission => {
          expect(permissions).toContain(permission);
        });
      });

      it('should handle invalid role gracefully', () => {
        const permissions = getUserPermissions('INVALID' as Role);
        expect(permissions).toEqual([]);
      });
    });

    describe('roleHasPermission', () => {
      it('should return false for null role', () => {
        const result = roleHasPermission(null, PERMISSIONS.DOCUMENT_READ);
        expect(result).toBe(false);
      });

      it('should validate USER permissions correctly', () => {
        expect(roleHasPermission(ROLES.USER, PERMISSIONS.DOCUMENT_READ)).toBe(true);
        expect(roleHasPermission(ROLES.USER, PERMISSIONS.DOCUMENT_WRITE)).toBe(true);
        expect(roleHasPermission(ROLES.USER, PERMISSIONS.ADMIN_PANEL)).toBe(false);
        expect(roleHasPermission(ROLES.USER, PERMISSIONS.USER_DELETE)).toBe(false);
      });

      it('should validate ADMIN permissions correctly', () => {
        const allPermissions = Object.values(PERMISSIONS);
        
        allPermissions.forEach(permission => {
          expect(roleHasPermission(ROLES.ADMIN, permission)).toBe(true);
        });
      });

      it('should handle invalid permission gracefully', () => {
        const result = roleHasPermission(ROLES.USER, 'invalid:permission' as Permission);
        expect(result).toBe(false);
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

      it('should return false when session has no role', async () => {
        mockGetServerSession.mockResolvedValue({
          user: { id: '1', email: 'test@example.com' }
        } as any);
        
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

      it('should work correctly for admin users', async () => {
        mockGetServerSession.mockResolvedValue({
          user: { id: '1', email: 'admin@example.com', role: 'ADMIN' }
        } as any);
        
        const result = await userHasPermission(PERMISSIONS.ADMIN_PANEL);
        expect(result).toBe(true);
      });
    });

    describe('userHasRole', () => {
      it('should return false when no session exists', async () => {
        mockGetServerSession.mockResolvedValue(null);
        
        const result = await userHasRole(ROLES.USER);
        expect(result).toBe(false);
      });

      it('should return false when session has no role', async () => {
        mockGetServerSession.mockResolvedValue({
          user: { id: '1', email: 'test@example.com' }
        } as any);
        
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

      it('should return null when session has no user', async () => {
        mockGetServerSession.mockResolvedValue({} as any);
        
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
            PERMISSIONS.DOCUMENT_WRITE,
            PERMISSIONS.DOCUMENT_DELETE,
            PERMISSIONS.DOCUMENT_SHARE
          ])
        });
      });

      it('should handle user with no role', async () => {
        mockGetServerSession.mockResolvedValue({
          user: { 
            id: '1', 
            email: 'test@example.com', 
            name: 'Test User'
          }
        } as any);
        
        const result = await getCurrentUser();
        
        expect(result).toEqual({
          id: '1',
          email: 'test@example.com',
          name: 'Test User',
          role: undefined,
          permissions: []
        });
      });
    });
  });

  describe('Request-based Permission Functions', () => {
    describe('checkRequestPermission', () => {
      const mockRequest = {} as NextRequest;

      it('should return false when no token exists', async () => {
        mockGetToken.mockResolvedValue(null);
        
        const result = await checkRequestPermission(mockRequest, PERMISSIONS.DOCUMENT_READ);
        expect(result).toBe(false);
      });

      it('should return false when token has no role', async () => {
        mockGetToken.mockResolvedValue({
          email: 'test@example.com'
        } as any);
        
        const result = await checkRequestPermission(mockRequest, PERMISSIONS.DOCUMENT_READ);
        expect(result).toBe(false);
      });

      it('should return true when token has required permission', async () => {
        mockGetToken.mockResolvedValue({
          email: 'test@example.com',
          role: 'USER'
        } as any);
        
        const result = await checkRequestPermission(mockRequest, PERMISSIONS.DOCUMENT_READ);
        expect(result).toBe(true);
      });

      it('should return false when token lacks required permission', async () => {
        mockGetToken.mockResolvedValue({
          email: 'test@example.com',
          role: 'USER'
        } as any);
        
        const result = await checkRequestPermission(mockRequest, PERMISSIONS.ADMIN_PANEL);
        expect(result).toBe(false);
      });

      it('should call getToken with correct parameters', async () => {
        mockGetToken.mockResolvedValue(null);
        
        await checkRequestPermission(mockRequest, PERMISSIONS.DOCUMENT_READ);
        
        expect(mockGetToken).toHaveBeenCalledWith({
          req: mockRequest,
          secret: process.env.NEXTAUTH_SECRET
        });
      });
    });
  });

  describe('Authentication Decorators', () => {
    describe('requirePermission', () => {
      const mockHandler = jest.fn();
      const mockRequest = { method: 'GET' } as any;

      beforeEach(() => {
        mockHandler.mockClear();
      });

      it('should call handler when user has permission', async () => {
        mockGetServerSession.mockResolvedValue({
          user: { id: '1', email: 'test@example.com', role: 'USER' }
        } as any);

        const decoratedHandler = requirePermission(PERMISSIONS.DOCUMENT_READ)(mockHandler);
        await decoratedHandler(mockRequest);

        expect(mockHandler).toHaveBeenCalledWith(mockRequest);
      });

      it('should return 403 response when user lacks permission', async () => {
        mockGetServerSession.mockResolvedValue({
          user: { id: '1', email: 'test@example.com', role: 'USER' }
        } as any);

        const decoratedHandler = requirePermission(PERMISSIONS.ADMIN_PANEL)(mockHandler);
        const response = await decoratedHandler(mockRequest);

        expect(mockHandler).not.toHaveBeenCalled();
        expect(response).toBeInstanceOf(Response);
        expect(response.status).toBe(403);
        
        const body = await response.json();
        expect(body.error).toBe('Forbidden');
        expect(body.code).toBe('INSUFFICIENT_PERMISSIONS');
      });

      it('should return 403 response when no session exists', async () => {
        mockGetServerSession.mockResolvedValue(null);

        const decoratedHandler = requirePermission(PERMISSIONS.DOCUMENT_READ)(mockHandler);
        const response = await decoratedHandler(mockRequest);

        expect(mockHandler).not.toHaveBeenCalled();
        expect(response).toBeInstanceOf(Response);
        expect(response.status).toBe(403);
      });
    });

    describe('requireRole', () => {
      const mockHandler = jest.fn();
      const mockRequest = { method: 'GET' } as any;

      beforeEach(() => {
        mockHandler.mockClear();
      });

      it('should call handler when user has required role', async () => {
        mockGetServerSession.mockResolvedValue({
          user: { id: '1', email: 'admin@example.com', role: 'ADMIN' }
        } as any);

        const decoratedHandler = requireRole(ROLES.ADMIN)(mockHandler);
        await decoratedHandler(mockRequest);

        expect(mockHandler).toHaveBeenCalledWith(mockRequest);
      });

      it('should return 403 response when user lacks required role', async () => {
        mockGetServerSession.mockResolvedValue({
          user: { id: '1', email: 'test@example.com', role: 'USER' }
        } as any);

        const decoratedHandler = requireRole(ROLES.ADMIN)(mockHandler);
        const response = await decoratedHandler(mockRequest);

        expect(mockHandler).not.toHaveBeenCalled();
        expect(response).toBeInstanceOf(Response);
        expect(response.status).toBe(403);
        
        const body = await response.json();
        expect(body.error).toBe('Forbidden');
        expect(body.message).toBe('Missing required role: ADMIN');
        expect(body.code).toBe('INSUFFICIENT_ROLE');
      });

      it('should return 403 response when no session exists', async () => {
        mockGetServerSession.mockResolvedValue(null);

        const decoratedHandler = requireRole(ROLES.USER)(mockHandler);
        const response = await decoratedHandler(mockRequest);

        expect(mockHandler).not.toHaveBeenCalled();
        expect(response).toBeInstanceOf(Response);
        expect(response.status).toBe(403);
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
        expect(body.message).toBe('Authentication required');
        expect(body.code).toBe('AUTH_REQUIRED');
      });

      it('should return 401 response when session has no user', async () => {
        mockGetServerSession.mockResolvedValue({} as any);

        const result = await requireAuthentication();
        
        expect(result).toBeInstanceOf(Response);
        expect(result?.status).toBe(401);
      });
    });

    describe('requireAuthAndPermission', () => {
      it('should return null when user is authenticated and has permission', async () => {
        mockGetServerSession.mockResolvedValue({
          user: { id: '1', email: 'test@example.com', role: 'USER' }
        } as any);

        const result = await requireAuthAndPermission(PERMISSIONS.DOCUMENT_READ);
        expect(result).toBeNull();
      });

      it('should return 401 response when user is not authenticated', async () => {
        mockGetServerSession.mockResolvedValue(null);

        const result = await requireAuthAndPermission(PERMISSIONS.DOCUMENT_READ);
        
        expect(result).toBeInstanceOf(Response);
        expect(result?.status).toBe(401);
      });

      it('should return 403 response when user lacks permission', async () => {
        mockGetServerSession.mockResolvedValue({
          user: { id: '1', email: 'test@example.com', role: 'USER' }
        } as any);

        const result = await requireAuthAndPermission(PERMISSIONS.ADMIN_PANEL);
        
        expect(result).toBeInstanceOf(Response);
        expect(result?.status).toBe(403);
        
        const body = await result?.json();
        expect(body.error).toBe('Forbidden');
        expect(body.code).toBe('INSUFFICIENT_PERMISSIONS');
      });
    });

    describe('requireAuthAndRole', () => {
      it('should return null when user is authenticated and has role', async () => {
        mockGetServerSession.mockResolvedValue({
          user: { id: '1', email: 'admin@example.com', role: 'ADMIN' }
        } as any);

        const result = await requireAuthAndRole(ROLES.ADMIN);
        expect(result).toBeNull();
      });

      it('should return 401 response when user is not authenticated', async () => {
        mockGetServerSession.mockResolvedValue(null);

        const result = await requireAuthAndRole(ROLES.ADMIN);
        
        expect(result).toBeInstanceOf(Response);
        expect(result?.status).toBe(401);
      });

      it('should return 403 response when user lacks required role', async () => {
        mockGetServerSession.mockResolvedValue({
          user: { id: '1', email: 'test@example.com', role: 'USER' }
        } as any);

        const result = await requireAuthAndRole(ROLES.ADMIN);
        
        expect(result).toBeInstanceOf(Response);
        expect(result?.status).toBe(403);
        
        const body = await result?.json();
        expect(body.error).toBe('Forbidden');
        expect(body.message).toBe('Missing required role: ADMIN');
        expect(body.code).toBe('INSUFFICIENT_ROLE');
      });
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle malformed session data gracefully', async () => {
      mockGetServerSession.mockResolvedValue({
        user: { email: 'test@example.com' } // Missing id and name
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

    it('should handle malformed token data gracefully', async () => {
      const mockRequest = {} as NextRequest;
      mockGetToken.mockResolvedValue({
        email: 'test@example.com'
        // Missing role
      } as any);

      const result = await checkRequestPermission(mockRequest, PERMISSIONS.DOCUMENT_READ);
      expect(result).toBe(false);
    });

    it('should handle async errors in getServerSession', async () => {
      mockGetServerSession.mockRejectedValue(new Error('Session error'));

      await expect(userHasPermission(PERMISSIONS.DOCUMENT_READ)).rejects.toThrow('Session error');
    });

    it('should handle async errors in getToken', async () => {
      const mockRequest = {} as NextRequest;
      mockGetToken.mockRejectedValue(new Error('Token error'));

      await expect(checkRequestPermission(mockRequest, PERMISSIONS.DOCUMENT_READ)).rejects.toThrow('Token error');
    });

    it('should handle role constants correctly', () => {
      expect(ROLES.USER).toBe('USER');
      expect(ROLES.ADMIN).toBe('ADMIN');
    });

    it('should handle permission constants correctly', () => {
      expect(PERMISSIONS.DOCUMENT_READ).toBe('document:read');
      expect(PERMISSIONS.ADMIN_PANEL).toBe('admin:panel');
      expect(PERMISSIONS.USER_DELETE).toBe('user:delete');
    });

    it('should handle empty role gracefully', () => {
      const permissions = getUserPermissions('' as Role);
      expect(permissions).toEqual([]);
      
      const hasPermission = roleHasPermission('' as Role, PERMISSIONS.DOCUMENT_READ);
      expect(hasPermission).toBe(false);
    });

    it('should handle undefined values in decorators', async () => {
      const mockHandler = jest.fn();
      mockGetServerSession.mockResolvedValue({
        user: { role: undefined }
      } as any);

      const decoratedHandler = requireRole(ROLES.USER)(mockHandler);
      const response = await decoratedHandler({} as any);

      expect(response).toBeInstanceOf(Response);
      expect(response.status).toBe(403);
    });
  });

  describe('Type Safety and Constants', () => {
    it('should have correct role type definitions', () => {
      const userRole: Role = ROLES.USER;
      const adminRole: Role = ROLES.ADMIN;
      
      expect(typeof userRole).toBe('string');
      expect(typeof adminRole).toBe('string');
    });

    it('should have correct permission type definitions', () => {
      const readPermission: Permission = PERMISSIONS.DOCUMENT_READ;
      const adminPermission: Permission = PERMISSIONS.ADMIN_PANEL;
      
      expect(typeof readPermission).toBe('string');
      expect(typeof adminPermission).toBe('string');
    });

    it('should ensure all permissions follow naming convention', () => {
      const allPermissions = Object.values(PERMISSIONS);
      
      allPermissions.forEach(permission => {
        expect(permission).toMatch(/^[a-z]+:[a-z]+$/);
      });
    });

    it('should ensure proper role-permission mapping structure', () => {
      const userPermissions = getUserPermissions(ROLES.USER);
      const adminPermissions = getUserPermissions(ROLES.ADMIN);
      
      expect(Array.isArray(userPermissions)).toBe(true);
      expect(Array.isArray(adminPermissions)).toBe(true);
      expect(adminPermissions.length).toBeGreaterThan(userPermissions.length);
    });
  });
}); 