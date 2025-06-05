/**
 * Unit Tests for RBAC Permission System
 * 
 * This test suite verifies the role-based access control functionality,
 * including permission validation, role checking, and utility functions.
 */

import { 
  ROLES, 
  PERMISSIONS, 
  getUserPermissions, 
  roleHasPermission,
  type Role,
  type Permission 
} from '../../src/lib/permissions';

describe('RBAC Permission System', () => {
  
  describe('Role and Permission Constants', () => {
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
  });

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
      expect(permissions).not.toContain(PERMISSIONS.USER_WRITE);
      expect(permissions).not.toContain(PERMISSIONS.USER_DELETE);
      expect(permissions).not.toContain(PERMISSIONS.ADMIN_PANEL);
      expect(permissions).not.toContain(PERMISSIONS.AUDIT_LOG_READ);
      expect(permissions).not.toContain(PERMISSIONS.SYSTEM_CONFIG);
    });

    it('should return all permissions for ADMIN role', () => {
      const permissions = getUserPermissions(ROLES.ADMIN);
      const allPermissions = Object.values(PERMISSIONS);
      
      // Admin should have all permissions
      allPermissions.forEach(permission => {
        expect(permissions).toContain(permission);
      });
    });

    it('should return empty array for invalid role', () => {
      const permissions = getUserPermissions('INVALID_ROLE' as Role);
      expect(permissions).toEqual([]);
    });
  });

  describe('roleHasPermission', () => {
    it('should return false for null role', () => {
      const result = roleHasPermission(null, PERMISSIONS.DOCUMENT_READ);
      expect(result).toBe(false);
    });

    it('should validate USER permissions correctly', () => {
      // User should have document permissions
      expect(roleHasPermission(ROLES.USER, PERMISSIONS.DOCUMENT_READ)).toBe(true);
      expect(roleHasPermission(ROLES.USER, PERMISSIONS.DOCUMENT_WRITE)).toBe(true);
      expect(roleHasPermission(ROLES.USER, PERMISSIONS.DOCUMENT_DELETE)).toBe(true);
      expect(roleHasPermission(ROLES.USER, PERMISSIONS.DOCUMENT_SHARE)).toBe(true);
      
      // User should NOT have admin permissions
      expect(roleHasPermission(ROLES.USER, PERMISSIONS.USER_READ)).toBe(false);
      expect(roleHasPermission(ROLES.USER, PERMISSIONS.USER_WRITE)).toBe(false);
      expect(roleHasPermission(ROLES.USER, PERMISSIONS.USER_DELETE)).toBe(false);
      expect(roleHasPermission(ROLES.USER, PERMISSIONS.ADMIN_PANEL)).toBe(false);
      expect(roleHasPermission(ROLES.USER, PERMISSIONS.AUDIT_LOG_READ)).toBe(false);
      expect(roleHasPermission(ROLES.USER, PERMISSIONS.SYSTEM_CONFIG)).toBe(false);
    });

    it('should validate ADMIN permissions correctly', () => {
      const allPermissions = Object.values(PERMISSIONS);
      
      // Admin should have all permissions
      allPermissions.forEach(permission => {
        expect(roleHasPermission(ROLES.ADMIN, permission)).toBe(true);
      });
    });

    it('should return false for invalid permission', () => {
      const result = roleHasPermission(ROLES.USER, 'invalid:permission' as Permission);
      expect(result).toBe(false);
    });
  });

  describe('Permission Inheritance', () => {
    it('should ensure admin has all user permissions plus admin-specific permissions', () => {
      const userPermissions = getUserPermissions(ROLES.USER);
      const adminPermissions = getUserPermissions(ROLES.ADMIN);
      
      // All user permissions should be included in admin permissions
      userPermissions.forEach(permission => {
        expect(adminPermissions).toContain(permission);
      });
      
      // Admin should have additional permissions
      expect(adminPermissions.length).toBeGreaterThan(userPermissions.length);
    });

    it('should have distinct permission sets between roles', () => {
      const userPermissions = getUserPermissions(ROLES.USER);
      const adminOnlyPermissions = [
        PERMISSIONS.USER_READ,
        PERMISSIONS.USER_WRITE,
        PERMISSIONS.USER_DELETE,
        PERMISSIONS.ADMIN_PANEL,
        PERMISSIONS.AUDIT_LOG_READ,
        PERMISSIONS.SYSTEM_CONFIG
      ];
      
      // User should not have any admin-only permissions
      adminOnlyPermissions.forEach(permission => {
        expect(userPermissions).not.toContain(permission);
      });
    });
  });

  describe('Permission Categories', () => {
    it('should have correct document permissions', () => {
      const documentPermissions = [
        PERMISSIONS.DOCUMENT_READ,
        PERMISSIONS.DOCUMENT_WRITE,
        PERMISSIONS.DOCUMENT_DELETE,
        PERMISSIONS.DOCUMENT_SHARE
      ];
      
      documentPermissions.forEach(permission => {
        expect(permission).toMatch(/^document:/);
      });
    });

    it('should have correct user management permissions', () => {
      const userPermissions = [
        PERMISSIONS.USER_READ,
        PERMISSIONS.USER_WRITE,
        PERMISSIONS.USER_DELETE
      ];
      
      userPermissions.forEach(permission => {
        expect(permission).toMatch(/^user:/);
      });
    });

    it('should have correct admin permissions', () => {
      expect(PERMISSIONS.ADMIN_PANEL).toMatch(/^admin:/);
      expect(PERMISSIONS.AUDIT_LOG_READ).toMatch(/^audit:/);
      expect(PERMISSIONS.SYSTEM_CONFIG).toMatch(/^system:/);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty strings gracefully', () => {
      expect(getUserPermissions('' as Role)).toEqual([]);
      expect(roleHasPermission('' as Role, PERMISSIONS.DOCUMENT_READ)).toBe(false);
    });

    it('should handle undefined role gracefully', () => {
      expect(getUserPermissions(undefined as any)).toEqual([]);
      expect(roleHasPermission(undefined as any, PERMISSIONS.DOCUMENT_READ)).toBe(false);
    });

    it('should be case sensitive for roles', () => {
      expect(getUserPermissions('user' as Role)).toEqual([]);
      expect(getUserPermissions('admin' as Role)).toEqual([]);
      expect(roleHasPermission('user' as Role, PERMISSIONS.DOCUMENT_READ)).toBe(false);
    });
  });

  describe('Permission System Integrity', () => {
    it('should have no duplicate permissions', () => {
      const allPermissions = Object.values(PERMISSIONS);
      const uniquePermissions = [...new Set(allPermissions)];
      
      expect(allPermissions.length).toBe(uniquePermissions.length);
    });

    it('should have no duplicate roles', () => {
      const allRoles = Object.values(ROLES);
      const uniqueRoles = [...new Set(allRoles)];
      
      expect(allRoles.length).toBe(uniqueRoles.length);
    });

    it('should ensure all permissions follow naming convention', () => {
      const allPermissions = Object.values(PERMISSIONS);
      
      allPermissions.forEach(permission => {
        expect(permission).toMatch(/^[a-z]+:[a-z_]+$/);
      });
    });
  });
}); 