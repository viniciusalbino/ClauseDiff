import { useMemo } from "react";
import { useAuth } from "./useAuth";

// Define available roles
export const ROLES = {
  USER: "USER",
  ADMIN: "ADMIN",
} as const;

export type Role = typeof ROLES[keyof typeof ROLES];

// Define available permissions
export const PERMISSIONS = {
  // Document permissions
  DOCUMENT_READ: "document:read",
  DOCUMENT_WRITE: "document:write",
  DOCUMENT_DELETE: "document:delete",
  DOCUMENT_SHARE: "document:share",
  
  // User management permissions
  USER_READ: "user:read",
  USER_WRITE: "user:write",
  USER_DELETE: "user:delete",
  
  // Admin permissions
  ADMIN_PANEL: "admin:panel",
  AUDIT_LOG_READ: "audit:read",
  SYSTEM_CONFIG: "system:config",
} as const;

export type Permission = typeof PERMISSIONS[keyof typeof PERMISSIONS];

// Role-based permission mappings
const ROLE_PERMISSIONS: Record<Role, Permission[]> = {
  [ROLES.USER]: [
    PERMISSIONS.DOCUMENT_READ,
    PERMISSIONS.DOCUMENT_WRITE,
    PERMISSIONS.DOCUMENT_DELETE,
    PERMISSIONS.DOCUMENT_SHARE,
  ],
  [ROLES.ADMIN]: [
    // Admins have all permissions
    ...Object.values(PERMISSIONS),
  ],
};

export interface UsePermissionsReturn {
  hasPermission: (permission: Permission) => boolean;
  hasRole: (role: Role) => boolean;
  hasAnyRole: (roles: Role[]) => boolean;
  hasAllPermissions: (permissions: Permission[]) => boolean;
  hasAnyPermission: (permissions: Permission[]) => boolean;
  userRole: Role | null;
  userPermissions: Permission[];
  isAdmin: boolean;
  isUser: boolean;
}

/**
 * Hook for checking user permissions and roles.
 * 
 * @returns Permission checking functions and user role information
 */
export function usePermissions(): UsePermissionsReturn {
  const { user, isAuthenticated } = useAuth();

  const userRole = useMemo(() => {
    if (!isAuthenticated || !user?.role) {
      return null;
    }
    return user.role as Role;
  }, [isAuthenticated, user?.role]);

  const userPermissions = useMemo(() => {
    if (!userRole) {
      return [];
    }
    return ROLE_PERMISSIONS[userRole] || [];
  }, [userRole]);

  const hasPermission = useMemo(() => {
    return (permission: Permission): boolean => {
      if (!isAuthenticated) {
        return false;
      }
      return userPermissions.includes(permission);
    };
  }, [isAuthenticated, userPermissions]);

  const hasRole = useMemo(() => {
    return (role: Role): boolean => {
      if (!isAuthenticated) {
        return false;
      }
      return userRole === role;
    };
  }, [isAuthenticated, userRole]);

  const hasAnyRole = useMemo(() => {
    return (roles: Role[]): boolean => {
      if (!isAuthenticated || !userRole) {
        return false;
      }
      return roles.includes(userRole);
    };
  }, [isAuthenticated, userRole]);

  const hasAllPermissions = useMemo(() => {
    return (permissions: Permission[]): boolean => {
      if (!isAuthenticated) {
        return false;
      }
      return permissions.every(permission => userPermissions.includes(permission));
    };
  }, [isAuthenticated, userPermissions]);

  const hasAnyPermission = useMemo(() => {
    return (permissions: Permission[]): boolean => {
      if (!isAuthenticated) {
        return false;
      }
      return permissions.some(permission => userPermissions.includes(permission));
    };
  }, [isAuthenticated, userPermissions]);

  const isAdmin = useMemo(() => {
    return hasRole(ROLES.ADMIN);
  }, [hasRole]);

  const isUser = useMemo(() => {
    return hasRole(ROLES.USER);
  }, [hasRole]);

  return {
    hasPermission,
    hasRole,
    hasAnyRole,
    hasAllPermissions,
    hasAnyPermission,
    userRole,
    userPermissions,
    isAdmin,
    isUser,
  };
}

/**
 * Higher-order component that renders children only if user has required permission.
 * 
 * @param permission Required permission
 * @param fallback Optional fallback component to render if permission is not granted
 */
export function RequirePermission({ 
  permission, 
  children, 
  fallback = null 
}: {
  permission: Permission;
  children: React.ReactNode;
  fallback?: React.ReactNode;
}) {
  const { hasPermission } = usePermissions();

  if (!hasPermission(permission)) {
    return <>{fallback}</>;
  }

  return <>{children}</>;
}

/**
 * Higher-order component that renders children only if user has required role.
 * 
 * @param role Required role
 * @param fallback Optional fallback component to render if role is not granted
 */
export function RequireRole({ 
  role, 
  children, 
  fallback = null 
}: {
  role: Role;
  children: React.ReactNode;
  fallback?: React.ReactNode;
}) {
  const { hasRole } = usePermissions();

  if (!hasRole(role)) {
    return <>{fallback}</>;
  }

  return <>{children}</>;
} 