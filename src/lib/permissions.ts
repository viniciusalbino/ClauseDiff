/**
 * Server-side Permission Validation Utilities
 * 
 * This module provides server-side utilities for validating user permissions
 * and roles in API routes and middleware. It works with NextAuth sessions
 * and JWT tokens.
 */

import { getServerSession } from "next-auth/next";
import { getToken } from "next-auth/jwt";
import { NextRequest } from "next/server";
import { authOptions } from "./auth-config";

// Define roles and permissions for server-side use
export const ROLES = {
  USER: "USER",
  ADMIN: "ADMIN",
} as const;

export type Role = typeof ROLES[keyof typeof ROLES];

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

// Role-based permission mappings (server-side)
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

/**
 * Get user permissions based on their role
 */
export function getUserPermissions(role: Role | null): Permission[] {
  if (!role) return [];
  return ROLE_PERMISSIONS[role] || [];
}

/**
 * Check if a role has a specific permission
 */
export function roleHasPermission(role: Role | null, permission: Permission): boolean {
  if (!role) return false;
  const permissions = getUserPermissions(role);
  return permissions.includes(permission);
}

/**
 * Check if a user has a specific permission (for use in API routes)
 */
export async function userHasPermission(permission: Permission): Promise<boolean> {
  const session = await getServerSession(authOptions);
  if (!session?.user?.role) return false;
  
  return roleHasPermission(session.user.role as Role, permission);
}

/**
 * Check if a user has a specific role (for use in API routes)
 */
export async function userHasRole(role: Role): Promise<boolean> {
  const session = await getServerSession(authOptions);
  if (!session?.user?.role) return false;
  
  return session.user.role === role;
}

/**
 * Get current user session with role information
 */
export async function getCurrentUser() {
  const session = await getServerSession(authOptions);
  if (!session?.user) return null;
  
  return {
    id: session.user.id,
    email: session.user.email,
    name: session.user.name,
    role: session.user.role as Role | null,
    permissions: getUserPermissions(session.user.role as Role),
  };
}

/**
 * Middleware helper to check permissions from request token
 */
export async function checkRequestPermission(
  request: NextRequest,
  permission: Permission
): Promise<boolean> {
  const token = await getToken({ 
    req: request, 
    secret: process.env.NEXTAUTH_SECRET 
  });
  
  if (!token?.role) return false;
  return roleHasPermission(token.role as Role, permission);
}

/**
 * API route permission checker decorator
 */
export function requirePermission(permission: Permission) {
  return function(handler: Function) {
    return async function(req: any, ...args: any[]) {
      const hasPermission = await userHasPermission(permission);
      
      if (!hasPermission) {
        return new Response(
          JSON.stringify({ 
            error: 'Forbidden',
            message: `Missing required permission: ${permission}`,
            code: 'INSUFFICIENT_PERMISSIONS'
          }),
          { 
            status: 403,
            headers: { 'Content-Type': 'application/json' }
          }
        );
      }
      
      return handler(req, ...args);
    };
  };
}

/**
 * API route role checker decorator
 */
export function requireRole(role: Role) {
  return function(handler: Function) {
    return async function(req: any, ...args: any[]) {
      const hasRole = await userHasRole(role);
      
      if (!hasRole) {
        return new Response(
          JSON.stringify({ 
            error: 'Forbidden',
            message: `Missing required role: ${role}`,
            code: 'INSUFFICIENT_ROLE'
          }),
          { 
            status: 403,
            headers: { 'Content-Type': 'application/json' }
          }
        );
      }
      
      return handler(req, ...args);
    };
  };
}

/**
 * API route authentication checker
 */
export async function requireAuthentication() {
  const session = await getServerSession(authOptions);
  
  if (!session?.user) {
    return new Response(
      JSON.stringify({ 
        error: 'Unauthorized',
        message: 'Authentication required',
        code: 'AUTH_REQUIRED'
      }),
      { 
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }
  
  return null; // No error, user is authenticated
}

/**
 * Combined authentication and permission check
 */
export async function requireAuthAndPermission(permission: Permission) {
  // First check authentication
  const authError = await requireAuthentication();
  if (authError) return authError;
  
  // Then check permission
  const hasPermission = await userHasPermission(permission);
  if (!hasPermission) {
    return new Response(
      JSON.stringify({ 
        error: 'Forbidden',
        message: `Missing required permission: ${permission}`,
        code: 'INSUFFICIENT_PERMISSIONS'
      }),
      { 
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }
  
  return null; // No error, user is authenticated and has permission
}

/**
 * Combined authentication and role check
 */
export async function requireAuthAndRole(role: Role) {
  // First check authentication
  const authError = await requireAuthentication();
  if (authError) return authError;
  
  // Then check role
  const hasRole = await userHasRole(role);
  if (!hasRole) {
    return new Response(
      JSON.stringify({ 
        error: 'Forbidden',
        message: `Missing required role: ${role}`,
        code: 'INSUFFICIENT_ROLE'
      }),
      { 
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }
  
  return null; // No error, user is authenticated and has role
} 