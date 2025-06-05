import { renderHook } from '@testing-library/react';
import { render } from '@testing-library/react';
import { useAuth } from '@/hooks/useAuth';
import { 
  usePermissions, 
  RequirePermission, 
  RequireRole,
  ROLES, 
  PERMISSIONS,
  type Role,
  type Permission 
} from '@/hooks/usePermissions';

// Mock the useAuth hook
jest.mock('@/hooks/useAuth');

const mockUseAuth = useAuth as jest.MockedFunction<typeof useAuth>;

describe('usePermissions Hook', () => {
  // Helper function to create mock auth state
  const createMockAuthState = (
    isAuthenticated: boolean = false,
    role: Role | null = null,
    userId: string = '123'
  ) => ({
    user: isAuthenticated ? {
      id: userId,
      email: 'test@example.com',
      role,
    } : null,
    isAuthenticated,
    isLoading: false,
    isError: false,
    login: jest.fn(),
    loginWithGoogle: jest.fn(),
    logout: jest.fn(),
    refreshSession: jest.fn(),
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Unauthenticated User', () => {
    beforeEach(() => {
      mockUseAuth.mockReturnValue(createMockAuthState(false));
    });

    it('should return null for userRole when unauthenticated', () => {
      const { result } = renderHook(() => usePermissions());

      expect(result.current.userRole).toBeNull();
    });

    it('should return empty array for userPermissions when unauthenticated', () => {
      const { result } = renderHook(() => usePermissions());

      expect(result.current.userPermissions).toEqual([]);
    });

    it('should return false for all permission checks when unauthenticated', () => {
      const { result } = renderHook(() => usePermissions());

      expect(result.current.hasPermission(PERMISSIONS.DOCUMENT_READ)).toBe(false);
      expect(result.current.hasPermission(PERMISSIONS.ADMIN_PANEL)).toBe(false);
    });

    it('should return false for all role checks when unauthenticated', () => {
      const { result } = renderHook(() => usePermissions());

      expect(result.current.hasRole(ROLES.USER)).toBe(false);
      expect(result.current.hasRole(ROLES.ADMIN)).toBe(false);
    });

    it('should return false for hasAnyRole when unauthenticated', () => {
      const { result } = renderHook(() => usePermissions());

      expect(result.current.hasAnyRole([ROLES.USER, ROLES.ADMIN])).toBe(false);
    });

    it('should return false for hasAllPermissions when unauthenticated', () => {
      const { result } = renderHook(() => usePermissions());

      expect(result.current.hasAllPermissions([PERMISSIONS.DOCUMENT_READ, PERMISSIONS.DOCUMENT_WRITE])).toBe(false);
    });

    it('should return false for hasAnyPermission when unauthenticated', () => {
      const { result } = renderHook(() => usePermissions());

      expect(result.current.hasAnyPermission([PERMISSIONS.DOCUMENT_READ, PERMISSIONS.ADMIN_PANEL])).toBe(false);
    });

    it('should return false for isAdmin and isUser when unauthenticated', () => {
      const { result } = renderHook(() => usePermissions());

      expect(result.current.isAdmin).toBe(false);
      expect(result.current.isUser).toBe(false);
    });
  });

  describe('Authenticated User with USER Role', () => {
    beforeEach(() => {
      mockUseAuth.mockReturnValue(createMockAuthState(true, ROLES.USER));
    });

    it('should return USER for userRole', () => {
      const { result } = renderHook(() => usePermissions());

      expect(result.current.userRole).toBe(ROLES.USER);
    });

    it('should return correct permissions for USER role', () => {
      const { result } = renderHook(() => usePermissions());

      const expectedPermissions = [
        PERMISSIONS.DOCUMENT_READ,
        PERMISSIONS.DOCUMENT_WRITE,
        PERMISSIONS.DOCUMENT_DELETE,
        PERMISSIONS.DOCUMENT_SHARE,
      ];

      expect(result.current.userPermissions).toEqual(expectedPermissions);
    });

    it('should return true for document permissions', () => {
      const { result } = renderHook(() => usePermissions());

      expect(result.current.hasPermission(PERMISSIONS.DOCUMENT_READ)).toBe(true);
      expect(result.current.hasPermission(PERMISSIONS.DOCUMENT_WRITE)).toBe(true);
      expect(result.current.hasPermission(PERMISSIONS.DOCUMENT_DELETE)).toBe(true);
      expect(result.current.hasPermission(PERMISSIONS.DOCUMENT_SHARE)).toBe(true);
    });

    it('should return false for admin permissions', () => {
      const { result } = renderHook(() => usePermissions());

      expect(result.current.hasPermission(PERMISSIONS.ADMIN_PANEL)).toBe(false);
      expect(result.current.hasPermission(PERMISSIONS.AUDIT_LOG_READ)).toBe(false);
      expect(result.current.hasPermission(PERMISSIONS.SYSTEM_CONFIG)).toBe(false);
    });

    it('should return true for USER role check', () => {
      const { result } = renderHook(() => usePermissions());

      expect(result.current.hasRole(ROLES.USER)).toBe(true);
    });

    it('should return false for ADMIN role check', () => {
      const { result } = renderHook(() => usePermissions());

      expect(result.current.hasRole(ROLES.ADMIN)).toBe(false);
    });

    it('should correctly validate hasAnyRole', () => {
      const { result } = renderHook(() => usePermissions());

      expect(result.current.hasAnyRole([ROLES.USER])).toBe(true);
      expect(result.current.hasAnyRole([ROLES.ADMIN])).toBe(false);
      expect(result.current.hasAnyRole([ROLES.USER, ROLES.ADMIN])).toBe(true);
    });

    it('should correctly validate hasAllPermissions', () => {
      const { result } = renderHook(() => usePermissions());

      // Should have all document permissions
      expect(result.current.hasAllPermissions([
        PERMISSIONS.DOCUMENT_READ,
        PERMISSIONS.DOCUMENT_WRITE
      ])).toBe(true);

      // Should not have admin permissions
      expect(result.current.hasAllPermissions([
        PERMISSIONS.DOCUMENT_READ,
        PERMISSIONS.ADMIN_PANEL
      ])).toBe(false);
    });

    it('should correctly validate hasAnyPermission', () => {
      const { result } = renderHook(() => usePermissions());

      // Should have at least one document permission
      expect(result.current.hasAnyPermission([
        PERMISSIONS.DOCUMENT_READ,
        PERMISSIONS.ADMIN_PANEL
      ])).toBe(true);

      // Should not have any admin permissions
      expect(result.current.hasAnyPermission([
        PERMISSIONS.ADMIN_PANEL,
        PERMISSIONS.SYSTEM_CONFIG
      ])).toBe(false);
    });

    it('should return correct isAdmin and isUser flags', () => {
      const { result } = renderHook(() => usePermissions());

      expect(result.current.isAdmin).toBe(false);
      expect(result.current.isUser).toBe(true);
    });
  });

  describe('Authenticated User with ADMIN Role', () => {
    beforeEach(() => {
      mockUseAuth.mockReturnValue(createMockAuthState(true, ROLES.ADMIN));
    });

    it('should return ADMIN for userRole', () => {
      const { result } = renderHook(() => usePermissions());

      expect(result.current.userRole).toBe(ROLES.ADMIN);
    });

    it('should return all permissions for ADMIN role', () => {
      const { result } = renderHook(() => usePermissions());

      const allPermissions = Object.values(PERMISSIONS);
      expect(result.current.userPermissions).toEqual(allPermissions);
    });

    it('should return true for all permissions', () => {
      const { result } = renderHook(() => usePermissions());

      Object.values(PERMISSIONS).forEach(permission => {
        expect(result.current.hasPermission(permission)).toBe(true);
      });
    });

    it('should return true for ADMIN role check', () => {
      const { result } = renderHook(() => usePermissions());

      expect(result.current.hasRole(ROLES.ADMIN)).toBe(true);
    });

    it('should return false for USER role check', () => {
      const { result } = renderHook(() => usePermissions());

      expect(result.current.hasRole(ROLES.USER)).toBe(false);
    });

    it('should correctly validate hasAnyRole for admin', () => {
      const { result } = renderHook(() => usePermissions());

      expect(result.current.hasAnyRole([ROLES.ADMIN])).toBe(true);
      expect(result.current.hasAnyRole([ROLES.USER])).toBe(false);
      expect(result.current.hasAnyRole([ROLES.USER, ROLES.ADMIN])).toBe(true);
    });

    it('should return true for hasAllPermissions with any permission set', () => {
      const { result } = renderHook(() => usePermissions());

      expect(result.current.hasAllPermissions([
        PERMISSIONS.DOCUMENT_READ,
        PERMISSIONS.ADMIN_PANEL,
        PERMISSIONS.SYSTEM_CONFIG
      ])).toBe(true);

      expect(result.current.hasAllPermissions(Object.values(PERMISSIONS))).toBe(true);
    });

    it('should return true for hasAnyPermission with any permission set', () => {
      const { result } = renderHook(() => usePermissions());

      expect(result.current.hasAnyPermission([PERMISSIONS.ADMIN_PANEL])).toBe(true);
      expect(result.current.hasAnyPermission([PERMISSIONS.DOCUMENT_READ])).toBe(true);
    });

    it('should return correct isAdmin and isUser flags', () => {
      const { result } = renderHook(() => usePermissions());

      expect(result.current.isAdmin).toBe(true);
      expect(result.current.isUser).toBe(false);
    });
  });

  describe('Edge Cases', () => {
    it('should handle user with no role', () => {
      mockUseAuth.mockReturnValue(createMockAuthState(true, null));

      const { result } = renderHook(() => usePermissions());

      expect(result.current.userRole).toBeNull();
      expect(result.current.userPermissions).toEqual([]);
      expect(result.current.hasPermission(PERMISSIONS.DOCUMENT_READ)).toBe(false);
      expect(result.current.hasRole(ROLES.USER)).toBe(false);
      expect(result.current.isAdmin).toBe(false);
      expect(result.current.isUser).toBe(false);
    });

    it('should handle user with undefined role', () => {
      mockUseAuth.mockReturnValue({
        ...createMockAuthState(true, ROLES.USER),
        user: {
          id: '123',
          email: 'test@example.com',
          role: undefined,
        },
      });

      const { result } = renderHook(() => usePermissions());

      expect(result.current.userRole).toBeNull();
      expect(result.current.userPermissions).toEqual([]);
    });

    it('should handle empty permission arrays', () => {
      mockUseAuth.mockReturnValue(createMockAuthState(true, ROLES.USER));

      const { result } = renderHook(() => usePermissions());

      expect(result.current.hasAllPermissions([])).toBe(true);
      expect(result.current.hasAnyPermission([])).toBe(false);
    });

    it('should handle empty role arrays', () => {
      mockUseAuth.mockReturnValue(createMockAuthState(true, ROLES.USER));

      const { result } = renderHook(() => usePermissions());

      expect(result.current.hasAnyRole([])).toBe(false);
    });
  });

  describe('Function Reference Stability', () => {
    it('should maintain stable function references', () => {
      mockUseAuth.mockReturnValue(createMockAuthState(true, ROLES.USER));

      const { result, rerender } = renderHook(() => usePermissions());

      const firstHasPermission = result.current.hasPermission;
      const firstHasRole = result.current.hasRole;
      const firstHasAnyRole = result.current.hasAnyRole;
      const firstHasAllPermissions = result.current.hasAllPermissions;
      const firstHasAnyPermission = result.current.hasAnyPermission;

      rerender();

      expect(result.current.hasPermission).toBe(firstHasPermission);
      expect(result.current.hasRole).toBe(firstHasRole);
      expect(result.current.hasAnyRole).toBe(firstHasAnyRole);
      expect(result.current.hasAllPermissions).toBe(firstHasAllPermissions);
      expect(result.current.hasAnyPermission).toBe(firstHasAnyPermission);
    });
  });

  describe('State Changes', () => {
    it('should update permissions when user role changes', () => {
      const { result, rerender } = renderHook(() => usePermissions());

      // Start as USER
      mockUseAuth.mockReturnValue(createMockAuthState(true, ROLES.USER));
      rerender();

      expect(result.current.hasPermission(PERMISSIONS.ADMIN_PANEL)).toBe(false);
      expect(result.current.isUser).toBe(true);
      expect(result.current.isAdmin).toBe(false);

      // Change to ADMIN
      mockUseAuth.mockReturnValue(createMockAuthState(true, ROLES.ADMIN));
      rerender();

      expect(result.current.hasPermission(PERMISSIONS.ADMIN_PANEL)).toBe(true);
      expect(result.current.isUser).toBe(false);
      expect(result.current.isAdmin).toBe(true);
    });

    it('should update permissions when authentication status changes', () => {
      const { result, rerender } = renderHook(() => usePermissions());

      // Start unauthenticated
      mockUseAuth.mockReturnValue(createMockAuthState(false));
      rerender();

      expect(result.current.hasPermission(PERMISSIONS.DOCUMENT_READ)).toBe(false);

      // Become authenticated
      mockUseAuth.mockReturnValue(createMockAuthState(true, ROLES.USER));
      rerender();

      expect(result.current.hasPermission(PERMISSIONS.DOCUMENT_READ)).toBe(true);
    });
  });
});

describe('RequirePermission Component', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should render children when user has required permission', () => {
    mockUseAuth.mockReturnValue({
      user: { id: '123', email: 'test@example.com', role: ROLES.USER },
      isAuthenticated: true,
      isLoading: false,
      isError: false,
      login: jest.fn(),
      loginWithGoogle: jest.fn(),
      logout: jest.fn(),
      refreshSession: jest.fn(),
    });

    const { getByText } = render(
      <RequirePermission permission={PERMISSIONS.DOCUMENT_READ}>
        <div>Protected Content</div>
      </RequirePermission>
    );

    expect(getByText('Protected Content')).toBeInTheDocument();
  });

  it('should not render children when user lacks required permission', () => {
    mockUseAuth.mockReturnValue({
      user: { id: '123', email: 'test@example.com', role: ROLES.USER },
      isAuthenticated: true,
      isLoading: false,
      isError: false,
      login: jest.fn(),
      loginWithGoogle: jest.fn(),
      logout: jest.fn(),
      refreshSession: jest.fn(),
    });

    const { queryByText } = render(
      <RequirePermission permission={PERMISSIONS.ADMIN_PANEL}>
        <div>Admin Content</div>
      </RequirePermission>
    );

    expect(queryByText('Admin Content')).not.toBeInTheDocument();
  });

  it('should render fallback when user lacks required permission', () => {
    mockUseAuth.mockReturnValue({
      user: { id: '123', email: 'test@example.com', role: ROLES.USER },
      isAuthenticated: true,
      isLoading: false,
      isError: false,
      login: jest.fn(),
      loginWithGoogle: jest.fn(),
      logout: jest.fn(),
      refreshSession: jest.fn(),
    });

    const { getByText, queryByText } = render(
      <RequirePermission 
        permission={PERMISSIONS.ADMIN_PANEL}
        fallback={<div>Access Denied</div>}
      >
        <div>Admin Content</div>
      </RequirePermission>
    );

    expect(queryByText('Admin Content')).not.toBeInTheDocument();
    expect(getByText('Access Denied')).toBeInTheDocument();
  });

  it('should handle unauthenticated user', () => {
    mockUseAuth.mockReturnValue({
      user: null,
      isAuthenticated: false,
      isLoading: false,
      isError: false,
      login: jest.fn(),
      loginWithGoogle: jest.fn(),
      logout: jest.fn(),
      refreshSession: jest.fn(),
    });

    const { queryByText } = render(
      <RequirePermission permission={PERMISSIONS.DOCUMENT_READ}>
        <div>Protected Content</div>
      </RequirePermission>
    );

    expect(queryByText('Protected Content')).not.toBeInTheDocument();
  });
});

describe('RequireRole Component', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should render children when user has required role', () => {
    mockUseAuth.mockReturnValue({
      user: { id: '123', email: 'test@example.com', role: ROLES.ADMIN },
      isAuthenticated: true,
      isLoading: false,
      isError: false,
      login: jest.fn(),
      loginWithGoogle: jest.fn(),
      logout: jest.fn(),
      refreshSession: jest.fn(),
    });

    const { getByText } = render(
      <RequireRole role={ROLES.ADMIN}>
        <div>Admin Content</div>
      </RequireRole>
    );

    expect(getByText('Admin Content')).toBeInTheDocument();
  });

  it('should not render children when user lacks required role', () => {
    mockUseAuth.mockReturnValue({
      user: { id: '123', email: 'test@example.com', role: ROLES.USER },
      isAuthenticated: true,
      isLoading: false,
      isError: false,
      login: jest.fn(),
      loginWithGoogle: jest.fn(),
      logout: jest.fn(),
      refreshSession: jest.fn(),
    });

    const { queryByText } = render(
      <RequireRole role={ROLES.ADMIN}>
        <div>Admin Content</div>
      </RequireRole>
    );

    expect(queryByText('Admin Content')).not.toBeInTheDocument();
  });

  it('should render fallback when user lacks required role', () => {
    mockUseAuth.mockReturnValue({
      user: { id: '123', email: 'test@example.com', role: ROLES.USER },
      isAuthenticated: true,
      isLoading: false,
      isError: false,
      login: jest.fn(),
      loginWithGoogle: jest.fn(),
      logout: jest.fn(),
      refreshSession: jest.fn(),
    });

    const { getByText, queryByText } = render(
      <RequireRole 
        role={ROLES.ADMIN}
        fallback={<div>Insufficient Role</div>}
      >
        <div>Admin Content</div>
      </RequireRole>
    );

    expect(queryByText('Admin Content')).not.toBeInTheDocument();
    expect(getByText('Insufficient Role')).toBeInTheDocument();
  });

  it('should handle unauthenticated user', () => {
    mockUseAuth.mockReturnValue({
      user: null,
      isAuthenticated: false,
      isLoading: false,
      isError: false,
      login: jest.fn(),
      loginWithGoogle: jest.fn(),
      logout: jest.fn(),
      refreshSession: jest.fn(),
    });

    const { queryByText } = render(
      <RequireRole role={ROLES.USER}>
        <div>User Content</div>
      </RequireRole>
    );

    expect(queryByText('User Content')).not.toBeInTheDocument();
  });
}); 