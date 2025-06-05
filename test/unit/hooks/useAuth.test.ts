import { renderHook, act, waitFor } from '@testing-library/react';
import { useRouter } from 'next/navigation';
import { useSession, signIn, signOut } from 'next-auth/react';
import { useAuth, type AuthUser, type AuthState, type UseAuthReturn } from '@/hooks/useAuth';

// Mock dependencies
jest.mock('next/navigation');
jest.mock('next-auth/react');

const mockUseRouter = useRouter as jest.MockedFunction<typeof useRouter>;
const mockUseSession = useSession as jest.MockedFunction<typeof useSession>;
const mockSignIn = signIn as jest.MockedFunction<typeof signIn>;
const mockSignOut = signOut as jest.MockedFunction<typeof signOut>;

describe('useAuth Hook', () => {
  // Mock router instance
  const mockRouter = {
    push: jest.fn(),
    replace: jest.fn(),
    prefetch: jest.fn(),
    back: jest.fn(),
    forward: jest.fn(),
    refresh: jest.fn(),
  };

  // Mock session update function
  const mockUpdate = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
    mockUseRouter.mockReturnValue(mockRouter as any);
  });

  describe('Session State Management', () => {
    it('should return loading state when session is loading', () => {
      mockUseSession.mockReturnValue({
        data: null,
        status: 'loading',
        update: mockUpdate,
      });

      const { result } = renderHook(() => useAuth());

      expect(result.current.isLoading).toBe(true);
      expect(result.current.isAuthenticated).toBe(false);
      expect(result.current.user).toBe(null);
      expect(result.current.isError).toBe(false);
    });

    it('should return authenticated state when session exists', () => {
      const mockSession = {
        user: {
          id: '123',
          name: 'John Doe',
          email: 'john@example.com',
          image: 'https://example.com/avatar.jpg',
          firstName: 'John',
          lastName: 'Doe',
          emailVerified: new Date('2023-01-01'),
          role: 'USER',
        },
        expires: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(), // 24 hours from now
      };

      mockUseSession.mockReturnValue({
        data: mockSession,
        status: 'authenticated',
        update: mockUpdate,
      });

      const { result } = renderHook(() => useAuth());

      expect(result.current.isLoading).toBe(false);
      expect(result.current.isAuthenticated).toBe(true);
      expect(result.current.user).toEqual(mockSession.user);
      expect(result.current.isError).toBe(false);
    });

    it('should return unauthenticated state when no session', () => {
      mockUseSession.mockReturnValue({
        data: null,
        status: 'unauthenticated',
        update: mockUpdate,
      });

      const { result } = renderHook(() => useAuth());

      expect(result.current.isLoading).toBe(false);
      expect(result.current.isAuthenticated).toBe(false);
      expect(result.current.user).toBe(null);
      expect(result.current.isError).toBe(true);
    });

    it('should handle session with minimal user data', () => {
      const mockSession = {
        user: {
          id: '123',
          email: 'john@example.com',
          // Missing optional fields
        },
        expires: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      };

      mockUseSession.mockReturnValue({
        data: mockSession,
        status: 'authenticated',
        update: mockUpdate,
      });

      const { result } = renderHook(() => useAuth());

      expect(result.current.isAuthenticated).toBe(true);
      expect(result.current.user).toEqual({
        id: '123',
        email: 'john@example.com',
        name: undefined,
        image: undefined,
        firstName: undefined,
        lastName: undefined,
        emailVerified: undefined,
        role: undefined,
      });
    });
  });

  describe('Login Functionality', () => {
    beforeEach(() => {
      mockUseSession.mockReturnValue({
        data: null,
        status: 'unauthenticated',
        update: mockUpdate,
      });
    });

    it('should handle successful login', async () => {
      mockSignIn.mockResolvedValue({
        ok: true,
        error: null,
        status: 200,
        url: null,
      });

      const { result } = renderHook(() => useAuth());

      let loginResult: any;
      await act(async () => {
        loginResult = await result.current.login('john@example.com', 'password123');
      });

      expect(mockSignIn).toHaveBeenCalledWith('credentials', {
        redirect: false,
        email: 'john@example.com',
        password: 'password123',
      });

      expect(loginResult).toEqual({
        success: true,
      });
    });

    it('should handle login with invalid credentials', async () => {
      mockSignIn.mockResolvedValue({
        ok: false,
        error: 'CredentialsSignin',
        status: 401,
        url: null,
      });

      const { result } = renderHook(() => useAuth());

      let loginResult: any;
      await act(async () => {
        loginResult = await result.current.login('john@example.com', 'wrongpassword');
      });

      expect(loginResult).toEqual({
        success: false,
        error: 'Email ou senha inválidos',
      });
    });

    it('should handle login callback error', async () => {
      mockSignIn.mockResolvedValue({
        ok: false,
        error: 'Callback',
        status: 500,
        url: null,
      });

      const { result } = renderHook(() => useAuth());

      let loginResult: any;
      await act(async () => {
        loginResult = await result.current.login('john@example.com', 'password123');
      });

      expect(loginResult).toEqual({
        success: false,
        error: 'Erro de autenticação',
      });
    });

    it('should handle custom login error message', async () => {
      mockSignIn.mockResolvedValue({
        ok: false,
        error: 'UserNotFound',
        status: 404,
        url: null,
      });

      const { result } = renderHook(() => useAuth());

      let loginResult: any;
      await act(async () => {
        loginResult = await result.current.login('john@example.com', 'password123');
      });

      expect(loginResult).toEqual({
        success: false,
        error: 'UserNotFound',
      });
    });

    it('should handle login network error', async () => {
      mockSignIn.mockRejectedValue(new Error('Network error'));

      const { result } = renderHook(() => useAuth());

      let loginResult: any;
      await act(async () => {
        loginResult = await result.current.login('john@example.com', 'password123');
      });

      expect(loginResult).toEqual({
        success: false,
        error: 'Falha na conexão. Tente novamente.',
      });
    });

    it('should handle unknown login failure', async () => {
      mockSignIn.mockResolvedValue({
        ok: false,
        error: null,
        status: 500,
        url: null,
      });

      const { result } = renderHook(() => useAuth());

      let loginResult: any;
      await act(async () => {
        loginResult = await result.current.login('john@example.com', 'password123');
      });

      expect(loginResult).toEqual({
        success: false,
        error: 'Erro desconhecido ao fazer login',
      });
    });
  });

  describe('Google Login Functionality', () => {
    beforeEach(() => {
      mockUseSession.mockReturnValue({
        data: null,
        status: 'unauthenticated',
        update: mockUpdate,
      });
    });

    it('should handle successful Google login', async () => {
      mockSignIn.mockResolvedValue({
        ok: true,
        error: null,
        status: 200,
        url: null,
      });

      const { result } = renderHook(() => useAuth());

      await act(async () => {
        await result.current.loginWithGoogle();
      });

      expect(mockSignIn).toHaveBeenCalledWith('google', { redirect: false });
    });

    it('should handle Google login error', async () => {
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      mockSignIn.mockRejectedValue(new Error('Google OAuth error'));

      const { result } = renderHook(() => useAuth());

      await expect(
        act(async () => {
          await result.current.loginWithGoogle();
        })
      ).rejects.toThrow('Falha ao iniciar login com Google');

      expect(consoleErrorSpy).toHaveBeenCalledWith('Google login error:', expect.any(Error));
      consoleErrorSpy.mockRestore();
    });
  });

  describe('Logout Functionality', () => {
    beforeEach(() => {
      mockUseSession.mockReturnValue({
        data: { 
          user: { id: '123', email: 'john@example.com' },
          expires: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
        },
        status: 'authenticated',
        update: mockUpdate,
      });
    });

    it('should handle successful logout', async () => {
      mockSignOut.mockResolvedValue({ url: '/login' });

      const { result } = renderHook(() => useAuth());

      await act(async () => {
        await result.current.logout();
      });

      expect(mockSignOut).toHaveBeenCalledWith({
        redirect: false,
        callbackUrl: '/login',
      });

      expect(mockRouter.push).toHaveBeenCalledWith('/login');
    });

    it('should handle logout error and force redirect', async () => {
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      mockSignOut.mockRejectedValue(new Error('Logout failed'));

      const { result } = renderHook(() => useAuth());

      await act(async () => {
        await result.current.logout();
      });

      expect(consoleErrorSpy).toHaveBeenCalledWith('Logout error:', expect.any(Error));
      expect(mockRouter.push).toHaveBeenCalledWith('/login');
      consoleErrorSpy.mockRestore();
    });
  });

  describe('Session Refresh Functionality', () => {
    beforeEach(() => {
      mockUseSession.mockReturnValue({
        data: { 
          user: { id: '123', email: 'john@example.com' },
          expires: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
        },
        status: 'authenticated',
        update: mockUpdate,
      });
    });

    it('should handle successful session refresh', async () => {
      mockUpdate.mockResolvedValue(undefined);

      const { result } = renderHook(() => useAuth());

      await act(async () => {
        await result.current.refreshSession();
      });

      expect(mockUpdate).toHaveBeenCalled();
    });

    it('should handle session refresh error', async () => {
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      mockUpdate.mockRejectedValue(new Error('Refresh failed'));

      const { result } = renderHook(() => useAuth());

      await act(async () => {
        await result.current.refreshSession();
      });

      expect(consoleErrorSpy).toHaveBeenCalledWith('Session refresh error:', expect.any(Error));
      consoleErrorSpy.mockRestore();
    });
  });

  describe('Hook Return Type', () => {
    it('should return all required properties and methods', () => {
      mockUseSession.mockReturnValue({
        data: null,
        status: 'unauthenticated',
        update: mockUpdate,
      });

      const { result } = renderHook(() => useAuth());

      // Check state properties
      expect(result.current).toHaveProperty('user');
      expect(result.current).toHaveProperty('isLoading');
      expect(result.current).toHaveProperty('isAuthenticated');
      expect(result.current).toHaveProperty('isError');

      // Check action methods
      expect(result.current).toHaveProperty('login');
      expect(result.current).toHaveProperty('loginWithGoogle');
      expect(result.current).toHaveProperty('logout');
      expect(result.current).toHaveProperty('refreshSession');

      // Check types
      expect(typeof result.current.login).toBe('function');
      expect(typeof result.current.loginWithGoogle).toBe('function');
      expect(typeof result.current.logout).toBe('function');
      expect(typeof result.current.refreshSession).toBe('function');
    });

    it('should maintain stable function references', () => {
      mockUseSession.mockReturnValue({
        data: null,
        status: 'unauthenticated',
        update: mockUpdate,
      });

      const { result, rerender } = renderHook(() => useAuth());

      const firstLogin = result.current.login;
      const firstLogout = result.current.logout;
      const firstLoginWithGoogle = result.current.loginWithGoogle;
      const firstRefreshSession = result.current.refreshSession;

      rerender();

      expect(result.current.login).toBe(firstLogin);
      expect(result.current.logout).toBe(firstLogout);
      expect(result.current.loginWithGoogle).toBe(firstLoginWithGoogle);
      expect(result.current.refreshSession).toBe(firstRefreshSession);
    });
  });

  describe('State Transitions', () => {
    it('should handle transition from loading to authenticated', () => {
      const { result, rerender } = renderHook(() => useAuth());

      // Start with loading state
      mockUseSession.mockReturnValue({
        data: null,
        status: 'loading',
        update: mockUpdate,
      });

      rerender();

      expect(result.current.isLoading).toBe(true);
      expect(result.current.isAuthenticated).toBe(false);

      // Transition to authenticated
      mockUseSession.mockReturnValue({
        data: {
          user: { id: '123', email: 'john@example.com' },
          expires: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
        },
        status: 'authenticated',
        update: mockUpdate,
      });

      rerender();

      expect(result.current.isLoading).toBe(false);
      expect(result.current.isAuthenticated).toBe(true);
      expect(result.current.user).toEqual({
        id: '123',
        email: 'john@example.com',
        name: undefined,
        image: undefined,
        firstName: undefined,
        lastName: undefined,
        emailVerified: undefined,
        role: undefined,
      });
    });

    it('should handle transition from authenticated to unauthenticated', () => {
      const { result, rerender } = renderHook(() => useAuth());

      // Start with authenticated state
      mockUseSession.mockReturnValue({
        data: {
          user: { id: '123', email: 'john@example.com' },
        },
        status: 'authenticated',
        update: mockUpdate,
      });

      rerender();

      expect(result.current.isAuthenticated).toBe(true);
      expect(result.current.user).toBeTruthy();

      // Transition to unauthenticated
      mockUseSession.mockReturnValue({
        data: null,
        status: 'unauthenticated',
        update: mockUpdate,
      });

      rerender();

      expect(result.current.isAuthenticated).toBe(false);
      expect(result.current.user).toBe(null);
      expect(result.current.isError).toBe(true);
    });
  });

  describe('Error Handling Edge Cases', () => {
    it('should handle session data with null user', () => {
      mockUseSession.mockReturnValue({
        data: { user: null },
        status: 'authenticated',
        update: mockUpdate,
      });

      const { result } = renderHook(() => useAuth());

      expect(result.current.isAuthenticated).toBe(false);
      expect(result.current.user).toBe(null);
    });

    it('should handle missing session data', () => {
      mockUseSession.mockReturnValue({
        data: null,
        status: 'authenticated',
        update: mockUpdate,
      });

      const { result } = renderHook(() => useAuth());

      expect(result.current.isAuthenticated).toBe(false);
      expect(result.current.user).toBe(null);
    });

    it('should handle login with empty credentials', async () => {
      mockSignIn.mockResolvedValue({
        ok: false,
        error: 'CredentialsSignin',
        status: 401,
        url: null,
      });

      const { result } = renderHook(() => useAuth());

      let loginResult: any;
      await act(async () => {
        loginResult = await result.current.login('', '');
      });

      expect(mockSignIn).toHaveBeenCalledWith('credentials', {
        redirect: false,
        email: '',
        password: '',
      });

      expect(loginResult).toEqual({
        success: false,
        error: 'Email ou senha inválidos',
      });
    });
  });
}); 