/**
 * Integration Tests for Login/Logout Flow
 * 
 * Tests the complete authentication workflow including API interactions,
 * state management, and UI updates using the existing mock system.
 */

import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { server } from '../../__mocks__/api/mock-server'
import { handlers } from '../../__mocks__/api/handlers'
import { generateMockUser } from '../../__mocks__/api/utils'
import { useAuth, UseAuthReturn } from '../../../src/hooks/useAuth'
import { useSession } from 'next-auth/react'
import React from 'react'

// Mock NextAuth
jest.mock('next-auth/react')
const mockUseSession = useSession as jest.MockedFunction<typeof useSession>

// Mock the auth hook
jest.mock('../../../src/hooks/useAuth')
const mockUseAuth = useAuth as jest.MockedFunction<typeof useAuth>

// Mock next/navigation
jest.mock('next/navigation', () => ({
  useRouter: () => ({
    push: jest.fn(),
    replace: jest.fn(),
    refresh: jest.fn(),
  }),
}))

// Test component that uses auth
const TestAuthComponent: React.FC = () => {
  const { user, login, logout, isLoading, isError } = useAuth()

  const handleLogin = async () => {
    try {
      const result = await login('test@example.com', 'password')
      console.log('Login result:', result)
    } catch (err) {
      console.error('Login failed:', err)
    }
  }

  const handleLogout = async () => {
    try {
      await logout()
    } catch (err) {
      console.error('Logout failed:', err)
    }
  }

  if (isLoading) {
    return <div data-testid="loading">Loading...</div>
  }

  return (
    <div>
      {user ? (
        <div>
          <div data-testid="user-info">
            Welcome, {user.name} ({user.email})
          </div>
          <button data-testid="logout-button" onClick={handleLogout}>
            Logout
          </button>
        </div>
      ) : (
        <div>
          <button data-testid="login-button" onClick={handleLogin}>
            Login
          </button>
          {isError && (
            <div data-testid="error-message">Authentication error</div>
          )}
        </div>
      )}
    </div>
  )
}

describe('Login/Logout Flow Integration', () => {
  const mockUser = generateMockUser()
  
  beforeAll(() => {
    // Setup mock server
    global.fetch = server.mockFetch
    server.listen({ onUnhandledRequest: 'error' })
  })

  beforeEach(() => {
    // Reset mocks
    jest.clearAllMocks()
    
    // Setup default mock implementations
    mockUseSession.mockReturnValue({
      data: null,
      status: 'unauthenticated',
      update: jest.fn()
    })

    mockUseAuth.mockReturnValue({
      user: null,
      login: jest.fn(),
      loginWithGoogle: jest.fn(),
      logout: jest.fn(),
      refreshSession: jest.fn(),
      isLoading: false,
      isError: false,
      isAuthenticated: false
    })

    // Use the handlers from the existing mock system
    server.use(...handlers)
  })

  afterEach(() => {
    server.resetHandlers()
  })

  afterAll(() => {
    server.close()
    jest.restoreAllMocks()
  })

  describe('Successful Login Flow', () => {
    it('should complete login flow and update user state', async () => {
      const user = userEvent.setup()

      const mockLogin = jest.fn().mockResolvedValue({ success: true })

      // Update mock to return loading state initially, then success
      mockUseAuth
        .mockReturnValueOnce({
          user: null,
          login: mockLogin,
          loginWithGoogle: jest.fn(),
          logout: jest.fn(),
          refreshSession: jest.fn(),
          isLoading: false,
          isError: false,
          isAuthenticated: false
        })
        .mockReturnValueOnce({
          user: null,
          login: mockLogin,
          loginWithGoogle: jest.fn(),
          logout: jest.fn(),
          refreshSession: jest.fn(),
          isLoading: true,
          isError: false,
          isAuthenticated: false
        })
        .mockReturnValue({
          user: mockUser,
          login: mockLogin,
          loginWithGoogle: jest.fn(),
          logout: jest.fn(),
          refreshSession: jest.fn(),
          isLoading: false,
          isError: false,
          isAuthenticated: true
        })

      const { rerender } = render(<TestAuthComponent />)

      // Initially should show login button
      expect(screen.getByTestId('login-button')).toBeInTheDocument()

      // Click login button
      await user.click(screen.getByTestId('login-button'))

      // Should call login function
      expect(mockLogin).toHaveBeenCalledWith('test@example.com', 'password')

      // Rerender with loading state
      mockUseAuth.mockReturnValue({
        user: null,
        login: mockLogin,
        loginWithGoogle: jest.fn(),
        logout: jest.fn(),
        refreshSession: jest.fn(),
        isLoading: true,
        isError: false,
        isAuthenticated: false
      })
      rerender(<TestAuthComponent />)

      // Should show loading state
      expect(screen.getByTestId('loading')).toBeInTheDocument()

      // Rerender with authenticated state
      mockUseAuth.mockReturnValue({
        user: mockUser,
        login: mockLogin,
        loginWithGoogle: jest.fn(),
        logout: jest.fn(),
        refreshSession: jest.fn(),
        isLoading: false,
        isError: false,
        isAuthenticated: true
      })
      rerender(<TestAuthComponent />)

      // Should show user info and logout button
      await waitFor(() => {
        expect(screen.getByTestId('user-info')).toBeInTheDocument()
        expect(screen.getByTestId('logout-button')).toBeInTheDocument()
        expect(screen.getByText(`Welcome, ${mockUser.name} (${mockUser.email})`)).toBeInTheDocument()
      })
    })

    it('should handle session persistence after login', async () => {
      // Mock session with authenticated user
      mockUseSession.mockReturnValue({
        data: {
          user: mockUser,
          expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
        },
        status: 'authenticated',
        update: jest.fn()
      })

      mockUseAuth.mockReturnValue({
        user: mockUser,
        login: jest.fn(),
        loginWithGoogle: jest.fn(),
        logout: jest.fn(),
        refreshSession: jest.fn(),
        isLoading: false,
        isError: false,
        isAuthenticated: true
      })

      render(<TestAuthComponent />)

      // Should show authenticated state
      expect(screen.getByTestId('user-info')).toBeInTheDocument()
      expect(screen.getByTestId('logout-button')).toBeInTheDocument()
      expect(screen.getByText(`Welcome, ${mockUser.name} (${mockUser.email})`)).toBeInTheDocument()
    })
  })

  describe('Failed Login Flow', () => {
    it('should handle login failure with error response', async () => {
      const user = userEvent.setup()

      const mockLogin = jest.fn().mockResolvedValue({ 
        success: false, 
        error: 'Invalid credentials' 
      })

      mockUseAuth
        .mockReturnValueOnce({
          user: null,
          login: mockLogin,
          loginWithGoogle: jest.fn(),
          logout: jest.fn(),
          refreshSession: jest.fn(),
          isLoading: false,
          isError: false,
          isAuthenticated: false
        })
        .mockReturnValue({
          user: null,
          login: mockLogin,
          loginWithGoogle: jest.fn(),
          logout: jest.fn(),
          refreshSession: jest.fn(),
          isLoading: false,
          isError: true,
          isAuthenticated: false
        })

      const { rerender } = render(<TestAuthComponent />)

      // Click login button
      await user.click(screen.getByTestId('login-button'))

      // Should call login function
      expect(mockLogin).toHaveBeenCalledWith('test@example.com', 'password')

      // Rerender with error state
      rerender(<TestAuthComponent />)

      // Should show error message
      await waitFor(() => {
        expect(screen.getByTestId('error-message')).toBeInTheDocument()
        expect(screen.getByText('Authentication error')).toBeInTheDocument()
      })

      // Should still show login button
      expect(screen.getByTestId('login-button')).toBeInTheDocument()
    })
  })

  describe('Logout Flow', () => {
    it('should complete logout flow and clear user state', async () => {
      const user = userEvent.setup()

      const mockLogout = jest.fn().mockResolvedValue(undefined)

      // Start with authenticated state
      mockUseAuth
        .mockReturnValueOnce({
          user: mockUser,
          login: jest.fn(),
          loginWithGoogle: jest.fn(),
          logout: mockLogout,
          refreshSession: jest.fn(),
          isLoading: false,
          isError: false,
          isAuthenticated: true
        })
        .mockReturnValueOnce({
          user: mockUser,
          login: jest.fn(),
          loginWithGoogle: jest.fn(),
          logout: mockLogout,
          refreshSession: jest.fn(),
          isLoading: true,
          isError: false,
          isAuthenticated: true
        })
        .mockReturnValue({
          user: null,
          login: jest.fn(),
          loginWithGoogle: jest.fn(),
          logout: mockLogout,
          refreshSession: jest.fn(),
          isLoading: false,
          isError: false,
          isAuthenticated: false
        })

      const { rerender } = render(<TestAuthComponent />)

      // Should show authenticated state
      expect(screen.getByTestId('user-info')).toBeInTheDocument()
      expect(screen.getByTestId('logout-button')).toBeInTheDocument()

      // Click logout button
      await user.click(screen.getByTestId('logout-button'))

      // Should call logout function
      expect(mockLogout).toHaveBeenCalled()

      // Rerender with loading state
      mockUseAuth.mockReturnValue({
        user: null,
        login: jest.fn(),
        loginWithGoogle: jest.fn(),
        logout: mockLogout,
        refreshSession: jest.fn(),
        isLoading: true,
        isError: false,
        isAuthenticated: false
      })
      rerender(<TestAuthComponent />)

      // Should show loading state
      expect(screen.getByTestId('loading')).toBeInTheDocument()

      // Rerender with logged out state
      mockUseAuth.mockReturnValue({
        user: null,
        login: jest.fn(),
        loginWithGoogle: jest.fn(),
        logout: mockLogout,
        refreshSession: jest.fn(),
        isLoading: false,
        isError: false,
        isAuthenticated: false
      })
      rerender(<TestAuthComponent />)

      // Should show login button again
      await waitFor(() => {
        expect(screen.getByTestId('login-button')).toBeInTheDocument()
        expect(screen.queryByTestId('user-info')).not.toBeInTheDocument()
        expect(screen.queryByTestId('logout-button')).not.toBeInTheDocument()
      })
    })
  })

  describe('Authentication State Transitions', () => {
    it('should handle rapid login/logout cycles', async () => {
      const user = userEvent.setup()

      const mockLogin = jest.fn().mockResolvedValue({ success: true })
      const mockLogout = jest.fn().mockResolvedValue(undefined)

      let isAuthenticated = false

      mockUseAuth.mockImplementation(() => ({
        user: isAuthenticated ? mockUser : null,
        login: mockLogin,
        loginWithGoogle: jest.fn(),
        logout: mockLogout,
        refreshSession: jest.fn(),
        isLoading: false,
        isError: false,
        isAuthenticated
      }))

      const { rerender } = render(<TestAuthComponent />)

      // Start logged out
      expect(screen.getByTestId('login-button')).toBeInTheDocument()

      // Login
      await user.click(screen.getByTestId('login-button'))
      isAuthenticated = true
      rerender(<TestAuthComponent />)

      expect(screen.getByTestId('user-info')).toBeInTheDocument()

      // Logout
      await user.click(screen.getByTestId('logout-button'))
      isAuthenticated = false
      rerender(<TestAuthComponent />)

      expect(screen.getByTestId('login-button')).toBeInTheDocument()

      // Login again
      await user.click(screen.getByTestId('login-button'))
      isAuthenticated = true
      rerender(<TestAuthComponent />)

      expect(screen.getByTestId('user-info')).toBeInTheDocument()

      // Verify both functions were called multiple times
      expect(mockLogin).toHaveBeenCalledTimes(2)
      expect(mockLogout).toHaveBeenCalledTimes(1)
    })

    it('should handle session expiration', async () => {
      // Mock expired session
      mockUseSession.mockReturnValue({
        data: null,
        status: 'unauthenticated',
        update: jest.fn()
      })

      mockUseAuth.mockReturnValue({
        user: null,
        login: jest.fn(),
        loginWithGoogle: jest.fn(),
        logout: jest.fn(),
        refreshSession: jest.fn(),
        isLoading: false,
        isError: true,
        isAuthenticated: false
      })

      render(<TestAuthComponent />)

      // Should show login button and session expired error
      expect(screen.getByTestId('login-button')).toBeInTheDocument()
      expect(screen.getByTestId('error-message')).toBeInTheDocument()
      expect(screen.getByText('Authentication error')).toBeInTheDocument()
    })
  })

  describe('API Integration', () => {
    it('should interact with mock API endpoints', async () => {
      const fetchSpy = jest.spyOn(global, 'fetch')
      
      // Test login API call
      const response = await fetch('/api/auth/signin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com', password: 'password' })
      })

      expect(response.ok).toBe(true)
      const data = await response.json()
      expect(data.success).toBe(true)
      expect(data.user).toBeDefined()

      fetchSpy.mockRestore()
    })

    it('should handle logout API call', async () => {
      const fetchSpy = jest.spyOn(global, 'fetch')
      
      // Test logout API call
      const response = await fetch('/api/auth/signout', {
        method: 'POST'
      })

      expect(response.ok).toBe(true)
      const data = await response.json()
      expect(data.success).toBe(true)

      fetchSpy.mockRestore()
    })
  })
}) 