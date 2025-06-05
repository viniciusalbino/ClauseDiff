/**
 * Integration Tests for Password Reset Flow
 * 
 * Tests the complete password reset workflow including forgot password,
 * email verification, and password update using the existing mock system.
 */

import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { server } from '../../__mocks__/api/mock-server'
import { handlers } from '../../__mocks__/api/handlers'
import React from 'react'

// Forgot Password component for testing
const TestForgotPasswordComponent: React.FC = () => {
  const [email, setEmail] = React.useState('')
  const [isLoading, setIsLoading] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)
  const [success, setSuccess] = React.useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    if (!email.trim()) {
      setError('Email is required')
      return
    }

    if (!email.includes('@')) {
      setError('Invalid email format')
      return
    }

    setIsLoading(true)
    setError(null)

    try {
      const response = await fetch('/api/auth/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      })

      const data = await response.json()

      if (response.ok && data.success) {
        setSuccess(true)
      } else {
        setError(data.error || 'Failed to send reset email')
      }
    } catch (err) {
      setError('Network error. Please try again.')
    } finally {
      setIsLoading(false)
    }
  }

  if (success) {
    return (
      <div data-testid="reset-email-sent">
        <h2>Check Your Email</h2>
        <p>We've sent a password reset link to {email}</p>
        <button data-testid="back-to-login" onClick={() => setSuccess(false)}>
          Back to Login
        </button>
      </div>
    )
  }

  return (
    <form onSubmit={handleSubmit} data-testid="forgot-password-form">
      <div>
        <input
          data-testid="email-input"
          type="email"
          placeholder="Enter your email"
          value={email}
          onChange={(e) => {
            setEmail(e.target.value)
            setError(null)
          }}
        />
      </div>
      {error && (
        <div data-testid="error-message" style={{ color: 'red' }}>
          {error}
        </div>
      )}
      <button
        data-testid="submit-button"
        type="submit"
        disabled={isLoading}
      >
        {isLoading ? 'Sending...' : 'Send Reset Link'}
      </button>
    </form>
  )
}

// Reset Password component for testing
const TestResetPasswordComponent: React.FC<{ token: string }> = ({ token }) => {
  const [formData, setFormData] = React.useState({
    password: '',
    confirmPassword: ''
  })
  const [isLoading, setIsLoading] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)
  const [success, setSuccess] = React.useState(false)

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target
    setFormData(prev => ({ ...prev, [name]: value }))
    setError(null)
  }

  const validateForm = () => {
    if (!formData.password) return 'Password is required'
    if (formData.password.length < 8) return 'Password must be at least 8 characters'
    if (formData.password !== formData.confirmPassword) return 'Passwords do not match'
    return null
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    const validationError = validateForm()
    if (validationError) {
      setError(validationError)
      return
    }

    setIsLoading(true)
    setError(null)

    try {
      const response = await fetch('/api/auth/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token,
          password: formData.password
        })
      })

      const data = await response.json()

      if (response.ok && data.success) {
        setSuccess(true)
      } else {
        setError(data.error || 'Failed to reset password')
      }
    } catch (err) {
      setError('Network error. Please try again.')
    } finally {
      setIsLoading(false)
    }
  }

  if (success) {
    return (
      <div data-testid="password-reset-success">
        <h2>Password Reset Successful</h2>
        <p>Your password has been updated successfully.</p>
        <button data-testid="login-button">Login with New Password</button>
      </div>
    )
  }

  return (
    <form onSubmit={handleSubmit} data-testid="reset-password-form">
      <div>
        <input
          data-testid="password-input"
          name="password"
          type="password"
          placeholder="New Password"
          value={formData.password}
          onChange={handleInputChange}
        />
      </div>
      <div>
        <input
          data-testid="confirmPassword-input"
          name="confirmPassword"
          type="password"
          placeholder="Confirm New Password"
          value={formData.confirmPassword}
          onChange={handleInputChange}
        />
      </div>
      {error && (
        <div data-testid="error-message" style={{ color: 'red' }}>
          {error}
        </div>
      )}
      <button
        data-testid="submit-button"
        type="submit"
        disabled={isLoading}
      >
        {isLoading ? 'Resetting...' : 'Reset Password'}
      </button>
    </form>
  )
}

describe('Password Reset Flow Integration', () => {
  beforeAll(() => {
    global.fetch = server.mockFetch
    server.listen({ onUnhandledRequest: 'error' })
  })

  beforeEach(() => {
    jest.clearAllMocks()
    server.use(...handlers)
  })

  afterEach(() => {
    server.resetHandlers()
  })

  afterAll(() => {
    server.close()
    jest.restoreAllMocks()
  })

  describe('Forgot Password Flow', () => {
    it('should complete forgot password workflow', async () => {
      const user = userEvent.setup()
      render(<TestForgotPasswordComponent />)

      // Fill email and submit
      await user.type(screen.getByTestId('email-input'), 'user@example.com')
      await user.click(screen.getByTestId('submit-button'))

      // Should show success message
      await waitFor(() => {
        expect(screen.getByTestId('reset-email-sent')).toBeInTheDocument()
        expect(screen.getByText('Check Your Email')).toBeInTheDocument()
        expect(screen.getByText("We've sent a password reset link to user@example.com")).toBeInTheDocument()
      })

      // Should have back to login button
      expect(screen.getByTestId('back-to-login')).toBeInTheDocument()
    })

    it('should validate email input', async () => {
      const user = userEvent.setup()
      render(<TestForgotPasswordComponent />)

      // Submit without email
      await user.click(screen.getByTestId('submit-button'))

      await waitFor(() => {
        expect(screen.getByTestId('error-message')).toBeInTheDocument()
        expect(screen.getByText('Email is required')).toBeInTheDocument()
      })

      // Test invalid email format
      await user.type(screen.getByTestId('email-input'), 'invalid-email')
      await user.click(screen.getByTestId('submit-button'))

      await waitFor(() => {
        expect(screen.getByTestId('error-message')).toBeInTheDocument()
        expect(screen.getByText('Invalid email format')).toBeInTheDocument()
      })
    })

    it('should clear errors on input change', async () => {
      const user = userEvent.setup()
      render(<TestForgotPasswordComponent />)

      // Submit to trigger error
      await user.click(screen.getByTestId('submit-button'))

      await waitFor(() => {
        expect(screen.getByTestId('error-message')).toBeInTheDocument()
      })

      // Type in email to clear error
      await user.type(screen.getByTestId('email-input'), 'user@example.com')

      expect(screen.queryByTestId('error-message')).not.toBeInTheDocument()
    })
  })

  describe('Reset Password Flow', () => {
    it('should complete password reset workflow', async () => {
      const user = userEvent.setup()
      const testToken = 'valid-reset-token'
      
      render(<TestResetPasswordComponent token={testToken} />)

      // Fill password fields
      await user.type(screen.getByTestId('password-input'), 'newpassword123')
      await user.type(screen.getByTestId('confirmPassword-input'), 'newpassword123')
      await user.click(screen.getByTestId('submit-button'))

      // Should show success message
      await waitFor(() => {
        expect(screen.getByTestId('password-reset-success')).toBeInTheDocument()
        expect(screen.getByText('Password Reset Successful')).toBeInTheDocument()
        expect(screen.getByText('Your password has been updated successfully.')).toBeInTheDocument()
      })

      // Should have login button
      expect(screen.getByTestId('login-button')).toBeInTheDocument()
    })

    it('should validate password requirements', async () => {
      const user = userEvent.setup()
      render(<TestResetPasswordComponent token="test-token" />)

      // Test empty password
      await user.click(screen.getByTestId('submit-button'))

      await waitFor(() => {
        expect(screen.getByTestId('error-message')).toBeInTheDocument()
        expect(screen.getByText('Password is required')).toBeInTheDocument()
      })

      // Test short password
      await user.type(screen.getByTestId('password-input'), '123')
      await user.type(screen.getByTestId('confirmPassword-input'), '123')
      await user.click(screen.getByTestId('submit-button'))

      await waitFor(() => {
        expect(screen.getByText('Password must be at least 8 characters')).toBeInTheDocument()
      })
    })

    it('should validate password confirmation', async () => {
      const user = userEvent.setup()
      render(<TestResetPasswordComponent token="test-token" />)

      // Fill mismatched passwords
      await user.type(screen.getByTestId('password-input'), 'password123')
      await user.type(screen.getByTestId('confirmPassword-input'), 'differentpassword')
      await user.click(screen.getByTestId('submit-button'))

      await waitFor(() => {
        expect(screen.getByTestId('error-message')).toBeInTheDocument()
        expect(screen.getByText('Passwords do not match')).toBeInTheDocument()
      })
    })
  })

  describe('Error Handling', () => {
    it('should handle invalid email in forgot password', async () => {
      const user = userEvent.setup()
      
      // Mock API to return error for invalid email
      server.use(
        ...handlers.filter(h => !h.path.includes('/api/auth/forgot-password')),
        {
          method: 'POST',
          path: '/api/auth/forgot-password',
          handler: () => {
            return new Response(JSON.stringify({
              success: false,
              error: 'Email not found'
            }), { status: 404 })
          }
        }
      )

      render(<TestForgotPasswordComponent />)

      await user.type(screen.getByTestId('email-input'), 'nonexistent@example.com')
      await user.click(screen.getByTestId('submit-button'))

      await waitFor(() => {
        expect(screen.getByTestId('error-message')).toBeInTheDocument()
        expect(screen.getByText('Email not found')).toBeInTheDocument()
      })
    })

    it('should handle invalid token in password reset', async () => {
      const user = userEvent.setup()
      
      // Mock API to return error for invalid token
      server.use(
        ...handlers.filter(h => !h.path.includes('/api/auth/reset-password')),
        {
          method: 'POST',
          path: '/api/auth/reset-password',
          handler: () => {
            return new Response(JSON.stringify({
              success: false,
              error: 'Invalid or expired token'
            }), { status: 400 })
          }
        }
      )

      render(<TestResetPasswordComponent token="invalid-token" />)

      await user.type(screen.getByTestId('password-input'), 'newpassword123')
      await user.type(screen.getByTestId('confirmPassword-input'), 'newpassword123')
      await user.click(screen.getByTestId('submit-button'))

      await waitFor(() => {
        expect(screen.getByTestId('error-message')).toBeInTheDocument()
        expect(screen.getByText('Invalid or expired token')).toBeInTheDocument()
      })
    })

    it('should handle network errors', async () => {
      const user = userEvent.setup()
      const originalFetch = global.fetch
      
      // Mock fetch to throw error
      global.fetch = jest.fn().mockRejectedValue(new Error('Network error'))

      render(<TestForgotPasswordComponent />)

      await user.type(screen.getByTestId('email-input'), 'user@example.com')
      await user.click(screen.getByTestId('submit-button'))

      await waitFor(() => {
        expect(screen.getByTestId('error-message')).toBeInTheDocument()
        expect(screen.getByText('Network error. Please try again.')).toBeInTheDocument()
      })

      // Restore fetch
      global.fetch = originalFetch
    })
  })

  describe('API Integration', () => {
    it('should make correct forgot password API call', async () => {
      const fetchSpy = jest.spyOn(global, 'fetch')
      const user = userEvent.setup()
      
      render(<TestForgotPasswordComponent />)

      await user.type(screen.getByTestId('email-input'), 'test@example.com')
      await user.click(screen.getByTestId('submit-button'))

      await waitFor(() => {
        expect(fetchSpy).toHaveBeenCalledWith('/api/auth/forgot-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: 'test@example.com' })
        })
      })

      fetchSpy.mockRestore()
    })

    it('should make correct reset password API call', async () => {
      const fetchSpy = jest.spyOn(global, 'fetch')
      const user = userEvent.setup()
      const testToken = 'test-token'
      
      render(<TestResetPasswordComponent token={testToken} />)

      await user.type(screen.getByTestId('password-input'), 'newpassword123')
      await user.type(screen.getByTestId('confirmPassword-input'), 'newpassword123')
      await user.click(screen.getByTestId('submit-button'))

      await waitFor(() => {
        expect(fetchSpy).toHaveBeenCalledWith('/api/auth/reset-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            token: testToken,
            password: 'newpassword123'
          })
        })
      })

      fetchSpy.mockRestore()
    })

    it('should handle successful API responses', async () => {
      // Test forgot password API
      const forgotResponse = await fetch('/api/auth/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com' })
      })

      expect(forgotResponse.ok).toBe(true)
      const forgotData = await forgotResponse.json()
      expect(forgotData.success).toBe(true)

      // Test reset password API
      const resetResponse = await fetch('/api/auth/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: 'valid-token',
          password: 'newpassword123'
        })
      })

      expect(resetResponse.ok).toBe(true)
      const resetData = await resetResponse.json()
      expect(resetData.success).toBe(true)
    })
  })
}) 