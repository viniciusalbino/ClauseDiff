/**
 * Integration Tests for User Registration and Email Verification Flow
 * 
 * Tests the complete user registration workflow including form validation,
 * API interactions, and email verification using the existing mock system.
 */

import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { server } from '../../__mocks__/api/mock-server'
import { handlers } from '../../__mocks__/api/handlers'
import { generateMockUser } from '../../__mocks__/api/utils'
import React from 'react'

// Registration form component for testing
const TestRegistrationComponent: React.FC = () => {
  const [formData, setFormData] = React.useState({
    firstName: '',
    lastName: '',
    email: '',
    password: '',
    confirmPassword: ''
  })
  const [isLoading, setIsLoading] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)
  const [success, setSuccess] = React.useState(false)
  const [emailVerificationSent, setEmailVerificationSent] = React.useState(false)

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target
    setFormData(prev => ({ ...prev, [name]: value }))
    setError(null) // Clear error on input change
  }

  const validateForm = () => {
    if (!formData.firstName.trim()) return 'First name is required'
    if (!formData.lastName.trim()) return 'Last name is required'
    if (!formData.email.trim()) return 'Email is required'
    if (!formData.email.includes('@')) return 'Invalid email format'
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
      const response = await fetch('/api/auth/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          firstName: formData.firstName,
          lastName: formData.lastName,
          email: formData.email,
          password: formData.password
        })
      })

      const data = await response.json()

      if (response.ok && data.success) {
        setSuccess(true)
        // Simulate email verification sending
        setTimeout(() => {
          setEmailVerificationSent(true)
        }, 1000)
      } else {
        setError(data.error || 'Registration failed')
      }
    } catch (err) {
      setError('Network error. Please try again.')
    } finally {
      setIsLoading(false)
    }
  }

  const handleResendVerification = async () => {
    try {
      const response = await fetch('/api/auth/resend-verification', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: formData.email })
      })

      if (response.ok) {
        setEmailVerificationSent(true)
      }
    } catch (err) {
      setError('Failed to resend verification email')
    }
  }

  if (success && emailVerificationSent) {
    return (
      <div data-testid="verification-sent">
        <h2>Check Your Email</h2>
        <p>We've sent a verification link to {formData.email}</p>
        <button data-testid="resend-button" onClick={handleResendVerification}>
          Resend Email
        </button>
      </div>
    )
  }

  if (success) {
    return (
      <div data-testid="registration-success">
        <h2>Registration Successful!</h2>
        <p>Sending verification email...</p>
      </div>
    )
  }

  return (
    <form onSubmit={handleSubmit} data-testid="registration-form">
      <div>
        <input
          data-testid="firstName-input"
          name="firstName"
          type="text"
          placeholder="First Name"
          value={formData.firstName}
          onChange={handleInputChange}
        />
      </div>
      <div>
        <input
          data-testid="lastName-input"
          name="lastName"
          type="text"
          placeholder="Last Name"
          value={formData.lastName}
          onChange={handleInputChange}
        />
      </div>
      <div>
        <input
          data-testid="email-input"
          name="email"
          type="email"
          placeholder="Email"
          value={formData.email}
          onChange={handleInputChange}
        />
      </div>
      <div>
        <input
          data-testid="password-input"
          name="password"
          type="password"
          placeholder="Password"
          value={formData.password}
          onChange={handleInputChange}
        />
      </div>
      <div>
        <input
          data-testid="confirmPassword-input"
          name="confirmPassword"
          type="password"
          placeholder="Confirm Password"
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
        {isLoading ? 'Creating Account...' : 'Create Account'}
      </button>
    </form>
  )
}

describe('Registration Flow Integration', () => {
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

  describe('Successful Registration Flow', () => {
    it('should complete full registration workflow', async () => {
      const user = userEvent.setup()
      render(<TestRegistrationComponent />)

      // Fill out registration form
      await user.type(screen.getByTestId('firstName-input'), 'John')
      await user.type(screen.getByTestId('lastName-input'), 'Doe')
      await user.type(screen.getByTestId('email-input'), 'john.doe@example.com')
      await user.type(screen.getByTestId('password-input'), 'securepassword123')
      await user.type(screen.getByTestId('confirmPassword-input'), 'securepassword123')

      // Verify form values
      expect(screen.getByDisplayValue('John')).toBeInTheDocument()
      expect(screen.getByDisplayValue('Doe')).toBeInTheDocument()
      expect(screen.getByDisplayValue('john.doe@example.com')).toBeInTheDocument()

      // Submit form
      await user.click(screen.getByTestId('submit-button'))

      // Should show loading state
      expect(screen.getByText('Creating Account...')).toBeInTheDocument()

      // Should show success message
      await waitFor(() => {
        expect(screen.getByTestId('registration-success')).toBeInTheDocument()
        expect(screen.getByText('Registration Successful!')).toBeInTheDocument()
        expect(screen.getByText('Sending verification email...')).toBeInTheDocument()
      })

      // Should eventually show email verification sent
      await waitFor(() => {
        expect(screen.getByTestId('verification-sent')).toBeInTheDocument()
        expect(screen.getByText('Check Your Email')).toBeInTheDocument()
        expect(screen.getByText("We've sent a verification link to john.doe@example.com")).toBeInTheDocument()
      }, { timeout: 2000 })
    })

    it('should handle email verification resend', async () => {
      const user = userEvent.setup()
      render(<TestRegistrationComponent />)

      // Complete registration flow first
      await user.type(screen.getByTestId('firstName-input'), 'Jane')
      await user.type(screen.getByTestId('lastName-input'), 'Smith')
      await user.type(screen.getByTestId('email-input'), 'jane.smith@example.com')
      await user.type(screen.getByTestId('password-input'), 'password123')
      await user.type(screen.getByTestId('confirmPassword-input'), 'password123')
      await user.click(screen.getByTestId('submit-button'))

      // Wait for verification sent screen
      await waitFor(() => {
        expect(screen.getByTestId('verification-sent')).toBeInTheDocument()
      }, { timeout: 2000 })

      // Test resend functionality
      const resendButton = screen.getByTestId('resend-button')
      expect(resendButton).toBeInTheDocument()
      
      await user.click(resendButton)
      
      // Should still show verification sent message
      expect(screen.getByTestId('verification-sent')).toBeInTheDocument()
    })
  })

  describe('Form Validation', () => {
    it('should validate required fields', async () => {
      const user = userEvent.setup()
      render(<TestRegistrationComponent />)

      // Try to submit empty form
      await user.click(screen.getByTestId('submit-button'))

      await waitFor(() => {
        expect(screen.getByTestId('error-message')).toBeInTheDocument()
        expect(screen.getByText('First name is required')).toBeInTheDocument()
      })
    })

    it('should validate email format', async () => {
      const user = userEvent.setup()
      render(<TestRegistrationComponent />)

      // Fill form with invalid email
      await user.type(screen.getByTestId('firstName-input'), 'John')
      await user.type(screen.getByTestId('lastName-input'), 'Doe')
      await user.type(screen.getByTestId('email-input'), 'invalid-email')
      await user.type(screen.getByTestId('password-input'), 'password123')
      await user.type(screen.getByTestId('confirmPassword-input'), 'password123')

      await user.click(screen.getByTestId('submit-button'))

      await waitFor(() => {
        expect(screen.getByTestId('error-message')).toBeInTheDocument()
        expect(screen.getByText('Invalid email format')).toBeInTheDocument()
      })
    })

    it('should validate password requirements', async () => {
      const user = userEvent.setup()
      render(<TestRegistrationComponent />)

      // Fill form with short password
      await user.type(screen.getByTestId('firstName-input'), 'John')
      await user.type(screen.getByTestId('lastName-input'), 'Doe')
      await user.type(screen.getByTestId('email-input'), 'john@example.com')
      await user.type(screen.getByTestId('password-input'), '123')
      await user.type(screen.getByTestId('confirmPassword-input'), '123')

      await user.click(screen.getByTestId('submit-button'))

      await waitFor(() => {
        expect(screen.getByTestId('error-message')).toBeInTheDocument()
        expect(screen.getByText('Password must be at least 8 characters')).toBeInTheDocument()
      })
    })

    it('should validate password confirmation', async () => {
      const user = userEvent.setup()
      render(<TestRegistrationComponent />)

      // Fill form with mismatched passwords
      await user.type(screen.getByTestId('firstName-input'), 'John')
      await user.type(screen.getByTestId('lastName-input'), 'Doe')
      await user.type(screen.getByTestId('email-input'), 'john@example.com')
      await user.type(screen.getByTestId('password-input'), 'password123')
      await user.type(screen.getByTestId('confirmPassword-input'), 'differentpassword')

      await user.click(screen.getByTestId('submit-button'))

      await waitFor(() => {
        expect(screen.getByTestId('error-message')).toBeInTheDocument()
        expect(screen.getByText('Passwords do not match')).toBeInTheDocument()
      })
    })

    it('should clear errors on input change', async () => {
      const user = userEvent.setup()
      render(<TestRegistrationComponent />)

      // Submit empty form to trigger error
      await user.click(screen.getByTestId('submit-button'))

      await waitFor(() => {
        expect(screen.getByTestId('error-message')).toBeInTheDocument()
      })

      // Type in first name field to clear error
      await user.type(screen.getByTestId('firstName-input'), 'John')

      // Error should be cleared
      expect(screen.queryByTestId('error-message')).not.toBeInTheDocument()
    })
  })

  describe('Failed Registration Scenarios', () => {
    it('should handle duplicate email error', async () => {
      const user = userEvent.setup()
      
      // Mock API to return duplicate email error
      server.use(
        ...handlers.filter(h => !h.path.includes('/api/auth/signup')),
        {
          method: 'POST',
          path: '/api/auth/signup',
          handler: () => {
            return new Response(JSON.stringify({
              success: false,
              error: 'Email already exists'
            }), { status: 409 })
          }
        }
      )

      render(<TestRegistrationComponent />)

      // Fill and submit form
      await user.type(screen.getByTestId('firstName-input'), 'John')
      await user.type(screen.getByTestId('lastName-input'), 'Doe')
      await user.type(screen.getByTestId('email-input'), 'existing@example.com')
      await user.type(screen.getByTestId('password-input'), 'password123')
      await user.type(screen.getByTestId('confirmPassword-input'), 'password123')
      await user.click(screen.getByTestId('submit-button'))

      await waitFor(() => {
        expect(screen.getByTestId('error-message')).toBeInTheDocument()
        expect(screen.getByText('Email already exists')).toBeInTheDocument()
      })

      // Form should still be visible for retry
      expect(screen.getByTestId('registration-form')).toBeInTheDocument()
    })

    it('should handle network errors', async () => {
      const user = userEvent.setup()
      
      // Mock fetch to throw network error
      const originalFetch = global.fetch
      global.fetch = jest.fn().mockRejectedValue(new Error('Network error'))

      render(<TestRegistrationComponent />)

      // Fill and submit form
      await user.type(screen.getByTestId('firstName-input'), 'John')
      await user.type(screen.getByTestId('lastName-input'), 'Doe')
      await user.type(screen.getByTestId('email-input'), 'john@example.com')
      await user.type(screen.getByTestId('password-input'), 'password123')
      await user.type(screen.getByTestId('confirmPassword-input'), 'password123')
      await user.click(screen.getByTestId('submit-button'))

      await waitFor(() => {
        expect(screen.getByTestId('error-message')).toBeInTheDocument()
        expect(screen.getByText('Network error. Please try again.')).toBeInTheDocument()
      })

      // Restore original fetch
      global.fetch = originalFetch
    })
  })

  describe('API Integration', () => {
    it('should make correct registration API call', async () => {
      const fetchSpy = jest.spyOn(global, 'fetch')
      const user = userEvent.setup()
      
      render(<TestRegistrationComponent />)

      await user.type(screen.getByTestId('firstName-input'), 'John')
      await user.type(screen.getByTestId('lastName-input'), 'Doe')
      await user.type(screen.getByTestId('email-input'), 'john@example.com')
      await user.type(screen.getByTestId('password-input'), 'password123')
      await user.type(screen.getByTestId('confirmPassword-input'), 'password123')
      await user.click(screen.getByTestId('submit-button'))

      await waitFor(() => {
        expect(fetchSpy).toHaveBeenCalledWith('/api/auth/signup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            firstName: 'John',
            lastName: 'Doe',
            email: 'john@example.com',
            password: 'password123'
          })
        })
      })

      fetchSpy.mockRestore()
    })

    it('should handle successful API response', async () => {
      const response = await fetch('/api/auth/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          firstName: 'Test',
          lastName: 'User',
          email: 'test@example.com',
          password: 'password123'
        })
      })

      expect(response.ok).toBe(true)
      const data = await response.json()
      expect(data.success).toBe(true)
      expect(data.user).toBeDefined()
      expect(data.token).toBeDefined()
    })
  })
}) 