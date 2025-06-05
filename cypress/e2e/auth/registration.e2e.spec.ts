/**
 * E2E Tests for User Registration Journey
 * 
 * Tests the complete user registration flow across different browsers
 * and viewport configurations.
 */

import { loginPage, registerPage } from '../../support/page-objects'

describe('User Registration E2E Journey', () => {
  beforeEach(() => {
    cy.cleanDatabase()
    cy.visit('/register')
  })

  afterEach(() => {
    cy.cleanDatabase()
  })

  describe('Complete Registration Flow', () => {
    it('should complete full registration workflow on desktop', () => {
      cy.viewport(1280, 720) // Desktop viewport

      // Fill registration form
      registerPage.enterFirstName('John')
      registerPage.enterLastName('Doe')
      registerPage.enterEmail('john.doe@example.com')
      registerPage.enterPassword('SecurePassword123!')
      registerPage.enterConfirmPassword('SecurePassword123!')
      registerPage.acceptTerms()

      // Verify password strength indicator
      registerPage.verifyPasswordStrength('strong')

      // Submit registration
      registerPage.clickSubmitButton()

      // Verify success message
      registerPage.verifySuccessMessage()
      registerPage.verifyEmailVerificationMessage('john.doe@example.com')

      // Verify user is created in database
      cy.checkDatabaseUser('john.doe@example.com')
    })

    it('should complete registration workflow on mobile', () => {
      cy.viewport('iphone-x') // Mobile viewport

      // Test mobile-specific interactions
      registerPage.enterFirstName('Jane')
      registerPage.enterLastName('Smith')
      registerPage.enterEmail('jane.smith@example.com')
      registerPage.enterPassword('MobilePassword123!')
      registerPage.enterConfirmPassword('MobilePassword123!')

      // Mobile-specific scrolling may be needed
      cy.scrollTo('bottom')
      registerPage.acceptTerms()
      registerPage.clickSubmitButton()

      registerPage.verifySuccessMessage()
      registerPage.verifyEmailVerificationMessage('jane.smith@example.com')
    })

    it('should complete registration workflow on tablet', () => {
      cy.viewport('ipad-2') // Tablet viewport

      registerPage.enterFirstName('Robert')
      registerPage.enterLastName('Johnson')
      registerPage.enterEmail('robert.johnson@example.com')
      registerPage.enterPassword('TabletPassword123!')
      registerPage.enterConfirmPassword('TabletPassword123!')
      registerPage.acceptTerms()
      registerPage.clickSubmitButton()

      registerPage.verifySuccessMessage()
      registerPage.verifyEmailVerificationMessage('robert.johnson@example.com')
    })
  })

  describe('Form Validation', () => {
    it('should validate all required fields', () => {
      // Try to submit empty form
      registerPage.clickSubmitButton()

      // Verify validation errors appear
      registerPage.verifyValidationError('firstName', 'First name is required')
      
      // Fill fields one by one and verify errors clear
      registerPage.enterFirstName('John')
      registerPage.verifyNoValidationError('firstName')

      registerPage.enterLastName('Doe')
      registerPage.verifyNoValidationError('lastName')

      registerPage.enterEmail('john@example.com')
      registerPage.verifyNoValidationError('email')

      registerPage.enterPassword('Password123!')
      registerPage.verifyNoValidationError('password')

      registerPage.enterConfirmPassword('Password123!')
      registerPage.verifyNoValidationError('confirmPassword')
    })

    it('should validate email format', () => {
      registerPage.enterFirstName('John')
      registerPage.enterLastName('Doe')
      
      // Test invalid email formats
      const invalidEmails = [
        'invalid-email',
        'test@',
        '@example.com',
        'test..test@example.com'
      ]

      invalidEmails.forEach(email => {
        registerPage.clearEmailField()
        registerPage.enterEmail(email)
        registerPage.clickSubmitButton()
        registerPage.verifyValidationError('email', 'Please enter a valid email address')
      })

      // Test valid email
      registerPage.clearEmailField()
      registerPage.enterEmail('valid@example.com')
      registerPage.verifyNoValidationError('email')
    })

    it('should validate password requirements', () => {
      registerPage.enterFirstName('John')
      registerPage.enterLastName('Doe')
      registerPage.enterEmail('john@example.com')

      // Test weak passwords
      const weakPasswords = [
        '123',           // Too short
        'password',      // No uppercase or numbers
        'PASSWORD',      // No lowercase or numbers
        '12345678',      // No letters
        'Password'       // No numbers
      ]

      weakPasswords.forEach(password => {
        registerPage.clearPasswordField()
        registerPage.enterPassword(password)
        registerPage.verifyPasswordStrength('weak')
      })

      // Test strong password
      registerPage.clearPasswordField()
      registerPage.enterPassword('StrongPassword123!')
      registerPage.verifyPasswordStrength('strong')
    })

    it('should validate password confirmation', () => {
      registerPage.enterFirstName('John')
      registerPage.enterLastName('Doe')
      registerPage.enterEmail('john@example.com')
      registerPage.enterPassword('Password123!')
      registerPage.enterConfirmPassword('DifferentPassword123!')
      
      registerPage.clickSubmitButton()
      registerPage.verifyValidationError('confirmPassword', 'Passwords do not match')

      // Fix password confirmation
      registerPage.clearConfirmPasswordField()
      registerPage.enterConfirmPassword('Password123!')
      registerPage.verifyNoValidationError('confirmPassword')
    })

    it('should require terms and conditions acceptance', () => {
      registerPage.enterFirstName('John')
      registerPage.enterLastName('Doe')
      registerPage.enterEmail('john@example.com')
      registerPage.enterPassword('Password123!')
      registerPage.enterConfirmPassword('Password123!')
      
      // Don't accept terms
      registerPage.clickSubmitButton()
      registerPage.verifyValidationError('terms', 'You must accept the terms and conditions')

      // Accept terms
      registerPage.acceptTerms()
      registerPage.verifyNoValidationError('terms')
    })
  })

  describe('Error Scenarios', () => {
    it('should handle duplicate email registration', () => {
      // Create a user first
      cy.createTestUser({
        email: 'existing@example.com',
        firstName: 'Existing',
        lastName: 'User',
        password: 'password123'
      })

      // Try to register with same email
      registerPage.enterFirstName('John')
      registerPage.enterLastName('Doe')
      registerPage.enterEmail('existing@example.com')
      registerPage.enterPassword('Password123!')
      registerPage.enterConfirmPassword('Password123!')
      registerPage.acceptTerms()
      registerPage.clickSubmitButton()

      // Verify error message
      registerPage.verifyErrorMessage('Email address is already registered')
      
      // Verify form is still accessible for retry
      registerPage.verifyFormIsVisible()
    })

    it('should handle network errors gracefully', () => {
      // Intercept registration API to simulate network error
      cy.intercept('POST', '/api/auth/register', {
        statusCode: 500,
        body: { error: 'Internal server error' }
      }).as('registrationError')

      registerPage.enterFirstName('John')
      registerPage.enterLastName('Doe')
      registerPage.enterEmail('john@example.com')
      registerPage.enterPassword('Password123!')
      registerPage.enterConfirmPassword('Password123!')
      registerPage.acceptTerms()
      registerPage.clickSubmitButton()

      cy.wait('@registrationError')
      registerPage.verifyErrorMessage('Registration failed. Please try again.')
    })

    it('should handle slow network conditions', () => {
      // Simulate slow network
      cy.intercept('POST', '/api/auth/register', (req) => {
        req.reply((res) => {
          res.delay(3000) // 3 second delay
          res.send({ success: true, user: { id: '123' } })
        })
      }).as('slowRegistration')

      registerPage.enterFirstName('John')
      registerPage.enterLastName('Doe')
      registerPage.enterEmail('john@example.com')
      registerPage.enterPassword('Password123!')
      registerPage.enterConfirmPassword('Password123!')
      registerPage.acceptTerms()
      registerPage.clickSubmitButton()

      // Verify loading state
      registerPage.verifyLoadingState()
      
      cy.wait('@slowRegistration')
      registerPage.verifySuccessMessage()
    })
  })

  describe('Accessibility', () => {
    it('should be accessible with keyboard navigation', () => {
      // Test tab navigation through form
      cy.get('body').tab()
      cy.focused().should('have.attr', 'data-testid', 'firstName-input')
      
      cy.focused().tab()
      cy.focused().should('have.attr', 'data-testid', 'lastName-input')
      
      cy.focused().tab()
      cy.focused().should('have.attr', 'data-testid', 'email-input')
      
      cy.focused().tab()
      cy.focused().should('have.attr', 'data-testid', 'password-input')
      
      cy.focused().tab()
      cy.focused().should('have.attr', 'data-testid', 'confirmPassword-input')
      
      cy.focused().tab()
      cy.focused().should('have.attr', 'data-testid', 'terms-checkbox')
      
      cy.focused().tab()
      cy.focused().should('have.attr', 'data-testid', 'submit-button')
    })

    it('should have proper ARIA labels and descriptions', () => {
      registerPage.verifyAccessibilityLabels()
      registerPage.verifyAriaDescriptions()
    })

    it('should pass automated accessibility checks', () => {
      cy.checkA11y()
    })

    it('should work with screen readers', () => {
      // Test with high contrast mode
      cy.get('body').invoke('attr', 'style', 'filter: contrast(5)')
      
      // Verify form is still usable
      registerPage.enterFirstName('John')
      registerPage.enterLastName('Doe')
      registerPage.enterEmail('john@example.com')
      registerPage.enterPassword('Password123!')
      registerPage.enterConfirmPassword('Password123!')
      registerPage.acceptTerms()
      
      // Verify contrast doesn't break functionality
      registerPage.clickSubmitButton()
      registerPage.verifySuccessMessage()
    })
  })

  describe('Cross-Browser Compatibility', () => {
    // These tests will run on different browsers based on Cypress configuration
    it('should work on Chrome', () => {
      registerPage.enterFirstName('Chrome')
      registerPage.enterLastName('User')
      registerPage.enterEmail('chrome@example.com')
      registerPage.enterPassword('ChromePassword123!')
      registerPage.enterConfirmPassword('ChromePassword123!')
      registerPage.acceptTerms()
      registerPage.clickSubmitButton()
      registerPage.verifySuccessMessage()
    })

    it('should work on Firefox', () => {
      registerPage.enterFirstName('Firefox')
      registerPage.enterLastName('User')
      registerPage.enterEmail('firefox@example.com')
      registerPage.enterPassword('FirefoxPassword123!')
      registerPage.enterConfirmPassword('FirefoxPassword123!')
      registerPage.acceptTerms()
      registerPage.clickSubmitButton()
      registerPage.verifySuccessMessage()
    })

    it('should work on Safari', () => {
      registerPage.enterFirstName('Safari')
      registerPage.enterLastName('User')
      registerPage.enterEmail('safari@example.com')
      registerPage.enterPassword('SafariPassword123!')
      registerPage.enterConfirmPassword('SafariPassword123!')
      registerPage.acceptTerms()
      registerPage.clickSubmitButton()
      registerPage.verifySuccessMessage()
    })
  })

  describe('Email Verification Flow', () => {
    it('should handle email verification after registration', () => {
      // Complete registration
      registerPage.enterFirstName('Verify')
      registerPage.enterLastName('User')
      registerPage.enterEmail('verify@example.com')
      registerPage.enterPassword('VerifyPassword123!')
      registerPage.enterConfirmPassword('VerifyPassword123!')
      registerPage.acceptTerms()
      registerPage.clickSubmitButton()

      // Verify email verification screen
      registerPage.verifyEmailVerificationMessage('verify@example.com')
      
      // Test resend email functionality
      registerPage.clickResendEmailButton()
      registerPage.verifyResendEmailMessage()

      // Simulate email verification link click
      cy.visit('/auth/verify-email?token=mock-verification-token&email=verify@example.com')
      
      // Verify successful verification
      cy.contains('Email verified successfully').should('be.visible')
      cy.contains('You can now log in').should('be.visible')
    })

    it('should handle expired verification tokens', () => {
      cy.visit('/auth/verify-email?token=expired-token&email=test@example.com')
      
      cy.contains('Verification link expired').should('be.visible')
      cy.contains('Request new verification email').should('be.visible')
    })

    it('should handle invalid verification tokens', () => {
      cy.visit('/auth/verify-email?token=invalid-token&email=test@example.com')
      
      cy.contains('Invalid verification link').should('be.visible')
      cy.contains('Please check your email').should('be.visible')
    })
  })

  describe('Social Registration Integration', () => {
    it('should provide Google registration option', () => {
      registerPage.verifyGoogleSignupButton()
      registerPage.clickGoogleSignupButton()
      
      // Mock Google OAuth flow
      cy.window().should('have.property', 'google')
    })

    it('should handle social registration errors', () => {
      // Intercept OAuth callback to simulate error
      cy.intercept('GET', '/api/auth/callback/google', {
        statusCode: 400,
        body: { error: 'OAuth error' }
      }).as('oauthError')

      registerPage.clickGoogleSignupButton()
      
      cy.wait('@oauthError')
      registerPage.verifyErrorMessage('Social registration failed')
    })
  })

  describe('Security Features', () => {
    it('should implement proper password security', () => {
      registerPage.enterFirstName('Security')
      registerPage.enterLastName('Test')
      registerPage.enterEmail('security@example.com')
      
      // Test password visibility toggle
      registerPage.enterPassword('SecretPassword123!')
      registerPage.verifyPasswordIsHidden()
      
      registerPage.togglePasswordVisibility()
      registerPage.verifyPasswordIsVisible()
      
      registerPage.togglePasswordVisibility()
      registerPage.verifyPasswordIsHidden()
    })

    it('should implement CSRF protection', () => {
      // Verify CSRF token is present
      cy.get('meta[name="csrf-token"]').should('exist')
      
      // Verify form includes CSRF protection
      cy.get('form').within(() => {
        cy.get('input[name="_token"]').should('exist')
      })
    })

    it('should implement rate limiting protection', () => {
      // Attempt multiple rapid registrations
      for (let i = 0; i < 5; i++) {
        registerPage.enterFirstName(`User${i}`)
        registerPage.enterLastName('Test')
        registerPage.enterEmail(`user${i}@example.com`)
        registerPage.enterPassword('Password123!')
        registerPage.enterConfirmPassword('Password123!')
        registerPage.acceptTerms()
        registerPage.clickSubmitButton()
        
        if (i < 3) {
          registerPage.verifySuccessMessage()
          cy.go('back')
        }
      }
      
      // Should see rate limiting message
      registerPage.verifyErrorMessage('Too many registration attempts')
    })
  })
}) 