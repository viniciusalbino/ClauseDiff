import { LoginPage } from '../../support/page-objects';

describe('Login/Logout Error Scenarios E2E', () => {
  const loginPage = new LoginPage();
  
  beforeEach(() => {
    // Clear any existing sessions and visit login page
    cy.clearCookies();
    cy.clearLocalStorage();
    cy.clearSessionStorage();
    cy.visit('/login');
    cy.checkA11y();
  });

  describe('Login Error Scenarios', () => {
    context('Invalid Credentials', () => {
      it('should display error for invalid email format', () => {
        loginPage.enterEmail('invalid-email');
        loginPage.enterPassword('Password123');
        loginPage.clickLoginButton();

        // Should show email validation error
        cy.get('[data-testid="email-error"]')
          .should('be.visible')
          .and('contain', 'Please enter a valid email address');
        
        // Should not redirect
        cy.url().should('include', '/login');
        cy.checkA11y();
      });

      it('should display error for empty email', () => {
        loginPage.enterPassword('Password123');
        loginPage.clickLoginButton();

        cy.get('[data-testid="email-error"]')
          .should('be.visible')
          .and('contain', 'Email is required');
        
        cy.url().should('include', '/login');
      });

      it('should display error for empty password', () => {
        loginPage.enterEmail('test@example.com');
        loginPage.clickLoginButton();

        cy.get('[data-testid="password-error"]')
          .should('be.visible')
          .and('contain', 'Password is required');
        
        cy.url().should('include', '/login');
      });

      it('should display error for short password', () => {
        loginPage.enterEmail('test@example.com');
        loginPage.enterPassword('123');
        loginPage.clickLoginButton();

        cy.get('[data-testid="password-error"]')
          .should('be.visible')
          .and('contain', 'Password must be at least 8 characters');
      });

      it('should handle non-existent user credentials', () => {
        loginPage.enterEmail('nonexistent@example.com');
        loginPage.enterPassword('WrongPassword123');
        loginPage.clickLoginButton();

        // Should show general authentication error
        cy.get('[data-testid="login-error"]')
          .should('be.visible')
          .and('contain', 'Invalid email or password');
        
        // Form should remain accessible
        cy.get('[data-testid="email-input"]').should('not.be.disabled');
        cy.get('[data-testid="password-input"]').should('not.be.disabled');
        cy.get('[data-testid="login-button"]').should('not.be.disabled');
        
        cy.url().should('include', '/login');
      });

      it('should handle wrong password for existing user', () => {
        // First create a test user
        cy.createTestUser({
          email: 'existing@example.com',
          password: 'CorrectPassword123',
          firstName: 'Test',
          lastName: 'User'
        });

        loginPage.enterEmail('existing@example.com');
        loginPage.enterPassword('WrongPassword123');
        loginPage.clickLoginButton();

        cy.get('[data-testid="login-error"]')
          .should('be.visible')
          .and('contain', 'Invalid email or password');
        
        cy.url().should('include', '/login');
        
        // Clean up
        cy.deleteTestUser('existing@example.com');
      });
    });

    context('Account Status Issues', () => {
      it('should handle unverified email account', () => {
        // Create unverified user
        cy.createTestUser({
          email: 'unverified@example.com',
          password: 'Password123',
          firstName: 'Unverified',
          lastName: 'User',
          emailVerified: false
        });

        loginPage.enterEmail('unverified@example.com');
        loginPage.enterPassword('Password123');
        loginPage.clickLoginButton();

        cy.get('[data-testid="verification-error"]')
          .should('be.visible')
          .and('contain', 'Please verify your email address before logging in');
        
        // Should offer resend verification option
        cy.get('[data-testid="resend-verification-button"]')
          .should('be.visible')
          .and('contain', 'Resend verification email');
        
        cy.deleteTestUser('unverified@example.com');
      });

      it('should handle suspended account', () => {
        cy.createTestUser({
          email: 'suspended@example.com',
          password: 'Password123',
          firstName: 'Suspended',
          lastName: 'User',
          status: 'suspended'
        });

        loginPage.enterEmail('suspended@example.com');
        loginPage.enterPassword('Password123');
        loginPage.clickLoginButton();

        cy.get('[data-testid="account-suspended-error"]')
          .should('be.visible')
          .and('contain', 'Your account has been suspended');
        
        cy.deleteTestUser('suspended@example.com');
      });
    });

    context('Network and Server Errors', () => {
      it('should handle network connection errors', () => {
        // Intercept and fail the login request
        cy.intercept('POST', '/api/auth/callback/credentials', {
          forceNetworkError: true
        }).as('networkError');

        loginPage.enterEmail('test@example.com');
        loginPage.enterPassword('Password123');
        loginPage.clickLoginButton();

        cy.wait('@networkError');

        cy.get('[data-testid="network-error"]')
          .should('be.visible')
          .and('contain', 'Network error. Please check your connection and try again.');
        
        // Should offer retry option
        cy.get('[data-testid="retry-button"]')
          .should('be.visible')
          .and('contain', 'Retry');
      });

      it('should handle server timeout', () => {
        cy.intercept('POST', '/api/auth/callback/credentials', {
          delay: 30000 // Simulate timeout
        }).as('timeoutRequest');

        loginPage.enterEmail('test@example.com');
        loginPage.enterPassword('Password123');
        loginPage.clickLoginButton();

        // Should show loading state initially
        cy.get('[data-testid="login-button"]')
          .should('contain', 'Signing in...')
          .and('be.disabled');

        // Cancel the request after a reasonable time
        cy.wait(5000);

        cy.get('[data-testid="timeout-error"]')
          .should('be.visible')
          .and('contain', 'Login is taking longer than expected');
      });

      it('should handle 500 server errors gracefully', () => {
        cy.intercept('POST', '/api/auth/callback/credentials', {
          statusCode: 500,
          body: { error: 'Internal Server Error' }
        }).as('serverError');

        loginPage.enterEmail('test@example.com');
        loginPage.enterPassword('Password123');
        loginPage.clickLoginButton();

        cy.wait('@serverError');

        cy.get('[data-testid="server-error"]')
          .should('be.visible')
          .and('contain', 'Something went wrong. Please try again later.');
      });
    });

    context('Rate Limiting and Security', () => {
      it('should handle too many failed login attempts', () => {
        const email = 'ratelimited@example.com';
        
        // Simulate multiple failed attempts
        for (let i = 0; i < 5; i++) {
          loginPage.clearForm();
          loginPage.enterEmail(email);
          loginPage.enterPassword('WrongPassword');
          loginPage.clickLoginButton();
          
          if (i < 4) {
            cy.get('[data-testid="login-error"]').should('be.visible');
          }
        }

        // 6th attempt should trigger rate limiting
        loginPage.clearForm();
        loginPage.enterEmail(email);
        loginPage.enterPassword('WrongPassword');
        loginPage.clickLoginButton();

        cy.get('[data-testid="rate-limit-error"]')
          .should('be.visible')
          .and('contain', 'Too many failed attempts. Please try again in');
        
        // Login button should be disabled
        cy.get('[data-testid="login-button"]').should('be.disabled');
        
        // Should show countdown timer
        cy.get('[data-testid="rate-limit-countdown"]').should('be.visible');
      });

      it('should handle CSRF token mismatch', () => {
        cy.intercept('POST', '/api/auth/callback/credentials', {
          statusCode: 403,
          body: { error: 'CSRF token mismatch' }
        }).as('csrfError');

        loginPage.enterEmail('test@example.com');
        loginPage.enterPassword('Password123');
        loginPage.clickLoginButton();

        cy.wait('@csrfError');

        cy.get('[data-testid="csrf-error"]')
          .should('be.visible')
          .and('contain', 'Security error. Please refresh the page and try again.');
        
        // Should offer refresh option
        cy.get('[data-testid="refresh-button"]')
          .should('be.visible')
          .and('contain', 'Refresh page');
      });
    });
  });

  describe('Logout Error Scenarios', () => {
    beforeEach(() => {
      // Create and login a test user first
      cy.createTestUser({
        email: 'logout-test@example.com',
        password: 'Password123',
        firstName: 'Logout',
        lastName: 'Test'
      });
      
      cy.loginApi('logout-test@example.com', 'Password123');
      cy.visit('/dashboard');
    });

    afterEach(() => {
      cy.deleteTestUser('logout-test@example.com');
    });

    it('should handle logout network errors gracefully', () => {
      cy.intercept('POST', '/api/auth/signout', {
        forceNetworkError: true
      }).as('logoutNetworkError');

      // Attempt to logout
      cy.get('[data-testid="user-menu"]').click();
      cy.get('[data-testid="logout-button"]').click();

      cy.wait('@logoutNetworkError');

      // Should show error but still attempt local logout
      cy.get('[data-testid="logout-error"]')
        .should('be.visible')
        .and('contain', 'Unable to logout properly. You have been logged out locally.');
      
      // Should still redirect to login page
      cy.url().should('include', '/login');
      
      // Should clear local session data
      cy.window().then((win) => {
        expect(win.localStorage.getItem('next-auth.session-token')).to.be.null;
      });
    });

    it('should handle logout server errors', () => {
      cy.intercept('POST', '/api/auth/signout', {
        statusCode: 500,
        body: { error: 'Server error during logout' }
      }).as('logoutServerError');

      cy.get('[data-testid="user-menu"]').click();
      cy.get('[data-testid="logout-button"]').click();

      cy.wait('@logoutServerError');

      // Should show warning but complete logout
      cy.get('[data-testid="logout-warning"]')
        .should('be.visible')
        .and('contain', 'Logout completed but there was an issue with the server');
      
      cy.url().should('include', '/login');
    });

    it('should handle session timeout during logout', () => {
      cy.intercept('POST', '/api/auth/signout', {
        statusCode: 401,
        body: { error: 'Session expired' }
      }).as('sessionExpired');

      cy.get('[data-testid="user-menu"]').click();
      cy.get('[data-testid="logout-button"]').click();

      cy.wait('@sessionExpired');

      // Should handle gracefully since session was already invalid
      cy.url().should('include', '/login');
      
      cy.get('[data-testid="session-expired-message"]')
        .should('be.visible')
        .and('contain', 'Your session has expired');
    });
  });

  describe('Session Management Error Scenarios', () => {
    beforeEach(() => {
      cy.createTestUser({
        email: 'session-test@example.com',
        password: 'Password123',
        firstName: 'Session',
        lastName: 'Test'
      });
      
      cy.loginApi('session-test@example.com', 'Password123');
    });

    afterEach(() => {
      cy.deleteTestUser('session-test@example.com');
    });

    it('should handle session expiration during navigation', () => {
      cy.visit('/dashboard');
      
      // Mock session expiration
      cy.intercept('GET', '/api/auth/session', {
        statusCode: 401,
        body: { error: 'Session expired' }
      }).as('sessionExpired');

      // Try to navigate to a protected page
      cy.visit('/profile');
      
      cy.wait('@sessionExpired');

      // Should redirect to login with message
      cy.url().should('include', '/login');
      cy.get('[data-testid="session-expired-banner"]')
        .should('be.visible')
        .and('contain', 'Your session has expired. Please log in again.');
    });

    it('should handle concurrent session conflicts', () => {
      cy.visit('/dashboard');
      
      // Simulate another session being created
      cy.intercept('GET', '/api/auth/session', {
        statusCode: 409,
        body: { error: 'Session conflict detected' }
      }).as('sessionConflict');

      // Refresh the page to trigger session check
      cy.reload();
      
      cy.wait('@sessionConflict');

      cy.get('[data-testid="session-conflict-modal"]')
        .should('be.visible')
        .and('contain', 'Another session detected');
      
      // Should offer options to continue or logout
      cy.get('[data-testid="continue-session-button"]').should('be.visible');
      cy.get('[data-testid="logout-other-sessions-button"]').should('be.visible');
    });

    it('should handle token refresh failures', () => {
      cy.visit('/dashboard');
      
      // Mock token refresh failure
      cy.intercept('POST', '/api/auth/token', {
        statusCode: 400,
        body: { error: 'Invalid refresh token' }
      }).as('tokenRefreshFailed');

      // Wait for token refresh to be attempted (simulated by waiting)
      cy.wait(1000);
      
      // Trigger an action that requires authentication
      cy.get('[data-testid="user-menu"]').click();
      
      cy.wait('@tokenRefreshFailed');

      // Should redirect to login
      cy.url().should('include', '/login');
      cy.get('[data-testid="token-refresh-error"]')
        .should('be.visible')
        .and('contain', 'Authentication expired. Please log in again.');
    });
  });

  describe('Browser Compatibility and Edge Cases', () => {
    it('should handle disabled JavaScript gracefully', () => {
      // This test ensures the page still shows appropriate messaging
      cy.visit('/login');
      
      // Simulate disabled JavaScript by intercepting all JS
      cy.window().then((win) => {
        // Override JavaScript functions
        win.fetch = undefined as any;
        win.XMLHttpRequest = undefined as any;
      });

      cy.get('[data-testid="no-js-warning"]')
        .should('be.visible')
        .and('contain', 'JavaScript is required for this application');
    });

    it('should handle localStorage unavailability', () => {
      cy.visit('/login');
      
      // Mock localStorage being unavailable
      cy.window().then((win) => {
        Object.defineProperty(win, 'localStorage', {
          value: null,
          writable: false
        });
      });

      loginPage.enterEmail('test@example.com');
      loginPage.enterPassword('Password123');
      loginPage.clickLoginButton();

      // Should show warning about storage
      cy.get('[data-testid="storage-warning"]')
        .should('be.visible')
        .and('contain', 'Local storage is not available');
    });

    it('should handle cookies being disabled', () => {
      // Clear all cookies and prevent new ones
      cy.clearCookies();
      
      // Mock document.cookie to simulate disabled cookies
      cy.window().then((win) => {
        Object.defineProperty(win.document, 'cookie', {
          get: () => '',
          set: () => {},
          configurable: false
        });
      });

      cy.visit('/login');

      loginPage.enterEmail('test@example.com');
      loginPage.enterPassword('Password123');
      loginPage.clickLoginButton();

      cy.get('[data-testid="cookies-disabled-error"]')
        .should('be.visible')
        .and('contain', 'Cookies must be enabled to log in');
    });
  });

  describe('Accessibility Error States', () => {
    it('should maintain accessibility during error states', () => {
      loginPage.enterEmail('invalid-email');
      loginPage.enterPassword('short');
      loginPage.clickLoginButton();

      // Check that errors are properly announced
      cy.get('[data-testid="email-error"]')
        .should('have.attr', 'role', 'alert')
        .and('have.attr', 'aria-live', 'polite');
      
      cy.get('[data-testid="password-error"]')
        .should('have.attr', 'role', 'alert')
        .and('have.attr', 'aria-live', 'polite');

      // Form should still be keyboard navigable
      cy.get('[data-testid="email-input"]').focus();
      cy.get('[data-testid="email-input"]').should('be.focused');
      
      cy.get('[data-testid="email-input"]').tab();
      cy.get('[data-testid="password-input"]').should('be.focused');

      // Run accessibility check on error state
      cy.checkA11y();
    });

    it('should provide proper error descriptions for screen readers', () => {
      loginPage.enterEmail('test@invalid');
      loginPage.clickLoginButton();

      cy.get('[data-testid="email-input"]')
        .should('have.attr', 'aria-describedby')
        .and('contain', 'email-error');
      
      cy.get('[data-testid="email-error"]')
        .should('have.attr', 'id', 'email-error');
    });
  });

  describe('Error Recovery and User Guidance', () => {
    it('should provide helpful error recovery suggestions', () => {
      loginPage.enterEmail('test@example.com');
      loginPage.enterPassword('wrongpassword');
      loginPage.clickLoginButton();

      cy.get('[data-testid="login-error"]').should('be.visible');
      
      // Should show recovery options
      cy.get('[data-testid="forgot-password-link"]')
        .should('be.visible')
        .and('contain', 'Forgot your password?');
      
      cy.get('[data-testid="create-account-link"]')
        .should('be.visible')
        .and('contain', "Don't have an account? Sign up");
    });

    it('should clear errors when user corrects input', () => {
      // First create an error
      loginPage.enterEmail('invalid-email');
      loginPage.clickLoginButton();
      
      cy.get('[data-testid="email-error"]').should('be.visible');
      
      // Then correct the input
      loginPage.clearEmail();
      loginPage.enterEmail('valid@example.com');
      
      // Error should be cleared
      cy.get('[data-testid="email-error"]').should('not.exist');
    });

    it('should maintain form state during error recovery', () => {
      const email = 'user@example.com';
      const password = 'Password123';
      
      loginPage.enterEmail(email);
      loginPage.enterPassword(password);
      
      // Cause a network error
      cy.intercept('POST', '/api/auth/callback/credentials', {
        forceNetworkError: true
      }).as('networkError');
      
      loginPage.clickLoginButton();
      cy.wait('@networkError');
      
      // Form values should be preserved
      cy.get('[data-testid="email-input"]').should('have.value', email);
      cy.get('[data-testid="password-input"]').should('have.value', password);
      
      // User can retry without re-entering data
      cy.intercept('POST', '/api/auth/callback/credentials', {
        statusCode: 200,
        body: { url: '/dashboard' }
      }).as('successfulLogin');
      
      cy.get('[data-testid="retry-button"]').click();
      cy.wait('@successfulLogin');
      
      cy.url().should('include', '/dashboard');
    });
  });
});