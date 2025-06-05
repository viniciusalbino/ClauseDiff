// ***********************************************************
// This example support/e2e.ts is processed and
// loaded automatically before your test files.
//
// This is a great place to put global configuration and
// behavior that modifies Cypress.
//
// You can change the location of this file or turn off
// automatically serving support files with the
// 'supportFile' configuration option.
//
// You can read more here:
// https://on.cypress.io/configuration
// ***********************************************************

// Import commands.js using ES2015 syntax:
import './commands'

// Alternatively you can use CommonJS syntax:
// require('./commands')

// Add global declarations for TypeScript support
declare global {
  namespace Cypress {
    interface Chainable {
      /**
       * Custom command to log in a user
       * @example cy.login('user@example.com', 'password')
       */
      login(email: string, password: string): Chainable<Element>
      
      /**
       * Custom command to log in a user via API
       * @example cy.loginApi('user@example.com', 'password')
       */
      loginApi(email: string, password: string): Chainable<void>
      
      /**
       * Custom command to log out the current user
       * @example cy.logout()
       */
      logout(): Chainable<Element>
      
      /**
       * Custom command to register a new user
       * @example cy.register('user@example.com', 'password', 'First', 'Last')
       */
      register(email: string, password: string, firstName: string, lastName: string): Chainable<Element>
      
      /**
       * Custom command to seed the database with test data
       * @example cy.seedDatabase()
       */
      seedDatabase(): Chainable<null>
      
      /**
       * Custom command to clean the database
       * @example cy.cleanDatabase()
       */
      cleanDatabase(): Chainable<null>
      
      /**
       * Custom command to upload a file
       * @example cy.uploadFile('input[type="file"]', 'test-file.pdf')
       */
      uploadFile(selector: string, fileName: string): Chainable<Element>
      
      /**
       * Custom command to wait for an element to be visible and interactable
       * @example cy.waitForElement('[data-testid="submit-btn"]')
       */
      waitForElement(selector: string): Chainable<Element>
      
      /**
       * Custom command to check if user is authenticated
       * @example cy.checkAuthentication()
       */
      checkAuthentication(): Chainable<boolean>
      
      /**
       * Custom command to create a test user via API
       * @example cy.createTestUser({email: 'test@example.com', password: 'password123'})
       */
      createTestUser(userData: any): Chainable<any>
      
      /**
       * Custom command to delete a test user via API
       * @example cy.deleteTestUser('user-id')
       */
      deleteTestUser(userId: string): Chainable<void>
      
      /**
       * Custom command to reset password via API
       * @example cy.resetPassword('user@example.com', 'newPassword123')
       */
      resetPassword(email: string, newPassword: string): Chainable<void>
      
      /**
       * Custom command to simulate file comparison
       * @example cy.compareFiles('file1.pdf', 'file2.pdf')
       */
      compareFiles(file1: string, file2: string): Chainable<void>
      
      /**
       * Custom command to check for accessibility violations
       * @example cy.checkA11y()
       */
      checkA11y(): Chainable<void>

      /**
       * Custom command to check if user exists in database
       * @example cy.checkDatabaseUser('user@example.com')
       */
      checkDatabaseUser(email: string): Chainable<any>
    }
  }
}

// Configure Cypress for better testing experience
beforeEach(() => {
  // Set up interceptors for API calls
  cy.intercept('GET', '/api/auth/session', { statusCode: 200, body: null }).as('getSession')
  cy.intercept('POST', '/api/auth/signin', { statusCode: 200 }).as('signIn')
  cy.intercept('POST', '/api/auth/signout', { statusCode: 200 }).as('signOut')
  
  // Clear cookies and local storage before each test
  cy.clearCookies()
  cy.clearLocalStorage()
})

// Handle uncaught exceptions to prevent test failures for expected errors
Cypress.on('uncaught:exception', (err, runnable) => {
  // Returning false here prevents Cypress from failing the test
  // This can be customized based on specific error types you want to ignore
  if (err.message.includes('ResizeObserver loop limit exceeded')) {
    return false
  }
  
  // Return false for other expected errors in development
  if (err.message.includes('Network Error') || err.message.includes('Script error')) {
    return false
  }
  
  return true
}) 