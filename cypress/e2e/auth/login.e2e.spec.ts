import { loginPage } from '../../support/page-objects'

describe('Login Flow', () => {
  beforeEach(() => {
    cy.cleanDatabase()
  })

  it('should display login page correctly', () => {
    loginPage.visit()
    loginPage.verifyLoginPageDisplayed()
  })

  it('should show validation errors for empty fields', () => {
    loginPage.visit()
    loginPage.submitEmptyForm()
    loginPage.verifyEmailError('Email is required')
    loginPage.verifyPasswordError('Password is required')
  })

  it('should show error for invalid credentials', () => {
    cy.fixture('test-users').then((users) => {
      loginPage.visit()
      loginPage.login(users.invalidUser.email, users.invalidUser.password)
      loginPage.verifyErrorMessage('Invalid credentials')
    })
  })

  it('should successfully login with valid credentials', () => {
    cy.fixture('test-users').then((users) => {
      // First create the test user
      cy.createTestUser(users.validUser)
      
      cy.visit('/login')
      cy.get('[data-testid="email-input"]').type(users.validUser.email)
      cy.get('[data-testid="password-input"]').type(users.validUser.password)
      cy.get('[data-testid="login-button"]').click()
      
      // Should redirect to dashboard after successful login
      cy.url().should('not.include', '/login')
      cy.get('[data-testid="user-menu"]').should('be.visible')
    })
  })

  it('should redirect to intended page after login', () => {
    cy.fixture('test-users').then((users) => {
      cy.createTestUser(users.validUser)
      
      // Try to access protected page
      cy.visit('/profile')
      cy.url().should('include', '/login')
      
      // Login
      cy.get('[data-testid="email-input"]').type(users.validUser.email)
      cy.get('[data-testid="password-input"]').type(users.validUser.password)
      cy.get('[data-testid="login-button"]').click()
      
      // Should redirect to original intended page
      cy.url().should('include', '/profile')
    })
  })

  it('should handle forgot password link', () => {
    cy.visit('/login')
    cy.get('[data-testid="forgot-password-link"]').click()
    cy.url().should('include', '/forgot-password')
    cy.get('h1').should('contain.text', 'Reset Password')
  })

  it('should handle register link', () => {
    cy.visit('/login')
    cy.get('[data-testid="register-link"]').click()
    cy.url().should('include', '/register')
    cy.get('h1').should('contain.text', 'Register')
  })

  after(() => {
    cy.cleanDatabase()
  })
}) 