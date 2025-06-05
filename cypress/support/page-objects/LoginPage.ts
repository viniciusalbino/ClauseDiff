import { BasePage } from './BasePage'

/**
 * Login Page Object
 * Handles all interactions with the login page
 */
export class LoginPage extends BasePage {
  // Selectors
  private readonly selectors = {
    emailInput: '[data-testid="email-input"]',
    passwordInput: '[data-testid="password-input"]',
    loginButton: '[data-testid="login-button"]',
    forgotPasswordLink: '[data-testid="forgot-password-link"]',
    registerLink: '[data-testid="register-link"]',
    errorMessage: '[data-testid="error-message"]',
    emailError: '[data-testid="email-error"]',
    passwordError: '[data-testid="password-error"]',
    loadingSpinner: '[data-testid="loading-spinner"]',
    pageTitle: 'h1',
    rememberMeCheckbox: '[data-testid="remember-me-checkbox"]'
  }

  constructor() {
    super('/login')
  }

  /**
   * Enter email address
   */
  enterEmail(email: string): void {
    this.typeText(this.selectors.emailInput, email)
  }

  /**
   * Enter password
   */
  enterPassword(password: string): void {
    this.typeText(this.selectors.passwordInput, password)
  }

  /**
   * Click login button
   */
  clickLoginButton(): void {
    this.clickElement(this.selectors.loginButton)
  }

  /**
   * Click forgot password link
   */
  clickForgotPasswordLink(): void {
    this.clickElement(this.selectors.forgotPasswordLink)
  }

  /**
   * Click register link
   */
  clickRegisterLink(): void {
    this.clickElement(this.selectors.registerLink)
  }

  /**
   * Check remember me checkbox
   */
  checkRememberMe(): void {
    this.checkCheckbox(this.selectors.rememberMeCheckbox)
  }

  /**
   * Complete login process
   */
  login(email: string, password: string, rememberMe: boolean = false): void {
    this.enterEmail(email)
    this.enterPassword(password)
    
    if (rememberMe) {
      this.checkRememberMe()
    }
    
    this.clickLoginButton()
  }

  /**
   * Verify login page is displayed
   */
  verifyLoginPageDisplayed(): void {
    this.waitForElement(this.selectors.emailInput)
    this.waitForElement(this.selectors.passwordInput)
    this.waitForElement(this.selectors.loginButton)
    this.elementContainsText(this.selectors.pageTitle, 'Login')
  }

  /**
   * Verify email validation error
   */
  verifyEmailError(message: string): void {
    this.elementContainsText(this.selectors.emailError, message)
  }

  /**
   * Verify password validation error
   */
  verifyPasswordError(message: string): void {
    this.elementContainsText(this.selectors.passwordError, message)
  }

  /**
   * Verify general error message
   */
  verifyErrorMessage(message: string): void {
    this.elementContainsText(this.selectors.errorMessage, message)
  }

  /**
   * Wait for login to complete
   */
  waitForLoginComplete(): void {
    // Wait for redirect away from login page
    this.checkUrlNotContains('/login')
  }

  /**
   * Verify loading state
   */
  verifyLoadingState(): void {
    this.isElementVisible(this.selectors.loadingSpinner)
  }

  /**
   * Clear login form
   */
  clearForm(): void {
    cy.get(this.selectors.emailInput).clear()
    cy.get(this.selectors.passwordInput).clear()
  }

  /**
   * Check if login button is disabled
   */
  isLoginButtonDisabled(): Cypress.Chainable<boolean> {
    return cy.get(this.selectors.loginButton).should('be.disabled').then(() => true)
  }

  /**
   * Check if login button is enabled
   */
  isLoginButtonEnabled(): Cypress.Chainable<boolean> {
    return cy.get(this.selectors.loginButton).should('not.be.disabled').then(() => true)
  }

  /**
   * Verify all form elements are present
   */
  verifyFormElements(): void {
    this.isElementVisible(this.selectors.emailInput)
    this.isElementVisible(this.selectors.passwordInput)
    this.isElementVisible(this.selectors.loginButton)
    this.isElementVisible(this.selectors.forgotPasswordLink)
    this.isElementVisible(this.selectors.registerLink)
  }

  /**
   * Submit empty form to trigger validation
   */
  submitEmptyForm(): void {
    this.clickLoginButton()
  }

  /**
   * Verify page accessibility
   */
  verifyAccessibility(): void {
    cy.checkA11y()
  }
} 