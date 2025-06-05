import { BasePage } from './BasePage'

/**
 * Register Page Object
 * Handles all interactions with the registration page
 */
export class RegisterPage extends BasePage {
  // Selectors
  private readonly selectors = {
    firstNameInput: '[data-testid="first-name-input"]',
    lastNameInput: '[data-testid="last-name-input"]',
    emailInput: '[data-testid="email-input"]',
    passwordInput: '[data-testid="password-input"]',
    confirmPasswordInput: '[data-testid="confirm-password-input"]',
    termsCheckbox: '[data-testid="terms-checkbox"]',
    registerButton: '[data-testid="register-button"]',
    loginLink: '[data-testid="login-link"]',
    errorMessage: '[data-testid="error-message"]',
    successMessage: '[data-testid="success-message"]',
    firstNameError: '[data-testid="first-name-error"]',
    lastNameError: '[data-testid="last-name-error"]',
    emailError: '[data-testid="email-error"]',
    passwordError: '[data-testid="password-error"]',
    confirmPasswordError: '[data-testid="confirm-password-error"]',
    termsError: '[data-testid="terms-error"]',
    loadingSpinner: '[data-testid="loading-spinner"]',
    pageTitle: 'h1',
    passwordStrengthIndicator: '[data-testid="password-strength"]'
  }

  constructor() {
    super('/register')
  }

  /**
   * Enter first name
   */
  enterFirstName(firstName: string): void {
    this.typeText(this.selectors.firstNameInput, firstName)
  }

  /**
   * Enter last name
   */
  enterLastName(lastName: string): void {
    this.typeText(this.selectors.lastNameInput, lastName)
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
   * Enter confirm password
   */
  enterConfirmPassword(password: string): void {
    this.typeText(this.selectors.confirmPasswordInput, password)
  }

  /**
   * Accept terms and conditions
   */
  acceptTerms(): void {
    this.checkCheckbox(this.selectors.termsCheckbox)
  }

  /**
   * Click register button
   */
  clickRegisterButton(): void {
    this.clickElement(this.selectors.registerButton)
  }

  /**
   * Click login link
   */
  clickLoginLink(): void {
    this.clickElement(this.selectors.loginLink)
  }

  /**
   * Complete registration process
   */
  register(
    firstName: string,
    lastName: string,
    email: string,
    password: string,
    acceptTerms: boolean = true
  ): void {
    this.enterFirstName(firstName)
    this.enterLastName(lastName)
    this.enterEmail(email)
    this.enterPassword(password)
    this.enterConfirmPassword(password)
    
    if (acceptTerms) {
      this.acceptTerms()
    }
    
    this.clickRegisterButton()
  }

  /**
   * Verify registration page is displayed
   */
  verifyRegistrationPageDisplayed(): void {
    this.waitForElement(this.selectors.firstNameInput)
    this.waitForElement(this.selectors.lastNameInput)
    this.waitForElement(this.selectors.emailInput)
    this.waitForElement(this.selectors.passwordInput)
    this.waitForElement(this.selectors.confirmPasswordInput)
    this.waitForElement(this.selectors.termsCheckbox)
    this.waitForElement(this.selectors.registerButton)
    this.elementContainsText(this.selectors.pageTitle, 'Register')
  }

  /**
   * Verify first name validation error
   */
  verifyFirstNameError(message: string): void {
    this.elementContainsText(this.selectors.firstNameError, message)
  }

  /**
   * Verify last name validation error
   */
  verifyLastNameError(message: string): void {
    this.elementContainsText(this.selectors.lastNameError, message)
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
   * Verify confirm password validation error
   */
  verifyConfirmPasswordError(message: string): void {
    this.elementContainsText(this.selectors.confirmPasswordError, message)
  }

  /**
   * Verify terms validation error
   */
  verifyTermsError(message: string): void {
    this.elementContainsText(this.selectors.termsError, message)
  }

  /**
   * Verify general error message
   */
  verifyErrorMessage(message: string): void {
    this.elementContainsText(this.selectors.errorMessage, message)
  }

  /**
   * Verify success message with text
   */
  verifySuccessMessage(message: string): void {
    this.elementContainsText(this.selectors.successMessage, message)
  }

  /**
   * Wait for registration to complete
   */
  waitForRegistrationComplete(): void {
    // Wait for redirect away from register page or success message
    cy.get('body').then($body => {
      if ($body.find(this.selectors.successMessage).length > 0) {
        this.isElementVisible(this.selectors.successMessage)
      } else {
        this.checkUrlNotContains('/register')
      }
    })
  }

  /**
   * Verify loading state
   */
  verifyLoadingState(): void {
    this.isElementVisible(this.selectors.loadingSpinner)
  }

  /**
   * Clear registration form
   */
  clearForm(): void {
    cy.get(this.selectors.firstNameInput).clear()
    cy.get(this.selectors.lastNameInput).clear()
    cy.get(this.selectors.emailInput).clear()
    cy.get(this.selectors.passwordInput).clear()
    cy.get(this.selectors.confirmPasswordInput).clear()
    cy.get(this.selectors.termsCheckbox).uncheck()
  }

  /**
   * Check if register button is disabled
   */
  isRegisterButtonDisabled(): Cypress.Chainable<boolean> {
    return cy.get(this.selectors.registerButton).should('be.disabled').then(() => true)
  }

  /**
   * Check if register button is enabled
   */
  isRegisterButtonEnabled(): Cypress.Chainable<boolean> {
    return cy.get(this.selectors.registerButton).should('not.be.disabled').then(() => true)
  }

  /**
   * Verify all form elements are present
   */
  verifyFormElements(): void {
    this.isElementVisible(this.selectors.firstNameInput)
    this.isElementVisible(this.selectors.lastNameInput)
    this.isElementVisible(this.selectors.emailInput)
    this.isElementVisible(this.selectors.passwordInput)
    this.isElementVisible(this.selectors.confirmPasswordInput)
    this.isElementVisible(this.selectors.termsCheckbox)
    this.isElementVisible(this.selectors.registerButton)
    this.isElementVisible(this.selectors.loginLink)
  }

  /**
   * Submit empty form to trigger validation
   */
  submitEmptyForm(): void {
    this.clickRegisterButton()
  }

  /**
   * Verify password strength indicator
   */
  verifyPasswordStrength(strength: 'weak' | 'medium' | 'strong'): void {
    this.elementContainsText(this.selectors.passwordStrengthIndicator, strength)
  }

  /**
   * Verify page accessibility
   */
  verifyAccessibility(): void {
    cy.checkA11y()
  }

  /**
   * Register with mismatched passwords
   */
  registerWithMismatchedPasswords(
    firstName: string,
    lastName: string,
    email: string,
    password: string,
    confirmPassword: string
  ): void {
    this.enterFirstName(firstName)
    this.enterLastName(lastName)
    this.enterEmail(email)
    this.enterPassword(password)
    this.enterConfirmPassword(confirmPassword)
    this.acceptTerms()
    this.clickRegisterButton()
  }

  // Additional methods for E2E tests

  /**
   * Click submit button (alias for clickRegisterButton)
   */
  clickSubmitButton(): void {
    this.clickRegisterButton()
  }

  /**
   * Verify success message appears (overload without parameters)
   */
  verifySuccessMessageAppears(): void {
    this.isElementVisible(this.selectors.successMessage)
  }

  /**
   * Verify email verification message
   */
  verifyEmailVerificationMessage(email: string): void {
    cy.contains(`We've sent a verification link to ${email}`).should('be.visible')
  }

  /**
   * Verify validation error for any field
   */
  verifyValidationError(field: string, message: string): void {
    const errorSelector = this.selectors[`${field}Error` as keyof typeof this.selectors] as string
    if (errorSelector) {
      this.elementContainsText(errorSelector, message)
    } else {
      cy.get(`[data-testid="${field}-error"]`).should('contain', message)
    }
  }

  /**
   * Verify no validation error for a field
   */
  verifyNoValidationError(field: string): void {
    const errorSelector = this.selectors[`${field}Error` as keyof typeof this.selectors] as string
    if (errorSelector) {
      cy.get(errorSelector).should('not.exist')
    } else {
      cy.get(`[data-testid="${field}-error"]`).should('not.exist')
    }
  }

  /**
   * Clear email field
   */
  clearEmailField(): void {
    cy.get(this.selectors.emailInput).clear()
  }

  /**
   * Clear password field
   */
  clearPasswordField(): void {
    cy.get(this.selectors.passwordInput).clear()
  }

  /**
   * Clear confirm password field
   */
  clearConfirmPasswordField(): void {
    cy.get(this.selectors.confirmPasswordInput).clear()
  }

  /**
   * Verify form is visible
   */
  verifyFormIsVisible(): void {
    this.isElementVisible('[data-testid="registration-form"]')
  }

  /**
   * Click resend email button
   */
  clickResendEmailButton(): void {
    this.clickElement('[data-testid="resend-email-button"]')
  }

  /**
   * Verify resend email message
   */
  verifyResendEmailMessage(): void {
    cy.contains('Verification email sent').should('be.visible')
  }

  /**
   * Verify Google signup button
   */
  verifyGoogleSignupButton(): void {
    this.isElementVisible('[data-testid="google-signup-button"]')
  }

  /**
   * Click Google signup button
   */
  clickGoogleSignupButton(): void {
    this.clickElement('[data-testid="google-signup-button"]')
  }

  /**
   * Verify password is hidden
   */
  verifyPasswordIsHidden(): void {
    cy.get(this.selectors.passwordInput).should('have.attr', 'type', 'password')
  }

  /**
   * Verify password is visible
   */
  verifyPasswordIsVisible(): void {
    cy.get(this.selectors.passwordInput).should('have.attr', 'type', 'text')
  }

  /**
   * Toggle password visibility
   */
  togglePasswordVisibility(): void {
    this.clickElement('[data-testid="password-toggle"]')
  }

  /**
   * Verify accessibility labels
   */
  verifyAccessibilityLabels(): void {
    cy.get(this.selectors.firstNameInput).should('have.attr', 'aria-label')
    cy.get(this.selectors.lastNameInput).should('have.attr', 'aria-label')
    cy.get(this.selectors.emailInput).should('have.attr', 'aria-label')
    cy.get(this.selectors.passwordInput).should('have.attr', 'aria-label')
    cy.get(this.selectors.confirmPasswordInput).should('have.attr', 'aria-label')
  }

  /**
   * Verify ARIA descriptions
   */
  verifyAriaDescriptions(): void {
    cy.get(this.selectors.passwordInput).should('have.attr', 'aria-describedby')
    cy.get(this.selectors.emailInput).should('have.attr', 'aria-describedby')
  }
} 