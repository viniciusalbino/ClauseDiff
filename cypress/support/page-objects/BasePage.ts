/**
 * Base Page Object class with common functionality
 * All page objects should extend this class
 */
export abstract class BasePage {
  protected url: string

  constructor(url: string) {
    this.url = url
  }

  /**
   * Visit the page
   */
  visit(): void {
    cy.visit(this.url)
  }

  /**
   * Get the current URL
   */
  getCurrentUrl(): Cypress.Chainable<string> {
    return cy.url()
  }

  /**
   * Wait for page to load
   */
  waitForPageLoad(): void {
    cy.get('body').should('be.visible')
  }

  /**
   * Check if element exists
   */
  elementExists(selector: string): Cypress.Chainable<boolean> {
    return cy.get('body').then($body => {
      return $body.find(selector).length > 0
    })
  }

  /**
   * Wait for element to be visible
   */
  waitForElement(selector: string, timeout: number = 10000): Cypress.Chainable<JQuery<HTMLElement>> {
    return cy.get(selector, { timeout }).should('be.visible')
  }

  /**
   * Click element with retry logic
   */
  clickElement(selector: string): void {
    cy.get(selector).should('be.visible').and('not.be.disabled').click()
  }

  /**
   * Type text into input field
   */
  typeText(selector: string, text: string): void {
    cy.get(selector).should('be.visible').clear().type(text)
  }

  /**
   * Get element text
   */
  getElementText(selector: string): Cypress.Chainable<string> {
    return cy.get(selector).invoke('text')
  }

  /**
   * Check if element is visible
   */
  isElementVisible(selector: string): Cypress.Chainable<boolean> {
    return cy.get(selector).should('be.visible').then(() => true)
  }

  /**
   * Check if element contains text
   */
  elementContainsText(selector: string, text: string): void {
    cy.get(selector).should('contain.text', text)
  }

  /**
   * Upload file to input
   */
  uploadFile(selector: string, fileName: string): void {
    cy.get(selector).attachFile(fileName)
  }

  /**
   * Check page title
   */
  checkPageTitle(title: string): void {
    cy.title().should('contain', title)
  }

  /**
   * Check if URL contains path
   */
  checkUrlContains(path: string): void {
    cy.url().should('include', path)
  }

  /**
   * Check if URL does not contain path
   */
  checkUrlNotContains(path: string): void {
    cy.url().should('not.include', path)
  }

  /**
   * Scroll to element
   */
  scrollToElement(selector: string): void {
    cy.get(selector).scrollIntoView()
  }

  /**
   * Check if checkbox is checked
   */
  isCheckboxChecked(selector: string): Cypress.Chainable<boolean> {
    return cy.get(selector).should('be.checked').then(() => true)
  }

  /**
   * Check checkbox
   */
  checkCheckbox(selector: string): void {
    cy.get(selector).check()
  }

  /**
   * Uncheck checkbox
   */
  uncheckCheckbox(selector: string): void {
    cy.get(selector).uncheck()
  }

  /**
   * Select option from dropdown
   */
  selectOption(selector: string, value: string): void {
    cy.get(selector).select(value)
  }

  /**
   * Wait for API request to complete
   */
  waitForApiRequest(alias: string): void {
    cy.wait(alias)
  }

  /**
   * Check for error message
   */
  checkErrorMessage(message: string): void {
    cy.get('[data-testid="error-message"]').should('contain.text', message)
  }

  /**
   * Check for success message
   */
  checkSuccessMessage(message: string): void {
    cy.get('[data-testid="success-message"]').should('contain.text', message)
  }
} 