import { BasePage } from './BasePage'

/**
 * Document Comparison Page Object
 * Handles all interactions with the document comparison functionality
 */
export class DocumentComparisonPage extends BasePage {
  // Selectors
  private readonly selectors = {
    fileUpload1: '[data-testid="file-upload-1"]',
    fileUpload2: '[data-testid="file-upload-2"]',
    compareButton: '[data-testid="compare-button"]',
    comparisonResults: '[data-testid="comparison-results"]',
    differenceSummary: '[data-testid="difference-summary"]',
    exportButton: '[data-testid="export-button"]',
    exportDropdown: '[data-testid="export-dropdown"]',
    exportPdfButton: '[data-testid="export-pdf"]',
    exportCsvButton: '[data-testid="export-csv"]',
    clearButton: '[data-testid="clear-button"]',
    loadingSpinner: '[data-testid="loading-spinner"]',
    errorMessage: '[data-testid="error-message"]',
    successMessage: '[data-testid="success-message"]',
    file1Preview: '[data-testid="file-1-preview"]',
    file2Preview: '[data-testid="file-2-preview"]',
    file1Name: '[data-testid="file-1-name"]',
    file2Name: '[data-testid="file-2-name"]',
    file1Size: '[data-testid="file-1-size"]',
    file2Size: '[data-testid="file-2-size"]',
    progressBar: '[data-testid="progress-bar"]',
    comparisonToolbar: '[data-testid="comparison-toolbar"]',
    zoomInButton: '[data-testid="zoom-in"]',
    zoomOutButton: '[data-testid="zoom-out"]',
    resetZoomButton: '[data-testid="reset-zoom"]',
    nextDifferenceButton: '[data-testid="next-difference"]',
    previousDifferenceButton: '[data-testid="previous-difference"]',
    differenceCounter: '[data-testid="difference-counter"]',
    pageTitle: 'h1'
  }

  constructor() {
    super('/compare')
  }

  /**
   * Upload first file
   */
  uploadFirstFile(fileName: string): void {
    this.uploadFile(this.selectors.fileUpload1, fileName)
  }

  /**
   * Upload second file
   */
  uploadSecondFile(fileName: string): void {
    this.uploadFile(this.selectors.fileUpload2, fileName)
  }

  /**
   * Upload both files and compare
   */
  compareFiles(file1: string, file2: string): void {
    this.uploadFirstFile(file1)
    this.uploadSecondFile(file2)
    this.clickCompareButton()
  }

  /**
   * Click compare button
   */
  clickCompareButton(): void {
    this.clickElement(this.selectors.compareButton)
  }

  /**
   * Click export button
   */
  clickExportButton(): void {
    this.clickElement(this.selectors.exportButton)
  }

  /**
   * Export as PDF
   */
  exportAsPdf(): void {
    this.clickExportButton()
    this.clickElement(this.selectors.exportPdfButton)
  }

  /**
   * Export as CSV
   */
  exportAsCsv(): void {
    this.clickExportButton()
    this.clickElement(this.selectors.exportCsvButton)
  }

  /**
   * Clear comparison
   */
  clearComparison(): void {
    this.clickElement(this.selectors.clearButton)
  }

  /**
   * Zoom in on comparison view
   */
  zoomIn(): void {
    this.clickElement(this.selectors.zoomInButton)
  }

  /**
   * Zoom out on comparison view
   */
  zoomOut(): void {
    this.clickElement(this.selectors.zoomOutButton)
  }

  /**
   * Reset zoom to default
   */
  resetZoom(): void {
    this.clickElement(this.selectors.resetZoomButton)
  }

  /**
   * Navigate to next difference
   */
  goToNextDifference(): void {
    this.clickElement(this.selectors.nextDifferenceButton)
  }

  /**
   * Navigate to previous difference
   */
  goToPreviousDifference(): void {
    this.clickElement(this.selectors.previousDifferenceButton)
  }

  /**
   * Verify comparison page is displayed
   */
  verifyComparisonPageDisplayed(): void {
    this.waitForElement(this.selectors.fileUpload1)
    this.waitForElement(this.selectors.fileUpload2)
    this.waitForElement(this.selectors.compareButton)
    this.elementContainsText(this.selectors.pageTitle, 'Document Comparison')
  }

  /**
   * Verify files are uploaded
   */
  verifyFilesUploaded(): void {
    this.isElementVisible(this.selectors.file1Preview)
    this.isElementVisible(this.selectors.file2Preview)
    this.isElementVisible(this.selectors.file1Name)
    this.isElementVisible(this.selectors.file2Name)
  }

  /**
   * Verify comparison results are displayed
   */
  verifyComparisonResults(): void {
    this.waitForElement(this.selectors.comparisonResults, 30000)
    this.isElementVisible(this.selectors.differenceSummary)
    this.isElementVisible(this.selectors.comparisonToolbar)
  }

  /**
   * Verify loading state during comparison
   */
  verifyLoadingState(): void {
    this.isElementVisible(this.selectors.loadingSpinner)
    this.isElementVisible(this.selectors.progressBar)
  }

  /**
   * Verify error message
   */
  verifyErrorMessage(message: string): void {
    this.elementContainsText(this.selectors.errorMessage, message)
  }

  /**
   * Verify success message
   */
  verifySuccessMessage(message: string): void {
    this.elementContainsText(this.selectors.successMessage, message)
  }

  /**
   * Get file 1 name
   */
  getFile1Name(): Cypress.Chainable<string> {
    return this.getElementText(this.selectors.file1Name)
  }

  /**
   * Get file 2 name
   */
  getFile2Name(): Cypress.Chainable<string> {
    return this.getElementText(this.selectors.file2Name)
  }

  /**
   * Get file 1 size
   */
  getFile1Size(): Cypress.Chainable<string> {
    return this.getElementText(this.selectors.file1Size)
  }

  /**
   * Get file 2 size
   */
  getFile2Size(): Cypress.Chainable<string> {
    return this.getElementText(this.selectors.file2Size)
  }

  /**
   * Get difference count
   */
  getDifferenceCount(): Cypress.Chainable<string> {
    return this.getElementText(this.selectors.differenceCounter)
  }

  /**
   * Verify compare button is disabled
   */
  verifyCompareButtonDisabled(): void {
    cy.get(this.selectors.compareButton).should('be.disabled')
  }

  /**
   * Verify compare button is enabled
   */
  verifyCompareButtonEnabled(): void {
    cy.get(this.selectors.compareButton).should('not.be.disabled')
  }

  /**
   * Verify export functionality is available
   */
  verifyExportAvailable(): void {
    this.isElementVisible(this.selectors.exportButton)
  }

  /**
   * Verify navigation controls are available
   */
  verifyNavigationControls(): void {
    this.isElementVisible(this.selectors.nextDifferenceButton)
    this.isElementVisible(this.selectors.previousDifferenceButton)
    this.isElementVisible(this.selectors.differenceCounter)
  }

  /**
   * Verify zoom controls are available
   */
  verifyZoomControls(): void {
    this.isElementVisible(this.selectors.zoomInButton)
    this.isElementVisible(this.selectors.zoomOutButton)
    this.isElementVisible(this.selectors.resetZoomButton)
  }

  /**
   * Wait for comparison to complete
   */
  waitForComparisonComplete(): void {
    // Wait for loading to disappear and results to appear
    cy.get(this.selectors.loadingSpinner).should('not.exist')
    this.waitForElement(this.selectors.comparisonResults, 30000)
  }

  /**
   * Verify file upload validation
   */
  verifyFileUploadValidation(errorMessage: string): void {
    this.verifyErrorMessage(errorMessage)
  }

  /**
   * Verify supported file types message
   */
  verifySupportedFileTypes(): void {
    cy.contains('Supported file types: PDF, DOC, DOCX').should('be.visible')
  }

  /**
   * Verify maximum file size message
   */
  verifyMaxFileSize(): void {
    cy.contains('Maximum file size: 10MB').should('be.visible')
  }

  /**
   * Verify page accessibility
   */
  verifyAccessibility(): void {
    cy.checkA11y()
  }

  /**
   * Test drag and drop file upload
   */
  dragAndDropFile(selector: string, fileName: string): void {
    cy.fixture(fileName, 'base64').then(fileContent => {
      cy.get(selector).trigger('dragover')
      cy.get(selector).trigger('drop', {
        dataTransfer: {
          files: [
            new File([fileContent], fileName, { type: 'application/pdf' })
          ]
        }
      })
    })
  }

  /**
   * Verify responsive design on mobile
   */
  verifyMobileLayout(): void {
    cy.viewport('iphone-6')
    this.verifyComparisonPageDisplayed()
    // Check that elements stack vertically on mobile
    cy.get(this.selectors.fileUpload1).should('be.visible')
    cy.get(this.selectors.fileUpload2).should('be.visible')
  }

  /**
   * Verify responsive design on tablet
   */
  verifyTabletLayout(): void {
    cy.viewport('ipad-2')
    this.verifyComparisonPageDisplayed()
    // Check that layout adapts for tablet
    cy.get(this.selectors.fileUpload1).should('be.visible')
    cy.get(this.selectors.fileUpload2).should('be.visible')
  }
} 