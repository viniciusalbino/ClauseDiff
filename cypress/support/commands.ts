/// <reference types="cypress" />
/// <reference types="cypress-file-upload" />
/// <reference types="cypress-axe" />

// ***********************************************
// This example commands.js shows you how to
// create various custom commands and overwrite
// existing commands.
//
// For more comprehensive examples of custom
// commands please read more here:
// https://on.cypress.io/custom-commands
// ***********************************************

import 'cypress-file-upload'
import 'cypress-axe'

/**
 * Custom command to log in a user via the UI
 * @param email - User email
 * @param password - User password
 */
Cypress.Commands.add('login', (email: string, password: string) => {
  cy.session([email, password], () => {
    cy.visit('/login')
    cy.get('[data-testid="email-input"]').type(email)
    cy.get('[data-testid="password-input"]').type(password)
    cy.get('[data-testid="login-button"]').click()
    cy.url().should('not.include', '/login')
    cy.get('[data-testid="user-menu"]').should('be.visible')
  })
})

/**
 * Custom command to log in a user via API (faster for setup)
 * @param email - User email
 * @param password - User password
 */
Cypress.Commands.add('loginApi', (email: string, password: string) => {
  cy.request({
    method: 'POST',
    url: '/api/auth/signin',
    body: {
      email: email,
      password: password,
      csrfToken: 'mock-csrf-token'
    }
  }).then((response) => {
    expect(response.status).to.eq(200)
  })
})

/**
 * Custom command to log out the current user
 */
Cypress.Commands.add('logout', () => {
  cy.visit('/api/auth/signout', { method: 'POST' })
  cy.visit('/')
  cy.get('[data-testid="login-button"]').should('be.visible')
})

/**
 * Custom command to register a new user
 * @param email - User email
 * @param password - User password
 * @param firstName - User first name
 * @param lastName - User last name
 */
Cypress.Commands.add('register', (email: string, password: string, firstName: string, lastName: string) => {
  cy.visit('/register')
  cy.get('[data-testid="first-name-input"]').type(firstName)
  cy.get('[data-testid="last-name-input"]').type(lastName)
  cy.get('[data-testid="email-input"]').type(email)
  cy.get('[data-testid="password-input"]').type(password)
  cy.get('[data-testid="confirm-password-input"]').type(password)
  cy.get('[data-testid="terms-checkbox"]').check()
  cy.get('[data-testid="register-button"]').click()
})

/**
 * Custom command to seed the database with test data
 */
Cypress.Commands.add('seedDatabase', () => {
  cy.task('seedDatabase')
})

/**
 * Custom command to clean the database
 */
Cypress.Commands.add('cleanDatabase', () => {
  cy.task('cleanDatabase')
})

/**
 * Custom command to upload a file
 * @param selector - Element selector for file input
 * @param fileName - Name of the file to upload from fixtures
 */
Cypress.Commands.add('uploadFile', (selector: string, fileName: string) => {
  cy.get(selector).attachFile(fileName)
})

/**
 * Custom command to wait for an element to be visible and interactable
 * @param selector - Element selector
 */
Cypress.Commands.add('waitForElement', (selector: string) => {
  cy.get(selector, { timeout: 10000 })
    .should('be.visible')
    .and('not.be.disabled')
})

/**
 * Custom command to check if user is authenticated
 */
Cypress.Commands.add('checkAuthentication', () => {
  return cy.request({
    url: '/api/auth/session',
    failOnStatusCode: false
  }).then((response) => {
    return response.status === 200 && response.body?.user
  })
})

/**
 * Custom command to create a test user via API
 * @param userData - User data object
 */
Cypress.Commands.add('createTestUser', (userData: any) => {
  cy.request({
    method: 'POST',
    url: '/api/auth/register',
    body: userData
  }).then((response) => {
    expect(response.status).to.eq(201)
    return response.body
  })
})

/**
 * Custom command to delete a test user via API
 * @param userId - User ID to delete
 */
Cypress.Commands.add('deleteTestUser', (userId: string) => {
  cy.request({
    method: 'DELETE',
    url: `/api/admin/users/${userId}`,
    failOnStatusCode: false
  })
})

/**
 * Custom command to reset password via API (for testing)
 * @param email - User email
 * @param newPassword - New password
 */
Cypress.Commands.add('resetPassword', (email: string, newPassword: string) => {
  cy.request({
    method: 'POST',
    url: '/api/auth/reset-password',
    body: {
      email: email,
      password: newPassword,
      token: 'test-reset-token'
    }
  })
})

/**
 * Custom command to simulate file comparison
 * @param file1 - First file name from fixtures
 * @param file2 - Second file name from fixtures
 */
Cypress.Commands.add('compareFiles', (file1: string, file2: string) => {
  cy.get('[data-testid="file-upload-1"]').attachFile(file1)
  cy.get('[data-testid="file-upload-2"]').attachFile(file2)
  cy.get('[data-testid="compare-button"]').click()
  cy.get('[data-testid="comparison-results"]', { timeout: 30000 }).should('be.visible')
})

/**
 * Custom command to check for accessibility violations
 */
Cypress.Commands.add('checkA11y', () => {
  cy.injectAxe()
  cy.checkA11y()
})

// Database management commands
Cypress.Commands.add('checkDatabaseUser', (email: string) => {
  cy.task('checkDatabaseUser', email)
})

Cypress.Commands.add('createTestUser', (userData: any) => {
  cy.task('createTestUser', userData)
})

Cypress.Commands.add('deleteTestUser', (userId: string) => {
  cy.task('deleteTestUser', userId)
}) 