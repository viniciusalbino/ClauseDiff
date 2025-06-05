import { defineConfig } from 'cypress'

export default defineConfig({
  e2e: {
    baseUrl: 'http://localhost:3000',
    supportFile: 'cypress/support/e2e.ts',
    specPattern: 'cypress/e2e/**/*.{js,jsx,ts,tsx}',
    viewportWidth: 1280,
    viewportHeight: 720,
    video: true,
    screenshotOnRunFailure: true,
    videosFolder: 'cypress/videos',
    screenshotsFolder: 'cypress/screenshots',
    setupNodeEvents(on, config) {
      // implement node event listeners here
      
      // Task for seeding test data
      on('task', {
        seedDatabase() {
          // Database seeding logic for tests
          return null
        },
        cleanDatabase() {
          // Database cleanup logic for tests
          return null
        },
        log(message) {
          console.log(message)
          return null
        }
      })
    },
    env: {
      // Environment variables for testing
      NEXTAUTH_URL: 'http://localhost:3000',
      TEST_USER_EMAIL: 'test@clausediff.com',
      TEST_USER_PASSWORD: 'TestPassword123!',
      API_URL: 'http://localhost:3000/api'
    }
  },
  
  component: {
    devServer: {
      framework: 'next',
      bundler: 'webpack',
    },
    supportFile: 'cypress/support/component.ts',
    specPattern: 'cypress/component/**/*.{js,jsx,ts,tsx}',
    viewportWidth: 1280,
    viewportHeight: 720,
  },
  
  // Browser configurations for cross-browser testing
  experimentalStudio: true,
  retries: {
    runMode: 2,
    openMode: 0
  },
  
  // Default command timeout
  defaultCommandTimeout: 10000,
  requestTimeout: 10000,
  responseTimeout: 10000,
  
  // File server options
  fileServerFolder: '.',
  fixturesFolder: 'cypress/fixtures',
  
  // Additional viewport configurations for testing
  viewportHeight: 720,
  viewportWidth: 1280,
  
  // Browser configurations for cross-browser testing
  chromeWebSecurity: false,
  
  // Concurrent testing
  numTestsKeptInMemory: 0,
  
  // Performance optimizations
  watchForFileChanges: false,
  video: false, // Disable video recording for faster tests unless needed
  screenshotOnRunFailure: true
}) 