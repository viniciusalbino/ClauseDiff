/**
 * Prisma Testing Utilities - Central Export Point
 * 
 * Provides a comprehensive testing infrastructure for Prisma database operations
 * with mocking, transaction rollback, and seeding capabilities.
 */

// Core client and mocking utilities
export {
  prismaMock,
  resetPrismaMocks,
  resetMockData,
  seedMockData,
  getMockData
} from './client';

// Transaction rollback utilities
export {
  beginTransaction,
  rollbackTransaction,
  commitTransaction,
  setupTransactionRollback,
  withTransaction,
  createTransactionMock,
  databaseIsolation,
  transactionHelpers
} from './transaction';

// Database test utilities
export {
  databaseTestKit,
  setupDatabaseTests,
  setupTransactionTests,
  mockPrismaClient,
  withCleanDatabase,
  withSeededDatabase,
  databaseAssertions
} from './utils';

// Seeding utilities (simplified export to avoid TypeScript issues)
export { seedScenarios, dataGenerators } from './seed';

/**
 * Prisma Test Kit - All-in-one testing solution
 * 
 * This provides a complete testing infrastructure for Prisma operations:
 * - Mock Prisma client with realistic behavior
 * - Transaction rollback for test isolation
 * - Database seeding for consistent test data
 * - Utilities for common testing scenarios
 */
export const prismaTestKit = {
  // Mock client for database operations
  client: {} as any, // Will be populated by importing module

  // Setup functions for different testing scenarios
  setup: {
    // Clean database isolation (no transaction rollback)
    databaseIsolation: () => {
      const { setupDatabaseTests } = require('./utils');
      setupDatabaseTests();
    },

    // Transaction-based isolation (with rollback)
    transactionIsolation: () => {
      const { setupTransactionTests } = require('./utils');
      setupTransactionTests();
    },

    // Mock Prisma client globally
    mockClient: () => {
      const { mockPrismaClient } = require('./utils');
      mockPrismaClient();
    }
  },

  // Quick access to common operations
  quick: {
    // Reset everything to clean state
    reset: () => {
      const { resetPrismaMocks } = require('./client');
      resetPrismaMocks();
    },

    // Create test user
    createUser: async (userData: any = {}) => {
      const { databaseTestKit } = require('./utils');
      return await databaseTestKit.seed.basicUser();
    },

    // Create admin user
    createAdmin: async () => {
      const { databaseTestKit } = require('./utils');
      return await databaseTestKit.seed.adminUser();
    },

    // Create user session
    createSession: async (userId: string) => {
      const { databaseTestKit } = require('./utils');
      return await databaseTestKit.seed.userSession(userId);
    },

    // Verify database is empty
    isEmpty: () => {
      const { databaseTestKit } = require('./utils');
      return databaseTestKit.verify.isEmpty();
    },

    // Get record counts
    getCounts: () => {
      const { databaseTestKit } = require('./utils');
      return databaseTestKit.verify.getCounts();
    }
  },

  // Test scenarios
  scenarios: {
    // Basic authenticated user
    authenticatedUser: async () => {
      const { databaseTestKit } = require('./utils');
      return await databaseTestKit.scenarios.authenticatedUser();
    },

    // Admin user with permissions
    adminUser: async () => {
      const { databaseTestKit } = require('./utils');
      return await databaseTestKit.scenarios.adminUser();
    },

    // Multiple users
    multipleUsers: async () => {
      const { databaseTestKit } = require('./utils');
      return await databaseTestKit.scenarios.multipleUsers();
    }
  },

  // Test helpers
  helpers: {
    // Run test with clean database
    withCleanDb: async (testFn: () => Promise<any> | any) => {
      const { withCleanDatabase } = require('./utils');
      return await withCleanDatabase(testFn);
    },

    // Run test with seeded data
    withSeededDb: async (seedFn: () => Promise<void> | void, testFn: () => Promise<any> | any) => {
      const { withSeededDatabase } = require('./utils');
      return await withSeededDatabase(seedFn, testFn);
    },

    // Run test within transaction
    withTransaction: async (testFn: () => Promise<any> | any) => {
      const { withTransaction } = require('./transaction');
      return await withTransaction(testFn);
    }
  },

  // Assertions
  assert: {
    // Assert user was created
    userCreated: async (email: string, expectedData: any = {}) => {
      const { databaseAssertions } = require('./utils');
      return await databaseAssertions.assertUserCreated(email, expectedData);
    },

    // Assert session was created
    sessionCreated: async (sessionToken: string, userId: string) => {
      const { databaseAssertions } = require('./utils');
      return await databaseAssertions.assertSessionCreated(sessionToken, userId);
    },

    // Assert database is clean
    databaseClean: () => {
      const { databaseAssertions } = require('./utils');
      return databaseAssertions.assertDatabaseClean();
    },

    // Assert specific record counts
    counts: (expectedCounts: any) => {
      const { databaseAssertions } = require('./utils');
      return databaseAssertions.assertCounts(expectedCounts);
    }
  }
};

// Populate the client after imports are resolved
setTimeout(() => {
  const { prismaMock } = require('./client');
  prismaTestKit.client = prismaMock;
}, 0);

export default prismaTestKit; 