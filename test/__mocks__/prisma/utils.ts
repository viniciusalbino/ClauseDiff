/**
 * Prisma Database Test Utilities
 * 
 * Central utilities for database testing with Prisma mocks,
 * transaction rollback, and seeding capabilities.
 */

import { prismaMock, resetPrismaMocks, resetMockData, getMockData } from './client';
import { 
  setupTransactionRollback, 
  withTransaction, 
  databaseIsolation,
  transactionHelpers 
} from './transaction';

/**
 * Database Test Kit - Main testing utilities
 */
export const databaseTestKit = {
  // Client and mock management
  client: prismaMock,
  resetMocks: resetPrismaMocks,
  resetData: resetMockData,
  getData: getMockData,

  // Transaction utilities
  setupRollback: setupTransactionRollback,
  withTransaction,
  isolation: databaseIsolation,
  transactionHelpers,

  // Simplified seeding for testing
  seed: {
    // Create a basic test user
    basicUser: async () => {
      const user = {
        id: 'user-test-1',
        email: 'test@example.com',
        firstName: 'Test',
        lastName: 'User',
        role: 'USER',
        createdAt: new Date(),
        updatedAt: new Date(),
        emailVerified: new Date(),
        name: 'Test User'
      };
      
      await prismaMock.user.create({ data: user as any });
      return user;
    },

    // Create an admin user
    adminUser: async () => {
      const user = {
        id: 'user-admin-1',
        email: 'admin@example.com',
        firstName: 'Admin',
        lastName: 'User',
        role: 'ADMIN',
        createdAt: new Date(),
        updatedAt: new Date(),
        emailVerified: new Date(),
        name: 'Admin User'
      };
      
      await prismaMock.user.create({ data: user as any });
      return user;
    },

    // Create a session for a user
    userSession: async (userId: string) => {
      const session = {
        id: `session-${userId}`,
        sessionToken: `token-${userId}`,
        userId,
        expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
      };
      
      await prismaMock.session.create({ data: session });
      return session;
    },

    // Create audit log entry
    auditLog: async (userId: string, eventType: string) => {
      const log = {
        id: `audit-${Date.now()}`,
        userId,
        eventType,
        ip: '127.0.0.1',
        userAgent: 'Test Agent',
        timestamp: new Date(),
        details: {}
      };
      
      await prismaMock.auditLog.create({ data: log });
      return log;
    },

    // Clear all data
    clear: () => {
      resetMockData();
    }
  },

  // Test scenario helpers
  scenarios: {
    // Set up authenticated user scenario
    authenticatedUser: async () => {
      const user = await databaseTestKit.seed.basicUser();
      const session = await databaseTestKit.seed.userSession(user.id);
      return { user, session };
    },

    // Set up admin user scenario
    adminUser: async () => {
      const user = await databaseTestKit.seed.adminUser();
      const session = await databaseTestKit.seed.userSession(user.id);
      return { user, session };
    },

    // Set up multiple users scenario
    multipleUsers: async () => {
      const user1 = await databaseTestKit.seed.basicUser();
      const user2 = await databaseTestKit.seed.adminUser();
      const session1 = await databaseTestKit.seed.userSession(user1.id);
      const session2 = await databaseTestKit.seed.userSession(user2.id);
      
      return { 
        users: [user1, user2], 
        sessions: [session1, session2] 
      };
    }
  },

  // Verification utilities
  verify: {
    // Check if database is empty
    isEmpty: () => {
      const data = getMockData();
      return Object.values(data).every(arr => arr.length === 0);
    },

    // Check if user exists
    userExists: async (email: string) => {
      const user = await prismaMock.user.findUnique({ where: { email } });
      return !!user;
    },

    // Check if session exists
    sessionExists: async (sessionToken: string) => {
      const session = await prismaMock.session.findUnique({ where: { sessionToken } });
      return !!session;
    },

    // Get record counts
    getCounts: () => {
      const data = getMockData();
      return {
        users: data.users.length,
        sessions: data.sessions.length,
        accounts: data.accounts.length,
        auditLogs: data.auditLogs.length,
        verificationTokens: data.verificationTokens.length
      };
    }
  }
};

/**
 * Setup function for test suites that need database isolation
 */
export function setupDatabaseTests() {
  beforeEach(() => {
    resetPrismaMocks();
    databaseIsolation.cleanDatabase();
  });

  afterEach(() => {
    resetPrismaMocks();
    databaseIsolation.cleanDatabase();
  });
}

/**
 * Setup function for test suites that need transaction rollback
 */
export function setupTransactionTests() {
  setupTransactionRollback();
  
  beforeEach(() => {
    resetPrismaMocks();
  });
}

/**
 * Mock the Prisma client in Jest
 * Note: This should be called at the top of test files that need Prisma mocking
 */
export function mockPrismaClient() {
  // This function is kept for compatibility but the actual mocking
  // should be done in individual test files using jest.mock()
  return prismaMock;
}

/**
 * Test helper to run a test with clean database state
 */
export async function withCleanDatabase<T>(testFn: () => Promise<T> | T): Promise<T> {
  databaseIsolation.cleanDatabase();
  
  try {
    const result = await testFn();
    return result;
  } finally {
    databaseIsolation.cleanDatabase();
  }
}

/**
 * Test helper to run a test with seeded data
 */
export async function withSeededDatabase<T>(
  seedFn: () => Promise<void> | void,
  testFn: () => Promise<T> | T
): Promise<T> {
  return await withCleanDatabase(async () => {
    await seedFn();
    return await testFn();
  });
}

/**
 * Assert that database operations are working correctly
 */
export const databaseAssertions = {
  // Assert user was created correctly
  assertUserCreated: async (email: string, expectedData: any) => {
    const user = await prismaMock.user.findUnique({ where: { email } });
    expect(user).toBeTruthy();
    expect(user?.email).toBe(email);
    
    if (expectedData.role) {
      expect(user?.role).toBe(expectedData.role);
    }
    
    if (expectedData.name) {
      expect(user?.name).toBe(expectedData.name);
    }
  },

  // Assert session was created correctly
  assertSessionCreated: async (sessionToken: string, userId: string) => {
    const session = await prismaMock.session.findUnique({ where: { sessionToken } });
    expect(session).toBeTruthy();
    expect(session?.userId).toBe(userId);
    expect(session?.expires).toBeInstanceOf(Date);
  },

  // Assert audit log was created
  assertAuditLogCreated: async (userId: string, eventType: string) => {
    const logs = await prismaMock.auditLog.findMany({
      where: { userId, eventType }
    });
    expect(logs.length).toBeGreaterThan(0);
  },

  // Assert database is clean
  assertDatabaseClean: () => {
    expect(databaseTestKit.verify.isEmpty()).toBe(true);
  },

  // Assert specific counts
  assertCounts: (expectedCounts: Partial<ReturnType<typeof databaseTestKit.verify.getCounts>>) => {
    const actualCounts = databaseTestKit.verify.getCounts();
    
    Object.entries(expectedCounts).forEach(([key, expectedValue]) => {
      expect(actualCounts[key as keyof typeof actualCounts]).toBe(expectedValue);
    });
  }
};

// Export the main utilities
export {
  prismaMock,
  resetPrismaMocks,
  withTransaction,
  setupTransactionRollback,
  databaseIsolation
};

export default databaseTestKit; 