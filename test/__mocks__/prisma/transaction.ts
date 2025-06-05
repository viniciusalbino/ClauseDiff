/**
 * Prisma Transaction Rollback Utilities
 * 
 * Provides utilities for transaction-based test isolation,
 * ensuring that database changes are rolled back after each test.
 */

import { prismaMock, resetMockData, getMockData } from './client';

// Stack to store database snapshots for rollback
let transactionStack: Array<{
  users: any[];
  accounts: any[];
  sessions: any[];
  auditLogs: any[];
  billingAccounts: any[];
  verificationTokens: any[];
}> = [];

/**
 * Begin a new transaction by saving current state
 */
export function beginTransaction() {
  const currentState = getMockData();
  transactionStack.push({
    users: [...currentState.users],
    accounts: [...currentState.accounts],
    sessions: [...currentState.sessions],
    auditLogs: [...currentState.auditLogs],
    billingAccounts: [...currentState.billingAccounts],
    verificationTokens: [...currentState.verificationTokens]
  });
}

/**
 * Rollback to the last transaction point
 */
export function rollbackTransaction() {
  if (transactionStack.length === 0) {
    // No transaction to rollback to, reset to empty state
    resetMockData();
    return;
  }

  const previousState = transactionStack.pop();
  if (previousState) {
    // Restore previous state
    const mockDataModule = require('./client');
    Object.assign(mockDataModule.mockData, previousState);
  }
}

/**
 * Commit transaction by removing the last saved state
 */
export function commitTransaction() {
  if (transactionStack.length > 0) {
    transactionStack.pop();
  }
}

/**
 * Setup automatic transaction rollback for tests
 * Use this in beforeEach to ensure test isolation
 */
export function setupTransactionRollback() {
  beforeEach(() => {
    beginTransaction();
  });

  afterEach(() => {
    rollbackTransaction();
  });
}

/**
 * Create a transaction context for a test function
 */
export async function withTransaction<T>(testFn: () => Promise<T> | T): Promise<T> {
  beginTransaction();
  
  try {
    const result = await testFn();
    commitTransaction();
    return result;
  } catch (error) {
    rollbackTransaction();
    throw error;
  }
}

/**
 * Mock transaction implementation that automatically handles rollback
 */
export function createTransactionMock() {
  return jest.fn().mockImplementation(async (operations: any) => {
    beginTransaction();
    
    try {
      const results = [];
      
      if (Array.isArray(operations)) {
        for (const operation of operations) {
          results.push(await operation);
        }
      } else if (typeof operations === 'function') {
        const result = await operations(prismaMock);
        results.push(result);
      }
      
      // Simulate commit
      commitTransaction();
      return results;
    } catch (error) {
      // Simulate rollback on error
      rollbackTransaction();
      throw error;
    }
  });
}

/**
 * Database isolation utilities for different test scenarios
 */
export const databaseIsolation = {
  // Ensure each test runs with a clean database
  cleanDatabase: () => {
    resetMockData();
    transactionStack = [];
  },

  // Save current database state as a checkpoint
  createCheckpoint: () => {
    beginTransaction();
  },

  // Restore to the last checkpoint
  restoreCheckpoint: () => {
    rollbackTransaction();
  },

  // Get current transaction depth (for debugging)
  getTransactionDepth: () => {
    return transactionStack.length;
  },

  // Verify transaction isolation is working
  verifyIsolation: () => {
    const currentData = getMockData();
    const totalRecords = Object.values(currentData).reduce((sum, arr) => sum + arr.length, 0);
    
    return {
      hasData: totalRecords > 0,
      transactionDepth: transactionStack.length,
      recordCounts: {
        users: currentData.users.length,
        accounts: currentData.accounts.length,
        sessions: currentData.sessions.length,
        auditLogs: currentData.auditLogs.length,
        billingAccounts: currentData.billingAccounts.length,
        verificationTokens: currentData.verificationTokens.length
      }
    };
  }
};

/**
 * Transaction test helpers for common scenarios
 */
export const transactionHelpers = {
  // Test that changes are isolated
  testIsolation: async (testFn: () => Promise<void>) => {
    const initialState = getMockData();
    
    await withTransaction(async () => {
      await testFn();
      
      // Verify changes were made during transaction
      const duringTransactionState = getMockData();
      const hasChanges = JSON.stringify(initialState) !== JSON.stringify(duringTransactionState);
      
      if (!hasChanges) {
        throw new Error('Expected changes during transaction, but none were detected');
      }
    });
    
    // Verify changes were rolled back
    const finalState = getMockData();
    expect(finalState).toEqual(initialState);
  },

  // Test transaction rollback on error
  testRollbackOnError: async (testFn: () => Promise<void>) => {
    const initialState = getMockData();
    
    try {
      await withTransaction(async () => {
        await testFn();
        throw new Error('Simulated error to trigger rollback');
      });
    } catch (error) {
      // Expected error
    }
    
    // Verify rollback occurred
    const finalState = getMockData();
    expect(finalState).toEqual(initialState);
  },

  // Test nested transactions
  testNestedTransactions: async () => {
    const initialState = getMockData();
    
    await withTransaction(async () => {
      // First level changes
      await prismaMock.user.create({ data: { email: 'test1@example.com' } });
      
      await withTransaction(async () => {
        // Second level changes
        await prismaMock.user.create({ data: { email: 'test2@example.com' } });
        
        const nestedState = getMockData();
        expect(nestedState.users.length).toBe(2);
      });
      
      // After nested transaction commits
      const afterNestedState = getMockData();
      expect(afterNestedState.users.length).toBe(2);
    });
    
    // After outer transaction commits
    const finalState = getMockData();
    expect(finalState.users.length).toBe(2);
  }
};

export default {
  beginTransaction,
  rollbackTransaction,
  commitTransaction,
  setupTransactionRollback,
  withTransaction,
  createTransactionMock,
  databaseIsolation,
  transactionHelpers
}; 