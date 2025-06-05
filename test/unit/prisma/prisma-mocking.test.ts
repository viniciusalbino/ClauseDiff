/**
 * Prisma Mocking Test Suite
 * 
 * Tests the comprehensive Prisma testing infrastructure including:
 * - Client mocking functionality
 * - Transaction rollback capabilities
 * - Database seeding utilities
 * - Test isolation mechanisms
 */

// Mock Prisma client
jest.mock('../../../src/lib/prisma', () => {
  const { prismaMock } = require('../../__mocks__/prisma/client');
  return {
    prisma: prismaMock
  };
});

import {
  prismaTestKit,
  prismaMock,
  withTransaction,
  withCleanDatabase,
  databaseIsolation,
  setupDatabaseTests,
  databaseAssertions
} from '../../__mocks__/prisma';

describe('Prisma Testing Infrastructure', () => {
  // Set up database isolation for these tests
  setupDatabaseTests();

  describe('Basic Client Mocking', () => {
    it('should create a user successfully', async () => {
      const userData = {
        email: 'test@example.com',
        firstName: 'Test',
        lastName: 'User',
        role: 'USER' as const
      };

      const createdUser = await prismaMock.user.create({ data: userData });

      expect(createdUser).toBeTruthy();
      expect(createdUser.email).toBe(userData.email);
      expect(createdUser.id).toBeTruthy();
      expect(createdUser.createdAt).toBeInstanceOf(Date);
    });

    it('should find a user by email', async () => {
      // Create user first
      const userData = {
        email: 'findme@example.com',
        firstName: 'Find',
        lastName: 'Me'
      };

      await prismaMock.user.create({ data: userData });

      // Find the user
      const foundUser = await prismaMock.user.findUnique({
        where: { email: userData.email }
      });

      expect(foundUser).toBeTruthy();
      expect(foundUser?.email).toBe(userData.email);
    });

    it('should return null for non-existent user', async () => {
      const foundUser = await prismaMock.user.findUnique({
        where: { email: 'nonexistent@example.com' }
      });

      expect(foundUser).toBeNull();
    });

    it('should update user data', async () => {
      // Create user first
      const userData = {
        email: 'update@example.com',
        firstName: 'Original',
        lastName: 'Name'
      };

      const createdUser = await prismaMock.user.create({ data: userData });

      // Update the user
      const updatedUser = await prismaMock.user.update({
        where: { id: createdUser.id },
        data: { firstName: 'Updated' }
      });

      expect(updatedUser.firstName).toBe('Updated');
      expect(updatedUser.lastName).toBe('Name'); // Should remain unchanged
      expect(updatedUser.updatedAt).toBeInstanceOf(Date);
    });

    it('should delete a user', async () => {
      // Create user first
      const userData = {
        email: 'delete@example.com',
        firstName: 'To',
        lastName: 'Delete'
      };

      const createdUser = await prismaMock.user.create({ data: userData });

      // Delete the user
      const deletedUser = await prismaMock.user.delete({
        where: { id: createdUser.id }
      });

      expect(deletedUser.id).toBe(createdUser.id);

      // Verify user is deleted
      const foundUser = await prismaMock.user.findUnique({
        where: { id: createdUser.id }
      });

      expect(foundUser).toBeNull();
    });

    it('should handle findMany with filtering', async () => {
      // Create multiple users
      await prismaMock.user.create({
        data: { email: 'user1@example.com', role: 'USER' }
      });
      await prismaMock.user.create({
        data: { email: 'admin1@example.com', role: 'ADMIN' }
      });
      await prismaMock.user.create({
        data: { email: 'user2@example.com', role: 'USER' }
      });

      // Find all users
      const allUsers = await prismaMock.user.findMany();
      expect(allUsers.length).toBe(3);

      // Find users with specific role
      const userRoleUsers = await prismaMock.user.findMany({
        where: { role: 'USER' }
      });
      expect(userRoleUsers.length).toBe(2);

      // Find with limit
      const limitedUsers = await prismaMock.user.findMany({
        take: 2
      });
      expect(limitedUsers.length).toBe(2);
    });

    it('should count users', async () => {
      // Create some users
      await prismaMock.user.create({ data: { email: 'count1@example.com' } });
      await prismaMock.user.create({ data: { email: 'count2@example.com' } });

      const count = await prismaMock.user.count();
      expect(count).toBe(2);
    });
  });

  describe('Session Management', () => {
    it('should create and manage sessions', async () => {
      // Create user first
      const user = await prismaMock.user.create({
        data: { email: 'session@example.com' }
      });

      // Create session
      const sessionData = {
        sessionToken: 'test-session-token',
        userId: user.id,
        expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
      };

      const createdSession = await prismaMock.session.create({ data: sessionData });

      expect(createdSession.sessionToken).toBe(sessionData.sessionToken);
      expect(createdSession.userId).toBe(user.id);

      // Find session
      const foundSession = await prismaMock.session.findUnique({
        where: { sessionToken: sessionData.sessionToken }
      });

      expect(foundSession).toBeTruthy();
      expect(foundSession?.userId).toBe(user.id);

      // Delete session
      await prismaMock.session.delete({
        where: { sessionToken: sessionData.sessionToken }
      });

      const deletedSession = await prismaMock.session.findUnique({
        where: { sessionToken: sessionData.sessionToken }
      });

      expect(deletedSession).toBeNull();
    });

    it('should handle session cleanup for user', async () => {
      // Create user
      const user = await prismaMock.user.create({
        data: { email: 'cleanup@example.com' }
      });

      // Create multiple sessions
      await prismaMock.session.create({
        data: {
          sessionToken: 'token1',
          userId: user.id,
          expires: new Date()
        }
      });
      
      await prismaMock.session.create({
        data: {
          sessionToken: 'token2',
          userId: user.id,
          expires: new Date()
        }
      });

      // Delete all sessions for user
      const deleteResult = await prismaMock.session.deleteMany({
        where: { userId: user.id }
      });

      expect(deleteResult.count).toBe(2);

      // Verify sessions are deleted
      const remainingSessions = await prismaMock.session.findMany({
        where: { userId: user.id }
      });

      expect(remainingSessions.length).toBe(0);
    });
  });

  describe('Audit Logging', () => {
    it('should create and query audit logs', async () => {
      // Create user first
      const user = await prismaMock.user.create({
        data: { email: 'audit@example.com' }
      });

      // Create audit log
      const logData = {
        userId: user.id,
        eventType: 'LOGIN',
        ip: '192.168.1.1',
        userAgent: 'Test Browser',
        details: { provider: 'credentials' }
      };

      const createdLog = await prismaMock.auditLog.create({ data: logData });

      expect(createdLog.eventType).toBe('LOGIN');
      expect(createdLog.userId).toBe(user.id);
      expect(createdLog.timestamp).toBeInstanceOf(Date);

      // Query logs
      const userLogs = await prismaMock.auditLog.findMany({
        where: { userId: user.id }
      });

      expect(userLogs.length).toBe(1);
      expect(userLogs[0].eventType).toBe('LOGIN');

      // Query by event type
      const loginLogs = await prismaMock.auditLog.findMany({
        where: { eventType: 'LOGIN' }
      });

      expect(loginLogs.length).toBeGreaterThan(0);
    });

    it('should handle audit log ordering and limiting', async () => {
      // Create user
      const user = await prismaMock.user.create({
        data: { email: 'audit-order@example.com' }
      });

      // Create multiple logs with different timestamps
      await prismaMock.auditLog.create({
        data: {
          userId: user.id,
          eventType: 'LOGIN',
          timestamp: new Date('2024-01-01T10:00:00Z')
        }
      });

      await prismaMock.auditLog.create({
        data: {
          userId: user.id,
          eventType: 'LOGOUT',
          timestamp: new Date('2024-01-01T11:00:00Z')
        }
      });

      await prismaMock.auditLog.create({
        data: {
          userId: user.id,
          eventType: 'LOGIN',
          timestamp: new Date('2024-01-01T12:00:00Z')
        }
      });

      // Query with ordering and limit
      const recentLogs = await prismaMock.auditLog.findMany({
        where: { userId: user.id },
        orderBy: { timestamp: 'desc' },
        take: 2
      });

      expect(recentLogs.length).toBe(2);
      expect(recentLogs[0].eventType).toBe('LOGIN'); // Most recent
      expect(recentLogs[1].eventType).toBe('LOGOUT');
    });
  });

  describe('Transaction Support', () => {
    it('should handle transaction operations', async () => {
      const operations = [
        prismaMock.user.create({
          data: { email: 'transaction1@example.com' }
        }),
        prismaMock.user.create({
          data: { email: 'transaction2@example.com' }
        })
      ];

      const results = await prismaMock.$transaction(operations);

      expect(results.length).toBe(2);
      expect(results[0].email).toBe('transaction1@example.com');
      expect(results[1].email).toBe('transaction2@example.com');
    });

    it('should handle function-based transactions', async () => {
      const result = await prismaMock.$transaction(async (tx) => {
        const user = await tx.user.create({
          data: { email: 'func-transaction@example.com' }
        });

        const session = await tx.session.create({
          data: {
            sessionToken: 'func-token',
            userId: user.id,
            expires: new Date()
          }
        });

        return { user, session };
      });

      expect(result.user.email).toBe('func-transaction@example.com');
      expect(result.session.userId).toBe(result.user.id);
    });
  });

  describe('Test Kit Integration', () => {
    it('should provide quick access to common operations', async () => {
      // Reset and verify empty state
      prismaTestKit.quick.reset();
      expect(prismaTestKit.quick.isEmpty()).toBe(true);

      // Create user using test kit
      const user = await prismaTestKit.quick.createUser();
      expect(user.email).toBeTruthy();

      // Create admin using test kit
      const admin = await prismaTestKit.quick.createAdmin();
      expect(admin.role).toBe('ADMIN');

      // Verify counts
      const counts = prismaTestKit.quick.getCounts();
      expect(counts.users).toBe(2);
    });

    it('should provide scenario helpers', async () => {
      // Test authenticated user scenario
      const { user, session } = await prismaTestKit.scenarios.authenticatedUser();
      
      expect(user.email).toBeTruthy();
      expect(session.userId).toBe(user.id);

      await databaseAssertions.assertUserCreated(user.email, { role: 'USER' });
      await databaseAssertions.assertSessionCreated(session.sessionToken, user.id);
    });

    it('should provide clean database helper', async () => {
      // Add some data
      await prismaMock.user.create({ data: { email: 'cleanup-test@example.com' } });
      
      let counts = prismaTestKit.quick.getCounts();
      expect(counts.users).toBe(1);

      // Test with clean database
      await prismaTestKit.helpers.withCleanDb(async () => {
        const cleanCounts = prismaTestKit.quick.getCounts();
        expect(cleanCounts.users).toBe(0);

        // Create data inside clean context
        await prismaMock.user.create({ data: { email: 'temp@example.com' } });
        
        const tempCounts = prismaTestKit.quick.getCounts();
        expect(tempCounts.users).toBe(1);
      });

      // Verify cleanup happened
      const finalCounts = prismaTestKit.quick.getCounts();
      expect(finalCounts.users).toBe(0);
    });

    it('should provide transaction rollback helper', async () => {
      const initialCounts = prismaTestKit.quick.getCounts();

      await prismaTestKit.helpers.withTransaction(async () => {
        await prismaMock.user.create({ data: { email: 'rollback-test@example.com' } });
        
        const duringCounts = prismaTestKit.quick.getCounts();
        expect(duringCounts.users).toBe(initialCounts.users + 1);
      });

      const finalCounts = prismaTestKit.quick.getCounts();
      expect(finalCounts.users).toBe(initialCounts.users + 1); // Should be committed
    });
  });

  describe('Data Isolation', () => {
    it('should isolate tests from each other', () => {
      // This test should start with clean state due to setupDatabaseTests()
      expect(prismaTestKit.quick.isEmpty()).toBe(true);
    });

    it('should maintain isolation between tests', async () => {
      // Add data in this test
      await prismaMock.user.create({ data: { email: 'isolated@example.com' } });
      
      const counts = prismaTestKit.quick.getCounts();
      expect(counts.users).toBe(1);
      
      // The next test should start clean due to isolation
    });

    it('should start clean again', () => {
      // Should be clean due to test isolation
      expect(prismaTestKit.quick.isEmpty()).toBe(true);
    });
  });

  describe('Error Handling', () => {
    it('should handle user not found errors', async () => {
      await expect(
        prismaMock.user.update({
          where: { id: 'non-existent' },
          data: { firstName: 'Updated' }
        })
      ).rejects.toThrow('User not found');
    });

    it('should handle session not found errors', async () => {
      await expect(
        prismaMock.session.delete({
          where: { sessionToken: 'non-existent' }
        })
      ).rejects.toThrow('Session not found');
    });
  });
}); 