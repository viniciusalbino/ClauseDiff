/**
 * Prisma Database Seeding Utilities
 * 
 * Provides utilities for seeding the mock database with consistent
 * test data for various testing scenarios.
 */

import { prismaMock, seedMockData } from './client';

/**
 * Default test user data
 */
export const defaultUsers = {
  testUser: {
    id: 'user-test-1',
    email: 'test@example.com',
    firstName: 'Test',
    lastName: 'User',
    role: 'USER' as const,
    createdAt: new Date('2024-01-01T00:00:00.000Z'),
    updatedAt: new Date('2024-01-01T00:00:00.000Z'),
    emailVerified: new Date('2024-01-01T00:00:00.000Z'),
    name: 'Test User',
    image: null,
    password: null,
    city: null,
    state: null,
    cpf: null,
    resetToken: null,
    resetTokenExpiry: null
  },

  adminUser: {
    id: 'user-admin-1',
    email: 'admin@example.com',
    firstName: 'Admin',
    lastName: 'User',
    role: 'ADMIN' as const,
    createdAt: new Date('2024-01-01T00:00:00.000Z'),
    updatedAt: new Date('2024-01-01T00:00:00.000Z'),
    emailVerified: new Date('2024-01-01T00:00:00.000Z'),
    name: 'Admin User',
    image: null,
    password: null,
    city: null,
    state: null,
    cpf: null,
    resetToken: null,
    resetTokenExpiry: null
  },

  unverifiedUser: {
    id: 'user-unverified-1',
    email: 'unverified@example.com',
    firstName: 'Unverified',
    lastName: 'User',
    role: 'USER' as const,
    createdAt: new Date('2024-01-01T00:00:00.000Z'),
    updatedAt: new Date('2024-01-01T00:00:00.000Z'),
    emailVerified: null,
    name: 'Unverified User',
    image: null,
    password: null,
    city: null,
    state: null,
    cpf: null,
    resetToken: null,
    resetTokenExpiry: null
  }
};

/**
 * Default test session data
 */
export const defaultSessions = {
  testUserSession: {
    id: 'session-test-1',
    sessionToken: 'test-session-token-1',
    userId: 'user-test-1',
    expires: new Date('2024-12-31T23:59:59.999Z')
  },

  adminUserSession: {
    id: 'session-admin-1',
    sessionToken: 'admin-session-token-1',
    userId: 'user-admin-1',
    expires: new Date('2024-12-31T23:59:59.999Z')
  },

  expiredSession: {
    id: 'session-expired-1',
    sessionToken: 'expired-session-token-1',
    userId: 'user-test-1',
    expires: new Date('2023-01-01T00:00:00.000Z')
  }
};

/**
 * Default test account data (OAuth providers)
 */
export const defaultAccounts = {
  googleAccount: {
    id: 'account-google-1',
    userId: 'user-test-1',
    type: 'oauth',
    provider: 'google',
    providerAccountId: 'google-account-id-1',
    refresh_token: 'google-refresh-token',
    access_token: 'google-access-token',
    expires_at: Math.floor(Date.now() / 1000) + 3600,
    token_type: 'Bearer',
    scope: 'openid profile email',
    id_token: 'google-id-token',
    session_state: null
  },

  credentialsAccount: {
    id: 'account-credentials-1',
    userId: 'user-admin-1',
    type: 'credentials',
    provider: 'credentials',
    providerAccountId: 'credentials-account-id-1',
    refresh_token: null,
    access_token: null,
    expires_at: null,
    token_type: null,
    scope: null,
    id_token: null,
    session_state: null
  }
};

/**
 * Default test audit log data
 */
export const defaultAuditLogs = {
  loginEvent: {
    id: 'audit-login-1',
    userId: 'user-test-1',
    eventType: 'LOGIN',
    ip: '192.168.1.1',
    userAgent: 'Mozilla/5.0 (Test Browser)',
    timestamp: new Date('2024-01-01T12:00:00.000Z'),
    details: { provider: 'credentials' }
  },

  logoutEvent: {
    id: 'audit-logout-1',
    userId: 'user-test-1',
    eventType: 'LOGOUT',
    ip: '192.168.1.1',
    userAgent: 'Mozilla/5.0 (Test Browser)',
    timestamp: new Date('2024-01-01T12:30:00.000Z'),
    details: {}
  },

  adminAction: {
    id: 'audit-admin-1',
    userId: 'user-admin-1',
    eventType: 'ADMIN_ACTION',
    ip: '192.168.1.2',
    userAgent: 'Mozilla/5.0 (Admin Browser)',
    timestamp: new Date('2024-01-01T10:00:00.000Z'),
    details: { action: 'user_management', target: 'user-test-1' }
  }
};

/**
 * Default verification tokens
 */
export const defaultVerificationTokens = {
  emailVerification: {
    identifier: 'unverified@example.com',
    token: 'email-verification-token-1',
    expires: new Date('2024-12-31T23:59:59.999Z')
  },

  passwordReset: {
    identifier: 'test@example.com',
    token: 'password-reset-token-1',
    expires: new Date('2024-12-31T23:59:59.999Z')
  }
};

/**
 * Seeding functions for different scenarios
 */
export const seedScenarios = {
  // Basic scenario with authenticated user
  basicUser: () => {
    seedMockData({
      users: [defaultUsers.testUser],
      sessions: [defaultSessions.testUserSession],
      accounts: [defaultAccounts.googleAccount],
      auditLogs: [defaultAuditLogs.loginEvent],
      billingAccounts: [],
      verificationTokens: []
    });
  },

  // Admin scenario with admin user and permissions
  adminUser: () => {
    seedMockData({
      users: [defaultUsers.adminUser, defaultUsers.testUser],
      sessions: [defaultSessions.adminUserSession, defaultSessions.testUserSession],
      accounts: [defaultAccounts.credentialsAccount, defaultAccounts.googleAccount],
      auditLogs: [defaultAuditLogs.adminAction, defaultAuditLogs.loginEvent],
      billingAccounts: [],
      verificationTokens: []
    });
  },

  // Unverified user scenario
  unverifiedUser: () => {
    seedMockData({
      users: [defaultUsers.unverifiedUser],
      sessions: [],
      accounts: [],
      auditLogs: [],
      billingAccounts: [],
      verificationTokens: [defaultVerificationTokens.emailVerification]
    });
  },

  // Multiple users scenario
  multipleUsers: () => {
    seedMockData({
      users: [defaultUsers.testUser, defaultUsers.adminUser, defaultUsers.unverifiedUser],
      sessions: [defaultSessions.testUserSession, defaultSessions.adminUserSession],
      accounts: [defaultAccounts.googleAccount, defaultAccounts.credentialsAccount],
      auditLogs: [defaultAuditLogs.loginEvent, defaultAuditLogs.logoutEvent, defaultAuditLogs.adminAction],
      billingAccounts: [],
      verificationTokens: [defaultVerificationTokens.emailVerification, defaultVerificationTokens.passwordReset]
    });
  },

  // Session management scenario
  sessionManagement: () => {
    seedMockData({
      users: [defaultUsers.testUser],
      sessions: [defaultSessions.testUserSession, defaultSessions.expiredSession],
      accounts: [defaultAccounts.googleAccount],
      auditLogs: [defaultAuditLogs.loginEvent, defaultAuditLogs.logoutEvent],
      billingAccounts: [],
      verificationTokens: []
    });
  },

  // Empty database scenario
  empty: () => {
    seedMockData({
      users: [],
      sessions: [],
      accounts: [],
      auditLogs: [],
      billingAccounts: [],
      verificationTokens: []
    });
  }
};

/**
 * Dynamic data generators for creating test data on the fly
 */
export const dataGenerators = {
  // Generate a user with custom properties
  user: (overrides: Partial<typeof defaultUsers.testUser> = {}) => ({
    id: `user-${Date.now()}-${Math.random().toString(36).substring(7)}`,
    email: `user-${Math.random().toString(36).substring(7)}@example.com`,
    firstName: 'Generated',
    lastName: 'User',
    role: 'USER' as const,
    createdAt: new Date(),
    updatedAt: new Date(),
    emailVerified: new Date(),
    name: 'Generated User',
    image: null,
    password: null,
    city: null,
    state: null,
    cpf: null,
    resetToken: null,
    resetTokenExpiry: null,
    ...overrides
  }),

  // Generate a session with custom properties
  session: (userId: string, overrides: Partial<typeof defaultSessions.testUserSession> = {}) => ({
    id: `session-${Date.now()}-${Math.random().toString(36).substring(7)}`,
    sessionToken: `token-${Math.random().toString(36).substring(7)}`,
    userId,
    expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days from now
    ...overrides
  }),

  // Generate an audit log with custom properties
  auditLog: (userId: string, eventType: string, overrides: Partial<typeof defaultAuditLogs.loginEvent> = {}) => ({
    id: `audit-${Date.now()}-${Math.random().toString(36).substring(7)}`,
    userId,
    eventType,
    ip: '127.0.0.1',
    userAgent: 'Test User Agent',
    timestamp: new Date(),
    details: {},
    ...overrides
  }),

  // Generate an account with custom properties
  account: (userId: string, provider: string, overrides: Partial<typeof defaultAccounts.googleAccount> = {}) => ({
    id: `account-${Date.now()}-${Math.random().toString(36).substring(7)}`,
    userId,
    type: 'oauth',
    provider,
    providerAccountId: `${provider}-${Math.random().toString(36).substring(7)}`,
    refresh_token: `refresh-${Math.random().toString(36).substring(7)}`,
    access_token: `access-${Math.random().toString(36).substring(7)}`,
    expires_at: Math.floor(Date.now() / 1000) + 3600,
    token_type: 'Bearer',
    scope: 'openid profile email',
    id_token: `id-${Math.random().toString(36).substring(7)}`,
    session_state: null,
    ...overrides
  })
};

/**
 * Seed the database with custom data using Prisma operations
 */
export async function seedWithPrisma(scenario: keyof typeof seedScenarios | 'custom', customData?: any) {
  if (scenario === 'custom' && customData) {
    // Seed with custom data
    for (const user of customData.users || []) {
      await prismaMock.user.create({ data: user });
    }
    
    for (const session of customData.sessions || []) {
      await prismaMock.session.create({ data: session });
    }
    
    for (const account of customData.accounts || []) {
      await prismaMock.account.create({ data: account });
    }
    
    for (const auditLog of customData.auditLogs || []) {
      await prismaMock.auditLog.create({ data: auditLog });
    }
    
    for (const token of customData.verificationTokens || []) {
      await prismaMock.verificationToken.create({ data: token });
    }
  } else if (scenario in seedScenarios) {
    // Use predefined scenario
    seedScenarios[scenario as keyof typeof seedScenarios]();
  }
}

/**
 * Helper functions for common seeding operations
 */
export const seedHelpers = {
  // Create a complete user with session and account
  createUserWithSession: async (userOverrides = {}, sessionOverrides = {}) => {
    const user = dataGenerators.user(userOverrides);
    const session = dataGenerators.session(user.id, sessionOverrides);
    
    await prismaMock.user.create({ data: user });
    await prismaMock.session.create({ data: session });
    
    return { user, session };
  },

  // Create multiple users with different roles
  createUsersWithRoles: async (count: number = 3) => {
    const roles = ['USER', 'ADMIN'] as const;
    const users = [];
    
    for (let i = 0; i < count; i++) {
      const role = roles[i % roles.length] as 'USER' | 'ADMIN';
      const user = dataGenerators.user({
        role,
        email: `user${i + 1}@example.com`
      });
      
      await prismaMock.user.create({ data: user });
      users.push(user);
    }
    
    return users;
  },

  // Create audit trail for a user
  createAuditTrail: async (userId: string, eventCount: number = 5) => {
    const eventTypes = ['LOGIN', 'LOGOUT', 'PASSWORD_CHANGE', 'PROFILE_UPDATE', 'DOCUMENT_UPLOAD'];
    const logs = [];
    
    for (let i = 0; i < eventCount; i++) {
      const log = dataGenerators.auditLog(userId, eventTypes[i % eventTypes.length], {
        timestamp: new Date(Date.now() - i * 60 * 60 * 1000) // Spread over hours
      });
      
      await prismaMock.auditLog.create({ data: log });
      logs.push(log);
    }
    
    return logs;
  }
};

export default {
  seedScenarios,
  dataGenerators,
  seedWithPrisma,
  seedHelpers,
  defaultUsers,
  defaultSessions,
  defaultAccounts,
  defaultAuditLogs,
  defaultVerificationTokens
}; 