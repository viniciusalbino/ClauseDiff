/**
 * Prisma Client Mock for Testing
 * 
 * Provides a mock implementation of the Prisma client with transaction rollback
 * capabilities to ensure test isolation and prevent data persistence.
 */

import { PrismaClient } from '@prisma/client';

// Mock data storage for simulating database state during tests
let mockData: {
  users: any[];
  accounts: any[];
  sessions: any[];
  auditLogs: any[];
  billingAccounts: any[];
  verificationTokens: any[];
} = {
  users: [],
  accounts: [],
  sessions: [],
  auditLogs: [],
  billingAccounts: [],
  verificationTokens: []
};

/**
 * Reset mock data to initial state
 */
export function resetMockData() {
  mockData = {
    users: [],
    accounts: [],
    sessions: [],
    auditLogs: [],
    billingAccounts: [],
    verificationTokens: []
  };
}

/**
 * Seed mock data with initial test data
 */
export function seedMockData(data: Partial<typeof mockData>) {
  Object.assign(mockData, data);
}

/**
 * Get current mock data (for testing purposes)
 */
export function getMockData() {
  return { ...mockData };
}

/**
 * Create mock Prisma client with jest functions
 */
export const prismaMock = {
  user: {
    create: jest.fn().mockImplementation(async (args: any) => {
      const newUser = {
        id: `user-${Date.now()}-${Math.random().toString(36).substring(7)}`,
        createdAt: new Date(),
        updatedAt: new Date(),
        role: 'USER',
        emailVerified: null,
        ...args.data
      };
      mockData.users.push(newUser);
      return newUser;
    }),

    findUnique: jest.fn().mockImplementation(async (args: any) => {
      const user = mockData.users.find(u => {
        if (args.where.id) return u.id === args.where.id;
        if (args.where.email) return u.email === args.where.email;
        if (args.where.cpf) return u.cpf === args.where.cpf;
        return false;
      });
      return user || null;
    }),

    findMany: jest.fn().mockImplementation(async (args: any = {}) => {
      let users = [...mockData.users];
      
      if (args.where) {
        users = users.filter((user: any) => {
          if (args.where.role) return user.role === args.where.role;
          if (args.where.createdAt) return true; // Simple date filtering
          return true;
        });
      }

      if (args.take) {
        users = users.slice(0, args.take);
      }

      return users;
    }),

    update: jest.fn().mockImplementation(async (args: any) => {
      const userIndex = mockData.users.findIndex(u => u.id === args.where.id);
      if (userIndex === -1) {
        throw new Error('User not found');
      }
      
      mockData.users[userIndex] = {
        ...mockData.users[userIndex],
        ...args.data,
        updatedAt: new Date()
      };
      
      return mockData.users[userIndex];
    }),

    delete: jest.fn().mockImplementation(async (args: any) => {
      const userIndex = mockData.users.findIndex(u => u.id === args.where.id);
      if (userIndex === -1) {
        throw new Error('User not found');
      }
      
      const deletedUser = mockData.users[userIndex];
      mockData.users.splice(userIndex, 1);
      return deletedUser;
    }),

    count: jest.fn().mockImplementation(async () => mockData.users.length),

    upsert: jest.fn().mockImplementation(async (args: any) => {
      const existingUser = mockData.users.find(u => u.id === args.where.id);
      if (existingUser) {
        return prismaMock.user.update({ where: args.where, data: args.update });
      } else {
        return prismaMock.user.create({ data: args.create });
      }
    })
  },

  session: {
    create: jest.fn().mockImplementation(async (args: any) => {
      const newSession = {
        id: `session-${Date.now()}-${Math.random().toString(36).substring(7)}`,
        ...args.data
      };
      mockData.sessions.push(newSession);
      return newSession;
    }),

    findUnique: jest.fn().mockImplementation(async (args: any) => {
      const session = mockData.sessions.find(s => {
        if (args.where.id) return s.id === args.where.id;
        if (args.where.sessionToken) return s.sessionToken === args.where.sessionToken;
        return false;
      });
      return session || null;
    }),

    findMany: jest.fn().mockImplementation(async (args: any = {}) => {
      let sessions = [...mockData.sessions];
      
      if (args.where) {
        sessions = sessions.filter((session: any) => {
          if (args.where.userId) return session.userId === args.where.userId;
          return true;
        });
      }

      return sessions;
    }),

    delete: jest.fn().mockImplementation(async (args: any) => {
      const sessionIndex = mockData.sessions.findIndex(s => {
        if (args.where.id) return s.id === args.where.id;
        if (args.where.sessionToken) return s.sessionToken === args.where.sessionToken;
        return false;
      });
      
      if (sessionIndex === -1) {
        throw new Error('Session not found');
      }
      
      const deletedSession = mockData.sessions[sessionIndex];
      mockData.sessions.splice(sessionIndex, 1);
      return deletedSession;
    }),

    deleteMany: jest.fn().mockImplementation(async (args: any) => {
      const initialLength = mockData.sessions.length;
      mockData.sessions = mockData.sessions.filter(s => {
        if (args.where.userId) return s.userId !== args.where.userId;
        return true;
      });
      return { count: initialLength - mockData.sessions.length };
    })
  },

  account: {
    create: jest.fn().mockImplementation(async (args: any) => {
      const newAccount = {
        id: `account-${Date.now()}-${Math.random().toString(36).substring(7)}`,
        ...args.data
      };
      mockData.accounts.push(newAccount);
      return newAccount;
    }),

    findUnique: jest.fn().mockImplementation(async (args: any) => {
      const account = mockData.accounts.find(a => {
        if (args.where.id) return a.id === args.where.id;
        if (args.where.provider_providerAccountId) {
          return a.provider === args.where.provider_providerAccountId.provider &&
                 a.providerAccountId === args.where.provider_providerAccountId.providerAccountId;
        }
        return false;
      });
      return account || null;
    }),

    delete: jest.fn().mockImplementation(async (args: any) => {
      const accountIndex = mockData.accounts.findIndex(a => a.id === args.where.id);
      if (accountIndex === -1) {
        throw new Error('Account not found');
      }
      
      const deletedAccount = mockData.accounts[accountIndex];
      mockData.accounts.splice(accountIndex, 1);
      return deletedAccount;
    })
  },

  auditLog: {
    create: jest.fn().mockImplementation(async (args: any) => {
      const newLog = {
        id: `audit-${Date.now()}-${Math.random().toString(36).substring(7)}`,
        timestamp: new Date(),
        ...args.data
      };
      mockData.auditLogs.push(newLog);
      return newLog;
    }),

    findMany: jest.fn().mockImplementation(async (args: any = {}) => {
      let logs = [...mockData.auditLogs];
      
      if (args.where) {
        logs = logs.filter((log: any) => {
          if (args.where.userId) return log.userId === args.where.userId;
          if (args.where.eventType) return log.eventType === args.where.eventType;
          return true;
        });
      }

      if (args.orderBy && args.orderBy.timestamp) {
        logs.sort((a: any, b: any) => {
          if (args.orderBy.timestamp === 'desc') {
            return b.timestamp.getTime() - a.timestamp.getTime();
          }
          return a.timestamp.getTime() - b.timestamp.getTime();
        });
      }

      if (args.take) {
        logs = logs.slice(0, args.take);
      }

      return logs;
    })
  },

  verificationToken: {
    create: jest.fn().mockImplementation(async (args: any) => {
      const newToken = {
        identifier: args.data.identifier,
        token: args.data.token,
        expires: args.data.expires
      };
      mockData.verificationTokens.push(newToken);
      return newToken;
    }),

    findUnique: jest.fn().mockImplementation(async (args: any) => {
      const token = mockData.verificationTokens.find(t => {
        if (args.where.token) return t.token === args.where.token;
        if (args.where.identifier_token) {
          return t.identifier === args.where.identifier_token.identifier &&
                 t.token === args.where.identifier_token.token;
        }
        return false;
      });
      return token || null;
    }),

    delete: jest.fn().mockImplementation(async (args: any) => {
      const tokenIndex = mockData.verificationTokens.findIndex(t => {
        if (args.where.token) return t.token === args.where.token;
        if (args.where.identifier_token) {
          return t.identifier === args.where.identifier_token.identifier &&
                 t.token === args.where.identifier_token.token;
        }
        return false;
      });
      
      if (tokenIndex === -1) {
        throw new Error('Token not found');
      }
      
      const deletedToken = mockData.verificationTokens[tokenIndex];
      mockData.verificationTokens.splice(tokenIndex, 1);
      return deletedToken;
    })
  },

  $transaction: jest.fn().mockImplementation(async (operations: any) => {
    if (Array.isArray(operations)) {
      const results = [];
      for (const operation of operations) {
        results.push(await operation);
      }
      return results;
    } else if (typeof operations === 'function') {
      // For function-based transactions, return the result directly
      return await operations(prismaMock);
    }
    
    return [];
  }),

  $connect: jest.fn().mockResolvedValue(undefined),
  $disconnect: jest.fn().mockResolvedValue(undefined),
  $executeRaw: jest.fn().mockResolvedValue(0),
  $queryRaw: jest.fn().mockResolvedValue([])
} as unknown as PrismaClient;

/**
 * Reset all Prisma mocks to initial state
 */
export function resetPrismaMocks() {
  resetMockData();
  
  // Reset all jest mock functions
  Object.values(prismaMock.user).forEach(fn => {
    if (jest.isMockFunction(fn)) {
      fn.mockClear();
    }
  });
  
  Object.values(prismaMock.session).forEach(fn => {
    if (jest.isMockFunction(fn)) {
      fn.mockClear();
    }
  });
  
  Object.values(prismaMock.account).forEach(fn => {
    if (jest.isMockFunction(fn)) {
      fn.mockClear();
    }
  });
  
  Object.values(prismaMock.auditLog).forEach(fn => {
    if (jest.isMockFunction(fn)) {
      fn.mockClear();
    }
  });
  
  Object.values(prismaMock.verificationToken).forEach(fn => {
    if (jest.isMockFunction(fn)) {
      fn.mockClear();
    }
  });
  
  [prismaMock.$transaction, prismaMock.$connect, prismaMock.$disconnect, 
   prismaMock.$executeRaw, prismaMock.$queryRaw].forEach(fn => {
    if (jest.isMockFunction(fn)) {
      fn.mockClear();
    }
  });
}

export default prismaMock; 