module.exports = {
  preset: 'ts-jest/presets/default-esm',
  testEnvironment: 'jsdom',
  extensionsToTreatAsEsm: ['.ts', '.tsx'],
  transform: {
    '^.+\\.(ts|tsx)$': ['ts-jest', { 
      useESM: true,
      tsconfig: {
        jsx: 'react-jsx'
      }
    }],
    '^.+\\.(js|jsx)$': ['babel-jest']
  },
  moduleNameMapper: {
    // Domain sublayer aliases (most specific first)
    '^@domain/entities/(.*)$': '<rootDir>/src/domain/entities/$1',
    '^@domain/repositories/(.*)$': '<rootDir>/src/domain/repositories/$1',
    '^@domain/services/(.*)$': '<rootDir>/src/domain/services/$1',
    
    // Application sublayer aliases
    '^@application/dto/(.*)$': '<rootDir>/src/application/dto/$1',
    '^@application/use-cases/(.*)$': '<rootDir>/src/application/use-cases/$1',
    '^@application/services/(.*)$': '<rootDir>/src/application/services/$1',
    
    // Infrastructure sublayer aliases
    '^@infrastructure/database/(.*)$': '<rootDir>/src/infrastructure/database/$1',
    '^@infrastructure/external-services/(.*)$': '<rootDir>/src/infrastructure/external-services/$1',
    '^@infrastructure/storage/(.*)$': '<rootDir>/src/infrastructure/storage/$1',
    '^@infrastructure/repositories/(.*)$': '<rootDir>/src/infrastructure/repositories/$1',
    
    // Presentation sublayer aliases
    '^@presentation/components/(.*)$': '<rootDir>/src/presentation/components/$1',
    '^@presentation/hooks/(.*)$': '<rootDir>/src/presentation/hooks/$1',
    '^@presentation/layouts/(.*)$': '<rootDir>/src/presentation/layouts/$1',
    '^@presentation/providers/(.*)$': '<rootDir>/src/presentation/providers/$1',
    
    // Domain-Driven Design layer aliases (general)
    '^@domain/(.*)$': '<rootDir>/src/domain/$1',
    '^@application/(.*)$': '<rootDir>/src/application/$1',
    '^@infrastructure/(.*)$': '<rootDir>/src/infrastructure/$1',
    '^@presentation/(.*)$': '<rootDir>/src/presentation/$1',
    
    // Specific source aliases
    '^@components/(.*)$': '<rootDir>/src/components/$1',
    '^@lib/(.*)$': '<rootDir>/src/lib/$1',
    '^@hooks/(.*)$': '<rootDir>/src/hooks/$1',
    '^@utils/(.*)$': '<rootDir>/src/utils/$1',
    '^@services/(.*)$': '<rootDir>/src/services/$1',
    
    // Test utilities aliases (specific first)
    '^@test-utils$': '<rootDir>/test/utils/index',
    '^@test-mocks/(.*)$': '<rootDir>/test/__mocks__/$1',
    '^@test/(.*)$': '<rootDir>/test/$1',
    
    // General source alias (most general last)
    '^@/(.*)$': '<rootDir>/src/$1',
    
    // Mock libraries
    '^jose$': '<rootDir>/test/__mocks__/jose.ts',
  },
  testPathIgnorePatterns: ['/node_modules/', '/.next/'],
  collectCoverage: true,
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  collectCoverageFrom: [
    'src/**/*.{ts,tsx}',
    '!src/**/*.d.ts',
    '!src/index.tsx',
    '!src/App.tsx',
    '!src/presentation/**/*.tsx'
  ],
  coverageThreshold: {
    global: {
      statements: 10,
      branches: 10,
      functions: 10,
      lines: 10,
    },
  },
  setupFilesAfterEnv: ['<rootDir>/test/setup.ts'],
  setupFiles: ['<rootDir>/test/polyfills.ts'],
  transformIgnorePatterns: [
    'node_modules/(?!(jose|openid-client|next-auth|@next-auth|@panva|oauth4webapi|preact|uuid)/)'
  ],
  testTimeout: 10000,
}; 