import '@testing-library/jest-dom';
import { setupMockServer } from './__mocks__/api/mock-server';
import { resetPrismaMocks } from './__mocks__/prisma';
import { resetMockData } from './__mocks__/prisma/client';

// Setup mock server for all tests
setupMockServer();

// Mock environment variables
process.env.NEXTAUTH_URL = 'http://localhost:3000';
process.env.NEXTAUTH_SECRET = 'test-secret';
process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';

// Custom mock server will handle most HTTP requests, but keep a fallback fetch mock for unhandled requests
global.fetch = jest.fn((url: string | URL | Request, init?: RequestInit) => {
  console.warn(`Unmocked fetch call to: ${url}`);
  return Promise.resolve({
    ok: true,
    status: 200,
    statusText: 'OK',
    headers: {
      get: (key: string) => {
        const headers: { [key: string]: string } = {
          'content-type': 'application/json',
          'set-cookie': 'session=abc123; HttpOnly; Secure; SameSite=Strict'
        };
        return headers[key.toLowerCase()] || null;
      }
    },
    json: () => Promise.resolve({}),
    text: () => Promise.resolve(''),
    redirected: false,
    type: 'basic',
    url: '',
    clone: jest.fn(),
    body: null,
    bodyUsed: false,
    arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
    blob: () => Promise.resolve(new Blob()),
    formData: () => Promise.resolve(new FormData()),
  } as unknown as Response);
});

// Mock NextAuth
jest.mock('next-auth/react', () => ({
  useSession: jest.fn(() => ({ data: null, status: 'unauthenticated' })),
  signIn: jest.fn(),
  signOut: jest.fn(),
  SessionProvider: ({ children }: { children: React.ReactNode }) => children,
}));

// Mock Next.js router
jest.mock('next/router', () => ({
  useRouter: jest.fn(() => ({
    push: jest.fn(),
    pathname: '/',
    query: {},
    asPath: '/',
  })),
}));

// Mock Next.js navigation
jest.mock('next/navigation', () => ({
  useRouter: jest.fn(() => ({
    push: jest.fn(),
    replace: jest.fn(),
    back: jest.fn(),
    forward: jest.fn(),
    refresh: jest.fn(),
    pathname: '/',
    query: {},
    asPath: '/',
  })),
  usePathname: jest.fn(() => '/'),
  useSearchParams: jest.fn(() => new URLSearchParams()),
}));

// Mock Next.js server components
jest.mock('next/server', () => ({
  NextRequest: jest.fn().mockImplementation(() => ({
    url: 'http://localhost:3000',
    method: 'GET',
    headers: new Map(),
    nextUrl: { pathname: '/', search: '', searchParams: new URLSearchParams() },
  })),
  NextResponse: {
    json: jest.fn((data) => ({ json: () => Promise.resolve(data) })),
    redirect: jest.fn(),
    next: jest.fn(),
  },
}));

// Mock crypto for Node.js environment
global.crypto = {
  randomUUID: () => 'test-uuid-' + Math.random().toString(36).substr(2, 9),
  getRandomValues: (arr: any) => {
    for (let i = 0; i < arr.length; i++) {
      arr[i] = Math.floor(Math.random() * 256);
    }
    return arr;
  },
} as any;

// Suppress console warnings for tests
const originalConsoleWarn = console.warn;
const originalConsoleError = console.error;

beforeAll(async () => {
  // Setup custom Jest matchers
  try {
    const { setupCustomMatchers } = await import('./utils/custom-matchers');
    setupCustomMatchers();
  } catch (error) {
    // Custom matchers are optional, continue if they fail to load
    console.warn('Failed to load custom matchers:', error);
  }
  
  console.warn = jest.fn();
  console.error = jest.fn();
});

afterAll(() => {
  console.warn = originalConsoleWarn;
  console.error = originalConsoleError;
});

// Reset all mocks after each test
afterEach(() => {
  jest.clearAllMocks();
  resetPrismaMocks();
  resetMockData();
  
  // Reset NextAuth mocks if available
  try {
    const { resetNextAuthMocks } = require('./__mocks__/nextauth/provider');
    resetNextAuthMocks();
  } catch (error) {
    // NextAuth mocks are optional
  }
});

// Global test utilities available in all test files
declare global {
  namespace globalThis {
    var testUtils: {
      delay: (ms: number) => Promise<void>;
      waitForUpdate: () => Promise<void>;
      flushPromises: () => Promise<void>;
    };
  }
}

// Add global test utilities
globalThis.testUtils = {
  delay: (ms: number) => new Promise(resolve => setTimeout(resolve, ms)),
  waitForUpdate: () => new Promise(resolve => setTimeout(resolve, 0)),
  flushPromises: () => new Promise(resolve => setTimeout(resolve, 0))
}; 