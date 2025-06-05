import '@testing-library/jest-dom';

// Mock environment variables
process.env.NEXTAUTH_URL = 'http://localhost:3000';
process.env.NEXTAUTH_SECRET = 'test-secret';
process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';

// Mock fetch
global.fetch = jest.fn(() =>
  Promise.resolve({
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
  } as unknown as Response)
);

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

// Reset all mocks after each test
afterEach(() => {
  jest.clearAllMocks();
}); 