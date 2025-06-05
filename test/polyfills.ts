/**
 * Test Environment Polyfills
 * 
 * This file provides polyfills for APIs that are missing in the Node.js test environment
 * but are available in browsers, particularly for NextAuth and crypto operations.
 */

import { TextEncoder, TextDecoder } from 'util';

// Polyfill TextEncoder and TextDecoder for NextAuth/jose
(global as any).TextEncoder = TextEncoder;
(global as any).TextDecoder = TextDecoder;

// Polyfill crypto.subtle for NextAuth JWT operations
const cryptoSubtle = {
  digest: jest.fn().mockImplementation(async (algorithm: string, data: ArrayBuffer) => {
    // Mock implementation that returns a consistent hash
    const hash = new Uint8Array(32); // SHA-256 produces 32 bytes
    for (let i = 0; i < 32; i++) {
      hash[i] = Math.floor(Math.random() * 256);
    }
    return hash.buffer;
  }),
  
  sign: jest.fn().mockImplementation(async () => {
    // Mock signature
    const signature = new Uint8Array(64);
    for (let i = 0; i < 64; i++) {
      signature[i] = Math.floor(Math.random() * 256);
    }
    return signature.buffer;
  }),
  
  verify: jest.fn().mockResolvedValue(true),
  
  encrypt: jest.fn().mockImplementation(async () => {
    const encrypted = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
      encrypted[i] = Math.floor(Math.random() * 256);
    }
    return encrypted.buffer;
  }),
  
  decrypt: jest.fn().mockImplementation(async () => {
    const decrypted = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
      decrypted[i] = Math.floor(Math.random() * 256);
    }
    return decrypted.buffer;
  }),
  
  generateKey: jest.fn().mockResolvedValue({
    algorithm: { name: 'HMAC' },
    extractable: true,
    type: 'secret',
    usages: ['sign', 'verify']
  }),
  
  importKey: jest.fn().mockResolvedValue({
    algorithm: { name: 'HMAC' },
    extractable: true,
    type: 'secret',
    usages: ['sign', 'verify']
  }),
  
  exportKey: jest.fn().mockResolvedValue(new ArrayBuffer(32))
};

// Enhance the global crypto object
if (!global.crypto) {
  (global as any).crypto = {};
}

// Use Object.defineProperty to override readonly property
Object.defineProperty(global.crypto, 'subtle', {
  value: cryptoSubtle,
  writable: true,
  configurable: true
});

// Ensure getRandomValues is available
if (!global.crypto.getRandomValues) {
  global.crypto.getRandomValues = (arr: any) => {
    for (let i = 0; i < arr.length; i++) {
      arr[i] = Math.floor(Math.random() * 256);
    }
    return arr;
  };
}

// Ensure randomUUID is available
if (!global.crypto.randomUUID) {
  (global.crypto as any).randomUUID = () => {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  };
}

// Polyfill structuredClone for older Node.js versions
if (!(global as any).structuredClone) {
  (global as any).structuredClone = (obj: any) => JSON.parse(JSON.stringify(obj));
}

// Polyfill performance.timeOrigin and performance.now for timing measurements
if (!global.performance) {
  (global as any).performance = {
    timeOrigin: Date.now(),
    now: () => Date.now() - (global as any).performance.timeOrigin,
    mark: jest.fn(),
    measure: jest.fn(),
    clearMarks: jest.fn(),
    clearMeasures: jest.fn(),
    getEntriesByName: jest.fn().mockReturnValue([]),
    getEntriesByType: jest.fn().mockReturnValue([]),
    getEntries: jest.fn().mockReturnValue([])
  };
}

// Mock URL constructor for tests that need it
if (!(global as any).URL) {
  (global as any).URL = class MockURL {
    href: string;
    origin: string;
    protocol: string;
    hostname: string;
    port: string;
    pathname: string;
    search: string;
    hash: string;
    searchParams: URLSearchParams;

    constructor(url: string, base?: string) {
      this.href = url;
      this.origin = 'http://localhost:3000';
      this.protocol = 'http:';
      this.hostname = 'localhost';
      this.port = '3000';
      this.pathname = '/';
      this.search = '';
      this.hash = '';
      this.searchParams = new URLSearchParams();
    }

    toString() {
      return this.href;
    }
  };
}

// Add Response polyfill for custom mock server
if (typeof Response === 'undefined') {
  (global as any).Response = class Response {
    body: any;
    status: number;
    statusText: string;
    headers: Map<string, string>;
    ok: boolean;
    redirected = false;
    type = 'basic' as ResponseType;
    url = '';
    bodyUsed = false;

    constructor(body?: any, init?: ResponseInit) {
      this.body = body;
      this.status = init?.status || 200;
      this.statusText = init?.statusText || 'OK';
      this.headers = new Map(Object.entries(init?.headers || {}));
      this.ok = this.status >= 200 && this.status < 300;
    }

    async json() {
      return typeof this.body === 'string' ? JSON.parse(this.body) : this.body;
    }

    async text() {
      return typeof this.body === 'string' ? this.body : JSON.stringify(this.body);
    }

    async arrayBuffer() {
      return new ArrayBuffer(0);
    }

    async blob() {
      return new Blob();
    }

    async formData() {
      return new FormData();
    }

    clone() {
      return new Response(this.body, {
        status: this.status,
        statusText: this.statusText,
        headers: Object.fromEntries(this.headers)
      });
    }

    static json(data: any, init?: ResponseInit) {
      return new Response(JSON.stringify(data), {
        ...init,
        headers: {
          'Content-Type': 'application/json',
          ...init?.headers
        }
      });
    }

    static error() {
      return new Response(null, { status: 500, statusText: 'Internal Server Error' });
    }
  };
}

// Add BroadcastChannel polyfill for custom mock server
if (typeof BroadcastChannel === 'undefined') {
  (global as any).BroadcastChannel = class BroadcastChannel {
    name: string;
    onmessage: ((event: MessageEvent) => void) | null = null;
    onmessageerror: ((event: MessageEvent) => void) | null = null;

    constructor(name: string) {
      this.name = name;
    }

    postMessage(message: any) {
      // Mock implementation - in real environment this would broadcast to other contexts
    }

    close() {
      // Mock implementation
    }

    addEventListener(type: string, listener: EventListener) {
      // Mock implementation
    }

    removeEventListener(type: string, listener: EventListener) {
      // Mock implementation
    }

    dispatchEvent(event: Event) {
      return true;
    }
  };
} 