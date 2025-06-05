/**
 * Custom Mock Server Implementation
 * 
 * A lightweight mock server that provides API mocking functionality
 * for testing without external dependencies.
 */

// Mock HTTP methods and response types
export const http = {
  get: (path: string, handler: (req: MockRequest) => MockResponse | Promise<MockResponse>) => ({ method: 'GET', path, handler }),
  post: (path: string, handler: (req: MockRequest) => MockResponse | Promise<MockResponse>) => ({ method: 'POST', path, handler }),
  put: (path: string, handler: (req: MockRequest) => MockResponse | Promise<MockResponse>) => ({ method: 'PUT', path, handler }),
  delete: (path: string, handler: (req: MockRequest) => MockResponse | Promise<MockResponse>) => ({ method: 'DELETE', path, handler }),
  patch: (path: string, handler: (req: MockRequest) => MockResponse | Promise<MockResponse>) => ({ method: 'PATCH', path, handler }),
  options: (path: string, handler: (req: MockRequest) => MockResponse | Promise<MockResponse>) => ({ method: 'OPTIONS', path, handler }),
  head: (path: string, handler: (req: MockRequest) => MockResponse | Promise<MockResponse>) => ({ method: 'HEAD', path, handler }),
  all: (path: string, handler: (req: MockRequest) => MockResponse | Promise<MockResponse>) => ({ method: 'ALL', path, handler }),
};

export const HttpResponse = {
  json: (data: any, init?: { status?: number; headers?: Record<string, string> }) => {
    return new Response(JSON.stringify(data), {
      status: init?.status || 200,
      headers: {
        'Content-Type': 'application/json',
        ...init?.headers
      }
    });
  },
  
  text: (text: string, init?: { status?: number; headers?: Record<string, string> }) => {
    return new Response(text, {
      status: init?.status || 200,
      headers: {
        'Content-Type': 'text/plain',
        ...init?.headers
      }
    });
  },
  
  error: () => {
    return new Response(null, { status: 500, statusText: 'Internal Server Error' });
  }
};

interface MockRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  params: Record<string, string>;
  json: () => Promise<any>;
  text: () => Promise<string>;
  formData: () => Promise<FormData>;
}

interface MockResponse extends Response {}

interface MockHandler {
  method: string;
  path: string;
  handler: (req: MockRequest) => MockResponse | Promise<MockResponse>;
}

class MockServer {
  private handlers: MockHandler[] = [];
  private isListening = false;

  listen(options?: { onUnhandledRequest?: string }) {
    this.isListening = true;
    console.log('Mock server started');
  }

  close() {
    this.isListening = false;
    this.handlers = [];
    console.log('Mock server closed');
  }

  resetHandlers() {
    this.handlers = [];
  }

  use(...handlers: MockHandler[]) {
    this.handlers.push(...handlers);
  }

  // Helper method to find matching handler
  findHandler(method: string, url: string): MockHandler | undefined {
    return this.handlers.find(handler => {
      if (handler.method !== 'ALL' && handler.method !== method) {
        return false;
      }
      
      // Simple path matching - can be enhanced for parameters
      const pathPattern = handler.path.replace(/:[^/]+/g, '[^/]+');
      const regex = new RegExp(`^${pathPattern}$`);
      return regex.test(url);
    });
  }

  // Mock fetch implementation
  mockFetch = jest.fn(async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const urlString = typeof url === 'string' ? url : url.toString();
    const method = init?.method || 'GET';
    
    const handler = this.findHandler(method, urlString);
    
    if (handler) {
      // Extract path parameters
      const params: Record<string, string> = {};
      const pathParts = handler.path.split('/');
      const urlParts = urlString.split('/');
      
      pathParts.forEach((part, index) => {
        if (part.startsWith(':')) {
          const paramName = part.slice(1);
          params[paramName] = urlParts[index] || '';
        }
      });

      const mockRequest: MockRequest = {
        url: urlString,
        method,
        headers: (init?.headers as Record<string, string>) || {},
        params,
        json: async () => {
          if (init?.body) {
            return typeof init.body === 'string' ? JSON.parse(init.body) : init.body;
          }
          return {};
        },
        text: async () => {
          return init?.body?.toString() || '';
        },
        formData: async () => {
          return init?.body as FormData || new FormData();
        }
      };

      return await handler.handler(mockRequest);
    }

    // Default response for unhandled requests
    console.warn(`Unhandled request: ${method} ${urlString}`);
    return new Response(JSON.stringify({}), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  });
}

// Create singleton server instance
export const server = new MockServer();

// Helper functions for test setup
export const setupMockServer = () => {
  beforeAll(() => {
    // Replace global fetch with our mock
    global.fetch = server.mockFetch;
    server.listen({ onUnhandledRequest: 'error' });
  });

  afterEach(() => {
    server.resetHandlers();
  });

  afterAll(() => {
    server.close();
    // Restore original fetch if needed
    jest.restoreAllMocks();
  });
};

export default server; 