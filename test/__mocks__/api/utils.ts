/**
 * Mock API Test Utilities
 * 
 * Utility functions for common mock test scenarios, data generation,
 * and test helpers for API mocking.
 */

import { http, HttpResponse, server } from './mock-server';

// Data generators for dynamic test data
export const generateMockUser = (overrides: Partial<any> = {}) => ({
  id: `user-${Math.random().toString(36).substr(2, 9)}`,
  email: `test-${Math.random().toString(36).substr(2, 5)}@example.com`,
  firstName: 'Test',
  lastName: 'User',
  name: 'Test User',
  role: 'USER',
  emailVerified: new Date(),
  createdAt: new Date(),
  image: null,
  _count: {
    auditLogs: Math.floor(Math.random() * 10)
  },
  ...overrides
});

export const generateMockAuditLog = (overrides: Partial<any> = {}) => ({
  id: `audit-${Math.random().toString(36).substr(2, 9)}`,
  userId: 'test-user-id',
  action: 'USER_LOGIN',
  details: { ip: '127.0.0.1', userAgent: 'Test Browser' },
  timestamp: new Date(),
  ipAddress: '127.0.0.1',
  userAgent: 'Test Browser',
  ...overrides
});

// Mock response builders
export const createSuccessResponse = (data: any) => 
  HttpResponse.json({ success: true, ...data });

export const createErrorResponse = (error: string, message: string, status = 400) =>
  HttpResponse.json({ error, message }, { status });

export const createUnauthorizedResponse = (message = 'Authentication required') =>
  HttpResponse.json({ error: 'Unauthorized', message }, { status: 401 });

export const createForbiddenResponse = (message = 'Insufficient permissions') =>
  HttpResponse.json({ error: 'Forbidden', message }, { status: 403 });

export const createNotFoundResponse = (message = 'Resource not found') =>
  HttpResponse.json({ error: 'Not Found', message }, { status: 404 });

export const createServerErrorResponse = (message = 'Internal server error') =>
  HttpResponse.json({ error: 'Server Error', message }, { status: 500 });

// Test scenario helpers
export const mockSuccessfulLogin = (user = generateMockUser()) => {
  server.use(
    http.post('/api/auth/callback/credentials', () => createSuccessResponse({ user })),
    http.get('/api/auth/session', () => createSuccessResponse({ user }))
  );
};

export const mockFailedLogin = (error = 'Invalid credentials') => {
  server.use(
    http.post('/api/auth/callback/credentials', () => 
      createUnauthorizedResponse(error)
    )
  );
};

export const mockUserSession = (user = generateMockUser()) => {
  server.use(
    http.get('/api/auth/session', () => createSuccessResponse({ user }))
  );
};

export const mockNoSession = () => {
  server.use(
    http.get('/api/auth/session', () => 
      HttpResponse.json({ user: null })
    )
  );
};

export const mockAdminSession = () => {
  const adminUser = generateMockUser({ role: 'ADMIN', email: 'admin@example.com' });
  mockUserSession(adminUser);
};

export const mockApiError = (endpoint: string, method: 'GET' | 'POST' | 'PUT' | 'DELETE' = 'GET', status = 500) => {
  const httpMethod = method.toLowerCase() as keyof typeof http;
  server.use(
    http[httpMethod](endpoint, () => createServerErrorResponse())
  );
};

export const mockNetworkError = (endpoint: string, method: 'GET' | 'POST' | 'PUT' | 'DELETE' = 'GET') => {
  const httpMethod = method.toLowerCase() as keyof typeof http;
  server.use(
    http[httpMethod](endpoint, () => HttpResponse.error())
  );
};

export const mockSlowResponse = (
  endpoint: string, 
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' = 'GET',
  delay = 2000
) => {
  const httpMethod = method.toLowerCase() as keyof typeof http;
  server.use(
    http[httpMethod](endpoint, async () => {
      await new Promise(resolve => setTimeout(resolve, delay));
      return createSuccessResponse({ message: 'Slow response' });
    })
  );
};

// File upload helpers
export const mockFileUpload = (success = true) => {
  if (success) {
    server.use(
      http.post('/api/upload', () => createSuccessResponse({
        uploadId: 'test-upload-id',
        fileName: 'test-file.docx',
        fileSize: 1024,
        mimeType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
      }))
    );
  } else {
    server.use(
      http.post('/api/upload', () => createErrorResponse('Upload failed', 'File upload error'))
    );
  }
};

export const mockDocumentComparison = (success = true) => {
  if (success) {
    server.use(
      http.post('/api/compare', () => createSuccessResponse({
        comparisonId: 'test-comparison-id',
        differences: [
          {
            type: 'insertion',
            content: 'New text added',
            position: { start: 10, end: 25 }
          }
        ],
        summary: {
          insertions: 1,
          deletions: 0,
          modifications: 0,
          totalChanges: 1
        }
      }))
    );
  } else {
    server.use(
      http.post('/api/compare', () => createErrorResponse('Comparison failed', 'Document comparison error'))
    );
  }
};

// Permission-based helpers
export const mockPermissionDenied = (endpoint: string, method: 'GET' | 'POST' | 'PUT' | 'DELETE' = 'GET') => {
  const httpMethod = method.toLowerCase() as keyof typeof http;
  server.use(
    http[httpMethod](endpoint, () => createForbiddenResponse())
  );
};

// Pagination helpers
export const mockPaginatedResponse = (
  data: any[], 
  page = 1, 
  limit = 10, 
  total?: number
) => {
  const totalCount = total || data.length;
  const startIndex = (page - 1) * limit;
  const endIndex = startIndex + limit;
  const paginatedData = data.slice(startIndex, endIndex);

  return createSuccessResponse({
    data: paginatedData,
    pagination: {
      page,
      limit,
      total: totalCount,
      pages: Math.ceil(totalCount / limit)
    }
  });
};

// Rate limiting helpers
export const mockRateLimit = (endpoint: string, method: 'GET' | 'POST' | 'PUT' | 'DELETE' = 'GET') => {
  const httpMethod = method.toLowerCase() as keyof typeof http;
  server.use(
    http[httpMethod](endpoint, () => 
      HttpResponse.json(
        { error: 'Rate limit exceeded', message: 'Too many requests' },
        { 
          status: 429,
          headers: {
            'Retry-After': '60',
            'X-RateLimit-Limit': '100',
            'X-RateLimit-Remaining': '0',
            'X-RateLimit-Reset': (Date.now() + 60000).toString()
          }
        }
      )
    )
  );
};

// CSRF helpers
export const mockCSRFError = (endpoint: string, method: 'POST' | 'PUT' | 'DELETE' = 'POST') => {
  const httpMethod = method.toLowerCase() as keyof typeof http;
  server.use(
    http[httpMethod](endpoint, () => 
      HttpResponse.json(
        { error: 'CSRF validation failed', message: 'Invalid or missing CSRF token' },
        { status: 403 }
      )
    )
  );
};

// Test data cleanup
export const resetTestData = () => {
  server.resetHandlers();
};

// Assert helpers for tests
export const expectApiCall = async (endpoint: string, method = 'GET') => {
  // This would need to be implemented based on how you want to verify API calls
  // For now, it's a placeholder for future implementation
  return Promise.resolve(true);
}; 