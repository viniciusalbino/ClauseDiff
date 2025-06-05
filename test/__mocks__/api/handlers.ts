/**
 * API Mock Handlers
 * 
 * Mock handlers for all API endpoints in the ClauseDiff application.
 * These mocks allow testing without making real HTTP requests.
 */

import { http, HttpResponse } from './mock-server';
import { generateMockUser, generateMockAuditLog } from './utils';

// Mock data for consistent testing
const mockUser = generateMockUser();
const mockAdminUser = generateMockUser({ role: 'admin' });
const mockAuditLogs = Array.from({ length: 20 }, () => generateMockAuditLog());

// Default handlers for all API endpoints
export const handlers = [
  // Authentication endpoints
  http.get('/api/auth/session', (req) => {
    return HttpResponse.json({
      user: mockUser,
      expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
    });
  }),

  http.post('/api/auth/signin', async (req) => {
    const body = await req.json();
    return HttpResponse.json({
      success: true,
      user: mockUser,
      token: 'mock-jwt-token'
    });
  }),

  http.post('/api/auth/signup', async (req) => {
    const body = await req.json();
    return HttpResponse.json({
      success: true,
      user: { ...mockUser, ...body },
      token: 'mock-jwt-token'
    });
  }),

  http.post('/api/auth/signout', (req) => {
    return HttpResponse.json({
      success: true,
      message: 'Successfully signed out'
    });
  }),

  http.post('/api/auth/callback/credentials', async (req) => {
    const body = await req.json();
    
    if (body.email === 'test@example.com' && body.password === 'password') {
      return HttpResponse.json({
        success: true,
        user: mockUser
      });
    }
    
    return HttpResponse.json(
      { error: 'Invalid credentials' },
      { status: 401 }
    );
  }),

  http.post('/api/auth/callback/google', (req) => {
    return HttpResponse.json({
      success: true,
      user: mockUser
    });
  }),

  http.post('/api/auth/forgot-password', async (req) => {
    const body = await req.json();
    return HttpResponse.json({
      success: true,
      message: 'Password reset email sent'
    });
  }),

  http.post('/api/auth/reset-password', async (req) => {
    const body = await req.json();
    return HttpResponse.json({
      success: true,
      message: 'Password reset successfully'
    });
  }),

  // User endpoints
  http.get('/api/user/profile', (req) => {
    return HttpResponse.json({
      success: true,
      user: mockUser
    });
  }),

  http.put('/api/user/profile', async (req) => {
    const body = await req.json();
    return HttpResponse.json({
      success: true,
      user: { ...mockUser, ...body }
    });
  }),

  // Admin endpoints
  http.get('/api/admin/users', (req) => {
    const url = new URL(req.url);
    const limit = parseInt(url.searchParams.get('limit') || '10');
    const page = parseInt(url.searchParams.get('page') || '1');
    
    const users = Array.from({ length: limit }, (_, i) => ({
      ...mockUser,
      id: `user-${i + 1}`,
      email: `user${i + 1}@example.com`,
      name: `User ${i + 1}`
    }));

    return HttpResponse.json({
      success: true,
      users,
      pagination: {
        page,
        limit,
        total: 50,
        pages: Math.ceil(50 / limit)
      }
    });
  }),

  http.get('/api/admin/users/:id', (req) => {
    const { id } = req.params;
    return HttpResponse.json({
      success: true,
      user: { ...mockUser, id }
    });
  }),

  http.put('/api/admin/users/:id', async (req) => {
    const { id } = req.params;
    const body = await req.json();
    return HttpResponse.json({
      success: true,
      user: { ...mockUser, id, ...body }
    });
  }),

  http.delete('/api/admin/users/:id', (req) => {
    const { id } = req.params;
    return HttpResponse.json({
      success: true,
      message: `User ${id} deleted successfully`
    });
  }),

  // Audit log endpoints
  http.get('/api/admin/audit', (req) => {
    const url = new URL(req.url);
    const limit = parseInt(url.searchParams.get('limit') || '10');
    const page = parseInt(url.searchParams.get('page') || '1');

    return HttpResponse.json({
      success: true,
      auditLogs: mockAuditLogs.slice(0, limit),
      pagination: {
        page,
        limit,
        total: mockAuditLogs.length,
        pages: Math.ceil(mockAuditLogs.length / limit)
      }
    });
  }),

  // File processing endpoints
  http.post('/api/upload', async (req) => {
    const formData = await req.formData();
    const file = formData.get('file') as File;
    
    if (!file) {
      return HttpResponse.json(
        { error: 'No file provided' },
        { status: 400 }
      );
    }

    return HttpResponse.json({
      success: true,
      uploadId: 'test-upload-id',
      fileName: file.name,
      fileSize: file.size,
      mimeType: file.type
    });
  }),

  http.post('/api/compare', async (req) => {
    const body = await req.json();
    
    return HttpResponse.json({
      success: true,
      comparisonId: 'test-comparison-id',
      differences: [
        {
          type: 'insertion',
          content: 'This text was added',
          position: { start: 10, end: 30 }
        },
        {
          type: 'deletion',
          content: 'This text was removed',
          position: { start: 50, end: 75 }
        },
        {
          type: 'modification',
          oldContent: 'Original text',
          newContent: 'Modified text',
          position: { start: 100, end: 125 }
        }
      ],
      summary: {
        insertions: 1,
        deletions: 1,
        modifications: 1,
        totalChanges: 3
      }
    });
  }),

  // Export endpoints
  http.get('/api/export/:comparisonId', (req) => {
    const { comparisonId } = req.params;
    return HttpResponse.json({
      success: true,
      downloadUrl: `/downloads/${comparisonId}.pdf`,
      format: 'pdf',
      fileName: `comparison-${comparisonId}.pdf`
    });
  }),

  // Error scenarios for testing
  http.post('/api/test/error', () => {
    return HttpResponse.json(
      { error: 'Test error', message: 'This is a test error for testing error handling' },
      { status: 500 }
    );
  }),

  http.post('/api/test/unauthorized', () => {
    return HttpResponse.json(
      { error: 'Unauthorized', message: 'Authentication required' },
      { status: 401 }
    );
  }),

  http.post('/api/test/forbidden', () => {
    return HttpResponse.json(
      { error: 'Forbidden', message: 'Insufficient permissions' },
      { status: 403 }
    );
  }),

  // Rate limiting test endpoint
  http.post('/api/test/rate-limit', () => {
    return HttpResponse.json(
      { error: 'Rate limit exceeded', message: 'Too many requests' },
      { status: 429 }
    );
  })
];

// Handlers for different user roles
export const adminHandlers = [
  http.get('/api/auth/session', () => {
    return HttpResponse.json({
      user: mockAdminUser,
      expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
    });
  })
];

// Error handlers for testing error scenarios
export const errorHandlers = [
  http.get('/api/auth/session', () => {
    return HttpResponse.json(
      { error: 'Session error' },
      { status: 500 }
    );
  }),

  http.post('/api/auth/callback/credentials', () => {
    return HttpResponse.json(
      { error: 'Invalid credentials' },
      { status: 401 }
    );
  })
];

export default handlers; 