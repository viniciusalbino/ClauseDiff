/**
 * Custom Mock Server Integration Tests
 * 
 * Tests to verify that our custom mock server is correctly configured
 * and can mock API endpoints for testing.
 */

import { http, HttpResponse, server } from '../../__mocks__/api/mock-server';
import { 
  generateMockUser,
  createSuccessResponse
} from '../../__mocks__/api/utils';

describe('Mock Server Integration', () => {
  describe('Basic Server Setup', () => {
    test('should initialize mock server', () => {
      // Test that the mock server can be initialized
      expect(server).toBeDefined();
      expect(server.listen).toBeDefined();
      expect(server.close).toBeDefined();
      expect(server.resetHandlers).toBeDefined();
      expect(server.use).toBeDefined();
    });

    test('should handle server lifecycle', () => {
      // Test server lifecycle methods
      server.listen();
      server.resetHandlers();
      server.use();
      server.close();
      
      expect(true).toBe(true); // Basic test to ensure methods can be called
    });
  });

  describe('HTTP Handler Creation', () => {
    test('should create HTTP handlers', () => {
      const handler = http.get('/api/test', () => {
        return HttpResponse.json({ message: 'test' });
      });
      
      expect(handler).toBeDefined();
      expect(handler.method).toBe('GET');
      expect(handler.path).toBe('/api/test');
      server.use(handler);
    });

    test('should create different HTTP methods', () => {
      const getHandler = http.get('/api/test', () => HttpResponse.json({}));
      const postHandler = http.post('/api/test', () => HttpResponse.json({}));
      const putHandler = http.put('/api/test', () => HttpResponse.json({}));
      const deleteHandler = http.delete('/api/test', () => HttpResponse.json({}));
      
      expect(getHandler.method).toBe('GET');
      expect(postHandler.method).toBe('POST');
      expect(putHandler.method).toBe('PUT');
      expect(deleteHandler.method).toBe('DELETE');
      
      server.use(getHandler, postHandler, putHandler, deleteHandler);
    });
  });

  describe('API Request Mocking', () => {
    test('should mock GET requests', async () => {
      // Set up a handler
      server.use(
        http.get('/api/users', () => {
          return HttpResponse.json({ users: [{ id: 1, name: 'Test User' }] });
        })
      );

      // Make the request
      const response = await fetch('/api/users');
      const data = await response.json();

      expect(response.ok).toBe(true);
      expect(data.users).toHaveLength(1);
      expect(data.users[0].name).toBe('Test User');
    });

    test('should mock POST requests', async () => {
      server.use(
        http.post('/api/users', async (req) => {
          const body = await req.json();
          return HttpResponse.json({ 
            success: true, 
            user: { id: 2, ...body } 
          });
        })
      );

      const response = await fetch('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'New User', email: 'new@example.com' })
      });
      const data = await response.json();

      expect(response.ok).toBe(true);
      expect(data.success).toBe(true);
      expect(data.user.name).toBe('New User');
      expect(data.user.email).toBe('new@example.com');
    });

    test('should handle path parameters', async () => {
      server.use(
        http.get('/api/users/:id', (req) => {
          const { id } = req.params;
          return HttpResponse.json({ 
            user: { id, name: `User ${id}` } 
          });
        })
      );

      const response = await fetch('/api/users/123');
      const data = await response.json();

      expect(response.ok).toBe(true);
      expect(data.user.id).toBe('123');
      expect(data.user.name).toBe('User 123');
    });

    test('should handle error responses', async () => {
      server.use(
        http.get('/api/error', () => {
          return HttpResponse.json(
            { error: 'Something went wrong' },
            { status: 500 }
          );
        })
      );

      const response = await fetch('/api/error');
      const data = await response.json();

      expect(response.status).toBe(500);
      expect(data.error).toBe('Something went wrong');
    });
  });

  describe('Dynamic Handler Configuration', () => {
    test('should allow runtime handler changes', async () => {
      // First request should work normally
      let response = await fetch('/api/auth/session');
      expect(response.ok).toBe(true);
      
      // Override with error handler
      server.use(
        http.get('/api/auth/session', () => {
          return HttpResponse.json(
            { error: 'Session expired' },
            { status: 401 }
          );
        })
      );
      
      // Second request should return error
      response = await fetch('/api/auth/session');
      const data = await response.json();
      
      expect(response.status).toBe(401);
      expect(data.error).toBe('Session expired');
    });

    test('should reset handlers between tests', async () => {
      // This test should start with clean handlers
      const response = await fetch('/api/auth/session');
      expect(response.ok).toBe(true);
    });
  });

  describe('File Upload Mocking', () => {
    test('should mock file upload with custom handler', async () => {
      // Set up custom handler for this test
      server.use(
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
        })
      );

      const formData = new FormData();
      const file = new File(['test content'], 'test.docx', {
        type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
      });
      formData.append('file', file);
      
      const response = await fetch('/api/upload', {
        method: 'POST',
        body: formData
      });
      const data = await response.json();
      
      expect(response.ok).toBe(true);
      expect(data.fileName).toBe('test.docx');
      expect(data.uploadId).toBe('test-upload-id');
    });

    test('should handle missing file upload with custom handler', async () => {
      // Set up custom handler for this test
      server.use(
        http.post('/api/upload', async (req) => {
          const formData = await req.formData();
          const file = formData.get('file') as File;
          
          if (!file) {
            return HttpResponse.json(
              { error: 'No file provided' },
              { status: 400 }
            );
          }

          return HttpResponse.json({ success: true });
        })
      );

      const formData = new FormData();
      
      const response = await fetch('/api/upload', {
        method: 'POST',
        body: formData
      });
      const data = await response.json();
      
      expect(response.status).toBe(400);
      expect(data.error).toBe('No file provided');
    });
  });

  describe('Document Comparison Mocking', () => {
    test('should mock document comparison with custom handler', async () => {
      // Set up custom handler for this test
      server.use(
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
        })
      );

      const response = await fetch('/api/compare', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          originalDocId: 'doc1',
          revisedDocId: 'doc2'
        })
      });
      const data = await response.json();
      
      expect(response.ok).toBe(true);
      expect(data.comparisonId).toBe('test-comparison-id');
      expect(data.differences).toHaveLength(3);
      expect(data.summary.totalChanges).toBe(3);
    });
  });

  describe('Error Scenarios', () => {
    test('should handle network errors', async () => {
      server.use(
        http.get('/api/test/network-error', () => HttpResponse.error())
      );
      
      try {
        await fetch('/api/test/network-error');
        fail('Should have thrown an error');
      } catch (error) {
        expect(error).toBeDefined();
      }
    });

    test('should handle rate limiting with custom handler', async () => {
      server.use(
        http.post('/api/test/rate-limit', () => {
          return HttpResponse.json(
            { error: 'Rate limit exceeded', message: 'Too many requests' },
            { status: 429 }
          );
        })
      );

      const response = await fetch('/api/test/rate-limit', { method: 'POST' });
      const data = await response.json();
      
      expect(response.status).toBe(429);
      expect(data.error).toBe('Rate limit exceeded');
    });

    test('should handle unauthorized access with custom handler', async () => {
      server.use(
        http.post('/api/test/unauthorized', () => {
          return HttpResponse.json(
            { error: 'Unauthorized', message: 'Authentication required' },
            { status: 401 }
          );
        })
      );

      const response = await fetch('/api/test/unauthorized', { method: 'POST' });
      const data = await response.json();
      
      expect(response.status).toBe(401);
      expect(data.error).toBe('Unauthorized');
    });

    test('should handle forbidden access with custom handler', async () => {
      server.use(
        http.post('/api/test/forbidden', () => {
          return HttpResponse.json(
            { error: 'Forbidden', message: 'Insufficient permissions' },
            { status: 403 }
          );
        })
      );

      const response = await fetch('/api/test/forbidden', { method: 'POST' });
      const data = await response.json();
      
      expect(response.status).toBe(403);
      expect(data.error).toBe('Forbidden');
    });
  });

  describe('Data Generation', () => {
    test('should generate unique mock users', () => {
      const user1 = generateMockUser();
      const user2 = generateMockUser();
      
      expect(user1.id).not.toBe(user2.id);
      expect(user1.email).not.toBe(user2.email);
    });

    test('should allow user overrides', () => {
      const user = generateMockUser({
        email: 'custom@example.com',
        role: 'ADMIN'
      });
      
      expect(user.email).toBe('custom@example.com');
      expect(user.role).toBe('ADMIN');
    });
  });

  describe('Response Builders', () => {
    test('should create success responses', () => {
      const response = createSuccessResponse({ message: 'Test message' });
      expect(response).toBeInstanceOf(Response);
    });
  });
}); 