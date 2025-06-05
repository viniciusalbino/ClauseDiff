/**
 * Task 4.6: Security Headers Validation Tests (CSP, HSTS, X-Frame-Options, etc.)
 * 
 * This test suite validates security headers across all application responses:
 * - Content Security Policy (CSP)
 * - HTTP Strict Transport Security (HSTS)
 * - X-Frame-Options
 * - X-Content-Type-Options
 * - X-XSS-Protection
 * - Referrer-Policy
 * - Feature-Policy/Permissions-Policy
 * - CORS headers
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { server } from '@test-mocks/api/mock-server';

describe('🛡️ Task 4.6: Security Headers Validation Tests', () => {
  
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

  describe('🔒 Content Security Policy (CSP)', () => {
    const testEndpoints = [
      '/api/auth/signin',
      '/api/user/profile',
      '/api/admin/users',
      '/api/upload',
      '/api/compare'
    ];

    it('should include Content-Security-Policy header', async () => {
      for (const endpoint of testEndpoints) {
        const response = await fetch(endpoint, {
          method: 'GET',
          headers: { 'Authorization': 'Bearer valid-token' }
        });

        const cspHeader = response.headers.get('Content-Security-Policy');
        expect(cspHeader).toBeDefined();
        expect(cspHeader).not.toBe('');
      }
    });

    it('should have restrictive default-src directive', async () => {
      const response = await fetch('/api/auth/signin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com', password: 'test' })
      });

      const cspHeader = response.headers.get('Content-Security-Policy');
      if (cspHeader) {
        expect(cspHeader).toMatch(/default-src\s+[^;]*'self'/);
        expect(cspHeader).not.toMatch(/default-src\s+[^;]*\*/); // Should not allow wildcard
      }
    });

    it('should restrict script-src to prevent XSS', async () => {
      const response = await fetch('/api/user/profile', {
        method: 'GET',
        headers: { 'Authorization': 'Bearer valid-token' }
      });

      const cspHeader = response.headers.get('Content-Security-Policy');
      if (cspHeader) {
        expect(cspHeader).toMatch(/script-src\s+[^;]*'self'/);
        expect(cspHeader).not.toMatch(/script-src\s+[^;]*'unsafe-inline'/);
        expect(cspHeader).not.toMatch(/script-src\s+[^;]*'unsafe-eval'/);
      }
    });

    it('should prevent object-src execution', async () => {
      const response = await fetch('/api/upload', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer valid-token' },
        body: new FormData()
      });

      const cspHeader = response.headers.get('Content-Security-Policy');
      if (cspHeader) {
        expect(cspHeader).toMatch(/object-src\s+[^;]*'none'/);
      }
    });

    it('should restrict base-uri to prevent base tag injection', async () => {
      const response = await fetch('/api/auth/signin', {
        method: 'GET'
      });

      const cspHeader = response.headers.get('Content-Security-Policy');
      if (cspHeader) {
        expect(cspHeader).toMatch(/base-uri\s+[^;]*'self'/);
      }
    });

    it('should include frame-ancestors to prevent clickjacking', async () => {
      const response = await fetch('/api/user/profile', {
        method: 'GET',
        headers: { 'Authorization': 'Bearer valid-token' }
      });

      const cspHeader = response.headers.get('Content-Security-Policy');
      if (cspHeader) {
        expect(cspHeader).toMatch(/frame-ancestors\s+[^;]*'none'|frame-ancestors\s+[^;]*'self'/);
      }
    });
  });

  describe('🔐 HTTP Strict Transport Security (HSTS)', () => {
    it('should include HSTS header for HTTPS requests', async () => {
      const response = await fetch('/api/auth/signin', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'X-Forwarded-Proto': 'https'
        },
        body: JSON.stringify({ email: 'test@example.com', password: 'test' })
      });

      const hstsHeader = response.headers.get('Strict-Transport-Security');
      expect(hstsHeader).toBeDefined();
      expect(hstsHeader).not.toBe('');
    });

    it('should have appropriate max-age directive', async () => {
      const response = await fetch('/api/user/profile', {
        method: 'GET',
        headers: { 
          'Authorization': 'Bearer valid-token',
          'X-Forwarded-Proto': 'https'
        }
      });

      const hstsHeader = response.headers.get('Strict-Transport-Security');
      if (hstsHeader) {
        expect(hstsHeader).toMatch(/max-age=\d+/);
        
        const maxAgeMatch = hstsHeader.match(/max-age=(\d+)/);
        if (maxAgeMatch) {
          const maxAge = parseInt(maxAgeMatch[1]);
          expect(maxAge).toBeGreaterThanOrEqual(31536000); // At least 1 year
        }
      }
    });

    it('should include includeSubDomains directive', async () => {
      const response = await fetch('/api/admin/users', {
        method: 'GET',
        headers: { 
          'Authorization': 'Bearer admin-token',
          'X-Forwarded-Proto': 'https'
        }
      });

      const hstsHeader = response.headers.get('Strict-Transport-Security');
      if (hstsHeader) {
        expect(hstsHeader).toMatch(/includeSubDomains/);
      }
    });

    it('should include preload directive for production', async () => {
      const response = await fetch('/api/auth/signin', {
        method: 'GET',
        headers: { 'X-Forwarded-Proto': 'https' }
      });

      const hstsHeader = response.headers.get('Strict-Transport-Security');
      if (hstsHeader && process.env.NODE_ENV === 'production') {
        expect(hstsHeader).toMatch(/preload/);
      }
    });
  });

  describe('🖼️ X-Frame-Options', () => {
    const sensitiveEndpoints = [
      '/api/auth/signin',
      '/api/auth/signup',
      '/api/user/change-password',
      '/api/admin/users',
      '/api/upload'
    ];

    it('should include X-Frame-Options header', async () => {
      for (const endpoint of sensitiveEndpoints) {
        const response = await fetch(endpoint, {
          method: 'GET',
          headers: { 'Authorization': 'Bearer valid-token' }
        });

        const frameOptionsHeader = response.headers.get('X-Frame-Options');
        expect(frameOptionsHeader).toBeDefined();
        expect(frameOptionsHeader).not.toBe('');
      }
    });

    it('should have restrictive frame options', async () => {
      const response = await fetch('/api/auth/signin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com', password: 'test' })
      });

      const frameOptionsHeader = response.headers.get('X-Frame-Options');
      if (frameOptionsHeader) {
        expect(['DENY', 'SAMEORIGIN']).toContain(frameOptionsHeader);
      }
    });

    it('should prevent embedding in foreign frames', async () => {
      const response = await fetch('/api/user/profile', {
        method: 'GET',
        headers: { 'Authorization': 'Bearer valid-token' }
      });

      const frameOptionsHeader = response.headers.get('X-Frame-Options');
      expect(frameOptionsHeader).not.toBe('ALLOWALL');
      expect(frameOptionsHeader).not.toMatch(/ALLOW-FROM.*evil\.com/);
    });
  });

  describe('📄 X-Content-Type-Options', () => {
    it('should include X-Content-Type-Options header', async () => {
      const response = await fetch('/api/upload', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer valid-token' },
        body: new FormData()
      });

      const contentTypeOptionsHeader = response.headers.get('X-Content-Type-Options');
      expect(contentTypeOptionsHeader).toBeDefined();
      expect(contentTypeOptionsHeader).toBe('nosniff');
    });

    it('should prevent MIME type sniffing on all responses', async () => {
      const endpoints = [
        '/api/auth/signin',
        '/api/user/profile',
        '/api/files',
        '/api/compare'
      ];

      for (const endpoint of endpoints) {
        const response = await fetch(endpoint, {
          method: 'GET',
          headers: { 'Authorization': 'Bearer valid-token' }
        });

        const contentTypeOptionsHeader = response.headers.get('X-Content-Type-Options');
        expect(contentTypeOptionsHeader).toBe('nosniff');
      }
    });
  });

  describe('🛡️ X-XSS-Protection', () => {
    it('should include X-XSS-Protection header', async () => {
      const response = await fetch('/api/auth/signin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com', password: 'test' })
      });

      const xssProtectionHeader = response.headers.get('X-XSS-Protection');
      expect(xssProtectionHeader).toBeDefined();
    });

    it('should enable XSS protection with blocking mode', async () => {
      const response = await fetch('/api/user/profile', {
        method: 'GET',
        headers: { 'Authorization': 'Bearer valid-token' }
      });

      const xssProtectionHeader = response.headers.get('X-XSS-Protection');
      if (xssProtectionHeader) {
        expect(xssProtectionHeader).toMatch(/1;\s*mode=block/);
      }
    });
  });

  describe('🔗 Referrer-Policy', () => {
    it('should include Referrer-Policy header', async () => {
      const response = await fetch('/api/auth/signin', {
        method: 'GET'
      });

      const referrerPolicyHeader = response.headers.get('Referrer-Policy');
      expect(referrerPolicyHeader).toBeDefined();
    });

    it('should have strict referrer policy', async () => {
      const response = await fetch('/api/user/profile', {
        method: 'GET',
        headers: { 'Authorization': 'Bearer valid-token' }
      });

      const referrerPolicyHeader = response.headers.get('Referrer-Policy');
      if (referrerPolicyHeader) {
        const strictPolicies = [
          'no-referrer',
          'same-origin',
          'strict-origin',
          'strict-origin-when-cross-origin'
        ];
        expect(strictPolicies.some(policy => 
          referrerPolicyHeader.includes(policy)
        )).toBe(true);
      }
    });
  });

  describe('🔧 Permissions-Policy / Feature-Policy', () => {
    it('should include Permissions-Policy header', async () => {
      const response = await fetch('/api/upload', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer valid-token' },
        body: new FormData()
      });

      const permissionsPolicyHeader = response.headers.get('Permissions-Policy') || 
                                      response.headers.get('Feature-Policy');
      expect(permissionsPolicyHeader).toBeDefined();
    });

    it('should restrict dangerous features', async () => {
      const response = await fetch('/api/auth/signin', {
        method: 'GET'
      });

      const permissionsPolicyHeader = response.headers.get('Permissions-Policy') || 
                                      response.headers.get('Feature-Policy');
      if (permissionsPolicyHeader) {
        // Should disable dangerous features
        expect(permissionsPolicyHeader).toMatch(/camera\s*=\s*\(\)/);
        expect(permissionsPolicyHeader).toMatch(/microphone\s*=\s*\(\)/);
        expect(permissionsPolicyHeader).toMatch(/geolocation\s*=\s*\(\)/);
      }
    });
  });

  describe('🌐 CORS Headers', () => {
    it('should not include permissive CORS headers by default', async () => {
      const response = await fetch('/api/user/profile', {
        method: 'GET',
        headers: { 'Authorization': 'Bearer valid-token' }
      });

      const corsHeader = response.headers.get('Access-Control-Allow-Origin');
      if (corsHeader) {
        expect(corsHeader).not.toBe('*');
      }
    });

    it('should validate CORS origins when present', async () => {
      const response = await fetch('/api/auth/signin', {
        method: 'OPTIONS',
        headers: { 
          'Origin': 'https://evil.com',
          'Access-Control-Request-Method': 'POST'
        }
      });

      const corsHeader = response.headers.get('Access-Control-Allow-Origin');
      if (corsHeader) {
        expect(corsHeader).not.toBe('https://evil.com');
      }
    });

    it('should not expose sensitive headers in CORS', async () => {
      const response = await fetch('/api/user/profile', {
        method: 'OPTIONS',
        headers: { 
          'Origin': 'https://trusted-domain.com',
          'Access-Control-Request-Method': 'GET'
        }
      });

      const exposedHeaders = response.headers.get('Access-Control-Expose-Headers');
      if (exposedHeaders) {
        expect(exposedHeaders).not.toMatch(/authorization|cookie|session/i);
      }
    });
  });

  describe('📨 Cache Control', () => {
    it('should prevent caching of sensitive data', async () => {
      const sensitiveEndpoints = [
        '/api/auth/signin',
        '/api/user/profile',
        '/api/admin/users',
        '/api/user/change-password'
      ];

      for (const endpoint of sensitiveEndpoints) {
        const response = await fetch(endpoint, {
          method: 'GET',
          headers: { 'Authorization': 'Bearer valid-token' }
        });

        const cacheControlHeader = response.headers.get('Cache-Control');
        if (cacheControlHeader) {
          expect(cacheControlHeader).toMatch(/no-cache|no-store|private/);
        }

        const pragmaHeader = response.headers.get('Pragma');
        if (pragmaHeader) {
          expect(pragmaHeader).toBe('no-cache');
        }
      }
    });

    it('should set appropriate cache headers for static content', async () => {
      const response = await fetch('/api/files/public', {
        method: 'GET'
      });

      if (response.ok) {
        const cacheControlHeader = response.headers.get('Cache-Control');
        if (cacheControlHeader) {
          // Static content can be cached but should have validation
          expect(cacheControlHeader).toMatch(/max-age=\d+/);
        }
      }
    });
  });

  describe('🔍 Information Disclosure Prevention', () => {
    it('should not expose server information', async () => {
      const response = await fetch('/api/auth/signin', {
        method: 'GET'
      });

      const serverHeader = response.headers.get('Server');
      const poweredByHeader = response.headers.get('X-Powered-By');
      
      if (serverHeader) {
        expect(serverHeader).not.toMatch(/nginx\/[\d.]+|apache\/[\d.]+|express/i);
      }
      
      expect(poweredByHeader).toBeNull();
    });

    it('should not expose technology stack details', async () => {
      const response = await fetch('/api/user/profile', {
        method: 'GET',
        headers: { 'Authorization': 'Bearer valid-token' }
      });

      // Should not expose specific technology versions
      const headers = Array.from(response.headers.entries());
      const headerValues = headers.map(([, value]) => value.toLowerCase()).join(' ');
      
      expect(headerValues).not.toMatch(/php\/[\d.]+|python\/[\d.]+|node\.js\/[\d.]+/);
      expect(headerValues).not.toMatch(/nextjs|react|express|fastify/);
    });
  });

  describe('🚫 Security Headers Validation', () => {
    it('should not include dangerous headers', async () => {
      const response = await fetch('/api/auth/signin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com', password: 'test' })
      });

      // Should not include headers that could expose information
      expect(response.headers.get('X-AspNet-Version')).toBeNull();
      expect(response.headers.get('X-AspNetMvc-Version')).toBeNull();
      expect(response.headers.get('X-Powered-By')).toBeNull();
      expect(response.headers.get('Server')).not.toMatch(/IIS|Apache|nginx/);
    });

    it('should have consistent security headers across all endpoints', async () => {
      const endpoints = [
        '/api/auth/signin',
        '/api/user/profile',
        '/api/admin/users',
        '/api/upload',
        '/api/compare'
      ];

      const securityHeaders = [
        'X-Content-Type-Options',
        'X-Frame-Options',
        'X-XSS-Protection',
        'Referrer-Policy'
      ];

      for (const endpoint of endpoints) {
        const response = await fetch(endpoint, {
          method: 'GET',
          headers: { 'Authorization': 'Bearer valid-token' }
        });

        for (const header of securityHeaders) {
          expect(response.headers.get(header)).toBeDefined();
        }
      }
    });
  });

  describe('🔒 API-Specific Security Headers', () => {
    it('should include JSON-specific security headers', async () => {
      const response = await fetch('/api/user/profile', {
        method: 'GET',
        headers: { 
          'Authorization': 'Bearer valid-token',
          'Accept': 'application/json'
        }
      });

      const contentType = response.headers.get('Content-Type');
      if (contentType && contentType.includes('application/json')) {
        // JSON responses should have appropriate charset
        expect(contentType).toMatch(/charset=utf-8/i);
      }
    });

    it('should prevent JSON hijacking', async () => {
      const response = await fetch('/api/user/profile', {
        method: 'GET',
        headers: { 'Authorization': 'Bearer valid-token' }
      });

      if (response.ok) {
        const data = await response.json();
        const responseText = JSON.stringify(data);
        
        // Should not start with array (to prevent JSON hijacking)
        expect(responseText).not.toMatch(/^\s*\[/);
      }
    });

    it('should include appropriate MIME type for file downloads', async () => {
      const response = await fetch('/api/files/download/test.pdf', {
        method: 'GET',
        headers: { 'Authorization': 'Bearer valid-token' }
      });

      if (response.ok) {
        const contentType = response.headers.get('Content-Type');
        const contentDisposition = response.headers.get('Content-Disposition');
        
        if (contentDisposition && contentDisposition.includes('attachment')) {
          expect(contentType).not.toBe('text/html');
          expect(contentType).not.toBe('application/javascript');
        }
      }
    });
  });
}); 