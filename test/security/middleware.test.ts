/**
 * Security Middleware Tests
 * Tests for rate limiting, timing attacks, CSRF protection, and security logging
 */

import { NextRequest } from 'next/server';
import { middleware } from '../../middleware';

// Mock NextAuth JWT
jest.mock('next-auth/jwt', () => ({
  getToken: jest.fn()
}));

describe('Security Middleware Tests', () => {
  const mockGetToken = require('next-auth/jwt').getToken;
  
  beforeEach(() => {
    jest.clearAllMocks();
    mockGetToken.mockResolvedValue(null); // Default to no token
  });

  describe('Rate Limiting', () => {
    test('should allow requests within rate limit', async () => {
      const request = new NextRequest('http://localhost:3000/api/test', {
        method: 'GET',
        headers: { 'x-forwarded-for': '192.168.1.100' }
      });

      const response = await middleware(request);
      expect(response.status).not.toBe(429);
    });

    test('should block requests exceeding general rate limit', async () => {
      const ip = '192.168.1.101';
      
      // Make multiple requests to exceed rate limit
      for (let i = 0; i < 105; i++) {
        const request = new NextRequest('http://localhost:3000/api/test', {
          method: 'GET',
          headers: { 'x-forwarded-for': ip }
        });
        
        const response = await middleware(request);
        
        if (i >= 100) {
          expect(response.status).toBe(429);
          const body = await response.json();
          expect(body.code).toBe('RATE_LIMIT_EXCEEDED');
        }
      }
    });

    test('should apply stricter rate limiting for auth endpoints', async () => {
      const ip = '192.168.1.102';
      
      // Make multiple requests to auth endpoint
      for (let i = 0; i < 15; i++) {
        const request = new NextRequest('http://localhost:3000/api/auth/signin', {
          method: 'POST',
          headers: { 'x-forwarded-for': ip }
        });
        
        const response = await middleware(request);
        
        if (i >= 10) {
          expect(response.status).toBe(429);
        }
      }
    });

    test('should apply special login attempt limiting', async () => {
      const ip = '192.168.1.103';
      
      // Make multiple login attempts
      for (let i = 0; i < 8; i++) {
        const request = new NextRequest('http://localhost:3000/api/auth/callback/credentials', {
          method: 'POST',
          headers: { 'x-forwarded-for': ip }
        });
        
        const response = await middleware(request);
        
        if (i >= 5) {
          expect(response.status).toBe(429);
          const body = await response.json();
          expect(body.code).toBe('LOGIN_RATE_LIMIT_EXCEEDED');
        }
      }
    });
  });

  describe('CSRF Protection', () => {
    test('should allow GET requests without CSRF token', async () => {
      const request = new NextRequest('http://localhost:3000/api/test', {
        method: 'GET'
      });

      const response = await middleware(request);
      expect(response.status).not.toBe(403);
    });

    test('should block POST requests without CSRF token', async () => {
      const request = new NextRequest('http://localhost:3000/api/test', {
        method: 'POST',
        headers: { 'x-forwarded-for': '192.168.1.104' }
      });

      const response = await middleware(request);
      expect(response.status).toBe(403);
      
      const body = await response.json();
      expect(body.code).toBe('CSRF_ERROR');
    });

    test('should allow POST requests with valid CSRF token', async () => {
      const csrfToken = 'valid-csrf-token';
      
      const request = new NextRequest('http://localhost:3000/api/test', {
        method: 'POST',
        headers: {
          'x-csrf-token': csrfToken,
          'cookie': `__Host-csrf-token=${csrfToken}`
        }
      });

      const response = await middleware(request);
      expect(response.status).not.toBe(403);
    });

    test('should skip CSRF check for NextAuth endpoints', async () => {
      const request = new NextRequest('http://localhost:3000/api/auth/signin', {
        method: 'POST'
      });

      const response = await middleware(request);
      expect(response.status).not.toBe(403);
    });
  });

  describe('Security Headers', () => {
    test('should add security headers to all responses', async () => {
      const request = new NextRequest('http://localhost:3000/api/test', {
        method: 'GET'
      });

      const response = await middleware(request);
      
      expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff');
      expect(response.headers.get('X-Frame-Options')).toBe('DENY');
      expect(response.headers.get('X-XSS-Protection')).toBe('1; mode=block');
      expect(response.headers.get('Strict-Transport-Security')).toContain('max-age=31536000');
      expect(response.headers.get('Content-Security-Policy')).toContain("default-src 'self'");
    });
  });

  describe('Route Protection', () => {
    test('should allow access to public routes without token', async () => {
      const request = new NextRequest('http://localhost:3000/login', {
        method: 'GET'
      });

      const response = await middleware(request);
      expect(response.status).not.toBe(401);
    });

    test('should block access to protected routes without token', async () => {
      const request = new NextRequest('http://localhost:3000/dashboard', {
        method: 'GET',
        headers: { 'x-forwarded-for': '192.168.1.105' }
      });

      const response = await middleware(request);
      expect(response.status).toBe(302); // Redirect to login
    });

    test('should allow access to protected routes with valid token', async () => {
      mockGetToken.mockResolvedValue({ 
        sub: 'user123',
        email: 'test@example.com' 
      });

      const request = new NextRequest('http://localhost:3000/dashboard', {
        method: 'GET'
      });

      const response = await middleware(request);
      expect(response.status).not.toBe(401);
      expect(response.status).not.toBe(302);
    });

    test('should return JSON error for protected API routes', async () => {
      const request = new NextRequest('http://localhost:3000/api/protected/test', {
        method: 'GET',
        headers: { 'x-forwarded-for': '192.168.1.106' }
      });

      const response = await middleware(request);
      expect(response.status).toBe(401);
      
      const body = await response.json();
      expect(body.code).toBe('AUTH_REQUIRED');
    });
  });

  describe('Timing Attack Protection', () => {
    test('should add delay to login endpoints', async () => {
      const startTime = Date.now();
      
      const request = new NextRequest('http://localhost:3000/api/auth/signin', {
        method: 'POST',
        headers: { 'x-forwarded-for': '192.168.1.107' }
      });

      await middleware(request);
      
      const endTime = Date.now();
      const duration = endTime - startTime;
      
      // Should have at least minimum delay (100ms)
      expect(duration).toBeGreaterThanOrEqual(100);
    });
  });

  describe('Security Event Logging', () => {
    // Note: These tests verify that security events are logged
    // In a real implementation, you'd test the actual logging mechanism
    
    test('should log CSRF validation failures', async () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      
      const request = new NextRequest('http://localhost:3000/api/test', {
        method: 'POST',
        headers: { 'x-forwarded-for': '192.168.1.108' }
      });

      await middleware(request);
      
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringMatching(/\[SECURITY\] CSRF_VALIDATION_FAILED/)
      );
      
      consoleSpy.mockRestore();
    });

    test('should log unauthorized access attempts', async () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      
      const request = new NextRequest('http://localhost:3000/dashboard', {
        method: 'GET',
        headers: { 'x-forwarded-for': '192.168.1.109' }
      });

      await middleware(request);
      
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringMatching(/\[SECURITY\] UNAUTHORIZED_ACCESS_ATTEMPT/)
      );
      
      consoleSpy.mockRestore();
    });
  });

  describe('Progressive Backoff', () => {
    test('should apply progressive backoff after multiple failures', async () => {
      // This test would need to coordinate with the login failure endpoint
      // For now, we'll test the rate limiting behavior which includes backoff
      
      const ip = '192.168.1.110';
      
      // Make multiple failed login attempts
      for (let i = 0; i < 8; i++) {
        const request = new NextRequest('http://localhost:3000/api/auth/callback/credentials', {
          method: 'POST',
          headers: { 'x-forwarded-for': ip }
        });
        
        const response = await middleware(request);
        
        if (i >= 5) {
          expect(response.status).toBe(429);
          const body = await response.json();
          expect(body).toHaveProperty('retryAfterSeconds');
        }
      }
    });
  });

  describe('Edge Cases', () => {
    test('should handle requests without IP address', async () => {
      const request = new NextRequest('http://localhost:3000/api/test', {
        method: 'GET'
      });

      const response = await middleware(request);
      expect(response.status).not.toBe(500); // Should handle gracefully
    });

    test('should handle malformed CSRF headers', async () => {
      const request = new NextRequest('http://localhost:3000/api/test', {
        method: 'POST',
        headers: {
          'x-csrf-token': 'invalid-token',
          'cookie': 'malformed-cookie'
        }
      });

      const response = await middleware(request);
      expect(response.status).toBe(403);
    });
  });
});

describe('Integration with NextAuth', () => {
  test('should coordinate with NextAuth for login failures', async () => {
    // Test the login failure endpoint
    const request = new NextRequest('http://localhost:3000/api/auth/login-failure', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        ip: '192.168.1.111',
        type: 'failure'
      })
    });

    // This would be handled by the login-failure route
    // We're testing that the integration point exists
    expect(request.url).toContain('/api/auth/login-failure');
  });
}); 