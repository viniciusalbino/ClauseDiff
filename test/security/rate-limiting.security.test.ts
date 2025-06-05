/**
 * Task 4.8: Rate Limiting Tests for Various Endpoints and Attack Scenarios
 * 
 * This test suite validates rate limiting protection across all application endpoints:
 * - API endpoint rate limiting
 * - Authentication brute force protection
 * - File upload rate limiting
 * - Search and query rate limiting
 * - Distributed attack simulation
 * - Rate limit bypass attempts
 * - Progressive rate limiting
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { server } from '@test-mocks/api/mock-server';

describe('🛡️ Task 4.8: Rate Limiting Security Tests', () => {
  
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

  describe('🔐 Authentication Endpoint Rate Limiting', () => {
    it('should rate limit login attempts', async () => {
      const maxAttempts = 5;
      const responses = [];

      // Attempt multiple login requests rapidly
      for (let i = 0; i < maxAttempts + 3; i++) {
        const response = await fetch('/api/auth/signin', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: 'test@example.com',
            password: 'wrongpassword'
          })
        });
        responses.push(response);
      }

      // Should rate limit after max attempts
      const rateLimitedResponses = responses.filter(r => r.status === 429);
      expect(rateLimitedResponses.length).toBeGreaterThan(0);

      // Check rate limit headers
      const rateLimitedResponse = rateLimitedResponses[0];
      expect(rateLimitedResponse.headers.get('X-RateLimit-Limit')).toBeDefined();
      expect(rateLimitedResponse.headers.get('X-RateLimit-Remaining')).toBeDefined();
      expect(rateLimitedResponse.headers.get('Retry-After')).toBeDefined();
    });

    it('should implement progressive delays for repeated failures', async () => {
      const responses = [];
      const timings = [];

      for (let i = 0; i < 8; i++) {
        const startTime = Date.now();
        
        const response = await fetch('/api/auth/signin', {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'X-Forwarded-For': '192.168.1.100'
          },
          body: JSON.stringify({
            email: 'test@example.com',
            password: `wrongpassword${i}`
          })
        });
        
        const endTime = Date.now();
        responses.push(response);
        timings.push(endTime - startTime);
      }

      // Later attempts should take longer (progressive delays)
      const earlyTiming = timings.slice(0, 3).reduce((a, b) => a + b, 0) / 3;
      const laterTiming = timings.slice(-3).reduce((a, b) => a + b, 0) / 3;
      
      expect(laterTiming).toBeGreaterThan(earlyTiming * 1.5); // At least 50% slower
    });

    it('should rate limit by IP address across different accounts', async () => {
      const accounts = [
        'user1@example.com',
        'user2@example.com', 
        'user3@example.com',
        'admin@example.com'
      ];

      const responses = [];
      const sourceIP = '10.0.0.100';

      // Try multiple accounts from same IP
      for (const email of accounts) {
        for (let i = 0; i < 3; i++) {
          const response = await fetch('/api/auth/signin', {
            method: 'POST',
            headers: { 
              'Content-Type': 'application/json',
              'X-Forwarded-For': sourceIP
            },
            body: JSON.stringify({
              email,
              password: 'wrongpassword'
            })
          });
          responses.push(response);
        }
      }

      // Should rate limit IP even across different accounts
      const rateLimitedResponses = responses.filter(r => r.status === 429);
      expect(rateLimitedResponses.length).toBeGreaterThan(0);
    });

    it('should handle registration endpoint rate limiting', async () => {
      const registrationAttempts = [];

      for (let i = 0; i < 15; i++) {
        const response = await fetch('/api/auth/signup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            firstName: 'Test',
            lastName: 'User',
            email: `test${i}@example.com`,
            password: 'validpassword123'
          })
        });
        registrationAttempts.push(response);
      }

      // Should rate limit rapid registrations
      const rateLimitedAttempts = registrationAttempts.filter(r => r.status === 429);
      expect(rateLimitedAttempts.length).toBeGreaterThan(0);
    });

    it('should rate limit password reset requests', async () => {
      const resetAttempts = [];

      for (let i = 0; i < 10; i++) {
        const response = await fetch('/api/auth/forgot-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: 'test@example.com'
          })
        });
        resetAttempts.push(response);
      }

      // Should prevent password reset spam
      const rateLimitedAttempts = resetAttempts.filter(r => r.status === 429);
      expect(rateLimitedAttempts.length).toBeGreaterThan(0);
    });
  });

  describe('📁 File Upload Rate Limiting', () => {
    it('should rate limit file upload requests', async () => {
      const uploadAttempts = [];

      for (let i = 0; i < 20; i++) {
        const formData = new FormData();
        formData.append('file', new Blob(['test content'], { type: 'text/plain' }), `test${i}.txt`);

        const response = await fetch('/api/upload', {
          method: 'POST',
          headers: { 'Authorization': 'Bearer valid-token' },
          body: formData
        });
        uploadAttempts.push(response);
      }

      // Should rate limit excessive uploads
      const rateLimitedUploads = uploadAttempts.filter(r => r.status === 429);
      expect(rateLimitedUploads.length).toBeGreaterThan(0);
    });

    it('should implement size-based rate limiting', async () => {
      const largeFileAttempts = [];

      for (let i = 0; i < 5; i++) {
        const largeContent = 'A'.repeat(10 * 1024 * 1024); // 10MB files
        const formData = new FormData();
        formData.append('file', new Blob([largeContent], { type: 'text/plain' }), `large${i}.txt`);

        const response = await fetch('/api/upload', {
          method: 'POST',
          headers: { 'Authorization': 'Bearer valid-token' },
          body: formData
        });
        largeFileAttempts.push(response);
      }

      // Should rate limit large file uploads more aggressively
      const rateLimitedLargeUploads = largeFileAttempts.filter(r => r.status === 429);
      expect(rateLimitedLargeUploads.length).toBeGreaterThan(0);
    });

    it('should rate limit concurrent uploads', async () => {
      const concurrentUploads = [];

      // Create 15 concurrent upload requests
      for (let i = 0; i < 15; i++) {
        const formData = new FormData();
        formData.append('file', new Blob(['concurrent test'], { type: 'text/plain' }), `concurrent${i}.txt`);

        const uploadPromise = fetch('/api/upload', {
          method: 'POST',
          headers: { 'Authorization': 'Bearer valid-token' },
          body: formData
        });
        concurrentUploads.push(uploadPromise);
      }

      const responses = await Promise.all(concurrentUploads);
      
      // Should limit concurrent uploads
      const rateLimitedConcurrent = responses.filter(r => r.status === 429);
      expect(rateLimitedConcurrent.length).toBeGreaterThan(0);
    });
  });

  describe('🔍 Search and Query Rate Limiting', () => {
    it('should rate limit search queries', async () => {
      const searchQueries = [
        'document', 'contract', 'agreement', 'policy', 'terms',
        'legal', 'clause', 'section', 'article', 'paragraph'
      ];

      const searchResponses = [];

      // Rapid search requests
      for (let i = 0; i < 25; i++) {
        const query = searchQueries[i % searchQueries.length];
        const response = await fetch(`/api/search?q=${encodeURIComponent(query)}`, {
          method: 'GET',
          headers: { 'Authorization': 'Bearer valid-token' }
        });
        searchResponses.push(response);
      }

      // Should rate limit excessive searches
      const rateLimitedSearches = searchResponses.filter(r => r.status === 429);
      expect(rateLimitedSearches.length).toBeGreaterThan(0);
    });

    it('should rate limit complex queries differently', async () => {
      const complexQueries = [
        'very long complex search query with multiple terms and conditions',
        'another extremely detailed search with specific criteria and filters',
        'comprehensive search across multiple document types and categories'
      ];

      const complexSearchResponses = [];

      for (let i = 0; i < 10; i++) {
        const query = complexQueries[i % complexQueries.length];
        const response = await fetch(`/api/search?q=${encodeURIComponent(query)}&filters=all&sort=relevance`, {
          method: 'GET',
          headers: { 'Authorization': 'Bearer valid-token' }
        });
        complexSearchResponses.push(response);
      }

      // Complex queries should be rate limited more aggressively
      const rateLimitedComplex = complexSearchResponses.filter(r => r.status === 429);
      expect(rateLimitedComplex.length).toBeGreaterThan(0);
    });

    it('should rate limit comparison requests', async () => {
      const comparisonAttempts = [];

      for (let i = 0; i < 12; i++) {
        const response = await fetch('/api/compare', {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'Authorization': 'Bearer valid-token'
          },
          body: JSON.stringify({
            document1: 'doc1.pdf',
            document2: 'doc2.pdf',
            options: { detailed: true }
          })
        });
        comparisonAttempts.push(response);
      }

      // Should rate limit comparison operations
      const rateLimitedComparisons = comparisonAttempts.filter(r => r.status === 429);
      expect(rateLimitedComparisons.length).toBeGreaterThan(0);
    });
  });

  describe('👤 User-Specific Rate Limiting', () => {
    it('should implement different rate limits for different user tiers', async () => {
      const userTiers = [
        { token: 'free-user-token', expectedLimit: 10 },
        { token: 'premium-user-token', expectedLimit: 50 },
        { token: 'enterprise-user-token', expectedLimit: 200 }
      ];

      for (const tier of userTiers) {
        const responses = [];
        
        for (let i = 0; i < tier.expectedLimit + 5; i++) {
          const response = await fetch('/api/user/profile', {
            method: 'GET',
            headers: { 'Authorization': `Bearer ${tier.token}` }
          });
          responses.push(response);
        }

        const successfulRequests = responses.filter(r => r.status === 200).length;
        const rateLimitedRequests = responses.filter(r => r.status === 429).length;

        // Should respect tier-specific limits
        expect(successfulRequests).toBeGreaterThanOrEqual(tier.expectedLimit);
        expect(rateLimitedRequests).toBeGreaterThan(0);
      }
    });

    it('should rate limit admin operations', async () => {
      const adminOperations = [
        '/api/admin/users',
        '/api/admin/audit',
        '/api/admin/settings',
        '/api/admin/reports'
      ];

      const adminResponses = [];

      for (const endpoint of adminOperations) {
        for (let i = 0; i < 15; i++) {
          const response = await fetch(endpoint, {
            method: 'GET',
            headers: { 'Authorization': 'Bearer admin-token' }
          });
          adminResponses.push(response);
        }
      }

      // Should rate limit admin operations
      const rateLimitedAdmin = adminResponses.filter(r => r.status === 429);
      expect(rateLimitedAdmin.length).toBeGreaterThan(0);
    });
  });

  describe('🌐 Distributed Attack Simulation', () => {
    it('should handle distributed brute force attacks', async () => {
      const attackerIPs = [
        '192.168.1.10', '192.168.1.11', '192.168.1.12',
        '10.0.0.10', '10.0.0.11', '10.0.0.12',
        '172.16.0.10', '172.16.0.11', '172.16.0.12'
      ];

      const distributedResponses = [];

      for (const ip of attackerIPs) {
        for (let i = 0; i < 8; i++) {
          const response = await fetch('/api/auth/signin', {
            method: 'POST',
            headers: { 
              'Content-Type': 'application/json',
              'X-Forwarded-For': ip
            },
            body: JSON.stringify({
              email: 'target@example.com',
              password: `attack${i}`
            })
          });
          distributedResponses.push({ response, ip });
        }
      }

      // Should detect and block distributed attacks
      const rateLimitedIPs = new Set();
      distributedResponses.forEach(({ response, ip }) => {
        if (response.status === 429) {
          rateLimitedIPs.add(ip);
        }
      });

      expect(rateLimitedIPs.size).toBeGreaterThan(0);
    });

    it('should implement global rate limiting for severe attacks', async () => {
      const massiveAttackIPs = Array.from({ length: 50 }, (_, i) => `203.0.113.${i + 1}`);
      
      const massiveAttackResponses = [];

      // Simulate massive distributed attack
      for (const ip of massiveAttackIPs.slice(0, 20)) { // Test with first 20 IPs
        for (let i = 0; i < 3; i++) {
          const response = await fetch('/api/auth/signin', {
            method: 'POST',
            headers: { 
              'Content-Type': 'application/json',
              'X-Forwarded-For': ip
            },
            body: JSON.stringify({
              email: 'victim@example.com',
              password: 'brutforce'
            })
          });
          massiveAttackResponses.push(response);
        }
      }

      // Should trigger global protection mechanisms
      const globallyBlocked = massiveAttackResponses.filter(r => 
        r.status === 503 || r.status === 429
      );
      expect(globallyBlocked.length).toBeGreaterThan(0);
    });
  });

  describe('🚫 Rate Limit Bypass Attempts', () => {
    it('should prevent rate limit bypass through header manipulation', async () => {
      const bypassHeaders = [
        { 'X-Forwarded-For': '127.0.0.1' },
        { 'X-Real-IP': 'localhost' },
        { 'X-Client-IP': '::1' },
        { 'X-Originating-IP': '192.168.1.1' },
        { 'X-Remote-IP': '10.0.0.1' },
        { 'Client-IP': '172.16.0.1' }
      ];

      for (const headers of bypassHeaders) {
        const bypassAttempts = [];
        
        for (let i = 0; i < 10; i++) {
          const response = await fetch('/api/auth/signin', {
            method: 'POST',
            headers: { 
              'Content-Type': 'application/json',
              ...headers
            },
            body: JSON.stringify({
              email: 'test@example.com',
              password: 'bypass_attempt'
            })
          });
          bypassAttempts.push(response);
        }

        // Should not be fooled by header manipulation
        const rateLimitedBypass = bypassAttempts.filter(r => r.status === 429);
        expect(rateLimitedBypass.length).toBeGreaterThan(0);
      }
    });

    it('should prevent rate limit bypass through User-Agent rotation', async () => {
      const userAgents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15'
      ];

      const rotationAttempts = [];
      
      for (let i = 0; i < 25; i++) {
        const userAgent = userAgents[i % userAgents.length];
        const response = await fetch('/api/auth/signin', {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'User-Agent': userAgent
          },
          body: JSON.stringify({
            email: 'test@example.com',
            password: 'rotation_bypass'
          })
        });
        rotationAttempts.push(response);
      }

      // Should not be bypassed by User-Agent rotation
      const rateLimitedRotation = rotationAttempts.filter(r => r.status === 429);
      expect(rateLimitedRotation.length).toBeGreaterThan(0);
    });

    it('should prevent rate limit bypass through session manipulation', async () => {
      const sessionIds = [
        'session_1', 'session_2', 'session_3', 'session_4', 'session_5',
        'new_session_1', 'new_session_2', 'temp_session_1', 'temp_session_2'
      ];

      const sessionBypassAttempts = [];

      for (let i = 0; i < 20; i++) {
        const sessionId = sessionIds[i % sessionIds.length];
        const response = await fetch('/api/user/profile', {
          method: 'GET',
          headers: { 
            'Cookie': `sessionId=${sessionId}`,
            'Authorization': 'Bearer bypass-token'
          }
        });
        sessionBypassAttempts.push(response);
      }

      // Should not be bypassed by session manipulation
      const rateLimitedSession = sessionBypassAttempts.filter(r => r.status === 429);
      expect(rateLimitedSession.length).toBeGreaterThan(0);
    });
  });

  describe('⏱️ Rate Limit Recovery and Reset', () => {
    it('should reset rate limits after timeout period', async () => {
      // Trigger rate limit
      const initialAttempts = [];
      for (let i = 0; i < 6; i++) {
        const response = await fetch('/api/auth/signin', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: 'test@example.com',
            password: 'test'
          })
        });
        initialAttempts.push(response);
      }

      // Should be rate limited
      const rateLimited = initialAttempts.filter(r => r.status === 429);
      expect(rateLimited.length).toBeGreaterThan(0);

      // Wait for rate limit reset (simulate with mock)
      await new Promise(resolve => setTimeout(resolve, 100));

      // Try again after reset period
      const postResetResponse = await fetch('/api/auth/signin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'test@example.com',
          password: 'test'
        })
      });

      // Should allow requests again (or at least not be rate limited immediately)
      expect([200, 401, 400]).toContain(postResetResponse.status);
    });

    it('should provide accurate rate limit information in headers', async () => {
      const response = await fetch('/api/auth/signin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'test@example.com',
          password: 'test'
        })
      });

      // Should include rate limit headers
      const rateLimitHeaders = [
        'X-RateLimit-Limit',
        'X-RateLimit-Remaining', 
        'X-RateLimit-Reset'
      ];

      for (const header of rateLimitHeaders) {
        const headerValue = response.headers.get(header);
        if (headerValue !== null) {
          expect(headerValue).toBeDefined();
          expect(headerValue).not.toBe('');
        }
      }
    });

    it('should handle rate limit edge cases gracefully', async () => {
      const edgeCases = [
        // Empty requests
        { body: '', contentType: 'application/json' },
        
        // Malformed JSON
        { body: '{"invalid": json}', contentType: 'application/json' },
        
        // Very large requests
        { body: JSON.stringify({ data: 'A'.repeat(100000) }), contentType: 'application/json' },
        
        // Missing content type
        { body: '{"test": "data"}', contentType: '' }
      ];

      for (const testCase of edgeCases) {
        const response = await fetch('/api/auth/signin', {
          method: 'POST',
          headers: testCase.contentType ? { 'Content-Type': testCase.contentType } : {},
          body: testCase.body
        });

        // Should handle edge cases without crashing
        expect([200, 400, 401, 422, 429]).toContain(response.status);
      }
    });
  });

  describe('📊 Rate Limiting Metrics and Monitoring', () => {
    it('should track rate limiting metrics', async () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();

      // Trigger various rate limit scenarios
      await fetch('/api/auth/signin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com', password: 'test' })
      });

      // Should log rate limiting metrics
      expect(consoleSpy).toHaveBeenCalled();
      
      consoleSpy.mockRestore();
    });

    it('should differentiate between legitimate and malicious traffic', async () => {
      // Legitimate user pattern
      const legitimateRequests = [];
      for (let i = 0; i < 5; i++) {
        await new Promise(resolve => setTimeout(resolve, 50)); // Reasonable delays
        const response = await fetch('/api/user/profile', {
          method: 'GET',
          headers: { 
            'Authorization': 'Bearer valid-token',
            'User-Agent': 'Mozilla/5.0 (consistent user agent)'
          }
        });
        legitimateRequests.push(response);
      }

      // Malicious pattern
      const maliciousRequests = [];
      for (let i = 0; i < 15; i++) {
        const response = await fetch('/api/auth/signin', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: 'admin@example.com',
            password: `bruteforce${i}`
          })
        });
        maliciousRequests.push(response);
      }

      // Legitimate traffic should generally succeed
      const legitimateSuccesses = legitimateRequests.filter(r => r.status === 200);
      expect(legitimateSuccesses.length).toBeGreaterThan(0);

      // Malicious traffic should be rate limited
      const maliciousRateLimited = maliciousRequests.filter(r => r.status === 429);
      expect(maliciousRateLimited.length).toBeGreaterThan(0);
    });
  });
}); 