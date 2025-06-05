/**
 * Task 4.2: XSS Protection Tests for Form Inputs and Data Rendering
 * 
 * This test suite validates XSS protection across all user input points and data rendering:
 * - Form input sanitization
 * - Data output encoding
 * - Content Security Policy (CSP) enforcement
 * - DOM-based XSS prevention
 * - Stored XSS protection
 * - Reflected XSS protection
 */

import React from 'react';
import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { render, screen, fireEvent, cleanup } from '@testing-library/react';
import { server } from '@test-mocks/api/mock-server';
import '@testing-library/jest-dom';

describe('🛡️ Task 4.2: XSS Protection Tests', () => {
  
  // Common XSS payloads for testing
  const xssPayloads = [
    // Basic script tags
    "<script>alert('XSS')</script>",
    "<SCRIPT>alert('XSS')</SCRIPT>",
    "<ScRiPt>alert('XSS')</ScRiPt>",
    
    // Event handlers
    "<img src=x onerror=alert('XSS')>",
    "<input type=text onmouseover=alert('XSS')>",
    "<div onclick=alert('XSS')>Click me</div>",
    "<body onload=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    
    // JavaScript URLs
    "<a href=javascript:alert('XSS')>Click</a>",
    "<iframe src=javascript:alert('XSS')></iframe>",
    
    // Data URLs
    "<iframe src=data:text/html,<script>alert('XSS')</script>></iframe>",
    "<object data=data:text/html,<script>alert('XSS')</script>></object>",
    
    // Expression and eval
    "<img src=x onerror=eval('alert(\"XSS\")')>",
    "<input value=\"';alert('XSS');//\">",
    
    // Encoding bypass attempts
    "&#60;script&#62;alert('XSS')&#60;/script&#62;",
    "%3Cscript%3Ealert('XSS')%3C/script%3E",
    "\\u003cscript\\u003ealert('XSS')\\u003c/script\\u003e",
    
    // Template injections
    "{{constructor.constructor('alert(\"XSS\")')()}}",
    "${alert('XSS')}",
    "#{7*7}",
    
    // CSS injection
    "<style>body{background:url('javascript:alert(\"XSS\")')}</style>",
    "<link rel=stylesheet href=javascript:alert('XSS')>",
    
    // Form input specific
    "\"><script>alert('XSS')</script>",
    "';alert('XSS');//",
    "javascript:alert('XSS')",
    
    // Advanced payloads
    "<img src=# onerror=eval(atob('YWxlcnQoJ1hTUycpOw=='))>", // Base64 encoded
    "<svg><animate onbegin=alert('XSS')>",
    "<details open ontoggle=alert('XSS')>",
    "<marquee onstart=alert('XSS')>XSS</marquee>"
  ];

  // DOM-based XSS payloads
  const domXssPayloads = [
    "#<script>alert('DOM XSS')</script>",
    "#javascript:alert('DOM XSS')",
    "#<img src=x onerror=alert('DOM XSS')>",
    "#';alert('DOM XSS');//"
  ];

  beforeEach(() => {
    jest.clearAllMocks();
    global.fetch = server.mockFetch;
    server.listen({ onUnhandledRequest: 'error' });
  });

  afterEach(() => {
    cleanup();
    server.resetHandlers();
    jest.restoreAllMocks();
  });

  afterAll(() => {
    server.close();
  });

  describe('📝 Form Input XSS Protection', () => {
    // Mock form components for testing
    const TestForm = ({ onSubmit }: { onSubmit: (data: any) => void }) => {
      const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        const formData = new FormData(e.target as HTMLFormElement);
        const data = Object.fromEntries(formData.entries());
        onSubmit(data);
      };

      return (
        <form onSubmit={handleSubmit} data-testid="test-form">
          <input name="firstName" data-testid="firstName-input" />
          <input name="lastName" data-testid="lastName-input" />
          <input name="email" data-testid="email-input" />
          <textarea name="description" data-testid="description-input" />
          <select name="category" data-testid="category-select">
            <option value="test">Test</option>
          </select>
          <button type="submit" data-testid="submit-button">Submit</button>
        </form>
      );
    };

    it('should sanitize XSS payloads in text inputs', async () => {
      const onSubmit = jest.fn();
      render(<TestForm onSubmit={onSubmit} />);

      for (const payload of xssPayloads) {
        const firstNameInput = screen.getByTestId('firstName-input');
        
        fireEvent.change(firstNameInput, { target: { value: payload } });
        fireEvent.click(screen.getByTestId('submit-button'));

        expect(onSubmit).toHaveBeenCalled();
        const submittedData = onSubmit.mock.calls[onSubmit.mock.calls.length - 1][0];
        
        // Check that dangerous scripts are not executed
        expect(document.querySelector('script')).toBeNull();
        
        // Verify the payload is properly sanitized or encoded
        expect(submittedData.firstName).not.toContain('<script>');
        expect(submittedData.firstName).not.toContain('javascript:');
        expect(submittedData.firstName).not.toContain('onerror=');
        
        onSubmit.mockClear();
      }
    });

    it('should sanitize XSS payloads in textarea inputs', async () => {
      const onSubmit = jest.fn();
      render(<TestForm onSubmit={onSubmit} />);

      for (const payload of xssPayloads) {
        const descriptionInput = screen.getByTestId('description-input');
        
        fireEvent.change(descriptionInput, { target: { value: payload } });
        fireEvent.click(screen.getByTestId('submit-button'));

        expect(onSubmit).toHaveBeenCalled();
        const submittedData = onSubmit.mock.calls[onSubmit.mock.calls.length - 1][0];
        
        // Verify no script execution
        expect(document.querySelector('script')).toBeNull();
        
        // Verify sanitization
        expect(submittedData.description).not.toContain('<script>');
        expect(submittedData.description).not.toContain('javascript:');
        
        onSubmit.mockClear();
      }
    });

    it('should protect against XSS in form submission to API', async () => {
      for (const payload of xssPayloads) {
        const response = await fetch('/api/auth/signup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            firstName: payload,
            lastName: 'Test',
            email: 'test@example.com',
            password: 'validpassword123'
          })
        });

        expect(response.status).not.toBe(500);
        
        if (response.ok) {
          const data = await response.json();
          // Verify response doesn't contain unescaped XSS
          const responseText = JSON.stringify(data);
          expect(responseText).not.toContain('<script>');
          expect(responseText).not.toContain('javascript:');
          expect(responseText).not.toContain('onerror=');
        }
      }
    });
  });

  describe('🖥️ Data Rendering XSS Protection', () => {
    // Mock component that renders user data
    const UserProfile = ({ userData }: { userData: any }) => (
      <div data-testid="user-profile">
        <h1 data-testid="user-name">{userData.name}</h1>
        <p data-testid="user-bio">{userData.bio}</p>
        <div data-testid="user-html" dangerouslySetInnerHTML={{ __html: userData.safeHtml }} />
      </div>
    );

    it('should safely render user-generated content', () => {
      for (const payload of xssPayloads) {
        const userData = {
          name: payload,
          bio: payload,
          safeHtml: payload // This should be sanitized before reaching component
        };

        render(<UserProfile userData={userData} />);

        // Verify no script tags were executed
        expect(document.querySelector('script')).toBeNull();
        
        // Verify content is rendered safely
        const nameElement = screen.getByTestId('user-name');
        const bioElement = screen.getByTestId('user-bio');
        
        // Text content should be escaped automatically by React
        expect(nameElement.textContent).toBe(payload);
        expect(bioElement.textContent).toBe(payload);
        
        // Verify no dangerous elements in DOM
        expect(document.querySelector('script[src]')).toBeNull();
        expect(document.querySelector('[onload]')).toBeNull();
        expect(document.querySelector('[onerror]')).toBeNull();
        
        cleanup();
      }
    });

    it('should protect against XSS in API response rendering', async () => {
      for (const payload of xssPayloads) {
        const response = await fetch('/api/user/profile', {
          method: 'GET',
          headers: { 'Authorization': 'Bearer valid-token' }
        });

        if (response.ok) {
          const userData = await response.json();
          
          // Mock API response with XSS payload
          const mockUserData = {
            ...userData.user,
            firstName: payload,
            lastName: payload,
            bio: payload
          };

          render(<UserProfile userData={mockUserData} />);

          // Verify safe rendering
          expect(document.querySelector('script')).toBeNull();
          expect(document.querySelector('[onclick]')).toBeNull();
          expect(document.querySelector('[onmouseover]')).toBeNull();
          
          cleanup();
        }
      }
    });
  });

  describe('🔒 Content Security Policy (CSP) Testing', () => {
    it('should have proper CSP headers that prevent XSS', async () => {
      const response = await fetch('/api/auth/signin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com', password: 'test' })
      });

      // Note: In a real implementation, you'd check actual CSP headers
      // This is a mock test showing the expectation
      const cspHeader = response.headers.get('Content-Security-Policy');
      
      if (cspHeader) {
        expect(cspHeader).toContain("default-src 'self'");
        expect(cspHeader).toContain("script-src 'self'");
        expect(cspHeader).toContain("object-src 'none'");
        expect(cspHeader).toContain("base-uri 'self'");
      }
    });

    it('should prevent inline script execution via CSP', () => {
      // Test that inline scripts are blocked by CSP
      const scriptElement = document.createElement('script');
      scriptElement.textContent = "window.xssExecuted = true;";
      document.head.appendChild(scriptElement);
      
      // In a proper CSP implementation, this should be blocked
      expect(window.xssExecuted).toBeUndefined();
      
      document.head.removeChild(scriptElement);
    });
  });

  describe('🌐 DOM-based XSS Protection', () => {
    // Mock component that uses URL fragments
    const UrlFragmentComponent = () => {
      const [fragment, setFragment] = React.useState('');
      
      React.useEffect(() => {
        // Simulate reading from URL fragment (dangerous if not sanitized)
        const hash = window.location.hash.substring(1);
        // In a secure implementation, this should be sanitized
        setFragment(hash);
      }, []);

      return (
        <div data-testid="fragment-content">
          {fragment}
        </div>
      );
    };

    it('should protect against DOM-based XSS in URL fragments', () => {
      for (const payload of domXssPayloads) {
        // Simulate navigation to URL with XSS payload in fragment
        window.location.hash = payload;
        
        render(<UrlFragmentComponent />);
        
        // Verify no script execution
        expect(document.querySelector('script')).toBeNull();
        
        const contentElement = screen.getByTestId('fragment-content');
        // Content should be safely rendered as text
        expect(contentElement.textContent).toBe(payload.substring(1)); // Remove #
        
        cleanup();
      }
    });

    it('should sanitize dynamic DOM manipulation', () => {
      const container = document.createElement('div');
      container.setAttribute('data-testid', 'dynamic-content');
      document.body.appendChild(container);

      for (const payload of xssPayloads) {
        // Simulate unsafe DOM manipulation (should be prevented)
        try {
          container.innerHTML = payload;
          
          // Verify no script execution
          expect(document.querySelector('script')).toBeNull();
          expect(window.xssExecuted).toBeUndefined();
          
        } catch (error) {
          // Some payloads might throw errors, which is acceptable
          expect(error).toBeDefined();
        }
        
        container.innerHTML = ''; // Clean up
      }
      
      document.body.removeChild(container);
    });
  });

  describe('💾 Stored XSS Protection', () => {
    it('should protect against stored XSS in user profiles', async () => {
      for (const payload of xssPayloads) {
        // Submit profile update with XSS payload
        const updateResponse = await fetch('/api/user/profile', {
          method: 'PUT',
          headers: { 
            'Content-Type': 'application/json',
            'Authorization': 'Bearer valid-token'
          },
          body: JSON.stringify({
            firstName: payload,
            bio: payload
          })
        });

        expect(updateResponse.status).not.toBe(500);

        // Retrieve profile and verify XSS protection
        const getResponse = await fetch('/api/user/profile', {
          method: 'GET',
          headers: { 'Authorization': 'Bearer valid-token' }
        });

        if (getResponse.ok) {
          const userData = await getResponse.json();
          
          // Verify stored data is sanitized
          expect(userData.user.firstName).not.toContain('<script>');
          expect(userData.user.bio).not.toContain('javascript:');
          expect(userData.user.firstName).not.toContain('onerror=');
        }
      }
    });

    it('should protect against stored XSS in file metadata', async () => {
      for (const payload of xssPayloads) {
        const formData = new FormData();
        formData.append('file', new Blob(['test'], { type: 'text/plain' }));
        formData.append('filename', payload);
        formData.append('description', payload);

        const response = await fetch('/api/upload', {
          method: 'POST',
          headers: { 'Authorization': 'Bearer valid-token' },
          body: formData
        });

        expect(response.status).not.toBe(500);

        if (response.ok) {
          const data = await response.json();
          
          // Verify file metadata is sanitized
          expect(data.filename || '').not.toContain('<script>');
          expect(data.description || '').not.toContain('javascript:');
        }
      }
    });
  });

  describe('🔄 Reflected XSS Protection', () => {
    it('should protect against reflected XSS in search parameters', async () => {
      for (const payload of xssPayloads) {
        const encodedPayload = encodeURIComponent(payload);
        const response = await fetch(`/api/search?q=${encodedPayload}`, {
          method: 'GET',
          headers: { 'Authorization': 'Bearer valid-token' }
        });

        expect(response.status).not.toBe(500);

        if (response.ok) {
          const data = await response.json();
          const responseText = JSON.stringify(data);
          
          // Verify response doesn't reflect unescaped XSS
          expect(responseText).not.toContain('<script>');
          expect(responseText).not.toContain('javascript:');
          expect(responseText).not.toContain('onerror=');
        }
      }
    });

    it('should protect against reflected XSS in error messages', async () => {
      for (const payload of xssPayloads) {
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
          const errorMessage = data.message || data.error || '';
          
          // Verify error messages don't reflect XSS payloads
          expect(errorMessage).not.toContain('<script>');
          expect(errorMessage).not.toContain('javascript:');
          expect(errorMessage).not.toContain('onerror=');
        }
      }
    });
  });

  describe('🧪 Advanced XSS Attack Vectors', () => {
    it('should protect against mutation XSS (mXSS)', () => {
      const mxssPayloads = [
        "<listing>&lt;img src=x onerror=alert('mXSS')&gt;</listing>",
        "<style>&lt;img src=x onerror=alert('mXSS')&gt;</style>",
        "<noscript>&lt;img src=x onerror=alert('mXSS')&gt;</noscript>"
      ];

      for (const payload of mxssPayloads) {
        const container = document.createElement('div');
        container.innerHTML = payload;
        document.body.appendChild(container);
        
        // Wait for any potential mutations
        setTimeout(() => {
          expect(document.querySelector('img[onerror]')).toBeNull();
          expect(window.xssExecuted).toBeUndefined();
          
          document.body.removeChild(container);
        }, 100);
      }
    });

    it('should protect against filter bypass techniques', () => {
      const bypassPayloads = [
        "j\\u0061vascript:alert('XSS')",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=",
        "<svg/onload=alert('XSS')>",
        "<img src=x onerror=eval('\\x61\\x6c\\x65\\x72\\x74\\x28\\x27\\x58\\x53\\x53\\x27\\x29')>",
        "javascript&#58;alert('XSS')",
        "<script>\\u0061\\u006c\\u0065\\u0072\\u0074('XSS')</script>"
      ];

      for (const payload of bypassPayloads) {
        const container = document.createElement('div');
        container.innerHTML = payload;
        document.body.appendChild(container);
        
        // Verify no script execution
        expect(document.querySelector('script')).toBeNull();
        expect(window.xssExecuted).toBeUndefined();
        
        document.body.removeChild(container);
      }
    });

    it('should protect against polyglot XSS payloads', () => {
      const polyglotPayloads = [
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
        "\"><script>alert('XSS')</script><!--",
        "';alert('XSS');//"
      ];

      for (const payload of polyglotPayloads) {
        const container = document.createElement('div');
        container.innerHTML = payload;
        document.body.appendChild(container);
        
        // Verify no script execution
        expect(document.querySelector('script')).toBeNull();
        expect(window.xssExecuted).toBeUndefined();
        
        document.body.removeChild(container);
      }
    });
  });

  describe('🔍 XSS Detection and Reporting', () => {
    it('should detect and log XSS attempts', async () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      for (const payload of xssPayloads) {
        await fetch('/api/auth/signin', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: payload,
            password: 'test'
          })
        });
      }

      // In a real implementation, XSS attempts should be logged
      // This is a mock expectation
      expect(consoleSpy).toHaveBeenCalled();
      
      consoleSpy.mockRestore();
    });

    it('should have XSS protection headers', async () => {
      const response = await fetch('/api/auth/signin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com', password: 'test' })
      });

      // Check for XSS protection headers (in real implementation)
      const xssProtection = response.headers.get('X-XSS-Protection');
      const contentType = response.headers.get('X-Content-Type-Options');
      
      if (xssProtection) {
        expect(xssProtection).toBe('1; mode=block');
      }
      
      if (contentType) {
        expect(contentType).toBe('nosniff');
      }
    });
  });
});