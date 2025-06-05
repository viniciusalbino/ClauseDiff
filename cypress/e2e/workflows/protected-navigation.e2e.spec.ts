describe('Protected Page Navigation and Permission Checking E2E', () => {
  beforeEach(() => {
    // Clear any existing sessions
    cy.clearCookies();
    cy.clearLocalStorage();
    cy.clearSessionStorage();
  });

  describe('Unauthenticated Access Protection', () => {
    const protectedPages = [
      '/dashboard',
      '/profile',
      '/compare',
      '/history',
      '/settings',
      '/admin',
      '/admin/users',
      '/admin/audit'
    ];

    protectedPages.forEach((page) => {
      it(`should redirect unauthenticated users from ${page} to login`, () => {
        cy.visit(page, { failOnStatusCode: false });
        
        // Should redirect to login page
        cy.url().should('include', '/login');
        
        // Should show appropriate message about needing to log in
        cy.get('[data-testid="auth-required-message"]')
          .should('be.visible')
          .and('contain', 'Please log in to access this page');
        
        // Should preserve the intended destination
        cy.url().should('include', `redirect=${encodeURIComponent(page)}`);
        
        cy.checkA11y();
      });
    });

    it('should redirect to intended page after successful login', () => {
      const intendedPage = '/dashboard';
      
      // Create test user
      cy.createTestUser({
        email: 'redirect-test@example.com',
        password: 'Password123',
        firstName: 'Redirect',
        lastName: 'Test'
      });

      // Try to access protected page
      cy.visit(intendedPage, { failOnStatusCode: false });
      cy.url().should('include', '/login');

      // Log in
      cy.login('redirect-test@example.com', 'Password123');

      // Should redirect to originally intended page
      cy.url().should('include', intendedPage);
      cy.get('[data-testid="dashboard"]').should('be.visible');

      cy.deleteTestUser('redirect-test@example.com');
    });

    it('should handle deep-linked protected URLs correctly', () => {
      const deepLink = '/compare?file1=abc&file2=def';
      
      cy.visit(deepLink, { failOnStatusCode: false });
      
      // Should redirect to login
      cy.url().should('include', '/login');
      
      // Should preserve query parameters
      cy.url().should('include', encodeURIComponent(deepLink));
    });

    it('should block API endpoints for unauthenticated users', () => {
      const protectedApiEndpoints = [
        '/api/user/profile',
        '/api/files/upload',
        '/api/files/compare',
        '/api/export/pdf',
        '/api/admin/users'
      ];

      protectedApiEndpoints.forEach((endpoint) => {
        cy.request({
          url: endpoint,
          failOnStatusCode: false
        }).then((response) => {
          expect(response.status).to.eq(401);
          expect(response.body).to.have.property('error');
        });
      });
    });
  });

  describe('Role-Based Access Control', () => {
    describe('Regular User Permissions', () => {
      beforeEach(() => {
        cy.createTestUser({
          email: 'user@example.com',
          password: 'Password123',
          firstName: 'Regular',
          lastName: 'User',
          role: 'user'
        });
        
        cy.loginApi('user@example.com', 'Password123');
      });

      afterEach(() => {
        cy.deleteTestUser('user@example.com');
      });

      const allowedPages = [
        '/dashboard',
        '/profile',
        '/compare',
        '/history',
        '/settings'
      ];

      allowedPages.forEach((page) => {
        it(`should allow regular users to access ${page}`, () => {
          cy.visit(page);
          
          // Should successfully load the page
          cy.url().should('include', page);
          cy.get('body').should('not.contain', '403');
          cy.get('body').should('not.contain', 'Access Denied');
          
          cy.checkA11y();
        });
      });

      const forbiddenPages = [
        '/admin',
        '/admin/users',
        '/admin/audit',
        '/admin/settings'
      ];

      forbiddenPages.forEach((page) => {
        it(`should deny regular users access to ${page}`, () => {
          cy.visit(page, { failOnStatusCode: false });
          
          // Should show 403 or redirect to unauthorized page
          cy.url().should('match', /(403|unauthorized)/);
          
          cy.get('[data-testid="access-denied"]')
            .should('be.visible')
            .and('contain', 'You do not have permission to access this page');
          
          // Should provide navigation back to allowed areas
          cy.get('[data-testid="back-to-dashboard"]')
            .should('be.visible')
            .and('contain', 'Return to Dashboard');
        });
      });

      it('should block admin API endpoints for regular users', () => {
        const adminApiEndpoints = [
          '/api/admin/users',
          '/api/admin/audit',
          '/api/admin/settings'
        ];

        adminApiEndpoints.forEach((endpoint) => {
          cy.request({
            url: endpoint,
            failOnStatusCode: false
          }).then((response) => {
            expect(response.status).to.eq(403);
            expect(response.body.error).to.contain('Insufficient permissions');
          });
        });
      });

      it('should hide admin navigation elements for regular users', () => {
        cy.visit('/dashboard');
        
        // Admin menu items should not be visible
        cy.get('[data-testid="admin-menu"]').should('not.exist');
        cy.get('[data-testid="user-management"]').should('not.exist');
        cy.get('[data-testid="audit-logs"]').should('not.exist');
        
        // User menu should only show allowed options
        cy.get('[data-testid="user-menu"]').click();
        cy.get('[data-testid="profile-link"]').should('be.visible');
        cy.get('[data-testid="settings-link"]').should('be.visible');
        cy.get('[data-testid="admin-link"]').should('not.exist');
      });
    });

    describe('Admin User Permissions', () => {
      beforeEach(() => {
        cy.createTestUser({
          email: 'admin@example.com',
          password: 'Password123',
          firstName: 'Admin',
          lastName: 'User',
          role: 'admin'
        });
        
        cy.loginApi('admin@example.com', 'Password123');
      });

      afterEach(() => {
        cy.deleteTestUser('admin@example.com');
      });

      const allPages = [
        '/dashboard',
        '/profile',
        '/compare',
        '/history',
        '/settings',
        '/admin',
        '/admin/users',
        '/admin/audit'
      ];

      allPages.forEach((page) => {
        it(`should allow admin users to access ${page}`, () => {
          cy.visit(page);
          
          cy.url().should('include', page);
          cy.get('body').should('not.contain', '403');
          cy.get('body').should('not.contain', 'Access Denied');
        });
      });

      it('should show admin navigation elements for admin users', () => {
        cy.visit('/dashboard');
        
        // Admin menu should be visible
        cy.get('[data-testid="admin-menu"]').should('be.visible');
        
        // User menu should show admin options
        cy.get('[data-testid="user-menu"]').click();
        cy.get('[data-testid="admin-panel-link"]').should('be.visible');
        cy.get('[data-testid="user-management-link"]').should('be.visible');
        cy.get('[data-testid="audit-logs-link"]').should('be.visible');
      });

      it('should allow access to admin API endpoints', () => {
        const adminApiEndpoints = [
          { endpoint: '/api/admin/users', method: 'GET' },
          { endpoint: '/api/admin/audit', method: 'GET' }
        ];

        adminApiEndpoints.forEach(({ endpoint, method }) => {
          cy.request({
            method,
            url: endpoint
          }).then((response) => {
            expect(response.status).to.eq(200);
          });
        });
      });

      it('should display admin-specific UI elements', () => {
        cy.visit('/admin/users');
        
        // Admin-specific actions should be visible
        cy.get('[data-testid="create-user-button"]').should('be.visible');
        cy.get('[data-testid="bulk-actions"]').should('be.visible');
        cy.get('[data-testid="user-list"]').should('be.visible');
        
        // Should show user management tools
        cy.get('[data-testid="user-search"]').should('be.visible');
        cy.get('[data-testid="user-filters"]').should('be.visible');
      });
    });

    describe('Super Admin Permissions', () => {
      beforeEach(() => {
        cy.createTestUser({
          email: 'superadmin@example.com',
          password: 'Password123',
          firstName: 'Super',
          lastName: 'Admin',
          role: 'superadmin'
        });
        
        cy.loginApi('superadmin@example.com', 'Password123');
      });

      afterEach(() => {
        cy.deleteTestUser('superadmin@example.com');
      });

      it('should allow access to all system areas including dangerous operations', () => {
        const superAdminPages = [
          '/admin/system',
          '/admin/database',
          '/admin/logs',
          '/admin/maintenance'
        ];

        superAdminPages.forEach((page) => {
          cy.visit(page, { failOnStatusCode: false });
          
          // Should have access (may need to mock these pages)
          cy.url().should('include', page);
        });
      });

      it('should show destructive action capabilities', () => {
        cy.visit('/admin/users');
        
        // Super admin should see dangerous actions
        cy.get('[data-testid="bulk-delete-users"]').should('be.visible');
        cy.get('[data-testid="system-reset"]').should('be.visible');
        
        // Should require confirmation for destructive actions
        cy.get('[data-testid="bulk-delete-users"]').click();
        cy.get('[data-testid="confirmation-modal"]')
          .should('be.visible')
          .and('contain', 'This action cannot be undone');
      });
    });
  });

  describe('Session-Based Navigation Security', () => {
    beforeEach(() => {
      cy.createTestUser({
        email: 'session-test@example.com',
        password: 'Password123',
        firstName: 'Session',
        lastName: 'Test'
      });
      
      cy.loginApi('session-test@example.com', 'Password123');
    });

    afterEach(() => {
      cy.deleteTestUser('session-test@example.com');
    });

    it('should redirect to login when session expires during navigation', () => {
      cy.visit('/dashboard');
      
      // Mock session expiration
      cy.intercept('GET', '/api/auth/session', {
        statusCode: 401,
        body: { error: 'Session expired' }
      }).as('sessionExpired');

      // Try to navigate to another protected page
      cy.visit('/profile');
      
      cy.wait('@sessionExpired');
      
      // Should redirect to login
      cy.url().should('include', '/login');
      cy.get('[data-testid="session-expired-message"]')
        .should('be.visible')
        .and('contain', 'Your session has expired');
    });

    it('should handle session invalidation gracefully', () => {
      cy.visit('/dashboard');
      
      // Invalidate session by clearing cookies
      cy.clearCookies();
      
      // Try to perform an authenticated action
      cy.get('[data-testid="user-menu"]').click();
      
      // Should detect invalid session and redirect
      cy.url().should('include', '/login');
    });

    it('should prevent access with tampered session data', () => {
      cy.visit('/dashboard');
      
      // Tamper with session data
      cy.window().then((win) => {
        win.localStorage.setItem('next-auth.session-token', 'invalid-token');
      });
      
      // Try to access protected content
      cy.visit('/profile');
      
      // Should redirect to login
      cy.url().should('include', '/login');
    });
  });

  describe('Navigation Security Edge Cases', () => {
    it('should handle malformed URLs gracefully', () => {
      const malformedUrls = [
        '/dashboard/../admin',
        '/profile/../../admin/users',
        '/compare?redirect=javascript:alert(1)',
        '/admin%2Fusers',
        '/admin//users'
      ];

      malformedUrls.forEach((url) => {
        cy.visit(url, { failOnStatusCode: false });
        
        // Should either redirect to login or show appropriate error
        cy.url().should('match', /(login|404|error)/);
        
        // Should not execute any dangerous operations
        cy.window().then((win) => {
          expect(win.location.pathname).to.not.include('../');
        });
      });
    });

    it('should prevent privilege escalation through URL manipulation', () => {
      cy.createTestUser({
        email: 'privilege-test@example.com',
        password: 'Password123',
        firstName: 'Privilege',
        lastName: 'Test',
        role: 'user'
      });
      
      cy.loginApi('privilege-test@example.com', 'Password123');
      
      const escalationAttempts = [
        '/admin?role=admin',
        '/admin/users?override=true',
        '/profile?user=admin',
        '/api/admin/users?bypass=true'
      ];

      escalationAttempts.forEach((url) => {
        cy.visit(url, { failOnStatusCode: false });
        
        // Should deny access regardless of query parameters
        cy.url().should('match', /(403|unauthorized|login)/);
      });
      
      cy.deleteTestUser('privilege-test@example.com');
    });

    it('should handle concurrent session conflicts', () => {
      cy.createTestUser({
        email: 'concurrent@example.com',
        password: 'Password123',
        firstName: 'Concurrent',
        lastName: 'Test'
      });
      
      cy.loginApi('concurrent@example.com', 'Password123');
      cy.visit('/dashboard');
      
      // Simulate another session being created
      cy.intercept('GET', '/api/auth/session', {
        statusCode: 409,
        body: { 
          error: 'Session conflict',
          conflictingSession: { id: 'other-session', loginTime: new Date().toISOString() }
        }
      }).as('sessionConflict');

      // Trigger session check
      cy.reload();
      cy.wait('@sessionConflict');

      // Should show conflict resolution dialog
      cy.get('[data-testid="session-conflict-modal"]')
        .should('be.visible')
        .and('contain', 'Multiple sessions detected');
      
      // Should offer options
      cy.get('[data-testid="continue-session"]').should('be.visible');
      cy.get('[data-testid="terminate-other-sessions"]').should('be.visible');
      cy.get('[data-testid="logout-all"]').should('be.visible');
      
      cy.deleteTestUser('concurrent@example.com');
    });

    it('should validate permissions on client-side route changes', () => {
      cy.createTestUser({
        email: 'route-test@example.com',
        password: 'Password123',
        firstName: 'Route',
        lastName: 'Test',
        role: 'user'
      });
      
      cy.loginApi('route-test@example.com', 'Password123');
      cy.visit('/dashboard');
      
      // Attempt to navigate via client-side routing to admin area
      cy.window().then((win) => {
        win.history.pushState({}, '', '/admin');
      });
      
      // Should detect unauthorized navigation and block
      cy.get('[data-testid="access-denied"]')
        .should('be.visible')
        .and('contain', 'You do not have permission');
      
      cy.deleteTestUser('route-test@example.com');
    });
  });

  describe('Permission-Based UI Rendering', () => {
    describe('Dynamic Content Filtering', () => {
      beforeEach(() => {
        cy.createTestUser({
          email: 'ui-test@example.com',
          password: 'Password123',
          firstName: 'UI',
          lastName: 'Test',
          role: 'user'
        });
        
        cy.loginApi('ui-test@example.com', 'Password123');
      });

      afterEach(() => {
        cy.deleteTestUser('ui-test@example.com');
      });

      it('should show/hide navigation items based on permissions', () => {
        cy.visit('/dashboard');
        
        // Regular user navigation
        cy.get('[data-testid="nav-dashboard"]').should('be.visible');
        cy.get('[data-testid="nav-compare"]').should('be.visible');
        cy.get('[data-testid="nav-history"]').should('be.visible');
        cy.get('[data-testid="nav-profile"]').should('be.visible');
        
        // Admin navigation should be hidden
        cy.get('[data-testid="nav-admin"]').should('not.exist');
        cy.get('[data-testid="nav-user-management"]').should('not.exist');
      });

      it('should filter action buttons based on permissions', () => {
        cy.visit('/compare');
        
        // Regular actions should be available
        cy.get('[data-testid="upload-file"]').should('be.visible');
        cy.get('[data-testid="start-comparison"]').should('be.visible');
        
        // Admin-only actions should be hidden
        cy.get('[data-testid="admin-override"]').should('not.exist');
        cy.get('[data-testid="system-comparison"]').should('not.exist');
      });

      it('should display appropriate content based on user role', () => {
        cy.visit('/history');
        
        // Should show user's own comparison history
        cy.get('[data-testid="user-comparisons"]').should('be.visible');
        
        // Should not show other users' data
        cy.get('[data-testid="all-users-comparisons"]').should('not.exist');
        cy.get('[data-testid="admin-statistics"]').should('not.exist');
      });
    });

    describe('Form Field Permissions', () => {
      beforeEach(() => {
        cy.createTestUser({
          email: 'form-test@example.com',
          password: 'Password123',
          firstName: 'Form',
          lastName: 'Test',
          role: 'user'
        });
        
        cy.loginApi('form-test@example.com', 'Password123');
      });

      afterEach(() => {
        cy.deleteTestUser('form-test@example.com');
      });

      it('should disable admin-only form fields for regular users', () => {
        cy.visit('/profile');
        
        // Regular fields should be editable
        cy.get('[data-testid="first-name"]').should('not.be.disabled');
        cy.get('[data-testid="last-name"]').should('not.be.disabled');
        cy.get('[data-testid="email"]').should('not.be.disabled');
        
        // Admin fields should be disabled or hidden
        cy.get('[data-testid="user-role"]').should('be.disabled');
        cy.get('[data-testid="account-status"]').should('not.exist');
      });

      it('should validate form submissions against permissions', () => {
        cy.visit('/profile');
        
        // Attempt to modify read-only data via form manipulation
        cy.get('[data-testid="first-name"]').clear().type('Modified');
        cy.get('[data-testid="save-profile"]').click();
        
        // Should save allowed changes
        cy.get('[data-testid="save-success"]').should('be.visible');
        
        // But attempting to change role should fail
        cy.request({
          method: 'PUT',
          url: '/api/user/profile',
          body: { role: 'admin' },
          failOnStatusCode: false
        }).then((response) => {
          expect(response.status).to.eq(403);
        });
      });
    });
  });

  describe('Cross-Feature Permission Integration', () => {
    it('should maintain consistent permissions across different features', () => {
      // Test with admin user
      cy.createTestUser({
        email: 'integration-admin@example.com',
        password: 'Password123',
        firstName: 'Integration',
        lastName: 'Admin',
        role: 'admin'
      });
      
      cy.loginApi('integration-admin@example.com', 'Password123');
      
      // Check navigation permissions
      cy.visit('/admin');
      cy.get('[data-testid="admin-dashboard"]').should('be.visible');
      
      // Check API permissions
      cy.request('/api/admin/users').then((response) => {
        expect(response.status).to.eq(200);
      });
      
      // Check UI elements
      cy.visit('/dashboard');
      cy.get('[data-testid="admin-menu"]').should('be.visible');
      
      cy.deleteTestUser('integration-admin@example.com');
    });

    it('should handle permission changes during active session', () => {
      cy.createTestUser({
        email: 'permission-change@example.com',
        password: 'Password123',
        firstName: 'Permission',
        lastName: 'Change',
        role: 'admin'
      });
      
      cy.loginApi('permission-change@example.com', 'Password123');
      cy.visit('/admin');
      
      // Should have admin access initially
      cy.get('[data-testid="admin-dashboard"]').should('be.visible');
      
      // Simulate permission downgrade
      cy.intercept('GET', '/api/auth/session', {
        statusCode: 200,
        body: {
          user: {
            id: 'test-user',
            email: 'permission-change@example.com',
            role: 'user' // Role changed to user
          }
        }
      }).as('downgradedSession');
      
      // Trigger session refresh
      cy.reload();
      cy.wait('@downgradedSession');
      
      // Should lose admin access
      cy.url().should('include', '403');
      cy.get('[data-testid="access-denied"]').should('be.visible');
      
      cy.deleteTestUser('permission-change@example.com');
    });
  });
});