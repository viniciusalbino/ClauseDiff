/**
 * Test Utilities Integration Test
 * 
 * Comprehensive test suite to verify all test utilities work correctly
 * and integrate properly with each other.
 */

import React from 'react';
import { screen, waitFor } from '@testing-library/react';
import {
  renderWithAuth,
  renderWithAdmin,
  renderWithoutAuth,
  renderWithErrorBoundary,
  auth,
  asyncTestUtils,
  createTestError,
  errorThrowers,
  testUtils,
  testScenarios
} from '../../utils';
import { mockSignIn } from '../../__mocks__/nextauth';

// Simple test components
const TestComponent = ({ text = 'Test Component' }: { text?: string }) =>
  React.createElement('div', { 'data-testid': 'test-component' }, text);

const AuthenticatedComponent = () => {
  return React.createElement(
    'div',
    { 'data-testid': 'authenticated-component' },
    React.createElement('h1', null, 'Welcome, authenticated user!'),
    React.createElement('p', null, 'You have access to this content.')
  );
};

const AdminComponent = () => {
  return React.createElement(
    'div',
    { 'data-testid': 'admin-component' },
    React.createElement('h1', null, 'Admin Dashboard'),
    React.createElement('p', null, 'Admin-only content here.')
  );
};

describe('Test Utilities Integration', () => {
  describe('Render Utilities', () => {
    it('should render component with authenticated user', async () => {
      const { getByTestId } = renderWithAuth(React.createElement(AuthenticatedComponent));
      
      expect(getByTestId('authenticated-component')).toBeInTheDocument();
      expect(screen.getByText('Welcome, authenticated user!')).toBeInTheDocument();
    });

    it('should render component with admin user', async () => {
      const { getByTestId } = renderWithAdmin(React.createElement(AdminComponent));
      
      expect(getByTestId('admin-component')).toBeInTheDocument();
      expect(screen.getByText('Admin Dashboard')).toBeInTheDocument();
    });

    it('should render component without authentication', async () => {
      const { getByTestId } = renderWithoutAuth(React.createElement(TestComponent, { text: 'Guest content' }));
      
      expect(getByTestId('test-component')).toBeInTheDocument();
      expect(screen.getByText('Guest content')).toBeInTheDocument();
    });

    it('should render component with error boundary', async () => {
      const ThrowingComponent = errorThrowers.ThrowingComponent;
      const onError = jest.fn();
      
      const { getByTestId } = renderWithErrorBoundary(
        React.createElement(ThrowingComponent, { error: createTestError.basic('Test error') }),
        onError
      );
      
      await waitFor(() => {
        expect(getByTestId('error-boundary')).toBeInTheDocument();
      });
      
      expect(onError).toHaveBeenCalled();
    });
  });

  describe('Authentication Utilities', () => {
    it('should create test session with correct role', async () => {
      const session = auth.createTestSession('ADMIN');
      
      expect(auth.isLoggedIn(session)).toBe(true);
      expect(auth.isAdmin(session)).toBe(true);
      expect(auth.isUser(session)).toBe(false);
    });

    it('should validate authentication state', async () => {
      const userSession = auth.createTestSession('USER');
      const adminSession = auth.createTestSession('ADMIN');
      
      // Test authentication assertions
      auth.isAuthenticated(userSession);
      auth.hasRole(userSession, 'USER');
      auth.hasRole(adminSession, 'ADMIN');
      
      // Test permission checks
      expect(auth.canRead(userSession)).toBe(true);
      expect(auth.canWrite(userSession)).toBe(true);
    });

    it('should simulate login flow', async () => {
      const session = await auth.simulateLogin('USER');
      
      expect(session).toBeTruthy();
      expect(session.user.role).toBe('USER');
      expect(session.user.id).toBeDefined();
      expect(session.user.email).toBeDefined();
    });

    it('should simulate failed login', async () => {
      const expectedResult = await auth.simulateFailedLogin('Invalid credentials');
      
      // Verify the expected result structure
      expect(expectedResult.error).toBe('Invalid credentials');
      expect(expectedResult.ok).toBe(false);
      expect(expectedResult.status).toBe(401);
      
      // Verify that the mock was configured correctly
      expect(mockSignIn).toHaveBeenCalledTimes(0); // Should not have been called yet
      expect(typeof mockSignIn).toBe('function');
    });
  });

  describe('Async Utilities', () => {
    it('should handle promise delays', async () => {
      const startTime = Date.now();
      await asyncTestUtils.promiseUtils.delay(100);
      const endTime = Date.now();
      
      expect(endTime - startTime).toBeGreaterThanOrEqual(90); // Allow some variance
    });

    it('should test promise resolution', async () => {
      const testData = { message: 'success' };
      const promise = asyncTestUtils.promiseUtils.delayedResolve(testData, 50);
      
      const result = await asyncTestUtils.asyncPatterns.expectToResolve(promise, testData);
      expect(result).toEqual(testData);
    });

    it('should test promise rejection', async () => {
      const error = new Error('Test error');
      const promise = asyncTestUtils.promiseUtils.delayedReject(error, 50);
      
      const caughtError = await asyncTestUtils.asyncPatterns.expectToReject(promise, 'Test error');
      expect(caughtError.message).toBe('Test error');
    });

    it('should handle controllable promises', async () => {
      const { promise, resolve } = asyncTestUtils.promiseUtils.controllable<string>();
      
      setTimeout(() => resolve('resolved'), 10);
      
      const result = await promise;
      expect(result).toBe('resolved');
    });
  });

  describe('Error Utilities', () => {
    it('should create different types of test errors', () => {
      const networkError = createTestError.network('Connection failed', 500);
      const validationError = createTestError.validation('Invalid input', 'email');
      const authError = createTestError.auth('Unauthorized');
      
      expect(networkError.code).toBe('NETWORK_ERROR');
      expect(networkError.statusCode).toBe(500);
      
      expect(validationError.code).toBe('VALIDATION_ERROR');
      expect(validationError.context?.field).toBe('email');
      
      expect(authError.code).toBe('AUTH_ERROR');
      expect(authError.statusCode).toBe(401);
    });

    it('should test synchronous error throwing', () => {
      const error = createTestError.basic('Sync error');
      const thrower = errorThrowers.throwSync(error);
      
      expect(thrower).toThrow('Sync error');
    });

    it('should test asynchronous error throwing', async () => {
      const error = createTestError.basic('Async error');
      const thrower = errorThrowers.throwAsync(error, 10);
      
      await expect(thrower()).rejects.toThrow('Async error');
    });
  });

  describe('Custom Matchers', () => {
    it('should use custom authentication matchers', async () => {
      const session = auth.createTestSession('ADMIN', {
        user: {
          id: 'test-1',
          email: 'admin@test.com',
          name: 'Admin User',
          role: 'ADMIN',
          permissions: ['read:users', 'write:users']
        }
      });
      
      expect(session).toBeAuthenticated();
      expect(session).toHaveRole('ADMIN');
      expect(session).toHavePermission('read:users');
      expect(session).toHaveAnyPermission(['read:users', 'delete:users']);
    });

    it('should use custom error matchers', async () => {
      const errorFunction = () => {
        throw new Error('Custom error message');
      };
      
      expect(errorFunction).toThrowWithMessage('Custom error');
      
      const rejectedPromise = Promise.reject(new Error('Promise error'));
      await expect(rejectedPromise).toRejectWithMessage('Promise error');
    });

    it('should use custom array matchers', () => {
      const testArray = [
        { id: 1, name: 'Item 1' },
        { id: 2, name: 'Item 2' },
        { id: 3, name: 'Item 3' }
      ];
      
      expect(testArray).toBeArrayOfLength(3);
      expect(testArray).toContainObject({ id: 2, name: 'Item 2' });
    });

    it('should use custom business logic matchers', () => {
      expect('test@example.com').toBeValidEmail();
      expect('https://example.com').toBeValidUrl();
      
      const apiResponse = {
        id: 'string',
        name: 'string',
        count: 'number'
      };
      
      const testData = {
        id: 'test-123',
        name: 'Test Item',
        count: 42
      };
      
      expect(testData).toMatchApiResponse(apiResponse);
    });
  });

  describe('Test Scenarios', () => {
    it('should provide authentication scenarios', async () => {
      const userSession = await testScenarios.auth.authenticatedUser();
      const adminSession = await testScenarios.auth.authenticatedAdmin();
      const noSession = await testScenarios.auth.unauthenticated();
      
      expect(userSession?.user?.role).toBe('USER');
      expect(adminSession?.user?.role).toBe('ADMIN');
      expect(noSession).toBeNull();
    });

    it('should provide error scenarios', async () => {
      const networkError = await testScenarios.errors.networkError(404);
      const validationError = await testScenarios.errors.validationError('email');
      const authError = await testScenarios.errors.authError();
      
      expect(networkError.statusCode).toBe(404);
      expect(validationError.context?.field).toBe('email');
      expect(authError.code).toBe('AUTH_ERROR');
    });

    it('should provide loading scenarios', async () => {
      const successPromise = testScenarios.loading.async({ data: 'success' }, 50);
      const errorPromise = testScenarios.loading.error('Failed to load', 50);
      
      const successResult = await successPromise;
      expect(successResult.data).toBe('success');
      
      await expect(errorPromise).rejects.toThrow('Failed to load');
    });
  });

  describe('Test Utils Quick Access', () => {
    it('should provide quick render functions', async () => {
      const authResult = await testUtils.renderAuth(React.createElement(TestComponent, { text: 'Auth test' }));
      const adminResult = await testUtils.renderAdmin(React.createElement(TestComponent, { text: 'Admin test' }));
      const guestResult = await testUtils.renderGuest(React.createElement(TestComponent, { text: 'Guest test' }));
      
      expect(authResult.getByText('Auth test')).toBeInTheDocument();
      expect(adminResult.getByText('Admin test')).toBeInTheDocument();
      expect(guestResult.getByText('Guest test')).toBeInTheDocument();
    });

    it('should provide quick async utilities', async () => {
      const startTime = Date.now();
      await testUtils.delay(50);
      const endTime = Date.now();
      
      expect(endTime - startTime).toBeGreaterThanOrEqual(40);
    });

    it('should provide quick error testing', async () => {
      const errorFunction = async () => {
        throw new Error('Quick error test');
      };
      
      const error = await testUtils.expectError(errorFunction, 'Quick error');
      expect(error.message).toContain('Quick error');
    });

    it('should provide quick auth session creation', async () => {
      const userSession = await testUtils.createAuthSession('USER');
      const adminSession = await testUtils.createAuthSession('ADMIN');
      
      expect(userSession.user.role).toBe('USER');
      expect(adminSession.user.role).toBe('ADMIN');
    });
  });

  describe('Global Test Utilities', () => {
    it('should have global test utilities available', async () => {
      expect(globalThis.testUtils).toBeDefined();
      expect(typeof globalThis.testUtils.delay).toBe('function');
      expect(typeof globalThis.testUtils.waitForUpdate).toBe('function');
      expect(typeof globalThis.testUtils.flushPromises).toBe('function');
      
      // Test global delay function
      const startTime = Date.now();
      await globalThis.testUtils.delay(30);
      const endTime = Date.now();
      
      expect(endTime - startTime).toBeGreaterThanOrEqual(25);
    });
  });
}); 