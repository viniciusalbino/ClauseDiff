/**
 * Custom Render Functions with Providers
 * 
 * Provides enhanced render functions that wrap components with necessary providers
 * for comprehensive testing including NextAuth, Router, and other context providers.
 */

import React from 'react';
import { render, RenderOptions, RenderResult } from '@testing-library/react';
import { SessionProvider } from 'next-auth/react';
import { useRouter } from 'next/router';
import { MockSessionProvider } from '../__mocks__/nextauth/provider';
import { MockSession } from '../__mocks__/nextauth/session';

// Mock router data
interface MockRouterData {
  pathname?: string;
  query?: Record<string, string | string[]>;
  asPath?: string;
  push?: jest.Mock;
  replace?: jest.Mock;
  back?: jest.Mock;
  forward?: jest.Mock;
  refresh?: jest.Mock;
}

// Custom render options
interface CustomRenderOptions extends Omit<RenderOptions, 'wrapper'> {
  // Session provider options
  session?: MockSession | null;
  withSessionProvider?: boolean;
  
  // Router options
  router?: MockRouterData;
  withRouter?: boolean;
  
  // Other provider options
  withErrorBoundary?: boolean;
  
  // Custom wrapper component
  wrapper?: React.ComponentType<{ children: React.ReactNode }>;
}

/**
 * Mock router implementation
 */
function createMockRouter(routerData: MockRouterData = {}): any {
  return {
    pathname: '/',
    query: {},
    asPath: '/',
    push: jest.fn().mockResolvedValue(true),
    replace: jest.fn().mockResolvedValue(true),
    back: jest.fn(),
    forward: jest.fn(),
    refresh: jest.fn(),
    ...routerData
  };
}

/**
 * Error boundary component for testing error scenarios
 */
class TestErrorBoundary extends React.Component<
  { children: React.ReactNode; onError?: (error: Error) => void },
  { hasError: boolean; error?: Error }
> {
  constructor(props: any) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    this.props.onError?.(error);
    console.error('Test Error Boundary caught an error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div data-testid="error-boundary">
          <h2>Something went wrong in test</h2>
          <details>
            <summary>Error details</summary>
            <pre>{this.state.error?.message}</pre>
          </details>
        </div>
      );
    }

    return this.props.children;
  }
}

/**
 * Create a wrapper component with providers
 */
function createWrapper(options: CustomRenderOptions) {
  const {
    session,
    withSessionProvider = false,
    router,
    withRouter = false,
    withErrorBoundary = false,
    wrapper: CustomWrapper
  } = options;

  return function Wrapper({ children }: { children: React.ReactNode }) {
    let component = children;

    // Wrap with custom wrapper if provided
    if (CustomWrapper) {
      component = <CustomWrapper>{component}</CustomWrapper>;
    }

    // Wrap with error boundary if requested
    if (withErrorBoundary) {
      component = <TestErrorBoundary>{component}</TestErrorBoundary>;
    }

    // Wrap with session provider if requested
    if (withSessionProvider) {
      component = (
        <MockSessionProvider session={session}>
          {component}
        </MockSessionProvider>
      );
    }

    // Mock router if requested
    if (withRouter) {
      const mockRouter = createMockRouter(router);
      // Note: In a real implementation, you might need to mock useRouter here
      // For now, we'll assume the router is mocked at the module level
    }

    return <>{component}</>;
  };
}

/**
 * Enhanced render function with providers
 */
export function renderWithProviders(
  ui: React.ReactElement,
  options: CustomRenderOptions = {}
): RenderResult & { mockRouter?: any } {
  const {
    session,
    router,
    withRouter = false,
    ...renderOptions
  } = options;

  const mockRouter = withRouter ? createMockRouter(router) : undefined;

  // Mock the router if requested
  if (withRouter && mockRouter) {
    (useRouter as jest.Mock).mockReturnValue(mockRouter);
  }

  const Wrapper = createWrapper(options);

  const result = render(ui, {
    wrapper: Wrapper,
    ...renderOptions
  });

  return {
    ...result,
    mockRouter
  };
}

/**
 * Render with authenticated session
 */
export function renderWithAuth(
  ui: React.ReactElement,
  sessionData?: Partial<MockSession>,
  options: Omit<CustomRenderOptions, 'session' | 'withSessionProvider'> = {}
): RenderResult {
  const defaultSession: MockSession = {
    user: {
      id: 'test-user-1',
      email: 'test@example.com',
      name: 'Test User',
      role: 'USER'
    },
    expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
  };

  return renderWithProviders(ui, {
    ...options,
    session: { ...defaultSession, ...sessionData },
    withSessionProvider: true
  });
}

/**
 * Render with unauthenticated session
 */
export function renderWithoutAuth(
  ui: React.ReactElement,
  options: Omit<CustomRenderOptions, 'session' | 'withSessionProvider'> = {}
): RenderResult {
  return renderWithProviders(ui, {
    ...options,
    session: null,
    withSessionProvider: true
  });
}

/**
 * Render with loading session
 */
export function renderWithLoadingAuth(
  ui: React.ReactElement,
  options: Omit<CustomRenderOptions, 'session' | 'withSessionProvider'> = {}
): RenderResult {
  return renderWithProviders(ui, {
    ...options,
    session: null,
    withSessionProvider: true
  });
}

/**
 * Render with admin session
 */
export function renderWithAdmin(
  ui: React.ReactElement,
  sessionData?: Partial<MockSession>,
  options: Omit<CustomRenderOptions, 'session' | 'withSessionProvider'> = {}
): RenderResult {
  const adminSession: MockSession = {
    user: {
      id: 'admin-user-1',
      email: 'admin@example.com',
      name: 'Admin User',
      role: 'ADMIN'
    },
    expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
  };

  return renderWithProviders(ui, {
    ...options,
    session: { ...adminSession, ...sessionData },
    withSessionProvider: true
  });
}

/**
 * Render with router
 */
export function renderWithRouter(
  ui: React.ReactElement,
  routerData?: MockRouterData,
  options: Omit<CustomRenderOptions, 'router' | 'withRouter'> = {}
): RenderResult & { mockRouter: any } {
  const result = renderWithProviders(ui, {
    ...options,
    router: routerData,
    withRouter: true
  });

  return result as RenderResult & { mockRouter: any };
}

/**
 * Render with error boundary
 */
export function renderWithErrorBoundary(
  ui: React.ReactElement,
  onError?: (error: Error) => void,
  options: Omit<CustomRenderOptions, 'withErrorBoundary'> = {}
): RenderResult {
  const ErrorWrapper = ({ children }: { children: React.ReactNode }) => (
    <TestErrorBoundary onError={onError}>
      {children}
    </TestErrorBoundary>
  );

  return renderWithProviders(ui, {
    ...options,
    wrapper: ErrorWrapper,
    withErrorBoundary: false // We're handling it manually
  });
}

/**
 * Comprehensive render with all providers
 */
export function renderWithAllProviders(
  ui: React.ReactElement,
  options: CustomRenderOptions = {}
): RenderResult & { mockRouter?: any } {
  return renderWithProviders(ui, {
    withSessionProvider: true,
    withRouter: true,
    withErrorBoundary: true,
    session: {
      user: {
        id: 'test-user-1',
        email: 'test@example.com',
        name: 'Test User',
        role: 'USER'
      },
      expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
    },
    ...options
  });
}

/**
 * Create a custom render function with predefined options
 */
export function createCustomRender(defaultOptions: CustomRenderOptions) {
  return function customRender(
    ui: React.ReactElement,
    options: CustomRenderOptions = {}
  ): RenderResult & { mockRouter?: any } {
    return renderWithProviders(ui, {
      ...defaultOptions,
      ...options
    });
  };
}

// Export commonly used render functions
export {
  render as baseRender,
  TestErrorBoundary
};

// Default export
export default renderWithProviders; 