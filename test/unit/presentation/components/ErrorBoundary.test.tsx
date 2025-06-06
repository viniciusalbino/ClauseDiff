import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { ErrorBoundary } from '../../../../src/presentation/components/ErrorBoundary';

// Test component that throws errors
const ThrowingComponent = ({ shouldThrow = true, errorMessage = 'Test error' }: {
  shouldThrow?: boolean;
  errorMessage?: string;
}) => {
  if (shouldThrow) {
    throw new Error(errorMessage);
  }
  return <div data-testid="success-component">Component rendered successfully</div>;
};

describe('ErrorBoundary', () => {
  beforeEach(() => {
    // Suppress console.error in tests
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('should render children when no error occurs', () => {
    render(
      <ErrorBoundary>
        <ThrowingComponent shouldThrow={false} />
      </ErrorBoundary>
    );

    expect(screen.getByTestId('success-component')).toBeInTheDocument();
    expect(screen.getByText('Component rendered successfully')).toBeInTheDocument();
  });

  it('should catch and display error with default fallback', () => {
    render(
      <ErrorBoundary>
        <ThrowingComponent errorMessage="Network connection failed" />
      </ErrorBoundary>
    );

    expect(screen.getByText('Component Error')).toBeInTheDocument();
    expect(screen.getByText(/network error occurred/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /reload page/i })).toBeInTheDocument();
  });

  it('should display different error types correctly', () => {
    const { rerender } = render(
      <ErrorBoundary level="page">
        <ThrowingComponent errorMessage="Permission denied" />
      </ErrorBoundary>
    );

    expect(screen.getByText('Page Error')).toBeInTheDocument();
    expect(screen.getByText(/unauthorized access/i)).toBeInTheDocument();

    rerender(
      <ErrorBoundary level="section">
        <ThrowingComponent errorMessage="Validation failed" />
      </ErrorBoundary>
    );

    expect(screen.getByText('Section Error')).toBeInTheDocument();
    expect(screen.getByText(/please check your input/i)).toBeInTheDocument();
  });

  it('should call onError callback when error occurs', () => {
    const onError = jest.fn();

    render(
      <ErrorBoundary onError={onError}>
        <ThrowingComponent errorMessage="Test error" />
      </ErrorBoundary>
    );

    expect(onError).toHaveBeenCalledWith(
      expect.any(Error),
      expect.objectContaining({
        componentStack: expect.any(String)
      })
    );
  });

  it('should handle retry functionality', async () => {
    let shouldThrow = true;
    const TestComponent = () => {
      if (shouldThrow) {
        throw new Error('Temporary error');
      }
      return <div data-testid="success-after-retry">Success after retry</div>;
    };

    render(
      <ErrorBoundary enableRetry={true} maxRetries={3}>
        <TestComponent />
      </ErrorBoundary>
    );

    // Error should be displayed initially
    expect(screen.getByText('Component Error')).toBeInTheDocument();

    // Click retry button
    const retryButton = screen.getByRole('button', { name: /retry/i });
    
    // Simulate fixing the error
    shouldThrow = false;
    
    fireEvent.click(retryButton);

    // After retry, success component should render
    await waitFor(() => {
      expect(screen.getByTestId('success-after-retry')).toBeInTheDocument();
    });
  });

  it('should disable retry after max attempts', () => {
    render(
      <ErrorBoundary enableRetry={true} maxRetries={1}>
        <ThrowingComponent />
      </ErrorBoundary>
    );

    const retryButton = screen.getByRole('button', { name: /retry/i });
    
    // First retry
    fireEvent.click(retryButton);
    
    // Should show retry count
    expect(screen.getByText(/retry.*\(1\/1\)/i)).toBeInTheDocument();
    
    // Click retry again
    fireEvent.click(retryButton);
    
    // Retry button should be disabled or show max retries reached
    expect(screen.getByText('Retry attempts: 1/1')).toBeInTheDocument();
  });

  it('should render custom fallback when provided', () => {
    const CustomFallback = (error: Error, retry: () => void) => (
      <div data-testid="custom-fallback">
        <h2>Custom Error UI</h2>
        <p>Error: {error.message}</p>
        <button onClick={retry}>Custom Retry</button>
      </div>
    );

    render(
      <ErrorBoundary fallback={CustomFallback}>
        <ThrowingComponent errorMessage="Custom error" />
      </ErrorBoundary>
    );

    expect(screen.getByTestId('custom-fallback')).toBeInTheDocument();
    expect(screen.getByText('Custom Error UI')).toBeInTheDocument();
    expect(screen.getByText('Error: Custom error')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Custom Retry' })).toBeInTheDocument();
  });

  it('should show error details in development mode', () => {
    const originalEnv = process.env.NODE_ENV;
    // Mock NODE_ENV properly
    Object.defineProperty(process.env, 'NODE_ENV', {
      value: 'development',
      writable: true
    });

    render(
      <ErrorBoundary>
        <ThrowingComponent errorMessage="Development error" />
      </ErrorBoundary>
    );

    expect(screen.getByText('Error Details')).toBeInTheDocument();

    // Restore original value
    Object.defineProperty(process.env, 'NODE_ENV', {
      value: originalEnv,
      writable: true
    });
  });

  it('should handle different error severities', () => {
    const { rerender } = render(
      <ErrorBoundary level="page">
        <ThrowingComponent errorMessage="Critical resource error" />
      </ErrorBoundary>
    );

    expect(screen.getByText(/the page encountered an unexpected error/i)).toBeInTheDocument();

    rerender(
      <ErrorBoundary level="component">
        <ThrowingComponent errorMessage="Processing failed" />
      </ErrorBoundary>
    );

    expect(screen.getByText(/this component failed to load/i)).toBeInTheDocument();
  });

  it('should reload page when reload button is clicked', () => {
    // Mock window.location.reload
    const mockReload = jest.fn();
    Object.defineProperty(window, 'location', {
      value: { reload: mockReload },
      writable: true
    });

    render(
      <ErrorBoundary>
        <ThrowingComponent />
      </ErrorBoundary>
    );

    const reloadButton = screen.getByRole('button', { name: /reload page/i });
    fireEvent.click(reloadButton);

    expect(mockReload).toHaveBeenCalled();
  });
}); 