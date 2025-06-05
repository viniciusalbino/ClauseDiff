import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { Toolbar } from '@/components/Toolbar';

describe('Toolbar Component', () => {
  // Helper function to create mock props
  const createMockProps = (overrides = {}) => ({
    onCompare: jest.fn(),
    onExportPdf: jest.fn(),
    onExportCsv: jest.fn(),
    canCompare: true,
    canExport: true,
    isComparing: false,
    ...overrides,
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Basic Rendering', () => {
    it('should render the toolbar with title', () => {
      const props = createMockProps();
      render(<Toolbar {...props} />);

      expect(screen.getByText('ClauseDiff')).toBeInTheDocument();
    });

    it('should render compare button', () => {
      const props = createMockProps();
      render(<Toolbar {...props} />);

      expect(screen.getByRole('button', { name: /comparar/i })).toBeInTheDocument();
    });

    it('should render export CSV button', () => {
      const props = createMockProps();
      render(<Toolbar {...props} />);

      expect(screen.getByRole('button', { name: /exportar csv/i })).toBeInTheDocument();
    });

    it('should render with correct icons', () => {
      const props = createMockProps();
      const { container } = render(<Toolbar {...props} />);

      // Check for SVG icons (CompareIcon and CsvIcon)
      const svgElements = container.querySelectorAll('svg');
      expect(svgElements).toHaveLength(2);
    });
  });

  describe('Button States', () => {
    describe('Compare Button', () => {
      it('should be enabled when canCompare is true and not comparing', () => {
        const props = createMockProps({ canCompare: true, isComparing: false });
        render(<Toolbar {...props} />);

        const compareButton = screen.getByRole('button', { name: /comparar/i });
        expect(compareButton).not.toBeDisabled();
      });

      it('should be disabled when canCompare is false', () => {
        const props = createMockProps({ canCompare: false, isComparing: false });
        render(<Toolbar {...props} />);

        const compareButton = screen.getByRole('button', { name: /comparar/i });
        expect(compareButton).toBeDisabled();
      });

      it('should be disabled when isComparing is true', () => {
        const props = createMockProps({ canCompare: true, isComparing: true });
        render(<Toolbar {...props} />);

        const compareButton = screen.getByRole('button', { name: /comparando/i });
        expect(compareButton).toBeDisabled();
      });

      it('should be disabled when both canCompare is false and isComparing is true', () => {
        const props = createMockProps({ canCompare: false, isComparing: true });
        render(<Toolbar {...props} />);

        const compareButton = screen.getByRole('button', { name: /comparando/i });
        expect(compareButton).toBeDisabled();
      });

      it('should show "Comparando..." text when isComparing is true', () => {
        const props = createMockProps({ isComparing: true });
        render(<Toolbar {...props} />);

        expect(screen.getByText('Comparando...')).toBeInTheDocument();
        expect(screen.queryByText('Comparar')).not.toBeInTheDocument();
      });

      it('should show "Comparar" text when isComparing is false', () => {
        const props = createMockProps({ isComparing: false });
        render(<Toolbar {...props} />);

        expect(screen.getByText('Comparar')).toBeInTheDocument();
        expect(screen.queryByText('Comparando...')).not.toBeInTheDocument();
      });
    });

    describe('Export CSV Button', () => {
      it('should be enabled when canExport is true and not comparing', () => {
        const props = createMockProps({ canExport: true, isComparing: false });
        render(<Toolbar {...props} />);

        const exportButton = screen.getByRole('button', { name: /exportar csv/i });
        expect(exportButton).not.toBeDisabled();
      });

      it('should be disabled when canExport is false', () => {
        const props = createMockProps({ canExport: false, isComparing: false });
        render(<Toolbar {...props} />);

        const exportButton = screen.getByRole('button', { name: /exportar csv/i });
        expect(exportButton).toBeDisabled();
      });

      it('should be disabled when isComparing is true', () => {
        const props = createMockProps({ canExport: true, isComparing: true });
        render(<Toolbar {...props} />);

        const exportButton = screen.getByRole('button', { name: /exportar csv/i });
        expect(exportButton).toBeDisabled();
      });

      it('should be disabled when both canExport is false and isComparing is true', () => {
        const props = createMockProps({ canExport: false, isComparing: true });
        render(<Toolbar {...props} />);

        const exportButton = screen.getByRole('button', { name: /exportar csv/i });
        expect(exportButton).toBeDisabled();
      });
    });
  });

  describe('Button Interactions', () => {
    it('should call onCompare when compare button is clicked', () => {
      const props = createMockProps({ canCompare: true, isComparing: false });
      render(<Toolbar {...props} />);

      const compareButton = screen.getByRole('button', { name: /comparar/i });
      fireEvent.click(compareButton);

      expect(props.onCompare).toHaveBeenCalledTimes(1);
    });

    it('should not call onCompare when compare button is disabled', () => {
      const props = createMockProps({ canCompare: false, isComparing: false });
      render(<Toolbar {...props} />);

      const compareButton = screen.getByRole('button', { name: /comparar/i });
      fireEvent.click(compareButton);

      expect(props.onCompare).not.toHaveBeenCalled();
    });

    it('should call onExportCsv when export CSV button is clicked', () => {
      const props = createMockProps({ canExport: true, isComparing: false });
      render(<Toolbar {...props} />);

      const exportButton = screen.getByRole('button', { name: /exportar csv/i });
      fireEvent.click(exportButton);

      expect(props.onExportCsv).toHaveBeenCalledTimes(1);
    });

    it('should not call onExportCsv when export CSV button is disabled', () => {
      const props = createMockProps({ canExport: false, isComparing: false });
      render(<Toolbar {...props} />);

      const exportButton = screen.getByRole('button', { name: /exportar csv/i });
      fireEvent.click(exportButton);

      expect(props.onExportCsv).not.toHaveBeenCalled();
    });

    it('should handle multiple rapid clicks correctly', () => {
      const props = createMockProps({ canCompare: true, canExport: true, isComparing: false });
      render(<Toolbar {...props} />);

      const compareButton = screen.getByRole('button', { name: /comparar/i });
      const exportButton = screen.getByRole('button', { name: /exportar csv/i });

      // Rapid clicks
      fireEvent.click(compareButton);
      fireEvent.click(exportButton);
      fireEvent.click(compareButton);
      fireEvent.click(exportButton);

      expect(props.onCompare).toHaveBeenCalledTimes(2);
      expect(props.onExportCsv).toHaveBeenCalledTimes(2);
    });
  });

  describe('Styling and Layout', () => {
    it('should apply correct container styling', () => {
      const props = createMockProps();
      const { container } = render(<Toolbar {...props} />);

      const toolbarContainer = container.firstChild as HTMLElement;
      expect(toolbarContainer).toHaveClass(
        'w-full',
        'bg-white',
        'shadow-md',
        'p-3',
        'flex',
        'flex-col',
        'sm:flex-row',
        'items-center',
        'justify-between',
        'sticky',
        'top-0',
        'z-10'
      );
    });

    it('should apply correct title styling', () => {
      const props = createMockProps();
      render(<Toolbar {...props} />);

      const title = screen.getByText('ClauseDiff');
      expect(title).toHaveClass('font-bold', 'text-blue-800', 'mb-2', 'sm:mb-0');
    });

    it('should apply correct button container styling', () => {
      const props = createMockProps();
      const { container } = render(<Toolbar {...props} />);

      const buttonContainer = container.querySelector('.flex.items-center.space-x-2.sm\\:space-x-3');
      expect(buttonContainer).toBeInTheDocument();
    });

    it('should apply correct compare button styling', () => {
      const props = createMockProps({ canCompare: true, isComparing: false });
      render(<Toolbar {...props} />);

      const compareButton = screen.getByRole('button', { name: /comparar/i });
      expect(compareButton).toHaveClass(
        'flex',
        'items-center',
        'space-x-2',
        'px-4',
        'py-2',
        'rounded-md',
        'bg-blue-800',
        'text-white',
        'hover:bg-blue-700',
        'transition-colors'
      );
    });

    it('should apply correct export CSV button styling', () => {
      const props = createMockProps({ canExport: true, isComparing: false });
      render(<Toolbar {...props} />);

      const exportButton = screen.getByRole('button', { name: /exportar csv/i });
      expect(exportButton).toHaveClass(
        'flex',
        'items-center',
        'space-x-2',
        'px-4',
        'py-2',
        'rounded-md',
        'bg-gray-700',
        'text-white',
        'hover:bg-gray-600',
        'transition-colors'
      );
    });

    it('should apply disabled styling when buttons are disabled', () => {
      const props = createMockProps({ canCompare: false, canExport: false });
      render(<Toolbar {...props} />);

      const compareButton = screen.getByRole('button', { name: /comparar/i });
      const exportButton = screen.getByRole('button', { name: /exportar csv/i });

      expect(compareButton).toHaveClass('opacity-50', 'cursor-not-allowed');
      expect(exportButton).toHaveClass('opacity-50', 'cursor-not-allowed');
    });
  });

  describe('Responsive Behavior', () => {
    it('should have responsive flex direction classes', () => {
      const props = createMockProps();
      const { container } = render(<Toolbar {...props} />);

      const toolbarContainer = container.firstChild as HTMLElement;
      expect(toolbarContainer).toHaveClass('flex-col', 'sm:flex-row');
    });

    it('should have responsive spacing classes for title', () => {
      const props = createMockProps();
      render(<Toolbar {...props} />);

      const title = screen.getByText('ClauseDiff');
      expect(title).toHaveClass('mb-2', 'sm:mb-0');
    });

    it('should have responsive spacing classes for button container', () => {
      const props = createMockProps();
      const { container } = render(<Toolbar {...props} />);

      const buttonContainer = container.querySelector('.space-x-2.sm\\:space-x-3');
      expect(buttonContainer).toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    it('should have proper button roles', () => {
      const props = createMockProps();
      render(<Toolbar {...props} />);

      const buttons = screen.getAllByRole('button');
      expect(buttons).toHaveLength(2);
    });

    it('should have focus styles for keyboard navigation', () => {
      const props = createMockProps();
      render(<Toolbar {...props} />);

      const compareButton = screen.getByRole('button', { name: /comparar/i });
      const exportButton = screen.getByRole('button', { name: /exportar csv/i });

      expect(compareButton).toHaveClass('focus:outline-none', 'focus:ring-2', 'focus:ring-blue-500', 'focus:ring-opacity-50');
      expect(exportButton).toHaveClass('focus:outline-none', 'focus:ring-2', 'focus:ring-blue-500', 'focus:ring-opacity-50');
    });

    it('should be keyboard accessible', () => {
      const props = createMockProps({ canCompare: true, canExport: true });
      render(<Toolbar {...props} />);

      const compareButton = screen.getByRole('button', { name: /comparar/i });
      const exportButton = screen.getByRole('button', { name: /exportar csv/i });

      // Test that buttons can receive focus
      compareButton.focus();
      expect(document.activeElement).toBe(compareButton);

      exportButton.focus();
      expect(document.activeElement).toBe(exportButton);

      // Test that buttons are clickable (keyboard users can activate with Enter/Space)
      fireEvent.click(compareButton);
      expect(props.onCompare).toHaveBeenCalledTimes(1);

      fireEvent.click(exportButton);
      expect(props.onExportCsv).toHaveBeenCalledTimes(1);
    });

    it('should have proper heading structure', () => {
      const props = createMockProps();
      render(<Toolbar {...props} />);

      const heading = screen.getByRole('heading', { level: 1 });
      expect(heading).toHaveTextContent('ClauseDiff');
    });
  });

  describe('Icon Integration', () => {
    it('should render icons with correct size', () => {
      const props = createMockProps();
      const { container } = render(<Toolbar {...props} />);

      const svgElements = container.querySelectorAll('svg');
      svgElements.forEach(svg => {
        expect(svg).toHaveAttribute('width', '18');
        expect(svg).toHaveAttribute('height', '18');
      });
    });

    it('should render icons with correct color classes', () => {
      const props = createMockProps();
      const { container } = render(<Toolbar {...props} />);

      const svgElements = container.querySelectorAll('svg');
      svgElements.forEach(svg => {
        expect(svg).toHaveClass('text-white');
      });
    });
  });

  describe('Edge Cases', () => {
    it('should handle all props being false', () => {
      const props = createMockProps({
        canCompare: false,
        canExport: false,
        isComparing: false,
      });

      expect(() => {
        render(<Toolbar {...props} />);
      }).not.toThrow();

      const compareButton = screen.getByRole('button', { name: /comparar/i });
      const exportButton = screen.getByRole('button', { name: /exportar csv/i });

      expect(compareButton).toBeDisabled();
      expect(exportButton).toBeDisabled();
    });

    it('should handle all props being true', () => {
      const props = createMockProps({
        canCompare: true,
        canExport: true,
        isComparing: true,
      });

      expect(() => {
        render(<Toolbar {...props} />);
      }).not.toThrow();

      const compareButton = screen.getByRole('button', { name: /comparando/i });
      const exportButton = screen.getByRole('button', { name: /exportar csv/i });

      expect(compareButton).toBeDisabled();
      expect(exportButton).toBeDisabled();
    });

    it('should handle missing callback functions gracefully', () => {
      const props = {
        onCompare: undefined as any,
        onExportPdf: jest.fn(),
        onExportCsv: undefined as any,
        canCompare: true,
        canExport: true,
        isComparing: false,
      };

      expect(() => {
        render(<Toolbar {...props} />);
      }).not.toThrow();
    });
  });

  describe('Component Props', () => {
    it('should accept all required props', () => {
      const props = createMockProps();

      expect(() => {
        render(<Toolbar {...props} />);
      }).not.toThrow();
    });

    it('should handle prop changes correctly', () => {
      const props = createMockProps({ isComparing: false });
      const { rerender } = render(<Toolbar {...props} />);

      expect(screen.getByText('Comparar')).toBeInTheDocument();

      const updatedProps = createMockProps({ isComparing: true });
      rerender(<Toolbar {...updatedProps} />);

      expect(screen.getByText('Comparando...')).toBeInTheDocument();
      expect(screen.queryByText('Comparar')).not.toBeInTheDocument();
    });

    it('should handle callback prop changes', () => {
      const initialProps = createMockProps();
      const { rerender } = render(<Toolbar {...initialProps} />);

      const compareButton = screen.getByRole('button', { name: /comparar/i });
      fireEvent.click(compareButton);
      expect(initialProps.onCompare).toHaveBeenCalledTimes(1);

      const newOnCompare = jest.fn();
      const updatedProps = { ...initialProps, onCompare: newOnCompare };
      rerender(<Toolbar {...updatedProps} />);

      fireEvent.click(compareButton);
      expect(newOnCompare).toHaveBeenCalledTimes(1);
      expect(initialProps.onCompare).toHaveBeenCalledTimes(1); // Should not be called again
    });
  });

  describe('Performance', () => {
    it('should not re-render unnecessarily when props do not change', () => {
      const props = createMockProps();
      const { rerender } = render(<Toolbar {...props} />);

      expect(screen.getByText('ClauseDiff')).toBeInTheDocument();

      // Re-render with same props
      rerender(<Toolbar {...props} />);

      expect(screen.getByText('ClauseDiff')).toBeInTheDocument();
    });

    it('should handle rapid state changes efficiently', () => {
      const props = createMockProps({ isComparing: false });
      const { rerender } = render(<Toolbar {...props} />);

      // Rapid state changes
      for (let i = 0; i < 10; i++) {
        const updatedProps = createMockProps({ isComparing: i % 2 === 0 });
        rerender(<Toolbar {...updatedProps} />);
      }

      // Should still render correctly
      expect(screen.getByText('ClauseDiff')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /comparar/i })).toBeInTheDocument();
    });
  });
}); 