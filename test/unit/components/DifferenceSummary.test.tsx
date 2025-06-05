import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { DifferenceSummary } from '@/components/DifferenceSummary';
import { ComparisonResult, DIFF_INSERT, DIFF_DELETE, DIFF_EQUAL } from '../../../types';

describe('DifferenceSummary Component', () => {
  // Helper function to create mock comparison data
  const createMockSummary = (additions = 10, deletions = 5, totalDifferences = 3) => ({
    additions,
    deletions,
    totalDifferences,
  });

  const createMockRawDiffs = (diffs: Array<{ type: 'insert' | 'delete' | 'equal'; text: string }>) => diffs;

  describe('Null/Empty State Handling', () => {
    it('should return null when summary is null', () => {
      const { container } = render(
        <DifferenceSummary summary={null as any} rawDiffs={[]} />
      );
      expect(container.firstChild).toBeNull();
    });

    it('should return null when rawDiffs is null', () => {
      const summary = createMockSummary();
      const { container } = render(
        <DifferenceSummary summary={summary} rawDiffs={null as any} />
      );
      expect(container.firstChild).toBeNull();
    });

    it('should return null when both summary and rawDiffs are null', () => {
      const { container } = render(
        <DifferenceSummary summary={null as any} rawDiffs={null as any} />
      );
      expect(container.firstChild).toBeNull();
    });

    it('should return null when summary is undefined', () => {
      const { container } = render(
        <DifferenceSummary summary={undefined as any} rawDiffs={[]} />
      );
      expect(container.firstChild).toBeNull();
    });
  });

  describe('Basic Rendering', () => {
    it('should render with valid data', () => {
      const summary = createMockSummary(15, 8, 5);
      const rawDiffs = createMockRawDiffs([
        { type: DIFF_INSERT, text: 'Added text' },
        { type: DIFF_DELETE, text: 'Removed text' },
      ]);

      render(<DifferenceSummary summary={summary} rawDiffs={rawDiffs} />);

      expect(screen.getByText('Resumo das Alterações')).toBeInTheDocument();
      expect(screen.getByText('Estatísticas Gerais:')).toBeInTheDocument();
    });

    it('should display correct statistics', () => {
      const summary = createMockSummary(25, 12, 7);
      const rawDiffs = createMockRawDiffs([]);

      render(<DifferenceSummary summary={summary} rawDiffs={rawDiffs} />);

      expect(screen.getByText('25 caracteres')).toBeInTheDocument();
      expect(screen.getByText('12 caracteres')).toBeInTheDocument();
      expect(screen.getByText('7')).toBeInTheDocument();
    });

    it('should be open by default', () => {
      const summary = createMockSummary();
      const rawDiffs = createMockRawDiffs([]);

      render(<DifferenceSummary summary={summary} rawDiffs={rawDiffs} />);

      expect(screen.getByText('Estatísticas Gerais:')).toBeInTheDocument();
    });
  });

  describe('Toggle Functionality', () => {
    it('should toggle open/closed state when header is clicked', () => {
      const summary = createMockSummary();
      const rawDiffs = createMockRawDiffs([]);

      render(<DifferenceSummary summary={summary} rawDiffs={rawDiffs} />);

      const toggleButton = screen.getByRole('button', { name: /resumo das alterações/i });

      // Initially open
      expect(screen.getByText('Estatísticas Gerais:')).toBeInTheDocument();

      // Click to close
      fireEvent.click(toggleButton);
      expect(screen.queryByText('Estatísticas Gerais:')).not.toBeInTheDocument();

      // Click to open again
      fireEvent.click(toggleButton);
      expect(screen.getByText('Estatísticas Gerais:')).toBeInTheDocument();
    });

    it('should rotate chevron icon when toggling', () => {
      const summary = createMockSummary();
      const rawDiffs = createMockRawDiffs([]);

      render(<DifferenceSummary summary={summary} rawDiffs={rawDiffs} />);

      const toggleButton = screen.getByRole('button', { name: /resumo das alterações/i });
      const chevronIcon = toggleButton.querySelector('svg');

      // Initially open (rotated)
      expect(chevronIcon).toHaveClass('rotate-180');

      // Click to close (not rotated)
      fireEvent.click(toggleButton);
      expect(chevronIcon).not.toHaveClass('rotate-180');

      // Click to open again (rotated)
      fireEvent.click(toggleButton);
      expect(chevronIcon).toHaveClass('rotate-180');
    });
  });

  describe('Significant Changes Display', () => {
    it('should display significant changes when available', () => {
      const summary = createMockSummary(10, 5, 3);
      const rawDiffs = createMockRawDiffs([
        { type: DIFF_INSERT, text: 'New important text' },
        { type: DIFF_DELETE, text: 'Old removed text' },
        { type: DIFF_EQUAL, text: 'Unchanged text' },
      ]);

      render(<DifferenceSummary summary={summary} rawDiffs={rawDiffs} />);

      expect(screen.getByText('Principais Alterações:')).toBeInTheDocument();
      expect(screen.getByText('New important text')).toBeInTheDocument();
      expect(screen.getByText('Old removed text')).toBeInTheDocument();
      expect(screen.queryByText('Unchanged text')).not.toBeInTheDocument();
    });

    it('should filter out equal diffs and empty text', () => {
      const summary = createMockSummary(10, 5, 3);
      const rawDiffs = createMockRawDiffs([
        { type: DIFF_INSERT, text: 'Valid addition' },
        { type: DIFF_DELETE, text: '   ' }, // Only whitespace
        { type: DIFF_EQUAL, text: 'Should be filtered' },
        { type: DIFF_INSERT, text: '' }, // Empty string
        { type: DIFF_DELETE, text: 'Valid deletion' },
      ]);

      render(<DifferenceSummary summary={summary} rawDiffs={rawDiffs} />);

      expect(screen.getByText('Valid addition')).toBeInTheDocument();
      expect(screen.getByText('Valid deletion')).toBeInTheDocument();
      expect(screen.queryByText('Should be filtered')).not.toBeInTheDocument();
    });

    it('should limit significant changes to 10 items', () => {
      const summary = createMockSummary(100, 50, 20);
      const rawDiffs = createMockRawDiffs(
        Array.from({ length: 15 }, (_, i) => ({
          type: i % 2 === 0 ? DIFF_INSERT : DIFF_DELETE,
          text: `Change ${i + 1}`,
        }))
      );

      render(<DifferenceSummary summary={summary} rawDiffs={rawDiffs} />);

      // Should show first 10 changes
      expect(screen.getByText('Change 1')).toBeInTheDocument();
      expect(screen.getByText('Change 10')).toBeInTheDocument();
      expect(screen.queryByText('Change 11')).not.toBeInTheDocument();
      expect(screen.queryByText('Change 15')).not.toBeInTheDocument();
    });

    it('should apply correct styling for insertions', () => {
      const summary = createMockSummary(10, 5, 2);
      const rawDiffs = createMockRawDiffs([
        { type: DIFF_INSERT, text: 'Added content' },
      ]);

      render(<DifferenceSummary summary={summary} rawDiffs={rawDiffs} />);

      const addedItem = screen.getByText('Added content').closest('li');
      expect(addedItem).toHaveClass('bg-green-100');
      expect(screen.getByText('ADICIONADO:')).toHaveClass('text-green-800');
    });

    it('should apply correct styling for deletions', () => {
      const summary = createMockSummary(10, 5, 2);
      const rawDiffs = createMockRawDiffs([
        { type: DIFF_DELETE, text: 'Removed content' },
      ]);

      render(<DifferenceSummary summary={summary} rawDiffs={rawDiffs} />);

      const removedItem = screen.getByText('Removed content').closest('li');
      expect(removedItem).toHaveClass('bg-red-100');
      expect(screen.getByText('REMOVIDO:')).toHaveClass('text-red-800');
    });
  });

  describe('Text Truncation', () => {
    it('should truncate long text and show ellipsis', () => {
      const longText = 'A'.repeat(150); // 150 characters
      const summary = createMockSummary(10, 5, 1);
      const rawDiffs = createMockRawDiffs([
        { type: DIFF_INSERT, text: longText },
      ]);

      render(<DifferenceSummary summary={summary} rawDiffs={rawDiffs} />);

      const truncatedText = 'A'.repeat(100) + '...';
      expect(screen.getByText(truncatedText)).toBeInTheDocument();
    });

    it('should not truncate short text', () => {
      const shortText = 'Short text';
      const summary = createMockSummary(10, 5, 1);
      const rawDiffs = createMockRawDiffs([
        { type: DIFF_INSERT, text: shortText },
      ]);

      render(<DifferenceSummary summary={summary} rawDiffs={rawDiffs} />);

      expect(screen.getByText(shortText)).toBeInTheDocument();
      expect(screen.queryByText(/\.\.\./)).not.toBeInTheDocument();
    });

    it('should show full text in title attribute for truncated text', () => {
      const longText = 'B'.repeat(150);
      const summary = createMockSummary(10, 5, 1);
      const rawDiffs = createMockRawDiffs([
        { type: DIFF_INSERT, text: longText },
      ]);

      render(<DifferenceSummary summary={summary} rawDiffs={rawDiffs} />);

      const textElement = screen.getByText('B'.repeat(100) + '...');
      expect(textElement).toHaveAttribute('title', longText);
    });
  });

  describe('Empty States', () => {
    it('should show "no differences" message when no differences exist', () => {
      const summary = createMockSummary(0, 0, 0);
      const rawDiffs = createMockRawDiffs([
        { type: DIFF_EQUAL, text: 'Same content' },
      ]);

      render(<DifferenceSummary summary={summary} rawDiffs={rawDiffs} />);

      expect(screen.getByText('Nenhuma diferença encontrada entre os documentos.')).toBeInTheDocument();
    });

    it('should show "whitespace differences" message when only minor differences exist', () => {
      const summary = createMockSummary(0, 0, 5); // Has differences but no significant changes
      const rawDiffs = createMockRawDiffs([
        { type: DIFF_INSERT, text: '   ' }, // Only whitespace
        { type: DIFF_DELETE, text: '' }, // Empty
        { type: DIFF_EQUAL, text: 'Same content' },
      ]);

      render(<DifferenceSummary summary={summary} rawDiffs={rawDiffs} />);

      expect(screen.getByText('As diferenças encontradas são principalmente espaços em branco ou pequenas formatações.')).toBeInTheDocument();
    });

    it('should not show empty state messages when significant changes exist', () => {
      const summary = createMockSummary(10, 5, 3);
      const rawDiffs = createMockRawDiffs([
        { type: DIFF_INSERT, text: 'Significant change' },
      ]);

      render(<DifferenceSummary summary={summary} rawDiffs={rawDiffs} />);

      expect(screen.queryByText('Nenhuma diferença encontrada entre os documentos.')).not.toBeInTheDocument();
      expect(screen.queryByText('As diferenças encontradas são principalmente espaços em branco ou pequenas formatações.')).not.toBeInTheDocument();
    });
  });

  describe('Styling and Layout', () => {
    it('should apply correct container styling', () => {
      const summary = createMockSummary();
      const rawDiffs = createMockRawDiffs([]);

      const { container } = render(<DifferenceSummary summary={summary} rawDiffs={rawDiffs} />);

      const mainContainer = container.firstChild as HTMLElement;
      expect(mainContainer).toHaveClass('bg-white', 'shadow-lg', 'rounded-lg', 'w-full', 'md:w-80', 'lg:w-96');
    });

    it('should apply correct header styling', () => {
      const summary = createMockSummary();
      const rawDiffs = createMockRawDiffs([]);

      render(<DifferenceSummary summary={summary} rawDiffs={rawDiffs} />);

      const headerButton = screen.getByRole('button', { name: /resumo das alterações/i });
      expect(headerButton).toHaveClass('w-full', 'flex', 'items-center', 'justify-between', 'p-3', 'bg-gray-700', 'text-white');
    });

    it('should apply correct content area styling', () => {
      const summary = createMockSummary();
      const rawDiffs = createMockRawDiffs([]);

      const { container } = render(<DifferenceSummary summary={summary} rawDiffs={rawDiffs} />);

      const contentArea = container.querySelector('.p-4.overflow-y-auto.flex-grow');
      expect(contentArea).toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    it('should have proper button role for toggle', () => {
      const summary = createMockSummary();
      const rawDiffs = createMockRawDiffs([]);

      render(<DifferenceSummary summary={summary} rawDiffs={rawDiffs} />);

      const toggleButton = screen.getByRole('button', { name: /resumo das alterações/i });
      expect(toggleButton).toBeInTheDocument();
    });

    it('should have focus outline for keyboard navigation', () => {
      const summary = createMockSummary();
      const rawDiffs = createMockRawDiffs([]);

      render(<DifferenceSummary summary={summary} rawDiffs={rawDiffs} />);

      const toggleButton = screen.getByRole('button', { name: /resumo das alterações/i });
      expect(toggleButton).toHaveClass('focus:outline-none');
    });

    it('should provide proper list structure for changes', () => {
      const summary = createMockSummary(10, 5, 2);
      const rawDiffs = createMockRawDiffs([
        { type: DIFF_INSERT, text: 'Addition' },
        { type: DIFF_DELETE, text: 'Deletion' },
      ]);

      render(<DifferenceSummary summary={summary} rawDiffs={rawDiffs} />);

      const lists = screen.getAllByRole('list');
      expect(lists).toHaveLength(2); // Statistics list and changes list
    });
  });

  describe('Edge Cases', () => {
    it('should handle zero values in statistics', () => {
      const summary = createMockSummary(0, 0, 0);
      const rawDiffs = createMockRawDiffs([]);

      render(<DifferenceSummary summary={summary} rawDiffs={rawDiffs} />);

      expect(screen.getAllByText('0 caracteres')).toHaveLength(2); // Both additions and deletions
      expect(screen.getByText('0')).toBeInTheDocument(); // Total differences
    });

    it('should handle very large numbers in statistics', () => {
      const summary = createMockSummary(999999, 888888, 777);
      const rawDiffs = createMockRawDiffs([]);

      render(<DifferenceSummary summary={summary} rawDiffs={rawDiffs} />);

      expect(screen.getByText('999999 caracteres')).toBeInTheDocument();
      expect(screen.getByText('888888 caracteres')).toBeInTheDocument();
      expect(screen.getByText('777')).toBeInTheDocument();
    });

    it('should handle special characters in diff text', () => {
      const summary = createMockSummary(10, 5, 2);
      const rawDiffs = createMockRawDiffs([
        { type: DIFF_INSERT, text: 'Special chars: <>&"\'`' },
        { type: DIFF_DELETE, text: 'Unicode: 🚀 ñ ç ü' },
      ]);

      render(<DifferenceSummary summary={summary} rawDiffs={rawDiffs} />);

      expect(screen.getByText('Special chars: <>&"\'`')).toBeInTheDocument();
      expect(screen.getByText('Unicode: 🚀 ñ ç ü')).toBeInTheDocument();
    });

    it('should handle mixed content with newlines and tabs', () => {
      const summary = createMockSummary(10, 5, 1);
      const rawDiffs = createMockRawDiffs([
        { type: DIFF_INSERT, text: 'Line 1\nLine 2\tTabbed' },
      ]);

      render(<DifferenceSummary summary={summary} rawDiffs={rawDiffs} />);

      expect(screen.getByText((content, element) => {
        return element?.textContent === 'Line 1\nLine 2\tTabbed';
      })).toBeInTheDocument();
    });
  });

  describe('Performance', () => {
    it('should handle large number of diffs efficiently', () => {
      const summary = createMockSummary(1000, 500, 100);
      const rawDiffs = createMockRawDiffs(
        Array.from({ length: 1000 }, (_, i) => ({
          type: i % 3 === 0 ? DIFF_INSERT : i % 3 === 1 ? DIFF_DELETE : DIFF_EQUAL,
          text: `Diff item ${i}`,
        }))
      );

      expect(() => {
        render(<DifferenceSummary summary={summary} rawDiffs={rawDiffs} />);
      }).not.toThrow();

      // Should still only show first 10 significant changes
      expect(screen.getByText('Diff item 0')).toBeInTheDocument();
      expect(screen.queryByText('Diff item 15')).not.toBeInTheDocument();
    });

    it('should not re-render unnecessarily when props do not change', () => {
      const summary = createMockSummary(10, 5, 2);
      const rawDiffs = createMockRawDiffs([
        { type: DIFF_INSERT, text: 'Test change' },
      ]);

      const { rerender } = render(<DifferenceSummary summary={summary} rawDiffs={rawDiffs} />);

      expect(screen.getByText('Test change')).toBeInTheDocument();

      // Re-render with same props
      rerender(<DifferenceSummary summary={summary} rawDiffs={rawDiffs} />);

      expect(screen.getByText('Test change')).toBeInTheDocument();
    });
  });

  describe('Component Props', () => {
    it('should accept valid summary and rawDiffs props', () => {
      const summary = createMockSummary(5, 3, 1);
      const rawDiffs = createMockRawDiffs([
        { type: DIFF_INSERT, text: 'New text' },
      ]);

      expect(() => {
        render(<DifferenceSummary summary={summary} rawDiffs={rawDiffs} />);
      }).not.toThrow();
    });

    it('should handle prop changes correctly', () => {
      const initialSummary = createMockSummary(10, 5, 2);
      const initialRawDiffs = createMockRawDiffs([
        { type: DIFF_INSERT, text: 'Initial change' },
      ]);

      const { rerender } = render(
        <DifferenceSummary summary={initialSummary} rawDiffs={initialRawDiffs} />
      );

      expect(screen.getByText('Initial change')).toBeInTheDocument();
      expect(screen.getByText('10 caracteres')).toBeInTheDocument();

      const updatedSummary = createMockSummary(20, 15, 3);
      const updatedRawDiffs = createMockRawDiffs([
        { type: DIFF_DELETE, text: 'Updated change' },
      ]);

      rerender(<DifferenceSummary summary={updatedSummary} rawDiffs={updatedRawDiffs} />);

      expect(screen.getByText('Updated change')).toBeInTheDocument();
      expect(screen.getByText('20 caracteres')).toBeInTheDocument();
      expect(screen.queryByText('Initial change')).not.toBeInTheDocument();
    });
  });
}); 