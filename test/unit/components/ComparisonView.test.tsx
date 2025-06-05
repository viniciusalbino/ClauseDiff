import React from 'react';
import { render, screen } from '@testing-library/react';
import { ComparisonView } from '@/components/ComparisonView';

describe('ComparisonView Component', () => {
  describe('Empty State', () => {
    it('should display empty state message when no content is provided', () => {
      render(<ComparisonView htmlContent1={null} htmlContent2={null} />);

      expect(screen.getByText('Carregue dois documentos para iniciar a comparação.')).toBeInTheDocument();
    });

    it('should display empty state message when both contents are undefined', () => {
      render(<ComparisonView htmlContent1={undefined as any} htmlContent2={undefined as any} />);

      expect(screen.getByText('Carregue dois documentos para iniciar a comparação.')).toBeInTheDocument();
    });

    it('should display empty state message when both contents are empty strings', () => {
      render(<ComparisonView htmlContent1="" htmlContent2="" />);

      expect(screen.getByText('Carregue dois documentos para iniciar a comparação.')).toBeInTheDocument();
    });

    it('should apply correct empty state styling', () => {
      render(<ComparisonView htmlContent1={null} htmlContent2={null} />);

      const emptyStateContainer = screen.getByText('Carregue dois documentos para iniciar a comparação.').closest('div');
      expect(emptyStateContainer).toHaveClass('flex-1', 'flex', 'items-center', 'justify-center', 'text-gray-700', 'p-8');
    });
  });

  describe('Content Rendering', () => {
    it('should render both panes when content is provided', () => {
      const content1 = '<p>Document 1 content</p>';
      const content2 = '<p>Document 2 content</p>';

      render(<ComparisonView htmlContent1={content1} htmlContent2={content2} />);

      expect(screen.getByText('Document 1 content')).toBeInTheDocument();
      expect(screen.getByText('Document 2 content')).toBeInTheDocument();
    });

    it('should render content with default document names', () => {
      const content1 = '<p>Content 1</p>';
      const content2 = '<p>Content 2</p>';

      render(<ComparisonView htmlContent1={content1} htmlContent2={content2} />);

      expect(screen.getByText('Documento Original')).toBeInTheDocument();
      expect(screen.getByText('Documento Modificado')).toBeInTheDocument();
    });

    it('should render content with custom document names', () => {
      const content1 = '<p>Content 1</p>';
      const content2 = '<p>Content 2</p>';

      render(
        <ComparisonView 
          htmlContent1={content1} 
          htmlContent2={content2}
          docName1="Contract v1.0"
          docName2="Contract v2.0"
        />
      );

      expect(screen.getByText('Contract v1.0')).toBeInTheDocument();
      expect(screen.getByText('Contract v2.0')).toBeInTheDocument();
    });

    it('should handle null document names gracefully', () => {
      const content1 = '<p>Content 1</p>';
      const content2 = '<p>Content 2</p>';

      render(
        <ComparisonView 
          htmlContent1={content1} 
          htmlContent2={content2}
          docName1={null}
          docName2={null}
        />
      );

      // When null is passed, it falls back to the default names
      expect(screen.getByText('Documento Original')).toBeInTheDocument();
      expect(screen.getByText('Documento Modificado')).toBeInTheDocument();
    });

    it('should handle undefined document names gracefully', () => {
      const content1 = '<p>Content 1</p>';
      const content2 = '<p>Content 2</p>';

      render(
        <ComparisonView 
          htmlContent1={content1} 
          htmlContent2={content2}
          docName1={undefined}
          docName2={undefined}
        />
      );

      expect(screen.getByText('Documento Original')).toBeInTheDocument();
      expect(screen.getByText('Documento Modificado')).toBeInTheDocument();
    });
  });

  describe('Mixed Content States', () => {
    it('should render when only first content is provided', () => {
      const content1 = '<p>Only first content</p>';

      render(<ComparisonView htmlContent1={content1} htmlContent2={null} />);

      expect(screen.getByText('Only first content')).toBeInTheDocument();
      expect(screen.getByText('Documento Original')).toBeInTheDocument();
      expect(screen.getByText('Documento Modificado')).toBeInTheDocument();
    });

    it('should render when only second content is provided', () => {
      const content2 = '<p>Only second content</p>';

      render(<ComparisonView htmlContent1={null} htmlContent2={content2} />);

      expect(screen.getByText('Only second content')).toBeInTheDocument();
      expect(screen.getByText('Documento Original')).toBeInTheDocument();
      expect(screen.getByText('Documento Modificado')).toBeInTheDocument();
    });

    it('should display default message for empty content panes', () => {
      const content1 = '<p>Content 1</p>';

      render(<ComparisonView htmlContent1={content1} htmlContent2={null} />);

      expect(screen.getByText('Nenhum conteúdo para exibir.')).toBeInTheDocument();
    });

    it('should handle empty string content appropriately', () => {
      const content1 = '<p>Content 1</p>';
      const content2 = '';

      render(<ComparisonView htmlContent1={content1} htmlContent2={content2} />);

      expect(screen.getByText('Content 1')).toBeInTheDocument();
      expect(screen.getByText('Nenhum conteúdo para exibir.')).toBeInTheDocument();
    });
  });

  describe('HTML Content Rendering', () => {
    it('should render complex HTML content correctly', () => {
      const complexContent1 = `
        <div>
          <h1>Title</h1>
          <p>Paragraph with <strong>bold</strong> and <em>italic</em> text.</p>
          <ul>
            <li>Item 1</li>
            <li>Item 2</li>
          </ul>
        </div>
      `;
      const complexContent2 = `
        <div>
          <h2>Different Title</h2>
          <p>Modified paragraph with <span style="color: red;">colored</span> text.</p>
        </div>
      `;

      render(<ComparisonView htmlContent1={complexContent1} htmlContent2={complexContent2} />);

      expect(screen.getByText('Title')).toBeInTheDocument();
      expect(screen.getByText('Different Title')).toBeInTheDocument();
      expect(screen.getByText('bold')).toBeInTheDocument();
      expect(screen.getByText('italic')).toBeInTheDocument();
      expect(screen.getByText('Item 1')).toBeInTheDocument();
      expect(screen.getByText('Item 2')).toBeInTheDocument();
      expect(screen.getByText('colored')).toBeInTheDocument();
    });

    it('should handle special characters and entities in HTML', () => {
      const content1 = '<p>Special chars: &amp; &lt; &gt; &quot; &#39;</p>';
      const content2 = '<p>Unicode: © ® ™ €</p>';

      render(<ComparisonView htmlContent1={content1} htmlContent2={content2} />);

      expect(screen.getByText('Special chars: & < > " \'')).toBeInTheDocument();
      expect(screen.getByText('Unicode: © ® ™ €')).toBeInTheDocument();
    });

    it('should render diff-related HTML classes and styling', () => {
      const contentWithDiffClasses = `
        <p class="diff-added">Added text</p>
        <p class="diff-removed">Removed text</p>
        <p class="diff-modified">Modified text</p>
      `;

      render(<ComparisonView htmlContent1={contentWithDiffClasses} htmlContent2={contentWithDiffClasses} />);

      expect(screen.getAllByText('Added text')).toHaveLength(2);
      expect(screen.getAllByText('Removed text')).toHaveLength(2);
      expect(screen.getAllByText('Modified text')).toHaveLength(2);
    });
  });

  describe('Layout and Styling', () => {
    it('should apply correct grid layout classes', () => {
      const content1 = '<p>Content 1</p>';
      const content2 = '<p>Content 2</p>';

      const { container } = render(<ComparisonView htmlContent1={content1} htmlContent2={content2} />);

      const gridContainer = container.querySelector('.grid');
      expect(gridContainer).toHaveClass('grid-cols-1', 'md:grid-cols-2', 'gap-4', 'p-4');
    });

    it('should apply correct pane styling', () => {
      const content1 = '<p>Content 1</p>';
      const content2 = '<p>Content 2</p>';

      const { container } = render(<ComparisonView htmlContent1={content1} htmlContent2={content2} />);

      const panes = container.querySelectorAll('.flex-1.p-4.bg-white.shadow-md.rounded-lg.overflow-hidden');
      expect(panes).toHaveLength(2);
    });

    it('should apply correct title styling', () => {
      const content1 = '<p>Content 1</p>';
      const content2 = '<p>Content 2</p>';

      render(<ComparisonView htmlContent1={content1} htmlContent2={content2} docName1="Doc 1" docName2="Doc 2" />);

      const titles = screen.getAllByText(/Doc [12]/);
      titles.forEach(title => {
        expect(title).toHaveClass('font-semibold', 'text-blue-800', 'mb-3', 'pb-2', 'border-b', 'border-slate-300', 'truncate');
      });
    });

    it('should apply correct content area styling', () => {
      const content1 = '<p>Content 1</p>';
      const content2 = '<p>Content 2</p>';

      const { container } = render(<ComparisonView htmlContent1={content1} htmlContent2={content2} />);

      const contentAreas = container.querySelectorAll('#comparison-pane-1, #comparison-pane-2');
      expect(contentAreas).toHaveLength(2);
      
      contentAreas.forEach(area => {
        expect(area).toHaveClass('overflow-y-auto', 'text-sm', 'font-mono', 'text-gray-800', 'p-3', 'bg-white', 'rounded', 'border', 'border-gray-200');
      });
    });
  });

  describe('Document Names', () => {
    it('should truncate long document names', () => {
      const longName1 = 'This is a very long document name that should be truncated because it exceeds the normal length';
      const longName2 = 'Another extremely long document name that should also be truncated';
      const content1 = '<p>Content 1</p>';
      const content2 = '<p>Content 2</p>';

      render(<ComparisonView htmlContent1={content1} htmlContent2={content2} docName1={longName1} docName2={longName2} />);

      expect(screen.getByText(longName1)).toHaveClass('truncate');
      expect(screen.getByText(longName2)).toHaveClass('truncate');
    });

    it('should handle empty string document names', () => {
      const content1 = '<p>Content 1</p>';
      const content2 = '<p>Content 2</p>';

      render(<ComparisonView htmlContent1={content1} htmlContent2={content2} docName1="" docName2="" />);

      // When empty string is passed, it falls back to the default names (outer fallback)
      // because empty string is falsy in the OR expression
      expect(screen.getByText('Documento Original')).toBeInTheDocument();
      expect(screen.getByText('Documento Modificado')).toBeInTheDocument();
    });

    it('should handle document names with special characters', () => {
      const specialName1 = 'Contract_v1.0 (Final) [2023].docx';
      const specialName2 = 'Contract_v2.0 (Final) [2024].docx';
      const content1 = '<p>Content 1</p>';
      const content2 = '<p>Content 2</p>';

      render(<ComparisonView htmlContent1={content1} htmlContent2={content2} docName1={specialName1} docName2={specialName2} />);

      expect(screen.getByText(specialName1)).toBeInTheDocument();
      expect(screen.getByText(specialName2)).toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    it('should provide proper heading structure', () => {
      const content1 = '<p>Content 1</p>';
      const content2 = '<p>Content 2</p>';

      render(<ComparisonView htmlContent1={content1} htmlContent2={content2} />);

      const headings = screen.getAllByRole('heading', { level: 3 });
      expect(headings).toHaveLength(2);
    });

    it('should have identifiable content areas', () => {
      const content1 = '<p>Content 1</p>';
      const content2 = '<p>Content 2</p>';

      const { container } = render(<ComparisonView htmlContent1={content1} htmlContent2={content2} />);

      expect(container.querySelector('#comparison-pane-1')).toBeInTheDocument();
      expect(container.querySelector('#comparison-pane-2')).toBeInTheDocument();
    });

    it('should maintain proper contrast with text colors', () => {
      const content1 = '<p>Content 1</p>';
      const content2 = '<p>Content 2</p>';

      const { container } = render(<ComparisonView htmlContent1={content1} htmlContent2={content2} />);

      const contentAreas = container.querySelectorAll('#comparison-pane-1, #comparison-pane-2');
      contentAreas.forEach(area => {
        expect(area).toHaveClass('text-gray-800');
      });
    });
  });

  describe('Edge Cases', () => {
    it('should handle malformed HTML gracefully', () => {
      const malformedContent1 = '<p>Unclosed paragraph';
      const malformedContent2 = '<div><p>Nested but unclosed';

      expect(() => {
        render(<ComparisonView htmlContent1={malformedContent1} htmlContent2={malformedContent2} />);
      }).not.toThrow();
    });

    it('should handle very large content', () => {
      const largeContent = '<p>' + 'Large content '.repeat(1000) + '</p>';

      expect(() => {
        render(<ComparisonView htmlContent1={largeContent} htmlContent2={largeContent} />);
      }).not.toThrow();

      expect(screen.getAllByText(new RegExp('Large content'))).toHaveLength(2);
    });

    it('should handle content with script tags (security consideration)', () => {
      const contentWithScript = '<p>Safe content</p><script>alert("XSS")</script>';

      render(<ComparisonView htmlContent1={contentWithScript} htmlContent2={contentWithScript} />);

      expect(screen.getAllByText('Safe content')).toHaveLength(2);
      // Script should be rendered as text, not executed
    });

    it('should handle content with style tags', () => {
      const contentWithStyle = '<style>.test { color: red; }</style><p class="test">Styled content</p>';

      render(<ComparisonView htmlContent1={contentWithStyle} htmlContent2={contentWithStyle} />);

      expect(screen.getAllByText('Styled content')).toHaveLength(2);
    });
  });

  describe('Component Props', () => {
    it('should accept all required props', () => {
      expect(() => {
        render(<ComparisonView htmlContent1="<p>Test</p>" htmlContent2="<p>Test</p>" />);
      }).not.toThrow();
    });

    it('should accept all optional props', () => {
      expect(() => {
        render(
          <ComparisonView 
            htmlContent1="<p>Test</p>" 
            htmlContent2="<p>Test</p>"
            docName1="Document 1"
            docName2="Document 2"
          />
        );
      }).not.toThrow();
    });

    it('should handle prop changes correctly', () => {
      const { rerender } = render(<ComparisonView htmlContent1="<p>Initial</p>" htmlContent2="<p>Initial</p>" />);

      expect(screen.getAllByText('Initial')).toHaveLength(2);

      rerender(<ComparisonView htmlContent1="<p>Updated</p>" htmlContent2="<p>Updated</p>" />);

      expect(screen.getAllByText('Updated')).toHaveLength(2);
      expect(screen.queryByText('Initial')).not.toBeInTheDocument();
    });
  });

  describe('Responsive Design', () => {
    it('should apply responsive grid classes', () => {
      const content1 = '<p>Content 1</p>';
      const content2 = '<p>Content 2</p>';

      const { container } = render(<ComparisonView htmlContent1={content1} htmlContent2={content2} />);

      const gridContainer = container.querySelector('.grid');
      expect(gridContainer).toHaveClass('grid-cols-1', 'md:grid-cols-2');
    });

    it('should have appropriate spacing for different screen sizes', () => {
      const content1 = '<p>Content 1</p>';
      const content2 = '<p>Content 2</p>';

      const { container } = render(<ComparisonView htmlContent1={content1} htmlContent2={content2} />);

      const gridContainer = container.querySelector('.grid');
      expect(gridContainer).toHaveClass('gap-4');
    });
  });
}); 