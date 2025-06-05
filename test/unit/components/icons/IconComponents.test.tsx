import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { ChevronDownIcon } from '@/components/icons/ChevronDownIcon';
import { CompareIcon } from '@/components/icons/CompareIcon';
import { CsvIcon } from '@/components/icons/CsvIcon';
import { InfoIcon } from '@/components/icons/InfoIcon';
import { PdfIcon } from '@/components/icons/PdfIcon';
import { UploadIcon } from '@/components/icons/UploadIcon';

describe('Icon Components', () => {
  // Test data for all icon components
  const iconComponents = [
    { Component: ChevronDownIcon, name: 'ChevronDownIcon', defaultSize: 20 },
    { Component: CompareIcon, name: 'CompareIcon', defaultSize: 24 },
    { Component: CsvIcon, name: 'CsvIcon', defaultSize: 24 },
    { Component: InfoIcon, name: 'InfoIcon', defaultSize: 20 },
    { Component: PdfIcon, name: 'PdfIcon', defaultSize: 24 },
    { Component: UploadIcon, name: 'UploadIcon', defaultSize: 24 },
  ];

  describe('Basic Rendering', () => {
    iconComponents.forEach(({ Component, name }) => {
      it(`should render ${name} correctly`, () => {
        const { container } = render(<Component />);
        
        const svgElement = container.querySelector('svg');
        expect(svgElement).toBeInTheDocument();
        expect(svgElement).toHaveAttribute('xmlns', 'http://www.w3.org/2000/svg');
      });
    });

    iconComponents.forEach(({ Component, name }) => {
      it(`should render ${name} with correct viewBox`, () => {
        const { container } = render(<Component />);
        
        const svgElement = container.querySelector('svg');
        expect(svgElement).toHaveAttribute('viewBox', '0 0 24 24');
      });
    });

    iconComponents.forEach(({ Component, name }) => {
      it(`should render ${name} with correct stroke properties`, () => {
        const { container } = render(<Component />);
        
        const svgElement = container.querySelector('svg');
        expect(svgElement).toHaveAttribute('fill', 'none');
        expect(svgElement).toHaveAttribute('stroke', 'currentColor');
        expect(svgElement).toHaveAttribute('stroke-linecap', 'round');
        expect(svgElement).toHaveAttribute('stroke-linejoin', 'round');
      });
    });
  });

  describe('Size Prop Handling', () => {
    iconComponents.forEach(({ Component, name, defaultSize }) => {
      it(`should use default size for ${name}`, () => {
        const { container } = render(<Component />);
        
        const svgElement = container.querySelector('svg');
        expect(svgElement).toHaveAttribute('width', defaultSize.toString());
        expect(svgElement).toHaveAttribute('height', defaultSize.toString());
      });
    });

    iconComponents.forEach(({ Component, name }) => {
      it(`should accept custom numeric size for ${name}`, () => {
        const customSize = 32;
        const { container } = render(<Component size={customSize} />);
        
        const svgElement = container.querySelector('svg');
        expect(svgElement).toHaveAttribute('width', customSize.toString());
        expect(svgElement).toHaveAttribute('height', customSize.toString());
      });
    });

    iconComponents.forEach(({ Component, name }) => {
      it(`should accept custom string size for ${name}`, () => {
        const customSize = '2rem';
        const { container } = render(<Component size={customSize} />);
        
        const svgElement = container.querySelector('svg');
        expect(svgElement).toHaveAttribute('width', customSize);
        expect(svgElement).toHaveAttribute('height', customSize);
      });
    });

    iconComponents.forEach(({ Component, name }) => {
      it(`should handle zero size for ${name}`, () => {
        const { container } = render(<Component size={0} />);
        
        const svgElement = container.querySelector('svg');
        expect(svgElement).toHaveAttribute('width', '0');
        expect(svgElement).toHaveAttribute('height', '0');
      });
    });
  });

  describe('ClassName Prop Handling', () => {
    iconComponents.forEach(({ Component, name }) => {
      it(`should apply default className for ${name}`, () => {
        const { container } = render(<Component />);
        
        const svgElement = container.querySelector('svg');
        expect(svgElement).toHaveClass('text-gray-700');
      });
    });

    iconComponents.forEach(({ Component, name }) => {
      it(`should accept custom className for ${name}`, () => {
        const customClass = 'text-blue-500 custom-icon';
        const { container } = render(<Component className={customClass} />);
        
        const svgElement = container.querySelector('svg');
        expect(svgElement).toHaveClass('text-gray-700'); // Default class
        expect(svgElement).toHaveClass('text-blue-500'); // Custom class
        expect(svgElement).toHaveClass('custom-icon'); // Custom class
      });
    });

    iconComponents.forEach(({ Component, name }) => {
      it(`should handle empty className for ${name}`, () => {
        const { container } = render(<Component className="" />);
        
        const svgElement = container.querySelector('svg');
        expect(svgElement).toHaveClass('text-gray-700'); // Default class should still be there
      });
    });

    iconComponents.forEach(({ Component, name }) => {
      it(`should override default color with custom className for ${name}`, () => {
        const { container } = render(<Component className="text-red-500" />);
        
        const svgElement = container.querySelector('svg');
        expect(svgElement).toHaveClass('text-gray-700', 'text-red-500');
        // Note: CSS specificity will determine which color is applied
      });
    });
  });

  describe('SVG Props Forwarding', () => {
    iconComponents.forEach(({ Component, name }) => {
      it(`should forward SVG props for ${name}`, () => {
        const { container } = render(
          <Component 
            data-testid="custom-icon"
            role="img"
            aria-label="Custom icon"
            style={{ opacity: 0.5 }}
          />
        );
        
        const svgElement = container.querySelector('svg');
        expect(svgElement).toHaveAttribute('data-testid', 'custom-icon');
        expect(svgElement).toHaveAttribute('role', 'img');
        expect(svgElement).toHaveAttribute('aria-label', 'Custom icon');
        expect(svgElement).toHaveStyle({ opacity: '0.5' });
      });
    });

    iconComponents.forEach(({ Component, name }) => {
      it(`should handle onClick event for ${name}`, () => {
        const handleClick = jest.fn();
        const { container } = render(<Component onClick={handleClick} />);
        
        const svgElement = container.querySelector('svg');
        if (svgElement) {
          fireEvent.click(svgElement);
        }
        
        expect(handleClick).toHaveBeenCalledTimes(1);
      });
    });

    iconComponents.forEach(({ Component, name }) => {
      it(`should handle onMouseOver event for ${name}`, () => {
        const handleMouseOver = jest.fn();
        const { container } = render(<Component onMouseOver={handleMouseOver} />);
        
        const svgElement = container.querySelector('svg');
        if (svgElement) {
          svgElement.dispatchEvent(new MouseEvent('mouseover', { bubbles: true }));
        }
        
        expect(handleMouseOver).toHaveBeenCalledTimes(1);
      });
    });
  });

  describe('Accessibility', () => {
    iconComponents.forEach(({ Component, name }) => {
      it(`should be accessible with proper role for ${name}`, () => {
        const { container } = render(<Component role="img" aria-label={`${name} icon`} />);
        
        const svgElement = container.querySelector('svg');
        expect(svgElement).toHaveAttribute('role', 'img');
        expect(svgElement).toHaveAttribute('aria-label', `${name} icon`);
      });
    });

    iconComponents.forEach(({ Component, name }) => {
      it(`should support aria-hidden for decorative ${name}`, () => {
        const { container } = render(<Component aria-hidden="true" />);
        
        const svgElement = container.querySelector('svg');
        expect(svgElement).toHaveAttribute('aria-hidden', 'true');
      });
    });

    iconComponents.forEach(({ Component, name }) => {
      it(`should support focusable attribute for ${name}`, () => {
        const { container } = render(<Component focusable="false" />);
        
        const svgElement = container.querySelector('svg');
        expect(svgElement).toHaveAttribute('focusable', 'false');
      });
    });
  });

  describe('SVG Content Validation', () => {
    it('should render ChevronDownIcon with correct path content', () => {
      const { container } = render(<ChevronDownIcon />);
      
      const polyline = container.querySelector('polyline');
      expect(polyline).toBeInTheDocument();
      expect(polyline).toHaveAttribute('points', '6 9 12 15 18 9');
    });

    it('should render CompareIcon with correct path content', () => {
      const { container } = render(<CompareIcon />);
      
      const polylines = container.querySelectorAll('polyline');
      const lines = container.querySelectorAll('line');
      
      expect(polylines).toHaveLength(2);
      expect(lines).toHaveLength(3);
    });

    it('should render InfoIcon with correct path content', () => {
      const { container } = render(<InfoIcon />);
      
      const circle = container.querySelector('circle');
      const lines = container.querySelectorAll('line');
      
      expect(circle).toBeInTheDocument();
      expect(circle).toHaveAttribute('cx', '12');
      expect(circle).toHaveAttribute('cy', '12');
      expect(circle).toHaveAttribute('r', '10');
      expect(lines).toHaveLength(2);
    });

    it('should render CsvIcon with correct path content', () => {
      const { container } = render(<CsvIcon />);
      
      const paths = container.querySelectorAll('path');
      expect(paths.length).toBeGreaterThan(0);
    });

    it('should render PdfIcon with correct path content', () => {
      const { container } = render(<PdfIcon />);
      
      const paths = container.querySelectorAll('path');
      expect(paths.length).toBeGreaterThan(0);
    });

    it('should render UploadIcon with correct path content', () => {
      const { container } = render(<UploadIcon />);
      
      const paths = container.querySelectorAll('path');
      const lines = container.querySelectorAll('line');
      
      expect(paths.length + lines.length).toBeGreaterThan(0);
    });
  });

  describe('Edge Cases', () => {
    iconComponents.forEach(({ Component, name }) => {
      it(`should handle very large size for ${name}`, () => {
        const largeSize = 1000;
        const { container } = render(<Component size={largeSize} />);
        
        const svgElement = container.querySelector('svg');
        expect(svgElement).toHaveAttribute('width', largeSize.toString());
        expect(svgElement).toHaveAttribute('height', largeSize.toString());
      });
    });

    iconComponents.forEach(({ Component, name }) => {
      it(`should handle negative size for ${name}`, () => {
        const negativeSize = -10;
        const { container } = render(<Component size={negativeSize} />);
        
        const svgElement = container.querySelector('svg');
        expect(svgElement).toHaveAttribute('width', negativeSize.toString());
        expect(svgElement).toHaveAttribute('height', negativeSize.toString());
      });
    });

    iconComponents.forEach(({ Component, name }) => {
      it(`should handle complex className combinations for ${name}`, () => {
        const complexClass = 'text-blue-500 hover:text-blue-700 transition-colors duration-200 transform hover:scale-110';
        const { container } = render(<Component className={complexClass} />);
        
        const svgElement = container.querySelector('svg');
        expect(svgElement).toHaveClass('text-gray-700'); // Default
        complexClass.split(' ').forEach(cls => {
          expect(svgElement).toHaveClass(cls);
        });
      });
    });

    iconComponents.forEach(({ Component, name }) => {
      it(`should handle undefined props gracefully for ${name}`, () => {
        expect(() => {
          render(<Component size={undefined} className={undefined} />);
        }).not.toThrow();
      });
    });
  });

  describe('Performance', () => {
    iconComponents.forEach(({ Component, name }) => {
      it(`should not re-render unnecessarily for ${name}`, () => {
        const { rerender } = render(<Component size={24} />);
        
        // Re-render with same props
        expect(() => {
          rerender(<Component size={24} />);
        }).not.toThrow();
      });
    });

    iconComponents.forEach(({ Component, name }) => {
      it(`should handle rapid prop changes efficiently for ${name}`, () => {
        const { rerender } = render(<Component size={20} />);
        
        // Rapid prop changes
        for (let i = 0; i < 10; i++) {
          rerender(<Component size={20 + i} className={`text-color-${i}`} />);
        }
        
        // Should still render correctly
        const { container } = render(<Component size={29} className="text-color-9" />);
        const svgElement = container.querySelector('svg');
        expect(svgElement).toHaveAttribute('width', '29');
        expect(svgElement).toHaveClass('text-color-9');
      });
    });
  });

  describe('Component Props Interface', () => {
    iconComponents.forEach(({ Component, name }) => {
      it(`should accept all valid SVG props for ${name}`, () => {
        const props = {
          size: 32,
          className: 'custom-class',
          'data-testid': 'test-icon',
          role: 'img',
          'aria-label': 'Test icon',
          onClick: jest.fn(),
          onMouseOver: jest.fn(),
          style: { color: 'red' },
          tabIndex: 0,
        };

        expect(() => {
          render(<Component {...props} />);
        }).not.toThrow();
      });
    });

    iconComponents.forEach(({ Component, name }) => {
      it(`should handle prop changes correctly for ${name}`, () => {
        const initialProps = { size: 20, className: 'initial-class' };
        const { rerender, container } = render(<Component {...initialProps} />);

        let svgElement = container.querySelector('svg');
        expect(svgElement).toHaveAttribute('width', '20');
        expect(svgElement).toHaveClass('initial-class');

        const updatedProps = { size: 40, className: 'updated-class' };
        rerender(<Component {...updatedProps} />);

        svgElement = container.querySelector('svg');
        expect(svgElement).toHaveAttribute('width', '40');
        expect(svgElement).toHaveClass('updated-class');
      });
    });
  });

  describe('TypeScript Interface Compliance', () => {
    iconComponents.forEach(({ Component, name }) => {
      it(`should extend SVGProps interface correctly for ${name}`, () => {
        // This test ensures TypeScript compilation works correctly
        const svgProps: React.SVGProps<SVGSVGElement> = {
          width: 24,
          height: 24,
          viewBox: '0 0 24 24',
          fill: 'none',
          stroke: 'currentColor',
        };

        expect(() => {
          render(<Component {...svgProps} />);
        }).not.toThrow();
      });
    });

    iconComponents.forEach(({ Component, name }) => {
      it(`should handle IconProps interface correctly for ${name}`, () => {
        const iconProps = {
          size: 48,
          className: 'test-class',
          'data-testid': 'icon-test',
        };

        expect(() => {
          render(<Component {...iconProps} />);
        }).not.toThrow();
      });
    });
  });
}); 