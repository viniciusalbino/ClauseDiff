import { generateDiff } from '@/utils/diffEngine';
import { DIFF_INSERT, DIFF_DELETE, DIFF_EQUAL } from '../../../types';

// Mock the global diff_match_patch
const mockDiffMain = jest.fn();
const mockDiffCleanupSemantic = jest.fn();

beforeAll(() => {
  // Mock the global window.diff_match_patch
  Object.defineProperty(global, 'window', {
    value: {
      diff_match_patch: jest.fn().mockImplementation(() => ({
        diff_main: mockDiffMain,
        diff_cleanupSemantic: mockDiffCleanupSemantic,
      })),
    },
    writable: true
  });
});

beforeEach(() => {
  jest.clearAllMocks();
});

describe('diffEngine', () => {
  describe('generateDiff', () => {
    describe('Basic Functionality', () => {
      it('should generate diff for identical texts', () => {
        const text1 = 'Hello World';
        const text2 = 'Hello World';
        
        mockDiffMain.mockReturnValue([[0, 'Hello World']]);
        
        const result = generateDiff(text1, text2);
        
        expect(result.html1).toBe('Hello World');
        expect(result.html2).toBe('Hello World');
        expect(result.summary.additions).toBe(0);
        expect(result.summary.deletions).toBe(0);
        expect(result.summary.totalDifferences).toBe(0);
        expect(result.rawDiffs).toEqual([{ type: 'equal', text: 'Hello World' }]);
      });

      it('should generate diff for completely different texts', () => {
        const text1 = 'Hello';
        const text2 = 'World';
        
        mockDiffMain.mockReturnValue([
          [-1, 'Hello'],
          [1, 'World']
        ]);
        
        const result = generateDiff(text1, text2);
        
        expect(result.html1).toBe('<span class="bg-red-100 text-red-800 line-through">Hello</span>');
        expect(result.html2).toBe('<span class="bg-green-100 text-green-800">World</span>');
        expect(result.summary.additions).toBe(5); // "World" length
        expect(result.summary.deletions).toBe(5); // "Hello" length
        expect(result.summary.totalDifferences).toBe(2);
        expect(result.rawDiffs).toEqual([
          { type: 'delete', text: 'Hello' },
          { type: 'insert', text: 'World' }
        ]);
      });

      it('should generate diff for texts with additions', () => {
        const text1 = 'Hello';
        const text2 = 'Hello World';
        
        mockDiffMain.mockReturnValue([
          [0, 'Hello'],
          [1, ' World']
        ]);
        
        const result = generateDiff(text1, text2);
        
        expect(result.html1).toBe('Hello');
        expect(result.html2).toBe('Hello<span class="bg-green-100 text-green-800"> World</span>');
        expect(result.summary.additions).toBe(6); // " World" length
        expect(result.summary.deletions).toBe(0);
        expect(result.summary.totalDifferences).toBe(1);
        expect(result.rawDiffs).toEqual([
          { type: 'equal', text: 'Hello' },
          { type: 'insert', text: ' World' }
        ]);
      });

      it('should generate diff for texts with deletions', () => {
        const text1 = 'Hello World';
        const text2 = 'Hello';
        
        mockDiffMain.mockReturnValue([
          [0, 'Hello'],
          [-1, ' World']
        ]);
        
        const result = generateDiff(text1, text2);
        
        expect(result.html1).toBe('Hello<span class="bg-red-100 text-red-800 line-through"> World</span>');
        expect(result.html2).toBe('Hello');
        expect(result.summary.additions).toBe(0);
        expect(result.summary.deletions).toBe(6); // " World" length
        expect(result.summary.totalDifferences).toBe(1);
        expect(result.rawDiffs).toEqual([
          { type: 'equal', text: 'Hello' },
          { type: 'delete', text: ' World' }
        ]);
      });
    });

    describe('HTML Escaping', () => {
      it('should escape HTML characters in equal text', () => {
        const text1 = '<div>Hello & "World"</div>';
        const text2 = '<div>Hello & "World"</div>';
        
        mockDiffMain.mockReturnValue([[0, '<div>Hello & "World"</div>']]);
        
        const result = generateDiff(text1, text2);
        
        const expectedEscaped = '&lt;div&gt;Hello &amp; &quot;World&quot;&lt;/div&gt;';
        expect(result.html1).toBe(expectedEscaped);
        expect(result.html2).toBe(expectedEscaped);
      });

      it('should escape HTML characters in insertions', () => {
        const text1 = 'Hello';
        const text2 = 'Hello <script>alert("xss")</script>';
        
        mockDiffMain.mockReturnValue([
          [0, 'Hello'],
          [1, ' <script>alert("xss")</script>']
        ]);
        
        const result = generateDiff(text1, text2);
        
        expect(result.html2).toBe('Hello<span class="bg-green-100 text-green-800"> &lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;</span>');
      });

      it('should escape HTML characters in deletions', () => {
        const text1 = 'Hello <img src="x" onerror="alert(1)">';
        const text2 = 'Hello';
        
        mockDiffMain.mockReturnValue([
          [0, 'Hello'],
          [-1, ' <img src="x" onerror="alert(1)">']
        ]);
        
        const result = generateDiff(text1, text2);
        
        expect(result.html1).toBe('Hello<span class="bg-red-100 text-red-800 line-through"> &lt;img src=&quot;x&quot; onerror=&quot;alert(1)&quot;&gt;</span>');
      });

      it('should convert newlines to <br /> tags', () => {
        const text1 = 'Line 1\nLine 2';
        const text2 = 'Line 1\nLine 2';
        
        mockDiffMain.mockReturnValue([[0, 'Line 1\nLine 2']]);
        
        const result = generateDiff(text1, text2);
        
        expect(result.html1).toBe('Line 1<br />Line 2');
        expect(result.html2).toBe('Line 1<br />Line 2');
      });

      it('should handle single quotes correctly', () => {
        const text1 = "It's a test";
        const text2 = "It's a test";
        
        mockDiffMain.mockReturnValue([[0, "It's a test"]]);
        
        const result = generateDiff(text1, text2);
        
        expect(result.html1).toBe('It&#039;s a test');
        expect(result.html2).toBe('It&#039;s a test');
      });
    });

    describe('Complex Diff Scenarios', () => {
      it('should handle mixed operations correctly', () => {
        const text1 = 'The quick brown fox';
        const text2 = 'The slow brown cat';
        
        mockDiffMain.mockReturnValue([
          [0, 'The '],
          [-1, 'quick'],
          [1, 'slow'],
          [0, ' brown '],
          [-1, 'fox'],
          [1, 'cat']
        ]);
        
        const result = generateDiff(text1, text2);
        
        expect(result.html1).toBe('The <span class="bg-red-100 text-red-800 line-through">quick</span> brown <span class="bg-red-100 text-red-800 line-through">fox</span>');
        expect(result.html2).toBe('The <span class="bg-green-100 text-green-800">slow</span> brown <span class="bg-green-100 text-green-800">cat</span>');
        expect(result.summary.additions).toBe(7); // "slow" + "cat"
        expect(result.summary.deletions).toBe(8); // "quick" + "fox"
        expect(result.summary.totalDifferences).toBe(4);
      });

      it('should handle multiple consecutive operations', () => {
        const text1 = 'ABC';
        const text2 = 'XYZ';
        
        mockDiffMain.mockReturnValue([
          [-1, 'A'],
          [1, 'X'],
          [-1, 'B'],
          [1, 'Y'],
          [-1, 'C'],
          [1, 'Z']
        ]);
        
        const result = generateDiff(text1, text2);
        
        expect(result.html1).toBe('<span class="bg-red-100 text-red-800 line-through">A</span><span class="bg-red-100 text-red-800 line-through">B</span><span class="bg-red-100 text-red-800 line-through">C</span>');
        expect(result.html2).toBe('<span class="bg-green-100 text-green-800">X</span><span class="bg-green-100 text-green-800">Y</span><span class="bg-green-100 text-green-800">Z</span>');
        expect(result.summary.additions).toBe(3);
        expect(result.summary.deletions).toBe(3);
        expect(result.summary.totalDifferences).toBe(6);
      });

      it('should handle long text with multiple changes', () => {
        const longText1 = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.';
        const longText2 = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor.';
        
        mockDiffMain.mockReturnValue([
          [0, 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.'],
          [1, ' Sed do eiusmod tempor.']
        ]);
        
        const result = generateDiff(longText1, longText2);
        
        expect(result.html1).toBe('Lorem ipsum dolor sit amet, consectetur adipiscing elit.');
        expect(result.html2).toBe('Lorem ipsum dolor sit amet, consectetur adipiscing elit.<span class="bg-green-100 text-green-800"> Sed do eiusmod tempor.</span>');
        expect(result.summary.additions).toBe(23); // " Sed do eiusmod tempor." length
        expect(result.summary.deletions).toBe(0);
        expect(result.summary.totalDifferences).toBe(1);
      });
    });

    describe('Edge Cases', () => {
      it('should handle empty strings', () => {
        const text1 = '';
        const text2 = '';
        
        mockDiffMain.mockReturnValue([]);
        
        const result = generateDiff(text1, text2);
        
        expect(result.html1).toBe('');
        expect(result.html2).toBe('');
        expect(result.summary.additions).toBe(0);
        expect(result.summary.deletions).toBe(0);
        expect(result.summary.totalDifferences).toBe(0);
        expect(result.rawDiffs).toEqual([]);
      });

      it('should handle one empty string', () => {
        const text1 = '';
        const text2 = 'Hello World';
        
        mockDiffMain.mockReturnValue([[1, 'Hello World']]);
        
        const result = generateDiff(text1, text2);
        
        expect(result.html1).toBe('');
        expect(result.html2).toBe('<span class="bg-green-100 text-green-800">Hello World</span>');
        expect(result.summary.additions).toBe(11);
        expect(result.summary.deletions).toBe(0);
        expect(result.summary.totalDifferences).toBe(1);
      });

      it('should handle whitespace-only changes', () => {
        const text1 = 'Hello World';
        const text2 = 'Hello  World'; // Extra space
        
        mockDiffMain.mockReturnValue([
          [0, 'Hello'],
          [1, ' '],
          [0, ' World']
        ]);
        
        const result = generateDiff(text1, text2);
        
        expect(result.html2).toBe('Hello<span class="bg-green-100 text-green-800"> </span> World');
        expect(result.summary.additions).toBe(1);
        expect(result.summary.deletions).toBe(0);
        expect(result.summary.totalDifferences).toBe(0); // Whitespace-only changes don't count
      });

      it('should handle only whitespace differences', () => {
        const text1 = '   ';
        const text2 = '    '; // One more space
        
        mockDiffMain.mockReturnValue([
          [0, '   '],
          [1, ' ']
        ]);
        
        const result = generateDiff(text1, text2);
        
        expect(result.summary.totalDifferences).toBe(0); // Only whitespace
      });

      it('should handle tabs and newlines', () => {
        const text1 = 'Line1\tTab\nLine2';
        const text2 = 'Line1\tTab\nLine2';
        
        mockDiffMain.mockReturnValue([[0, 'Line1\tTab\nLine2']]);
        
        const result = generateDiff(text1, text2);
        
        expect(result.html1).toBe('Line1\tTab<br />Line2');
        expect(result.html2).toBe('Line1\tTab<br />Line2');
      });

      it('should handle very long strings', () => {
        const longString = 'A'.repeat(10000);
        const text1 = longString;
        const text2 = longString + 'B';
        
        mockDiffMain.mockReturnValue([
          [0, longString],
          [1, 'B']
        ]);
        
        const result = generateDiff(text1, text2);
        
        expect(result.html1).toBe(longString);
        expect(result.html2).toBe(longString + '<span class="bg-green-100 text-green-800">B</span>');
        expect(result.summary.additions).toBe(1);
        expect(result.summary.deletions).toBe(0);
        expect(result.summary.totalDifferences).toBe(1);
      });

      it('should handle special Unicode characters', () => {
        const text1 = 'Hello 🌍';
        const text2 = 'Hello 🌎';
        
        mockDiffMain.mockReturnValue([
          [0, 'Hello '],
          [-1, '🌍'],
          [1, '🌎']
        ]);
        
        const result = generateDiff(text1, text2);
        
        expect(result.html1).toBe('Hello <span class="bg-red-100 text-red-800 line-through">🌍</span>');
        expect(result.html2).toBe('Hello <span class="bg-green-100 text-green-800">🌎</span>');
      });
    });

    describe('Raw Diffs Conversion', () => {
      it('should correctly convert numeric operations to string types', () => {
        const text1 = 'Hello';
        const text2 = 'World';
        
        mockDiffMain.mockReturnValue([
          [-1, 'Hello'],
          [1, 'World']
        ]);
        
        const result = generateDiff(text1, text2);
        
        expect(result.rawDiffs).toEqual([
          { type: 'delete', text: 'Hello' },
          { type: 'insert', text: 'World' }
        ]);
      });

      it('should handle unknown operation codes gracefully', () => {
        const text1 = 'Hello';
        const text2 = 'Hello';
        
        // Mock an unknown operation code
        mockDiffMain.mockReturnValue([
          [999, 'Hello'] // Unknown operation code
        ]);
        
        const result = generateDiff(text1, text2);
        
        expect(result.rawDiffs).toEqual([
          { type: 'equal', text: 'Hello' }
        ]);
      });
    });

    describe('Statistics Calculation', () => {
      it('should calculate statistics correctly for complex diff', () => {
        const text1 = 'The quick brown fox jumps';
        const text2 = 'The slow brown cat runs';
        
        mockDiffMain.mockReturnValue([
          [0, 'The '],
          [-1, 'quick'],
          [1, 'slow'],
          [0, ' brown '],
          [-1, 'fox jumps'],
          [1, 'cat runs']
        ]);
        
        const result = generateDiff(text1, text2);
        
        expect(result.summary.additions).toBe(12); // "slow" + "cat runs"
        expect(result.summary.deletions).toBe(14); // "quick" + "fox jumps"
        expect(result.summary.totalDifferences).toBe(4); // 2 deletions + 2 insertions
      });

      it('should not count empty changes in totalDifferences', () => {
        const text1 = 'Hello';
        const text2 = 'Hello';
        
        mockDiffMain.mockReturnValue([
          [0, 'Hello'],
          [-1, ''],
          [1, '']
        ]);
        
        const result = generateDiff(text1, text2);
        
        expect(result.summary.totalDifferences).toBe(0);
      });

      it('should count non-empty whitespace changes in character count but not totalDifferences', () => {
        const text1 = 'Hello';
        const text2 = 'Hello ';
        
        mockDiffMain.mockReturnValue([
          [0, 'Hello'],
          [1, ' ']
        ]);
        
        const result = generateDiff(text1, text2);
        
        expect(result.summary.additions).toBe(1);
        expect(result.summary.totalDifferences).toBe(0); // Whitespace only
      });
    });

    describe('Integration with diff_match_patch', () => {
      it('should call diff_main with correct parameters', () => {
        const text1 = 'Hello';
        const text2 = 'World';
        
        mockDiffMain.mockReturnValue([]);
        
        generateDiff(text1, text2);
        
        expect(mockDiffMain).toHaveBeenCalledWith('Hello', 'World');
      });

      it('should call diff_cleanupSemantic after diff_main', () => {
        const text1 = 'Hello';
        const text2 = 'World';
        
        const mockDiffs = [[-1, 'Hello'], [1, 'World']];
        mockDiffMain.mockReturnValue(mockDiffs);
        
        generateDiff(text1, text2);
        
        expect(mockDiffMain).toHaveBeenCalledWith('Hello', 'World');
        expect(mockDiffCleanupSemantic).toHaveBeenCalledWith(mockDiffs);
        expect(mockDiffMain).toHaveBeenCalledTimes(1);
        expect(mockDiffCleanupSemantic).toHaveBeenCalledTimes(1);
      });

      it('should handle diff_match_patch errors gracefully', () => {
        const text1 = 'Hello';
        const text2 = 'World';
        
        mockDiffMain.mockImplementation(() => {
          throw new Error('diff_match_patch error');
        });
        
        expect(() => generateDiff(text1, text2)).toThrow('diff_match_patch error');
      });
    });

    describe('Performance', () => {
      it('should handle multiple calls efficiently', () => {
        const text1 = 'Hello';
        const text2 = 'World';
        
        mockDiffMain.mockReturnValue([[-1, 'Hello'], [1, 'World']]);
        
        // Multiple calls
        for (let i = 0; i < 100; i++) {
          generateDiff(text1, text2);
        }
        
        expect(mockDiffMain).toHaveBeenCalledTimes(100);
      });

      it('should not leak memory with large diffs', () => {
        const largeText1 = 'A'.repeat(1000);
        const largeText2 = 'B'.repeat(1000);
        
        mockDiffMain.mockReturnValue([
          [-1, largeText1],
          [1, largeText2]
        ]);
        
        const result = generateDiff(largeText1, largeText2);
        
        expect(result.summary.additions).toBe(1000);
        expect(result.summary.deletions).toBe(1000);
      });
    });

    describe('Return Value Structure', () => {
      it('should return object with correct structure', () => {
        const text1 = 'Hello';
        const text2 = 'World';
        
        mockDiffMain.mockReturnValue([[-1, 'Hello'], [1, 'World']]);
        
        const result = generateDiff(text1, text2);
        
        expect(result).toHaveProperty('html1');
        expect(result).toHaveProperty('html2');
        expect(result).toHaveProperty('summary');
        expect(result).toHaveProperty('rawDiffs');
        
        expect(result.summary).toHaveProperty('additions');
        expect(result.summary).toHaveProperty('deletions');
        expect(result.summary).toHaveProperty('totalDifferences');
        
        expect(typeof result.html1).toBe('string');
        expect(typeof result.html2).toBe('string');
        expect(typeof result.summary.additions).toBe('number');
        expect(typeof result.summary.deletions).toBe('number');
        expect(typeof result.summary.totalDifferences).toBe('number');
        expect(Array.isArray(result.rawDiffs)).toBe(true);
      });

      it('should ensure rawDiffs have correct structure', () => {
        const text1 = 'Hello';
        const text2 = 'World';
        
        mockDiffMain.mockReturnValue([
          [-1, 'Hello'],
          [1, 'World'],
          [0, 'Same']
        ]);
        
        const result = generateDiff(text1, text2);
        
        result.rawDiffs.forEach(diff => {
          expect(diff).toHaveProperty('type');
          expect(diff).toHaveProperty('text');
          expect(['insert', 'delete', 'equal']).toContain(diff.type);
          expect(typeof diff.text).toBe('string');
        });
      });
    });
  });
}); 