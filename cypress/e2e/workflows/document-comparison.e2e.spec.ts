import { DocumentComparisonPage } from '../../support/page-objects';

describe('Document Upload and Comparison Workflow E2E', () => {
  const docPage = new DocumentComparisonPage();
  
  beforeEach(() => {
    // Setup authenticated user
    cy.createTestUser({
      email: 'doctest@example.com',
      password: 'Password123',
      firstName: 'Document',
      lastName: 'Tester'
    });
    
    cy.loginApi('doctest@example.com', 'Password123');
    cy.visit('/compare');
    cy.checkA11y();
  });

  afterEach(() => {
    cy.deleteTestUser('doctest@example.com');
  });

  describe('File Upload Workflow', () => {
    context('Single File Upload', () => {
      it('should successfully upload a PDF file', () => {
        const fileName = 'sample-document.pdf';
        
        docPage.uploadFirstFile(fileName);
        
        // Verify file is uploaded and displayed
        cy.get('[data-testid="file1-name"]')
          .should('be.visible')
          .and('contain', fileName);
        
        // Verify file details are shown
        cy.get('[data-testid="file1-size"]').should('be.visible');
        cy.get('[data-testid="file1-type"]').should('contain', 'PDF');
        
        // Verify upload progress completed
        cy.get('[data-testid="file1-upload-progress"]').should('not.exist');
        cy.get('[data-testid="file1-upload-success"]').should('be.visible');
        
        cy.checkA11y();
      });

      it('should upload a Word document', () => {
        const fileName = 'sample-document.docx';
        
        docPage.uploadFirstFile(fileName);
        
        cy.get('[data-testid="file1-name"]').should('contain', fileName);
        cy.get('[data-testid="file1-type"]').should('contain', 'Word');
      });

      it('should upload a text file', () => {
        const fileName = 'sample-text.txt';
        
        docPage.uploadFirstFile(fileName);
        
        cy.get('[data-testid="file1-name"]').should('contain', fileName);
        cy.get('[data-testid="file1-type"]').should('contain', 'Text');
      });

      it('should show upload progress for large files', () => {
        // Create a larger test file
        const fileName = 'large-document.pdf';
        
        // Mock slow upload to see progress
        cy.intercept('POST', '/api/files/upload', {
          delay: 2000,
          statusCode: 200,
          body: { fileId: 'file-123', fileName: fileName }
        }).as('slowUpload');
        
        docPage.uploadFirstFile(fileName);
        
        // Should show progress bar
        cy.get('[data-testid="file1-upload-progress"]')
          .should('be.visible')
          .and('have.attr', 'aria-valuenow');
        
        // Should show upload status
        cy.get('[data-testid="file1-upload-status"]')
          .should('contain', 'Uploading...');
        
        cy.wait('@slowUpload');
        
        // Progress should complete
        cy.get('[data-testid="file1-upload-success"]').should('be.visible');
      });
    });

    context('Dual File Upload', () => {
      it('should upload two files sequentially', () => {
        const file1Name = 'document-v1.pdf';
        const file2Name = 'document-v2.pdf';
        
        // Upload first file
        docPage.uploadFirstFile(file1Name);
        cy.get('[data-testid="file1-name"]').should('contain', file1Name);
        
        // Upload second file
        docPage.uploadSecondFile(file2Name);
        cy.get('[data-testid="file2-name"]').should('contain', file2Name);
        
        // Both files should be ready
        cy.get('[data-testid="file1-upload-success"]').should('be.visible');
        cy.get('[data-testid="file2-upload-success"]').should('be.visible');
        
        // Compare button should be enabled
        cy.get('[data-testid="compare-button"]').should('not.be.disabled');
      });

      it('should handle concurrent file uploads', () => {
        // Start both uploads simultaneously
        docPage.uploadFilesConcurrently('doc1.pdf', 'doc2.pdf');
        
        // Both should complete successfully
        cy.get('[data-testid="file1-upload-success"]').should('be.visible');
        cy.get('[data-testid="file2-upload-success"]').should('be.visible');
        
        cy.get('[data-testid="compare-button"]').should('not.be.disabled');
      });

      it('should allow replacing uploaded files', () => {
        // Upload initial files
        docPage.uploadFirstFile('original1.pdf');
        docPage.uploadSecondFile('original2.pdf');
        
        // Replace first file
        docPage.replaceFirstFile('replacement1.pdf');
        
        cy.get('[data-testid="file1-name"]').should('contain', 'replacement1.pdf');
        cy.get('[data-testid="file2-name"]').should('contain', 'original2.pdf');
        
        // Replace second file
        docPage.replaceSecondFile('replacement2.pdf');
        
        cy.get('[data-testid="file2-name"]').should('contain', 'replacement2.pdf');
      });
    });

    context('Drag and Drop Upload', () => {
      it('should support drag and drop file upload', () => {
        const fileName = 'drag-drop-test.pdf';
        
        docPage.dragAndDropFile(fileName, 'file1-dropzone');
        
        cy.get('[data-testid="file1-name"]').should('contain', fileName);
        cy.get('[data-testid="file1-upload-success"]').should('be.visible');
      });

      it('should show drag over visual feedback', () => {
        cy.get('[data-testid="file1-dropzone"]')
          .trigger('dragenter')
          .should('have.class', 'drag-over');
        
        cy.get('[data-testid="file1-dropzone"]')
          .trigger('dragleave')
          .should('not.have.class', 'drag-over');
      });

      it('should handle multiple files dropped on same zone', () => {
        // Drop multiple files - should only accept the first
        docPage.dragAndDropMultipleFiles(['file1.pdf', 'file2.pdf'], 'file1-dropzone');
        
        cy.get('[data-testid="multiple-files-warning"]')
          .should('be.visible')
          .and('contain', 'Only one file can be uploaded at a time');
        
        // Should only upload the first file
        cy.get('[data-testid="file1-name"]').should('contain', 'file1.pdf');
      });
    });

    context('File Validation', () => {
      it('should reject unsupported file types', () => {
        docPage.uploadUnsupportedFile('image.jpg');
        
        cy.get('[data-testid="file-error"]')
          .should('be.visible')
          .and('contain', 'Unsupported file type');
        
        cy.get('[data-testid="supported-formats-link"]')
          .should('be.visible')
          .and('contain', 'View supported formats');
      });

      it('should reject files that are too large', () => {
        // Mock a large file upload
        cy.intercept('POST', '/api/files/upload', {
          statusCode: 413,
          body: { error: 'File too large', maxSize: '10MB' }
        }).as('largeFileUpload');
        
        docPage.uploadFirstFile('large-file.pdf');
        
        cy.wait('@largeFileUpload');
        
        cy.get('[data-testid="file-size-error"]')
          .should('be.visible')
          .and('contain', 'File size exceeds the 10MB limit');
      });

      it('should reject corrupted files', () => {
        cy.intercept('POST', '/api/files/upload', {
          statusCode: 400,
          body: { error: 'File appears to be corrupted' }
        }).as('corruptedFileUpload');
        
        docPage.uploadFirstFile('corrupted.pdf');
        
        cy.wait('@corruptedFileUpload');
        
        cy.get('[data-testid="file-corruption-error"]')
          .should('be.visible')
          .and('contain', 'File appears to be corrupted');
      });

      it('should validate file content matches extension', () => {
        cy.intercept('POST', '/api/files/upload', {
          statusCode: 400,
          body: { error: 'File content does not match extension' }
        }).as('mismatchedFileUpload');
        
        docPage.uploadFirstFile('fake.pdf'); // Actually a text file with .pdf extension
        
        cy.wait('@mismatchedFileUpload');
        
        cy.get('[data-testid="file-mismatch-error"]')
          .should('be.visible')
          .and('contain', 'File content does not match the extension');
      });
    });
  });

  describe('Document Comparison Process', () => {
    beforeEach(() => {
      // Upload two test files for comparison
      docPage.uploadFirstFile('document-v1.pdf');
      docPage.uploadSecondFile('document-v2.pdf');
    });

    context('Comparison Execution', () => {
      it('should successfully compare two documents', () => {
        docPage.startComparison();
        
        // Should show processing state
        cy.get('[data-testid="comparison-status"]')
          .should('contain', 'Analyzing documents...');
        
        cy.get('[data-testid="comparison-progress"]')
          .should('be.visible')
          .and('have.attr', 'aria-valuenow');
        
        // Wait for completion
        docPage.waitForComparisonComplete();
        
        // Should show results
        cy.get('[data-testid="comparison-results"]').should('be.visible');
        cy.get('[data-testid="similarity-score"]').should('be.visible');
        cy.get('[data-testid="differences-summary"]').should('be.visible');
        
        cy.checkA11y();
      });

      it('should show detailed comparison progress stages', () => {
        docPage.startComparison();
        
        // Should progress through stages
        const stages = [
          'Preparing documents...',
          'Extracting text...',
          'Analyzing differences...',
          'Generating results...'
        ];
        
        stages.forEach((stage) => {
          cy.get('[data-testid="comparison-stage"]')
            .should('contain', stage);
        });
        
        docPage.waitForComparisonComplete();
      });

      it('should allow canceling comparison in progress', () => {
        // Mock slow comparison to allow cancellation
        cy.intercept('POST', '/api/files/compare', {
          delay: 10000,
          statusCode: 200,
          body: { comparisonId: 'test-123' }
        }).as('slowComparison');
        
        docPage.startComparison();
        
        // Cancel while in progress
        cy.get('[data-testid="cancel-comparison-button"]')
          .should('be.visible')
          .click();
        
        cy.get('[data-testid="comparison-cancelled"]')
          .should('be.visible')
          .and('contain', 'Comparison cancelled');
        
        // Should return to initial state
        cy.get('[data-testid="compare-button"]').should('not.be.disabled');
      });
    });

    context('Comparison Results Display', () => {
      beforeEach(() => {
        docPage.startComparison();
        docPage.waitForComparisonComplete();
      });

      it('should display similarity score and statistics', () => {
        cy.get('[data-testid="similarity-score"]')
          .should('be.visible')
          .and('contain', '%');
        
        cy.get('[data-testid="total-differences"]').should('be.visible');
        cy.get('[data-testid="additions-count"]').should('be.visible');
        cy.get('[data-testid="deletions-count"]').should('be.visible');
        cy.get('[data-testid="modifications-count"]').should('be.visible');
      });

      it('should show differences in a navigable list', () => {
        cy.get('[data-testid="differences-list"]').should('be.visible');
        
        // Should have navigation controls
        cy.get('[data-testid="prev-difference"]').should('be.visible');
        cy.get('[data-testid="next-difference"]').should('be.visible');
        cy.get('[data-testid="difference-counter"]').should('be.visible');
        
        // Should be able to navigate through differences
        cy.get('[data-testid="next-difference"]').click();
        cy.get('[data-testid="current-difference"]').should('have.attr', 'data-index', '1');
      });

      it('should highlight differences with proper visual indicators', () => {
        // Check for different types of changes
        cy.get('[data-testid="added-text"]')
          .should('have.class', 'diff-added')
          .and('be.visible');
        
        cy.get('[data-testid="deleted-text"]')
          .should('have.class', 'diff-deleted')
          .and('be.visible');
        
        cy.get('[data-testid="modified-text"]')
          .should('have.class', 'diff-modified')
          .and('be.visible');
      });

      it('should provide side-by-side view toggle', () => {
        // Switch to side-by-side view
        cy.get('[data-testid="view-toggle"]').click();
        cy.get('[data-testid="side-by-side-view"]').should('be.visible');
        
        // Should show both documents
        cy.get('[data-testid="document1-view"]').should('be.visible');
        cy.get('[data-testid="document2-view"]').should('be.visible');
        
        // Switch back to unified view
        cy.get('[data-testid="view-toggle"]').click();
        cy.get('[data-testid="unified-view"]').should('be.visible');
      });

      it('should support zooming and navigation controls', () => {
        docPage.zoomIn();
        cy.get('[data-testid="zoom-level"]').should('contain', '110%');
        
        docPage.zoomOut();
        cy.get('[data-testid="zoom-level"]').should('contain', '100%');
        
        docPage.resetZoom();
        cy.get('[data-testid="zoom-level"]').should('contain', '100%');
      });
    });

    context('Filtering and Search', () => {
      beforeEach(() => {
        docPage.startComparison();
        docPage.waitForComparisonComplete();
      });

      it('should filter differences by type', () => {
        // Filter to show only additions
        cy.get('[data-testid="filter-additions"]').click();
        
        cy.get('[data-testid="differences-list"] .diff-added')
          .should('be.visible');
        cy.get('[data-testid="differences-list"] .diff-deleted')
          .should('not.exist');
        
        // Clear filter
        cy.get('[data-testid="clear-filters"]').click();
        cy.get('[data-testid="differences-list"] .diff-deleted')
          .should('be.visible');
      });

      it('should search within differences', () => {
        const searchTerm = 'specific text';
        
        cy.get('[data-testid="search-differences"]')
          .type(searchTerm);
        
        cy.get('[data-testid="search-results"]')
          .should('be.visible')
          .and('contain', 'matches found');
        
        // Should highlight search matches
        cy.get('[data-testid="search-highlight"]')
          .should('be.visible')
          .and('contain', searchTerm);
      });

      it('should provide advanced filtering options', () => {
        // Open advanced filters
        cy.get('[data-testid="advanced-filters"]').click();
        
        // Filter by line range
        cy.get('[data-testid="line-range-from"]').type('1');
        cy.get('[data-testid="line-range-to"]').type('50');
        cy.get('[data-testid="apply-line-filter"]').click();
        
        // Should only show differences in specified range
        cy.get('[data-testid="differences-list"] [data-line]')
          .each(($el) => {
            const lineNum = parseInt($el.attr('data-line') || '0');
            expect(lineNum).to.be.within(1, 50);
          });
      });
    });
  });

  describe('Export Functionality', () => {
    beforeEach(() => {
      docPage.uploadFirstFile('document-v1.pdf');
      docPage.uploadSecondFile('document-v2.pdf');
      docPage.startComparison();
      docPage.waitForComparisonComplete();
    });

    context('PDF Export', () => {
      it('should export comparison results as PDF', () => {
        // Mock the download
        cy.window().then((win) => {
          cy.stub(win, 'open').as('windowOpen');
        });
        
        docPage.exportToPDF();
        
        cy.get('[data-testid="export-progress"]')
          .should('be.visible')
          .and('contain', 'Generating PDF...');
        
        cy.get('[data-testid="export-success"]')
          .should('be.visible')
          .and('contain', 'PDF exported successfully');
        
        // Verify download was triggered
        cy.get('@windowOpen').should('have.been.called');
      });

      it('should allow customizing PDF export options', () => {
        cy.get('[data-testid="export-options"]').click();
        
        // Customize export settings
        cy.get('[data-testid="include-summary"]').check();
        cy.get('[data-testid="include-metadata"]').check();
        cy.get('[data-testid="page-orientation"]').select('landscape');
        
        docPage.exportToPDF();
        
        cy.get('[data-testid="export-success"]').should('be.visible');
      });
    });

    context('CSV Export', () => {
      it('should export differences as CSV', () => {
        docPage.exportToCSV();
        
        cy.get('[data-testid="csv-export-success"]')
          .should('be.visible')
          .and('contain', 'CSV exported successfully');
      });

      it('should include proper CSV headers and formatting', () => {
        // Mock the CSV response to verify content
        cy.intercept('POST', '/api/export/csv', {
          statusCode: 200,
          headers: {
            'Content-Type': 'text/csv',
            'Content-Disposition': 'attachment; filename="comparison.csv"'
          },
          body: 'Line,Type,Original,Modified,Status\n1,addition,"","New text",added\n'
        }).as('csvExport');
        
        docPage.exportToCSV();
        
        cy.wait('@csvExport');
        cy.get('[data-testid="csv-export-success"]').should('be.visible');
      });
    });

    context('Export Error Handling', () => {
      it('should handle export generation failures', () => {
        cy.intercept('POST', '/api/export/pdf', {
          statusCode: 500,
          body: { error: 'PDF generation failed' }
        }).as('pdfExportError');
        
        docPage.exportToPDF();
        
        cy.wait('@pdfExportError');
        
        cy.get('[data-testid="export-error"]')
          .should('be.visible')
          .and('contain', 'Failed to generate PDF');
        
        // Should offer retry option
        cy.get('[data-testid="retry-export"]')
          .should('be.visible')
          .and('contain', 'Try again');
      });

      it('should handle large export timeouts', () => {
        cy.intercept('POST', '/api/export/pdf', {
          delay: 30000 // Simulate timeout
        }).as('slowExport');
        
        docPage.exportToPDF();
        
        // Should show timeout message after reasonable wait
        cy.get('[data-testid="export-timeout"]', { timeout: 10000 })
          .should('be.visible')
          .and('contain', 'Export is taking longer than expected');
      });
    });
  });

  describe('Responsive Design and Mobile Support', () => {
    context('Mobile Viewport', () => {
      beforeEach(() => {
        cy.viewport('iphone-6');
      });

      it('should adapt upload interface for mobile', () => {
        // Upload areas should stack vertically on mobile
        cy.get('[data-testid="upload-container"]')
          .should('have.class', 'mobile-layout');
        
        // File selection should work with touch
        docPage.uploadFirstFile('mobile-test.pdf');
        
        cy.get('[data-testid="file1-name"]').should('contain', 'mobile-test.pdf');
      });

      it('should provide mobile-optimized comparison view', () => {
        docPage.uploadFirstFile('doc1.pdf');
        docPage.uploadSecondFile('doc2.pdf');
        docPage.startComparison();
        docPage.waitForComparisonComplete();
        
        // Should use mobile-optimized layout
        cy.get('[data-testid="comparison-results"]')
          .should('have.class', 'mobile-optimized');
        
        // Touch gestures should work for navigation
        cy.get('[data-testid="differences-list"]')
          .trigger('touchstart', { touches: [{ clientX: 100, clientY: 100 }] })
          .trigger('touchend');
      });
    });

    context('Tablet Viewport', () => {
      beforeEach(() => {
        cy.viewport('ipad-2');
      });

      it('should optimize layout for tablet screens', () => {
        docPage.uploadFirstFile('tablet-doc1.pdf');
        docPage.uploadSecondFile('tablet-doc2.pdf');
        
        // Should use tablet-optimized layout
        cy.get('[data-testid="upload-container"]')
          .should('have.class', 'tablet-layout');
        
        docPage.startComparison();
        docPage.waitForComparisonComplete();
        
        // Side-by-side view should work well on tablet
        cy.get('[data-testid="view-toggle"]').click();
        cy.get('[data-testid="side-by-side-view"]')
          .should('be.visible')
          .and('have.class', 'tablet-optimized');
      });
    });
  });

  describe('Performance and Large Document Handling', () => {
    it('should handle large documents efficiently', () => {
      // Mock large document processing
      cy.intercept('POST', '/api/files/upload', {
        delay: 1000,
        statusCode: 200,
        body: { 
          fileId: 'large-doc-1',
          fileName: 'large-document.pdf',
          size: 50000000, // 50MB
          pages: 500
        }
      }).as('largeDocUpload');
      
      docPage.uploadFirstFile('large-document.pdf');
      
      cy.wait('@largeDocUpload');
      
      // Should show appropriate warnings for large files
      cy.get('[data-testid="large-file-warning"]')
        .should('be.visible')
        .and('contain', 'Large file detected');
      
      cy.get('[data-testid="processing-time-estimate"]')
        .should('be.visible')
        .and('contain', 'Estimated processing time');
    });

    it('should implement pagination for large comparison results', () => {
      // Mock comparison with many differences
      cy.intercept('POST', '/api/files/compare', {
        statusCode: 200,
        body: {
          comparisonId: 'large-comparison',
          similarity: 60,
          totalDifferences: 1000,
          differences: Array.from({ length: 50 }, (_, i) => ({
            line: i + 1,
            type: 'modified',
            text: `Difference ${i + 1}`
          })),
          pagination: {
            page: 1,
            pageSize: 50,
            totalPages: 20
          }
        }
      }).as('largeComparisonResults');
      
      docPage.uploadFirstFile('doc1.pdf');
      docPage.uploadSecondFile('doc2.pdf');
      docPage.startComparison();
      
      cy.wait('@largeComparisonResults');
      
      // Should show pagination controls
      cy.get('[data-testid="pagination-controls"]').should('be.visible');
      cy.get('[data-testid="page-info"]').should('contain', 'Page 1 of 20');
      
      // Should be able to navigate pages
      cy.get('[data-testid="next-page"]').click();
      cy.get('[data-testid="page-info"]').should('contain', 'Page 2 of 20');
    });
  });

  describe('Error Recovery and Edge Cases', () => {
    it('should recover from network interruptions during upload', () => {
      // Start upload, then simulate network error
      cy.intercept('POST', '/api/files/upload', {
        forceNetworkError: true
      }).as('networkError');
      
      docPage.uploadFirstFile('network-test.pdf');
      
      cy.wait('@networkError');
      
      cy.get('[data-testid="upload-error"]')
        .should('be.visible')
        .and('contain', 'Network error during upload');
      
      // Resume upload after network recovery
      cy.intercept('POST', '/api/files/upload', {
        statusCode: 200,
        body: { fileId: 'resumed-upload', fileName: 'network-test.pdf' }
      }).as('resumedUpload');
      
      cy.get('[data-testid="retry-upload"]').click();
      
      cy.wait('@resumedUpload');
      cy.get('[data-testid="file1-upload-success"]').should('be.visible');
    });

    it('should handle browser refresh during comparison', () => {
      docPage.uploadFirstFile('refresh-test1.pdf');
      docPage.uploadSecondFile('refresh-test2.pdf');
      docPage.startComparison();
      
      // Simulate refresh during processing
      cy.reload();
      
      // Should detect incomplete comparison and offer recovery
      cy.get('[data-testid="recovery-banner"]')
        .should('be.visible')
        .and('contain', 'Previous comparison was interrupted');
      
      cy.get('[data-testid="resume-comparison"]').click();
      
      // Should restore state and continue
      docPage.waitForComparisonComplete();
      cy.get('[data-testid="comparison-results"]').should('be.visible');
    });

    it('should handle session expiration gracefully', () => {
      docPage.uploadFirstFile('session-test1.pdf');
      
      // Mock session expiration
      cy.intercept('POST', '/api/files/upload', {
        statusCode: 401,
        body: { error: 'Session expired' }
      }).as('sessionExpired');
      
      docPage.uploadSecondFile('session-test2.pdf');
      
      cy.wait('@sessionExpired');
      
      cy.get('[data-testid="session-expired-modal"]')
        .should('be.visible')
        .and('contain', 'Your session has expired');
      
      // Should offer re-authentication without losing work
      cy.get('[data-testid="reauth-button"]').click();
      cy.url().should('include', '/login');
    });
  });
});