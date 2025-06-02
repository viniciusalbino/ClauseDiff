# Data Processing Activities Map

## Document Processing Flow

### 1. File Upload and Initial Processing
- **Location**: `src/components/FileUpload.tsx`
- **Data Types**: .docx, .pdf, .txt files
- **Size Limit**: 5MB per file
- **Processing Steps**:
  1. File validation (MIME type and extension)
  2. Client-side file reading using FileReader API
  3. Temporary storage in component state

### 2. Document Processing
- **Location**: `src/utils/fileProcessor.ts`
- **Processing Types**:
  - DOCX: Using mammoth.js for text extraction
  - PDF: Using PDF.js for text extraction
  - TXT: Direct text reading
- **Data Storage**: 
  - In-memory only
  - Stored in React component state
  - No persistent storage

### 3. Document Comparison
- **Location**: 
  - Frontend: `src/utils/diffEngine.ts`
  - Backend (unused): `backend/src/services/docProcessor.js`
- **Processing**:
  - Text comparison using diff algorithm
  - HTML generation for visualization
  - Statistics calculation (additions, deletions, modifications)

### 4. Data Retention
- **Location**: `backend/src/routes/diff.js`
- **Retention Policy**:
  - In-memory storage with 1-hour expiration
  - Automatic cleanup via setTimeout
  - No persistent storage

### 5. Data Export
- **Location**: `src/utils/exportHandler.ts`
- **Export Formats**:
  - PDF: Using jsPDF and html2canvas
  - CSV: Raw diff data export
- **Data Handling**:
  - Client-side processing
  - Direct download to user's device
  - No server storage

## GDPR/LGPD Considerations

### Data Collection
- Only document content is processed
- No personal data collection
- No user tracking
- No cookies used

### Data Storage
- Temporary in-memory storage only
- 1-hour maximum retention
- No persistent storage
- No database usage

### Data Transfer
- All processing done client-side
- No data sent to third parties
- Export files generated and downloaded locally

### User Rights
- No user accounts required
- No data persistence
- Direct control over document upload/download
- No data sharing with third parties

## Security Measures

### File Validation
- MIME type checking
- File extension validation
- Size limit enforcement (5MB)
- Allowed file types restriction

### Data Protection
- Client-side processing
- No server-side storage
- Automatic cleanup
- No sensitive data collection

### Access Control
- No authentication required
- No user accounts
- Direct file access only

## Recommendations

1. **Documentation**:
   - Add privacy policy
   - Document data processing in user interface
   - Add data retention notices

2. **Security**:
   - Implement file sanitization
   - Add virus scanning
   - Consider adding optional authentication

3. **Compliance**:
   - Add GDPR/LGPD compliance notices
   - Document data processing purposes
   - Add user consent mechanisms

4. **Monitoring**:
   - Add logging for security events
   - Monitor file processing errors
   - Track system performance

## Open Questions

1. Should we implement user authentication for audit trails?
2. Do we need to add file sanitization?
3. Should we implement server-side processing for large files?
4. Do we need to add data encryption for sensitive documents? 