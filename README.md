# ClauseDiff - Document Comparison Tool

## 1. Project Overview

ClauseDiff is a client-side web application designed to help users compare two documents (.docx, .pdf, .txt) and identify differences between them. It visually highlights additions and deletions, provides a summary of changes, and allows users to export the comparison report in PDF format or a list of changes in CSV format. A key feature of ClauseDiff is its commitment to privacy: all document processing and comparison tasks are performed directly in the user's browser, meaning no files are uploaded to or stored on any server.

## 2. Core Functionality

*   **Document Upload**: Supports uploading two documents of types DOCX, PDF, or TXT.
*   **Client-Side Processing**: All file parsing and text extraction happen in the browser.
    *   `.docx` files are processed using Mammoth.js.
    *   `.pdf` files are processed using PDF.js.
    *   `.txt` files are read as plain text.
*   **Text Comparison**: Utilizes the `diff-match-patch` library to perform a robust comparison of the extracted text content from the two documents.
*   **Visual Difference Highlighting**: Displays the content of both documents side-by-side, with insertions highlighted in green and deletions in red (with a strikethrough).
*   **Difference Summary**: Provides a concise summary of changes, including the number of characters added/deleted and the total number of differing blocks. It also lists the most significant changes.
*   **Export to PDF**: Allows users to export the side-by-side comparison view as a PDF document using jsPDF and html2canvas.
*   **Export to CSV**: Enables exporting a list of identified additions and deletions in CSV format.

## 3. Architecture

ClauseDiff is a single-page application (SPA) built with React and TypeScript.

*   **Frontend**:
    *   **React**: For building the user interface components.
    *   **TypeScript**: For static typing and improved code quality.
    *   **Tailwind CSS**: For utility-first styling.
*   **Core Logic Libraries**:
    *   **`diff-match-patch`**: Google's library for text differencing and patch application.
    *   **`mammoth.js`**: Converts `.docx` documents to HTML and extracts raw text.
    *   **`pdf.js` (by Mozilla)**: Parses `.pdf` files and extracts text content.
    *   **`jspdf` & `html2canvas`**: Used in combination to generate PDF reports from HTML content.
*   **Application Structure**:
    *   `index.html`: The main HTML file that loads necessary CDN libraries and the React application.
    *   `index.tsx`: The entry point for the React application, mounting the `App` component.
    *   `App.tsx`: The main application component, managing state, file uploads, comparison logic, and orchestrating UI updates.
    *   `components/`: Contains reusable React components for UI elements like file uploads, comparison views, toolbar, difference summary, and icons.
    *   `utils/`: Houses utility functions for:
        *   `fileProcessor.ts`: Logic for reading and extracting text/HTML from different file types.
        *   `diffEngine.ts`: Wrapper around `diff-match-patch` to generate comparison results.
        *   `exportHandler.ts`: Functions for PDF and CSV export.
    *   `types.ts`: Defines TypeScript interfaces and types used throughout the application.
    *   `constants.ts`: Stores shared constants like color palettes and text sizes.
    *   `metadata.json`: Contains metadata about the application.
*   **Client-Side Processing**: All document processing and comparison logic runs entirely in the user's browser. This ensures user privacy as documents are not transmitted to any external server.

## 4. Key Technologies Used

*   React 19
*   TypeScript
*   Tailwind CSS
*   Diff-Match-Patch
*   Mammoth.js
*   PDF.js
*   jsPDF
*   html2canvas

## 5. File Structure Overview

```
/
├── App.tsx                  # Main application component
├── index.tsx                # React entry point
├── components/              # UI components
│   ├── icons/               # SVG icon components
│   ├── ComparisonView.tsx
│   ├── DifferenceSummary.tsx
│   ├── FileUpload.tsx
│   ├── LoadingSpinner.tsx
│   └── Toolbar.tsx
├── utils/                   # Utility functions
│   ├── diffEngine.ts
│   ├── exportHandler.ts
│   └── fileProcessor.ts
├── constants.ts             # Application-wide constants
├── types.ts                 # TypeScript type definitions
├── index.html               # Main HTML page
├── metadata.json            # Application metadata
└── README.md                # This file
```

## 6. Running Locally

Since this application is entirely client-side and relies on CDN-hosted libraries and ES modules, there's no complex build step required. You can run it by serving the project directory with a simple HTTP server.

1.  **Navigate to the project directory:**
    Open your terminal or command prompt and change to the directory where `index.html` is located.

2.  **Start a local HTTP server:**
    You have several options:

    *   **Using `npx serve` (requires Node.js and npm/npx):**
        ```bash
        npx serve
        ```
        This will typically start a server and tell you the local address (e.g., `http://localhost:3000`).

    *   **Using Python's built-in HTTP server:**
        If you have Python installed:
        *   Python 3.x:
            ```bash
            python -m http.server
            ```
        *   Python 2.x:
            ```bash
            python -m SimpleHTTPServer
            ```
        This will usually serve the files on `http://localhost:8000`.

    *   **Using a live server extension in your code editor (e.g., VS Code Live Server):**
        Many code editors have extensions that can launch a local development server with a single click.

3.  **Open the application in your browser:**
    Once the server is running, open your web browser and navigate to the local address provided by the server (e.g., `http://localhost:3000` or `http://localhost:8000`). You should see `index.html` rendered.

**Note:** Directly opening `index.html` via the `file:///` protocol might not work correctly due to browser security restrictions related to ES modules or other web features. Always use a local HTTP server.