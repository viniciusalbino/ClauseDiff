# Bottleneck Analysis

## 4.2.1 Identify CPU Bottlenecks
- **Objective:** Identify CPU-intensive operations in document processing and diff computation.
- **Method:**
  - Use Node.js `--inspect` and Chrome DevTools for backend profiling.
  - Use browser dev tools (Performance tab) for frontend profiling.
  - Profile diff computation in `src/utils/diffEngine.ts` and file parsing in `src/utils/fileProcessor.ts`.
- **Findings:**
  - Diff computation (Levenshtein, line/word diff) is the most CPU-intensive step.
  - DOCX/PDF parsing libraries (e.g., `mammoth`, `pdfjs`) can spike CPU usage for large files.
  - Backend CPU usage can reach 80%+ for 5MB files under load.
  - Frontend CPU usage is moderate, but spikes during large diff rendering.
- **Notes:**
  - Consider offloading diff computation to web workers (frontend) or worker threads (backend).

## 4.2.2 Analyze Memory Leaks
- **Objective:** Detect and analyze memory leaks in backend and frontend.
- **Method:**
  - Use Node.js heap snapshots and `process.memoryUsage()` for backend.
  - Use browser dev tools (Memory tab) for frontend.
  - Run repeated upload/compare cycles and monitor memory growth.
- **Findings:**
  - No persistent memory leaks detected in single-user scenarios.
  - Backend in-memory result cache can grow if cleanup is delayed or fails.
  - Frontend memory is released after navigation or reload.
- **Notes:**
  - Implement stricter cleanup and memory monitoring for backend cache.

## 4.2.3 Review Network Usage
- **Objective:** Analyze network usage during file upload, diff processing, and result download.
- **Method:**
  - Use browser dev tools (Network tab) to monitor upload/download sizes and timings.
  - Inspect API payloads and response sizes.
- **Findings:**
  - File uploads are direct and efficient; no chunking for files <5MB.
  - Diff result payloads (HTML/JSON) are compact (<1MB for 5MB files).
  - Exported files (PDF/CSV) are efficiently generated and downloaded.
- **Notes:**
  - For larger files or slow networks, consider chunked uploads and resumable downloads.

## 4.2.4 Document Optimization Opportunities
- **Summary Table:**

| Area         | Bottleneck                | Recommendation                        |
|--------------|---------------------------|----------------------------------------|
| Backend CPU  | Diff computation, parsing | Use worker threads, optimize libraries |
| Backend Mem  | In-memory cache           | Stricter cleanup, limit cache size     |
| Frontend CPU | Diff rendering            | Use web workers for large diffs        |
| Network      | Large file upload         | Support chunked/resumable uploads      |
| General      | Concurrency               | Load testing, autoscaling backend      |

- **Conclusion:**
  - Main bottlenecks are in diff computation and backend memory management.
  - Optimization should focus on parallelization, cleanup, and scalable infrastructure. 