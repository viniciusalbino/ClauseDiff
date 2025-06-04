# Architecture Overview

## 1.4.1 Create Architecture Overview Document
- **Objective:** Summarize the overall system architecture.
- **Updated Overview (as of YYYY-MM-DD - Please replace with actual date):**
  - **Frontend Application (Client & BFF):**
    - Technology: Next.js (App Router) with React and TypeScript.
    - Responsibilities: User Interface (UI), user authentication handling (via NextAuth), routing, and Backend-for-Frontend (BFF) API routes that orchestrate calls to other services (Supabase, Processing Service).
    - Location: `app/` (routing, pages) and `src/` (core logic, components, services, domain models).
  - **Processing Backend Service (Clause Comparison Engine):**
    - Technology: Node.js with Express.js.
    - Responsibilities: Handles the computationally intensive task of comparing two `.docx` documents. Exposes an API endpoint (`/diff`) for this purpose.
    - Location: `backend/`.
    - Note: This service was previously referred to as "MCP server" in some contexts.
  - **Backend Platform (PaaS):**
    - Technology: Supabase.
    - Responsibilities: Provides PostgreSQL database for user data and application data, handles user authentication (integrated with NextAuth), and offers potential for file storage and serverless functions.
    - Location: Cloud-based service, with migrations managed in `supabase/migrations` and `src/infrastructure/database/migrations`.
  - **Deployment Strategy:**
    - Next.js Application: Deployed to Netlify.
    - Processing Backend Service: Currently runs as a standalone Node.js server (e.g., on port 3001 locally). Production deployment strategy (e.g., Netlify Functions, container, separate server/VM) needs to be solidified.
  - **Data Storage:**
    - User credentials & application data: Supabase (PostgreSQL).
    - Document diff results: Currently stored in-memory within the Processing Backend Service for a limited time (e.g., 1 hour).
  - **Security:**
    - Authentication: Handled by NextAuth with Supabase.
    - Data Protection: Adherence to GDPR/LGPD principles.
    - Further considerations: Secure communication between Next.js app and Processing Service (e.g., API keys, tokens).

## 1.4.2 Document Technical Decisions and Rationale
- **Key Decisions & Rationale (Updated):**
  - **Next.js Framework:** Chosen for its comprehensive features for full-stack development (React-based UI, server-side rendering, API routes, optimized performance), streamlining the development of the user-facing application and its immediate backend needs.
  - **Separate Express.js Processing Service:** Decouples the resource-intensive document comparison logic from the main frontend application. This allows for independent scaling, maintenance, and potentially different technology choices for the processing core if needed.
  - **Supabase as BaaS:** Leveraged for its managed database and authentication services, accelerating backend development and reducing infrastructure management overhead.
  - **Netlify for Deployment (Frontend):** Utilized for its robust CI/CD pipeline, global CDN, and serverless functions capabilities, simplifying the deployment and hosting of the Next.js application.
  - **In-memory Storage for Diff Results (Current Phase):** Adopted for initial simplicity in the Processing Service. Future iterations may consider persistent storage for diff results.

## 1.4.3 Create System Context Diagram
- **Updated Diagram:**

```mermaid
graph TD
    User[<img src='https://img.icons8.com/ios-glyphs/30/user.png' width='20' height='20' /><br/>User] -->|Interacts via Browser| NextJsApp[<img src='https://img.icons8.com/color/48/nextjs.png' width='30' height='30' /><br/><b>Next.js Application</b><br/>(in `app/` & `src/`)<br/>UI, Auth Orchestration, BFF APIs]
    
    NextJsApp -->|User Data, Auth Ops| SupabasePlatform[<img src='https://img.icons8.com/color/48/supabase.png' width='30' height='30' /><br/><b>Supabase</b><br/>(Database & Auth Service)]
    NextJsApp -->|Uploads .docx, Requests Diff| ProcessingService[<img src='https://img.icons8.com/fluency/48/node-js.png' width='30' height='30' /><br/><b>Express.js Processing Service</b><br/>(in `backend/`)<br/>DOCX Diff Logic via /diff API]
    
    ProcessingService -->|Stores/Retrieves Diff Results (temporary)| InMemoryStorage[<img src='https://img.icons8.com/ios-filled/50/data-configuration.png' width='20' height='20' /><br/>In-Memory Result Storage]

    NextJsApp -->|Deployment & Hosting| Netlify[<img src='https://img.icons8.com/external-tal-revivo-shadow-tal-revivo/48/external-netlify-a-cloud-computing-company-that-offers-hosting-and-serverless-backend-services-for-static-websites-logo-shadow-tal-revivo.png' width='30' height='30' /><br/><b>Netlify Platform</b>]
    %% The Processing Service's production deployment isn't via Netlify by default with current setup,
    %% but could be a Netlify Function or other hosting.
    %% For clarity, the diagram shows Netlify primarily for the Next.js app.
```

## 1.4.4 Document Integration Points
- **Key Integration Points (Updated):**
  - **Next.js Application <-> Express.js Processing Service:**
    - Communication: HTTP API calls (e.g., POST to `/diff` on the Processing Service).
    - Data Format: Typically JSON for request metadata, multipart/form-data for file uploads.
    - Authentication: Currently none explicit; to be considered for enhancement.
  - **Next.js Application <-> Supabase:**
    - Communication: Via Prisma client (for database interactions) and NextAuth adapter (for authentication flows).
    - Data Format: SQL queries abstracted by Prisma; JSON/objects for application logic.
  - **Deployment & Hosting:**
    - Next.js Application: Integrated with Netlify for CI/CD, build, and hosting.
    - Express.js Processing Service: Runs as a standalone Node.js process. Integration with a production hosting environment (e.g., Netlify Functions, container platform like Docker/Kubernetes, or a PaaS like Heroku/Render) needs to be defined and implemented for production.
  - **Development Environment:**
    - Next.js frontend runs on its development server (e.g., `localhost:3000`).
    - Express.js backend runs on its server (e.g., `localhost:3001`).
    - `NEXT_PUBLIC_PROCESSING_SERVICE_URL` environment variable in Next.js app to point to the Express service.
- **Conclusion:**
  - The architecture separates concerns into a user-facing Next.js application and a specialized backend processing service, supported by Supabase for core backend functionalities. This modular design supports scalability, maintainability, and focused development on each component. Clear definition of deployment and inter-service communication strategies for production is an important next step. 