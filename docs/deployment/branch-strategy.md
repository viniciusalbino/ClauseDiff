# Branch Strategy

## 6.3.1 Review Current Branching
- **Objective:** Assess the current branching model for suitability and efficiency.
- **Current Setup:**
  - `main` branch for production
  - Feature branches for new work
  - PRs required for merging to `main`
  - Netlify deploys previews for all branches
- **Findings:**
  - Simple and effective for small/medium teams
  - All deploys traceable to a branch/PR

## 6.3.2 Design Branch Workflow
- **Objective:** Define a clear, scalable workflow for development and releases.
- **Recommended Workflow:**
  - `main`: production-ready code only
  - `develop`: (optional) for staging/integration
  - `feature/*`: new features
  - `bugfix/*`: bug fixes
  - `hotfix/*`: urgent production fixes
  - PRs required for all merges to `main`/`develop`
- **Best Practices:**
  - Use branch naming conventions
  - Require code review and CI checks before merge

## 6.3.3 Document Branch Policies
- **Objective:** Ensure all contributors follow consistent branch policies.
- **Policies:**
  - All work must be on a branch (no direct commits to `main`)
  - PRs must reference a task or issue
  - CI must pass before merge
  - Use descriptive commit messages
- **Documentation:**
  - Maintain branch policy doc in `docs/deployment/`

## 6.3.4 Create Branch Guide
- **Objective:** Provide a clear guide for branching, merging, and conflict resolution.
- **Guide:**
  - How to create, update, and delete branches
  - How to resolve merge conflicts
  - How to use Netlify/MCP previews for branch testing
  - How to rollback or hotfix production
- **Conclusion:**
  - A clear branch strategy and guide ensures smooth collaboration, safe deploys, and traceable changes. 