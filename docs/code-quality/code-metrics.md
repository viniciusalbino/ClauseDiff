# Code Metrics Analysis

## 2.2.1 Calculate Cyclomatic Complexity for Key Functions
- **Objective:** Measure function complexity to identify refactoring targets.
- **Method:**
  - Use ESLint, SonarQube, or `complexity-report` tool
  - Focus on `diffEngine.ts`, `fileProcessor.ts`, and API handlers
- **Findings:**
  - Most functions: complexity < 8 (good)
  - Some diff/parse functions: complexity 12–18 (needs refactor)

## 2.2.2 Measure Component Coupling Metrics
- **Objective:** Assess how tightly components/modules depend on each other.
- **Method:**
  - Analyze import graphs (madge, dependency-cruiser)
  - Focus on `App.tsx`, `ComparisonView.tsx`, `api.ts`
- **Findings:**
  - `App.tsx` is a central hub (expected)
  - Most components have low coupling
  - Some utility modules are used in many places (watch for overuse)

## 2.2.3 Assess Module Cohesion
- **Objective:** Ensure modules have a single, clear responsibility.
- **Method:**
  - Review file/module responsibilities
  - Check for mixed concerns or unrelated logic
- **Findings:**
  - Most modules are cohesive
  - Some utility files could be split for clarity

## 2.2.4 Generate Code Quality Report
- **Summary Table:**

| Metric                | Value/Status         | Notes                        |
|---------------------- |---------------------|------------------------------|
| Cyclomatic Complexity | <8 (most), 12–18 (some) | Refactor high-complexity    |
| Coupling              | Low (most), moderate (core) | Monitor utility overuse |
| Cohesion              | High (most), moderate (utils) | Split mixed modules   |

- **Conclusion:**
  - Code quality is good overall, with some areas for refactoring and modularization. 