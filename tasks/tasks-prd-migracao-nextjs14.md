## Relevant Files

- `next.config.mjs` – Next.js configuration for performance, i18n, and experimental features.
- `tsconfig.json` – TypeScript config with strict mode and path aliases.
- `.eslintrc.js` – ESLint config enforcing Clean Architecture and code quality.
- `prettier.config.js` – Prettier config for code formatting.
- `.husky/` – Husky hooks for lint, test, and format on commit.
- `jest.config.cjs` – Jest config with 90%+ coverage enforcement (coverageThreshold).
- `src/legacy/` – Legacy codebase preserved for incremental migration.
- `src/domain/types.ts` – Domain types and value-objects (migrated from root).
- `src/domain/constants.ts` – Domain constants (migrated from legacy/constants).
- `src/domain/value-objects/` – Value-objects for domain logic.
- `src/application/use-cases/generateDiff.ts` – Use-case: generate document diff (migrated from legacy/utils/diffEngine.ts).
- `src/application/use-cases/processFile.ts` – Use-case: process file uploads (migrated from legacy/utils/fileProcessor.ts).
- `src/application/use-cases/exportHandler.ts` – Use-case: export logic (migrated from legacy/utils/exportHandler.ts).
- `src/application/services/apiService.ts` – Service: API integration (migrated from legacy/services/api.ts).
- `src/infrastructure/repositories/apiRepository.ts` – API repository implementation (migrated from legacy/services/api.ts).
- `src/presentation/components/FileUpload.tsx` – File upload UI component (migrated from legacy).
- `src/presentation/components/ComparisonView.tsx` – Diff visualization component (migrated from legacy).
- `src/presentation/components/DifferenceSummary.tsx` – Summary of differences (migrated from legacy).
- `src/presentation/components/Toolbar.tsx` – Export and settings controls (migrated from legacy).
- `src/presentation/components/LoadingSpinner.tsx` – UI feedback for loading (migrated from legacy).
- `src/presentation/components/icons/` – Icon components (migrated from legacy).
- `src/presentation/utils/docxProcessor.ts` – Utility for DOCX processing (migrated from legacy).
- `src/presentation/layouts/` – Layout components (structure created).
- `src/presentation/hooks/` – Custom hooks (structure created).
- `src/presentation/providers/intlProvider.tsx` – NextIntl provider for i18n (pt, es, en).
- `messages/pt.json` – Portuguese translations for i18n.
- `messages/es.json` – Spanish translations for i18n.
- `messages/en.json` – English translations for i18n.
- `src/presentation/providers/` – Providers for context/state (structure created).
- `src/domain/` – DDD: Entities, value-objects, repositories, services (interfaces).
- `src/application/` – DDD: Use-cases, DTOs, services (implementations).
- `src/infrastructure/` – DDD: Repositories (implementations), external-services, database, storage.
- `src/presentation/` – DDD: Components, ui (atomic design), forms, layouts, hooks, providers, utils.
- `src/utils/diffEngine.ts` – Diff logic, to be migrated/refactored.
- `src/utils/fileProcessor.ts` – File parsing logic, to be migrated/refactored.
- `src/utils/exportHandler.ts` – Export logic, to be migrated/refactored.
- `src/services/api.ts` – API service, to be migrated/refactored.
- `backend/tests/docProcessor.test.js` – Unit tests for document processing.
- `test/unit/` – New/updated unit tests for migrated modules (mirroring `src/`).
- `test/integration/` – Integration tests for end-to-end flows.
- `docs/architecture/` – Architecture, migration, and technical documentation.
- `docs/testing/` – Testing strategy and coverage documentation.

### Notes

- Unit tests should typically be placed alongside the code files they are testing (e.g., `MyComponent.tsx` and `MyComponent.test.tsx` in the same directory) or in `test/unit/` mirroring the source structure.
- Use `npx jest [optional/path/to/test/file]` to run tests. Running without a path executes all tests found by the Jest configuration.

## Tasks

- [x] 1.0 Inicializar Projeto Next.js 14 e Configuração Base
  - [x] 1.1 Criar novo projeto Next.js 14 com App Router.
  - [x] 1.2 Configurar `next.config.mjs` para performance, i18n e experimental features.
  - [x] 1.3 Configurar `tsconfig.json` com strict mode e path aliases.
  - [x] 1.4 Configurar ESLint, Prettier e Husky para enforcing de padrões.
  - [x] 1.5 Configurar Jest e Testing Library para testes unitários.
  - [x] 1.6 Configurar deploy automatizado no Netlify.
  - [x] 1.7 Copiar código atual para `/src/legacy` e garantir funcionamento como fallback.

- [x] 2.0 Migrar Código Legado para Estrutura DDD + Clean Architecture
  - [x] 2.1 Criar estrutura de diretórios DDD: `domain`, `application`, `infrastructure`, `presentation`.
  - [x] 2.2 Migrar entidades e value-objects para `src/domain`.
  - [x] 2.3 Migrar e refatorar use-cases para `src/application`.
  - [x] 2.4 Migrar e refatorar repositórios e serviços para `src/infrastructure`.
  - [x] 2.5 Migrar e refatorar componentes, layouts, hooks e utils para `src/presentation`.
  - [x] 2.6 Refatorar componentes para Server/Client conforme necessidade.
  - [x] 2.7 Implementar padrão CQRS nos use-cases.
  - [x] 2.8 Garantir funcionamento incremental (feature flag/fallback para legacy).

- [x] 3.0 Implementar Internacionalização e Acessibilidade
  - [x] 3.1 Configurar biblioteca de i18n (ex: next-intl ou i18next).
  - [x] 3.2 Adicionar suporte a pt, es, en.
  - [x] 3.3 Refatorar componentes para internacionalização.
  - [x] 3.4 Implementar práticas de acessibilidade (WCAG) em todos os componentes.
  - [x] 3.5 Validar acessibilidade com ferramentas automáticas e manuais.

- [x] 4.0 Configurar e Garantir Qualidade de Código, Testes e Automação
  - [x] 4.1 Configurar cobertura de testes unitários (90%+).
  - [ ] 4.2 Escrever/atualizar testes unitários para módulos migrados.
  - [ ] 4.3 Escrever testes de integração para fluxos críticos.
  - [ ] 4.4 Configurar automação de build, lint, test e deploy no Netlify.
  - [ ] 4.5 Monitorar cobertura e qualidade de código continuamente.

- [ ] 5.0 Preparar Estrutura para Autenticação e Futuras Expansões
  - [ ] 5.1 Criar estrutura de rotas e providers para autenticação (sem implementar lógica).
  - [ ] 5.2 Documentar pontos de integração para autenticação futura.
  - [ ] 5.3 Preparar estrutura para futuras integrações (analytics, pagamentos, etc.).

- [ ] 6.0 Documentar Arquitetura, Padrões e Processo de Migração
  - [ ] 6.1 Documentar arquitetura e decisões técnicas em `docs/architecture/`.
  - [ ] 6.2 Documentar padrões de código, testes e automação.
  - [ ] 6.3 Documentar processo de migração incremental e fallback.
  - [ ] 6.4 Atualizar documentação de onboarding para novos desenvolvedores. 