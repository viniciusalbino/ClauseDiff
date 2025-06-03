# Padrões de Código, Testes e Automação – ClauseDiff

## 1. Padrões de Código
- **Linguagem:** TypeScript (strict mode)
- **Estilo:**
  - ESLint configurado com regras para Clean Architecture e import/order
  - Prettier para formatação consistente
  - Proibição de imports relativos cruzando domínios ("no-restricted-imports")
- **Configurações:**
  - [`tsconfig.json`](../../tsconfig.json)
  - [`.eslintrc.js`](../../.eslintrc.js)
  - [`prettier.config.js`](../../prettier.config.js)

## 2. Organização de Pastas
- **DDD + Clean Architecture:**
  - `src/domain/`, `src/application/`, `src/infrastructure/`, `src/presentation/`
- **Componentes UI:** Atomic Design em `src/presentation/ui/`
- **Testes:**
  - Unitários: `test/unit/` (espelhando estrutura de `src/`)
  - Integração: `test/integration/`

## 3. Testes
- **Ferramentas:** Jest + Testing Library
- **Cobertura:**
  - Cobertura mínima de 90% (temporariamente 10% para facilitar migração)
  - Relatórios em `coverage/`
- **Execução:**
  - `npm test` ou `npx jest`
  - Testes unitários e de integração automatizados
- **Configurações:**
  - [`jest.config.js`](../../jest.config.js)

## 4. Automação
- **CI/CD:**
  - Deploy automatizado no Netlify
  - Build, lint e testes executados em cada push
- **Husky:**
  - Pre-commit hooks para lint, test e format
  - Bloqueia commits quebrados
- **Scripts:**
  - `npm run lint`, `npm run format`, `npm run test`, `npm run build`
- **Configurações:**
  - [`netlify.toml`](../../netlify.toml)
  - [`.husky/`](../../.husky/)

## 5. Protocolo de Commits
- Mensagens de commit devem referenciar o task ID e descrever a mudança (ex: `5.1 Estrutura de autenticação`)
- PRs devem linkar para o task/PBI correspondente

## 6. Referências
- [README.md](../../README.md)
- [PRD de Migração](../../tasks/prd-migracao-nextjs14.md) 