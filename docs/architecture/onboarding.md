# Onboarding para Novos Desenvolvedores – ClauseDiff

## Visão Geral do Projeto
ClauseDiff é uma aplicação para comparação de documentos, migrada para Next.js 14 com DDD e Clean Architecture. O objetivo é garantir escalabilidade, testabilidade e preparação para internacionalização, acessibilidade e integrações futuras.

## 1. Pré-requisitos
- Node.js 18+
- npm 9+
- Netlify CLI (para deploy local)

## 2. Setup do Ambiente
```sh
git clone <repo-url>
cd clausediff
npm install
```
- Para rodar localmente:
  - `npm run dev`
- Para rodar testes:
  - `npm test`
- Para rodar lint/format:
  - `npm run lint`
  - `npm run format`
- Para build de produção:
  - `npm run build`
- Para deploy local Netlify:
  - `netlify dev`

## 3. Estrutura de Diretórios
- Veja [overview.md](./overview.md) para detalhes completos.
- Principais pastas:
  - `/app`: Rotas e entrypoints Next.js 14
  - `/src/domain`: Entidades, value-objects, interfaces
  - `/src/application`: Use-cases, DTOs, serviços
  - `/src/infrastructure`: Repositórios, integrações externas
  - `/src/presentation`: Componentes, UI, layouts, hooks, providers
  - `/src/legacy`: Código legado (fallback durante migração)

## 4. Padrões de Código e Testes
- TypeScript (strict)
- ESLint + Prettier
- Testes com Jest + Testing Library
- Veja [code-quality.md](./code-quality.md)

## 5. Protocolo de Commits e Contribuição
- Commits devem referenciar o task ID e descrever a mudança (ex: `6.4 Onboarding doc`)
- PRs devem linkar para o task/PBI correspondente
- Siga o fluxo de tarefas descrito em [tasks-prd-migracao-nextjs14.md](../../tasks/tasks-prd-migracao-nextjs14.md)

## 6. Documentação Importante
- [Visão Geral da Arquitetura](./overview.md)
- [Processo de Migração](./migration-process.md)
- [Integração de Autenticação](./auth-integration.md)
- [Padrões de Código e Testes](./code-quality.md)
- [PRD de Migração](../../tasks/prd-migracao-nextjs14.md)

## 7. Dúvidas e Contato
- Consulte a documentação acima.
- Para dúvidas técnicas, abra uma issue ou consulte o responsável pelo projeto. 