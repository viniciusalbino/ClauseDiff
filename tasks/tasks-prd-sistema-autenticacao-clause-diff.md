## Relevant Files

- `src/infrastructure/database/schema.prisma` - Prisma schema: modelagem de usuários, contas, sessões, tokens, billing e audit log compatíveis com Auth.js (NextAuth), incluindo índices otimizados, relações e enum Role.
- `app/api/auth/[...nextauth]/route.ts` - Configuração principal do Auth.js (NextAuth) com adapters e provedores.
- `middleware.ts` - Middleware de segurança para autenticação, autorização e headers.
- `src/hooks/useAuth.ts` - Hook React para autenticação e sessão.
- `src/hooks/useRequireAuth.ts` - Hook React para proteção de rotas.
- `src/hooks/usePermissions.ts` - Hook React para RBAC.
- `src/components/LoginForm.tsx` - Componente de formulário de login.
- `src/components/RegisterForm.tsx` - Componente de formulário de cadastro.
- `src/components/PasswordRecoveryForm.tsx` - Componente de recuperação de senha.
- `src/components/ProfileForm.tsx` - Componente de gerenciamento de perfil.
- `test/security/auth.test.ts` - Testes automatizados de segurança e autenticação.
- `test/security/middleware.test.ts` - Testes de middleware de segurança.

### Notes

- Unit tests devem ser colocados próximos aos arquivos de código correspondentes.
- Use `npx jest [optional/path/to/test/file]` para rodar os testes.
- O banco de dados já está preparado para logging/auditoria de eventos de autenticação e segurança via tabela `AuditLog`.

## Tasks

- [x] 1.0 Modelagem e Migrations Prisma
  - [x] 1.1 Definir o schema de usuários com campos obrigatórios (nome, sobrenome, email, senha) e opcionais (cidade, estado, CPF)
  - [x] 1.2 Definir models para contas, sessões e tokens compatíveis com Auth.js
  - [x] 1.3 Criar migrations automatizadas
  - [x] 1.4 Adicionar índices otimizados para queries frequentes
  - [x] 1.5 Planejar expansão futura para cobrança (billing)
  - [x] 1.6 Testar integridade do schema e migrations

- [x] 2.0 Implementação do Auth.js (NextAuth) com provedores e adapter Prisma
  - [x] 2.1 Configurar Auth.js com TypeScript type-safe
  - [x] 2.2 Integrar adapter Prisma com customizações para logging e auditoria
  - [x] 2.3 Implementar provedor de credenciais (email/senha) com validação Zod e hash bcrypt + salt
  - [x] 2.4 Implementar provedor Google OAuth com escopo mínimo necessário
  - [x] 2.5 Implementar rotação de tokens JWT com refresh strategy
  - [x] 2.6 Implementar proteção CSRF avançada
  - [x] 2.7 Testar fluxos de cadastro, login, logout e recuperação de senha

- [x] 3.0 Implementação dos Middlewares de Segurança
  - [x] 3.1 Implementar rate limiting para tentativas de login
  - [x] 3.2 Implementar proteção contra timing attacks
  - [x] 3.3 Adicionar headers de segurança (CSP, HSTS, etc.)
  - [x] 3.4 Implementar logging de eventos de segurança
  - [x] 3.5 Testar middleware em cenários de ataque simulados

- [x] 4.0 Implementação dos Hooks e Componentes de Autenticação no Frontend
  - [x] 4.1 Implementar hook `useAuth()` com tipagem completa
  - [x] 4.2 Implementar hook `useRequireAuth()` com redirecionamento e preservação de URL
  - [x] 4.3 Implementar hook `usePermissions()` para RBAC
  - [x] 4.4 Criar componente de formulário de login com validação e feedback
  - [x] 4.5 Criar componente de cadastro com validação de campos obrigatórios e opcionais
  - [x] 4.6 Criar componente de recuperação de senha com envio de código por email
  - [x] 4.7 Criar componente de gerenciamento de perfil (edição de dados do usuário)
  - [x] 4.8 Adaptar UI para acessibilidade, responsividade e feedback visual
  - [x] 4.9 Testar todos os fluxos de autenticação no frontend

- [x] 5.0 Implementação de RBAC e Gerenciamento de Permissões
  - [x] 5.1 Definir roles (user, admin) no schema e Auth.js
  - [x] 5.2 Implementar permissões granulares para cada role
  - [x] 5.3 Implementar middleware para verificação de permissões em rotas API
  - [x] 5.4 Testar restrição de acesso conforme role do usuário

- [x] 6.0 Testes de Segurança e Conformidade
  - [x] 6.1 Escrever testes automatizados para fluxos de autenticação (login, cadastro, recuperação de senha)
  - [x] 6.2 Escrever testes para cenários de ataque (brute force, CSRF, XSS, timing attacks)
  - [x] 6.3 Validar conformidade com LGPD/GDPR (exclusão de dados, consentimento)
  - [x] 6.4 Validar métricas de sucesso (tempo de login, taxa de recuperação, conversão)
  - [x] 6.5 Documentar resultados dos testes e ajustes necessários 