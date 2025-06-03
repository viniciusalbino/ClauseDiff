# PRD – Sistema de Autenticação Seguro ClauseDiff

## 1. Introdução/Overview

O objetivo deste projeto é implementar um sistema de autenticação robusto e seguro para o ClauseDiff, utilizando Auth.js (NextAuth) com Next.js, seguindo as melhores práticas de segurança recomendadas pela OWASP e NIST. O sistema permitirá que advogados e o público em geral possam se cadastrar, logar e acessar o restante do sistema de forma segura, eficiente e em conformidade com LGPD/GDPR.

## 2. Goals (Objetivos)

- Permitir cadastro e login de usuários (advogados e público geral).
- Suportar autenticação via email/senha e Google OAuth.
- Garantir segurança máxima, protegendo contra ataques comuns e vazamento de dados.
- Facilitar a recuperação de senha de forma segura.
- Prover gerenciamento de perfil básico.
- Medir e otimizar: tempo médio de login, taxa de recuperação de senha, conversão de login e zero incidentes de segurança.

## 3. User Stories

- Como usuário, quero me cadastrar usando email e senha para acessar o ClauseDiff.
- Como usuário, quero fazer login rapidamente usando minha conta Google.
- Como usuário, quero redefinir minha senha de forma segura para não perder acesso ao sistema.
- Como usuário, quero recuperar minha senha caso esqueça, recebendo um código por email.
- Como usuário, quero editar meu perfil básico (nome, sobrenome, email, senha, cidade, estado, CPF).
- Como admin, quero gerenciar permissões de acesso dos usuários.

## 4. Functional Requirements (Requisitos Funcionais)

1. O sistema deve permitir cadastro de usuários com email, senha, nome e sobrenome (obrigatórios), cidade, estado e CPF (opcionais).
2. O sistema deve permitir login via email/senha e Google OAuth.
3. O sistema deve validar credenciais usando Zod e armazenar senhas com bcrypt + salt.
4. O sistema deve enviar código de verificação por email para recuperação de senha.
5. O sistema deve permitir redefinição de senha via código enviado por email.
6. O sistema deve permitir gerenciamento de perfil (alteração de nome, sobrenome, cidade, estado, CPF, email/senha).
7. O sistema deve implementar RBAC com roles: user e admin.
8. O sistema deve proteger endpoints com middleware de autenticação e autorização.
9. O sistema deve registrar eventos de login/logout para auditoria.
10. O sistema deve proteger contra ataques de força bruta (rate limiting) e timing attacks.
11. O sistema deve implementar headers de segurança (CSP, HSTS, etc.).
12. O sistema deve ser totalmente tipado (TypeScript) e seguir princípios SOLID.
13. O sistema deve ser compatível com LGPD/GDPR.
14. O sistema deve ser facilmente testável, com testes de segurança para vulnerabilidades comuns.
15. O sistema deve utilizar Prisma para modelagem de usuários, contas, sessões e tokens, com migrations automatizadas e índices otimizados.

## 5. Non-Goals (Fora de Escopo)

- Não implementar 2FA neste momento.
- Não permitir login via Apple ou outros provedores além de Google.
- Não usar SMS para autenticação ou recuperação de senha.
- Não coletar telefone ou dados de cobrança nesta fase inicial.
- Não implementar multi-tenancy.
- Não permitir alteração de roles via interface de usuário comum.

## 6. Design Considerations

- Utilizar o HTML básico fornecido como base para as telas de autenticação, adaptando para React/Next.js e TailwindCSS.
- Garantir acessibilidade e responsividade (mobile-first).
- Utilizar fontes Inter e Noto Sans, conforme exemplo.
- Seguir padrões de UX modernos, com feedback visual claro para erros e sucesso.
- Botões de login social devem ser destacados e facilmente identificáveis.

## 7. Technical Considerations

- Utilizar Next.js (App Router) e Auth.js (NextAuth) com adapter Prisma.
- Utilizar Supabase (já configurado via MCP) para envio de emails (SMTP) e armazenamento de dados.
- Implementar logging e auditoria de eventos de autenticação.
- Utilizar Zod para validação de dados.
- Utilizar bcrypt para hash de senhas.
- Implementar rate limiting no middleware de login.
- Implementar proteção CSRF avançada.
- Utilizar JWT com refresh token e rotação segura.
- Garantir que todo o código seja TypeScript type-safe.
- Implementar testes automatizados para cenários de segurança (ex: brute force, CSRF, XSS).
- Planejar o schema para futura integração com sistema de cobrança.

## 8. Success Metrics

- Tempo médio de login ≤ 2 segundos.
- Taxa de recuperação de senha ≥ 90% (usuários conseguem recuperar sem suporte).
- Zero incidentes de segurança reportados.
- Conversão de login (cadastro → login) ≥ 80%.
- Conformidade com LGPD/GDPR validada.

## 9. Open Questions

- Serviço de email: Supabase (já configurado via MCP).
- Integração futura com sistema de cobrança: Sim, schema deve ser planejado para expansão.
- Ferramenta de auditoria/logging: Sem preferência definida.
- Limitação de infraestrutura: Sem limitação identificada. 