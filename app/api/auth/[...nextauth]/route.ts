/**
 * Auth route para autenticação com NextAuth v4 (Next.js 14 App Router).
 *
 * POLÍTICA DE AUDITORIA E LOGGING:
 * - Este endpoint implementa logging/auditoria de eventos de autenticação (login, logout, falha, etc.)
 *   para fins de segurança, rastreabilidade e compliance (LGPD/GDPR).
 * - O logging é controlado pela feature flag de ambiente AUDIT_LOGGING_ENABLED.
 *   - Para ativar: defina AUDIT_LOGGING_ENABLED=on no .env
 *   - Por padrão, o log está DESLIGADO para evitar custos/desempenho no MVP.
 * - Os eventos são registrados na tabela AuditLog do banco via Prisma.
 * - Falhas no log NÃO afetam o fluxo de autenticação.
 *
 * Para ativar o login Google OAuth, defina GOOGLE_CLIENT_ID e GOOGLE_CLIENT_SECRET no .env
 * Exemplo:
 *   GOOGLE_CLIENT_ID=xxxx.apps.googleusercontent.com
 *   GOOGLE_CLIENT_SECRET=xxxx
 */

import NextAuth from "next-auth";
import { authOptions } from "../../../../src/lib/auth-config";

const handler = NextAuth(authOptions);

export { handler as GET, handler as POST }; 