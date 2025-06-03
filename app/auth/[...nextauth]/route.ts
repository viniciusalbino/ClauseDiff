/**
 * Auth route para autenticação com NextAuth (Next.js 14 App Router).
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

import NextAuth, { NextAuthOptions, Session, User, Account, Profile } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import { JWT } from "next-auth/jwt";
import { z } from "zod";
import bcrypt from "bcryptjs";
// Certifique-se de instalar as dependências:
// npm install next-auth @auth/prisma-adapter @prisma/client zod bcryptjs
import { PrismaAdapter } from "@auth/prisma-adapter";
import { PrismaClient } from "@prisma/client";
import { NextRequest } from "next/server";
import GoogleProvider from "next-auth/providers/google";

const prisma = new PrismaClient();

// Feature flag para logging de auditoria (evita custo em MVP)
const AUDIT_LOGGING_ENABLED = process.env.AUDIT_LOGGING_ENABLED === "on";

// Função utilitária para registrar eventos de auditoria
async function logEvent({ userId, eventType, headers, details, ip, userAgent }: { userId?: string; eventType: string; headers?: Headers; details?: any; ip?: string | null; userAgent?: string | null }) {
  // Só registra se a feature flag estiver ativada
  if (!AUDIT_LOGGING_ENABLED) return;
  try {
    await prisma.auditLog.create({
      data: {
        userId,
        eventType,
        ip: (ip ?? headers?.get("x-forwarded-for")) || null,
        userAgent: (userAgent ?? headers?.get("user-agent")) || null,
        details,
      },
    });
  } catch (err) {
    // Não lançar erro para não quebrar o fluxo de autenticação
    console.error("Erro ao registrar evento de auditoria:", err);
  }
}

// Esquema de validação para login
const credentialsSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
});

export const authOptions: NextAuthOptions = {
  adapter: PrismaAdapter(prisma),
  providers: [
    CredentialsProvider({
      name: "Email e Senha",
      credentials: {
        email: { label: "Email", type: "email", placeholder: "seu@email.com" },
        password: { label: "Senha", type: "password" },
      },
      async authorize(credentials, req) {
        // Validação com Zod
        const parsed = credentialsSchema.safeParse(credentials);
        if (!parsed.success) {
          throw new Error("Credenciais inválidas");
        }
        const { email, password } = parsed.data;
        // Busca usuário no banco
        const user = await prisma.user.findUnique({ where: { email } });
        // Extrai IP e user-agent manualmente do req.headers (Record<string, any> | undefined)
        let ip: string | null = null;
        let userAgent: string | null = null;
        if (req?.headers) {
          ip = req.headers["x-forwarded-for"] ?? null;
          userAgent = req.headers["user-agent"] ?? null;
        }
        if (!user || !user.password) {
          await logEvent({ eventType: "login_failed", details: { email }, ip, userAgent });
          throw new Error("Usuário ou senha inválidos");
        }
        // Verifica senha com bcrypt
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
          await logEvent({ userId: user.id, eventType: "login_failed", details: { email }, ip, userAgent });
          throw new Error("Usuário ou senha inválidos");
        }
        // Retorna objeto user para NextAuth
        return {
          id: user.id,
          email: user.email,
          name: `${user.firstName} ${user.lastName}`,
          role: user.role,
        };
      },
    }),
    // Provedor Google OAuth (ativado apenas se as variáveis de ambiente estiverem presentes)
    ...(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET
      ? [GoogleProvider({
          clientId: process.env.GOOGLE_CLIENT_ID!,
          clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
          // Escopo mínimo necessário para autenticação
          authorization: {
            params: { scope: "openid email profile" },
          },
        })]
      : []),
  ],
  session: {
    strategy: "jwt",
  },
  pages: {
    signIn: "/login",
    error: "/login?error=true",
  },
  callbacks: {
    async signIn({ user, account, profile, email, credentials }) {
      // Log de login bem-sucedido
      await logEvent({ userId: user?.id, eventType: "login_success" });
      return true;
    },
    async session({ session, user, token }: { session: Session; user?: User; token?: JWT }) {
      return session;
    },
    async jwt({ token, user, account, profile, trigger, session }: {
      token: JWT;
      user?: User;
      account?: Account | null;
      profile?: Profile;
      trigger?: string;
      session?: Session;
    }) {
      return token;
    },
  },
  events: {
    async signIn(message: { user: User }) {
      // Log de login via event (fallback)
      await logEvent({ userId: message.user?.id, eventType: "login_event" });
    },
    async signOut(message: { token?: JWT }) {
      // Log de logout via event (fallback)
      await logEvent({ userId: message.token?.sub, eventType: "logout_event" });
    },
    // O callback 'error' não é suportado oficialmente pelo tipo EventCallbacks do NextAuth
    // Para logging de erros, use middlewares ou monitore logs do próprio NextAuth
  },
  // Outras opções e customizações serão adicionadas nos próximos sub-tasks
};

const handler = NextAuth(authOptions);

export { handler as GET, handler as POST }; 