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
import { PrismaAdapter } from "@next-auth/prisma-adapter";
import { PrismaClient } from "@prisma/client";
import GoogleProvider from "next-auth/providers/google";
import CredentialsProvider from "next-auth/providers/credentials";
import bcrypt from "bcryptjs";
import { z } from "zod";


const prisma = new PrismaClient();

// Feature flag para logging de auditoria
const AUDIT_LOGGING_ENABLED = process.env.AUDIT_LOGGING_ENABLED === "on";

// Função utilitária para registrar eventos de auditoria
async function logEvent({ userId, eventType, ip, userAgent, details }: { userId?: string; eventType: string; ip?: string | null; userAgent?: string | null; details?: any }) {
  if (!AUDIT_LOGGING_ENABLED) return;
  try {
    await prisma.auditLog.create({
      data: {
        userId,
        eventType,
        ip: ip || null,
        userAgent: userAgent || null,
        details,
      },
    });
  } catch (err) {
    console.error("Erro ao registrar evento de auditoria:", err);
  }
}

const credentialsSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
});

const authOptions = {
  adapter: PrismaAdapter(prisma),
  providers: [
    CredentialsProvider({
      name: "Email e Senha",
      credentials: {
        email: { label: "Email", type: "email", placeholder: "seu@email.com" },
        password: { label: "Senha", type: "password" },
      },
      async authorize(credentials) {
        const parsed = credentialsSchema.safeParse(credentials);
        if (!parsed.success) {
          throw new Error("Credenciais inválidas");
        }
        const { email, password } = parsed.data;
        const user = await prisma.user.findUnique({ where: { email } });

        if (!user || !user.password) {
          await logEvent({ eventType: "login_failed", details: { email } });
          throw new Error("Usuário ou senha inválidos");
        }
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
          await logEvent({ userId: user.id, eventType: "login_failed", details: { email } });
          throw new Error("Usuário ou senha inválidos");
        }
        return {
          id: user.id,
          email: user.email,
          name: `${user.firstName} ${user.lastName}`,
        };
      },
    }),
    ...(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET
      ? [GoogleProvider({
          clientId: process.env.GOOGLE_CLIENT_ID!,
          clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
          authorization: {
            params: { scope: "openid email profile" },
          },
        })]
      : []),
  ],
  session: {
    strategy: "jwt" as const,
  },
  pages: {
    signIn: "/login",
    error: "/login", // A página de erro agora é /login e o erro é passado por query param
  },
  callbacks: {
    async signIn({ user }: any) {
      await logEvent({ userId: user?.id, eventType: "login_success" });
      return true;
    },
    async jwt({ token, user, account }: any) {
      if (account && user) {
        token.id = user.id;
      }
      return token;
    },
    async session({ session, token }: any) {
      if (token && session.user) {
        session.user.id = token.id as string;
      }
      return session;
    },
  },
  events: {
    async signIn(message: { user: any }) {
      if (message.user) {
        await logEvent({ userId: message.user.id, eventType: "login_event_success" });
      }
    },
    async signOut(message: { token: any }) {
      if (message.token) {
        await logEvent({ userId: message.token.sub, eventType: "logout_event" });
      }
    },
  },
};

const handler = NextAuth(authOptions);

export { handler as GET, handler as POST }; 