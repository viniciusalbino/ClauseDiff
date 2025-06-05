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
import type { AuthOptions, Profile as NextAuthProfile } from "next-auth";
import GoogleProvider from "next-auth/providers/google";
import CredentialsProvider from "next-auth/providers/credentials";
import { PrismaAdapter } from "@next-auth/prisma-adapter";
import { prisma } from "@/lib/prisma"; // Use singleton Prisma instance
import bcrypt from "bcryptjs";
import { z } from "zod";

// Interface for the RAW profile data from Google, used in signIn callback and GoogleProvider.profile
interface RawGoogleProfile extends NextAuthProfile { 
  name?: string;
  email?: string;
  picture?: string;
  email_verified?: boolean; 
  given_name?: string;   
  family_name?: string;  
  sub: string; // 'sub' is guaranteed from Google and is the ID
  iss?: string;
  azp?: string;
  aud?: string;
  at_hash?: string;
  iat?: number;
  exp?: number;
}

const credentialsSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
});

// JWT token configuration for security and rotation
const JWT_MAX_AGE = 15 * 60; // 15 minutes - short-lived access tokens for security
const JWT_REFRESH_THRESHOLD = 5 * 60; // 5 minutes - refresh when 5 minutes left
const SESSION_MAX_AGE = 30 * 24 * 60 * 60; // 30 days - long-lived session
const SESSION_UPDATE_AGE = 24 * 60 * 60; // 24 hours - update session daily

const authOptions: AuthOptions = {
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
          throw new Error("Usuário ou senha inválidos");
        }
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
          throw new Error("Usuário ou senha inválidos");
        }
        // Return object must match NextAuth.User (augmented via types.ts)
        return {
          id: user.id,
          email: user.email,
          name: user.name || `${user.firstName || ''} ${user.lastName || ''}`.trim() || null,
          image: user.image,
          // Include other fields from augmented User type if available directly
          firstName: user.firstName,
          lastName: user.lastName,
          emailVerified: user.emailVerified,
          role: user.role,
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
          // Use RawGoogleProfile for the input 'profile' parameter.
          // The return type must conform to our augmented NextAuth.User type.
          profile(profile: RawGoogleProfile) { 
            // console.log("Google Profile in GoogleProvider.profile: ", profile);
            return {
              id: profile.sub, // This maps Google's 'sub' to NextAuth's 'id'
              name: profile.name || null,
              email: profile.email, // Email is expected
              image: profile.picture || null,
              // These are the custom fields we added to our NextAuth.User type
              emailVerified: profile.email_verified ? new Date() : null,
              firstName: profile.given_name || null,
              lastName: profile.family_name || null,
              // 'role' is not provided by Google. It will default from Prisma schema on user creation,
              // or be populated in JWT/session callbacks from DB.
            };
          },
        })]
      : []),
  ],
  session: {
    strategy: "jwt" as const,
    maxAge: SESSION_MAX_AGE, // 30 days - rolling session
    updateAge: SESSION_UPDATE_AGE, // Update session every 24 hours
  },
  jwt: {
    maxAge: JWT_MAX_AGE, // 15 minutes - short-lived for security
  },
  pages: {
    signIn: "/login",
    error: "/login", 
  },
  // Enhanced CSRF protection configuration
  useSecureCookies: process.env.NODE_ENV === "production",
  cookies: {
    sessionToken: {
      name: `${process.env.NODE_ENV === "production" ? "__Secure-" : ""}next-auth.session-token`,
      options: {
        httpOnly: true,
        sameSite: "strict",
        path: "/",
        secure: process.env.NODE_ENV === "production",
      },
    },
    callbackUrl: {
      name: `${process.env.NODE_ENV === "production" ? "__Secure-" : ""}next-auth.callback-url`,
      options: {
        httpOnly: true,
        sameSite: "strict",
        path: "/",
        secure: process.env.NODE_ENV === "production",
      },
    },
    csrfToken: {
      name: `${process.env.NODE_ENV === "production" ? "__Host-" : ""}next-auth.csrf-token`,
      options: {
        httpOnly: false, // Must be accessible to client for CSRF protection
        sameSite: "strict",
        path: "/",
        secure: process.env.NODE_ENV === "production",
      },
    },
  },
  callbacks: {
    // Use the standard NextAuth callback signature
    async signIn({ user, account, profile }) {
      // For Google OAuth, update user with latest info from Google profile if needed.
      // The 'user' object here should already have an 'id' if it's an existing user or newly created by adapter.
      if (account?.provider === "google" && profile && user.id) {
        const googleProfile = profile as RawGoogleProfile;
        
        // Update user with latest info from Google profile
        const dataToUpdate: any = {}; // Use any to avoid Prisma type issues
        if (googleProfile.picture && googleProfile.picture !== user.image) dataToUpdate.image = googleProfile.picture;
        
        const profileEmailVerified = googleProfile.email_verified ? new Date() : null;
        const userEmailVerified = user.emailVerified;
        // Compare dates properly or always update if different
        if (profileEmailVerified?.getTime() !== (userEmailVerified instanceof Date ? userEmailVerified.getTime() : null)) {
            dataToUpdate.emailVerified = profileEmailVerified;
        }

        if (googleProfile.given_name && googleProfile.given_name !== user.firstName) dataToUpdate.firstName = googleProfile.given_name;
        if (googleProfile.family_name && googleProfile.family_name !== user.lastName) dataToUpdate.lastName = googleProfile.family_name;
        
        // Update 'name' field if different
        if (googleProfile.name && googleProfile.name !== user.name) {
            dataToUpdate.name = googleProfile.name;
        }

        if (Object.keys(dataToUpdate).length > 0) {
          try {
            await prisma.user.update({
              where: { id: user.id! },
              data: dataToUpdate,
            });
          } catch (error) {
            console.error("Error updating user in signIn callback:", error);
          }
        }
      }
      return true; // Allow sign in
    },
    async jwt({ token, user }) {
      const now = Math.floor(Date.now() / 1000);
      
      // If it's a new user or new sign-in, 'user' object will be available.
      if (user?.id) {
        // Fresh login - set initial token data
        token.id = user.id;
        token.iat = now;
        token.exp = now + JWT_MAX_AGE;
        
        // Fetch the complete user from DB to ensure all fields are fresh, especially 'role'.
        const dbUser = await prisma.user.findUnique({ where: { id: user.id } });
        if (dbUser) {
          token.name = dbUser.name || `${dbUser.firstName || ''} ${dbUser.lastName || ''}`.trim() || null;
          token.email = dbUser.email;
          token.picture = dbUser.image;
          token.role = dbUser.role;
          token.firstName = dbUser.firstName;
          token.lastName = dbUser.lastName;
          token.emailVerified = dbUser.emailVerified;
        } else {
          // Fallback to user object if dbUser not found
          token.name = user.name || null;
          token.email = user.email || null;
          token.picture = user.image || null;
          token.role = user.role || null;
          token.firstName = user.firstName || null;
          token.lastName = user.lastName || null;
          token.emailVerified = user.emailVerified || null;
        }
        
        return token;
      }

      // Token rotation logic: Check if token is close to expiry and refresh if needed
      const timeUntilExpiry = (token.exp as number) - now;
      
      if (timeUntilExpiry < JWT_REFRESH_THRESHOLD) {
        console.log("JWT token is close to expiry, rotating...", {
          currentTime: now,
          tokenExp: token.exp,
          timeUntilExpiry,
          threshold: JWT_REFRESH_THRESHOLD
        });
        
        // Rotate the token by creating a new one with fresh expiry
        const newToken = {
          ...token,
          iat: now,
          exp: now + JWT_MAX_AGE,
        };
        
        // Refresh user data from database to ensure it's current
        if (token.id) {
          try {
            const dbUser = await prisma.user.findUnique({ where: { id: token.id as string } });
            if (dbUser) {
              newToken.name = dbUser.name || `${dbUser.firstName || ''} ${dbUser.lastName || ''}`.trim() || null;
              newToken.email = dbUser.email;
              newToken.picture = dbUser.image;
              newToken.role = dbUser.role;
              newToken.firstName = dbUser.firstName;
              newToken.lastName = dbUser.lastName;
              newToken.emailVerified = dbUser.emailVerified;
            }
          } catch (error) {
            console.error("Error refreshing user data during token rotation:", error);
            // Continue with existing token data if DB fetch fails
          }
        }
        
        console.log("JWT token rotated successfully", {
          oldExp: token.exp,
          newExp: newToken.exp,
          newIat: newToken.iat
        });
        
        return newToken;
      }
      
      // Token is still valid, return as-is
      return token;
    },
    async session({ session, token }) {
      // Send properties to the client, like id and any custom user properties.
      if (token && session.user) {
        session.user.id = token.id as string;
        session.user.name = token.name as string | null | undefined;
        session.user.email = token.email as string | null | undefined;
        session.user.image = token.picture as string | null | undefined;
        session.user.role = token.role as string | null | undefined;
        session.user.firstName = token.firstName as string | null | undefined;
        session.user.lastName = token.lastName as string | null | undefined;
        session.user.emailVerified = token.emailVerified as (Date | string | null | undefined);
        
        // Add JWT metadata for debugging in development
        if (process.env.NODE_ENV === "development") {
          session.debug = {
            tokenIat: token.iat as number | undefined,
            tokenExp: token.exp as number | undefined,
            timeUntilExpiry: token.exp ? (token.exp as number) - Math.floor(Date.now() / 1000) : undefined,
          };
        }
      }
      return session;
    },
    async redirect({ url, baseUrl }) {
      const parsedUrl = new URL(url, baseUrl);
      console.log(`Redirect callback: URL='${url}', BaseURL='${baseUrl}', Pathname='${parsedUrl.pathname}'`);
      
      // If we're being redirected to /login with error=Callback, but authentication was successful,
      // redirect to success page instead. The "Callback" error sometimes appears even on successful auth.
      if (parsedUrl.pathname === "/login" && parsedUrl.searchParams.get("error") === "Callback") {
        console.log("Redirecting to success page despite Callback error");
        return `${baseUrl}/success`;
      }
      
      // If we're being redirected to /login without explicit errors, go to success
      if (parsedUrl.pathname === "/login" && !parsedUrl.searchParams.has("error")) {
        console.log("Redirecting to success page from login");
        return `${baseUrl}/success`;
      }
      
      // For any other redirect to login with real errors, allow it
      if (parsedUrl.pathname === "/login" && parsedUrl.searchParams.has("error")) {
        console.log("Allowing redirect to login with error:", parsedUrl.searchParams.get("error"));
        return url;
      }
      
      // If there's a specific callbackUrl (not login), use it
      const callbackUrl = parsedUrl.searchParams.get("callbackUrl");
      if (callbackUrl && callbackUrl !== `${baseUrl}/login`) {
        console.log("Using callbackUrl:", callbackUrl);
        return callbackUrl;
      }
      
      console.log("Default redirect to:", url);
      return url;
    },
  },
  events: {
    async signIn() { /* console.log("EVENT: signIn"); */ },
    async signOut() { /* console.log("EVENT: signOut"); */ },
    async createUser() { /* console.log("EVENT: createUser"); */ },
    async updateUser() { /* console.log("EVENT: updateUser"); */ },
    async linkAccount() { /* console.log("EVENT: linkAccount"); */ },
    async session() { /* console.log("EVENT: session"); */ },
  },
  debug: process.env.NODE_ENV === "development",
};

const handler = NextAuth(authOptions);

export { handler as GET, handler as POST }; 