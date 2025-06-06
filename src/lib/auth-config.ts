/**
 * NextAuth Configuration
 * 
 * Centralized auth configuration that can be imported by both
 * the NextAuth route handler and other API endpoints
 */

import type { AuthOptions, Profile as NextAuthProfile } from "next-auth";
import GoogleProvider from "next-auth/providers/google";
import CredentialsProvider from "next-auth/providers/credentials";
import { PrismaAdapter } from "@next-auth/prisma-adapter";
import { prisma } from "./prisma";
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

export const authOptions: AuthOptions = {
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
      return true;
    },
    async jwt({ token, user }) {
      // On sign in, add user data to token
      if (user) {
        token.id = user.id;
        token.role = user.role;
        token.firstName = user.firstName;
        token.lastName = user.lastName;
        token.city = user.city;
        token.state = user.state;
        token.cpf = user.cpf;
        token.emailVerified = user.emailVerified;
      }

      // Implement JWT refresh logic
      const now = Math.floor(Date.now() / 1000);
      const tokenIssuedAt = (token.iat as number) || now;
      const tokenAge = now - tokenIssuedAt;

      // Refresh token if it's older than the refresh threshold
      if (tokenAge > JWT_REFRESH_THRESHOLD && token.email) {
        try {
                     const user = await prisma.user.findUnique({
             where: { email: token.email },
             select: {
               id: true,
               email: true,
               name: true,
               firstName: true,
               lastName: true,
               city: true,
               state: true,
               cpf: true,
               role: true,
               emailVerified: true,
             },
           });

                     if (user) {
             token.id = user.id;
             token.role = user.role;
             token.firstName = user.firstName;
             token.lastName = user.lastName;
             token.city = user.city;
             token.state = user.state;
             token.cpf = user.cpf;
             token.emailVerified = user.emailVerified;
             // Update issued at time for fresh token
             token.iat = now;
           }
        } catch (error) {
          console.error("Error refreshing JWT token:", error);
        }
      }

      return token;
    },
    async session({ session, token }) {
      // Send properties to the client
      if (session.user) {
        session.user.id = token.id as string;
        session.user.role = token.role as string;
        session.user.firstName = token.firstName as string;
        session.user.lastName = token.lastName as string;
        session.user.city = token.city as string;
        session.user.state = token.state as string;
        session.user.cpf = token.cpf as string;
        session.user.emailVerified = token.emailVerified as Date;
      }
      return session;
    },
    async redirect({ url, baseUrl }) {
      // Allows relative callback URLs
      if (url.startsWith("/")) return `${baseUrl}${url}`;
      // Allows callback URLs on the same origin
      else if (new URL(url).origin === baseUrl) return url;
      // Default redirect to compare page after successful authentication
      return `${baseUrl}/compare`;
    },
  },
}; 