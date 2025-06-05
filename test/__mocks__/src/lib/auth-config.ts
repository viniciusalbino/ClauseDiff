// Mock for auth-config.ts

export const authOptions = {
  adapter: null,
  providers: [],
  session: {
    strategy: "jwt" as const,
    maxAge: 30 * 24 * 60 * 60,
    updateAge: 24 * 60 * 60,
  },
  jwt: {
    maxAge: 15 * 60,
  },
  pages: {
    signIn: "/login",
    error: "/login",
  },
  callbacks: {
    async signIn() { return true; },
    async jwt({ token, user }: any) { return token; },
    async session({ session, token }: any) { return session; },
    async redirect({ url, baseUrl }: any) { return baseUrl; },
  },
};

export default { authOptions }; 