import { useSession, signIn, signOut } from "next-auth/react";
import { useRouter } from "next/navigation";
import { useCallback } from "react";

export interface AuthUser {
  id: string;
  name?: string | null;
  email?: string | null;
  image?: string | null;
  firstName?: string | null;
  lastName?: string | null;
  emailVerified?: string | Date | null;
  role?: string | null;
}

export interface AuthState {
  user: AuthUser | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  isError: boolean;
}

export interface AuthActions {
  login: (email: string, password: string) => Promise<{ success: boolean; error?: string }>;
  loginWithGoogle: () => Promise<void>;
  logout: () => Promise<void>;
  refreshSession: () => Promise<void>;
}

export interface UseAuthReturn extends AuthState, AuthActions {}

export function useAuth(): UseAuthReturn {
  const { data: session, status, update } = useSession();
  const router = useRouter();

  const login = useCallback(async (email: string, password: string) => {
    try {
      const result = await signIn("credentials", {
        redirect: false,
        email,
        password,
      });

      if (result?.error) {
        let errorMessage = "Erro ao fazer login";
        
        switch (result.error) {
          case "CredentialsSignin":
            errorMessage = "Email ou senha inválidos";
            break;
          case "Callback":
            errorMessage = "Erro de autenticação";
            break;
          default:
            errorMessage = result.error;
        }

        return {
          success: false,
          error: errorMessage,
        };
      }

      if (result?.ok) {
        return { success: true };
      }

      return {
        success: false,
        error: "Erro desconhecido ao fazer login",
      };
    } catch (error) {
      return {
        success: false,
        error: "Falha na conexão. Tente novamente.",
      };
    }
  }, []);

  const loginWithGoogle = useCallback(async () => {
    try {
      await signIn("google", { redirect: false });
    } catch (error) {
      console.error("Google login error:", error);
      throw new Error("Falha ao iniciar login com Google");
    }
  }, []);

  const logout = useCallback(async () => {
    try {
      await signOut({ 
        redirect: false,
        callbackUrl: "/login" 
      });
      router.push("/login");
    } catch (error) {
      console.error("Logout error:", error);
      // Force redirect even if signOut fails
      router.push("/login");
    }
  }, [router]);

  const refreshSession = useCallback(async () => {
    try {
      await update();
    } catch (error) {
      console.error("Session refresh error:", error);
    }
  }, [update]);

  const authState: AuthState = {
    user: session?.user ? {
      id: session.user.id,
      name: session.user.name,
      email: session.user.email,
      image: session.user.image,
      firstName: session.user.firstName,
      lastName: session.user.lastName,
      emailVerified: session.user.emailVerified,
      role: session.user.role,
    } : null,
    isLoading: status === "loading",
    isAuthenticated: !!session?.user,
    isError: status === "unauthenticated" && !session,
  };

  return {
    ...authState,
    login,
    loginWithGoogle,
    logout,
    refreshSession,
  };
} 