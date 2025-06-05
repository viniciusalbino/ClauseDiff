"use client";

import { useState } from "react";
import { signIn } from "next-auth/react";
import { useRouter } from "next/navigation"; // Or "next/router" if using Pages Router
import Link from "next/link"; // Import Link for navigation
// import { ShimmerButton } from "@/components/ui/shimmer-button"; // Temporarily comment out ShimmerButton



// Placeholder for ClauseDiff Icon - replace with an actual SVG or icon component
const ClauseDiffIcon = () => (
  <svg className="w-6 h-6 mr-2 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
  </svg>
);

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [rememberMe, setRememberMe] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const router = useRouter();

  const handleCredentialsLogin = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);

    try {
      const result = await signIn("credentials", {
        redirect: false,
        email,
        password,
      });

      if (result?.error) {
        // Map common error messages or display as is
        if (result.error === "CredentialsSignin") {
          setError("Email ou senha inválidos.");
        } else {
          setError(result.error);
        }
        setIsLoading(false);
      } else if (result?.ok) {
        router.push("/success");
      } else {
        setError("Ocorreu um erro desconhecido. Tente novamente.");
        setIsLoading(false);
      }
    } catch (err) {
      setError("Falha ao entrar. Verifique suas credenciais.");
      setIsLoading(false);
    }
  };

  const handleGoogleLogin = async () => {
    setIsLoading(true);
    setError(null);
    try {
      await signIn("google");
      // On successful sign-in, NextAuth will handle redirection.
      // If it stays on this page, it means there might have been an issue
      // or the callback URL needs verification.
    } catch (err) {
      setError("Falha ao iniciar o login com Google.");
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-800 flex flex-col items-center justify-between p-4">
      <header className="w-full max-w-6xl mx-auto flex justify-between items-center py-4 px-2 sm:px-0">
        <Link href="/" className="flex items-center text-2xl font-semibold text-slate-700 hover:text-blue-600">
          <ClauseDiffIcon />
          ClauseDiff
        </Link>
        <Link href="/" className="text-sm text-slate-600 hover:text-blue-600 hover:underline">
          Voltar para Home
        </Link>
      </header>

      <main className="flex flex-col items-center justify-center w-full flex-grow">
        <div className="w-full max-w-md p-8 space-y-8 bg-white shadow-xl rounded-lg">
          <div>
            <h2 className="text-center text-3xl font-bold text-slate-900">
              Acesse sua conta
            </h2>
            <p className="mt-2 text-center text-sm text-slate-600">
              Compare documents com precisão e eficiência
            </p>
          </div>

          {error && (
            <div className="mb-4 p-3 bg-red-100 border border-red-300 text-red-700 rounded-md text-sm">
              <p>{error}</p>
            </div>
          )}

          <form className="space-y-6" onSubmit={handleCredentialsLogin}>
            <div>
              <label
                htmlFor="email"
                className="block text-sm font-medium text-slate-700"
              >
                Email
              </label>
              <div className="mt-1">
                <input
                  id="email"
                  name="email"
                  type="email"
                  autoComplete="email"
                  required
                  placeholder="seu@email.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="appearance-none block w-full px-3 py-2 border border-slate-300 rounded-md shadow-sm placeholder-slate-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm disabled:bg-slate-50 disabled:text-slate-500 disabled:border-slate-200"
                  disabled={isLoading}
                />
              </div>
            </div>

            <div>
              <label
                htmlFor="password"
                className="block text-sm font-medium text-slate-700"
              >
                Senha
              </label>
              <div className="mt-1">
                <input
                  id="password"
                  name="password"
                  type="password"
                  autoComplete="current-password"
                  required
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="appearance-none block w-full px-3 py-2 border border-slate-300 rounded-md shadow-sm placeholder-slate-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm disabled:bg-slate-50 disabled:text-slate-500 disabled:border-slate-200"
                  disabled={isLoading}
                />
              </div>
            </div>

            <div className="flex items-center justify-between">
              <div className="flex items-center">
                <input
                  id="remember-me"
                  name="remember-me"
                  type="checkbox"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-slate-300 rounded disabled:opacity-70"
                  disabled={isLoading}
                />
                <label
                  htmlFor="remember-me"
                  className="ml-2 block text-sm text-slate-900"
                >
                  Lembrar-me
                </label>
              </div>

              <div className="text-sm">
                <a
                  href="#" // Replace with actual password reset link
                  className="font-medium text-blue-600 hover:text-blue-500 hover:underline"
                >
                  Esqueceu sua senha?
                </a>
              </div>
            </div>

            <div>
              <button
                type="submit"
                disabled={isLoading}
                className="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isLoading ? "Entrando..." : "Entrar"}
              </button>
            </div>
          </form>

          <div className="mt-6">
            <div className="relative">
              <div className="absolute inset-0 flex items-center" aria-hidden="true">
                <div className="w-full border-t border-slate-300" />
              </div>
              <div className="relative flex justify-center text-sm">
                <span className="px-2 bg-white text-slate-500">ou</span>
              </div>
            </div>

            <div className="mt-6">
              <button
                onClick={handleGoogleLogin}
                disabled={isLoading}
                className="w-full flex justify-center items-center py-2.5 px-4 border border-slate-300 rounded-md shadow-sm text-sm font-medium text-slate-700 bg-white hover:bg-slate-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <svg className="w-5 h-5 mr-2" viewBox="0 0 24 24">
                  <path fill="#4285f4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                  <path fill="#34a853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                  <path fill="#fbbc05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                  <path fill="#ea4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                </svg>
                Continuar com Google
              </button>
            </div>
          </div>
           <div className="text-sm text-center mt-8">
            <span className="text-slate-600">Não tem uma conta? </span>
            <Link 
              href="/register" 
              className="font-medium text-blue-600 hover:text-blue-500 hover:underline"
            >
              Cadastre-se
            </Link>
          </div>
        </div>
      </main>

      <footer className="w-full max-w-6xl mx-auto text-center py-6 px-2 sm:px-0">
        <p className="text-xs text-slate-500">
          © {new Date().getFullYear()} ClauseDiff. Todos os direitos reservados.
        </p>
      </footer>
    </div>
  );
} 