"use client";

import React, { useState, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { signIn } from "next-auth/react";
import Link from 'next/link';
import { motion } from 'framer-motion';

// Este é o componente principal da página de login agora.
function LoginPageContent() { 
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  // const [error, setError] = useState<string | null>(null); // Pode ser usado para exibir erros de login
  // const params = useSearchParams(); // Para ler ?error=... da URL se necessário
  // const callbackError = params.get("error");

  const handleGoogleLogin = async () => {
    setIsLoading(true);
    // setError(null);
    try {
      await signIn("google", { callbackUrl: "/dashboard" });
    } catch (err) {
      // setError("Erro ao iniciar login com Google.");
      console.error("Erro ao iniciar login com Google:", err);
      setIsLoading(false);
    }
    // Não é necessário setIsLoading(false) aqui se o redirecionamento ocorrer sempre
  };

  const handleEmailLogin = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setIsLoading(true);
    // setError(null);
    // TODO: Implementar lógica de login com email/senha usando signIn()
    // Exemplo: await signIn('credentials', { email, password, callbackUrl: '/dashboard' });
    console.log('Login com email/senha não implementado ainda.', { email, password });
    // try {
    //   const result = await signIn('credentials', {
    //     redirect: false, // Para manusear o erro aqui
    //     email,
    //     password,
    //   });
    //   if (result?.error) {
    //     setError(result.error);
    //     setIsLoading(false);
    //   } else if (result?.url) {
    //     // Redirecionar ou atualizar UI, o callbackUrl cuidará disso se redirect não for false
    //     window.location.href = "/dashboard";
    //   }
    // } catch (err) {
    //   setError("Ocorreu um erro inesperado.");
    //   setIsLoading(false);
    // }
    setIsLoading(false); // Remover se a lógica acima for implementada com redirect
  };

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col font-sans">
      {/* Header Simplificado */}
      <header className="w-full bg-white py-4 px-6 shadow-sm sticky top-0 z-50">
        <div className="container mx-auto flex justify-between items-center max-w-screen-xl">
          <Link href="/" className="flex items-center space-x-2">
            {/* <img src="/logo.svg" alt="ClauseDiff Logo" className="h-8 w-auto" /> */}
            <span className="font-bold text-xl text-primary-600">ClauseDiff</span>
          </Link>
          <Link href="/" className="text-sm text-gray-700 hover:text-primary-600 transition-colors">
            Voltar para Home
          </Link>
        </div>
      </header>
      
      {/* Conteúdo Principal */}
      <main className="flex-grow flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, ease: "easeOut" }}
          className="bg-white p-8 sm:p-10 rounded-xl shadow-2xl max-w-md w-full space-y-8 border border-gray-200"
        >
          <div className="text-center">
            <h1 className="text-3xl sm:text-4xl font-bold text-gray-900 mb-2">Acesse sua conta</h1>
            <p className="text-md text-gray-600">Compare documentos com precisão e eficiência.</p>
          </div>
          
          {/* {error && <p className="text-red-500 text-sm text-center">{error}</p>} */}
          {/* {callbackError && <p className="text-red-500 text-sm text-center">Erro: {callbackError}</p>} */}

          {/* Formulário de Login com Email */}
          <form onSubmit={handleEmailLogin} className="space-y-6">
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-1.5">
                Email
              </label>
              <input
                id="email"
                type="email"
                autoComplete="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-4 py-2.5 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 transition-shadow placeholder-gray-400"
                placeholder="seu@email.com"
              />
            </div>
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-1.5">
                Senha
              </label>
              <input
                id="password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-4 py-2.5 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 transition-shadow placeholder-gray-400"
                placeholder="••••••••"
              />
            </div>
            <div className="flex items-center justify-between text-sm">
              <div className="flex items-center">
                <input
                  id="remember-me"
                  name="remember-me"
                  type="checkbox"
                  className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
                />
                <label htmlFor="remember-me" className="ml-2 block text-gray-700">
                  Lembrar-me
                </label>
              </div>
              <Link href="#" className="font-medium text-primary-600 hover:text-primary-500 hover:underline">
                Esqueceu sua senha?
              </Link>
            </div>
            <button
              type="submit"
              disabled={isLoading || (!email && !password)}
              className="w-full bg-primary-600 hover:bg-primary-700 text-white font-semibold py-2.5 px-4 rounded-lg shadow-md hover:shadow-lg focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 transition-all duration-150 ease-in-out disabled:opacity-60 disabled:cursor-not-allowed"
            >
              {isLoading && !email && !password ? 'Entrando...' : (isLoading ? 'Verificando...' : 'Entrar')}
            </button>
          </form>
          
          <div className="relative my-6">
            <div className="absolute inset-0 flex items-center" aria-hidden="true">
              <div className="w-full border-t border-gray-300"></div>
            </div>
            <div className="relative flex justify-center text-sm">
              <span className="px-3 bg-white text-gray-500 font-medium">ou</span>
            </div>
          </div>
          
          <button
            onClick={handleGoogleLogin}
            disabled={isLoading}
            className="w-full flex items-center justify-center bg-white border border-gray-300 rounded-lg px-4 py-2.5 text-gray-700 font-medium hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition-colors shadow-sm hover:shadow-md disabled:opacity-60 disabled:cursor-not-allowed"
          >
            <svg className="h-5 w-5 mr-3" viewBox="0 0 24 24" fill="currentColor">
              <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"></path>
              <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"></path>
              <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"></path>
              <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"></path>
              <path d="M1 1h22v22H1z" fill="none"></path>
            </svg>
            Entrar com Google
          </button>
          
          <p className="mt-8 text-center text-sm text-gray-600">
            Não tem uma conta?{' '}
            <Link href="/signup" className="font-medium text-primary-600 hover:text-primary-500 hover:underline">
              Cadastre-se
            </Link>
          </p>
        </motion.div>
      </main>
      
      <footer className="bg-white py-6 border-t mt-auto">
        <div className="container mx-auto px-6 text-center text-gray-600 text-sm max-w-screen-xl">
          &copy; {new Date().getFullYear()} ClauseDiff. Todos os direitos reservados.
        </div>
      </footer>
    </div>
  );
}

// O componente exportado por padrão agora envolve LoginPageContent com Suspense.
export default function LoginPage() {
  return (
    <Suspense fallback={<div className="min-h-screen flex items-center justify-center text-lg font-semibold text-gray-700">Carregando página de login...</div>}>
      <LoginPageContent />
    </Suspense>
  );
} 