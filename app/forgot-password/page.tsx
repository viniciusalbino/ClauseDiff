'use client';

import { useState } from 'react';
import Link from 'next/link';
import { z } from 'zod';

// Validation schema
const forgotPasswordSchema = z.object({
  email: z.string().email('Email inválido').toLowerCase(),
});

type ForgotPasswordFormData = z.infer<typeof forgotPasswordSchema>;

// ClauseDiff Icon component (consistent with other pages)
const ClauseDiffIcon = () => (
  <svg className="w-6 h-6 mr-2 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
  </svg>
);

export default function ForgotPasswordPage() {
  const [formData, setFormData] = useState<ForgotPasswordFormData>({
    email: '',
  });
  const [errors, setErrors] = useState<Partial<ForgotPasswordFormData>>({});
  const [isLoading, setIsLoading] = useState(false);
  const [isSubmitted, setIsSubmitted] = useState(false);
  const [serverError, setServerError] = useState<string>('');

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    
    // Clear error when user starts typing
    if (errors[name as keyof typeof errors]) {
      setErrors(prev => ({ ...prev, [name]: '' }));
    }
    
    // Clear server error
    if (serverError) {
      setServerError('');
    }
  };

  const validateForm = (): boolean => {
    try {
      forgotPasswordSchema.parse(formData);
      setErrors({});
      return true;
    } catch (error) {
      if (error instanceof z.ZodError) {
        const fieldErrors: Partial<ForgotPasswordFormData> = {};
        error.errors.forEach((err) => {
          if (err.path[0]) {
            fieldErrors[err.path[0] as keyof ForgotPasswordFormData] = err.message;
          }
        });
        setErrors(fieldErrors);
      }
      return false;
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }

    setIsLoading(true);
    setServerError('');

    try {
      const response = await fetch('/api/auth/forgot-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(formData),
      });

      const data = await response.json();

      if (response.ok) {
        setIsSubmitted(true);
      } else {
        setServerError(data.details || data.error || 'Erro ao solicitar recuperação de senha');
      }
    } catch (error) {
      setServerError('Erro de conexão. Tente novamente.');
    } finally {
      setIsLoading(false);
    }
  };

  // Success state with consistent layout
  if (isSubmitted) {
    return (
      <div className="min-h-screen bg-slate-50 text-slate-800 flex flex-col items-center justify-between p-4">
        <header className="w-full max-w-6xl mx-auto flex justify-between items-center py-4 px-2 sm:px-0">
          <Link href="/" className="flex items-center text-2xl font-semibold text-slate-700 hover:text-blue-600">
            <ClauseDiffIcon />
            ClauseDiff
          </Link>
          <Link href="/login" className="text-sm text-slate-600 hover:text-blue-600 hover:underline">
            Voltar para Login
          </Link>
        </header>

        <main className="flex flex-col items-center justify-center w-full flex-grow">
          <div className="w-full max-w-md p-8 space-y-8 bg-white shadow-xl rounded-lg">
            <div className="text-center">
              <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-green-100 mb-4">
                <svg className="h-6 w-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <h2 className="text-3xl font-bold text-slate-900">
                Email Enviado!
              </h2>
              <p className="mt-2 text-sm text-slate-600">
                Se o email estiver cadastrado, você receberá um link de recuperação de senha em sua caixa de entrada.
              </p>
            </div>

            <div className="space-y-4">
              <Link
                href="/login"
                className="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                Voltar para Login
              </Link>
              <button
                onClick={() => {
                  setIsSubmitted(false);
                  setFormData({ email: '' });
                }}
                className="w-full flex justify-center py-2.5 px-4 border border-slate-300 rounded-md shadow-sm text-sm font-medium text-slate-700 bg-white hover:bg-slate-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                Enviar para outro email
              </button>
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

  // Main form with consistent layout
  return (
    <div className="min-h-screen bg-slate-50 text-slate-800 flex flex-col items-center justify-between p-4">
      <header className="w-full max-w-6xl mx-auto flex justify-between items-center py-4 px-2 sm:px-0">
        <Link href="/" className="flex items-center text-2xl font-semibold text-slate-700 hover:text-blue-600">
          <ClauseDiffIcon />
          ClauseDiff
        </Link>
        <Link href="/login" className="text-sm text-slate-600 hover:text-blue-600 hover:underline">
          Já tem conta? Faça login
        </Link>
      </header>

      <main className="flex flex-col items-center justify-center w-full flex-grow">
        <div className="w-full max-w-md p-8 space-y-8 bg-white shadow-xl rounded-lg">
          <div>
            <h2 className="text-center text-3xl font-bold text-slate-900">
              Recuperar Senha
            </h2>
            <p className="mt-2 text-center text-sm text-slate-600">
              Digite seu email para receber um link de recuperação de senha
            </p>
          </div>
          
          {serverError && (
            <div className="mb-4 p-3 bg-red-100 border border-red-300 text-red-700 rounded-md text-sm">
              <p>{serverError}</p>
            </div>
          )}
          
          <form className="space-y-6" onSubmit={handleSubmit}>
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
                  value={formData.email}
                  onChange={handleInputChange}
                  className={`appearance-none block w-full px-3 py-2 border rounded-md shadow-sm placeholder-slate-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm disabled:bg-slate-50 disabled:text-slate-500 disabled:border-slate-200 ${
                    errors.email ? 'border-red-300' : 'border-slate-300'
                  }`}
                  disabled={isLoading}
                />
                {errors.email && (
                  <p className="mt-1 text-sm text-red-600">{errors.email}</p>
                )}
              </div>
            </div>

            <div>
              <button
                type="submit"
                disabled={isLoading}
                className="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isLoading ? "Enviando..." : "Enviar Link de Recuperação"}
              </button>
            </div>
          </form>

          <div className="text-sm text-center">
            <Link
              href="/login"
              className="font-medium text-blue-600 hover:text-blue-500 hover:underline"
            >
              Voltar para Login
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