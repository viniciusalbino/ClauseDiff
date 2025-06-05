'use client';

import { useState, useEffect } from 'react';
import { useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { z } from 'zod';

// Validation schema
const resetPasswordSchema = z.object({
  password: z.string()
    .min(8, 'Senha deve ter pelo menos 8 caracteres')
    .regex(/[A-Z]/, 'Senha deve conter ao menos uma letra maiúscula')
    .regex(/[a-z]/, 'Senha deve conter ao menos uma letra minúscula')
    .regex(/[0-9]/, 'Senha deve conter ao menos um número')
    .regex(/[^A-Za-z0-9]/, 'Senha deve conter ao menos um caractere especial'),
  confirmPassword: z.string()
}).refine((data) => data.password === data.confirmPassword, {
  message: "As senhas não coincidem",
  path: ["confirmPassword"],
});

type ResetPasswordFormData = z.infer<typeof resetPasswordSchema>;

// ClauseDiff Icon component (consistent with other pages)
const ClauseDiffIcon = () => (
  <svg className="w-6 h-6 mr-2 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
  </svg>
);

export default function ResetPasswordPage() {
  const [formData, setFormData] = useState<ResetPasswordFormData>({
    password: '',
    confirmPassword: '',
  });
  const [errors, setErrors] = useState<Partial<ResetPasswordFormData>>({});
  const [isLoading, setIsLoading] = useState(false);
  const [isValidating, setIsValidating] = useState(true);
  const [tokenValid, setTokenValid] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const [serverError, setServerError] = useState<string>('');
  const [userEmail, setUserEmail] = useState<string>('');
  
  const searchParams = useSearchParams();
  const token = searchParams.get('token');

  useEffect(() => {
    const validateToken = async () => {
      if (!token) {
        setServerError('Token de recuperação não encontrado na URL');
        setIsValidating(false);
        return;
      }

      try {
        const response = await fetch(`/api/auth/reset-password?token=${encodeURIComponent(token)}`);
        const data = await response.json();

        if (response.ok && data.valid) {
          setTokenValid(true);
          setUserEmail(data.email);
        } else {
          setServerError(data.error || 'Token inválido ou expirado');
        }
      } catch (error) {
        setServerError('Erro ao validar o token de recuperação');
      } finally {
        setIsValidating(false);
      }
    };

    validateToken();
  }, [token]);

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
      resetPasswordSchema.parse(formData);
      setErrors({});
      return true;
    } catch (error) {
      if (error instanceof z.ZodError) {
        const fieldErrors: Partial<ResetPasswordFormData> = {};
        error.errors.forEach((err) => {
          if (err.path[0]) {
            fieldErrors[err.path[0] as keyof ResetPasswordFormData] = err.message;
          }
        });
        setErrors(fieldErrors);
      }
      return false;
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateForm() || !token) {
      return;
    }

    setIsLoading(true);
    setServerError('');

    try {
      const response = await fetch('/api/auth/reset-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          token,
          password: formData.password,
          confirmPassword: formData.confirmPassword,
        }),
      });

      const data = await response.json();

      if (response.ok) {
        setIsSuccess(true);
      } else {
        setServerError(data.details || data.error || 'Erro ao redefinir senha');
      }
    } catch (error) {
      setServerError('Erro de conexão. Tente novamente.');
    } finally {
      setIsLoading(false);
    }
  };

  // Loading state while validating token
  if (isValidating) {
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
          <div className="w-full max-w-md p-8 space-y-8 bg-white shadow-xl rounded-lg text-center">
            <div>
              <svg className="animate-spin mx-auto h-12 w-12 text-blue-600" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
              </svg>
              <h2 className="mt-4 text-xl font-semibold text-slate-900">
                Validando link de recuperação...
              </h2>
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

  // Success state
  if (isSuccess) {
    return (
      <div className="min-h-screen bg-slate-50 text-slate-800 flex flex-col items-center justify-between p-4">
        <header className="w-full max-w-6xl mx-auto flex justify-between items-center py-4 px-2 sm:px-0">
          <Link href="/" className="flex items-center text-2xl font-semibold text-slate-700 hover:text-blue-600">
            <ClauseDiffIcon />
            ClauseDiff
          </Link>
          <Link href="/login" className="text-sm text-slate-600 hover:text-blue-600 hover:underline">
            Fazer Login
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
                Senha Redefinida!
              </h2>
              <p className="mt-2 text-sm text-slate-600">
                Sua senha foi redefinida com sucesso. Você já pode fazer login com sua nova senha.
              </p>
            </div>

            <div>
              <Link
                href="/login"
                className="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                Fazer Login
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

  // Error state (invalid token)
  if (!tokenValid) {
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
              <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-red-100 mb-4">
                <svg className="h-6 w-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </div>
              <h2 className="text-3xl font-bold text-slate-900">
                Link Inválido
              </h2>
              <p className="mt-2 text-sm text-slate-600">
                {serverError || 'Este link de recuperação é inválido ou expirou. Solicite um novo link.'}
              </p>
            </div>

            <div className="space-y-4">
              <Link
                href="/forgot-password"
                className="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                Solicitar Novo Link
              </Link>
              <Link
                href="/login"
                className="w-full flex justify-center py-2.5 px-4 border border-slate-300 rounded-md shadow-sm text-sm font-medium text-slate-700 bg-white hover:bg-slate-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
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

  // Main form
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
          <div>
            <h2 className="text-center text-3xl font-bold text-slate-900">
              Redefinir Senha
            </h2>
            <p className="mt-2 text-center text-sm text-slate-600">
              {userEmail && `Criar nova senha para ${userEmail}`}
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
                htmlFor="password"
                className="block text-sm font-medium text-slate-700"
              >
                Nova Senha
              </label>
              <div className="mt-1">
                <input
                  id="password"
                  name="password"
                  type="password"
                  autoComplete="new-password"
                  required
                  placeholder="••••••••"
                  value={formData.password}
                  onChange={handleInputChange}
                  className={`appearance-none block w-full px-3 py-2 border rounded-md shadow-sm placeholder-slate-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm disabled:bg-slate-50 disabled:text-slate-500 disabled:border-slate-200 ${
                    errors.password ? 'border-red-300' : 'border-slate-300'
                  }`}
                  disabled={isLoading}
                />
                {errors.password && (
                  <p className="mt-1 text-sm text-red-600">{errors.password}</p>
                )}
              </div>
            </div>

            <div>
              <label
                htmlFor="confirmPassword"
                className="block text-sm font-medium text-slate-700"
              >
                Confirmar Nova Senha
              </label>
              <div className="mt-1">
                <input
                  id="confirmPassword"
                  name="confirmPassword"
                  type="password"
                  autoComplete="new-password"
                  required
                  placeholder="••••••••"
                  value={formData.confirmPassword}
                  onChange={handleInputChange}
                  className={`appearance-none block w-full px-3 py-2 border rounded-md shadow-sm placeholder-slate-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm disabled:bg-slate-50 disabled:text-slate-500 disabled:border-slate-200 ${
                    errors.confirmPassword ? 'border-red-300' : 'border-slate-300'
                  }`}
                  disabled={isLoading}
                />
                {errors.confirmPassword && (
                  <p className="mt-1 text-sm text-red-600">{errors.confirmPassword}</p>
                )}
              </div>
            </div>

            <div>
              <button
                type="submit"
                disabled={isLoading}
                className="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isLoading ? "Redefinindo..." : "Redefinir Senha"}
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