/**
 * 403 Forbidden Page
 * 
 * This page is shown when users try to access resources they don't have
 * permission to access.
 */

import Link from "next/link";

export default function ForbiddenPage() {
  return (
    <div className="min-h-screen bg-slate-50 flex items-center justify-center px-4">
      <div className="max-w-md w-full">
        {/* ClauseDiff Logo */}
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-slate-900">ClauseDiff</h1>
          <div className="h-1 w-20 bg-blue-600 mx-auto mt-2"></div>
        </div>

        {/* Forbidden Message */}
        <div className="bg-white rounded-lg shadow-xl p-8 text-center">
          <div className="text-red-500 text-6xl mb-4">🚫</div>
          
          <h2 className="text-2xl font-bold text-slate-900 mb-2">
            Acesso Negado
          </h2>
          
          <p className="text-slate-600 mb-6">
            Você não tem permissão para acessar esta página. Entre em contato com um administrador se você acredita que isso é um erro.
          </p>

          {/* Error Details */}
          <div className="bg-slate-50 rounded-lg p-4 mb-6">
            <p className="text-sm text-slate-700 font-medium">Código do Erro:</p>
            <p className="text-sm text-slate-500">403 - Forbidden</p>
          </div>

          {/* Action Buttons */}
          <div className="space-y-3">
            <Link
              href="/profile"
              className="w-full bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-700 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition-colors inline-block"
            >
              Voltar ao Perfil
            </Link>
            
            <Link
              href="/"
              className="w-full bg-slate-100 text-slate-700 py-2 px-4 rounded-lg hover:bg-slate-200 focus:ring-2 focus:ring-slate-500 focus:ring-offset-2 transition-colors inline-block"
            >
              Ir para Início
            </Link>
          </div>

          {/* Support */}
          <div className="mt-6 pt-6 border-t border-slate-200">
            <p className="text-sm text-slate-500">
              Precisa de ajuda?{" "}
              <a 
                href="mailto:suporte@clausediff.com" 
                className="text-blue-600 hover:text-blue-700 font-medium"
              >
                Entre em contato conosco
              </a>
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="mt-8 text-center">
          <p className="text-sm text-slate-500">
            © 2024 ClauseDiff. Todos os direitos reservados.
          </p>
        </div>
      </div>
    </div>
  );
} 