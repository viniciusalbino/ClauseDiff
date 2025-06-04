"use client";

import React, { useEffect, useState } from 'react';
import { useSession, signOut } from 'next-auth/react';

export default function SuccessPage() {
  const { data: session, status, update } = useSession();
  const [refreshCount, setRefreshCount] = useState(0);

  // Auto-refresh session every 30 seconds to test token rotation
  useEffect(() => {
    const interval = setInterval(async () => {
      if (session) {
        console.log("Auto-refreshing session to test JWT token rotation...");
        await update();
        setRefreshCount(prev => prev + 1);
      }
    }, 30000); // 30 seconds

    return () => clearInterval(interval);
  }, [session, update]);

  if (status === "loading") {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-2 text-gray-600">Carregando...</p>
        </div>
      </div>
    );
  }

  if (!session) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100">
        <div className="w-full max-w-md bg-white rounded-lg shadow-lg">
          <div className="text-center p-6">
            <h2 className="text-xl font-semibold text-red-600 mb-2">Sessão Expirada</h2>
            <p className="text-gray-600 mb-4">
              Sua sessão expirou. Por favor, faça login novamente.
            </p>
            <button 
              onClick={() => window.location.href = '/login'}
              className="w-full bg-blue-600 hover:bg-blue-700 text-white py-2 px-4 rounded-lg transition-colors"
            >
              Ir para Login
            </button>
          </div>
        </div>
      </div>
    );
  }

  const formatDate = (date: string | Date | null | undefined) => {
    if (!date) return 'N/A';
    return new Date(date).toLocaleString('pt-BR');
  };

  const formatTimeRemaining = (seconds: number) => {
    if (seconds <= 0) return 'Expirado';
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes}m ${remainingSeconds}s`;
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 py-8 px-4">
      <div className="max-w-4xl mx-auto space-y-6">
        {/* Header */}
        <div className="bg-white rounded-lg shadow-lg">
          <div className="text-center p-6">
            <div className="mx-auto mb-4 w-16 h-16 bg-green-100 rounded-full flex items-center justify-center">
              <svg className="w-8 h-8 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
            </div>
            <h1 className="text-2xl font-bold text-green-700 mb-2">Login Realizado com Sucesso!</h1>
            <p className="text-gray-600">
              Bem-vindo(a) ao ClauseDiff. Sua autenticação foi concluída com sucesso.
            </p>
          </div>
        </div>

        {/* User Information */}
        <div className="bg-white rounded-lg shadow-lg">
          <div className="p-6">
            <h2 className="flex items-center gap-2 text-lg font-semibold mb-4">
              <div className="w-2 h-2 bg-blue-600 rounded-full"></div>
              Informações do Usuário
            </h2>
            
            <div className="flex items-center space-x-4 mb-4">
              {session.user?.image && (
                <img
                  src={session.user.image}
                  alt="Profile"
                  className="w-16 h-16 rounded-full border-2 border-gray-200"
                />
              )}
              <div>
                <h3 className="text-lg font-semibold text-gray-900">
                  {session.user?.name || `${session.user?.firstName || ''} ${session.user?.lastName || ''}`.trim() || 'Usuário'}
                </h3>
                <p className="text-gray-600">{session.user?.email}</p>
                {session.user?.role && (
                  <span className="inline-block bg-gray-100 text-gray-800 text-sm px-2 py-1 rounded-md mt-1">
                    {session.user.role}
                  </span>
                )}
              </div>
            </div>
            
            <hr className="my-4 border-gray-200" />
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
              <div>
                <span className="font-medium text-gray-700">Nome Completo:</span>
                <p className="text-gray-600">{session.user?.name || 'N/A'}</p>
              </div>
              <div>
                <span className="font-medium text-gray-700">Email Verificado:</span>
                <p className="text-gray-600">{formatDate(session.user?.emailVerified)}</p>
              </div>
              <div>
                <span className="font-medium text-gray-700">Primeiro Nome:</span>
                <p className="text-gray-600">{session.user?.firstName || 'N/A'}</p>
              </div>
              <div>
                <span className="font-medium text-gray-700">Último Nome:</span>
                <p className="text-gray-600">{session.user?.lastName || 'N/A'}</p>
              </div>
            </div>
          </div>
        </div>

        {/* JWT Token Debug Information (Development Only) */}
        {process.env.NODE_ENV === 'development' && session.debug && (
          <div className="bg-orange-50 border border-orange-200 rounded-lg shadow-lg">
            <div className="p-6">
              <div className="flex items-center gap-2 mb-2">
                <div className="w-2 h-2 bg-orange-600 rounded-full"></div>
                <h2 className="text-lg font-semibold text-orange-800">Debug: JWT Token Information</h2>
                <span className="ml-auto text-xs bg-white border border-orange-300 text-orange-700 px-2 py-1 rounded">
                  Development Only
                </span>
              </div>
              <p className="text-orange-700 text-sm mb-4">
                Informações de debug sobre rotação de tokens JWT (visível apenas em desenvolvimento)
              </p>
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm mb-4">
                <div>
                  <span className="font-medium text-orange-700">Token Issued At:</span>
                  <p className="text-orange-800">
                    {session.debug.tokenIat ? new Date(session.debug.tokenIat * 1000).toLocaleTimeString('pt-BR') : 'N/A'}
                  </p>
                </div>
                <div>
                  <span className="font-medium text-orange-700">Token Expires At:</span>
                  <p className="text-orange-800">
                    {session.debug.tokenExp ? new Date(session.debug.tokenExp * 1000).toLocaleTimeString('pt-BR') : 'N/A'}
                  </p>
                </div>
                <div>
                  <span className="font-medium text-orange-700">Tempo Restante:</span>
                  <p className="text-orange-800 font-mono">
                    {session.debug.timeUntilExpiry !== undefined ? formatTimeRemaining(session.debug.timeUntilExpiry) : 'N/A'}
                  </p>
                </div>
              </div>
              
              <hr className="my-4 border-orange-200" />
              
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-orange-700">
                    Auto-refresh Count: <span className="font-mono font-bold">{refreshCount}</span>
                  </p>
                  <p className="text-xs text-orange-600 mt-1">
                    Sessão será atualizada automaticamente a cada 30 segundos para testar rotação de tokens.
                  </p>
                </div>
                <button
                  onClick={async () => {
                    console.log("Manual session refresh triggered");
                    await update();
                    setRefreshCount(prev => prev + 1);
                  }}
                  className="border border-orange-300 text-orange-700 hover:bg-orange-100 py-2 px-4 rounded-lg text-sm transition-colors"
                >
                  Atualizar Agora
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Action Buttons */}
        <div className="bg-white rounded-lg shadow-lg">
          <div className="p-6">
            <div className="flex flex-col sm:flex-row gap-3">
              <button 
                onClick={() => window.location.href = '/'}
                className="flex-1 bg-blue-600 hover:bg-blue-700 text-white py-3 px-4 rounded-lg transition-colors"
              >
                Ir para o App Principal
              </button>
              <button 
                onClick={() => window.location.href = '/profile'}
                className="flex-1 border border-gray-300 text-gray-700 hover:bg-gray-50 py-3 px-4 rounded-lg transition-colors"
              >
                Ver Perfil
              </button>
              <button 
                onClick={() => signOut({ callbackUrl: '/login' })}
                className="flex-1 bg-red-600 hover:bg-red-700 text-white py-3 px-4 rounded-lg transition-colors"
              >
                Sair
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
} 