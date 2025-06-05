"use client";

/**
 * Admin Dashboard Page
 * 
 * This page demonstrates role-based access control and permission-based UI components.
 * Only users with ADMIN role can access this page.
 */

import { useAuth } from "../../src/hooks/useAuth";
import { usePermissions, RequireRole, RequirePermission, ROLES, PERMISSIONS } from "../../src/hooks/usePermissions";
import { useRequireAuth } from "../../src/hooks/useRequireAuth";
import { useState, useEffect } from "react";

interface User {
  id: string;
  email: string;
  firstName?: string;
  lastName?: string;
  role: string;
  createdAt: string;
  emailVerified?: string;
  _count: {
    auditLogs: number;
  };
}

interface AuditLog {
  id: string;
  eventType: string;
  timestamp: string;
  ip?: string;
  details?: any;
  user?: {
    email: string;
    firstName?: string;
    lastName?: string;
  };
}

export default function AdminDashboard() {
  // Require authentication and admin role
  useRequireAuth();
  
  const { user, isLoading } = useAuth();
  const { isAdmin, hasPermission } = usePermissions();
  
  const [users, setUsers] = useState<User[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [isLoadingData, setIsLoadingData] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Fetch admin data
  useEffect(() => {
    if (!isAdmin) return;

    const fetchAdminData = async () => {
      try {
        setIsLoadingData(true);
        
        // Fetch users
        const usersResponse = await fetch('/api/admin/users?limit=5');
        if (usersResponse.ok) {
          const usersData = await usersResponse.json();
          setUsers(usersData.users || []);
        }

        // Fetch recent audit logs
        const auditResponse = await fetch('/api/admin/audit?limit=10');
        if (auditResponse.ok) {
          const auditData = await auditResponse.json();
          setAuditLogs(auditData.auditLogs || []);
        }
      } catch (err) {
        console.error('Error fetching admin data:', err);
        setError('Failed to load admin data');
      } finally {
        setIsLoadingData(false);
      }
    };

    fetchAdminData();
  }, [isAdmin]);

  // Loading state
  if (isLoading || isLoadingData) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-4 text-slate-600">Carregando painel administrativo...</p>
        </div>
      </div>
    );
  }

  return (
    <RequireRole role={ROLES.ADMIN} fallback={
      <div className="min-h-screen bg-slate-50 flex items-center justify-center">
        <div className="max-w-md w-full bg-white rounded-lg shadow-xl p-8 text-center">
          <div className="text-red-500 text-6xl mb-4">🚫</div>
          <h1 className="text-2xl font-bold text-slate-900 mb-2">Acesso Negado</h1>
          <p className="text-slate-600 mb-6">
            Você não tem permissão para acessar o painel administrativo.
          </p>
          <a 
            href="/profile" 
            className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors"
          >
            Voltar ao Perfil
          </a>
        </div>
      </div>
    }>
      <div className="min-h-screen bg-slate-50">
        {/* Header */}
        <header className="bg-white shadow-sm border-b">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between items-center py-6">
              <div>
                <h1 className="text-2xl font-bold text-slate-900">Painel Administrativo</h1>
                <p className="text-slate-600">Bem-vindo, {user?.firstName || user?.name || user?.email}</p>
              </div>
              <div className="flex items-center space-x-4">
                <span className="px-3 py-1 bg-purple-100 text-purple-800 rounded-full text-sm font-medium">
                  {user?.role}
                </span>
                <a 
                  href="/profile" 
                  className="text-slate-600 hover:text-slate-900 transition-colors"
                >
                  Voltar ao Perfil
                </a>
              </div>
            </div>
          </div>
        </header>

        {/* Main Content */}
        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {error && (
            <div className="mb-6 bg-red-50 border border-red-200 rounded-lg p-4">
              <p className="text-red-800">{error}</p>
            </div>
          )}

          {/* Stats Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div className="bg-white rounded-lg shadow p-6">
              <h3 className="text-lg font-semibold text-slate-900 mb-2">Total de Usuários</h3>
              <p className="text-3xl font-bold text-blue-600">{users.length}</p>
              <p className="text-sm text-slate-600 mt-1">Usuários cadastrados</p>
            </div>
            
            <RequirePermission permission={PERMISSIONS.AUDIT_LOG_READ}>
              <div className="bg-white rounded-lg shadow p-6">
                <h3 className="text-lg font-semibold text-slate-900 mb-2">Eventos de Auditoria</h3>
                <p className="text-3xl font-bold text-green-600">{auditLogs.length}</p>
                <p className="text-sm text-slate-600 mt-1">Eventos recentes</p>
              </div>
            </RequirePermission>

            <div className="bg-white rounded-lg shadow p-6">
              <h3 className="text-lg font-semibold text-slate-900 mb-2">Suas Permissões</h3>
              <div className="space-y-1">
                <div className="flex items-center">
                  <span className={`w-2 h-2 rounded-full mr-2 ${hasPermission(PERMISSIONS.USER_READ) ? 'bg-green-500' : 'bg-red-500'}`}></span>
                  <span className="text-sm text-slate-600">Gerenciar Usuários</span>
                </div>
                <div className="flex items-center">
                  <span className={`w-2 h-2 rounded-full mr-2 ${hasPermission(PERMISSIONS.AUDIT_LOG_READ) ? 'bg-green-500' : 'bg-red-500'}`}></span>
                  <span className="text-sm text-slate-600">Visualizar Auditoria</span>
                </div>
                <div className="flex items-center">
                  <span className={`w-2 h-2 rounded-full mr-2 ${hasPermission(PERMISSIONS.SYSTEM_CONFIG) ? 'bg-green-500' : 'bg-red-500'}`}></span>
                  <span className="text-sm text-slate-600">Configuração do Sistema</span>
                </div>
              </div>
            </div>
          </div>

          {/* Recent Users */}
          <RequirePermission permission={PERMISSIONS.USER_READ}>
            <div className="bg-white rounded-lg shadow mb-8">
              <div className="px-6 py-4 border-b border-slate-200">
                <h2 className="text-xl font-semibold text-slate-900">Usuários Recentes</h2>
              </div>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-slate-200">
                  <thead className="bg-slate-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                        Usuário
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                        Role
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                        Criado em
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                        Status
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-slate-200">
                    {users.map((user) => (
                      <tr key={user.id}>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div>
                            <div className="text-sm font-medium text-slate-900">
                              {user.firstName && user.lastName ? 
                                `${user.firstName} ${user.lastName}` : 
                                'Nome não informado'
                              }
                            </div>
                            <div className="text-sm text-slate-500">{user.email}</div>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                            user.role === 'ADMIN' ? 'bg-purple-100 text-purple-800' : 'bg-blue-100 text-blue-800'
                          }`}>
                            {user.role}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-500">
                          {new Date(user.createdAt).toLocaleDateString('pt-BR')}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                            user.emailVerified ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'
                          }`}>
                            {user.emailVerified ? 'Verificado' : 'Pendente'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </RequirePermission>

          {/* Recent Audit Logs */}
          <RequirePermission permission={PERMISSIONS.AUDIT_LOG_READ}>
            <div className="bg-white rounded-lg shadow">
              <div className="px-6 py-4 border-b border-slate-200">
                <h2 className="text-xl font-semibold text-slate-900">Eventos de Auditoria Recentes</h2>
              </div>
              <div className="divide-y divide-slate-200">
                {auditLogs.slice(0, 5).map((log) => (
                  <div key={log.id} className="px-6 py-4">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center">
                          <span className="text-sm font-medium text-slate-900">
                            {log.eventType.replace(/_/g, ' ')}
                          </span>
                          <span className="ml-2 px-2 py-1 bg-slate-100 text-slate-600 rounded text-xs">
                            {new Date(log.timestamp).toLocaleString('pt-BR')}
                          </span>
                        </div>
                        {log.user && (
                          <p className="text-sm text-slate-600 mt-1">
                            Usuário: {log.user.firstName && log.user.lastName ? 
                              `${log.user.firstName} ${log.user.lastName}` : 
                              log.user.email
                            }
                          </p>
                        )}
                        {log.ip && (
                          <p className="text-sm text-slate-500 mt-1">IP: {log.ip}</p>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </RequirePermission>
        </main>
      </div>
    </RequireRole>
  );
} 