"use client";

import { useSession, signOut } from "next-auth/react";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { OptimizedFileUpload } from "../../src/presentation/components/FileUpload/OptimizedFileUpload";
import { useSimpleCache } from "../../src/utils/SimpleCache";
import { usePerformanceMonitor } from "../../src/utils/PerformanceMonitor";

export default function DashboardPage() {
  const { data: session, status } = useSession();
  const router = useRouter();
  const [showMetrics, setShowMetrics] = useState(false);
  const [showCache, setShowCache] = useState(false);
  
  const { getCacheStats, clearCache } = useSimpleCache();
  const { getSummary } = usePerformanceMonitor();

  // Redirect if not authenticated
  if (status === "loading") {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (!session) {
    router.push("/login");
    return null;
  }

  const handleSignOut = () => {
    signOut({ callbackUrl: "/login" });
  };

  const handleUploadComplete = (files: any[]) => {
    console.log("Upload complete:", files);
    // Aqui você pode integrar com seu sistema de processamento
  };

  const cacheStats = getCacheStats();
  const performanceStats = getSummary();

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center">
              <h1 className="text-xl font-semibold text-gray-900">
                ClauseDiff - Sistema de Upload
              </h1>
            </div>
            
            <div className="flex items-center space-x-4">
              <span className="text-sm text-gray-600">
                Olá, {session.user?.name || session.user?.email}
              </span>
              
              <button
                onClick={() => setShowMetrics(!showMetrics)}
                className="px-3 py-1 text-xs bg-blue-100 text-blue-700 rounded-full hover:bg-blue-200"
              >
                📊 Métricas
              </button>
              
              <button
                onClick={() => setShowCache(!showCache)}
                className="px-3 py-1 text-xs bg-green-100 text-green-700 rounded-full hover:bg-green-200"
              >
                🗄️ Cache
              </button>
              
              <button
                onClick={handleSignOut}
                className="px-4 py-2 text-sm bg-red-600 text-white rounded-md hover:bg-red-700"
              >
                Sair
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          
          {/* Upload Area - Main Section */}
          <div className="lg:col-span-2">
            <div className="bg-white rounded-lg shadow-sm p-6">
              <h2 className="text-lg font-medium text-gray-900 mb-6">
                📎 Sistema de Upload Otimizado
              </h2>
              
              <OptimizedFileUpload
                maxFiles={5}
                maxSize={50 * 1024 * 1024} // 50MB
                allowedTypes={[
                  'application/pdf',
                  'text/plain',
                  'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
                ]}
                onUploadComplete={handleUploadComplete}
                className="space-y-4"
              />
            </div>
          </div>

          {/* Sidebar - Stats and Info */}
          <div className="space-y-6">
            
            {/* System Status */}
            <div className="bg-white rounded-lg shadow-sm p-6">
              <h3 className="text-sm font-medium text-gray-900 mb-4">
                🚀 Status do Sistema
              </h3>
              <div className="space-y-3 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-600">Web Workers:</span>
                  <span className="text-green-600">✅ Ativo</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Storage:</span>
                  <span className="text-green-600">✅ Local</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Cache:</span>
                  <span className="text-green-600">✅ Ativo</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Métricas:</span>
                  <span className="text-green-600">✅ Coletando</span>
                </div>
              </div>
            </div>

            {/* Performance Metrics */}
            {showMetrics && (
              <div className="bg-white rounded-lg shadow-sm p-6">
                <h3 className="text-sm font-medium text-gray-900 mb-4">
                  📊 Métricas de Performance
                </h3>
                <div className="space-y-2 text-xs">
                  {Object.keys(performanceStats).length === 0 ? (
                    <p className="text-gray-500">Nenhuma métrica coletada ainda</p>
                  ) : (
                    Object.entries(performanceStats).map(([operation, stats]) => (
                      <div key={operation} className="border-b pb-2">
                        <div className="font-medium">{operation}</div>
                        <div className="text-gray-600">
                          Operações: {stats.totalOperations}<br/>
                          Média: {Math.round(stats.averageDuration)}ms<br/>
                          Min/Max: {Math.round(stats.minDuration)}/{Math.round(stats.maxDuration)}ms
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}

            {/* Cache Stats */}
            {showCache && (
              <div className="bg-white rounded-lg shadow-sm p-6">
                <div className="flex justify-between items-center mb-4">
                  <h3 className="text-sm font-medium text-gray-900">
                    🗄️ Estatísticas do Cache
                  </h3>
                  <button
                    onClick={clearCache}
                    className="px-2 py-1 text-xs bg-red-100 text-red-700 rounded hover:bg-red-200"
                  >
                    Limpar
                  </button>
                </div>
                <div className="space-y-2 text-xs">
                  <div className="flex justify-between">
                    <span>Itens:</span>
                    <span>{cacheStats.total}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Tamanho:</span>
                    <span>{cacheStats.size}</span>
                  </div>
                  {cacheStats.oldest && (
                    <div className="flex justify-between">
                      <span>Mais antigo:</span>
                      <span>{new Date(cacheStats.oldest).toLocaleTimeString()}</span>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Instructions */}
            <div className="bg-blue-50 rounded-lg p-6">
              <h3 className="text-sm font-medium text-blue-900 mb-3">
                ℹ️ Como Testar
              </h3>
              <ul className="text-xs text-blue-800 space-y-2">
                <li>• Arraste arquivos PDF, TXT ou DOCX</li>
                                 <li>• Teste com arquivos grandes (&gt;10MB)</li>
                <li>• Observe o progresso em tempo real</li>
                <li>• Verifique as métricas de performance</li>
                <li>• Cache é mantido entre sessões</li>
              </ul>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
} 