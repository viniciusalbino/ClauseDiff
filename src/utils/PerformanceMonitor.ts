/**
 * Monitor simples de performance
 * Coleta métricas básicas de operações importantes
 */

export interface PerformanceMetric {
  name: string;
  duration: number;
  timestamp: number;
  metadata?: Record<string, any>;
}

export interface PerformanceStats {
  totalOperations: number;
  averageDuration: number;
  minDuration: number;
  maxDuration: number;
  recentOperations: PerformanceMetric[];
}

export class PerformanceMonitor {
  private metrics: PerformanceMetric[] = [];
  private maxMetrics: number;
  private timers = new Map<string, number>();

  constructor(maxMetrics = 100) {
    this.maxMetrics = maxMetrics;
  }

  // Inicia cronômetro para uma operação
  start(operationName: string): string {
    const id = `${operationName}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    this.timers.set(id, performance.now());
    return id;
  }

  // Finaliza cronômetro e registra métrica
  end(id: string, metadata?: Record<string, any>): number {
    const startTime = this.timers.get(id);
    if (!startTime) {
      console.warn(`Timer not found for operation: ${id}`);
      return 0;
    }

    const duration = performance.now() - startTime;
    const operationName = id.split('_')[0];

    this.addMetric({
      name: operationName,
      duration,
      timestamp: Date.now(),
      metadata
    });

    this.timers.delete(id);
    return duration;
  }

  // Adiciona métrica diretamente
  addMetric(metric: PerformanceMetric): void {
    this.metrics.push(metric);

    // Mantém apenas as métricas mais recentes
    if (this.metrics.length > this.maxMetrics) {
      this.metrics = this.metrics.slice(-this.maxMetrics);
    }
  }

  // Obtém estatísticas de uma operação
  getStats(operationName?: string): PerformanceStats {
    const filteredMetrics = operationName 
      ? this.metrics.filter(m => m.name === operationName)
      : this.metrics;

    if (filteredMetrics.length === 0) {
      return {
        totalOperations: 0,
        averageDuration: 0,
        minDuration: 0,
        maxDuration: 0,
        recentOperations: []
      };
    }

    const durations = filteredMetrics.map(m => m.duration);
    const recent = filteredMetrics.slice(-10); // Últimas 10 operações

    return {
      totalOperations: filteredMetrics.length,
      averageDuration: durations.reduce((sum, d) => sum + d, 0) / durations.length,
      minDuration: Math.min(...durations),
      maxDuration: Math.max(...durations),
      recentOperations: recent
    };
  }

  // Obtém resumo de todas as operações
  getSummary(): Record<string, PerformanceStats> {
    const operations = [...new Set(this.metrics.map(m => m.name))];
    const summary: Record<string, PerformanceStats> = {};

    operations.forEach(op => {
      summary[op] = this.getStats(op);
    });

    return summary;
  }

  // Limpa métricas antigas
  cleanup(olderThanMs = 60 * 60 * 1000): number { // 1 hora
    const cutoff = Date.now() - olderThanMs;
    const originalLength = this.metrics.length;
    
    this.metrics = this.metrics.filter(m => m.timestamp > cutoff);
    
    return originalLength - this.metrics.length;
  }

  // Exporta métricas para análise
  export(): PerformanceMetric[] {
    return [...this.metrics];
  }

  // Reseta todas as métricas
  reset(): void {
    this.metrics = [];
    this.timers.clear();
  }
}

// Hook para usar monitor de performance em React
import { useCallback, useMemo, useRef } from 'react';

export function usePerformanceMonitor() {
  const monitor = useRef(new PerformanceMonitor()).current;

  const measureAsync = useCallback(async <T>(
    operationName: string,
    operation: () => Promise<T>,
    metadata?: Record<string, any>
  ): Promise<T> => {
    const id = monitor.start(operationName);
    
    try {
      const result = await operation();
      monitor.end(id, { ...metadata, success: true });
      return result;
    } catch (error) {
      monitor.end(id, { 
        ...metadata, 
        success: false, 
        error: (error as Error).message 
      });
      throw error;
    }
  }, [monitor]);

  const measureSync = useCallback(<T>(
    operationName: string,
    operation: () => T,
    metadata?: Record<string, any>
  ): T => {
    const id = monitor.start(operationName);
    
    try {
      const result = operation();
      monitor.end(id, { ...metadata, success: true });
      return result;
    } catch (error) {
      monitor.end(id, { 
        ...metadata, 
        success: false, 
        error: (error as Error).message 
      });
      throw error;
    }
  }, [monitor]);

  const getStats = useCallback((operationName?: string) => {
    return monitor.getStats(operationName);
  }, [monitor]);

  const getSummary = useCallback(() => {
    return monitor.getSummary();
  }, [monitor]);

  return {
    measureAsync,
    measureSync,
    getStats,
    getSummary,
    monitor
  };
}

// Monitor global para uso em toda aplicação
export const globalPerformanceMonitor = new PerformanceMonitor(200);

// Utilitários simples para medição rápida
export const measure = {
  async: async <T>(name: string, fn: () => Promise<T>): Promise<T> => {
    const id = globalPerformanceMonitor.start(name);
    try {
      const result = await fn();
      globalPerformanceMonitor.end(id, { success: true });
      return result;
    } catch (error) {
      globalPerformanceMonitor.end(id, { success: false, error: (error as Error).message });
      throw error;
    }
  },

  sync: <T>(name: string, fn: () => T): T => {
    const id = globalPerformanceMonitor.start(name);
    try {
      const result = fn();
      globalPerformanceMonitor.end(id, { success: true });
      return result;
    } catch (error) {
      globalPerformanceMonitor.end(id, { success: false, error: (error as Error).message });
      throw error;
    }
  }
}; 