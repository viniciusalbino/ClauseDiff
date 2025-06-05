/**
 * Sistema de cache simples usando localStorage
 * Evita reprocessamento desnecessário de dados
 */

export interface CacheItem<T = any> {
  data: T;
  timestamp: number;
  ttl: number; // Time to live em milissegundos
}

export class SimpleCache {
  private prefix: string;
  private defaultTTL: number;

  constructor(prefix = 'clausediff_cache', defaultTTL = 60 * 60 * 1000) { // 1 hora
    this.prefix = prefix;
    this.defaultTTL = defaultTTL;
  }

  // Define item no cache
  set<T>(key: string, data: T, ttl?: number): void {
    try {
      const item: CacheItem<T> = {
        data,
        timestamp: Date.now(),
        ttl: ttl || this.defaultTTL
      };

      const cacheKey = `${this.prefix}_${key}`;
      localStorage.setItem(cacheKey, JSON.stringify(item));
    } catch (error) {
      console.warn('Cache set failed:', error);
    }
  }

  // Obtém item do cache
  get<T>(key: string): T | null {
    try {
      const cacheKey = `${this.prefix}_${key}`;
      const stored = localStorage.getItem(cacheKey);
      
      if (!stored) return null;

      const item: CacheItem<T> = JSON.parse(stored);
      const now = Date.now();

      // Verifica se expirou
      if (now - item.timestamp > item.ttl) {
        this.delete(key);
        return null;
      }

      return item.data;
    } catch (error) {
      console.warn('Cache get failed:', error);
      return null;
    }
  }

  // Remove item do cache
  delete(key: string): void {
    try {
      const cacheKey = `${this.prefix}_${key}`;
      localStorage.removeItem(cacheKey);
    } catch (error) {
      console.warn('Cache delete failed:', error);
    }
  }

  // Limpa todo o cache
  clear(): void {
    try {
      const keys = Object.keys(localStorage);
      keys.forEach(key => {
        if (key.startsWith(this.prefix)) {
          localStorage.removeItem(key);
        }
      });
    } catch (error) {
      console.warn('Cache clear failed:', error);
    }
  }

  // Limpa itens expirados
  cleanup(): number {
    let cleaned = 0;
    try {
      const keys = Object.keys(localStorage);
      const now = Date.now();

      keys.forEach(key => {
        if (!key.startsWith(this.prefix)) return;

        try {
          const stored = localStorage.getItem(key);
          if (!stored) return;

          const item: CacheItem = JSON.parse(stored);
          if (now - item.timestamp > item.ttl) {
            localStorage.removeItem(key);
            cleaned++;
          }
        } catch {
          // Item corrompido, remove
          localStorage.removeItem(key);
          cleaned++;
        }
      });
    } catch (error) {
      console.warn('Cache cleanup failed:', error);
    }

    return cleaned;
  }

  // Obtém estatísticas do cache
  getStats(): { total: number; size: string; oldest: number | null } {
    let total = 0;
    let totalSize = 0;
    let oldest: number | null = null;

    try {
      const keys = Object.keys(localStorage);
      
      keys.forEach(key => {
        if (!key.startsWith(this.prefix)) return;

        const stored = localStorage.getItem(key);
        if (stored) {
          total++;
          totalSize += stored.length;

          try {
            const item: CacheItem = JSON.parse(stored);
            if (oldest === null || item.timestamp < oldest) {
              oldest = item.timestamp;
            }
          } catch {
            // Ignora itens corrompidos
          }
        }
      });
    } catch (error) {
      console.warn('Cache stats failed:', error);
    }

    const sizeKB = (totalSize / 1024).toFixed(2);
    
    return {
      total,
      size: `${sizeKB}KB`,
      oldest
    };
  }
}

// Hook para usar cache em componentes React
import { useCallback, useMemo } from 'react';

export function useSimpleCache(prefix?: string, defaultTTL?: number) {
  const cache = useMemo(() => new SimpleCache(prefix, defaultTTL), [prefix, defaultTTL]);

  const setCache = useCallback(<T>(key: string, data: T, ttl?: number) => {
    cache.set(key, data, ttl);
  }, [cache]);

  const getCache = useCallback(<T>(key: string): T | null => {
    return cache.get<T>(key);
  }, [cache]);

  const deleteCache = useCallback((key: string) => {
    cache.delete(key);
  }, [cache]);

  const clearCache = useCallback(() => {
    cache.clear();
  }, [cache]);

  const cleanupCache = useCallback(() => {
    return cache.cleanup();
  }, [cache]);

  const getCacheStats = useCallback(() => {
    return cache.getStats();
  }, [cache]);

  return {
    setCache,
    getCache,
    deleteCache,
    clearCache,
    cleanupCache,
    getCacheStats
  };
}

// Cache global para uso geral
export const globalCache = new SimpleCache('clausediff_global', 30 * 60 * 1000); // 30 min 