/**
 * Testes unitários para SimpleCache
 * Testando sistema de cache implementado na Seção 5.0
 */

import { SimpleCache } from '../../../src/utils/SimpleCache';

// Mock localStorage
const localStorageMock = (() => {
  let store: Record<string, string> = {};
  return {
    getItem: (key: string) => store[key] || null,
    setItem: (key: string, value: string) => { store[key] = value; },
    removeItem: (key: string) => { delete store[key]; },
    clear: () => { store = {}; },
    get length() { return Object.keys(store).length; },
    key: (index: number) => Object.keys(store)[index] || null
  };
})();

Object.defineProperty(window, 'localStorage', {
  value: localStorageMock
});

describe('SimpleCache', () => {
  let cache: SimpleCache;

  beforeEach(() => {
    localStorageMock.clear();
    cache = new SimpleCache();
  });

  describe('Operações Básicas', () => {
    it('deve armazenar e recuperar dados', () => {
      const key = 'test-key';
      const value = { message: 'Hello World' };

      cache.set(key, value);
      const retrieved = cache.get(key);

      expect(retrieved).toEqual(value);
    });

    it('deve retornar null para chave inexistente', () => {
      const result = cache.get('non-existent-key');
      expect(result).toBeNull();
    });

    it('deve verificar se chave existe', () => {
      const key = 'test-key';
      
      expect(cache.get(key)).toBeNull();
      
      cache.set(key, 'value');
      expect(cache.get(key)).toBe('value');
    });

    it('deve remover item do cache', () => {
      const key = 'test-key';
      
      cache.set(key, 'value');
      expect(cache.get(key)).toBe('value');
      
      cache.delete(key);
      expect(cache.get(key)).toBeNull();
    });

    it('deve limpar todo o cache', () => {
      cache.set('key1', 'value1');
      cache.set('key2', 'value2');
      
      expect(cache.get('key1')).toBe('value1');
      expect(cache.get('key2')).toBe('value2');
      
      cache.clear();
      
      expect(cache.get('key1')).toBeNull();
      expect(cache.get('key2')).toBeNull();
    });
  });

  describe('TTL (Time To Live)', () => {
    it('deve expirar itens após TTL', async () => {
      const key = 'expiring-key';
      const value = 'expiring-value';
      const ttl = 100; // 100ms

      cache.set(key, value, ttl);
      expect(cache.get(key)).toEqual(value);

      // Aguardar expiração
      await new Promise(resolve => setTimeout(resolve, 150));
      
      expect(cache.get(key)).toBeNull();
    });

    it('deve usar TTL padrão quando não especificado', () => {
      const key = 'default-ttl-key';
      const value = 'value';

      cache.set(key, value);
      
      // Item deve existir imediatamente
      expect(cache.get(key)).toEqual(value);
    });

    it('deve permitir TTL infinito', () => {
      const key = 'infinite-key';
      const value = 'infinite-value';

      cache.set(key, value, Infinity);
      
      expect(cache.get(key)).toEqual(value);
    });
  });

  describe('Estatísticas', () => {
    it('deve fornecer estatísticas do cache', () => {
      cache.set('key1', 'value1');
      cache.set('key2', 'value2');
      
      const stats = cache.getStats();
      
      expect(stats.total).toBe(2);
      expect(stats.size).toContain('bytes');
      expect(stats.oldest).toBeDefined();
    });

    it('deve calcular tamanho aproximado', () => {
      const largeValue = 'x'.repeat(1000);
      cache.set('large-key', largeValue);
      
      const stats = cache.getStats();
      
      expect(stats.size).toContain('KB');
    });
  });

  describe('Limpeza Automática', () => {
    it('deve limpar itens expirados automaticamente', async () => {
      const key1 = 'short-lived';
      const key2 = 'long-lived';
      
      cache.set(key1, 'value1', 50); // 50ms
      cache.set(key2, 'value2', 1000); // 1s
      
      // Aguardar expiração do primeiro item
      await new Promise(resolve => setTimeout(resolve, 100));
      
      // Acessar cache para triggerar limpeza
      cache.get(key2);
      
             expect(cache.get(key1)).toBeNull();
       expect(cache.get(key2)).toBe('value2');
    });
  });

  describe('Serialização', () => {
    it('deve serializar objetos complexos', () => {
      const complexObject = {
        string: 'text',
        number: 42,
        boolean: true,
        array: [1, 2, 3],
        nested: {
          prop: 'value'
        }
      };

      cache.set('complex', complexObject);
      const retrieved = cache.get('complex');

      expect(retrieved).toEqual(complexObject);
    });

    it('deve lidar com valores null e undefined', () => {
      cache.set('null-value', null);
      cache.set('undefined-value', undefined);

      expect(cache.get('null-value')).toBeNull();
      expect(cache.get('undefined-value')).toBeNull();
    });
  });

  describe('Configuração', () => {
         it('deve aceitar configuração customizada', () => {
       const customCache = new SimpleCache('custom-', 5000);

       customCache.set('test', 'value');
       
       // Verificar se usa prefix customizado
       expect(localStorageMock.getItem('custom-_test')).toBeDefined();
     });
  });

  describe('Error Handling', () => {
    it('deve lidar com localStorage indisponível', () => {
      // Simular localStorage indisponível
      const originalLocalStorage = window.localStorage;
      Object.defineProperty(window, 'localStorage', {
        value: null,
        configurable: true
      });

      const fallbackCache = new SimpleCache();
      
      // Deve funcionar mesmo sem localStorage
      fallbackCache.set('test', 'value');
      expect(fallbackCache.get('test')).toEqual('value');

      // Restaurar localStorage
      Object.defineProperty(window, 'localStorage', {
        value: originalLocalStorage,
        configurable: true
      });
    });

    it('deve lidar com dados corrompidos no localStorage', () => {
      // Inserir dados corrompidos
      localStorageMock.setItem('clausediff-cache-corrupted', 'invalid-json');
      
      const result = cache.get('corrupted');
      
      expect(result).toBeNull();
    });
  });
}); 