export interface DebounceConfig {
  delay: number; // Delay em milissegundos (padrão: 300ms)
  immediate?: boolean; // Executar imediatamente na primeira chamada
  maxWait?: number; // Tempo máximo para esperar antes de executar forçadamente
}

export interface ScrollPosition {
  x: number;
  y: number;
  timestamp: number;
}

export interface ScrollMetrics {
  velocity: number;
  direction: 'up' | 'down' | 'left' | 'right' | 'none';
  distance: number;
  isScrolling: boolean;
}

/**
 * Utilitário para debouncing de eventos de scroll
 */
export class ScrollDebouncer {
  private readonly config: Required<DebounceConfig>;
  private timeoutId: number | null = null;
  private maxTimeoutId: number | null = null;
  private lastExecution = 0;
  private lastPosition: ScrollPosition | null = null;
  private isScrolling = false;
  private scrollStartTime = 0;

  constructor(config: Partial<DebounceConfig> = {}) {
    this.config = {
      delay: config.delay || 300,
      immediate: config.immediate ?? false,
      maxWait: config.maxWait || 1000
    };
  }

  /**
   * Debounce uma função de callback para scroll
   */
  public debounce<T extends any[]>(
    callback: (...args: T) => void,
    context?: any
  ): (...args: T) => void {
    return (...args: T) => {
      const now = Date.now();
      const timeSinceLastExecution = now - this.lastExecution;

      // Limpar timeout anterior
      if (this.timeoutId) {
        clearTimeout(this.timeoutId);
      }

      // Executar imediatamente se configurado e for a primeira vez
      if (this.config.immediate && timeSinceLastExecution > this.config.delay) {
        this.execute(callback, args, context);
        return;
      }

      // Configurar timeout para execução demorada
      this.timeoutId = window.setTimeout(() => {
        this.execute(callback, args, context);
      }, this.config.delay);

      // Configurar timeout máximo se especificado
      if (this.config.maxWait && !this.maxTimeoutId) {
        this.maxTimeoutId = window.setTimeout(() => {
          if (this.timeoutId) {
            clearTimeout(this.timeoutId);
            this.timeoutId = null;
          }
          this.execute(callback, args, context);
        }, this.config.maxWait);
      }
    };
  }

  /**
   * Debounce específico para eventos de scroll com métricas
   */
  public debouncedScrollHandler(
    callback: (position: ScrollPosition, metrics: ScrollMetrics) => void,
    element?: Element | Window
  ): (event: Event) => void {
    return this.debounce((event: Event) => {
      const position = this.getCurrentPosition(element);
      const metrics = this.calculateMetrics(position);
      
      callback(position, metrics);
    });
  }

  /**
   * Cria um listener de scroll otimizado
   */
  public createOptimizedScrollListener(
    callback: (position: ScrollPosition, metrics: ScrollMetrics) => void,
    element?: Element | Window,
    options: AddEventListenerOptions = {}
  ): () => void {
    const handler = this.debouncedScrollHandler(callback, element);
    const scrollEndHandler = this.createScrollEndHandler();
    
    const target = element || window;
    
    // Adicionar listeners
    target.addEventListener('scroll', handler, { 
      passive: true, 
      ...options 
    });
    
    target.addEventListener('scroll', scrollEndHandler, { 
      passive: true 
    });

    // Retornar função de cleanup
    return () => {
      target.removeEventListener('scroll', handler);
      target.removeEventListener('scroll', scrollEndHandler);
      this.cleanup();
    };
  }

  /**
   * Handler para detectar fim do scroll
   */
  private createScrollEndHandler(): () => void {
    let scrollEndTimeoutId: number | null = null;
    
    return () => {
      if (!this.isScrolling) {
        this.isScrolling = true;
        this.scrollStartTime = Date.now();
      }

      if (scrollEndTimeoutId) {
        clearTimeout(scrollEndTimeoutId);
      }

      scrollEndTimeoutId = window.setTimeout(() => {
        this.isScrolling = false;
        this.scrollStartTime = 0;
      }, this.config.delay + 50); // Um pouco mais que o delay do debounce
    };
  }

  /**
   * Obtém posição atual do scroll
   */
  private getCurrentPosition(element?: Element | Window): ScrollPosition {
    let x: number, y: number;

    if (!element || element === window) {
      x = window.pageXOffset || document.documentElement.scrollLeft;
      y = window.pageYOffset || document.documentElement.scrollTop;
    } else {
      const el = element as Element;
      x = el.scrollLeft;
      y = el.scrollTop;
    }

    return {
      x,
      y,
      timestamp: Date.now()
    };
  }

  /**
   * Calcula métricas de scroll
   */
  private calculateMetrics(currentPosition: ScrollPosition): ScrollMetrics {
    if (!this.lastPosition) {
      this.lastPosition = currentPosition;
      return {
        velocity: 0,
        direction: 'none',
        distance: 0,
        isScrolling: this.isScrolling
      };
    }

    const deltaX = currentPosition.x - this.lastPosition.x;
    const deltaY = currentPosition.y - this.lastPosition.y;
    const deltaTime = currentPosition.timestamp - this.lastPosition.timestamp;
    
    const distance = Math.sqrt(deltaX * deltaX + deltaY * deltaY);
    const velocity = deltaTime > 0 ? distance / deltaTime : 0;

    let direction: ScrollMetrics['direction'] = 'none';
    
    if (Math.abs(deltaY) > Math.abs(deltaX)) {
      direction = deltaY > 0 ? 'down' : 'up';
    } else if (Math.abs(deltaX) > 0) {
      direction = deltaX > 0 ? 'right' : 'left';
    }

    this.lastPosition = currentPosition;

    return {
      velocity,
      direction,
      distance,
      isScrolling: this.isScrolling
    };
  }

  /**
   * Executa o callback
   */
  private execute<T extends any[]>(
    callback: (...args: T) => void,
    args: T,
    context?: any
  ): void {
    this.lastExecution = Date.now();
    
    if (this.maxTimeoutId) {
      clearTimeout(this.maxTimeoutId);
      this.maxTimeoutId = null;
    }

    this.timeoutId = null;

    if (context) {
      callback.apply(context, args);
    } else {
      callback(...args);
    }
  }

  /**
   * Cancela execuções pendentes
   */
  public cancel(): void {
    if (this.timeoutId) {
      clearTimeout(this.timeoutId);
      this.timeoutId = null;
    }
    
    if (this.maxTimeoutId) {
      clearTimeout(this.maxTimeoutId);
      this.maxTimeoutId = null;
    }
  }

  /**
   * Força execução imediata se há uma pendente
   */
  public flush<T extends any[]>(
    callback: (...args: T) => void,
    args: T,
    context?: any
  ): void {
    if (this.timeoutId) {
      this.cancel();
      this.execute(callback, args, context);
    }
  }

  /**
   * Cleanup dos recursos
   */
  public cleanup(): void {
    this.cancel();
    this.lastPosition = null;
    this.isScrolling = false;
    this.scrollStartTime = 0;
  }

  /**
   * Obtém estatísticas do debouncer
   */
  public getStats(): {
    isActive: boolean;
    lastExecution: number;
    config: Required<DebounceConfig>;
    currentPosition: ScrollPosition | null;
    isScrolling: boolean;
  } {
    return {
      isActive: this.timeoutId !== null,
      lastExecution: this.lastExecution,
      config: this.config,
      currentPosition: this.lastPosition,
      isScrolling: this.isScrolling
    };
  }
}

/**
 * Função utilitária para criar um debouncer de scroll simples
 */
export function createScrollDebouncer(
  callback: (position: ScrollPosition, metrics: ScrollMetrics) => void,
  delay = 300,
  element?: Element | Window
): () => void {
  const debouncer = new ScrollDebouncer({ delay });
  return debouncer.createOptimizedScrollListener(callback, element);
}

/**
 * Hook utilitário para debouncing genérico
 */
export function useDebounce<T extends any[]>(
  callback: (...args: T) => void,
  delay = 300,
  options: Partial<DebounceConfig> = {}
): (...args: T) => void {
  const debouncer = new ScrollDebouncer({ delay, ...options });
  return debouncer.debounce(callback);
} 