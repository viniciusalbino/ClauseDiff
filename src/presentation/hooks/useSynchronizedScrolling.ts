import { useRef, useEffect, useCallback, useState } from 'react';

export interface SynchronizedScrollOptions {
  enabled?: boolean;
  smoothScrolling?: boolean;
  scrollDelay?: number;
  syncHorizontal?: boolean;
  syncVertical?: boolean;
  scrollTolerance?: number; // Pixels of tolerance before syncing
}

export interface ScrollState {
  scrollTop: number;
  scrollLeft: number;
  scrollHeight: number;
  scrollWidth: number;
  clientHeight: number;
  clientWidth: number;
}

/**
 * Hook para sincronização de scroll entre múltiplos painéis
 * Oferece scroll suave, tolerância configurável e controle fino
 */
export const useSynchronizedScrolling = (
  options: SynchronizedScrollOptions = {}
) => {
  const {
    enabled = true,
    smoothScrolling = true,
    scrollDelay = 16, // ~60fps
    syncHorizontal = true,
    syncVertical = true,
    scrollTolerance = 2
  } = options;

  const [isScrolling, setIsScrolling] = useState(false);
  const [activePanel, setActivePanel] = useState<string | null>(null);
  
  const panelRefs = useRef<Map<string, HTMLElement>>(new Map());
  const scrollStates = useRef<Map<string, ScrollState>>(new Map());
  const scrollTimeouts = useRef<Map<string, NodeJS.Timeout>>(new Map());
  const lastSyncTime = useRef<number>(0);

  /**
   * Registra um painel para sincronização
   */
  const registerPanel = useCallback((id: string, element: HTMLElement) => {
    if (!element) return;
    
    panelRefs.current.set(id, element);
    
    // Inicializar estado do scroll
    const initialState: ScrollState = {
      scrollTop: element.scrollTop,
      scrollLeft: element.scrollLeft,
      scrollHeight: element.scrollHeight,
      scrollWidth: element.scrollWidth,
      clientHeight: element.clientHeight,
      clientWidth: element.clientWidth
    };
    
    scrollStates.current.set(id, initialState);
  }, []);

  /**
   * Remove um painel da sincronização
   */
  const unregisterPanel = useCallback((id: string) => {
    panelRefs.current.delete(id);
    scrollStates.current.delete(id);
    
    const timeout = scrollTimeouts.current.get(id);
    if (timeout) {
      clearTimeout(timeout);
      scrollTimeouts.current.delete(id);
    }
  }, []);

  /**
   * Sincroniza scroll entre painéis
   */
  const syncScroll = useCallback((sourceId: string, targetIds?: string[]) => {
    if (!enabled) return;

    const now = Date.now();
    if (now - lastSyncTime.current < scrollDelay) return;
    lastSyncTime.current = now;

    const sourceElement = panelRefs.current.get(sourceId);
    if (!sourceElement) return;

    const sourceState = scrollStates.current.get(sourceId);
    if (!sourceState) return;

    const newScrollTop = sourceElement.scrollTop;
    const newScrollLeft = sourceElement.scrollLeft;

    // Verificar se houve mudança significativa
    const topDiff = Math.abs(newScrollTop - sourceState.scrollTop);
    const leftDiff = Math.abs(newScrollLeft - sourceState.scrollLeft);

    if (topDiff < scrollTolerance && leftDiff < scrollTolerance) return;

    // Atualizar estado do painel fonte
    scrollStates.current.set(sourceId, {
      ...sourceState,
      scrollTop: newScrollTop,
      scrollLeft: newScrollLeft
    });

    // Sincronizar com outros painéis
    const targetsToSync = targetIds || Array.from(panelRefs.current.keys()).filter(id => id !== sourceId);

    targetsToSync.forEach(targetId => {
      const targetElement = panelRefs.current.get(targetId);
      const targetState = scrollStates.current.get(targetId);
      
      if (!targetElement || !targetState) return;

      // Calcular posição proporcional
      const scrollTopRatio = sourceState.scrollHeight > sourceState.clientHeight 
        ? newScrollTop / (sourceState.scrollHeight - sourceState.clientHeight)
        : 0;

      const scrollLeftRatio = sourceState.scrollWidth > sourceState.clientWidth
        ? newScrollLeft / (sourceState.scrollWidth - sourceState.clientWidth)
        : 0;

      const targetScrollTop = syncVertical 
        ? scrollTopRatio * Math.max(0, targetState.scrollHeight - targetState.clientHeight)
        : targetElement.scrollTop;

      const targetScrollLeft = syncHorizontal 
        ? scrollLeftRatio * Math.max(0, targetState.scrollWidth - targetState.clientWidth)
        : targetElement.scrollLeft;

      // Aplicar scroll suave ou direto
      if (smoothScrolling && targetElement.scrollTo) {
        targetElement.scrollTo({
          top: targetScrollTop,
          left: targetScrollLeft,
          behavior: 'smooth'
        });
      } else {
        targetElement.scrollTop = targetScrollTop;
        targetElement.scrollLeft = targetScrollLeft;
      }

      // Atualizar estado do painel alvo
      scrollStates.current.set(targetId, {
        ...targetState,
        scrollTop: targetScrollTop,
        scrollLeft: targetScrollLeft
      });
    });
  }, [enabled, scrollDelay, syncHorizontal, syncVertical, scrollTolerance, smoothScrolling]);

  /**
   * Cria handler de scroll para um painel específico
   */
  const createScrollHandler = useCallback((panelId: string) => {
    return (event: Event) => {
      if (!enabled) return;

      const element = event.target as HTMLElement;
      if (!element) return;

      setActivePanel(panelId);
      setIsScrolling(true);

      // Atualizar estado do scroll
      const currentState = scrollStates.current.get(panelId);
      if (currentState) {
        scrollStates.current.set(panelId, {
          ...currentState,
          scrollTop: element.scrollTop,
          scrollLeft: element.scrollLeft,
          scrollHeight: element.scrollHeight,
          scrollWidth: element.scrollWidth,
          clientHeight: element.clientHeight,
          clientWidth: element.clientWidth
        });
      }

      // Throttle da sincronização
      const existingTimeout = scrollTimeouts.current.get(panelId);
      if (existingTimeout) {
        clearTimeout(existingTimeout);
      }

      const timeout = setTimeout(() => {
        syncScroll(panelId);
        setIsScrolling(false);
        setActivePanel(null);
        scrollTimeouts.current.delete(panelId);
      }, scrollDelay);

      scrollTimeouts.current.set(panelId, timeout);
    };
  }, [enabled, scrollDelay, syncScroll]);

  /**
   * Scroll programático para posição específica
   */
  const scrollToPosition = useCallback((
    position: { top?: number; left?: number },
    targetPanels?: string[]
  ) => {
    const panelsToScroll = targetPanels || Array.from(panelRefs.current.keys());

    panelsToScroll.forEach(panelId => {
      const element = panelRefs.current.get(panelId);
      if (!element) return;

      const scrollOptions: ScrollToOptions = {
        behavior: smoothScrolling ? 'smooth' : 'auto'
      };

      if (position.top !== undefined) scrollOptions.top = position.top;
      if (position.left !== undefined) scrollOptions.left = position.left;

      if (element.scrollTo) {
        element.scrollTo(scrollOptions);
      } else {
        if (position.top !== undefined) element.scrollTop = position.top;
        if (position.left !== undefined) element.scrollLeft = position.left;
      }
    });
  }, [smoothScrolling]);

  /**
   * Scroll para elemento específico
   */
  const scrollToElement = useCallback((
    selector: string,
    targetPanels?: string[],
    offset: { top?: number; left?: number } = {}
  ) => {
    const panelsToScroll = targetPanels || Array.from(panelRefs.current.keys());

    panelsToScroll.forEach(panelId => {
      const container = panelRefs.current.get(panelId);
      if (!container) return;

      const targetElement = container.querySelector(selector) as HTMLElement;
      if (!targetElement) return;

      const containerRect = container.getBoundingClientRect();
      const targetRect = targetElement.getBoundingClientRect();

      const scrollTop = container.scrollTop + (targetRect.top - containerRect.top) + (offset.top || 0);
      const scrollLeft = container.scrollLeft + (targetRect.left - containerRect.left) + (offset.left || 0);

      scrollToPosition({ top: scrollTop, left: scrollLeft }, [panelId]);
    });
  }, [scrollToPosition]);

  /**
   * Obtém estado atual do scroll de um painel
   */
  const getScrollState = useCallback((panelId: string): ScrollState | null => {
    return scrollStates.current.get(panelId) || null;
  }, []);

  /**
   * Obtém informações sobre todos os painéis
   */
  const getAllScrollStates = useCallback((): Record<string, ScrollState> => {
    const states: Record<string, ScrollState> = {};
    scrollStates.current.forEach((state, id) => {
      states[id] = state;
    });
    return states;
  }, []);

  /**
   * Reseta estados de scroll
   */
  const resetScrollStates = useCallback(() => {
    panelRefs.current.forEach((element, id) => {
      element.scrollTop = 0;
      element.scrollLeft = 0;
      
      const state = scrollStates.current.get(id);
      if (state) {
        scrollStates.current.set(id, {
          ...state,
          scrollTop: 0,
          scrollLeft: 0
        });
      }
    });
  }, []);

  // Cleanup na desmontagem
  useEffect(() => {
    return () => {
      scrollTimeouts.current.forEach(timeout => clearTimeout(timeout));
      scrollTimeouts.current.clear();
    };
  }, []);

  return {
    // Registration
    registerPanel,
    unregisterPanel,
    
    // Handlers
    createScrollHandler,
    
    // Programmatic scrolling
    scrollToPosition,
    scrollToElement,
    syncScroll,
    
    // State access
    getScrollState,
    getAllScrollStates,
    resetScrollStates,
    
    // Status
    isScrolling,
    activePanel,
    
    // Computed properties
    registeredPanels: Array.from(panelRefs.current.keys()),
    panelCount: panelRefs.current.size
  };
};

export default useSynchronizedScrolling; 