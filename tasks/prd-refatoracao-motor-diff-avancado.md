# PRD - Refatoração Avançada do Motor de Comparação de Documentos

## Introdução/Overview

O motor de comparação atual (`src/utils/diffEngine.ts`) apresenta limitações de arquitetura, performance e funcionalidade que impedem uma experiência otimizada para usuários que fazem uso intensivo da comparação de documentos. Esta refatoração visa implementar uma arquitetura modular com múltiplos algoritmos, otimizações de performance e visualização avançada, mantendo a simplicidade e foco no problema específico.

**Problema:** O motor atual usa apenas DiffMatchPatch, não possui otimizações para documentos grandes, tem visualização limitada e não segue a nova arquitetura DDD.

**Goal:** Criar um motor de comparação robusto, performático e extensível que ofereça resultados precisos para documentos jurídicos de até 5MB/30 páginas com tempo de processamento otimizado.

## Goals

1. **Arquitetura Modular:** Implementar interfaces claras e padrões de design para facilitar manutenção e extensibilidade
2. **Performance Otimizada:** Processar documentos de até 5MB em menos de 10 segundos
3. **Múltiplos Algoritmos:** Oferecer diferentes estratégias de comparação baseadas no tipo de documento
4. **Visualização Avançada:** Interface intuitiva com highlighting semântico e navegação eficiente
5. **Integração com Arquitetura:** Adequar-se à estrutura DDD/Clean Architecture existente

## User Stories

**Como advogado/usuário corporativo, eu quero:**

1. **US-1:** Comparar dois documentos .docx de até 30 páginas e receber resultado em menos de 10 segundos, para que eu possa revisar alterações rapidamente
2. **US-2:** Visualizar diferenças com highlighting por tipo de alteração (adição, remoção, modificação), para que eu possa identificar rapidamente o impacto das mudanças
3. **US-3:** Navegar pelas alterações usando keyboard shortcuts (setas, tab), para que eu possa revisar documentos de forma eficiente
4. **US-4:** Ver estatísticas detalhadas das alterações (percentual de similaridade, número de modificações), para que eu possa avaliar a extensão das mudanças
5. **US-5:** Exportar o resultado da comparação em PDF, DOC ou CSV, mantendo a funcionalidade atual
6. **US-6:** Escolher entre visualização side-by-side ou inline, para que eu possa adaptar à minha preferência de trabalho

## Functional Requirements

### FR-1: Arquitetura Modular
1.1. Interface `IDiffEngine` com métodos: `compare()`, `visualize()`, `getSummary()`
1.2. Implementações: `DiffMatchPatchEngine`, `MyersDiffEngine`, `SemanticDiffEngine`
1.3. Strategy pattern para seleção automática de algoritmo baseado no tamanho do documento
1.4. Factory para instanciação de engines conforme configuração
1.5. Adapter para uniformizar saída de diferentes algoritmos

### FR-2: Otimizações de Performance
2.1. Sistema de chunking configurável para documentos >1MB
2.2. Web Worker dedicado para operações de diff (não bloquear UI)
2.3. Cache LRU para resultados intermediários (máximo 100MB de cache)
2.4. Compressão de dados diff para reduzir uso de memória

### FR-3: Algoritmos de Comparação
3.1. Pré-processamento com normalização de texto (whitespace, encoding)
3.2. Tokenização inteligente para unidades semânticas (frases, parágrafos, seções)
3.3. Detecção de movimentação de blocos de texto
3.4. Algoritmo de diff semântico para mudanças de significado

### FR-4: Métricas e Análise
4.1. Cálculo de similaridade usando algoritmos: Jaccard, Levenshtein, Cosine
4.2. Estatísticas: total de alterações, adições, remoções, percentual de similaridade
4.3. Identificação de seções com maiores alterações
4.4. Exportação de métricas em formato JSON

### FR-5: Visualização Avançada
5.1. Highlighting semântico: cores diferentes para adição (verde), remoção (vermelho), modificação (amarelo)
5.2. Navegação por alteração: botões próximo/anterior, keyboard shortcuts (↑/↓, Tab/Shift+Tab)
5.3. Scrolling sincronizado entre painéis com debounce para performance
5.4. Opções de visualização: side-by-side (padrão), inline, unified
5.5. Collapse/expand de seções inalteradas (quando >5 linhas consecutivas)

### FR-6: Interface de Usuário
6.1. Manter paleta de cores atual: slate (cinza), blue (azul), green (verde), red (vermelho)
6.2. Layout consistente com login/registro: bg-slate-50, cards bg-white, shadow-xl
6.3. Upload de arquivos com drag & drop e validação (<5MB, .docx)
6.4. Barra de progresso durante processamento
6.5. Painel de estatísticas com informações resumidas

## Non-Goals (Out of Scope)

- Comparação de outros formatos além de .docx
- Integração com sistemas externos de versionamento (Git, SharePoint)
- Funcionalidades de colaboração em tempo real
- Histórico persistente de comparações (inicialmente)
- Recursos de IA/ML para análise de sentimento avançada
- Support para documentos >5MB na versão inicial

## Design Considerations

### Layout e Componentes
- **Seguir padrão visual das páginas login/register:** 
  - Background: `bg-slate-50`
  - Cards: `bg-white shadow-xl rounded-lg`
  - Botões primários: `bg-blue-600 hover:bg-blue-700`
  - Textos: `text-slate-900` (títulos), `text-slate-600` (descrições)

### Estrutura de Componentes
```
/src/presentation/components/diff/
  ├── DiffViewer.tsx          # Componente principal
  ├── DiffSideBySide.tsx      # Visualização lado a lado  
  ├── DiffInline.tsx          # Visualização inline
  ├── DiffNavigation.tsx      # Navegação entre alterações
  ├── DiffStats.tsx           # Painel de estatísticas
  ├── DiffControls.tsx        # Controles de visualização
  └── FileUpload.tsx          # Upload de arquivos
```

## Technical Considerations

### Arquitetura DDD
- **Domain:** Entidades `DocumentComparison`, `DiffResult`, interfaces `IDiffEngine`
- **Application:** Use cases `CompareDocuments`, `ExportComparison`
- **Infrastructure:** Implementações concretas dos engines, storage
- **Presentation:** Componentes React para visualização

### Performance
- Web Workers para evitar bloqueio da UI durante comparações longas
- Virtualização para renderização de documentos grandes
- Debouncing em scroll events (300ms)
- Lazy loading de seções não visíveis

### Tecnologias
- TypeScript para tipagem forte
- Web Workers API para processamento assíncrono
- IndexedDB para cache local (via Dexie.js)
- Canvas API para renderização otimizada (se necessário)

## Success Metrics

### Performance
- Tempo de processamento para documento 1MB: <3 segundos
- Tempo de processamento para documento 5MB: <10 segundos
- Responsividade da UI: sem bloqueios >100ms

### Qualidade
- Precisão na detecção de alterações: >95% em testes com documentos jurídicos
- Redução de falsos positivos em 50% comparado à implementação atual
- Taxa de satisfação do usuário: >85% em testes de usabilidade

### Adoção
- Tempo médio de uso por sessão: aumento de 20%
- Taxa de conclusão de comparações: >90%
- Redução em relatórios de bugs relacionados à comparação: 70%

## Open Questions

1. **Cache Strategy:** Usar IndexedDB ou localStorage para cache de resultados?
2. **Worker Fallback:** Como tratar browsers que não suportam Web Workers?
3. **Memory Limits:** Qual limite máximo de memória para cache LRU?
4. **Algorithm Selection:** Critérios específicos para seleção automática de algoritmo?
5. **Export Format:** Manter formatos de exportação atuais ou adicionar novos?

## Implementation Notes

### Big O Complexity Analysis
- **DiffMatchPatch:** O(n*m) onde n,m são tamanhos dos textos
- **Myers Algorithm:** O(n+m+d²) onde d é número de diferenças
- **Semantic Diff:** O(n*log(n)) com pré-processamento

### Benchmarks Planejados
- Documento 1 página (~2KB): <500ms
- Documento 10 páginas (~200KB): <2s  
- Documento 30 páginas (~5MB): <10s

### Phases de Implementação
1. **Fase 1:** Estruturas base, interfaces, DiffMatchPatch otimizado
2. **Fase 2:** Web Workers, cache, chunking
3. **Fase 3:** Algoritmos alternativos, visualização avançada
4. **Fase 4:** Métricas, exportação, refinamentos

---

**Estimativa de Desenvolvimento:** 2-3 semanas
**Prioridade:** Alta
**Stakeholders:** Equipe de desenvolvimento, usuários finais (advogados/empresas) 