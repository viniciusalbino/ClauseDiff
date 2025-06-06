# Tasks - Refatoração Avançada do Motor de Comparação de Documentos

Baseado no PRD: `prd-refatoracao-motor-diff-avancado.md`

## Relevant Files

- `src/domain/entities/DocumentComparison.ts` - Entidade de domínio para comparação de documentos
- `src/domain/entities/DiffResult.ts` - Entidade de domínio para resultado das diferenças
- `src/domain/interfaces/IDiffEngine.ts` - Interface principal do motor de diff
- `src/domain/interfaces/IStorageService.ts` - Interface para serviços de armazenamento/cache
- `src/application/use-cases/CompareDocuments.ts` - Use case para comparar documentos
- `src/application/use-cases/ExportComparison.ts` - Use case para exportar comparações
- `src/infrastructure/diff-engines/DiffMatchPatchEngine.ts` - Implementação do engine DiffMatchPatch
- `src/infrastructure/diff-engines/MyersDiffEngine.ts` - Implementação do algoritmo Myers
- `src/infrastructure/diff-engines/SemanticDiffEngine.ts` - Implementação do diff semântico
- `src/infrastructure/factories/DiffEngineFactory.ts` - Factory para criação de engines
- `src/infrastructure/adapters/DiffEngineAdapter.ts` - Adapter para uniformizar saídas
- `src/infrastructure/cache/LRUCache.ts` - Sistema de cache LRU
- `src/infrastructure/workers/DiffWorker.ts` - Web Worker para processamento
- `src/infrastructure/chunking/DocumentChunker.ts` - Sistema de chunking de documentos
- `src/presentation/components/diff/DiffViewer.tsx` - Componente principal de visualização
- `src/presentation/components/diff/DiffSideBySide.tsx` - Visualização lado a lado
- `src/presentation/components/diff/DiffInline.tsx` - Visualização inline
- `src/presentation/components/diff/DiffNavigation.tsx` - Navegação entre alterações
- `src/presentation/components/diff/DiffStats.tsx` - Painel de estatísticas
- `src/presentation/components/diff/DiffControls.tsx` - Controles de visualização
- `src/presentation/components/diff/FileUpload.tsx` - Componente de upload de arquivos
- `src/presentation/hooks/useDiffEngine.ts` - Hook para integração com React
- `src/presentation/hooks/useDiffNavigation.ts` - Hook para navegação
- `src/utils/text-processing/TextNormalizer.ts` - Utilitários de normalização de texto
- `src/utils/text-processing/SemanticTokenizer.ts` - Tokenização semântica
- `src/utils/metrics/SimilarityCalculator.ts` - Cálculo de métricas de similaridade
- `app/compare/page.tsx` - Página principal de comparação
- `test/unit/domain/entities/DocumentComparison.test.ts` - Testes das entidades
- `test/unit/infrastructure/diff-engines/*.test.ts` - Testes dos engines
- `test/unit/presentation/components/diff/*.test.tsx` - Testes dos componentes
- `test/integration/diff-engine-integration.test.ts` - Testes de integração
- `test/performance/diff-engine-benchmarks.test.ts` - Testes de performance

### Notes

- Unit tests should typically be placed alongside the code files they are testing (e.g., `DiffViewer.tsx` and `DiffViewer.test.tsx` in the same directory).
- Use `npx jest [optional/path/to/test/file]` to run tests. Running without a path executes all tests found by the Jest configuration.
- Performance tests should be run separately with `npm run test:performance`

## Tasks

- [ ] 1.0 Implementar Arquitetura Base e Interfaces DDD
  - [x] 1.1 Criar entidades de domínio (DocumentComparison, DiffResult)
  - [x] 1.2 Definir interface IDiffEngine com métodos compare(), visualize(), getSummary()
  - [x] 1.3 Criar interfaces para cache e storage (IStorageService, ICacheService)
  - [x] 1.4 Implementar use cases base (CompareDocuments, ExportComparison)
  - [x] 1.5 Configurar factory pattern para criação de engines
  - [x] 1.6 Implementar adapter pattern para uniformizar saídas de algoritmos
  - [x] 1.7 Configurar estrutura de testes unitários para camada de domínio

- [ ] 2.0 Implementar Otimizações de Performance
  - [x] 2.1 Criar Web Worker dedicado para operações de diff
  - [x] 2.2 Implementar sistema de cache LRU com limite de 100MB
  - [x] 2.3 Desenvolver sistema de chunking configurável para documentos >1MB
  - [x] 2.4 Implementar compressão de dados diff para reduzir uso de memória
  - [x] 2.5 Adicionar fallback para browsers sem suporte a Web Workers
  - [x] 2.6 Configurar debouncing para eventos de scroll (300ms)
  - [x] 2.7 Implementar testes de performance e benchmarks

- [ ] 3.0 Implementar Algoritmos Avançados de Comparação
  - [x] 3.1 Refatorar e otimizar DiffMatchPatchEngine existente
  - [x] 3.2 Implementar MyersDiffEngine como algoritmo alternativo
  - [x] 3.3 Desenvolver SemanticDiffEngine para análise semântica
  - [x] 3.4 Criar utilitários de pré-processamento e normalização de texto
  - [x] 3.5 Implementar tokenização inteligente para unidades semânticas
  - [x] 3.6 Desenvolver detecção de movimentação de blocos de texto
  - [x] 3.7 Implementar strategy pattern para seleção automática de algoritmo
  - [x] 3.8 Adicionar testes unitários para cada algoritmo

- [x] 4.0 Implementar Sistema de Visualização Avançada
  - [x] 4.1 Criar componente DiffSideBySide para visualização lado a lado
  - [x] 4.2 Implementar componente DiffInline para visualização inline
  - [x] 4.3 Desenvolver sistema de highlighting semântico por tipo de alteração
  - [x] 4.4 Criar componente de navegação entre alterações (DiffNavigation)
  - [x] 4.5 Implementar scrolling sincronizado entre painéis
  - [x] 4.7 Implementar collapse/expand de seções inalteradas
  - [x] 4.8 Criar painel de estatísticas (DiffStats) com métricas detalhadas
  - [x] 4.9 Adicionar controles de visualização (DiffControls)

- [ ] 5.0 Implementar Interface de Usuário e Integração
  - [x] 5.1 Criar componente FileUpload com drag & drop e validação
  - [x] 5.2 Desenvolver componente principal DiffViewer
  - [x] 5.3 Implementar hooks customizados (useDiffEngine, useDiffNavigation)
  - [ ] 5.4 Criar página de comparação (/compare) com layout responsivo
  - [ ] 5.5 Aplicar paleta de cores e estilos consistentes com login/registro
  - [ ] 5.6 Implementar barra de progresso durante processamento
  - [ ] 5.7 Integrar sistema de métricas e exportação
  - [x] 5.8 Adicionar tratamento de erros e estados de loading
  - [ ] 5.9 Configurar testes de integração end-to-end
  - [ ] 5.10 Realizar testes de usabilidade e ajustes finais 