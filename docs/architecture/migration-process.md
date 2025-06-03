# Processo de Migração Incremental e Fallback – ClauseDiff

## Visão Geral
A migração do ClauseDiff para Next.js 14 foi planejada para ser incremental, garantindo que as funcionalidades existentes continuem funcionando durante todo o processo. O código legado é mantido como fallback até a conclusão total da migração.

## Estratégia de Migração
- **Fase 1:** Setup inicial do projeto Next.js 14, configuração de ferramentas e cópia do código legado para `/src/legacy`.
- **Fase 2:** Refatoração gradual dos módulos do legado para a nova estrutura DDD + Clean Architecture.
- **Fase 3:** Otimizações, preparação para autenticação e integrações futuras.

## Fallback do Código Legado
- O diretório `/src/legacy` contém o código original, preservando todas as funcionalidades.
- Durante a migração, rotas e componentes podem delegar para o código legado caso a funcionalidade ainda não tenha sido migrada.
- Feature flags ou checagens condicionais podem ser usadas para alternar entre novo e legado.

## Identificação de Código Migrado vs. Legado
- **Migrado:** Localizado em `src/domain/`, `src/application/`, `src/infrastructure/`, `src/presentation/`.
- **Legado:** Localizado em `src/legacy/`.
- Componentes e módulos migrados devem ser removidos do legado após validação.

## Remoção Segura do Legado
- Após migrar e validar todas as funcionalidades, o diretório `/src/legacy` pode ser removido.
- Recomenda-se rodar testes completos e validação manual antes da remoção final.

## Convenções e Comandos
- Use feature flags ou variáveis de ambiente para alternar entre implementações, se necessário.
- Testes devem cobrir tanto o novo quanto o legado durante a transição.

## Referências
- [PRD de Migração](../../tasks/prd-migracao-nextjs14.md)
- [Visão Geral da Arquitetura](./overview.md) 