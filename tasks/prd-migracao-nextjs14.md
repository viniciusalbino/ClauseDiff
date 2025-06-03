# PRD – Migração ClauseDiff para Next.js 14 com App Router, DDD e Clean Architecture

## 1. Introdução/Overview
O objetivo deste projeto é migrar o ClauseDiff para Next.js 14, adotando o App Router e uma arquitetura avançada baseada em Domain-Driven Design (DDD) e Clean Architecture. A migração será incremental, garantindo que as funcionalidades atuais continuem funcionando durante o processo. O resultado esperado é uma base de código moderna, escalável, testável e preparada para internacionalização, acessibilidade e compliance.

## 2. Goals (Objetivos)
- Migrar a aplicação para Next.js 14 com App Router.
- Implementar estrutura de diretórios baseada em DDD e Clean Architecture.
- Garantir funcionamento contínuo das funcionalidades atuais durante a migração.
- Adotar padrões de código, testes e automação modernos.
- Preparar a base para autenticação, internacionalização (pt, es, en) e acessibilidade (WCAG).
- Alcançar 90% de cobertura de testes unitários.
- Documentar e automatizar todo o processo de build, lint, testes e deploy no Netlify.

## 3. User Stories
- **Como desenvolvedor**, quero uma estrutura de projeto clara e modular, para facilitar manutenção e evolução.
- **Como usuário**, quero acessar todas as funcionalidades atuais sem interrupção durante a migração.
- **Como gestor**, quero garantir que a aplicação esteja pronta para autenticação, internacionalização e compliance.
- **Como desenvolvedor**, quero que o código siga padrões de qualidade, testes e automação.

## 4. Functional Requirements
1. O sistema deve ser migrado para Next.js 14 com App Router.
2. A estrutura de diretórios deve seguir DDD e Clean Architecture conforme especificado.
3. A migração deve ser incremental, sem quebrar funcionalidades existentes.
4. O projeto deve conter configuração de ESLint, Prettier, Husky, Jest e Testing Library.
5. O sistema deve estar preparado para internacionalização (pt, es, en) e acessibilidade (WCAG).
6. O deploy deve ser automatizado no Netlify, com build, lint e testes.
7. O código deve manter 90% de cobertura de testes unitários.
8. O padrão CQRS deve ser implementado para operações de leitura/escrita.
9. O estado deve ser gerenciado com Context API, React Query e Zustand conforme o escopo.
10. O projeto deve conter exemplos de Server e Client Components, e migração de hooks como useEffect.

## 5. Non-Goals (Out of Scope)
- Implementação de autenticação (apenas preparação da estrutura).
- Novas funcionalidades além das já existentes (exceto ajustes para arquitetura).
- Migração de deploy para Vercel ou outras plataformas.
- Integração com sistemas externos não mencionados.
- Design system ou UI library customizada (a menos que especificado depois).

## 6. Design Considerations
- Estrutura de diretórios conforme solicitado (DDD + Clean Architecture).
- Componentização seguindo Atomic Design em `/ui`.
- Internacionalização com suporte a pt, es, en (ex: next-intl ou i18next).
- Acessibilidade: seguir WCAG em todos os componentes e páginas.
- Server Components para páginas e layouts, Client Components para interatividade.
- Separação clara entre domínio, aplicação, infraestrutura e apresentação.

## 7. Technical Considerations
- next.config.mjs otimizado para performance e internacionalização.
- tsconfig.json com strict mode e path aliases.
- ESLint configurado para enforcing de Clean Architecture.
- Prettier com regras padronizadas.
- Husky para pre-commit hooks (lint, test, format).
- Jest e Testing Library configurados para testes unitários.
- Netlify como plataforma de deploy (sem mudanças).
- CQRS implementado nos use-cases.
- Estado: Context API (local), React Query (server), Zustand (global complexo).
- Migração incremental: manter código legado funcional até a conclusão.

## 8. Success Metrics
- 100% das funcionalidades atuais migradas e funcionando em Next.js 14.
- Estrutura de diretórios e código aderente a DDD e Clean Architecture.
- 90%+ de cobertura de testes unitários.
- Deploy automatizado e funcional no Netlify.
- Pronto para internacionalização (pt, es, en) e acessibilidade (WCAG).
- Documentação clara para onboarding de novos devs.

## 9. Open Questions
- Alguma preferência por biblioteca de internacionalização? (ex: next-intl, i18next)
- Alguma restrição quanto ao uso de Server Actions do Next.js?
- Algum fluxo de autenticação preferido para futura implementação?
- Alguma integração futura prevista (ex: analytics, pagamentos, etc.)?

## Estrutura de Diretórios (DDD + Clean Architecture)

```plaintext
/app
  /api
  /auth/[...nextauth]/route.ts
  /contracts/route.ts
  /analysis/route.ts
  /(auth)
    /login/page.tsx
    /register/page.tsx
  /(dashboard)
    /page.tsx
    /contracts/page.tsx
    /analysis/[id]/page.tsx
    /comparison/[id]/page.tsx
/src
  /domain
    /entities
    /value-objects
    /repositories (interfaces)
    /services (interfaces)
  /application
    /use-cases
    /dto
    /services (implementations)
  /infrastructure
    /repositories (implementations)
    /external-services
    /database
    /storage
  /presentation
    /components
    /ui (atomic design)
    /forms
    /layouts
    /hooks
    /providers
    /utils
```

## Estratégia de Migração Incremental

### Fase 1: Setup Inicial Next.js (Tempo: 3 min)
- Criar novo projeto Next.js 14 com App Router.
- Copiar código atual para `/src/legacy` e manter funcionando.
- Configurar ESLint, Prettier, Husky, Jest, Testing Library.
- Configurar Netlify para build e deploy.
- Garantir que o app legacy funcione como fallback.

### Fase 2: Refatoração para Clean Architecture (Tempo: 8 min)
- Migrar gradualmente módulos do legacy para a nova estrutura DDD.
- Implementar domínio, use-cases, infraestrutura e apresentação.
- Refatorar componentes para Server/Client conforme necessidade.
- Implementar internacionalização e acessibilidade.
- Garantir cobertura de testes unitários (90%+).
- Adotar CQRS nos use-cases.

### Fase 3: Novas Funcionalidades e Otimizações (Tempo: 4 min)
- Preparar estrutura para autenticação (sem implementar).
- Otimizar performance, lazy loading, code splitting.
- Documentar arquitetura, padrões e processos.
- Validar deploy, testes e cobertura.

#### Dependências
- Node.js 18+, Next.js 14, React 18+, Netlify CLI, Jest, Testing Library, ESLint, Prettier, Husky, Zustand, React Query, next-intl/i18next.

## Configuração Técnica Detalhada

### next.config.mjs

```js
/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  swcMinify: true,
  experimental: {
    appDir: true,
    serverActions: true,
  },
  i18n: {
    locales: ['pt', 'es', 'en'],
    defaultLocale: 'pt',
  },
  images: {
    domains: ['localhost', 'your-cdn.com'],
  },
};

export default nextConfig;
```

### tsconfig.json

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "lib": ["dom", "dom.iterable", "esnext"],
    "allowJs": false,
    "skipLibCheck": true,
    "strict": true,
    "forceConsistentCasingInFileNames": true,
    "noEmit": true,
    "esModuleInterop": true,
    "module": "esnext",
    "moduleResolution": "bundler",
    "resolveJsonModule": true,
    "isolatedModules": true,
    "jsx": "preserve",
    "baseUrl": ".",
    "paths": {
      "@domain/*": ["src/domain/*"],
      "@application/*": ["src/application/*"],
      "@infrastructure/*": ["src/infrastructure/*"],
      "@presentation/*": ["src/presentation/*"]
    }
  },
  "include": ["next-env.d.ts", "**/*.ts", "**/*.tsx"],
  "exclude": ["node_modules"]
}
```

### .eslintrc.js

```js
module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  plugins: ['@typescript-eslint', 'react', 'import'],
  extends: [
    'next/core-web-vitals',
    'plugin:@typescript-eslint/recommended',
    'plugin:import/recommended',
    'plugin:import/typescript',
    'prettier'
  ],
  rules: {
    '@typescript-eslint/no-explicit-any': 'error',
    'import/order': [
      'error',
      {
        'groups': [['builtin', 'external'], 'internal', ['parent', 'sibling', 'index']],
        'newlines-between': 'always'
      }
    ],
    'no-restricted-imports': [
      'error',
      {
        'patterns': ['../*', './*']
      }
    ]
  }
};
```

### jest.config.js

```js
module.exports = {
  testEnvironment: 'jsdom',
  setupFilesAfterEnv: ['<rootDir>/jest.setup.js'],
  moduleNameMapper: {
    '^@domain/(.*)$': '<rootDir>/src/domain/$1',
    '^@application/(.*)$': '<rootDir>/src/application/$1',
    '^@infrastructure/(.*)$': '<rootDir>/src/infrastructure/$1',
    '^@presentation/(.*)$': '<rootDir>/src/presentation/$1'
  },
  testPathIgnorePatterns: ['/node_modules/', '/.next/'],
  collectCoverage: true,
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov'],
  collectCoverageFrom: [
    'src/**/*.{ts,tsx}',
    '!src/**/*.d.ts'
  ]
};
```

### Exemplo de Migração: FileUpload.tsx

**Antes (React tradicional):**
```tsx
// src/components/FileUpload.tsx
import React from 'react';

export function FileUpload({ onUpload }) {
  return (
    <input
      type="file"
      accept=".docx,.pdf,.txt"
      onChange={e => onUpload(e.target.files[0])}
    />
  );
}
```

**Depois (Next.js 14, Client Component, Clean Architecture):**
```tsx
// src/presentation/components/FileUpload.tsx
'use client';

import { useRef } from 'react';
import { useUploadFile } from '@application/use-cases/useUploadFile';

export function FileUpload({ onSuccess }: { onSuccess: (file: File) => void }) {
  const inputRef = useRef<HTMLInputElement>(null);
  const { uploadFile } = useUploadFile();

  const handleChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      await uploadFile(file);
      onSuccess(file);
    }
  };

  return (
    <input
      ref={inputRef}
      type="file"
      accept=".docx,.pdf,.txt"
      onChange={handleChange}
      aria-label="Upload file"
    />
  );
}
```

### Exemplo de Use-Case (Clean Architecture)

```ts
// src/application/use-cases/uploadFile.ts
import { FileRepository } from '@domain/repositories/FileRepository';

export class UploadFileUseCase {
  constructor(private fileRepo: FileRepository) {}

  async execute(file: File): Promise<void> {
    // Validação, regras de negócio, etc.
    await this.fileRepo.save(file);
  }
}

// src/application/use-cases/useUploadFile.ts (hook para Client Component)
import { UploadFileUseCase } from './uploadFile';
import { useCallback } from 'react';
import { useFileRepository } from '@infrastructure/repositories/useFileRepository';

export function useUploadFile() {
  const fileRepo = useFileRepository();
  const uploadFile = useCallback(
    (file: File) => new UploadFileUseCase(fileRepo).execute(file),
    [fileRepo]
  );
  return { uploadFile };
}
``` 