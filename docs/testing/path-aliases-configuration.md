# TypeScript Path Aliases Configuration for Jest

## Overview

This document describes the comprehensive TypeScript path aliases configuration implemented for Jest testing in the ClauseDiff project. The configuration ensures consistent module resolution across both TypeScript compilation and Jest testing environments.

## Implemented Aliases

### Domain-Driven Design Layer Aliases

#### Specific Sublayer Aliases (Highest Priority)
- `@domain/entities/*` → `src/domain/entities/*`
- `@domain/repositories/*` → `src/domain/repositories/*`
- `@domain/services/*` → `src/domain/services/*`
- `@application/dto/*` → `src/application/dto/*`
- `@application/use-cases/*` → `src/application/use-cases/*`
- `@application/services/*` → `src/application/services/*`
- `@infrastructure/database/*` → `src/infrastructure/database/*`
- `@infrastructure/external-services/*` → `src/infrastructure/external-services/*`
- `@infrastructure/storage/*` → `src/infrastructure/storage/*`
- `@infrastructure/repositories/*` → `src/infrastructure/repositories/*`
- `@presentation/components/*` → `src/presentation/components/*`
- `@presentation/hooks/*` → `src/presentation/hooks/*`
- `@presentation/layouts/*` → `src/presentation/layouts/*`
- `@presentation/providers/*` → `src/presentation/providers/*`

#### General Layer Aliases (Medium Priority)
- `@domain/*` → `src/domain/*`
- `@application/*` → `src/application/*`
- `@infrastructure/*` → `src/infrastructure/*`
- `@presentation/*` → `src/presentation/*`

### Source Code Aliases

#### Specific Source Aliases
- `@components/*` → `src/components/*`
- `@lib/*` → `src/lib/*`
- `@hooks/*` → `src/hooks/*`
- `@utils/*` → `src/utils/*`
- `@services/*` → `src/services/*`

#### General Source Alias (Lowest Priority)
- `@/*` → `src/*`

### Test Utilities Aliases

- `@test-utils` → `test/utils/index`
- `@test-mocks/*` → `test/__mocks__/*`
- `@test/*` → `test/*`

## Configuration Files

### Jest Configuration (`jest.config.cjs`)

The Jest configuration includes a comprehensive `moduleNameMapper` section with all aliases ordered by specificity (most specific first):

```javascript
moduleNameMapper: {
  // Domain sublayer aliases (most specific first)
  '^@domain/entities/(.*)$': '<rootDir>/src/domain/entities/$1',
  '^@domain/repositories/(.*)$': '<rootDir>/src/domain/repositories/$1',
  // ... other specific aliases
  
  // Domain-Driven Design layer aliases (general)
  '^@domain/(.*)$': '<rootDir>/src/domain/$1',
  // ... other general aliases
  
  // General source alias (most general last)
  '^@/(.*)$': '<rootDir>/src/$1',
}
```

### TypeScript Configuration (`tsconfig.json`)

The TypeScript configuration includes matching path aliases in the same order:

```json
{
  "compilerOptions": {
    "baseUrl": ".",
    "paths": {
      // Domain sublayer aliases (most specific first)
      "@domain/entities/*": ["src/domain/entities/*"],
      "@domain/repositories/*": ["src/domain/repositories/*"],
      // ... other specific aliases
      
      // Domain-Driven Design layer aliases (general)
      "@domain/*": ["src/domain/*"],
      // ... other general aliases
      
      // General source alias (most general last)
      "@/*": ["src/*"]
    }
  }
}
```

## Alias Resolution Priority

The aliases are configured with careful attention to resolution priority:

1. **Most Specific First**: Sublayer aliases like `@domain/entities/*` are resolved before general layer aliases like `@domain/*`
2. **Layer-Specific**: Each DDD layer has both specific and general aliases
3. **General Last**: The most general alias `@/*` is placed last to avoid conflicts

## Testing

A comprehensive test suite (`test/unit/config/path-aliases.test.ts`) validates:

- ✅ Basic alias resolution for existing files
- ✅ Jest moduleNameMapper configuration completeness
- ✅ TypeScript path configuration matching
- ✅ Specific domain sublayer alias configuration
- ✅ Consistent alias ordering (specific before general)
- ✅ Test utility alias resolution

## Usage Examples

### Domain Layer Imports

```typescript
// Specific entity import
import { User } from '@domain/entities/User';

// Specific repository import
import { UserRepository } from '@domain/repositories/UserRepository';

// General domain import
import { SomeUtility } from '@domain/utils/SomeUtility';
```

### Application Layer Imports

```typescript
// Specific DTO import
import { CreateUserDto } from '@application/dto/CreateUserDto';

// Specific use case import
import { CreateUserUseCase } from '@application/use-cases/CreateUserUseCase';

// General application import
import { SomeService } from '@application/SomeService';
```

### Test Imports

```typescript
// Test utilities
import { renderWithProviders, renderWithAuth } from '@test-utils';

// Test mocks
import { mockSignIn } from '@test-mocks/nextauth';

// General test files
import { someTestHelper } from '@test/helpers/someTestHelper';
```

## Benefits

1. **Clean Imports**: No more relative path imports like `../../../domain/entities/User`
2. **Consistent Resolution**: Same aliases work in both TypeScript and Jest
3. **DDD Support**: Specific aliases for each domain layer and sublayer
4. **Maintainable**: Easy to refactor and reorganize code
5. **IDE Support**: Full IntelliSense and auto-completion support
6. **Test-Friendly**: Dedicated aliases for test utilities and mocks

## Maintenance

When adding new directories or reorganizing the codebase:

1. Update both `jest.config.cjs` and `tsconfig.json`
2. Maintain the specificity order (specific before general)
3. Add corresponding test cases to verify the new aliases
4. Update this documentation

## Related Files

- `jest.config.cjs` - Jest configuration with moduleNameMapper
- `tsconfig.json` - TypeScript configuration with path aliases
- `test/unit/config/path-aliases.test.ts` - Test suite for alias validation
- `test/utils/index.ts` - Test utilities accessible via `@test-utils` 