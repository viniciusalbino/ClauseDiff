import { describe, it, expect } from '@jest/globals';

describe('Path Aliases Configuration', () => {
  it('should resolve @/ aliases correctly', async () => {
    // Test general source alias
    const { cn } = await import('@/lib/utils');
    expect(typeof cn).toBe('function');
  });

  it('should resolve @lib/ aliases correctly', async () => {
    // Test lib-specific alias
    const { cn } = await import('@lib/utils');
    expect(typeof cn).toBe('function');
  });

  it('should resolve @components/ aliases correctly', async () => {
    // Test component alias
    const { LoadingSpinner } = await import('@components/LoadingSpinner');
    expect(LoadingSpinner).toBeDefined();
  });

  // Test for alias resolution without importing (to avoid hooks issue)
  it('should resolve test utility aliases correctly', () => {
    // Use require.resolve to test if the path is correctly resolved
    expect(() => {
      require.resolve('@test/utils');
    }).not.toThrow();
  });

  it('should resolve test mocks aliases correctly', () => {
    // Test if mock paths resolve correctly
    expect(() => {
      require.resolve('@test-mocks/nextauth');
    }).not.toThrow();
  });

  // Test that Jest moduleNameMapper is configured correctly
  it('should have Jest moduleNameMapper configuration for all domain layers', () => {
    // This test verifies that Jest configuration includes all necessary aliases
    const fs = require('fs');
    const path = require('path');
    
    // Read Jest config to verify aliases are present
    const jestConfigPath = path.join(process.cwd(), 'jest.config.cjs');
    const jestConfigContent = fs.readFileSync(jestConfigPath, 'utf8');
    
    // Verify key aliases are present in the configuration
    expect(jestConfigContent).toContain('@domain/');
    expect(jestConfigContent).toContain('@application/');
    expect(jestConfigContent).toContain('@infrastructure/');
    expect(jestConfigContent).toContain('@presentation/');
    expect(jestConfigContent).toContain('@components/');
    expect(jestConfigContent).toContain('@lib/');
    expect(jestConfigContent).toContain('@hooks/');
    expect(jestConfigContent).toContain('@utils/');
    expect(jestConfigContent).toContain('@services/');
    expect(jestConfigContent).toContain('@test/');
    expect(jestConfigContent).toContain('@test-utils');
    expect(jestConfigContent).toContain('@test-mocks/');
  });

  it('should have TypeScript path configuration matching Jest aliases', () => {
    // Verify that TypeScript configuration includes matching aliases
    const fs = require('fs');
    const path = require('path');
    
    const tsConfigPath = path.join(process.cwd(), 'tsconfig.json');
    const tsConfigContent = fs.readFileSync(tsConfigPath, 'utf8');
    
    // Verify key TypeScript path aliases are present
    expect(tsConfigContent).toContain('"@/*"');
    expect(tsConfigContent).toContain('"@domain/*"');
    expect(tsConfigContent).toContain('"@application/*"');
    expect(tsConfigContent).toContain('"@infrastructure/*"');
    expect(tsConfigContent).toContain('"@presentation/*"');
    expect(tsConfigContent).toContain('"@components/*"');
    expect(tsConfigContent).toContain('"@lib/*"');
    expect(tsConfigContent).toContain('"@hooks/*"');
    expect(tsConfigContent).toContain('"@utils/*"');
    expect(tsConfigContent).toContain('"@services/*"');
    expect(tsConfigContent).toContain('"@test/*"');
    expect(tsConfigContent).toContain('"@test-utils"');
    expect(tsConfigContent).toContain('"@test-mocks/*"');
  });

  it('should resolve specific domain sublayer paths correctly', () => {
    // Test that specific sublayer aliases are configured
    const fs = require('fs');
    const path = require('path');
    
    const jestConfigPath = path.join(process.cwd(), 'jest.config.cjs');
    const jestConfigContent = fs.readFileSync(jestConfigPath, 'utf8');
    
    // Check for specific domain sublayer aliases
    expect(jestConfigContent).toContain('@domain/entities/');
    expect(jestConfigContent).toContain('@domain/repositories/');
    expect(jestConfigContent).toContain('@domain/services/');
    expect(jestConfigContent).toContain('@application/dto/');
    expect(jestConfigContent).toContain('@application/use-cases/');
    expect(jestConfigContent).toContain('@application/services/');
    expect(jestConfigContent).toContain('@infrastructure/database/');
    expect(jestConfigContent).toContain('@infrastructure/external-services/');
    expect(jestConfigContent).toContain('@infrastructure/storage/');
    expect(jestConfigContent).toContain('@infrastructure/repositories/');
    expect(jestConfigContent).toContain('@presentation/components/');
    expect(jestConfigContent).toContain('@presentation/hooks/');
    expect(jestConfigContent).toContain('@presentation/layouts/');
    expect(jestConfigContent).toContain('@presentation/providers/');
  });

  it('should have consistent alias ordering in Jest configuration', () => {
    // Verify that more specific aliases come before more general ones
    const fs = require('fs');
    const path = require('path');
    
    const jestConfigPath = path.join(process.cwd(), 'jest.config.cjs');
    const jestConfigContent = fs.readFileSync(jestConfigPath, 'utf8');
    
    // Extract moduleNameMapper section
    const moduleNameMapperMatch = jestConfigContent.match(/moduleNameMapper:\s*{([^}]+)}/s);
    expect(moduleNameMapperMatch).toBeTruthy();
    
    if (moduleNameMapperMatch) {
      const mapperContent = moduleNameMapperMatch[1];
      
      // More specific aliases should come before general ones to avoid conflicts
      // Look for the specific pattern vs the general pattern
      const domainEntitiesIndex = mapperContent.indexOf("'^@domain/entities/(.*)$'");
      const domainGeneralIndex = mapperContent.indexOf("'^@domain/(.*)$'");
      
      if (domainEntitiesIndex !== -1 && domainGeneralIndex !== -1) {
        // If both exist, specific should come before general (lower index)
        expect(domainEntitiesIndex).toBeLessThan(domainGeneralIndex);
      }
      
      // Also test application layer
      const appDtoIndex = mapperContent.indexOf("'^@application/dto/(.*)$'");
      const appGeneralIndex = mapperContent.indexOf("'^@application/(.*)$'");
      
      if (appDtoIndex !== -1 && appGeneralIndex !== -1) {
        expect(appDtoIndex).toBeLessThan(appGeneralIndex);
      }
      
      // Test that general @/ comes last
      const generalSourceIndex = mapperContent.indexOf("'^@/(.*)$'");
      const specificComponentIndex = mapperContent.indexOf("'^@components/(.*)$'");
      
      if (generalSourceIndex !== -1 && specificComponentIndex !== -1) {
        expect(specificComponentIndex).toBeLessThan(generalSourceIndex);
      }
    }
  });
}); 