/**
 * Custom Jest Matchers
 * 
 * Provides custom Jest matchers for enhanced test assertions
 * with better error messages and domain-specific testing patterns.
 */

import { expect } from '@jest/globals';

// Extend Jest matchers interface
declare global {
  namespace jest {
    interface Matchers<R> {
      // Authentication matchers
      toBeAuthenticated(): R;
      toHaveRole(expectedRole: string): R;
      toHavePermission(permission: string): R;
      toHaveAnyPermission(permissions: string[]): R;
      toHaveAllPermissions(permissions: string[]): R;
      
      // Error matchers
      toThrowWithMessage(expectedMessage: string | RegExp): R;
      toRejectWithMessage(expectedMessage: string | RegExp): Promise<R>;
      
      // DOM matchers
      toBeVisibleOnScreen(): R;
      toHaveExactText(text: string): R;
      toBeLoading(): R;
      toBeError(): R;
      
      // Array/Object matchers
      toContainObject(expectedObject: any): R;
      toBeArrayOfLength(expectedLength: number): R;
      toHaveProperty(property: string, value?: any): R;
      
      // Async matchers
      toResolveWithin(timeout: number): Promise<R>;
      toRejectWithin(timeout: number): Promise<R>;
      
      // Time matchers
      toBeWithinTimeRange(startTime: Date, endTime: Date): R;
      toBeBefore(otherDate: Date): R;
      toBeAfter(otherDate: Date): R;
      
      // Custom business logic matchers
      toBeValidEmail(): R;
      toBeValidUrl(): R;
      toMatchApiResponse(expectedSchema: any): R;
    }
  }
}

/**
 * Authentication matchers
 */
const authenticationMatchers = {
  toBeAuthenticated(received: any) {
    const pass = received && received.user && received.user.id && received.user.email;
    
    if (pass) {
      return {
        message: () => `Expected session not to be authenticated`,
        pass: true,
      };
    } else {
      return {
        message: () => `Expected session to be authenticated but got: ${JSON.stringify(received)}`,
        pass: false,
      };
    }
  },

  toHaveRole(received: any, expectedRole: string) {
    const actualRole = received?.user?.role;
    const pass = actualRole === expectedRole;
    
    if (pass) {
      return {
        message: () => `Expected user not to have role "${expectedRole}"`,
        pass: true,
      };
    } else {
      return {
        message: () => `Expected user to have role "${expectedRole}" but got "${actualRole}"`,
        pass: false,
      };
    }
  },

  toHavePermission(received: any, permission: string) {
    const permissions = received?.user?.permissions || [];
    const pass = permissions.includes(permission);
    
    if (pass) {
      return {
        message: () => `Expected user not to have permission "${permission}"`,
        pass: true,
      };
    } else {
      return {
        message: () => `Expected user to have permission "${permission}" but got permissions: [${permissions.join(', ')}]`,
        pass: false,
      };
    }
  },

  toHaveAnyPermission(received: any, expectedPermissions: string[]) {
    const permissions = received?.user?.permissions || [];
    const hasAny = expectedPermissions.some(permission => permissions.includes(permission));
    
    if (hasAny) {
      return {
        message: () => `Expected user not to have any of these permissions: [${expectedPermissions.join(', ')}]`,
        pass: true,
      };
    } else {
      return {
        message: () => `Expected user to have at least one of these permissions: [${expectedPermissions.join(', ')}] but got: [${permissions.join(', ')}]`,
        pass: false,
      };
    }
  },

  toHaveAllPermissions(received: any, expectedPermissions: string[]) {
    const permissions = received?.user?.permissions || [];
    const hasAll = expectedPermissions.every(permission => permissions.includes(permission));
    
    if (hasAll) {
      return {
        message: () => `Expected user not to have all of these permissions: [${expectedPermissions.join(', ')}]`,
        pass: true,
      };
    } else {
      const missing = expectedPermissions.filter(permission => !permissions.includes(permission));
      return {
        message: () => `Expected user to have all permissions: [${expectedPermissions.join(', ')}] but missing: [${missing.join(', ')}]`,
        pass: false,
      };
    }
  }
};

/**
 * Error matchers
 */
const errorMatchers = {
  toThrowWithMessage(received: () => any, expectedMessage: string | RegExp) {
    let thrownError: Error | null = null;
    
    try {
      received();
    } catch (error) {
      thrownError = error as Error;
    }
    
    if (!thrownError) {
      return {
        message: () => `Expected function to throw an error`,
        pass: false,
      };
    }
    
    const messageMatches = typeof expectedMessage === 'string'
      ? thrownError.message.includes(expectedMessage)
      : expectedMessage.test(thrownError.message);
    
    if (messageMatches) {
      return {
        message: () => `Expected function not to throw error with message matching "${expectedMessage}"`,
        pass: true,
      };
    } else {
      return {
        message: () => `Expected error message to match "${expectedMessage}" but got "${thrownError.message}"`,
        pass: false,
      };
    }
  },

  async toRejectWithMessage(received: Promise<any>, expectedMessage: string | RegExp) {
    let rejectionError: Error | null = null;
    
    try {
      await received;
    } catch (error) {
      rejectionError = error as Error;
    }
    
    if (!rejectionError) {
      return {
        message: () => `Expected promise to reject`,
        pass: false,
      };
    }
    
    const messageMatches = typeof expectedMessage === 'string'
      ? rejectionError.message.includes(expectedMessage)
      : expectedMessage.test(rejectionError.message);
    
    if (messageMatches) {
      return {
        message: () => `Expected promise not to reject with message matching "${expectedMessage}"`,
        pass: true,
      };
    } else {
      return {
        message: () => `Expected rejection message to match "${expectedMessage}" but got "${rejectionError.message}"`,
        pass: false,
      };
    }
  }
};

/**
 * DOM matchers
 */
const domMatchers = {
  toBeVisibleOnScreen(received: HTMLElement) {
    const isVisible = received.offsetWidth > 0 && received.offsetHeight > 0;
    const style = window.getComputedStyle(received);
    const isDisplayed = style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0';
    const pass = isVisible && isDisplayed;
    
    if (pass) {
      return {
        message: () => `Expected element not to be visible on screen`,
        pass: true,
      };
    } else {
      return {
        message: () => `Expected element to be visible on screen but it's hidden (display: ${style.display}, visibility: ${style.visibility}, opacity: ${style.opacity})`,
        pass: false,
      };
    }
  },

  toHaveExactText(received: HTMLElement, text: string) {
    const actualText = received.textContent?.trim();
    const pass = actualText === text;
    
    if (pass) {
      return {
        message: () => `Expected element not to have exact text "${text}"`,
        pass: true,
      };
    } else {
      return {
        message: () => `Expected element to have exact text "${text}" but got "${actualText}"`,
        pass: false,
      };
    }
  },

  toBeLoading(received: HTMLElement) {
    const hasLoadingClass = received.classList.contains('loading') || received.classList.contains('spinner');
    const hasLoadingRole = received.getAttribute('role') === 'status' || received.getAttribute('aria-busy') === 'true';
    const hasLoadingTestId = received.getAttribute('data-testid')?.includes('loading');
    const pass = hasLoadingClass || hasLoadingRole || hasLoadingTestId;
    
    if (pass) {
      return {
        message: () => `Expected element not to be in loading state`,
        pass: true,
      };
    } else {
      return {
        message: () => `Expected element to be in loading state but it's not`,
        pass: false,
      };
    }
  },

  toBeError(received: HTMLElement) {
    const hasErrorClass = received.classList.contains('error') || received.classList.contains('danger');
    const hasErrorRole = received.getAttribute('role') === 'alert';
    const hasErrorTestId = received.getAttribute('data-testid')?.includes('error');
    const pass = hasErrorClass || hasErrorRole || hasErrorTestId;
    
    if (pass) {
      return {
        message: () => `Expected element not to be in error state`,
        pass: true,
      };
    } else {
      return {
        message: () => `Expected element to be in error state but it's not`,
        pass: false,
      };
    }
  }
};

/**
 * Array/Object matchers
 */
const arrayObjectMatchers = {
  toContainObject(received: any[], expectedObject: any) {
    const pass = received.some(item => 
      Object.keys(expectedObject).every(key => item[key] === expectedObject[key])
    );
    
    if (pass) {
      return {
        message: () => `Expected array not to contain object ${JSON.stringify(expectedObject)}`,
        pass: true,
      };
    } else {
      return {
        message: () => `Expected array to contain object ${JSON.stringify(expectedObject)} but it doesn't`,
        pass: false,
      };
    }
  },

  toBeArrayOfLength(received: any[], expectedLength: number) {
    const pass = Array.isArray(received) && received.length === expectedLength;
    
    if (pass) {
      return {
        message: () => `Expected array not to have length ${expectedLength}`,
        pass: true,
      };
    } else {
      return {
        message: () => `Expected array to have length ${expectedLength} but got ${Array.isArray(received) ? received.length : 'not an array'}`,
        pass: false,
      };
    }
  }
};

/**
 * Async matchers
 */
const asyncMatchers = {
  async toResolveWithin(received: Promise<any>, timeout: number) {
    const startTime = Date.now();
    let resolved = false;
    
    try {
      await Promise.race([
        received.then(() => { resolved = true; }),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), timeout))
      ]);
    } catch (error) {
      if ((error as Error).message === 'Timeout') {
        return {
          message: () => `Expected promise to resolve within ${timeout}ms`,
          pass: false,
        };
      }
      throw error;
    }
    
    const actualTime = Date.now() - startTime;
    
    if (resolved) {
      return {
        message: () => `Expected promise not to resolve within ${timeout}ms but it resolved in ${actualTime}ms`,
        pass: true,
      };
    } else {
      return {
        message: () => `Expected promise to resolve within ${timeout}ms but it didn't`,
        pass: false,
      };
    }
  },

  async toRejectWithin(received: Promise<any>, timeout: number) {
    const startTime = Date.now();
    let rejected = false;
    
    try {
      await Promise.race([
        received.catch(() => { rejected = true; }),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), timeout))
      ]);
    } catch (error) {
      if ((error as Error).message === 'Timeout') {
        return {
          message: () => `Expected promise to reject within ${timeout}ms`,
          pass: false,
        };
      }
    }
    
    const actualTime = Date.now() - startTime;
    
    if (rejected) {
      return {
        message: () => `Expected promise not to reject within ${timeout}ms but it rejected in ${actualTime}ms`,
        pass: true,
      };
    } else {
      return {
        message: () => `Expected promise to reject within ${timeout}ms but it didn't`,
        pass: false,
      };
    }
  }
};

/**
 * Time matchers
 */
const timeMatchers = {
  toBeWithinTimeRange(received: Date, startTime: Date, endTime: Date) {
    const pass = received >= startTime && received <= endTime;
    
    if (pass) {
      return {
        message: () => `Expected date not to be within range ${startTime.toISOString()} - ${endTime.toISOString()}`,
        pass: true,
      };
    } else {
      return {
        message: () => `Expected date ${received.toISOString()} to be within range ${startTime.toISOString()} - ${endTime.toISOString()}`,
        pass: false,
      };
    }
  },

  toBeBefore(received: Date, otherDate: Date) {
    const pass = received < otherDate;
    
    if (pass) {
      return {
        message: () => `Expected ${received.toISOString()} not to be before ${otherDate.toISOString()}`,
        pass: true,
      };
    } else {
      return {
        message: () => `Expected ${received.toISOString()} to be before ${otherDate.toISOString()}`,
        pass: false,
      };
    }
  },

  toBeAfter(received: Date, otherDate: Date) {
    const pass = received > otherDate;
    
    if (pass) {
      return {
        message: () => `Expected ${received.toISOString()} not to be after ${otherDate.toISOString()}`,
        pass: true,
      };
    } else {
      return {
        message: () => `Expected ${received.toISOString()} to be after ${otherDate.toISOString()}`,
        pass: false,
      };
    }
  }
};

/**
 * Business logic matchers
 */
const businessLogicMatchers = {
  toBeValidEmail(received: string) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const pass = emailRegex.test(received);
    
    if (pass) {
      return {
        message: () => `Expected "${received}" not to be a valid email`,
        pass: true,
      };
    } else {
      return {
        message: () => `Expected "${received}" to be a valid email format`,
        pass: false,
      };
    }
  },

  toBeValidUrl(received: string) {
    try {
      new URL(received);
      return {
        message: () => `Expected "${received}" not to be a valid URL`,
        pass: true,
      };
    } catch {
      return {
        message: () => `Expected "${received}" to be a valid URL format`,
        pass: false,
      };
    }
  },

  toMatchApiResponse(received: any, expectedSchema: any) {
    const validateSchema = (obj: any, schema: any): boolean => {
      if (typeof schema === 'string') {
        return typeof obj === schema;
      }
      
      if (Array.isArray(schema)) {
        return Array.isArray(obj) && obj.every(item => validateSchema(item, schema[0]));
      }
      
      if (typeof schema === 'object' && schema !== null) {
        return typeof obj === 'object' && obj !== null &&
          Object.keys(schema).every(key => validateSchema(obj[key], schema[key]));
      }
      
      return obj === schema;
    };
    
    const pass = validateSchema(received, expectedSchema);
    
    if (pass) {
      return {
        message: () => `Expected response not to match API schema`,
        pass: true,
      };
    } else {
      return {
        message: () => `Expected response to match API schema but it doesn't. Got: ${JSON.stringify(received)}`,
        pass: false,
      };
    }
  }
};

/**
 * Setup all custom matchers
 */
export function setupCustomMatchers(): void {
  expect.extend({
    ...authenticationMatchers,
    ...errorMatchers,
    ...domMatchers,
    ...arrayObjectMatchers,
    ...asyncMatchers,
    ...timeMatchers,
    ...businessLogicMatchers
  });
}

/**
 * Export all matchers for individual use
 */
export {
  authenticationMatchers,
  errorMatchers,
  domMatchers,
  arrayObjectMatchers,
  asyncMatchers,
  timeMatchers,
  businessLogicMatchers
};

export default setupCustomMatchers; 