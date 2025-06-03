/**
 * AuthProvider skeleton for future authentication context (Clean Architecture).
 *
 * This provider will wrap the app and provide authentication state and actions.
 * No logic implemented yet.
 */
'use client';
import { createContext, ReactNode } from 'react';

// Define the AuthContext type (to be expanded in the future)
export const AuthContext = createContext(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  // TODO: Implement authentication state and actions here
  return (
    <AuthContext.Provider value={undefined}>
      {children}
    </AuthContext.Provider>
  );
} 