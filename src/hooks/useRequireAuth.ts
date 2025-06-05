import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "./useAuth";

export interface UseRequireAuthOptions {
  redirectTo?: string;
  redirectIfFound?: boolean;
}

export interface UseRequireAuthReturn {
  isLoading: boolean;
  isAuthenticated: boolean;
  user: any;
}

/**
 * Hook to require authentication for a page/component.
 * Redirects to login page if user is not authenticated.
 * 
 * @param options Configuration options
 * @returns Authentication state
 */
export function useRequireAuth(options: UseRequireAuthOptions = {}): UseRequireAuthReturn {
  const { 
    redirectTo = "/login", 
    redirectIfFound = false 
  } = options;
  
  const { user, isLoading, isAuthenticated } = useAuth();
  const router = useRouter();

  useEffect(() => {
    // Don't redirect while loading
    if (isLoading) return;

    // Redirect logic
    if (redirectIfFound) {
      // Redirect authenticated users away (useful for login/register pages)
      if (isAuthenticated) {
        router.push(redirectTo);
      }
    } else {
      // Redirect unauthenticated users to login (default behavior)
      if (!isAuthenticated) {
        // Preserve the current URL to redirect back after login
        const currentPath = window.location.pathname + window.location.search;
        const loginUrl = `/login?callbackUrl=${encodeURIComponent(currentPath)}`;
        router.push(loginUrl);
      }
    }
  }, [isLoading, isAuthenticated, redirectTo, redirectIfFound, router]);

  return {
    isLoading,
    isAuthenticated,
    user,
  };
}

/**
 * Utility function to create a protected component.
 * This should be implemented in a .tsx file where JSX is supported.
 * For now, we export the type definition for reference.
 */
export type WithRequireAuthOptions = UseRequireAuthOptions;

// Note: The HOC implementation should be moved to a .tsx file
// due to JSX syntax requirements. For now, use the useRequireAuth hook directly. 