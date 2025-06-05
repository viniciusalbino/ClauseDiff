import { NextRequest, NextResponse } from 'next/server';
import { getToken } from 'next-auth/jwt';

// Security configuration
const SECURITY_CONFIG = {
  // CSRF Protection
  csrf: {
    enabled: true,
    cookieName: '__Host-csrf-token',
    headerName: 'x-csrf-token',
    sameSite: 'strict' as const,
    secure: true,
    httpOnly: false, // Needs to be accessible to client for form submissions
  },
  
  // Rate limiting configuration
  rateLimit: {
    enabled: true,
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 100, // limit each IP to 100 requests per windowMs
    authWindowMs: 5 * 60 * 1000, // 5 minutes for auth endpoints
    authMaxRequests: 10, // stricter for auth endpoints
    // Specific login attempt limiting
    loginWindowMs: 15 * 60 * 1000, // 15 minutes for login attempts
    loginMaxAttempts: 5, // max 5 login attempts per 15 minutes
    // Progressive backoff for repeated failures
    progressiveBackoff: {
      enabled: true,
      baseDelayMs: 1000, // 1 second base delay
      maxDelayMs: 30000, // max 30 seconds delay
      multiplier: 2, // exponential backoff
    }
  },
  
  // Timing attack protection
  timingAttackProtection: {
    enabled: true,
    minDelayMs: 100, // minimum delay for all auth operations
    maxDelayMs: 2000, // maximum random delay
  },
  
  // Security headers
  securityHeaders: {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    'Content-Security-Policy': [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval' accounts.google.com",
      "style-src 'self' 'unsafe-inline' fonts.googleapis.com",
      "font-src 'self' fonts.gstatic.com",
      "img-src 'self' data: https: *.googleusercontent.com *.google.com",
      "connect-src 'self' accounts.google.com *.google.com",
      "frame-src 'self' accounts.google.com",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join('; '),
  },
};

// Rate limiting store (in production, use Redis or a proper database)
const rateStore = new Map<string, { count: number; resetTime: number }>();

// Login attempt tracking (separate from general rate limiting)
const loginAttemptStore = new Map<string, {
  attempts: number;
  firstAttempt: number;
  lastAttempt: number;
  failures: number;
  backoffUntil?: number;
}>();

// Security event logging store
const securityEventStore: Array<{
  timestamp: number;
  ip: string;
  event: string;
  details: Record<string, any>;
}> = [];

// CSRF token generation
function generateCSRFToken(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

// Enhanced login attempt tracking with progressive backoff
function checkLoginAttempts(ip: string): { allowed: boolean; backoffMs?: number } {
  const now = Date.now();
  const record = loginAttemptStore.get(ip);
  const config = SECURITY_CONFIG.rateLimit;
  
  if (!record) {
    // First attempt - create record
    loginAttemptStore.set(ip, {
      attempts: 1,
      firstAttempt: now,
      lastAttempt: now,
      failures: 0
    });
    return { allowed: true };
  }
  
  // Check if backoff period is still active
  if (record.backoffUntil && now < record.backoffUntil) {
    const backoffMs = record.backoffUntil - now;
    logSecurityEvent(ip, 'LOGIN_ATTEMPT_BLOCKED', { 
      reason: 'progressive_backoff',
      backoffRemainingMs: backoffMs,
      failures: record.failures
    });
    return { allowed: false, backoffMs };
  }
  
  // Reset attempts if window has passed
  if (now - record.firstAttempt > config.loginWindowMs) {
    record.attempts = 1;
    record.firstAttempt = now;
    record.lastAttempt = now;
    record.failures = 0;
    delete record.backoffUntil;
    return { allowed: true };
  }
  
  // Check if within rate limit
  if (record.attempts >= config.loginMaxAttempts) {
    logSecurityEvent(ip, 'LOGIN_RATE_LIMIT_EXCEEDED', {
      attempts: record.attempts,
      windowMs: config.loginWindowMs
    });
    return { allowed: false };
  }
  
  record.attempts++;
  record.lastAttempt = now;
  return { allowed: true };
}

// Record login failure and apply progressive backoff
export function recordLoginFailure(ip: string): void {
  const record = loginAttemptStore.get(ip);
  if (!record) return;
  
  record.failures++;
  
  const config = SECURITY_CONFIG.rateLimit.progressiveBackoff;
  if (config.enabled && record.failures >= 3) {
    // Apply progressive backoff after 3 failures
    const backoffDelay = Math.min(
      config.baseDelayMs * Math.pow(config.multiplier, record.failures - 3),
      config.maxDelayMs
    );
    
    record.backoffUntil = Date.now() + backoffDelay;
    
    logSecurityEvent(ip, 'LOGIN_PROGRESSIVE_BACKOFF_APPLIED', {
      failures: record.failures,
      backoffMs: backoffDelay
    });
  }
}

// Timing attack protection - adds random delay to auth operations
async function addTimingDelay(): Promise<void> {
  if (!SECURITY_CONFIG.timingAttackProtection.enabled) return;
  
  const { minDelayMs, maxDelayMs } = SECURITY_CONFIG.timingAttackProtection;
  const delay = minDelayMs + Math.random() * (maxDelayMs - minDelayMs);
  
  await new Promise(resolve => setTimeout(resolve, delay));
}

// Security event logging
function logSecurityEvent(ip: string, event: string, details: Record<string, any> = {}): void {
  const logEntry = {
    timestamp: Date.now(),
    ip,
    event,
    details
  };
  
  securityEventStore.push(logEntry);
  
  // Log to console for development (in production, send to proper logging service)
  console.log(`[SECURITY] ${event}:`, JSON.stringify({
    timestamp: new Date(logEntry.timestamp).toISOString(),
    ip,
    ...details
  }));
  
  // Keep only last 1000 events in memory (in production, use proper storage)
  if (securityEventStore.length > 1000) {
    securityEventStore.splice(0, securityEventStore.length - 1000);
  }
}

// Rate limiting function
function checkRateLimit(ip: string, isAuthEndpoint: boolean = false): boolean {
  const config = isAuthEndpoint 
    ? { windowMs: SECURITY_CONFIG.rateLimit.authWindowMs, maxRequests: SECURITY_CONFIG.rateLimit.authMaxRequests }
    : { windowMs: SECURITY_CONFIG.rateLimit.windowMs, maxRequests: SECURITY_CONFIG.rateLimit.maxRequests };
  
  const now = Date.now();
  const key = `${ip}-${isAuthEndpoint ? 'auth' : 'general'}`;
  const record = rateStore.get(key);
  
  if (!record || now > record.resetTime) {
    // Reset or create new record
    rateStore.set(key, { count: 1, resetTime: now + config.windowMs });
    return true;
  }
  
  if (record.count >= config.maxRequests) {
    return false; // Rate limit exceeded
  }
  
  record.count++;
  return true;
}

// CSRF validation
function validateCSRF(request: NextRequest): boolean {
  if (!SECURITY_CONFIG.csrf.enabled) return true;
  
  // Only check CSRF for state-changing methods
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method)) {
    return true;
  }
  
  // Skip CSRF check for NextAuth endpoints (they have their own CSRF protection)
  if (request.nextUrl.pathname.startsWith('/api/auth/')) {
    return true;
  }
  
  // Skip CSRF check for session-authenticated API routes
  // These routes use NextAuth session authentication, which is sufficient
  const sessionAuthenticatedRoutes = ['/api/user/', '/api/protected/'];
  if (sessionAuthenticatedRoutes.some(route => request.nextUrl.pathname.startsWith(route))) {
    return true;
  }
  
  const csrfToken = request.headers.get(SECURITY_CONFIG.csrf.headerName);
  const csrfCookie = request.cookies.get(SECURITY_CONFIG.csrf.cookieName)?.value;
  
  // Both token and cookie must be present and match
  return !!(csrfToken && csrfCookie && csrfToken === csrfCookie);
}

// Security headers function
function addSecurityHeaders(response: NextResponse): NextResponse {
  Object.entries(SECURITY_CONFIG.securityHeaders).forEach(([key, value]) => {
    response.headers.set(key, value);
  });
  
  return response;
}

// Main middleware function
export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const ip = request.ip || request.headers.get('x-forwarded-for') || 'unknown';
  
  // Create response object
  let response = NextResponse.next();
  
  // Apply security headers to all responses
  response = addSecurityHeaders(response);
  
  // Enhanced rate limiting with special handling for login attempts
  if (SECURITY_CONFIG.rateLimit.enabled) {
    const isAuthEndpoint = pathname.startsWith('/api/auth/');
    const isLoginEndpoint = pathname === '/api/auth/callback/credentials' || 
                           pathname === '/api/auth/signin/credentials' ||
                           pathname.includes('signin');
    
    // Check general rate limiting first
    const rateLimitPassed = checkRateLimit(ip, isAuthEndpoint);
    
    if (!rateLimitPassed) {
      logSecurityEvent(ip, 'GENERAL_RATE_LIMIT_EXCEEDED', { endpoint: pathname });
      return new NextResponse(
        JSON.stringify({ 
          error: 'Rate limit exceeded',
          message: 'Too many requests. Please try again later.',
          code: 'RATE_LIMIT_EXCEEDED'
        }),
        { 
          status: 429,
          headers: {
            'Content-Type': 'application/json',
            'Retry-After': '900', // 15 minutes
            ...Object.fromEntries(Object.entries(SECURITY_CONFIG.securityHeaders))
          }
        }
      );
    }
    
    // Additional login attempt checking
    if (isLoginEndpoint) {
      const loginCheck = checkLoginAttempts(ip);
      
      if (!loginCheck.allowed) {
        const retryAfter = loginCheck.backoffMs ? Math.ceil(loginCheck.backoffMs / 1000) : 900;
        
        return new NextResponse(
          JSON.stringify({ 
            error: 'Login attempts exceeded',
            message: 'Too many failed login attempts. Please try again later.',
            code: 'LOGIN_RATE_LIMIT_EXCEEDED',
            retryAfterSeconds: retryAfter
          }),
          { 
            status: 429,
            headers: {
              'Content-Type': 'application/json',
              'Retry-After': retryAfter.toString(),
              ...Object.fromEntries(Object.entries(SECURITY_CONFIG.securityHeaders))
            }
          }
        );
      }
      
      // Add timing delay for login attempts
      await addTimingDelay();
    }
  }
  
  // CSRF Protection
  if (SECURITY_CONFIG.csrf.enabled) {
    // Generate and set CSRF token for all GET requests
    if (request.method === 'GET' && !request.cookies.get(SECURITY_CONFIG.csrf.cookieName)?.value) {
      const csrfToken = generateCSRFToken();
      response.cookies.set(SECURITY_CONFIG.csrf.cookieName, csrfToken, {
        httpOnly: SECURITY_CONFIG.csrf.httpOnly,
        secure: SECURITY_CONFIG.csrf.secure,
        sameSite: SECURITY_CONFIG.csrf.sameSite,
        path: '/',
      });
    }
    
    // Validate CSRF for state-changing requests
    if (!validateCSRF(request)) {
      logSecurityEvent(ip, 'CSRF_VALIDATION_FAILED', { 
        endpoint: pathname,
        method: request.method,
        userAgent: request.headers.get('user-agent') 
      });
      
      return new NextResponse(
        JSON.stringify({ 
          error: 'CSRF validation failed',
          message: 'Invalid or missing CSRF token',
          code: 'CSRF_ERROR'
        }),
        { 
          status: 403,
          headers: {
            'Content-Type': 'application/json',
            ...Object.fromEntries(Object.entries(SECURITY_CONFIG.securityHeaders))
          }
        }
      );
    }
  }
  
  // Authentication-based route protection
  const token = await getToken({ 
    req: request, 
    secret: process.env.NEXTAUTH_SECRET 
  });
  
  // Protected routes - require authentication
  const protectedRoutes = ['/dashboard', '/profile', '/admin', '/api/protected'];
  const isProtectedRoute = protectedRoutes.some(route => pathname.startsWith(route));
  
  if (isProtectedRoute && !token) {
    logSecurityEvent(ip, 'UNAUTHORIZED_ACCESS_ATTEMPT', {
      route: pathname,
      method: request.method,
      userAgent: request.headers.get('user-agent'),
      referer: request.headers.get('referer')
    });
    
    // For API routes, return JSON error
    if (pathname.startsWith('/api/')) {
      return new NextResponse(
        JSON.stringify({ 
          error: 'Unauthorized',
          message: 'Authentication required',
          code: 'AUTH_REQUIRED'
        }),
        { 
          status: 401,
          headers: {
            'Content-Type': 'application/json',
            ...Object.fromEntries(Object.entries(SECURITY_CONFIG.securityHeaders))
          }
        }
      );
    }
    
    // For pages, redirect to login
    const loginUrl = new URL('/login', request.url);
    loginUrl.searchParams.set('callbackUrl', pathname);
    return NextResponse.redirect(loginUrl);
  }
  
  // Admin routes - require admin role
  const adminRoutes = ['/admin'];
  const isAdminRoute = adminRoutes.some(route => pathname.startsWith(route));
  
  if (isAdminRoute && token?.role !== 'ADMIN') {
    console.warn(`Non-admin user attempted to access admin route: ${pathname}, user: ${token?.email}, IP: ${ip}`);
    
    if (pathname.startsWith('/api/')) {
      return new NextResponse(
        JSON.stringify({ 
          error: 'Forbidden',
          message: 'Admin access required',
          code: 'ADMIN_REQUIRED'
        }),
        { 
          status: 403,
          headers: {
            'Content-Type': 'application/json',
            ...Object.fromEntries(Object.entries(SECURITY_CONFIG.securityHeaders))
          }
        }
      );
    }
    
    return NextResponse.redirect(new URL('/403', request.url));
  }
  
  // API Permission-based route protection
  const apiPermissionRoutes = [
    { path: '/api/admin/', role: 'ADMIN' },
    { path: '/api/user/profile', role: 'USER' }, // All authenticated users
    { path: '/api/users/', role: 'ADMIN' }, // User management requires admin
    { path: '/api/audit/', role: 'ADMIN' }, // Audit logs require admin
  ];
  
  for (const routeConfig of apiPermissionRoutes) {
    if (pathname.startsWith(routeConfig.path)) {
      if (!token) {
        logSecurityEvent(ip, 'UNAUTHORIZED_API_ACCESS', { route: pathname });
        return new NextResponse(
          JSON.stringify({ 
            error: 'Unauthorized',
            message: 'Authentication required',
            code: 'AUTH_REQUIRED'
          }),
          { 
            status: 401,
            headers: {
              'Content-Type': 'application/json',
              ...Object.fromEntries(Object.entries(SECURITY_CONFIG.securityHeaders))
            }
          }
        );
      }
      
      if (routeConfig.role === 'ADMIN' && token.role !== 'ADMIN') {
        logSecurityEvent(ip, 'FORBIDDEN_API_ACCESS', { 
          route: pathname, 
          userRole: token.role,
          requiredRole: routeConfig.role 
        });
        return new NextResponse(
          JSON.stringify({ 
            error: 'Forbidden',
            message: 'Insufficient permissions',
            code: 'INSUFFICIENT_PERMISSIONS'
          }),
          { 
            status: 403,
            headers: {
              'Content-Type': 'application/json',
              ...Object.fromEntries(Object.entries(SECURITY_CONFIG.securityHeaders))
            }
          }
        );
      }
      break; // Exit loop once we've processed the matching route
    }
  }
  
  // Log security events (in production, send to monitoring service)
  if (process.env.NODE_ENV === 'development') {
    console.log(`Security middleware: ${request.method} ${pathname} - IP: ${ip} - User: ${token?.email || 'anonymous'}`);
  }
  
  return response;
}

// Configure which paths the middleware should run on
export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public files (public directory)
     */
    '/((?!_next/static|_next/image|favicon.ico|.*\\.png$|.*\\.jpg$|.*\\.jpeg$|.*\\.gif$|.*\\.svg$).*)',
  ],
};

export default middleware; 