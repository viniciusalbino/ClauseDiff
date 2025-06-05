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

// CSRF token generation
function generateCSRFToken(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
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
  
  // Rate limiting
  if (SECURITY_CONFIG.rateLimit.enabled) {
    const isAuthEndpoint = pathname.startsWith('/api/auth/');
    const rateLimitPassed = checkRateLimit(ip, isAuthEndpoint);
    
    if (!rateLimitPassed) {
      console.warn(`Rate limit exceeded for IP: ${ip}, endpoint: ${pathname}`);
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
      console.warn(`CSRF validation failed for IP: ${ip}, endpoint: ${pathname}`);
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
    console.log(`Unauthorized access attempt to protected route: ${pathname} from IP: ${ip}`);
    
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
  
  if (isAdminRoute && token?.role !== 'admin') {
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