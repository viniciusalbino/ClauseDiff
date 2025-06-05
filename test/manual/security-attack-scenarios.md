# Security Attack Scenarios - Manual Testing Guide

This document outlines manual testing procedures for simulating various security attacks against our authentication system.

## Prerequisites

- Development environment running
- Access to browser developer tools
- Optional: Tools like Postman, curl, or similar for API testing
- Optional: Network tools for advanced testing

## Test Scenarios

### 1. Rate Limiting Tests

#### 1.1 General Rate Limiting
**Objective**: Verify general rate limiting protects against request flooding

**Steps**:
1. Open browser developer tools (Network tab)
2. Navigate to any page on the application
3. Use a script to make rapid requests:
```javascript
// Run in browser console
for (let i = 0; i < 110; i++) {
  fetch('/api/test', { method: 'GET' })
    .then(r => console.log(`Request ${i}: ${r.status}`));
}
```

**Expected Results**:
- First 100 requests should succeed (status 200)
- Requests 101+ should return 429 (Rate Limited)
- Response should include `Retry-After` header
- Error message: "Too many requests. Please try again later."

#### 1.2 Auth Endpoint Rate Limiting
**Objective**: Verify stricter limits on authentication endpoints

**Steps**:
1. Use the following script in browser console:
```javascript
for (let i = 0; i < 15; i++) {
  fetch('/api/auth/signin', { method: 'POST' })
    .then(r => console.log(`Auth request ${i}: ${r.status}`));
}
```

**Expected Results**:
- First 10 requests should succeed or return auth errors
- Requests 11+ should return 429 (Rate Limited)
- Faster rate limiting than general endpoints

#### 1.3 Login Attempt Rate Limiting
**Objective**: Verify specific login attempt tracking

**Steps**:
1. Go to login page
2. Attempt login with invalid credentials 6 times rapidly
3. Observe response times and error messages

**Expected Results**:
- First 5 attempts should process normally
- 6th attempt should be blocked with 429
- Error: "Too many failed login attempts"
- Progressive delay should be applied

### 2. CSRF Protection Tests

#### 2.1 Missing CSRF Token
**Objective**: Verify CSRF protection blocks requests without tokens

**Steps**:
1. Open browser developer tools
2. Try making POST request without CSRF token:
```javascript
fetch('/api/test', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ test: 'data' })
})
.then(r => console.log(r.status));
```

**Expected Results**:
- Response should be 403 Forbidden
- Error message: "Invalid or missing CSRF token"
- Code: "CSRF_ERROR"

#### 2.2 Invalid CSRF Token
**Objective**: Verify CSRF protection validates token correctness

**Steps**:
1. Get CSRF token from cookie (check browser dev tools > Application > Cookies)
2. Make request with wrong token:
```javascript
fetch('/api/test', {
  method: 'POST',
  headers: { 
    'Content-Type': 'application/json',
    'x-csrf-token': 'invalid-token-here'
  },
  body: JSON.stringify({ test: 'data' })
})
.then(r => console.log(r.status));
```

**Expected Results**:
- Response should be 403 Forbidden
- CSRF validation should fail

#### 2.3 Valid CSRF Token
**Objective**: Verify valid CSRF tokens are accepted

**Steps**:
1. Get CSRF token from cookie: `__Host-csrf-token`
2. Make request with correct token:
```javascript
// Get token from cookie first
const csrfToken = document.cookie
  .split('; ')
  .find(row => row.startsWith('__Host-csrf-token='))
  ?.split('=')[1];

fetch('/api/test', {
  method: 'POST',
  headers: { 
    'Content-Type': 'application/json',
    'x-csrf-token': csrfToken
  },
  body: JSON.stringify({ test: 'data' })
})
.then(r => console.log(r.status));
```

**Expected Results**:
- Request should not be blocked by CSRF
- May return 404 (endpoint doesn't exist) but not 403

### 3. Timing Attack Protection Tests

#### 3.1 Login Timing Consistency
**Objective**: Verify login attempts take consistent time regardless of user existence

**Steps**:
1. Measure time for login with non-existent user:
```javascript
const startTime = Date.now();
fetch('/api/auth/callback/credentials', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'nonexistent@example.com',
    password: 'wrongpassword'
  })
})
.then(() => {
  const endTime = Date.now();
  console.log(`Non-existent user time: ${endTime - startTime}ms`);
});
```

2. Measure time for login with existing user but wrong password
3. Compare timing differences

**Expected Results**:
- Both requests should take similar time (within reasonable variance)
- Minimum delay of 100ms should be applied
- No significant timing differences that could leak user existence

### 4. Progressive Backoff Tests

#### 4.1 Escalating Delays
**Objective**: Verify progressive backoff increases delays after repeated failures

**Steps**:
1. Attempt login 3 times with wrong credentials
2. Note timing on each attempt
3. Continue for several more attempts
4. Observe increasing delays

**Expected Results**:
- First 3 failures: normal processing time + base delay
- After 3 failures: exponentially increasing delays
- Maximum delay cap should be respected (30 seconds)
- Backoff period should be enforced

### 5. Security Headers Tests

#### 5.1 CSP (Content Security Policy)
**Objective**: Verify CSP headers prevent XSS attacks

**Steps**:
1. Check response headers in Network tab
2. Try injecting inline script:
```javascript
// This should be blocked by CSP
document.body.innerHTML += '<script>alert("XSS")</script>';
```

**Expected Results**:
- CSP header should be present: `Content-Security-Policy`
- Inline scripts should be blocked (unless specifically allowed)
- Console should show CSP violation errors

#### 5.2 HSTS Headers
**Objective**: Verify HTTPS enforcement headers

**Steps**:
1. Check response headers for `Strict-Transport-Security`
2. Verify header includes `max-age` and `includeSubDomains`

**Expected Results**:
- HSTS header present with long max-age (31536000 seconds)
- `includeSubDomains` directive included
- `preload` directive included

#### 5.3 Frame Protection
**Objective**: Verify clickjacking protection

**Steps**:
1. Check for `X-Frame-Options: DENY` header
2. Try embedding page in iframe (should fail)

**Expected Results**:
- `X-Frame-Options: DENY` header present
- Page cannot be embedded in iframe

### 6. Route Protection Tests

#### 6.1 Unauthenticated Access
**Objective**: Verify protected routes require authentication

**Steps**:
1. Ensure you're logged out
2. Try accessing: `/dashboard`, `/profile`, `/admin`
3. Try API routes: `/api/protected/*`

**Expected Results**:
- Web routes: Redirect to login page (302)
- API routes: Return 401 with JSON error
- Error code: "AUTH_REQUIRED"

#### 6.2 Authenticated Access
**Objective**: Verify authenticated users can access protected routes

**Steps**:
1. Log in to the application
2. Access protected routes
3. Verify normal functionality

**Expected Results**:
- No redirects or 401 errors
- Normal page/API functionality

### 7. Security Event Logging Tests

#### 7.1 Log Verification
**Objective**: Verify security events are properly logged

**Steps**:
1. Trigger various security events:
   - Failed CSRF validation
   - Rate limit exceeded
   - Unauthorized access attempt
   - Login failures
2. Check server console/logs for security events

**Expected Results**:
- Events logged with format: `[SECURITY] EVENT_NAME:`
- Includes timestamp, IP, and relevant details
- Events include:
  - `CSRF_VALIDATION_FAILED`
  - `GENERAL_RATE_LIMIT_EXCEEDED`
  - `LOGIN_RATE_LIMIT_EXCEEDED`
  - `UNAUTHORIZED_ACCESS_ATTEMPT`
  - `LOGIN_PROGRESSIVE_BACKOFF_APPLIED`

## Advanced Attack Simulations

### 8. Brute Force Attack Simulation

**Objective**: Verify the system properly handles sustained brute force attempts

**Steps**:
1. Use a script to automate multiple login attempts:
```bash
# Using curl (run in terminal)
for i in {1..20}; do
  curl -X POST http://localhost:3000/api/auth/signin \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"wrong'$i'"}' \
    -v
  sleep 1
done
```

**Expected Results**:
- Initial attempts processed normally
- After 5 attempts: rate limiting kicks in
- Progressive backoff applied
- Account not locked permanently (just time-based restrictions)

### 9. Session Fixation Tests

**Objective**: Verify session tokens are properly rotated

**Steps**:
1. Note session token before login
2. Complete login process
3. Check if session token changed
4. Verify old token is invalidated

**Expected Results**:
- Session token should change after login
- Old tokens should be invalidated
- New session should have fresh CSRF tokens

## Security Monitoring

### Checklist for Production
- [ ] Rate limiting configured appropriately for expected traffic
- [ ] Security headers configured and tested
- [ ] CSRF protection enabled and validated
- [ ] Security event logging working and monitored
- [ ] Progressive backoff functioning correctly
- [ ] Timing attack protection not causing UX issues
- [ ] Session management secure and tested

### Red Flags to Watch For
- ⚠️ Consistent timing patterns that could leak information
- ⚠️ Rate limiting too aggressive (blocking legitimate users)
- ⚠️ Security events not being logged
- ⚠️ CSRF tokens not being generated or validated
- ⚠️ Headers missing in production
- ⚠️ Progressive backoff not resetting appropriately

## Notes for Production Deployment

1. **Rate Limiting**: Replace in-memory store with Redis/database
2. **Security Logging**: Integrate with proper logging service (e.g., CloudWatch, DataDog)
3. **Monitoring**: Set up alerts for security events
4. **Performance**: Monitor timing delays don't impact user experience
5. **Testing**: Regular security testing and penetration testing
6. **Updates**: Keep security configurations updated with threat landscape 