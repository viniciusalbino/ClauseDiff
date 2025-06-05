/**
 * Mock for the 'jose' library used by NextAuth
 * This prevents NextAuth from failing during tests due to missing crypto APIs
 */

export const jwtVerify = jest.fn().mockResolvedValue({
  payload: {
    sub: 'test-user-id',
    email: 'test@example.com',
    name: 'Test User',
    role: 'USER',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 60 * 60, // 1 hour
  },
  protectedHeader: {
    alg: 'HS256',
    typ: 'JWT'
  }
});

export const SignJWT = jest.fn().mockImplementation(() => ({
  setProtectedHeader: jest.fn().mockReturnThis(),
  setIssuedAt: jest.fn().mockReturnThis(),
  setExpirationTime: jest.fn().mockReturnThis(),
  setSubject: jest.fn().mockReturnThis(),
  sign: jest.fn().mockResolvedValue('mock.jwt.token')
}));

export const importJWK = jest.fn().mockResolvedValue({
  type: 'secret',
  algorithm: { name: 'HMAC', hash: 'SHA-256' }
});

export const importPKCS8 = jest.fn().mockResolvedValue({
  type: 'private',
  algorithm: { name: 'RS256' }
});

export const importSPKI = jest.fn().mockResolvedValue({
  type: 'public',
  algorithm: { name: 'RS256' }
});

export const jwtDecrypt = jest.fn().mockResolvedValue({
  payload: {
    sub: 'test-user-id',
    email: 'test@example.com',
    name: 'Test User'
  },
  protectedHeader: {
    alg: 'dir',
    enc: 'A256GCM'
  }
});

export const EncryptJWT = jest.fn().mockImplementation(() => ({
  setProtectedHeader: jest.fn().mockReturnThis(),
  setIssuedAt: jest.fn().mockReturnThis(),
  setExpirationTime: jest.fn().mockReturnThis(),
  setSubject: jest.fn().mockReturnThis(),
  encrypt: jest.fn().mockResolvedValue('mock.encrypted.jwt')
}));

export const generateSecret = jest.fn().mockResolvedValue(new Uint8Array(32));

export const base64url = {
  encode: jest.fn().mockImplementation((input: string | Uint8Array) => {
    return typeof input === 'string' 
      ? Buffer.from(input).toString('base64url')
      : Buffer.from(input).toString('base64url');
  }),
  decode: jest.fn().mockImplementation((input: string) => {
    return new Uint8Array(Buffer.from(input, 'base64url'));
  })
};

export const errors = {
  JOSEError: class MockJOSEError extends Error {
    constructor(message: string) {
      super(message);
      this.name = 'JOSEError';
    }
  },
  JWTClaimValidationFailed: class MockJWTClaimValidationFailed extends Error {
    claim: string;
    reason: string;
    
    constructor(message: string, claim = 'unknown', reason = 'validation failed') {
      super(message);
      this.name = 'JWTClaimValidationFailed';
      this.claim = claim;
      this.reason = reason;
    }
  },
  JWTExpired: class MockJWTExpired extends Error {
    constructor(message: string) {
      super(message);
      this.name = 'JWTExpired';
    }
  }
};

// Default export for modules that use default import
const jose = {
  jwtVerify,
  SignJWT,
  importJWK,
  importPKCS8,
  importSPKI,
  jwtDecrypt,
  EncryptJWT,
  generateSecret,
  base64url,
  errors
};

export default jose; 