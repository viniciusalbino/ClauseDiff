// Mock for next-auth/jwt functions

export const getToken = jest.fn().mockResolvedValue(null);

export default {
  getToken,
}; 