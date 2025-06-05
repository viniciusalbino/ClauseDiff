// Mock for next-auth/next server functions

export const getServerSession = jest.fn().mockResolvedValue(null);

export default {
  getServerSession,
}; 