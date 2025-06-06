// src/index.integration.test.ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import worker from './index'; // Import the worker entry point

// Mock the microsoftGraphService
vi.mock('./services/microsoftGraphService', () => ({
  sendEmail: vi.fn().mockResolvedValue(true), // Mock implementation
}));

// Mock D1 database interactions for these tests
const mockD1Result = {
    run: vi.fn().mockResolvedValue({ meta: { changes: 1, last_row_id: 1 } }),
    bind: vi.fn(() => mockD1Result), // Chainable bind
    first: vi.fn().mockResolvedValue(null), // Default to user not found or token not found
    all: vi.fn().mockResolvedValue({ results: [] }),
};
const mockD1 = {
  prepare: vi.fn(() => mockD1Result),
};

const mockEnv = {
  JWT_SECRET: 'test-jwt-secret',
  MS_GRAPH_CLIENT_ID: 'test-client-id', // Needed by microsoftGraphService if not fully mocked
  MS_GRAPH_CLIENT_SECRET: 'test-client-secret',
  MS_GRAPH_TENANT_ID: 'test-tenant-id',
  MS_GRAPH_SENDING_USER_ID: 'test-sender@example.com',
  D1_DB: mockD1, // Provide the mock D1 binding
  // Add any other env vars your worker expects
};

describe('Worker Integration Tests for Email Endpoints', () => {
  beforeEach(() => {
    vi.clearAllMocks(); // Clear all mocks before each test
    // Reset D1 mock states if necessary for specific tests
    mockD1Result.first.mockResolvedValue(null); // Default reset
    mockD1Result.run.mockResolvedValue({ meta: { changes: 1, last_row_id: 1 } }); // Default success for inserts/updates
  });

  describe('POST /auth/register', () => {
    it('should call sendEmail on successful registration', async () => {
      const { sendEmail } = await import('./services/microsoftGraphService');

      const requestBody = { name: 'Test User', email: 'test@example.com', password: 'password123' };
      const request = new Request('http://localhost/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody),
      });

      const response = await worker.fetch(request, mockEnv, {} as any);
      expect(response.status).toBe(201); // User registered

      expect(sendEmail).toHaveBeenCalledOnce();
      expect(sendEmail).toHaveBeenCalledWith(
        mockEnv,
        expect.objectContaining({
          to: requestBody.email,
          subject: expect.stringContaining(`Welcome to It's Just Us, ${requestBody.name}!`),
          htmlBody: expect.stringContaining(`<h1>Welcome, ${requestBody.name}!</h1>`),
        })
      );
    });
  });

  describe('POST /api/auth/request-password-reset', () => {
    it('should call sendEmail when user exists', async () => {
      const { sendEmail } = await import('./services/microsoftGraphService');
      mockD1Result.first.mockResolvedValueOnce({ id: 1, email: 'user@example.com' }); // Simulate user found

      const requestBody = { email: 'user@example.com' };
      const request = new Request('http://localhost/api/auth/request-password-reset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody),
      });

      const response = await worker.fetch(request, mockEnv, {} as any);
      expect(response.status).toBe(200);

      expect(sendEmail).toHaveBeenCalledOnce();
      expect(sendEmail).toHaveBeenCalledWith(
        mockEnv,
        expect.objectContaining({
          to: requestBody.email,
          subject: 'Your Password Reset Request',
          htmlBody: expect.stringContaining('/reset-password?token='),
        })
      );
    });

    it('should NOT call sendEmail but return 200 if user does not exist (security)', async () => {
      const { sendEmail } = await import('./services/microsoftGraphService');
      mockD1Result.first.mockResolvedValueOnce(null); // Simulate user NOT found

      const requestBody = { email: 'nonexistent@example.com' };
      const request = new Request('http://localhost/api/auth/request-password-reset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody),
      });

      const response = await worker.fetch(request, mockEnv, {} as any);
      expect(response.status).toBe(200); // Still returns 200 for security
      expect(sendEmail).not.toHaveBeenCalled();
    });
  });

  describe('POST /api/auth/reset-password', () => {
    it('should call sendEmail on successful password reset', async () => {
      const { sendEmail } = await import('./services/microsoftGraphService');
      const userEmail = 'user@example.com';
      // Simulate token found and valid
      mockD1Result.first.mockResolvedValueOnce({ email: userEmail, expires_at: new Date(Date.now() + 3600 * 1000).toISOString() });
      // Simulate user password update success
      mockD1Result.run.mockResolvedValueOnce({ meta: { changes: 1 } }); // For user password update
      mockD1Result.run.mockResolvedValueOnce({ meta: { changes: 1 } }); // For deleting token

      const requestBody = { token: 'valid-plain-token', newPassword: 'newSecurePassword123' };
      const request = new Request('http://localhost/api/auth/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody),
      });

      const response = await worker.fetch(request, mockEnv, {} as any);
      expect(response.status).toBe(200);

      expect(sendEmail).toHaveBeenCalledOnce();
      expect(sendEmail).toHaveBeenCalledWith(
        mockEnv,
        expect.objectContaining({
          to: userEmail,
          subject: 'Your Password Has Been Reset',
          htmlBody: expect.stringContaining('<h1>Password Successfully Reset</h1>'),
        })
      );
    });
  });
});
