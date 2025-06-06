// src/services/microsoftGraphService.test.ts
import { describe, it, expect, vi, beforeEach, afterEach, afterAll } from 'vitest';
import { sendEmail } from './microsoftGraphService'; // Adjust path as necessary

// Mock environment variables (secrets)
const mockEnv = {
  MS_GRAPH_CLIENT_ID: 'test-client-id',
  MS_GRAPH_CLIENT_SECRET: 'test-client-secret',
  MS_GRAPH_TENANT_ID: 'test-tenant-id',
  MS_GRAPH_SENDING_USER_ID: 'test-sender@example.com',
};

// Mock global fetch
global.fetch = vi.fn();

// Helper to create a fetch response
const createFetchResponse = (ok: boolean, status: number, data: any) => {
  return Promise.resolve({
    ok,
    status,
    json: () => Promise.resolve(data),
    text: () => Promise.resolve(JSON.stringify(data)), // for error text
  });
};

// To reset the internal tokenCache in microsoftGraphService.ts if it's module-scoped
// This is a bit hacky. A better way would be to have a reset function in the module or pass cache as a dependency.
// For now, we can try to force re-evaluation by clearing module cache if Vitest supports it easily,
// or design tests understanding the shared cache.
// Vitest's `vi.resetModules()` can be used if the service is imported after this call in a `beforeEach`.
// Or, since tokenCache is a let variable, we can't directly reset it from outside without modifying the source.
// Tests will need to account for the shared cache or test token logic sequentially.

describe('microsoftGraphService', () => {
  beforeEach(() => {
    // vi.resetModules(); // Reset module state including tokenCache before each test
    // global.fetch = vi.fn(); // Re-assign mock fetch for each test
    // Note: Re-importing the service here if resetModules is used, to get the fresh state
    // const { sendEmail: freshSendEmail, getAccessToken: freshGetAccessToken } = await import('./microsoftGraphService');
    // sendEmail = freshSendEmail; getAccessToken = freshGetAccessToken;
    // This dynamic import approach can be complex.
    // For simplicity, let's assume tests are okay with sequential cache behavior or we manually manage time for expiry.
    // Resetting fetch mock calls is crucial.
    vi.mocked(global.fetch).mockClear(); // Clears call history but keeps mock implementation if any specific one was set.
                                      // If fetch was globally mocked and then specific mocks per test, ensure this doesn't interfere.
                                      // Better to just re-assign:
    global.fetch = vi.fn();
  });

  afterEach(() => {
     vi.clearAllMocks(); // Clears all information about mock calls and implementations.
  });

  // --- Tests for getAccessToken (if it were exported, or test implicitly via sendEmail) ---
  // Since getAccessToken is not exported, we test its behavior through sendEmail's token acquisition.
  // We'll focus on testing sendEmail and the token logic will be part of it.

  describe('sendEmail', () => {
    it('should request a new token, then send an email successfully', async () => {
      // Mock token response
      (fetch as vi.Mock).mockResolvedValueOnce(createFetchResponse(true, 200, {
        access_token: 'mock-access-token',
        expires_in: 3600,
      }));
      // Mock email send response
      (fetch as vi.Mock).mockResolvedValueOnce(createFetchResponse(true, 202, {}));

      const emailArgs = { to: 'recipient@example.com', subject: 'Test Subject', htmlBody: '<p>Test Body</p>' };
      const result = await sendEmail(mockEnv, emailArgs);

      expect(result).toBe(true);
      expect(fetch).toHaveBeenCalledTimes(2);

      // Check token request
      expect(fetch).toHaveBeenNthCalledWith(1,
        `https://login.microsoftonline.com/${mockEnv.MS_GRAPH_TENANT_ID}/oauth2/v2.0/token`,
        expect.objectContaining({
          method: 'POST',
          body: expect.stringContaining(`client_id=${mockEnv.MS_GRAPH_CLIENT_ID}`)
        })
      );

      // Check email request
      expect(fetch).toHaveBeenNthCalledWith(2,
        `https://graph.microsoft.com/v1.0/users/${mockEnv.MS_GRAPH_SENDING_USER_ID}/sendMail`,
        expect.objectContaining({
          method: 'POST',
          headers: {
            'Authorization': 'Bearer mock-access-token',
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            message: {
              subject: emailArgs.subject,
              body: { contentType: 'HTML', content: emailArgs.htmlBody },
              toRecipients: [{ emailAddress: { address: emailArgs.to } }],
            },
            saveToSentItems: 'true',
          }),
        })
      );
    });

    it('should use cached token for subsequent email if not expired', async () => {
      // First call: gets new token and sends email
      (fetch as vi.Mock)
        .mockResolvedValueOnce(createFetchResponse(true, 200, { access_token: 'cached-token', expires_in: 3600 }))
        .mockResolvedValueOnce(createFetchResponse(true, 202, {})); // email1

      const emailArgs1 = { to: 'r1@example.com', subject: 'S1', htmlBody: 'B1' };
      await sendEmail(mockEnv, emailArgs1); // Populates cache

      expect(fetch).toHaveBeenCalledTimes(2);
      // vi.clearAllMocks(); // Clear fetch mock calls for the next assertion, but not the cache within the module
      // Instead of clearAllMocks, just clear the call history for fetch for this specific test's logic
      vi.mocked(fetch).mockClear();


      // Second call: should use cached token
      (fetch as vi.Mock).mockResolvedValueOnce(createFetchResponse(true, 202, {})); // email2
      const emailArgs2 = { to: 'r2@example.com', subject: 'S2', htmlBody: 'B2' };
      await sendEmail(mockEnv, emailArgs2);

      expect(fetch).toHaveBeenCalledTimes(1); // Only email call, no new token call
      expect(fetch).toHaveBeenCalledWith(
        `https://graph.microsoft.com/v1.0/users/${mockEnv.MS_GRAPH_SENDING_USER_ID}/sendMail`,
        expect.objectContaining({ headers: { 'Authorization': 'Bearer cached-token' } })
      );
    });

    it('should request a new token if cached token is expired', async () => {
      // Initial call to populate cache with a token that will expire quickly
      (fetch as vi.Mock)
        .mockResolvedValueOnce(createFetchResponse(true, 200, { access_token: 'expiring-token', expires_in: 1 })) // Expires in 1 sec
        .mockResolvedValueOnce(createFetchResponse(true, 202, {}));

      const emailArgs1 = { to: 'r1@example.com', subject: 'S1', htmlBody: 'B1' };
      await sendEmail(mockEnv, emailArgs1);
      expect(fetch).toHaveBeenCalledTimes(2);
      vi.mocked(fetch).mockClear();


      // Wait for token to expire (e.g., 1.5 seconds)
      // Vitest advances timers if vi.useFakeTimers() is used. Otherwise, actual timeout.
      await new Promise(resolve => setTimeout(resolve, 1500));
      // vi.clearAllMocks(); // This would also clear the implementation of fetch. We only want to clear calls.


      // Second call: should request a new token
      (fetch as vi.Mock)
        .mockResolvedValueOnce(createFetchResponse(true, 200, { access_token: 'new-fresh-token', expires_in: 3600 }))
        .mockResolvedValueOnce(createFetchResponse(true, 202, {}));

      const emailArgs2 = { to: 'r2@example.com', subject: 'S2', htmlBody: 'B2' };
      await sendEmail(mockEnv, emailArgs2);

      expect(fetch).toHaveBeenCalledTimes(2); // Token request + Email request
      expect(fetch).toHaveBeenNthCalledWith(1, `https://login.microsoftonline.com/${mockEnv.MS_GRAPH_TENANT_ID}/oauth2/v2.0/token`, expect.anything());
      expect(fetch).toHaveBeenNthCalledWith(2, `https://graph.microsoft.com/v1.0/users/${mockEnv.MS_GRAPH_SENDING_USER_ID}/sendMail`,
         expect.objectContaining({ headers: { 'Authorization': 'Bearer new-fresh-token' }})
      );
    });


    it('should return false if token request fails', async () => {
      (fetch as vi.Mock).mockResolvedValueOnce(createFetchResponse(false, 500, { error: 'token_error' }));

      const result = await sendEmail(mockEnv, { to: 'r@e.com', subject: 'S', htmlBody: 'B' });
      expect(result).toBe(false);
      expect(fetch).toHaveBeenCalledTimes(1);
    });

    it('should return false if email sending fails', async () => {
      (fetch as vi.Mock)
        .mockResolvedValueOnce(createFetchResponse(true, 200, { access_token: 'good-token', expires_in: 3600 }))
        .mockResolvedValueOnce(createFetchResponse(false, 500, { error: 'send_mail_error' })); // Email send fails

      const result = await sendEmail(mockEnv, { to: 'r@e.com', subject: 'S', htmlBody: 'B' });
      expect(result).toBe(false);
      expect(fetch).toHaveBeenCalledTimes(2);
    });
  });
});
