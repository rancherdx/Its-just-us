// vitest.config.ts
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'miniflare', // Switch to miniflare for integration tests
    environmentOptions: {
      // Optional: configure miniflare specific options here
      // For example, D1 bindings, KV bindings, secrets, etc.
      // We'll mock D1 and secrets directly in tests for now.
      scriptPath: './src/index.js', // Entry point for the worker
    },
    mockReset: true,
    clearMocks: true,
  },
});
