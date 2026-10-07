/// <reference types="vitest/config" />
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

/**
 * R$F web workbench.
 *
 * - `npm run dev` proxies `/api` to a local `raf serve` (127.0.0.1:8765).
 * - `npm run build` writes `dist/`, which `raf serve` serves with an SPA fallback and a strict CSP
 *   (`script-src 'self'`): the build must not rely on inline scripts, eval or external origins.
 */
const API_TARGET = 'http://127.0.0.1:8765';

export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: false,
    proxy: {
      '/api': { target: API_TARGET, changeOrigin: true },
    },
  },
  preview: {
    host: '127.0.0.1',
    proxy: {
      '/api': { target: API_TARGET, changeOrigin: true },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'es2022',
    sourcemap: false,
    // Cytoscape is large; it lives in its own lazily loaded chunk (Graph and Replay pages only).
    chunkSizeWarningLimit: 700,
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    css: false,
    restoreMocks: true,
  },
});
