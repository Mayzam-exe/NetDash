import { defineConfig } from 'vite';

export default defineConfig({
  // Preact's automatic JSX runtime (Phase 1: components are .tsx).
  esbuild: {
    jsx: 'automatic',
    jsxImportSource: 'preact',
  },
  server: {
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:7420',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
  },
});
