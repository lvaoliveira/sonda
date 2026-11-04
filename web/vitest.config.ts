import path from 'node:path'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  resolve: { alias: { '@': path.resolve(import.meta.dirname, './src') } },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    css: false,
    // `pnpm test:coverage`, for the self-analysis (CONTRIBUTING.md): paths
    // from the repository's root, which is what SonarQube and sonda scan.
    coverage: {
      provider: 'v8',
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/**/*.test.{ts,tsx}', 'src/test/**', 'src/api/mock/**'],
      reporter: [['lcov', { projectRoot: '..' }], 'text-summary'],
    },
  },
})
