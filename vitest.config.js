import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['frontend/__tests__/**/*.test.{jsx,js}'],
    environment: 'jsdom',
    globals: true,
    setupFiles: [],
  },
})
