import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': { target: 'http://127.0.0.1:9001', changeOrigin: true },
    },
  },
  build: { outDir: 'dist', sourcemap: true },
})
