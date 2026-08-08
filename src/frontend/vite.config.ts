import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      // Map logical import to the runtime script injected by Wails at "/wails/runtime.js"
      'wails-runtime': '/wails/runtime.js',
    },
  },
  server: {
    host: '127.0.0.1',
    port: Number(process.env.WAILS_VITE_PORT) || 9245,
    strictPort: true,
  },
  build: {
    outDir: 'dist',
    rollupOptions: {
      external: ['/wails/runtime.js'],
    }
  },
})
