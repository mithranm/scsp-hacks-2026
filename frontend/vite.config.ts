import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    allowedHosts: [
      '4374-2600-1700-a0-32f0-611f-2df6-5f3e-f7ba.ngrok-free.app',
    ],
  },
})
