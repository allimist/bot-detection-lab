import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const api = process.env.API_URL ?? 'http://localhost:5178';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5179,
    proxy: { '/api': api, '/collector.js': api },
  },
});
