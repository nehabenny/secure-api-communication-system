import { defineConfig } from 'vite';
import fs from 'fs';
import path from 'path';

const backendCertsDir = path.resolve(__dirname, '../backend/certs');
const certExists = fs.existsSync(path.join(backendCertsDir, 'cert.pem'));

export default defineConfig({
  server: {
    // Proxy all /api requests to the HTTPS backend
    proxy: {
      '/api': {
        target: certExists ? 'https://localhost:3443' : 'http://localhost:3000',
        changeOrigin: true,
        secure: false, // Accept self-signed certs
      }
    }
  }
});
