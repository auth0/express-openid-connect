import { execSync } from 'child_process';
import { existsSync, mkdirSync, readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const certsDir = join(__dirname, '.certs');

/**
 * Generate self-signed certificate for local HTTPS testing
 * Returns { key, cert } for use with https.createServer
 */
export function getLocalCerts() {
  const keyPath = join(certsDir, 'localhost.key');
  const certPath = join(certsDir, 'localhost.crt');

  // Generate certs if they don't exist
  if (!existsSync(keyPath) || !existsSync(certPath)) {
    if (!existsSync(certsDir)) {
      mkdirSync(certsDir, { recursive: true });
    }

    console.log('Generating self-signed certificate for localhost...');

    // Generate self-signed cert using openssl
    execSync(
      `openssl req -x509 -newkey rsa:2048 -keyout "${keyPath}" -out "${certPath}" -days 365 -nodes -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null`,
      {
        stdio: 'pipe',
      },
    );

    console.log('Self-signed certificate generated.');
  }

  return {
    key: readFileSync(keyPath),
    cert: readFileSync(certPath),
  };
}
