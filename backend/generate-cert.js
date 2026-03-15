/**
 * generate-cert.js
 * Generates a self-signed TLS certificate using node-forge (pure JS, no openssl needed).
 */
import forge from 'node-forge';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const certsDir = path.join(__dirname, 'certs');

if (!fs.existsSync(certsDir)) {
  fs.mkdirSync(certsDir, { recursive: true });
}

// Generate 2048-bit RSA key pair
console.log('Generating 2048-bit RSA key pair...');
const keys = forge.pki.rsa.generateKeyPair(2048);

// Create self-signed certificate
const cert = forge.pki.createCertificate();
cert.publicKey = keys.publicKey;
cert.serialNumber = '01';
cert.validity.notBefore = new Date();
cert.validity.notAfter = new Date();
cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

const attrs = [{ name: 'commonName', value: 'localhost' }];
cert.setSubject(attrs);
cert.setIssuer(attrs);

cert.setExtensions([
  { name: 'subjectAltName', altNames: [
    { type: 2, value: 'localhost' },   // DNS
    { type: 7, ip: '127.0.0.1' },     // IP
  ]},
  { name: 'basicConstraints', cA: true },
  { name: 'keyUsage', keyCertSign: true, digitalSignature: true, keyEncipherment: true }
]);

// Sign with SHA-256
cert.sign(keys.privateKey, forge.md.sha256.create());

// Export to PEM
const certPem = forge.pki.certificateToPem(cert);
const keyPem = forge.pki.privateKeyToPem(keys.privateKey);

fs.writeFileSync(path.join(certsDir, 'cert.pem'), certPem);
fs.writeFileSync(path.join(certsDir, 'key.pem'), keyPem);

console.log('✅ Self-signed TLS certificate generated in backend/certs/');
console.log('   - cert.pem (public certificate, SHA-256 signed)');
console.log('   - key.pem  (private key, RSA 2048-bit)');
