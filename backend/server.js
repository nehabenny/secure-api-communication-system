import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import https from 'https';
import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

const HTTP_PORT = 3000;
const HTTPS_PORT = 3443;

/* ==========================================================================
   Middleware
   ========================================================================== */
app.use(cors());
app.use(express.json());

/* ==========================================================================
   In-Memory Stores (Prototype only — no DB needed)
   ========================================================================== */

// User accounts: Map<username, { salt, hash }>
const users = new Map();

// Active auth tokens: Map<token, { username, createdAt }>
const authTokens = new Map();

// ECDH sessions: Map<sessionId, { sharedSecret, username }>
const sessions = new Map();

// Server-level secret for signing auth tokens (generated at startup)
const SERVER_TOKEN_SECRET = crypto.randomBytes(32);

/* ==========================================================================
   Utility Functions
   ========================================================================== */

/**
 * Hash a password with SHA-256 + salt
 */
function hashPassword(password, salt) {
  return crypto.createHash('sha256').update(salt + password).digest('hex');
}

/**
 * Generate HMAC-SHA256 auth token
 */
function generateAuthToken(username) {
  const payload = `${username}:${Date.now()}:${crypto.randomBytes(16).toString('hex')}`;
  const hmac = crypto.createHmac('sha256', SERVER_TOKEN_SECRET)
                     .update(payload)
                     .digest('hex');
  const token = `${Buffer.from(payload).toString('base64')}.${hmac}`;
  authTokens.set(token, { username, createdAt: Date.now() });
  return token;
}

/**
 * Verify auth token
 */
function verifyAuthToken(token) {
  if (!token) return null;
  
  const session = authTokens.get(token);
  if (!session) return null;
  
  // Token expires after 1 hour
  if (Date.now() - session.createdAt > 3600000) {
    authTokens.delete(token);
    return null;
  }
  
  // Verify HMAC integrity of the token itself
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  
  const [payloadB64, receivedHmac] = parts;
  const payload = Buffer.from(payloadB64, 'base64').toString('utf8');
  
  const expectedHmac = crypto.createHmac('sha256', SERVER_TOKEN_SECRET)
                             .update(payload)
                             .digest('hex');
  
  const expectedBuf = Buffer.from(expectedHmac, 'hex');
  const receivedBuf = Buffer.from(receivedHmac, 'hex');
  
  if (expectedBuf.length !== receivedBuf.length) return null;
  if (!crypto.timingSafeEqual(expectedBuf, receivedBuf)) return null;
  
  return session;
}

/* ==========================================================================
   Auth Middleware — Protects routes that require a logged-in user
   ========================================================================== */
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ 
      error: 'UNAUTHORIZED', 
      reason: 'Missing or invalid Authorization header. Please log in first.' 
    });
  }
  
  const token = authHeader.slice(7);
  const session = verifyAuthToken(token);
  
  if (!session) {
    return res.status(401).json({ 
      error: 'UNAUTHORIZED', 
      reason: 'Auth token is invalid or expired. Please log in again.' 
    });
  }
  
  req.user = session;
  next();
}

/* ==========================================================================
   AUTH ROUTES
   ========================================================================== */

/**
 * POST /api/register — Create a new user account
 * Body: { username, password }
 */
app.post('/api/register', (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required.' });
    }
    
    if (username.length < 3 || password.length < 6) {
      return res.status(400).json({ error: 'Username must be ≥ 3 chars, password ≥ 6 chars.' });
    }
    
    if (users.has(username)) {
      return res.status(409).json({ error: 'Username already exists.' });
    }
    
    // Hash password with SHA-256 + random salt
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = hashPassword(password, salt);
    
    users.set(username, { salt, hash });
    
    console.log(`[Auth] New user registered: ${username}`);
    res.status(201).json({ 
      status: 'success', 
      message: `User '${username}' registered successfully.`,
      hashAlgorithm: 'SHA-256',
      saltLength: '128-bit'
    });
    
  } catch (error) {
    console.error('[Register Error]', error);
    res.status(500).json({ error: 'Registration failed.' });
  }
});

/**
 * POST /api/login — Authenticate and receive a session token
 * Body: { username, password }
 */
app.post('/api/login', (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required.' });
    }
    
    const user = users.get(username);
    if (!user) {
      return res.status(401).json({ error: 'UNAUTHORIZED', reason: 'Invalid credentials.' });
    }
    
    // Verify password by recomputing SHA-256(salt + password)
    const computedHash = hashPassword(password, user.salt);
    
    // Constant-time comparison to prevent timing attacks
    const expectedBuf = Buffer.from(user.hash, 'hex');
    const computedBuf = Buffer.from(computedHash, 'hex');
    
    if (!crypto.timingSafeEqual(expectedBuf, computedBuf)) {
      return res.status(401).json({ error: 'UNAUTHORIZED', reason: 'Invalid credentials.' });
    }
    
    // Generate auth token
    const token = generateAuthToken(username);
    
    console.log(`[Auth] User logged in: ${username}`);
    res.json({ 
      status: 'success', 
      message: `Authenticated as '${username}'.`,
      token,
      expiresIn: '1 hour'
    });
    
  } catch (error) {
    console.error('[Login Error]', error);
    res.status(500).json({ error: 'Login failed.' });
  }
});

/* ==========================================================================
   ECDH HANDSHAKE (Now protected by auth)
   ========================================================================== */
app.post('/api/handshake', requireAuth, (req, res) => {
  try {
    const { clientPublicKeyBase64 } = req.body;
    
    if (!clientPublicKeyBase64) {
      return res.status(400).json({ error: 'Client public key missing' });
    }

    // 1. Decode client public key from base64 (raw uncompressed format expected)
    const clientPublicKeyBuffer = Buffer.from(clientPublicKeyBase64, 'base64');
    
    // 2. Generate Server's ECDH key pair (secp256r1 == prime256v1)
    const serverECDH = crypto.createECDH('prime256v1');
    serverECDH.generateKeys();
    
    // 3. Derive Shared Secret using Server's Private Key + Client's Public Key
    const sharedSecret = serverECDH.computeSecret(clientPublicKeyBuffer);
    
    // 4. Generate a session ID to track this specific connection
    const sessionId = crypto.randomUUID();
    sessions.set(sessionId, { sharedSecret, username: req.user.username });
    
    // 5. Send Server's Public Key back to the client
    const serverPublicKeyBase64 = serverECDH.getPublicKey().toString('base64');
    
    console.log(`[Handshake] Secure session established for user '${req.user.username}': ${sessionId}`);
    
    res.json({
      sessionId,
      serverPublicKeyBase64
    });
    
  } catch (error) {
    console.error('[Handshake Error]', error);
    res.status(500).json({ error: 'Handshake failed' });
  }
});

/* ==========================================================================
   SECURE DATA TRANSMISSION (Protected by auth + HMAC)
   ========================================================================== */
app.post('/api/secure-data', requireAuth, (req, res) => {
  try {
    const { payload, timestamp, hmac, sessionId } = req.body;
    
    if (!payload || !timestamp || !hmac || !sessionId) {
      return res.status(400).json({ error: 'Missing required security fields' });
    }
    
    // 1. Look up the session
    const session = sessions.get(sessionId);
    if (!session) {
      return res.status(401).json({ error: 'Invalid or expired session. Please handshake again.' });
    }
    
    // 2. Check Timestamp (Replay Attack Protection)
    const now = Date.now();
    const requestTime = parseInt(timestamp, 10);
    const timeDelta = now - requestTime;
    
    // Reject if timestamp is in the future or older than 30 seconds
    if (timeDelta < -5000 || timeDelta > 30000) {
      console.warn(`[Replay Attempt] Request timestamp delta: ${timeDelta}ms`);
      return res.status(403).json({ error: 'INTEGRITY_BREACH', reason: 'Request timestamp is invalid or expired (Possible Replay Attack).' });
    }
    
    // 3. Recompute HMAC-SHA256
    // Payload + timestamp ensures each request signature is unique even for identical data
    const messageToSign = JSON.stringify(payload) + timestamp;
    
    const expectedHmac = crypto.createHmac('sha256', session.sharedSecret)
                                     .update(messageToSign)
                                     .digest('hex');
                                     
    // 4. Constant-time comparison to prevent timing attacks
    const expectedHmacBuffer = Buffer.from(expectedHmac, 'hex');
    const receivedHmacBuffer = Buffer.from(hmac, 'hex');
    
    if (expectedHmacBuffer.length !== receivedHmacBuffer.length) {
       console.warn(`[HMAC Length Mismatch] Given: ${receivedHmacBuffer.length}, Expected: ${expectedHmacBuffer.length}`);
       return res.status(403).json({ error: 'INTEGRITY_BREACH', reason: 'HMAC signature length mismatch.' });
    }
    
    const isValid = crypto.timingSafeEqual(expectedHmacBuffer, receivedHmacBuffer);
    
    if (!isValid) {
      console.error(`[Integrity Breach] HMAC signature failed validation for session ${sessionId}`);
      return res.status(403).json({ error: 'INTEGRITY_BREACH', reason: 'HMAC signature is invalid. Data may have been tampered with.' });
    }
    
    // 5. Success
    console.log(`[Secure Request] Verified from '${req.user.username}' (session ${sessionId}):`, payload);
    res.status(200).json({
      status: 'success',
      message: 'Request authenticity and payload integrity verified',
      user: req.user.username,
      processedData: `Echo secured payload: ${payload.message}`
    });

  } catch (error) {
    console.error('[Secure Data Error]', error);
    res.status(500).json({ error: 'Internal server error processing secure payload' });
  }
});

/* ==========================================================================
   PROTECTED RESOURCE — Demonstrates that only authed users can access data
   ========================================================================== */
app.get('/api/protected-resource', requireAuth, (req, res) => {
  console.log(`[Protected Resource] Accessed by '${req.user.username}'`);
  res.json({
    status: 'success',
    user: req.user.username,
    data: {
      classification: 'TOP SECRET',
      message: 'This data is only accessible to authenticated users.',
      records: [
        { id: 1, name: 'Classified Document Alpha', clearance: 'Level 5' },
        { id: 2, name: 'Operation Nightfall Report', clearance: 'Level 4' },
        { id: 3, name: 'Secure Communications Log', clearance: 'Level 3' }
      ],
      accessTimestamp: new Date().toISOString()
    }
  });
});

/* ==========================================================================
   HTTPS + HTTP Servers
   ========================================================================== */
const certsPath = path.join(__dirname, 'certs');
const certFile = path.join(certsPath, 'cert.pem');
const keyFile = path.join(certsPath, 'key.pem');

if (fs.existsSync(certFile) && fs.existsSync(keyFile)) {
  const httpsOptions = {
    key: fs.readFileSync(keyFile),
    cert: fs.readFileSync(certFile)
  };

  // HTTPS server (primary)
  https.createServer(httpsOptions, app).listen(HTTPS_PORT, () => {
    console.log(`🔒 Vault Backend (HTTPS) listening on https://localhost:${HTTPS_PORT}`);
  });

  // HTTP redirect server
  const redirectApp = express();
  redirectApp.use((req, res) => {
    res.redirect(301, `https://${req.hostname}:${HTTPS_PORT}${req.url}`);
  });
  http.createServer(redirectApp).listen(HTTP_PORT, () => {
    console.log(`↪  HTTP redirect server on http://localhost:${HTTP_PORT} → https://localhost:${HTTPS_PORT}`);
  });
} else {
  // Fallback: HTTP only (if certs not generated)
  console.warn('⚠️  TLS certificates not found in backend/certs/. Run: node generate-cert.js');
  console.warn('   Starting in HTTP-only mode...');
  app.listen(HTTP_PORT, () => {
    console.log(`⚠️  Vault Backend (HTTP) listening on http://localhost:${HTTP_PORT}`);
  });
}
