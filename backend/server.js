import express from 'express';
import cors from 'cors';
import crypto from 'crypto';

const app = express();
const port = 3000;

// Middleware
app.use(cors());
app.use(express.json());

// In-memory store for shared secrets (session-based)
// Not for production - just for demonstrating the ECDH flow
const sessions = new Map();

/**
 * Derived shared secret storage structure:
 * sessions.set(sessionId, {
 *   sharedSecret: Buffer (the 32-byte shared secret)
 * });
 */

app.post('/api/handshake', (req, res) => {
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
    sessions.set(sessionId, { sharedSecret });
    
    // 5. Send Server's Public Key back to the client
    const serverPublicKeyBase64 = serverECDH.getPublicKey().toString('base64');
    
    console.log(`[Handshake] New secure session established: ${sessionId}`);
    
    res.json({
      sessionId,
      serverPublicKeyBase64
    });
    
  } catch (error) {
    console.error('[Handshake Error]', error);
    res.status(500).json({ error: 'Handshake failed' });
  }
});

app.post('/api/secure-data', (req, res) => {
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
    
    const expectedHmacNodePath = crypto.createHmac('sha256', session.sharedSecret)
                                       .update(messageToSign)
                                       .digest('hex');
                                       
    // 4. Constant-time comparison to prevent timing attacks
    // We must ensure the buffers are of the same length before calling timingSafeEqual
    const expectedHmacBuffer = Buffer.from(expectedHmacNodePath, 'hex');
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
    console.log(`[Secure Request] Verified valid message from session ${sessionId}:`, payload);
    res.status(200).json({
      status: 'success',
      message: 'Request authenticity and payload integrity verified',
      processedData: `Echo secured payload: ${payload.message}`
    });

  } catch (error) {
    console.error('[Secure Data Error]', error);
    res.status(500).json({ error: 'Internal server error processing secure payload' });
  }
});

app.listen(port, () => {
  console.log(`Vault Backend is listening on port ${port}`);
});
