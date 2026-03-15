# 🔒 Secure API Communication System

A full-stack, native web prototype demonstrating **ECDH Key Exchange** and **HMAC-SHA256 signature verification** to protect against Man-in-the-Middle (MITM) and Replay attacks. 

Built with **Node.js (Native Crypto)** and **Vite (Vanilla JS + Web Crypto API)**, wrapped in a premium "Cyber-Vault" dark-mode aesthetic.

---

## 🎯 Security Features (OWASP A02 Mitigations)

This prototype was built specifically to demonstrate mitigations for **OWASP API Security Top 10 - A02: Cryptographic Failures**:

1. **ECDH Key Exchange (secp256r1):** The client and server generate ephemeral key pairs and derive a shared secret over an insecure channel. The secret itself is *never* transmitted over the wire.
2. **Data Integrity (HMAC-SHA256):** Every API request is signed using the derived shared secret. Any modification to the payload in transit causes the server to reject the request to prevent MITM tampering.
3. **Replay Attack Protection:** A client timestamp is included in the signed payload. The server rejects any request where the time delta exceeds 30 seconds.
4. **HTTPS Communication (TLS encryption):** All API traffic is encrypted in transit using a self-signed certificate, ensuring eavesdroppers cannot read the payloads.
5. **User Authentication (SHA-256):** A secure registration and login system. Passwords are hashed with SHA-256 and a 128-bit random salt.
6. **Timing Attack Mitigation:** The server uses `crypto.timingSafeEqual()` to safely compare signature buffers and password hashes.
7. **Zero External Crypto Dependencies:** Relies entirely on native browser features (`window.crypto.subtle`) and Node.js built-ins (`crypto`).

---

## 🖥️ UI & Interactive Elements

The application features a **"Cyber-Vault" Aesthetic** (`#0D1117` background, glassmorphism UI cards, glowing electric blue accents). 

**Interactive Features Include:**
- **Authentication Gate:** Secure registration and login flow. All other features are locked until authenticated.
- **Terminal Live Log:** A real-time system log panel displaying cryptographic operations (key generation, secret derivation, payload interception).
- **Public Key & Shared Secret Validation:** Displays truncated public keys and a masked shared secret on the client to visually confirm ECDH key exchange success.
- **The "Attacker" Toggle:** An interactive switch that simulates a Man-in-the-Middle (MITM) attack by maliciously altering the payload *after* the client computes the HMAC signature.
- **Protected Resources:** Fetch classified data from a protected endpoint that validates both the Bearer token and the ECDH session state.
- **Security Dashboard Badges:** Glowing green **SECURE** badges for verified requests, and glitching red **INTEGRITY BREACH** alerts for tampered signatures.

---

## 🏗️ Architecture Flow

```mermaid
sequenceDiagram
    participant Client as Frontend (Browser)
    participant Server as Backend (Node.js)

    Client->>Server: POST /api/login { username, password }
    Note over Server: Hash password with salt, compare.<br/>Generate Bearer Token.
    Server-->>Client: { token }

    Note over Client: Generate ephemeral ECDH key pair (secp256r1)
    Client->>Server: POST /api/handshake { clientPublicKey } (Auth: Bearer)
    Note over Server: Generate server ECDH key pair<br/>Derive shared secret via ECDH
    Server-->>Client: { serverPublicKey, sessionId }
    Note over Client: Derive shared secret via ECDH

    Note over Client,Server: ✅ Both sides now share the identical secret

    Client->>Server: POST /api/secure-data { payload, timestamp, hmac, sessionId } (Auth: Bearer)
    Note over Server: 1. Verify Bearer token<br/>2. Check timestamp ≤ 30s old<br/>3. Recompute HMAC-SHA256(payload+ts, secret)<br/>4. Constant-time compare with received HMAC
    alt Signature Valid
        Server-->>Client: 200 OK { status: "verified" }
    else Tampered / Replay
        Server-->>Client: 403 Forbidden { error: "INTEGRITY_BREACH" }
    end
```

---

## 🚀 How to Run Locally

### Requirements
- Node.js (v18+ recommended)

### 1. Start the Backend & Generate TLS Certificate

Open a terminal and run:

```bash
cd backend
npm install
npm run generate-cert  # Generates self-signed cert for HTTPS
npm run dev
```

The TLS server will start on `https://localhost:3443`.
*(Note: As this uses a self-signed certificate, your browser will show a "Not Secure" warning. You must click "Advanced > Proceed to localhost" when accessing the API or Frontend).*

### 2. Start the Frontend

Open a second terminal and run:

```bash
cd frontend
npm install
npm run dev
```

The Vite client will be available at `http://localhost:5173`. Open this URL in your browser to interact with the prototype.
