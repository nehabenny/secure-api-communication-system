// frontend/main.js
const API_BASE_URL = '/api'; // Proxied through Vite → HTTPS backend

// State
let clientKeyPair = null;
let currentSessionId = null;
let derivedSharedSecret = null; // Stored as CryptoKey object
let authToken = null;           // Bearer token from login

// DOM Elements — Auth
const inputUsername = document.getElementById('input-username');
const inputPassword = document.getElementById('input-password');
const btnRegister = document.getElementById('btn-register');
const btnLogin = document.getElementById('btn-login');
const btnLogout = document.getElementById('btn-logout');
const authIndicator = document.getElementById('auth-indicator');
const authForm = document.getElementById('auth-form');
const authSuccess = document.getElementById('auth-success');
const authUsernameDisplay = document.getElementById('auth-username-display');

// DOM Elements — ECDH / Transmit
const btnHandshake = document.getElementById('btn-handshake');
const btnSend = document.getElementById('btn-send');
const inputMessage = document.getElementById('input-message');
const toggleAttacker = document.getElementById('toggle-attacker');
const terminalOutput = document.getElementById('terminal-output');
const displayClientKey = document.getElementById('display-client-key');
const displayServerKey = document.getElementById('display-server-key');
const displaySharedSecret = document.getElementById('display-shared-secret');

// DOM Elements — Sections
const sectionHandshake = document.getElementById('section-handshake');
const sectionTransmit = document.getElementById('section-transmit');
const sectionProtected = document.getElementById('section-protected');
const btnFetchResource = document.getElementById('btn-fetch-resource');
const protectedDataDisplay = document.getElementById('protected-data-display');

// DOM Elements — Status
const badge = document.getElementById('status-badge');
const statusMsg = document.getElementById('status-message');

/* ==========================================================================
   Terminal Logging Utility
   ========================================================================== */
function logToTerminal(message, type = 'info') {
    const now = new Date();
    const timeStr = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}.${now.getMilliseconds().toString().padStart(3, '0')}`;

    const entry = document.createElement('div');
    entry.className = `log-entry ${type}`;
    entry.innerHTML = `<span class="time">[${timeStr}]</span><span class="msg">${message}</span>`;

    terminalOutput.appendChild(entry);
    terminalOutput.scrollTop = terminalOutput.scrollHeight;
}

function truncateString(str, length = 32) {
    if (!str) return '';
    if (str.length <= length) return str;
    return str.substring(0, length / 2) + '...' + str.substring(str.length - (length / 2));
}

function maskSecret(str) {
    if (!str) return '';
    return str.substring(0, 4) + '•'.repeat(24) + str.substring(str.length - 4);
}

// Convert ArrayBuffer to Hex String
function buf2hex(buffer) {
    return [...new Uint8Array(buffer)].map(x => x.toString(16).padStart(2, '0')).join('');
}

// Base64 ArrayBuffer conversions
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}

/**
 * Helper for authenticated fetch — attaches Bearer token
 */
async function authenticatedFetch(url, options = {}) {
    if (!options.headers) options.headers = {};
    if (authToken) {
        options.headers['Authorization'] = `Bearer ${authToken}`;
    }
    return fetch(url, options);
}

/* ==========================================================================
   UI State Management
   ========================================================================== */
function setAuthenticatedUI(username) {
    authForm.style.display = 'none';
    authSuccess.style.display = 'flex';
    authUsernameDisplay.textContent = username;
    authIndicator.textContent = 'Authenticated ✓';
    authIndicator.className = 'auth-indicator online';

    // Unlock the handshake + protected resource sections
    sectionHandshake.classList.remove('locked-section');
    sectionProtected.classList.remove('locked-section');
}

function setLoggedOutUI() {
    authToken = null;
    clientKeyPair = null;
    currentSessionId = null;
    derivedSharedSecret = null;

    authForm.style.display = 'block';
    authSuccess.style.display = 'none';
    authIndicator.textContent = 'Not Authenticated';
    authIndicator.className = 'auth-indicator offline';

    sectionHandshake.classList.add('locked-section');
    sectionTransmit.classList.add('locked-section');
    sectionProtected.classList.add('locked-section');

    // Reset key displays
    displayClientKey.textContent = 'Not generated yet...';
    displayClientKey.classList.add('masked-text');
    displayServerKey.textContent = 'Waiting for handshake...';
    displayServerKey.classList.add('masked-text');
    displaySharedSecret.textContent = '**********';
    displaySharedSecret.classList.add('masked-text');
    protectedDataDisplay.innerHTML = '<p class="muted-text">Authenticate and click "Fetch Classified Data" to access the protected API endpoint.</p>';

    btnHandshake.textContent = 'Initialize Handshake';
    updateBadge('default', 'STANDBY', 'Authenticate to begin secure operations.');
}

/* ==========================================================================
   Authentication — Register & Login
   ========================================================================== */
async function registerUser() {
    const username = inputUsername.value.trim();
    const password = inputPassword.value;

    if (!username || !password) {
        logToTerminal('Registration failed: Username and password are required.', 'error');
        return;
    }

    logToTerminal(`Registering user "${username}"...`, 'info');

    try {
        const response = await fetch(`${API_BASE_URL}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok) {
            logToTerminal(`✓ User registered — SHA-256 hash stored with ${data.saltLength} salt.`, 'success');
            logToTerminal('You can now log in.', 'info');
        } else {
            logToTerminal(`Registration failed: ${data.error}`, 'error');
        }
    } catch (err) {
        logToTerminal(`Network error: ${err.message}`, 'error');
    }
}

async function loginUser() {
    const username = inputUsername.value.trim();
    const password = inputPassword.value;

    if (!username || !password) {
        logToTerminal('Login failed: Username and password are required.', 'error');
        return;
    }

    logToTerminal(`Authenticating "${username}" (SHA-256 credential verification)...`, 'info');

    try {
        const response = await fetch(`${API_BASE_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok) {
            authToken = data.token;
            logToTerminal(`✓ Authenticated as "${username}". Token expires in ${data.expiresIn}.`, 'success');
            logToTerminal(`Bearer token: ${truncateString(authToken, 30)}`, 'info');
            setAuthenticatedUI(username);
            updateBadge('default', 'AUTHENTICATED', 'User authenticated. Initialize handshake to establish secure channel.');
        } else {
            logToTerminal(`Login failed: ${data.reason || data.error}`, 'error');
            updateBadge('breach', 'AUTH_FAILED', 'Invalid credentials — access denied.');
        }
    } catch (err) {
        logToTerminal(`Network error: ${err.message}`, 'error');
    }
}

function logoutUser() {
    logToTerminal('Session terminated. User logged out.', 'warning');
    setLoggedOutUI();
}

/* ==========================================================================
   Cryptography - Handshake (ECDH)
   ========================================================================== */
async function performHandshake() {
    if (!authToken) {
        logToTerminal('Access denied: Must authenticate before handshake.', 'error');
        return;
    }

    try {
        logToTerminal('Initializing ECDH Secp256r1 parameters...', 'info');

        // 1. Generate Client Key Pair (P-256 == prime256v1 == secp256r1)
        clientKeyPair = await window.crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-256" },
            true, // Extractable
            ["deriveKey", "deriveBits"]
        );
        logToTerminal('Local ECDH key pair generated.', 'success');

        // Export public key to 'raw' buffer, then to base64 to send to server
        const clientPublicKeyBuffer = await window.crypto.subtle.exportKey("raw", clientKeyPair.publicKey);
        const clientPubKeyBase64 = arrayBufferToBase64(clientPublicKeyBuffer);

        displayClientKey.textContent = truncateString(clientPubKeyBase64, 40);
        displayClientKey.classList.remove('masked-text');

        logToTerminal(`Transmitting Public Key to Server (HTTPS/TLS)...`, 'info');

        // 2. Send to Server (with auth header)
        const response = await authenticatedFetch(`${API_BASE_URL}/handshake`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ clientPublicKeyBase64: clientPubKeyBase64 })
        });

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            if (response.status === 401) {
                logToTerminal(`Unauthorized: ${errData.reason || 'Please log in again.'}`, 'error');
                updateBadge('breach', 'UNAUTHORIZED', 'Authentication required.');
                return;
            }
            throw new Error(errData.error || 'Server handshake failed');
        }
        const data = await response.json();

        currentSessionId = data.sessionId;

        displayServerKey.textContent = truncateString(data.serverPublicKeyBase64, 40);
        displayServerKey.classList.remove('masked-text');
        logToTerminal(`Received Server Public Key & Session ID.`, 'success');

        // 3. Import Server's Public Key
        const serverPubKeyBuffer = base64ToArrayBuffer(data.serverPublicKeyBase64);
        const serverPublicKey = await window.crypto.subtle.importKey(
            "raw",
            serverPubKeyBuffer,
            { name: "ECDH", namedCurve: "P-256" },
            true,
            []
        );

        logToTerminal('Deriving shared secret...', 'info');

        // 4. Derive Shared Secret Bits
        const sharedSecretBuffer = await window.crypto.subtle.deriveBits(
            { name: "ECDH", public: serverPublicKey },
            clientKeyPair.privateKey,
            256 // Need 256 bits (32 bytes) for SHA-256
        );

        // 5. Import the shared secret as an HMAC key for signing later
        derivedSharedSecret = await window.crypto.subtle.importKey(
            "raw",
            sharedSecretBuffer,
            { name: "HMAC", hash: "SHA-256" },
            true, // allow export so we can display it (not for prod!)
            ["sign", "verify"]
        );

        // Get hex representation to show in UI
        const hexSecret = buf2hex(sharedSecretBuffer);
        displaySharedSecret.textContent = maskSecret(hexSecret);
        displaySharedSecret.classList.remove('masked-text');

        logToTerminal('Shared Secret perfectly derived.', 'success');

        // Update UI State — unlock transmit
        sectionTransmit.classList.remove('locked-section');
        btnHandshake.textContent = 'Re-negotiate Handshake';

        updateBadge('secure', 'SECURE_CHANNEL_READY', 'All subsequent traffic will be signature verified.');

    } catch (err) {
        logToTerminal(`Handshake Error: ${err.message}`, 'error');
        updateBadge('breach', 'HANDSHAKE_FAILED', 'Could not establish secure channel.');
    }
}

/* ==========================================================================
   Cryptography - Sending Secure Data (HMAC)
   ========================================================================== */
async function sendSecureData() {
    if (!derivedSharedSecret || !currentSessionId) {
        logToTerminal('Cannot send data. Handshake not established.', 'warning');
        return;
    }

    const rawMessage = inputMessage.value.trim() || 'Default confidential payload';

    // 1. Prepare Payload & Metadata
    const payloadBox = { message: rawMessage, type: 'CONFIDENTIAL_DATA' };
    const timestamp = Date.now().toString(); // Integer string

    // Message to sign matches server: JSON.stringify(payload) + timestamp
    const messageToSign = JSON.stringify(payloadBox) + timestamp;
    const encoder = new TextEncoder();
    const dataToSign = encoder.encode(messageToSign);

    try {
        logToTerminal(`Computing HMAC-SHA256 signature...`, 'info');

        // 2. Compute Signature
        const signatureBuffer = await window.crypto.subtle.sign(
            "HMAC",
            derivedSharedSecret,
            dataToSign
        );
        const hmacHex = buf2hex(signatureBuffer);

        // 3. Check for Attacker Toggle
        const isAttacker = toggleAttacker.checked;

        let simulatedPayload = payloadBox;

        if (isAttacker) {
            logToTerminal('⚠️ MAN-IN-THE-MIDDLE ACTIVE', 'warning');
            logToTerminal('Intercepting packet...', 'warning');
            // Modify payload WITHOUT re-calculating the HMAC signature
            simulatedPayload = { ...payloadBox, message: rawMessage + " [TAMPERED BY ATTACKER]" };
            logToTerminal(`Modifying transit data to: "${simulatedPayload.message}"`, 'warning');
        }

        logToTerminal(`Sending Request (HTTPS): ${truncateString(hmacHex, 20)}...`, 'info');

        // 4. Transmit (with auth header)
        const response = await authenticatedFetch(`${API_BASE_URL}/secure-data`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                payload: simulatedPayload,
                timestamp,
                hmac: hmacHex,
                sessionId: currentSessionId
            })
        });

        const data = await response.json();

        if (response.ok) {
            logToTerminal(`Server: Request Integrity Verified ✓ (user: ${data.user})`, 'success');
            updateBadge('secure', 'SECURE', 'Integrity verified by Vault Backend.');
        } else if (response.status === 401) {
            logToTerminal(`Unauthorized: ${data.reason || 'Session expired.'}`, 'error');
            updateBadge('breach', 'UNAUTHORIZED', 'Authentication token expired or invalid.');
        } else {
            logToTerminal(`Server rejected packet: ${data.reason}`, 'error');
            updateBadge('breach', 'INTEGRITY BREACH', 'Data alteration detected in transit! Signature mismatch.');
        }

    } catch (err) {
        logToTerminal(`Transmission Error: ${err.message}`, 'error');
    }
}

/* ==========================================================================
   Protected Resource Fetcher
   ========================================================================== */
async function fetchProtectedResource() {
    if (!authToken) {
        logToTerminal('Access denied: Must authenticate first.', 'error');
        return;
    }

    logToTerminal('Requesting classified data from /api/protected-resource...', 'info');

    try {
        const response = await authenticatedFetch(`${API_BASE_URL}/protected-resource`);
        const data = await response.json();

        if (response.ok) {
            logToTerminal('✓ Protected resource accessed successfully.', 'success');

            // Render classified data in the UI
            const records = data.data.records.map(r =>
                `<div class="record-row">
                    <span class="record-id">#${r.id}</span>
                    <span class="record-name">${r.name}</span>
                    <span class="record-clearance clearance-badge">${r.clearance}</span>
                </div>`
            ).join('');

            protectedDataDisplay.innerHTML = `
                <div class="classified-header">
                    <span class="classified-tag">${data.data.classification}</span>
                    <span class="classified-time">${data.data.accessTimestamp}</span>
                </div>
                <p class="classified-msg">${data.data.message}</p>
                <div class="records-list">${records}</div>
            `;

        } else {
            logToTerminal(`Access denied: ${data.reason || data.error}`, 'error');
            protectedDataDisplay.innerHTML = `<p class="error-text">⛔ Unauthorized — ${data.reason || data.error}</p>`;
        }
    } catch (err) {
        logToTerminal(`Network error: ${err.message}`, 'error');
    }
}

/* ==========================================================================
   Status Badge Utility
   ========================================================================== */
function updateBadge(state, title, desc) {
    badge.className = `badge ${state}`;
    badge.textContent = title;
    statusMsg.textContent = desc;
}

/* ==========================================================================
   Event Listeners
   ========================================================================== */
btnRegister.addEventListener('click', registerUser);
btnLogin.addEventListener('click', loginUser);
btnLogout.addEventListener('click', logoutUser);
btnHandshake.addEventListener('click', performHandshake);
btnSend.addEventListener('click', sendSecureData);
btnFetchResource.addEventListener('click', fetchProtectedResource);

toggleAttacker.addEventListener('change', (e) => {
    if (e.target.checked) {
        logToTerminal('Simulation: Route hijacked. Monitoring transit data.', 'warning');
    } else {
        logToTerminal('Simulation: Route restored to normal path.', 'info');
    }
});

// Allow Enter key on password field to trigger login
inputPassword.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') loginUser();
});
