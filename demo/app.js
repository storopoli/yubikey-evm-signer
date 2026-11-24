// ============================================
// WASM Module Import & Initialization
// ============================================

import init, {
    YubiKeyDevice,
    isWebUsbSupported,
    getVersion
} from './wasm/yubikey_evm_signer_wasm.js';

// ============================================
// State Management
// ============================================

const state = {
    wasmReady: false,
    webUsbAvailable: false,
    device: null,
    // True while a call into the WASM module / device is pending (see runDeviceTask)
    busy: false,
    // Last PIV slot reported by the device itself (`getSlot()`)
    slot: null,
    pinVerified: false,
    mgmtAuthenticated: false,
    address: null,
    publicKey: null
};

// ============================================
// DOM Elements
// ============================================

const elements = {
    // Compatibility
    compatibilitySection: document.getElementById('compatibility-section'),
    compatibilityMessage: document.getElementById('compatibility-message'),

    // Connection
    connectionStatus: document.getElementById('connection-status'),
    transportMode: document.getElementById('transport-mode'),
    bridgeConfig: document.getElementById('bridge-config'),
    bridgeUrl: document.getElementById('bridge-url'),
    bridgeToken: document.getElementById('bridge-token'),
    transportHint: document.getElementById('transport-hint'),
    connectBtn: document.getElementById('connect-btn'),
    disconnectBtn: document.getElementById('disconnect-btn'),

    // PIN
    pinSection: document.getElementById('pin-section'),
    pinInput: document.getElementById('pin-input'),
    verifyPinBtn: document.getElementById('verify-pin-btn'),
    pinStatus: document.getElementById('pin-status'),

    // Slot & Key Management
    keySection: document.getElementById('key-section'),
    slotSelect: document.getElementById('slot-select'),
    getAddressBtn: document.getElementById('get-address-btn'),
    addressDisplay: document.getElementById('address-display'),
    publicKeyDisplay: document.getElementById('public-key-display'),
    mgmtAlgSelect: document.getElementById('mgmt-alg-select'),
    mgmtKeyInput: document.getElementById('mgmt-key-input'),
    mgmtStatus: document.getElementById('mgmt-status'),
    authMgmtBtn: document.getElementById('auth-mgmt-btn'),
    generateKeyBtn: document.getElementById('generate-key-btn'),

    // Transaction
    txSection: document.getElementById('tx-section'),
    txChainId: document.getElementById('tx-chain-id'),
    txNonce: document.getElementById('tx-nonce'),
    txTo: document.getElementById('tx-to'),
    txValue: document.getElementById('tx-value'),
    txGasLimit: document.getElementById('tx-gas-limit'),
    txMaxPriorityFee: document.getElementById('tx-max-priority-fee'),
    txMaxFee: document.getElementById('tx-max-fee'),
    txInput: document.getElementById('tx-input'),
    signTxBtn: document.getElementById('sign-tx-btn'),
    txSignature: document.getElementById('tx-signature'),

    // Typed Data
    typedDataSection: document.getElementById('typed-data-section'),
    typedDataInput: document.getElementById('typed-data-input'),
    loadExample712Btn: document.getElementById('load-example-712-btn'),
    signTypedDataBtn: document.getElementById('sign-typed-data-btn'),
    typedDataSignature: document.getElementById('typed-data-signature'),

    // Message
    messageSection: document.getElementById('message-section'),
    messageInput: document.getElementById('message-input'),
    signMessageBtn: document.getElementById('sign-message-btn'),
    messageSignature: document.getElementById('message-signature'),

    // Hash
    hashSection: document.getElementById('hash-section'),
    hashInput: document.getElementById('hash-input'),
    signHashBtn: document.getElementById('sign-hash-btn'),
    hashSignature: document.getElementById('hash-signature'),

    // Log
    logOutput: document.getElementById('log-output'),
    clearLogBtn: document.getElementById('clear-log-btn'),

    // Version
    version: document.getElementById('version')
};

// ============================================
// Logging Utilities (DOM-safe, no innerHTML)
// ============================================

function log(message, level = 'info') {
    const timestamp = new Date().toLocaleTimeString();
    const entry = document.createElement('div');
    entry.className = `log-entry ${level}`;

    const tsSpan = document.createElement('span');
    tsSpan.className = 'timestamp';
    tsSpan.textContent = `[${timestamp}]`;

    entry.appendChild(tsSpan);
    entry.appendChild(document.createTextNode(String(message)));

    elements.logOutput.appendChild(entry);
    elements.logOutput.scrollTop = elements.logOutput.scrollHeight;
}

// ============================================
// UI State Management
// ============================================

function updateTransportUI() {
    const isBridge = elements.transportMode.value === 'bridge';
    elements.bridgeConfig.classList.toggle('hidden', !isBridge);

    if (isBridge) {
        elements.transportHint.textContent =
            'Connects to the hardened local PC/SC bridge using constant-time Bearer auth and a PIV-only APDU allowlist.';
    } else {
        elements.transportHint.textContent = state.webUsbAvailable
            ? 'Experimental: Chromium blocks YubiKey VID 0x1050 and CCID class 0x0B on standard web pages. Prefer Local PC/SC Bridge.'
            : 'WebUSB is not available in this browser or context. Switch back to Local PC/SC Bridge.';
    }
    updateControls();
}

/**
 * Derives the enabled/disabled state of every control from `state`.
 *
 * While a device call is in flight (`state.busy`), every control that would call
 * into the device is disabled, because wasm-bindgen rejects any call on a
 * `YubiKeyDevice` while another one is pending on it.
 */
function updateControls() {
    const connected = Boolean(state.device);
    const busy = state.busy;
    const isBridge = elements.transportMode.value === 'bridge';
    const canConnect =
        state.wasmReady && !connected && (isBridge || state.webUsbAvailable);

    // Connection
    elements.transportMode.disabled = connected || busy;
    elements.bridgeUrl.disabled = connected || busy;
    elements.bridgeToken.disabled = connected || busy;
    elements.connectBtn.disabled = !canConnect || busy;
    elements.disconnectBtn.disabled = !connected || busy;

    // PIN
    elements.pinSection.classList.toggle('disabled-section', !connected);
    elements.pinInput.disabled = !connected || busy;
    elements.verifyPinBtn.disabled = !connected || busy;

    // Slot & key management
    elements.keySection.classList.toggle('disabled-section', !connected);
    elements.slotSelect.disabled = !connected || busy;
    elements.getAddressBtn.disabled = !connected || busy;
    elements.mgmtAlgSelect.disabled = !connected;
    elements.mgmtKeyInput.disabled = !connected || busy;
    elements.authMgmtBtn.disabled = !connected || busy;
    elements.generateKeyBtn.disabled = !connected || !state.mgmtAuthenticated || busy;

    // Signing sections (enabled once the PIN is verified)
    const signing = connected && state.pinVerified;
    const signingSections = [
        [elements.txSection, elements.signTxBtn, [
            elements.txChainId,
            elements.txNonce,
            elements.txTo,
            elements.txValue,
            elements.txGasLimit,
            elements.txMaxPriorityFee,
            elements.txMaxFee,
            elements.txInput
        ]],
        [elements.typedDataSection, elements.signTypedDataBtn, [elements.typedDataInput]],
        [elements.messageSection, elements.signMessageBtn, [elements.messageInput]],
        [elements.hashSection, elements.signHashBtn, [elements.hashInput]]
    ];
    for (const [section, button, inputs] of signingSections) {
        section.classList.toggle('disabled-section', !signing);
        for (const input of inputs) {
            input.disabled = !signing;
        }
        button.disabled = !signing || busy;
    }
}

function updateConnectionUI(connected) {
    elements.connectionStatus.textContent = connected ? 'Connected' : 'Disconnected';
    elements.connectionStatus.className = `status ${connected ? 'connected' : 'disconnected'}`;

    if (!connected) {
        // Clear sensitive inputs and all cached outputs on disconnect
        elements.pinInput.value = '';
        elements.mgmtKeyInput.value = '';
        showKey(null, null);
        elements.txSignature.value = '';
        elements.typedDataSignature.value = '';
        elements.messageSignature.value = '';
        elements.hashSignature.value = '';

        updatePinUI(false);
        updateMgmtUI(false);
    }
    updateControls();
}

function updatePinUI(verified) {
    state.pinVerified = verified;
    elements.pinStatus.textContent = verified ? 'Verified' : 'Not verified';
    elements.pinStatus.className = `status ${verified ? 'verified' : ''}`;
    // Enables signing once the PIN is verified (and disables it again on failure)
    updateControls();
}

function updateMgmtUI(authenticated) {
    state.mgmtAuthenticated = authenticated;
    elements.mgmtStatus.textContent = authenticated ? 'Authenticated' : 'Not authenticated';
    elements.mgmtStatus.className = `status ${authenticated ? 'verified' : ''}`;
    updateControls();
}

/** Shows the active slot's derived address and P-256 public key (`null` clears them). */
function showKey(address, publicKey) {
    state.address = address;
    state.publicKey = publicKey;
    elements.addressDisplay.textContent = address || '-';
    elements.publicKeyDisplay.textContent = publicKey || '-';
}

/** Shows `slot` (as reported by the device) in the slot dropdown. */
function showDeviceSlot(slot) {
    state.slot = slot;
    elements.slotSelect.value = slot;
}

// ============================================
// Validation Helpers
// ============================================

function parseStrictNonNegativeSafeInt(raw, fieldName, minValue) {
    const trimmed = String(raw).trim();
    if (!/^\d+$/.test(trimmed)) {
        throw new Error(`${fieldName} must be a base-10 integer`);
    }
    const parsed = Number.parseInt(trimmed, 10);
    if (!Number.isSafeInteger(parsed) || parsed < minValue) {
        throw new Error(`${fieldName} must be an integer >= ${minValue}`);
    }
    return parsed;
}

function validateUint256Input(raw, fieldName) {
    const trimmed = String(raw).trim();
    if (/^\d+$/.test(trimmed) || /^0[xX][0-9a-fA-F]+$/.test(trimmed)) {
        return trimmed;
    }
    throw new Error(`${fieldName} must be a non-negative decimal integer or 0x-prefixed hex value`);
}

function validateOptionalAddress(raw) {
    const trimmed = String(raw).trim();
    if (!trimmed) {
        return null;
    }
    if (!/^0x[a-fA-F0-9]{40}$/.test(trimmed)) {
        throw new Error('To Address must be a 20-byte 0x-prefixed Ethereum address (or empty for contract creation)');
    }
    return trimmed;
}

/**
 * Mirrors `validate_bridge_url` in crates/signer-wasm: returns the canonical
 * `http://127.0.0.1:<port>` (no trailing slash, no leading zeros). Port 80 is
 * rejected because browsers omit the default HTTP port from the `Host` header,
 * which the bridge requires to be exactly `127.0.0.1:<port>`.
 */
function validateBridgeUrl(raw) {
    const trimmed = String(raw).trim();
    const match = /^http:\/\/127\.0\.0\.1:(\d{1,5})\/?$/.exec(trimmed);
    const port = match ? Number.parseInt(match[1], 10) : 0;
    if (port < 1 || port > 65535 || port === 80) {
        throw new Error(
            'Bridge URL must be http://127.0.0.1:<port> with a port other than 80 (localhost and [::1] are not accepted)'
        );
    }
    return `http://127.0.0.1:${port}`;
}

function validateCalldataHex(raw) {
    const trimmed = String(raw).trim();
    if (!trimmed || trimmed === '0x' || trimmed === '0X') {
        return '0x';
    }
    if (!/^0[xX]([a-fA-F0-9]{2})+$/.test(trimmed)) {
        throw new Error('Input Data must be a valid even-length 0x-prefixed hex string');
    }
    return trimmed;
}

// ============================================
// Device Call Serialization
// ============================================

function errorMessage(error) {
    return (error && error.message) || String(error);
}

/**
 * Runs `task(state.device)` while holding the single global in-flight lock.
 *
 * Every async `YubiKeyDevice` method takes `&mut self`, so wasm-bindgen throws
 * "recursive use of an object detected" for ANY call (sync or async) on the
 * device while another call on it is pending (e.g. a signature waiting for a
 * touch). Every device call therefore goes through this function: it refuses to
 * start while another task is pending and disables all device controls until
 * the task settles.
 *
 * Inside `task`, only call methods on the `device` argument and await each async
 * call before making the next one.
 *
 * Resolves to `{ current, ok, value, error }`. `current` is false when the task
 * did not run (another one was pending) or when `state.device` changed while it
 * was pending; callers must not write a non-current result into the UI.
 *
 * If the task leaves the device disconnected (the bridge session expired or was
 * replaced, the card was reset, the YubiKey or bridge went away), the page
 * switches to its disconnected state before resolving; the result is still
 * `current` so the caller logs the device's error message. Pass
 * `{ closing: true }` for the task that disconnects on purpose.
 */
async function runDeviceTask(task, { closing = false } = {}) {
    if (state.busy) {
        log('Another YubiKey operation is still in progress; wait for it to finish', 'warn');
        return { current: false, ok: false };
    }

    const device = state.device;
    state.busy = true;
    updateControls();

    let outcome;
    try {
        outcome = { ok: true, value: await task(device) };
    } catch (error) {
        outcome = { ok: false, error };
    } finally {
        state.busy = false;
    }

    const current = state.device === device;
    if (!current) {
        log('Discarding the result of an operation started on a previous connection', 'warn');
    } else if (device && !closing && !isStillConnected(device)) {
        state.device = null;
        state.slot = null;
        updateConnectionUI(false);
        log('The YubiKey session ended; connect again to continue', 'warn');
    }
    updateControls();
    return { current, ...outcome };
}

/** `device.isConnected()`, treating a throwing call as still connected. */
function isStillConnected(device) {
    try {
        return device.isConnected();
    } catch {
        return true;
    }
}

// ============================================
// Device Operations
// ============================================

async function connectDevice() {
    if (!state.wasmReady) {
        log('WASM module is not loaded yet', 'error');
        return;
    }
    if (state.device) return;

    const mode = elements.transportMode.value;
    let url;
    let token;
    if (mode === 'bridge') {
        try {
            url = validateBridgeUrl(elements.bridgeUrl.value);
        } catch (validationError) {
            log(validationError.message, 'error');
            return;
        }
        token = elements.bridgeToken.value.trim();
        if (!token) {
            log('Please paste the session bearer token printed by `yubikey-cli bridge`', 'error');
            return;
        }
    } else if (!state.webUsbAvailable) {
        log('WebUSB is not supported in this browser; switch to Local PC/SC Bridge', 'error');
        return;
    }

    const requestedSlot = elements.slotSelect.value;
    const result = await runDeviceTask(async () => {
        let device;
        if (mode === 'bridge') {
            log(`Connecting via local PC/SC bridge at ${url}...`);
            device = await YubiKeyDevice.connectBridge(url, token);
            log('Connected to YubiKey via local PC/SC bridge', 'success');
        } else {
            log('Requesting YubiKey WebUSB connection...');
            device = await YubiKeyDevice.connect();
            log('Successfully connected to YubiKey via WebUSB', 'success');
        }

        try {
            // Sync the selected PIV slot with the device
            try {
                device.setSlot(requestedSlot);
            } catch (error) {
                log(`Failed to set PIV slot ${requestedSlot}: ${errorMessage(error)}`, 'error');
            }
            return { device, slot: device.getSlot() };
        } catch (error) {
            // Do not leak an open bridge session / claimed USB interface
            await device.disconnect().catch(() => {});
            throw error;
        }
    });

    if (!result.ok) {
        if (result.current) {
            log(`Connection failed: ${errorMessage(result.error)}`, 'error');
            updateConnectionUI(false);
        }
        return;
    }
    if (!result.current) {
        // Another connection appeared meanwhile; close the one we just opened.
        await result.value.device.disconnect().catch(() => {});
        return;
    }

    state.device = result.value.device;
    showDeviceSlot(result.value.slot);
    log(`Active PIV slot: ${result.value.slot}`, 'info');
    updateConnectionUI(true);
}

async function disconnectDevice() {
    if (!state.device) return;

    const result = await runDeviceTask(async (device) => {
        log('Disconnecting from YubiKey...');
        try {
            await device.disconnect();
            return { closed: true };
        } catch (error) {
            // disconnect() ran but reported an error: trust the transport state.
            return { closed: !device.isConnected(), error };
        }
    }, { closing: true });
    if (!result.current) return;

    if (!result.ok || !result.value.closed) {
        const error = result.ok ? result.value.error : result.error;
        log(`Disconnect failed; the YubiKey session is still open: ${errorMessage(error)}`, 'error');
        return;
    }
    if (result.value.error) {
        log(`Disconnect warning: ${errorMessage(result.value.error)}`, 'warn');
    }

    state.device = null;
    state.slot = null;
    log('Disconnected', 'success');
    updateConnectionUI(false);
}

async function changeSlot() {
    if (!state.device) return;

    const requested = elements.slotSelect.value;
    const result = await runDeviceTask((device) => {
        try {
            device.setSlot(requested);
            return { slot: device.getSlot() };
        } catch (error) {
            return { slot: device.getSlot(), error };
        }
    });

    if (!result.current) {
        // The device's slot is unchanged (or unknown); show the last slot it reported.
        if (state.slot) {
            elements.slotSelect.value = state.slot;
        }
        return;
    }
    if (!result.ok) {
        if (state.slot) {
            elements.slotSelect.value = state.slot;
        }
        log(`Failed to set PIV slot: ${errorMessage(result.error)}`, 'error');
        return;
    }

    const previousSlot = state.slot;
    showDeviceSlot(result.value.slot);
    if (result.value.error) {
        log(
            `Failed to set PIV slot ${requested}: ${errorMessage(result.value.error)}; still on slot ${result.value.slot}`,
            'error'
        );
        return;
    }
    if (result.value.slot !== previousSlot) {
        showKey(null, null);
    }
    log(`Active PIV slot set to ${result.value.slot}`, 'info');
}

async function verifyPin() {
    if (!state.device) return;

    const pin = elements.pinInput.value;
    if (!pin || pin.length < 6 || pin.length > 8) {
        log('PIN must be 6-8 characters', 'error');
        updatePinUI(false);
        return;
    }

    const result = await runDeviceTask(async (device) => {
        log('Verifying PIN...');
        await device.verifyPin(pin);
    });
    if (!result.current) return;

    if (result.ok) {
        log('PIN verified successfully', 'success');
        updatePinUI(true);
    } else {
        log(`PIN verification failed: ${errorMessage(result.error)}`, 'error');
        updatePinUI(false);
    }
}

async function authenticateManagementKey() {
    if (!state.device) return;

    const alg = elements.mgmtAlgSelect.value;
    const keyHex = elements.mgmtKeyInput.value.trim();
    if (!keyHex) {
        log('Please enter the management key hex', 'error');
        updateMgmtUI(false);
        return;
    }

    const result = await runDeviceTask(async (device) => {
        log(`Authenticating management key (${alg})...`);
        await device.authenticateManagementKey(keyHex, alg);
    });
    if (!result.current) return;

    if (result.ok) {
        log('Management key authenticated successfully', 'success');
        updateMgmtUI(true);
    } else {
        log(`Management key authentication failed: ${errorMessage(result.error)}`, 'error');
        updateMgmtUI(false);
    }
}

async function generateKey() {
    if (!state.device || !state.mgmtAuthenticated) {
        log('Authenticate the management key before generating a new key', 'error');
        return;
    }

    const pin = elements.pinInput.value;
    const optionalPin = pin ? pin : undefined;

    // The slot is read from the device (not the dropdown) and the confirmation,
    // log lines and key generation all happen under the same in-flight lock.
    const result = await runDeviceTask(async (device) => {
        const slot = device.getSlot();
        const confirmed = window.confirm(
            `WARNING: Generating a new P-256 key in PIV slot ${slot} will permanently overwrite any existing key in that slot. Continue?`
        );
        if (!confirmed) {
            return { slot, cancelled: true };
        }
        log(`Generating new P-256 key in slot ${slot}...`);
        let address;
        try {
            address = await device.generateKey(optionalPin);
        } catch (error) {
            return { slot, error };
        }
        // The new key exists from here on. lastGeneratedPublicKey() needs no card
        // access and survives a session that ended while the old certificate was
        // being deleted; on old firmware it may be the only copy of the key.
        const staleCertificate = device.hasStaleCertificate();
        const publicKey = device.lastGeneratedPublicKey() ?? null;
        return { slot, address, publicKey, staleCertificate };
    });
    // runDeviceTask has already switched the page to its disconnected state if
    // the session ended; the key is shown below, after that transition, so the
    // transition cannot wipe it.
    if (!result.current) return;

    if (!result.ok) {
        log(`Key generation failed: ${errorMessage(result.error)}`, 'error');
        return;
    }
    if (result.value.cancelled) {
        log('Key generation cancelled by user', 'info');
        return;
    }
    if (result.value.error) {
        log(
            `Key generation in slot ${result.value.slot} failed: ${errorMessage(result.value.error)}`,
            'error'
        );
        return;
    }

    const { slot, address, publicKey, staleCertificate } = result.value;
    showKey(address, publicKey);
    log(`Key generated in slot ${slot}. Derived address: ${address}`, 'success');
    if (publicKey) {
        log(`P-256 public key: ${publicKey}`, 'info');
    }
    if (!state.device) {
        log(
            `The session ended after the key was generated; save the public key above now (on firmware older than 5.3 it cannot be read back until a certificate for it is stored in slot ${slot})`,
            'warn'
        );
    }
    if (staleCertificate) {
        log(
            `The old certificate in slot ${slot} could not be deleted and still describes the previous key; remove or replace it before other software relies on it`,
            'warn'
        );
    }
}

async function getAddress() {
    if (!state.device) return;

    const result = await runDeviceTask(async (device) => {
        const slot = device.getSlot();
        log(`Reading the P-256 public key in slot ${slot}...`);
        const address = await device.getAddress();
        // Same lookup and cache as getAddress(): no further card commands.
        const publicKey = await device.getPublicKey();
        return { slot, address, publicKey, staleCertificate: device.hasStaleCertificate() };
    });
    if (!result.current) return;

    if (result.ok) {
        const { slot, address, publicKey, staleCertificate } = result.value;
        showKey(address, publicKey);
        log(`Derived address: ${address}`, 'success');
        log(`P-256 public key: ${publicKey}`, 'info');
        if (staleCertificate) {
            log(
                `The certificate in slot ${slot} belongs to an older key; the address and public key above come from the slot's key metadata`,
                'warn'
            );
        }
    } else {
        log(`Get address failed: ${errorMessage(result.error)}`, 'error');
    }
}

// ============================================
// Signing Operations
// ============================================

async function signTransaction() {
    if (!state.device || !state.pinVerified) return;

    const pin = elements.pinInput.value;
    let txJson;
    try {
        const chainId = parseStrictNonNegativeSafeInt(elements.txChainId.value, 'Chain ID', 1);
        const nonce = parseStrictNonNegativeSafeInt(elements.txNonce.value, 'Nonce', 0);
        const gasLimit = parseStrictNonNegativeSafeInt(elements.txGasLimit.value, 'Gas Limit', 1);
        const maxPriorityFee = validateUint256Input(
            elements.txMaxPriorityFee.value,
            'Max Priority Fee'
        );
        const maxFee = validateUint256Input(elements.txMaxFee.value, 'Max Fee');
        const value = validateUint256Input(elements.txValue.value, 'Value');
        const to = validateOptionalAddress(elements.txTo.value);
        const input = validateCalldataHex(elements.txInput.value);

        // The transaction JSON schema rejects unknown keys and requires `to`
        // (explicit `null` for contract creation), so always send exactly these keys.
        txJson = JSON.stringify({
            type: 'eip1559',
            chain_id: chainId,
            nonce,
            max_priority_fee_per_gas: maxPriorityFee,
            max_fee_per_gas: maxFee,
            gas_limit: gasLimit,
            to,
            value,
            input,
            access_list: []
        });
    } catch (validationError) {
        log(`Invalid transaction field: ${validationError.message}`, 'error');
        elements.txSignature.value = '';
        return;
    }

    const result = await runDeviceTask(async (device) => {
        log('Signing EIP-1559 transaction...');
        return device.signTransaction(pin, txJson);
    });
    if (!result.current) return;

    if (result.ok) {
        elements.txSignature.value = result.value;
        log(`Transaction signed: ${result.value.substring(0, 20)}...`, 'success');
    } else {
        log(`Transaction signing failed: ${errorMessage(result.error)}`, 'error');
        elements.txSignature.value = '';
    }
}

async function signTypedData() {
    if (!state.device || !state.pinVerified) return;

    const pin = elements.pinInput.value;
    const typedDataJson = elements.typedDataInput.value;

    if (!typedDataJson.trim()) {
        log('Please enter typed data JSON', 'error');
        return;
    }

    try {
        JSON.parse(typedDataJson);
    } catch {
        log('Invalid JSON format', 'error');
        elements.typedDataSignature.value = '';
        return;
    }

    const result = await runDeviceTask(async (device) => {
        log('Signing typed data (EIP-712)...');
        return device.signTypedData(pin, typedDataJson);
    });
    if (!result.current) return;

    if (result.ok) {
        elements.typedDataSignature.value = result.value;
        log(`Typed data signed: ${result.value.substring(0, 20)}...`, 'success');
    } else {
        log(`Typed data signing failed: ${errorMessage(result.error)}`, 'error');
        elements.typedDataSignature.value = '';
    }
}

async function signMessage() {
    if (!state.device || !state.pinVerified) return;

    const pin = elements.pinInput.value;
    const message = elements.messageInput.value;

    if (!message.trim()) {
        log('Please enter a message to sign', 'error');
        return;
    }

    const result = await runDeviceTask(async (device) => {
        log('Signing message (EIP-191)...');
        return device.signMessage(pin, message);
    });
    if (!result.current) return;

    if (result.ok) {
        elements.messageSignature.value = result.value;
        log(`Message signed: ${result.value.substring(0, 20)}...`, 'success');
    } else {
        log(`Message signing failed: ${errorMessage(result.error)}`, 'error');
        elements.messageSignature.value = '';
    }
}

async function signHash() {
    if (!state.device || !state.pinVerified) return;

    const pin = elements.pinInput.value;
    const hash = elements.hashInput.value.trim();

    if (!hash) {
        log('Please enter a hash to sign', 'error');
        return;
    }

    const cleanHash = /^0[xX]/.test(hash) ? `0x${hash.slice(2)}` : `0x${hash}`;
    if (!/^0x[a-fA-F0-9]{64}$/.test(cleanHash)) {
        log('Hash must be 32 bytes (64 hex characters)', 'error');
        return;
    }

    const result = await runDeviceTask(async (device) => {
        log('Signing hash...');
        return device.signHash(pin, cleanHash);
    });
    if (!result.current) return;

    if (result.ok) {
        elements.hashSignature.value = result.value;
        log(`Hash signed: ${result.value.substring(0, 20)}...`, 'success');
    } else {
        log(`Hash signing failed: ${errorMessage(result.error)}`, 'error');
        elements.hashSignature.value = '';
    }
}

// ============================================
// Helper Functions
// ============================================

function loadEip712Example() {
    const example = {
        domain: {
            name: 'Example DApp',
            version: '1',
            chainId: 1,
            verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC'
        },
        types: {
            Person: [
                { name: 'name', type: 'string' },
                { name: 'wallet', type: 'address' }
            ],
            Mail: [
                { name: 'from', type: 'Person' },
                { name: 'to', type: 'Person' },
                { name: 'contents', type: 'string' }
            ]
        },
        primaryType: 'Mail',
        message: {
            from: {
                name: 'Alice',
                wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826'
            },
            to: {
                name: 'Bob',
                wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB'
            },
            contents: 'Hello, Bob!'
        }
    };

    elements.typedDataInput.value = JSON.stringify(example, null, 2);
    log('Loaded EIP-712 example', 'info');
}

// ============================================
// Event Listeners
// ============================================

function setupEventListeners() {
    // Connection & Transport
    elements.transportMode.addEventListener('change', updateTransportUI);
    elements.connectBtn.addEventListener('click', connectDevice);
    elements.disconnectBtn.addEventListener('click', disconnectDevice);

    // PIN
    elements.verifyPinBtn.addEventListener('click', verifyPin);
    elements.pinInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') verifyPin();
    });

    // Slot & Key Management
    elements.slotSelect.addEventListener('change', changeSlot);
    elements.getAddressBtn.addEventListener('click', getAddress);
    elements.authMgmtBtn.addEventListener('click', authenticateManagementKey);
    elements.mgmtKeyInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') authenticateManagementKey();
    });
    elements.generateKeyBtn.addEventListener('click', generateKey);

    // Signing
    elements.signTxBtn.addEventListener('click', signTransaction);
    elements.signTypedDataBtn.addEventListener('click', signTypedData);
    elements.signMessageBtn.addEventListener('click', signMessage);
    elements.signHashBtn.addEventListener('click', signHash);

    // Helpers
    elements.loadExample712Btn.addEventListener('click', loadEip712Example);
    elements.clearLogBtn.addEventListener('click', () => {
        elements.logOutput.replaceChildren();
        log('Log cleared', 'info');
    });

    // Best-effort disconnect on page unload. This handler must never throw: while
    // another call is pending on the device, wasm-bindgen rejects every new call
    // (including isConnected()) synchronously, so each step is guarded separately
    // and disconnect() is still attempted.
    window.addEventListener('beforeunload', () => {
        const device = state.device;
        if (!device) return;
        let connected = true;
        try {
            connected = device.isConnected();
        } catch {
            // Busy with a pending call; still try to disconnect below.
        }
        if (!connected) return;
        try {
            void Promise.resolve(device.disconnect()).catch(() => {});
        } catch {
            // Rejected synchronously because a call is still pending; nothing else to do.
        }
    });
}

// ============================================
// Initialization
// ============================================

async function initialize() {
    // Always wire event listeners so Bridge mode, Clear Log, and Load Example work in all browsers
    setupEventListeners();

    try {
        log('Initializing WASM module...');
        await init();
        state.wasmReady = true;
        log('WASM module loaded', 'success');

        const version = getVersion();
        elements.version.textContent = `Version: ${version}`;
        log(`Library version: ${version}`, 'info');

        state.webUsbAvailable = isWebUsbSupported();
        if (!state.webUsbAvailable) {
            const webusbOption = elements.transportMode.querySelector('option[value="webusb"]');
            if (webusbOption) {
                webusbOption.disabled = true;
            }
            elements.transportMode.value = 'bridge';
            elements.compatibilitySection.classList.remove('hidden');
            elements.compatibilityMessage.textContent =
                'WebUSB is not supported in this browser or context. Local PC/SC Bridge mode is active and works in all desktop browsers.';
            log('WebUSB unavailable; using Local PC/SC Bridge mode', 'info');
        } else {
            log('WebUSB API detected (note: Chromium blocks YubiKey VID 0x1050 & CCID class 0x0B on standard pages; Local PC/SC Bridge recommended)', 'info');
        }

        updateTransportUI();
        log('Ready. Start `just cli-bridge`, paste the session token, and click "Connect YubiKey".', 'info');
    } catch (error) {
        log(`Initialization failed: ${error.message || error}`, 'error');
        elements.compatibilitySection.classList.remove('hidden');
        elements.compatibilityMessage.textContent =
            `Failed to load WASM module: ${error.message || error}. Run \`just demo-build\` before serving.`;
        elements.connectBtn.disabled = true;
    }
}

// Start initialization when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize);
} else {
    initialize();
}
