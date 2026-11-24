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
    pinVerified: false,
    mgmtAuthenticated: false,
    address: null
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
    const mode = elements.transportMode.value;
    const isBridge = mode === 'bridge';
    elements.bridgeConfig.classList.toggle('hidden', !isBridge);

    if (isBridge) {
        elements.transportHint.textContent =
            'Connects to the hardened local PC/SC bridge using constant-time Bearer auth and a PIV-only APDU allowlist.';
        elements.connectBtn.disabled = !state.wasmReady || Boolean(state.device);
    } else {
        elements.transportHint.textContent = state.webUsbAvailable
            ? 'Experimental: Chromium blocks YubiKey VID 0x1050 and CCID class 0x0B on standard web pages. Prefer Local PC/SC Bridge.'
            : 'WebUSB is not available in this browser or context. Switch back to Local PC/SC Bridge.';
        elements.connectBtn.disabled =
            !state.wasmReady || !state.webUsbAvailable || Boolean(state.device);
    }
}

function updateConnectionUI(connected) {
    elements.connectionStatus.textContent = connected ? 'Connected' : 'Disconnected';
    elements.connectionStatus.className = `status ${connected ? 'connected' : 'disconnected'}`;

    elements.transportMode.disabled = connected;
    elements.bridgeUrl.disabled = connected;
    elements.bridgeToken.disabled = connected;
    elements.disconnectBtn.disabled = !connected;
    updateTransportUI();

    // Enable/disable PIN and Key Management sections based on connection
    elements.pinSection.classList.toggle('disabled-section', !connected);
    elements.pinInput.disabled = !connected;
    elements.verifyPinBtn.disabled = !connected;

    updateKeyManagementUI(connected);

    if (!connected) {
        // Clear sensitive inputs and all cached outputs on disconnect
        state.pinVerified = false;
        state.mgmtAuthenticated = false;
        state.address = null;

        elements.pinInput.value = '';
        elements.mgmtKeyInput.value = '';
        elements.addressDisplay.textContent = '-';
        elements.txSignature.value = '';
        elements.typedDataSignature.value = '';
        elements.messageSignature.value = '';
        elements.hashSignature.value = '';

        updatePinUI(false);
        updateMgmtUI(false);
        updateSigningSectionsUI(false);
    }
}

function updatePinUI(verified) {
    state.pinVerified = verified;
    elements.pinStatus.textContent = verified ? 'Verified' : 'Not verified';
    elements.pinStatus.className = `status ${verified ? 'verified' : ''}`;
    // Enable signing once PIN is verified (and reset signing sections on failure!)
    updateSigningSectionsUI(Boolean(state.device) && verified);
}

function updateMgmtUI(authenticated) {
    state.mgmtAuthenticated = authenticated;
    elements.mgmtStatus.textContent = authenticated ? 'Authenticated' : 'Not authenticated';
    elements.mgmtStatus.className = `status ${authenticated ? 'verified' : ''}`;
    elements.generateKeyBtn.disabled = !state.device || !authenticated;
}

function updateKeyManagementUI(enabled) {
    elements.keySection.classList.toggle('disabled-section', !enabled);
    elements.slotSelect.disabled = !enabled;
    elements.getAddressBtn.disabled = !enabled;
    elements.mgmtAlgSelect.disabled = !enabled;
    elements.mgmtKeyInput.disabled = !enabled;
    elements.authMgmtBtn.disabled = !enabled;
    elements.generateKeyBtn.disabled = !enabled || !state.mgmtAuthenticated;
}

function updateSigningSectionsUI(enabled) {
    // Transaction section
    elements.txSection.classList.toggle('disabled-section', !enabled);
    elements.txChainId.disabled = !enabled;
    elements.txNonce.disabled = !enabled;
    elements.txTo.disabled = !enabled;
    elements.txValue.disabled = !enabled;
    elements.txGasLimit.disabled = !enabled;
    elements.txMaxPriorityFee.disabled = !enabled;
    elements.txMaxFee.disabled = !enabled;
    elements.txInput.disabled = !enabled;
    elements.signTxBtn.disabled = !enabled;

    // Typed data section
    elements.typedDataSection.classList.toggle('disabled-section', !enabled);
    elements.typedDataInput.disabled = !enabled;
    elements.signTypedDataBtn.disabled = !enabled;

    // Message section
    elements.messageSection.classList.toggle('disabled-section', !enabled);
    elements.messageInput.disabled = !enabled;
    elements.signMessageBtn.disabled = !enabled;

    // Hash section
    elements.hashSection.classList.toggle('disabled-section', !enabled);
    elements.hashInput.disabled = !enabled;
    elements.signHashBtn.disabled = !enabled;
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
// Device Operations
// ============================================

async function connectDevice() {
    if (!state.wasmReady) {
        log('WASM module is not loaded yet', 'error');
        return;
    }

    const mode = elements.transportMode.value;
    try {
        if (mode === 'bridge') {
            const url = elements.bridgeUrl.value.trim();
            const token = elements.bridgeToken.value.trim();
            if (!url) {
                log('Please enter the local PC/SC bridge URL (e.g. http://127.0.0.1:8765)', 'error');
                return;
            }
            if (!token) {
                log('Please paste the session bearer token printed by `yubikey-cli bridge`', 'error');
                return;
            }
            log(`Connecting via local PC/SC bridge at ${url}...`);
            state.device = await YubiKeyDevice.connectBridge(url, token);
            log('Connected to YubiKey via local PC/SC bridge', 'success');
        } else {
            if (!state.webUsbAvailable) {
                log('WebUSB is not supported in this browser; switch to Local PC/SC Bridge', 'error');
                return;
            }
            log('Requesting YubiKey WebUSB connection...');
            state.device = await YubiKeyDevice.connect();
            log('Successfully connected to YubiKey via WebUSB', 'success');
        }

        // Sync selected PIV slot with the device
        state.device.setSlot(elements.slotSelect.value);
        updateConnectionUI(true);
    } catch (error) {
        log(`Connection failed: ${error.message || error}`, 'error');
        state.device = null;
        updateConnectionUI(false);
    }
}

async function disconnectDevice() {
    if (!state.device) return;

    try {
        log('Disconnecting from YubiKey...');
        await state.device.disconnect();
        log('Disconnected', 'success');
    } catch (error) {
        log(`Disconnect error: ${error.message || error}`, 'warn');
    } finally {
        state.device = null;
        updateConnectionUI(false);
    }
}

function changeSlot() {
    if (!state.device) return;

    const slot = elements.slotSelect.value;
    try {
        state.device.setSlot(slot);
        state.address = null;
        elements.addressDisplay.textContent = '-';
        log(`Active PIV slot set to ${slot}`, 'info');
    } catch (error) {
        log(`Failed to set PIV slot: ${error.message || error}`, 'error');
    }
}

async function verifyPin() {
    if (!state.device) return;

    const pin = elements.pinInput.value;
    if (!pin || pin.length < 6 || pin.length > 8) {
        log('PIN must be 6-8 characters', 'error');
        updatePinUI(false);
        return;
    }

    try {
        log('Verifying PIN...');
        await state.device.verifyPin(pin);
        log('PIN verified successfully', 'success');
        updatePinUI(true);
    } catch (error) {
        log(`PIN verification failed: ${error.message || error}`, 'error');
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

    try {
        log(`Authenticating management key (${alg})...`);
        await state.device.authenticateManagementKey(keyHex, alg);
        log('Management key authenticated successfully', 'success');
        updateMgmtUI(true);
    } catch (error) {
        log(`Management key authentication failed: ${error.message || error}`, 'error');
        updateMgmtUI(false);
    }
}

async function generateKey() {
    if (!state.device || !state.mgmtAuthenticated) {
        log('Authenticate the management key before generating a new key', 'error');
        return;
    }

    const slot = elements.slotSelect.value;
    const confirmed = window.confirm(
        `WARNING: Generating a new P-256 key in PIV slot ${slot} will permanently overwrite any existing key in that slot. Continue?`
    );
    if (!confirmed) {
        log('Key generation cancelled by user', 'info');
        return;
    }

    const pin = elements.pinInput.value;
    const optionalPin = pin ? pin : undefined;

    try {
        log(`Generating new P-256 key in slot ${slot}...`);
        const address = await state.device.generateKey(optionalPin);
        state.address = address;
        elements.addressDisplay.textContent = address;
        log(`Key generated in slot ${slot}. Address: ${address}`, 'success');
    } catch (error) {
        log(`Key generation failed: ${error.message || error}`, 'error');
    }
}

async function getAddress() {
    if (!state.device) return;

    try {
        log(`Retrieving address from slot ${elements.slotSelect.value}...`);
        const address = await state.device.getAddress();
        state.address = address;
        elements.addressDisplay.textContent = address;
        log(`Address: ${address}`, 'success');
    } catch (error) {
        log(`Get address failed: ${error.message || error}`, 'error');
    }
}

// ============================================
// Signing Operations
// ============================================

async function signTransaction() {
    if (!state.device || !state.pinVerified) return;

    const pin = elements.pinInput.value;
    let tx;
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

        tx = {
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
        };
    } catch (validationError) {
        log(`Invalid transaction field: ${validationError.message}`, 'error');
        elements.txSignature.value = '';
        return;
    }

    try {
        log('Signing EIP-1559 transaction...');
        const txJson = JSON.stringify(tx);
        const signature = await state.device.signTransaction(pin, txJson);
        elements.txSignature.value = signature;
        log(`Transaction signed: ${signature.substring(0, 20)}...`, 'success');
    } catch (error) {
        log(`Transaction signing failed: ${error.message || error}`, 'error');
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
        log('Signing typed data (EIP-712)...');
        const signature = await state.device.signTypedData(pin, typedDataJson);
        elements.typedDataSignature.value = signature;
        log(`Typed data signed: ${signature.substring(0, 20)}...`, 'success');
    } catch (error) {
        if (error instanceof SyntaxError) {
            log('Invalid JSON format', 'error');
        } else {
            log(`Typed data signing failed: ${error.message || error}`, 'error');
        }
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

    try {
        log('Signing message (EIP-191)...');
        const signature = await state.device.signMessage(pin, message);
        elements.messageSignature.value = signature;
        log(`Message signed: ${signature.substring(0, 20)}...`, 'success');
    } catch (error) {
        log(`Message signing failed: ${error.message || error}`, 'error');
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

    try {
        log('Signing hash...');
        const signature = await state.device.signHash(pin, cleanHash);
        elements.hashSignature.value = signature;
        log(`Hash signed: ${signature.substring(0, 20)}...`, 'success');
    } catch (error) {
        log(`Hash signing failed: ${error.message || error}`, 'error');
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

    // Cleanly disconnect without unhandled promise rejections on page unload
    window.addEventListener('beforeunload', () => {
        if (state.device && state.device.isConnected()) {
            void state.device.disconnect().catch(() => {});
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
