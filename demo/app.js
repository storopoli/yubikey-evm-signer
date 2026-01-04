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
    device: null,
    pinVerified: false,
    address: null
};

// ============================================
// DOM Elements
// ============================================

const elements = {
    // Compatibility
    compatibilitySection: document.getElementById('compatibility-section'),

    // Connection
    connectionStatus: document.getElementById('connection-status'),
    connectBtn: document.getElementById('connect-btn'),
    disconnectBtn: document.getElementById('disconnect-btn'),

    // PIN
    pinSection: document.getElementById('pin-section'),
    pinInput: document.getElementById('pin-input'),
    verifyPinBtn: document.getElementById('verify-pin-btn'),
    pinStatus: document.getElementById('pin-status'),

    // Key Management
    keySection: document.getElementById('key-section'),
    generateKeyBtn: document.getElementById('generate-key-btn'),
    getAddressBtn: document.getElementById('get-address-btn'),
    addressDisplay: document.getElementById('address-display'),

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
// Logging Utilities
// ============================================

function log(message, level = 'info') {
    const timestamp = new Date().toLocaleTimeString();
    const entry = document.createElement('div');
    entry.className = `log-entry ${level}`;
    entry.innerHTML = `<span class="timestamp">[${timestamp}]</span>${escapeHtml(message)}`;
    elements.logOutput.appendChild(entry);
    elements.logOutput.scrollTop = elements.logOutput.scrollHeight;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ============================================
// UI State Management
// ============================================

function updateConnectionUI(connected) {
    elements.connectionStatus.textContent = connected ? 'Connected' : 'Disconnected';
    elements.connectionStatus.className = `status ${connected ? 'connected' : 'disconnected'}`;

    elements.connectBtn.disabled = connected;
    elements.disconnectBtn.disabled = !connected;

    // Enable/disable PIN section based on connection
    elements.pinSection.classList.toggle('disabled-section', !connected);
    elements.pinInput.disabled = !connected;
    elements.verifyPinBtn.disabled = !connected;

    if (!connected) {
        // Reset state on disconnect
        state.pinVerified = false;
        state.address = null;
        updatePinUI(false);
        updateKeyManagementUI(false);
        updateSigningSectionsUI(false);
        elements.addressDisplay.textContent = '-';
    }
}

function updatePinUI(verified) {
    state.pinVerified = verified;
    elements.pinStatus.textContent = verified ? 'Verified' : 'Not verified';
    elements.pinStatus.className = `status ${verified ? 'verified' : ''}`;
    updateKeyManagementUI(verified);
}

function updateKeyManagementUI(enabled) {
    elements.keySection.classList.toggle('disabled-section', !enabled);
    elements.generateKeyBtn.disabled = !enabled;
    elements.getAddressBtn.disabled = !enabled;
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
// Device Operations
// ============================================

async function connectDevice() {
    try {
        log('Requesting YubiKey connection...');
        state.device = await YubiKeyDevice.connect();
        log('Successfully connected to YubiKey', 'success');
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

async function verifyPin() {
    if (!state.device) return;

    const pin = elements.pinInput.value;
    if (!pin || pin.length < 6 || pin.length > 8) {
        log('PIN must be 6-8 characters', 'error');
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

async function generateKey() {
    if (!state.device || !state.pinVerified) return;

    const pin = elements.pinInput.value;

    try {
        log('Generating new key... (this may take a moment)');
        const address = await state.device.generateKey(pin);
        state.address = address;
        elements.addressDisplay.textContent = address;
        log(`Key generated. Address: ${address}`, 'success');
        updateSigningSectionsUI(true);
    } catch (error) {
        log(`Key generation failed: ${error.message || error}`, 'error');
    }
}

async function getAddress() {
    if (!state.device) return;

    try {
        log('Retrieving address...');
        const address = await state.device.getAddress();
        state.address = address;
        elements.addressDisplay.textContent = address;
        log(`Address: ${address}`, 'success');
        updateSigningSectionsUI(true);
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

    // Build transaction object
    const tx = {
        type: 'eip1559',
        chain_id: parseInt(elements.txChainId.value) || 1,
        nonce: parseInt(elements.txNonce.value) || 0,
        max_priority_fee_per_gas: elements.txMaxPriorityFee.value || '1000000000',
        max_fee_per_gas: elements.txMaxFee.value || '20000000000',
        gas_limit: parseInt(elements.txGasLimit.value) || 21000,
        to: elements.txTo.value || null,
        value: elements.txValue.value || '0',
        input: elements.txInput.value || '0x',
        access_list: []
    };

    try {
        log('Signing transaction...');
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
        // Validate JSON
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
    const hash = elements.hashInput.value;

    if (!hash.trim()) {
        log('Please enter a hash to sign', 'error');
        return;
    }

    // Validate hash format
    const cleanHash = hash.startsWith('0x') ? hash : `0x${hash}`;
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
    // Connection
    elements.connectBtn.addEventListener('click', connectDevice);
    elements.disconnectBtn.addEventListener('click', disconnectDevice);

    // PIN
    elements.verifyPinBtn.addEventListener('click', verifyPin);
    elements.pinInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') verifyPin();
    });

    // Key Management
    elements.generateKeyBtn.addEventListener('click', generateKey);
    elements.getAddressBtn.addEventListener('click', getAddress);

    // Signing
    elements.signTxBtn.addEventListener('click', signTransaction);
    elements.signTypedDataBtn.addEventListener('click', signTypedData);
    elements.signMessageBtn.addEventListener('click', signMessage);
    elements.signHashBtn.addEventListener('click', signHash);

    // Helpers
    elements.loadExample712Btn.addEventListener('click', loadEip712Example);
    elements.clearLogBtn.addEventListener('click', () => {
        elements.logOutput.innerHTML = '';
        log('Log cleared', 'info');
    });

    // Handle page unload
    window.addEventListener('beforeunload', () => {
        if (state.device && state.device.isConnected()) {
            state.device.disconnect();
        }
    });
}

// ============================================
// Initialization
// ============================================

async function initialize() {
    try {
        log('Initializing WASM module...');
        await init();
        log('WASM module loaded', 'success');

        // Display version
        const version = getVersion();
        elements.version.textContent = `Version: ${version}`;
        log(`Library version: ${version}`, 'info');

        // Check WebUSB support
        if (!isWebUsbSupported()) {
            elements.compatibilitySection.classList.remove('hidden');
            log('WebUSB not supported in this browser', 'error');
            return;
        }

        log('WebUSB supported', 'success');
        log('Ready. Click "Connect YubiKey" to begin.', 'info');

        // Setup event handlers
        setupEventListeners();

    } catch (error) {
        log(`Initialization failed: ${error.message || error}`, 'error');
        elements.compatibilitySection.classList.remove('hidden');
    }
}

// Start initialization when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize);
} else {
    initialize();
}
