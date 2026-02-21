/**
 * VaultGuard Pro - Enterprise-Grade Local Security
 * Advanced Cryptographic Implementation (PBKDF2 + AES-256)
 */

// --- Constants & Security Config ---
const CONFIG = {
    APP: 'VaultGuard Pro',
    VERSION: '2.0.0',
    KEYS: {
        VAULT_HASH: 'vg_pro_hash',      // Current Master Key Hash
        VAULT_SALT: 'vg_pro_salt',      // PBKDF2 Salt
        VAULT_DATA: 'vg_pro_data',      // Encrypted Payload
        AUDIT_LOG: 'vg_pro_audit',      // Security Logs
        RECOVERY: 'vg_pro_recovery'     // Recovery Hash
    },
    PBKDF2_ITERATIONS: 10000,
    SESSION_TIMEOUT: 60000,
    REVEAL_TIMEOUT: 10000
};

// --- Secure State ---
let state = {
    isAuthenticated: false,
    masterPassword: null,
    credentials: [],
    logs: [],
    currentView: 'dashboard',
    lastActivity: Date.now(),
    sessionTimer: null
};

// --- DOM Interface ---
const dom = {
    authScreen: document.getElementById('auth-screen'),
    mainScreen: document.getElementById('main-screen'),
    authForm: document.getElementById('auth-form'),
    masterPasswordInput: document.getElementById('master-password'),
    confirmPasswordInput: document.getElementById('confirm-password'),
    authTitle: document.getElementById('auth-title'),
    authSubtitle: document.getElementById('auth-subtitle'),
    authSubmitText: document.getElementById('auth-submit-text'),
    confirmGroup: document.getElementById('confirm-password-group'),
    passwordStrength: document.getElementById('password-strength'),

    navItems: document.querySelectorAll('.nav-item'),
    viewTitle: document.getElementById('view-title'),
    views: document.querySelectorAll('.view'),

    statTotal: document.getElementById('stat-total'),
    recentList: document.getElementById('recent-list'),

    credentialForm: document.getElementById('credential-form'),
    btnGeneratePw: document.getElementById('btn-generate-pw'),
    allCredsList: document.getElementById('all-creds-list'),
    searchCreds: document.getElementById('search-creds'),

    btnExport: document.getElementById('btn-export'),
    importFile: document.getElementById('import-file'),

    verifyModal: document.getElementById('verify-modal'),
    verifyForm: document.getElementById('verify-form'),
    verifyPassword: document.getElementById('verify-password'),
    btnCloseVerify: document.getElementById('btn-close-verify'),

    auditLogBody: document.getElementById('audit-log-body'),
    auditSessionCount: document.getElementById('audit-session-count'),
    auditFailedCount: document.getElementById('audit-failed-count'),

    timerVal: document.getElementById('timer-val')
};

// --- Initialization ---
document.addEventListener('DOMContentLoaded', () => {
    initVault();
    bindEvents();
});

function initVault() {
    const hasHash = localStorage.getItem(CONFIG.KEYS.VAULT_HASH);
    if (hasHash) {
        setAuthState('login');
    } else {
        setAuthState('setup');
    }
    loadAuditLogs();
}

function bindEvents() {
    dom.authForm.addEventListener('submit', handleAuth);
    dom.masterPasswordInput.addEventListener('input', checkEntropy);

    dom.navItems.forEach(btn => {
        if (btn.dataset.view) btn.addEventListener('click', () => switchView(btn.dataset.view));
    });

    dom.credentialForm.addEventListener('submit', handleSaveCredential);
    dom.btnGeneratePw.addEventListener('click', generateComplexToken);

    document.querySelectorAll('.toggle-password').forEach(btn => {
        btn.addEventListener('click', (e) => toggleVisibility(e.currentTarget));
    });

    dom.searchCreds.addEventListener('input', (e) => renderActiveVault(e.target.value));
    document.getElementById('btn-logout').addEventListener('click', lockTerminal);
    dom.btnExport.addEventListener('click', exportColdBackup);
    dom.importFile.addEventListener('change', importVaultBlob);

    dom.btnCloseVerify.addEventListener('click', () => dom.verifyModal.classList.remove('active'));
    dom.verifyForm.addEventListener('submit', handleVerification);

    ['mousedown', 'keydown', 'scroll'].forEach(ev => document.addEventListener(ev, touchActivity));

    document.getElementById('btn-purge')?.addEventListener('click', wipeTerminal);
    document.getElementById('btn-gen-recovery')?.addEventListener('click', generateRecoveryKey);
}

// --- Cryptography ---
function deriveKey(password, salt) {
    return CryptoJS.PBKDF2(password, salt, {
        keySize: 256 / 32,
        iterations: CONFIG.PBKDF2_ITERATIONS
    }).toString();
}

function encrypt(text) {
    if (!state.masterPassword) return null;
    return CryptoJS.AES.encrypt(text, state.masterPassword).toString();
}

function decrypt(cipher) {
    if (!state.masterPassword) return null;
    try {
        const bytes = CryptoJS.AES.decrypt(cipher, state.masterPassword);
        return bytes.toString(CryptoJS.enc.Utf8);
    } catch (e) { return null; }
}

// --- Auth System ---
function setAuthState(mode) {
    if (mode === 'setup') {
        dom.authTitle.textContent = 'Initialize Vault';
        dom.authSubtitle.textContent = 'Set a master key for local encryption.';
        dom.authSubmitText.textContent = 'Create Vault';
        dom.confirmGroup.style.display = 'block';
    } else {
        dom.authTitle.textContent = 'Terminal Locked';
        dom.authSubtitle.textContent = 'Verify authority to unlock local credentials.';
        dom.authSubmitText.textContent = 'De-crypt & Enter';
        dom.confirmGroup.style.display = 'none';
        dom.passwordStrength.style.display = 'none';
    }
}

async function handleAuth(e) {
    e.preventDefault();
    const pw = dom.masterPasswordInput.value;
    const isSetup = !localStorage.getItem(CONFIG.KEYS.VAULT_HASH);

    if (isSetup) {
        if (pw !== dom.confirmPasswordInput.value) return notify('Passwords do not match', 'error');
        if (pw.length < 12) return notify('Minimum 12 characters required', 'error');

        const salt = CryptoJS.lib.WordArray.random(128 / 8).toString();
        const hash = deriveKey(pw, salt);

        localStorage.setItem(CONFIG.KEYS.VAULT_HASH, hash);
        localStorage.setItem(CONFIG.KEYS.VAULT_SALT, salt);
        localStorage.setItem(CONFIG.KEYS.VAULT_DATA, '[]');

        addAudit('Vault Initialized', 'success', 'New secure environment established.');
        notify('Vault Initialized Successfully', 'success');
    }

    const salt = localStorage.getItem(CONFIG.KEYS.VAULT_SALT);
    const storedHash = localStorage.getItem(CONFIG.KEYS.VAULT_HASH);
    const inputHash = deriveKey(pw, salt);

    if (inputHash === storedHash) {
        state.isAuthenticated = true;
        state.masterPassword = pw;
        unlockTerminal();
        addAudit('Terminal Exit Lock', 'success', 'Master authority verified.');
    } else {
        addAudit('Unauthorized Access Attempt', 'danger', 'Invalid master key entered.');
        notify('Authorization Failed', 'error');
        dom.masterPasswordInput.value = '';
    }
}

function unlockTerminal() {
    dom.authScreen.classList.remove('active');
    dom.mainScreen.classList.add('active');
    loadData();
    switchView('dashboard');
    startSessionMonitor();
    lucide.createIcons();
}

function lockTerminal() {
    state.isAuthenticated = false;
    state.masterPassword = null;
    state.credentials = [];
    clearInterval(state.sessionTimer);

    dom.mainScreen.classList.remove('active');
    dom.authScreen.classList.add('active');
    dom.masterPasswordInput.value = '';
    setAuthState('login');
}

// --- Data & Views ---
function loadData() {
    const raw = localStorage.getItem(CONFIG.KEYS.VAULT_DATA);
    state.credentials = raw ? JSON.parse(raw) : [];
    updateHUD();
}

function saveData() {
    localStorage.setItem(CONFIG.KEYS.VAULT_DATA, JSON.stringify(state.credentials));
    updateHUD();
}

function switchView(viewId) {
    state.currentView = viewId;
    dom.navItems.forEach(b => b.classList.toggle('active', b.dataset.view === viewId));
    dom.views.forEach(v => v.classList.toggle('active', v.id === `view-${viewId}`));

    const titles = {
        'dashboard': 'Overview',
        'add-credential': 'Commit Entry',
        'all-credentials': 'Active Vault',
        'security-audit': 'Security Audit',
        'secure-backup': 'Data Export',
        'settings': 'Core Settings'
    };
    dom.viewTitle.textContent = titles[viewId];

    if (viewId === 'dashboard') renderRecent();
    if (viewId === 'all-credentials') renderActiveVault();
    if (viewId === 'security-audit') renderAuditLogs();
}

function renderRecent() {
    const list = [...state.credentials].sort((a, b) => b.at - a.at).slice(0, 3);
    dom.recentList.innerHTML = list.length ? list.map(c => createCredCard(c)).join('') : '<p class="empty-state">Secure storage is empty.</p>';
    lucide.createIcons();
}

function renderActiveVault(filter = '') {
    const items = state.credentials.filter(c =>
        c.platform.toLowerCase().includes(filter.toLowerCase()) ||
        c.user.toLowerCase().includes(filter.toLowerCase())
    );
    dom.allCredsList.innerHTML = items.length ? items.map(c => createCredCard(c)).join('') : '<p class="empty-state">No matching entries found.</p>';
    lucide.createIcons();
}

function createCredCard(c) {
    return `
        <div class="credential-card">
            <div class="cred-header">
                <div class="cred-platform-info">
                    <h4>${escape(c.platform)}</h4>
                    <p>${escape(c.user)}</p>
                </div>
                <div class="cred-actions">
                    <button class="action-btn" title="Edit" onclick="editEntry('${c.id}')"><i data-lucide="edit-3"></i></button>
                    <button class="action-btn delete" title="Delete" onclick="deleteEntry('${c.id}')"><i data-lucide="trash-2"></i></button>
                </div>
            </div>
            <div class="cred-body">
                <div class="cred-detail">
                    <label>ACCESS KEY</label>
                    <div class="cred-data-wrapper">
                        <span class="cred-masked" id="p-${c.id}">••••••••••••</span>
                        <button class="action-btn" onclick="reveal('${c.id}', 'password')"><i data-lucide="eye"></i></button>
                        <button class="action-btn" onclick="copy('${c.id}', 'password')"><i data-lucide="copy"></i></button>
                    </div>
                </div>
            </div>
        </div>`;
}

// --- Operations ---
let pendingAction = null;

function handleSaveCredential(e) {
    e.preventDefault();
    const id = document.getElementById('credential-id').value;
    const cred = {
        id: id || Date.now().toString(),
        platform: document.getElementById('cred-platform').value,
        user: document.getElementById('cred-username').value,
        password: encrypt(document.getElementById('cred-password').value),
        apiKey: document.getElementById('cred-apikey').value ? encrypt(document.getElementById('cred-apikey').value) : null,
        notes: document.getElementById('cred-notes').value,
        at: Date.now()
    };

    if (id) {
        const idx = state.credentials.findIndex(x => x.id === id);
        state.credentials[idx] = cred;
        addAudit('Entry Modified', 'info', `Record for ${cred.platform} updated.`);
    } else {
        state.credentials.push(cred);
        addAudit('Entry Committed', 'success', `New record for ${cred.platform} added.`);
    }

    saveData();
    notify('Entry Committed to Local Storage', 'success');
    switchView('all-credentials');
}

function reveal(id, key) {
    const c = state.credentials.find(x => x.id === id);
    const el = document.getElementById(`p-${id}`);

    promptVerify(() => {
        const val = decrypt(c[key]);
        el.textContent = val;
        el.className = 'cred-unmasked';
        setTimeout(() => {
            el.textContent = '••••••••••••';
            el.className = 'cred-masked';
        }, CONFIG.REVEAL_TIMEOUT);
    });
}

function copy(id, key) {
    const c = state.credentials.find(x => x.id === id);
    promptVerify(() => {
        navigator.clipboard.writeText(decrypt(c[key]));
        notify('Key copied to secure clipboard', 'success');
    });
}

function editEntry(id) {
    const c = state.credentials.find(x => x.id === id);
    promptVerify(() => {
        switchView('add-credential');
        document.getElementById('credential-id').value = c.id;
        document.getElementById('cred-platform').value = c.platform;
        document.getElementById('cred-username').value = c.user;
        document.getElementById('cred-password').value = decrypt(c.password);
        document.getElementById('cred-apikey').value = c.apiKey ? decrypt(c.apiKey) : '';
        document.getElementById('cred-notes').value = c.notes || '';
    });
}

function deleteEntry(id) {
    if (confirm('Permanently destroy this record?')) {
        state.credentials = state.credentials.filter(x => x.id !== id);
        saveData();
        addAudit('Entry Destroyed', 'danger', 'A record was permanently removed.');
        notify('Record Expunged', 'info');
        renderActiveVault();
    }
}

// --- Security Features ---
function startSessionMonitor() {
    if (state.sessionTimer) clearInterval(state.sessionTimer);
    state.sessionTimer = setInterval(() => {
        const diff = Date.now() - state.lastActivity;
        const left = Math.max(0, Math.ceil((CONFIG.SESSION_TIMEOUT - diff) / 1000));
        dom.timerVal.textContent = left;
        if (diff >= CONFIG.SESSION_TIMEOUT) lockTerminal();
    }, 1000);
}

function touchActivity() { state.lastActivity = Date.now(); }

function promptVerify(callback) {
    pendingAction = callback;
    dom.verifyModal.classList.add('active');
    dom.verifyPassword.value = '';
    dom.verifyPassword.focus();
}

function handleVerification(e) {
    e.preventDefault();
    const salt = localStorage.getItem(CONFIG.KEYS.VAULT_SALT);
    const hash = deriveKey(dom.verifyPassword.value, salt);
    if (hash === localStorage.getItem(CONFIG.KEYS.VAULT_HASH)) {
        const act = pendingAction;
        dom.verifyModal.classList.remove('active');
        pendingAction = null;
        if (act) act();
    } else {
        notify('Authorization Refused', 'error');
    }
}

function generateComplexToken() {
    const set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
    const arr = new Uint32Array(24);
    window.crypto.getRandomValues(arr);
    const tok = Array.from(arr).map(x => set[x % set.length]).join('');
    document.getElementById('cred-password').value = tok;
    notify('High-Entropy Token Generated', 'info');
}

function checkEntropy() {
    const val = dom.masterPasswordInput.value;
    const meter = dom.passwordStrength;
    const txt = meter.querySelector('.meter-text');
    meter.className = 'strength-meter';

    if (!val) return;
    let score = 0;
    if (val.length >= 12) score++;
    if (/[A-Z]/.test(val)) score++;
    if (/[0-9]/.test(val)) score++;
    if (/[^A-Za-z0-9]/.test(val)) score++;

    if (score < 2) { meter.classList.add('strength-weak'); txt.textContent = 'Entropy: Vulnerable'; }
    else if (score < 4) { meter.classList.add('strength-medium'); txt.textContent = 'Entropy: Solid'; }
    else { meter.classList.add('strength-strong'); txt.textContent = 'Entropy: Maximum'; }
}

// --- Audit & UI Updates ---
function loadAuditLogs() {
    const raw = localStorage.getItem(CONFIG.KEYS.AUDIT_LOG);
    state.logs = raw ? JSON.parse(raw) : [];
}

function addAudit(event, type, details) {
    state.logs.unshift({
        at: new Date().toISOString(),
        event,
        type,
        details
    });
    if (state.logs.length > 50) state.logs.pop();
    localStorage.setItem(CONFIG.KEYS.AUDIT_LOG, JSON.stringify(state.logs));
}

function renderAuditLogs() {
    dom.auditLogBody.innerHTML = state.logs.map(l => `
        <tr>
            <td style="font-family:monospace;font-size:0.8rem">${l.at.replace('T', ' ').slice(0, 19)}</td>
            <td><strong>${l.event}</strong></td>
            <td><span class="badge badge-${l.type}">${l.type.toUpperCase()}</span></td>
            <td style="color:var(--text-secondary);font-size:0.85rem">${l.details}</td>
        </tr>
    `).join('');

    dom.auditSessionCount.textContent = state.logs.filter(l => l.event === 'Terminal Exit Lock').length;
    dom.auditFailedCount.textContent = state.logs.filter(l => l.event === 'Unauthorized Access Attempt').length;
}

function updateHUD() {
    dom.statTotal.textContent = state.credentials.length;
}

function notify(msg, type = 'info') {
    const c = document.getElementById('toast-container');
    const t = document.createElement('div');
    t.className = `toast ${type}`;
    t.innerHTML = `<i data-lucide="${type === 'success' ? 'check-circle' : type === 'error' ? 'alert-octagon' : 'info'}"></i><span>${msg}</span>`;
    c.appendChild(t);
    lucide.createIcons();
    setTimeout(() => { t.style.opacity = '0'; setTimeout(() => t.remove(), 400); }, 3500);
}

function toggleVisibility(btn) {
    const inp = btn.parentElement.querySelector('input');
    const ico = btn.querySelector('i');
    inp.type = inp.type === 'password' ? 'text' : 'password';
    ico.setAttribute('data-lucide', inp.type === 'password' ? 'eye' : 'eye-off');
    lucide.createIcons();
}

// --- Pro Extras ---
function exportColdBackup() {
    const data = {
        meta: { app: CONFIG.APP, ver: CONFIG.VERSION, at: Date.now() },
        security: { hash: localStorage.getItem(CONFIG.KEYS.VAULT_HASH), salt: localStorage.getItem(CONFIG.KEYS.VAULT_SALT) },
        payload: localStorage.getItem(CONFIG.KEYS.VAULT_DATA)
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `VaultGuard_ColdBackup_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    addAudit('Backup Generated', 'info', 'Encrypted vault payload exported.');
}

function importVaultBlob(e) {
    const f = e.target.files[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
        try {
            const b = JSON.parse(ev.target.result);
            if (b.meta.app !== CONFIG.APP) throw 'Invalid Format';
            if (confirm('Overwrite existing terminal data with this blob?')) {
                localStorage.setItem(CONFIG.KEYS.VAULT_HASH, b.security.hash);
                localStorage.setItem(CONFIG.KEYS.VAULT_SALT, b.security.salt);
                localStorage.setItem(CONFIG.KEYS.VAULT_DATA, b.payload);
                location.reload();
            }
        } catch (err) { notify('Invalid Backup Blob', 'error'); }
    };
    reader.readAsText(f);
}

function wipeTerminal() {
    if (confirm('CRITICAL: This permanently destroys all cryptographic keys and stored data. Proceed?')) {
        localStorage.clear();
        location.reload();
    }
}

function generateRecoveryKey() {
    promptVerify(() => {
        const key = Array.from(window.crypto.getRandomValues(new Uint8Array(32)))
            .map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
        alert(`EMERGENCY RECOVERY KEY (Write this down!): \n\n ${key}`);
        addAudit('Recovery Key Generated', 'warning', 'A new emergency recovery string was issued.');
    });
}

function escape(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}
