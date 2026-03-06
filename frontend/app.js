// =====================================================
// Auth Service — Frontend App
// Tokens guardados em cookies HttpOnly (SameSite=Strict)
// O JavaScript NUNCA acede aos tokens — o browser gere tudo.
//
// Em produção, os cookies teriam Secure=true (HTTPS obrigatório).
// =====================================================

const API = '/api/v1/auth';

const app = {
    // State (sem tokens — estão nos cookies HttpOnly, invisíveis ao JS)
    mfaToken: null,

    // ===== SCREEN MANAGEMENT =====
    showScreen(name) {
        document.querySelectorAll('[id^="screen-"]').forEach(el => el.classList.add('hidden'));
        document.getElementById(`screen-${name}`).classList.remove('hidden');

        const userBar = document.getElementById('user-bar');
        if (name === 'dashboard') {
            userBar.classList.remove('hidden');
        } else {
            userBar.classList.add('hidden');
        }
    },

    // ===== TOAST NOTIFICATIONS =====
    toast(message, type = 'info') {
        const el = document.getElementById('toast');
        el.textContent = message;
        el.className = `toast ${type}`;
        el.classList.remove('hidden');
        clearTimeout(this._toastTimer);
        this._toastTimer = setTimeout(() => el.classList.add('hidden'), 4000);
    },

    // ===== API HELPER =====
    // credentials: 'include' garante que o browser envia os cookies HttpOnly.
    // Não precisamos de Authorization header — o cookie vai automaticamente!
    async api(endpoint, options = {}) {
        const headers = { 'Content-Type': 'application/json' };

        const res = await fetch(`${API}${endpoint}`, {
            ...options,
            headers: { ...headers, ...options.headers },
            credentials: 'include'  // <-- Envia cookies HttpOnly automaticamente
        });

        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            throw new Error(data.error || `Erro ${res.status}`);
        }
        return data;
    },

    // ===== LOADING BUTTON =====
    setLoading(form, loading) {
        const btn = form.querySelector('button[type="submit"]');
        if (loading) {
            btn.classList.add('loading');
            btn.disabled = true;
        } else {
            btn.classList.remove('loading');
            btn.disabled = false;
        }
    },

    // ===== REGISTER =====
    async register(e) {
        e.preventDefault();
        const form = e.target;
        this.setLoading(form, true);

        try {
            await this.api('/register', {
                method: 'POST',
                body: JSON.stringify({
                    name: document.getElementById('reg-name').value,
                    email: document.getElementById('reg-email').value,
                    password: document.getElementById('reg-password').value
                })
            });

            // Cookies HttpOnly foram definidos pelo backend — JS não precisa fazer nada
            this.toast('Conta criada com sucesso!', 'success');
            this.enterDashboard();
        } catch (err) {
            this.toast(err.message, 'error');
        } finally {
            this.setLoading(form, false);
        }
    },

    // ===== LOGIN =====
    async login(e) {
        e.preventDefault();
        const form = e.target;
        this.setLoading(form, true);

        try {
            const data = await this.api('/login', {
                method: 'POST',
                body: JSON.stringify({
                    email: document.getElementById('login-email').value,
                    password: document.getElementById('login-password').value
                })
            });

            if (data.mfa_required) {
                this.mfaToken = data.mfa_token;
                this.showScreen('mfa-challenge');
                this.toast('Insira o código 2FA', 'info');
            } else {
                // Cookies HttpOnly definidos pelo backend
                this.toast('Login efetuado!', 'success');
                this.enterDashboard();
            }
        } catch (err) {
            this.toast(err.message, 'error');
        } finally {
            this.setLoading(form, false);
        }
    },

    // ===== MFA VALIDATE LOGIN =====
    async mfaValidateLogin(e) {
        e.preventDefault();
        const form = e.target;
        this.setLoading(form, true);

        try {
            await this.api('/mfa/validate', {
                method: 'POST',
                body: JSON.stringify({
                    mfa_token: this.mfaToken,
                    code: document.getElementById('mfa-code').value
                })
            });

            this.mfaToken = null;
            this.toast('2FA verificado!', 'success');
            this.enterDashboard();
        } catch (err) {
            this.toast(err.message, 'error');
        } finally {
            this.setLoading(form, false);
        }
    },

    // ===== ENTER DASHBOARD =====
    async enterDashboard() {
        this.showScreen('dashboard');
        document.getElementById('dash-opaque').textContent = '🔒 HttpOnly (invisível ao JS)';

        // Ambos em paralelo
        await Promise.all([
            this.validateToken(),
            this.checkMFAStatus()
        ]);


    },

    // ===== VALIDATE TOKEN =====
    async validateToken() {
        try {
            // O cookie phantom_token é enviado automaticamente pelo browser
            const data = await this.api('/validate', { method: 'POST' });

            document.getElementById('dash-uid').textContent = data.user_id;
            document.getElementById('dash-role').textContent = data.role || 'user';
            document.getElementById('user-info').textContent = `${data.name} (${data.email})`;
            document.getElementById('dash-exp').textContent = 'Ativo (cookie HttpOnly)';

            this.toast('Token válido!', 'success');
            return true;
        } catch (err) {
            this.toast(`Token inválido: ${err.message}`, 'error');
            this.showScreen('login');
            return false;
        }
    },



    // ===== LOGOUT =====
    async logout() {
        try {
            // Backend limpa os cookies HttpOnly + revoga tokens
            await this.api('/logout', { method: 'POST' });
        } catch (err) {
            // Logout mesmo se API falhar
        }

        this.mfaToken = null;

        this.toast('Sessão encerrada', 'info');
        this.showScreen('login');
    },

    // ===== MFA STATUS =====
    async checkMFAStatus() {
        try {
            const data = await this.api('/mfa/status', { method: 'GET' });
            const enabled = data.mfa_enabled;

            document.getElementById('mfa-status-text').innerHTML = enabled
                ? '<span class="badge badge-active">Ativo</span>'
                : '<span class="badge badge-inactive">Inativo</span>';

            const actionsEl = document.getElementById('mfa-actions');
            document.getElementById('mfa-setup-area').classList.add('hidden');
            document.getElementById('mfa-disable-area').classList.add('hidden');

            if (enabled) {
                actionsEl.innerHTML = '<button onclick="app.showMFADisable()" class="btn btn-sm btn-danger mt-1">Desativar 2FA</button>';
            } else {
                actionsEl.innerHTML = '<button onclick="app.mfaSetup()" class="btn btn-sm btn-secondary mt-1">Ativar 2FA</button>';
            }
        } catch (err) {
            document.getElementById('mfa-status-text').textContent = 'Erro ao carregar';
        }
    },

    // ===== MFA SETUP =====
    async mfaSetup() {
        try {
            const data = await this.api('/mfa/setup', { method: 'POST' });

            const qrEl = document.getElementById('qr-code');
            qrEl.innerHTML = '';

            if (data.qr_code) {
                const img = document.createElement('img');
                img.src = data.qr_code;
                img.alt = 'QR Code 2FA';
                img.width = 200;
                qrEl.appendChild(img);
            } else {
                qrEl.innerHTML = '<p class="small" style="color:#e74c3c">Erro ao gerar QR code.<br>Use a chave manual abaixo.</p>';
            }

            document.getElementById('mfa-secret').textContent = data.secret;
            document.getElementById('mfa-setup-area').classList.remove('hidden');
            document.getElementById('mfa-actions').innerHTML = '';

            this.toast('Escaneie o QR code no Authenticator', 'info');
        } catch (err) {
            this.toast(err.message, 'error');
        }
    },

    // ===== MFA VERIFY SETUP =====
    async mfaVerifySetup(e) {
        e.preventDefault();
        const form = e.target;
        this.setLoading(form, true);

        try {
            await this.api('/mfa/verify-setup', {
                method: 'POST',
                body: JSON.stringify({
                    code: document.getElementById('mfa-setup-code').value
                })
            });

            this.toast('2FA ativado com sucesso!', 'success');
            document.getElementById('mfa-setup-area').classList.add('hidden');
            await this.checkMFAStatus();
        } catch (err) {
            this.toast(err.message, 'error');
        } finally {
            this.setLoading(form, false);
        }
    },

    // ===== MFA DISABLE =====
    showMFADisable() {
        document.getElementById('mfa-disable-area').classList.remove('hidden');
    },

    async mfaDisable(e) {
        e.preventDefault();
        const form = e.target;
        this.setLoading(form, true);

        try {
            await this.api('/mfa/disable', {
                method: 'POST',
                body: JSON.stringify({
                    code: document.getElementById('mfa-disable-code').value
                })
            });

            this.toast('2FA desativado', 'success');
            document.getElementById('mfa-disable-area').classList.add('hidden');
            await this.checkMFAStatus();
        } catch (err) {
            this.toast(err.message, 'error');
        } finally {
            this.setLoading(form, false);
        }
    },

    // ===== PASSWORD STRENGTH CHECKER =====
    initPasswordChecker() {
        const input = document.getElementById('reg-password');
        if (!input) return;

        input.addEventListener('input', () => {
            const val = input.value;
            this.setRule('rule-len', val.length >= 8);
            this.setRule('rule-upper', /[A-Z]/.test(val));
            this.setRule('rule-lower', /[a-z]/.test(val));
            this.setRule('rule-digit', /[0-9]/.test(val));
            this.setRule('rule-special', /[^a-zA-Z0-9]/.test(val));
        });
    },

    setRule(id, valid) {
        const el = document.getElementById(id);
        if (!el) return;
        el.classList.toggle('valid', valid);
        el.textContent = (valid ? '✓ ' : '✗ ') + el.textContent.slice(2);
    },

    // ===== INIT =====
    init() {
        this.initPasswordChecker();

        // Tentar validar o cookie existente (sobrevive a reload/fechar browser)
        // Se o cookie HttpOnly existir e for válido → entra directo no dashboard
        // Se não existir ou expirou → mostra login
        this.api('/validate', { method: 'POST' })
            .then(() => this.enterDashboard())
            .catch(() => this.showScreen('login'));
    }
};

// Start
document.addEventListener('DOMContentLoaded', () => app.init());
