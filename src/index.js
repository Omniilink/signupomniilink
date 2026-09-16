// OmniLink Signup Worker - signup.omniilink.workers.dev
// Handles authentication, account management, API key storage

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS headers
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // API routes
      if (path.startsWith('/api/')) {
        const response = await handleAPI(request, env, path);
        Object.entries(corsHeaders).forEach(([k, v]) => response.headers.set(k, v));
        return response;
      }

      // Serve HTML page
      return new Response(getHTML(), {
        headers: { 'Content-Type': 'text/html;charset=utf-8', ...corsHeaders },
      });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
      });
    }
  },
};

// ==========================================
// API Router
// ==========================================

async function handleAPI(request, env, path) {
  const json = async (data, status = 200) =>
    new Response(JSON.stringify(data), {
      status,
      headers: { 'Content-Type': 'application/json' },
    });

  // POST /api/signup
  if (path === '/api/signup' && request.method === 'POST') {
    const { email, password, name } = await request.json();
    if (!email || !password) return json({ error: 'Email and password required' }, 400);

    const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
    if (existing) return json({ error: 'Account already exists' }, 409);

    const hash = await hashPassword(password);
    const result = await env.DB.prepare('INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)')
      .bind(email, hash, name || '').run();

    const code = generateCode();
    const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    await env.DB.prepare('INSERT INTO verification_codes (email, code, purpose, expires_at) VALUES (?, ?, ?, ?)')
      .bind(email, code, 'signup', expires).run();

    await sendEmail(env, email, 'OmniLink Verification Code', `Your verification code is: ${code}\n\nThis code expires in 10 minutes.`);

    return json({ success: true, message: 'Verification code sent to your email' });
  }

  // POST /api/verify
  if (path === '/api/verify' && request.method === 'POST') {
    const { email, code } = await request.json();
    if (!email || !code) return json({ error: 'Email and code required' }, 400);

    const record = await env.DB.prepare(
      'SELECT id FROM verification_codes WHERE email = ? AND code = ? AND purpose = ? AND used = 0 AND expires_at > datetime(\'now\')'
    ).bind(email, code, 'signup').first();

    if (!record) return json({ error: 'Invalid or expired code' }, 400);

    await env.DB.prepare('UPDATE verification_codes SET used = 1 WHERE id = ?').bind(record.id).run();
    await env.DB.prepare('UPDATE users SET email_verified = 1 WHERE email = ?').bind(email).run();

    const user = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
    const token = await createSession(env, user.id);

    return json({ success: true, token, message: 'Email verified' });
  }

  // POST /api/signin
  if (path === '/api/signin' && request.method === 'POST') {
    const { email, password } = await request.json();
    if (!email || !password) return json({ error: 'Email and password required' }, 400);

    const user = await env.DB.prepare('SELECT id, password_hash, email_verified FROM users WHERE email = ?').bind(email).first();
    if (!user) return json({ error: 'Invalid credentials' }, 401);

    const valid = await verifyPassword(password, user.password_hash);
    if (!valid) return json({ error: 'Invalid credentials' }, 401);

    if (!user.email_verified) {
      const code = generateCode();
      const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();
      await env.DB.prepare('INSERT INTO verification_codes (email, code, purpose, expires_at) VALUES (?, ?, ?, ?)')
        .bind(email, code, 'signup', expires).run();
      await sendEmail(env, email, 'OmniLink Verification Code', `Your verification code is: ${code}`);
      return json({ error: 'Email not verified', needsVerification: true }, 403);
    }

    const token = await createSession(env, user.id);
    return json({ success: true, token });
  }

  // POST /api/forgot-password
  if (path === '/api/forgot-password' && request.method === 'POST') {
    const { email } = await request.json();
    const user = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
    if (!user) return json({ success: true, message: 'If the email exists, a code was sent' });

    const code = generateCode();
    const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    await env.DB.prepare('INSERT INTO verification_codes (email, code, purpose, expires_at) VALUES (?, ?, ?, ?)')
      .bind(email, code, 'reset', expires).run();
    await sendEmail(env, email, 'OmniLink Password Reset', `Your reset code is: ${code}`);
    return json({ success: true, message: 'If the email exists, a code was sent' });
  }

  // POST /api/reset-password
  if (path === '/api/reset-password' && request.method === 'POST') {
    const { email, code, newPassword } = await request.json();
    const record = await env.DB.prepare(
      'SELECT id FROM verification_codes WHERE email = ? AND code = ? AND purpose = ? AND used = 0 AND expires_at > datetime(\'now\')'
    ).bind(email, code, 'reset').first();
    if (!record) return json({ error: 'Invalid or expired code' }, 400);

    const hash = await hashPassword(newPassword);
    await env.DB.prepare('UPDATE users SET password_hash = ? WHERE email = ?').bind(hash, email).run();
    await env.DB.prepare('UPDATE verification_codes SET used = 1 WHERE id = ?').bind(record.id).run();
    return json({ success: true, message: 'Password reset successfully' });
  }

  // Authenticated routes
  const user = await authenticateUser(request, env);
  if (!user) return json({ error: 'Unauthorized' }, 401);

  // GET /api/user
  if (path === '/api/user' && request.method === 'GET') {
    const u = await env.DB.prepare('SELECT id, email, name, email_verified, storage_used_bytes, storage_limit_bytes, created_at FROM users WHERE id = ?')
      .bind(user.id).first();
    return json({ user: u });
  }

  // PUT /api/user
  if (path === '/api/user' && request.method === 'PUT') {
    const { name, currentPassword, newPassword } = await request.json();
    if (newPassword) {
      const u = await env.DB.prepare('SELECT password_hash FROM users WHERE id = ?').bind(user.id).first();
      if (!await verifyPassword(currentPassword, u.password_hash)) return json({ error: 'Current password incorrect' }, 400);
      await env.DB.prepare('UPDATE users SET password_hash = ? WHERE id = ?').bind(await hashPassword(newPassword), user.id).run();
    }
    if (name !== undefined) {
      await env.DB.prepare('UPDATE users SET name = ? WHERE id = ?').bind(name, user.id).run();
    }
    return json({ success: true });
  }

  // GET /api/api-keys
  if (path === '/api/api-keys' && request.method === 'GET') {
    const keys = await env.DB.prepare('SELECT id, provider, created_at, updated_at FROM user_api_keys WHERE user_id = ?')
      .bind(user.id).all();
    return json({ keys: keys.results });
  }

  // POST /api/api-keys
  if (path === '/api/api-keys' && request.method === 'POST') {
    const { provider, api_key } = await request.json();
    if (!provider || !api_key) return json({ error: 'Provider and key required' }, 400);

    const existing = await env.DB.prepare('SELECT id FROM user_api_keys WHERE user_id = ? AND provider = ?')
      .bind(user.id, provider).first();
    if (existing) {
      await env.DB.prepare('UPDATE user_api_keys SET api_key = ?, updated_at = datetime(\'now\') WHERE id = ?')
        .bind(api_key, existing.id).run();
    } else {
      await env.DB.prepare('INSERT INTO user_api_keys (user_id, provider, api_key) VALUES (?, ?, ?)')
        .bind(user.id, provider, api_key).run();
    }
    return json({ success: true });
  }

  // DELETE /api/api-keys/:id
  if (path.startsWith('/api/api-keys/') && request.method === 'DELETE') {
    const id = path.split('/').pop();
    await env.DB.prepare('DELETE FROM user_api_keys WHERE id = ? AND user_id = ?').bind(id, user.id).run();
    return json({ success: true });
  }

  // GET /api/backend-url
  if (path === '/api/backend-url' && request.method === 'GET') {
    const setting = await env.DB.prepare('SELECT value FROM settings WHERE key = ?').bind('backend_url').first();
    return json({ url: setting?.value || '' });
  }

  return json({ error: 'Not found' }, 404);
}

// ==========================================
// Auth Helpers
// ==========================================

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyPassword(password, hash) {
  const h = await hashPassword(password);
  return h === hash;
}

function generateCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function generateToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function createSession(env, userId) {
  const token = generateToken();
  const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(); // 30 days
  await env.DB.prepare('INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)')
    .bind(userId, token, expires).run();
  return token;
}

async function authenticateUser(request, env) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return null;
  const token = auth.slice(7);
  const session = await env.DB.prepare(
    'SELECT user_id FROM sessions WHERE token = ? AND expires_at > datetime(\'now\')'
  ).bind(token).first();
  return session ? { id: session.user_id } : null;
}

async function sendEmail(env, to, subject, body) {
  try {
    await env.EMAIL.send({
      from: 'OmniLink <noreply@omniilink.workers.dev>',
      to,
      subject,
      text: body,
    });
  } catch (e) {
    console.log('Email send failed:', e.message);
  }
}

// ==========================================
// HTML Page
// ==========================================

function getHTML() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OmniLink - Account</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#09090b;--bg2:#111113;--bg3:#18181b;--border:#27272a;--text:#fafafa;--text2:#a1a1aa;--accent:#2563eb;--accent2:#3b82f6;--success:#22c55e;--error:#ef4444;--radius:10px}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.container{width:100%;max-width:420px}
.logo{display:flex;align-items:center;gap:12px;margin-bottom:32px;justify-content:center}
.logo-icon{width:40px;height:40px;background:var(--accent);border-radius:10px;display:flex;align-items:center;justify-content:center}
.logo-icon svg{width:24px;height:24px;fill:#fff}
.logo-text{font-size:24px;font-weight:700;letter-spacing:-0.5px}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:32px}
h2{font-size:20px;margin-bottom:4px}
.subtitle{color:var(--text2);font-size:14px;margin-bottom:24px}
.form-group{margin-bottom:16px}
label{display:block;font-size:13px;color:var(--text2);margin-bottom:6px}
input{width:100%;padding:10px 14px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:14px;outline:none;transition:border-color 0.15s}
input:focus{border-color:var(--accent)}
.btn{width:100%;padding:10px;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;transition:all 0.15s}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:var(--accent2)}
.btn-secondary{background:var(--bg3);color:var(--text);border:1px solid var(--border)}
.btn-secondary:hover{border-color:var(--accent)}
.btn-google{background:#fff;color:#333;display:flex;align-items:center;justify-content:center;gap:8px;margin-bottom:12px}
.btn-google:hover{background:#f5f5f5}
.btn-google svg{width:18px;height:18px}
.divider{display:flex;align-items:center;gap:12px;margin:20px 0;color:var(--text2);font-size:12px}
.divider::before,.divider::after{content:'';flex:1;height:1px;background:var(--border)}
.links{text-align:center;margin-top:16px;font-size:13px;color:var(--text2)}
.links a{color:var(--accent);text-decoration:none;cursor:pointer}
.links a:hover{text-decoration:underline}
.error{color:var(--error);font-size:13px;margin-bottom:12px;display:none}
.success{color:var(--success);font-size:13px;margin-bottom:12px;display:none}
.hidden{display:none !important}
.code-inputs{display:flex;gap:8px;justify-content:center;margin:20px 0}
.code-inputs input{width:48px;text-align:center;font-size:20px;padding:12px 0;font-family:monospace}
.settings{padding:20px 0}
.settings h3{font-size:16px;margin-bottom:16px}
.key-list{margin:12px 0}
.key-item{display:flex;align-items:center;justify-content:space-between;padding:10px 14px;background:var(--bg);border:1px solid var(--border);border-radius:8px;margin-bottom:8px;font-size:13px}
.key-item .provider{font-weight:600;color:var(--accent)}
.key-item .date{color:var(--text2);font-size:11px}
.key-item .del{color:var(--error);cursor:pointer;border:none;background:none;font-size:18px;padding:0 4px}
.tutorial{margin-top:24px;padding:20px;background:var(--bg);border:1px solid var(--border);border-radius:8px}
.tutorial h4{margin-bottom:8px;font-size:14px}
.tutorial p{font-size:13px;color:var(--text2);line-height:1.6;margin-bottom:8px}
.tutorial ol{font-size:13px;color:var(--text2);line-height:1.8;padding-left:20px}
.storage-bar{height:6px;background:var(--bg);border-radius:3px;overflow:hidden;margin:8px 0}
.storage-fill{height:100%;background:var(--accent);border-radius:3px;transition:width 0.3s}
.storage-text{font-size:12px;color:var(--text2)}
</style>
</head>
<body>
<div class="container">
  <div class="logo">
    <div class="logo-icon"><svg viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg></div>
    <span class="logo-text">OmniLink</span>
  </div>

  <!-- Sign Up Form -->
  <div id="signup-view" class="card">
    <h2>Create Account</h2>
    <p class="subtitle">Get started with OmniLink</p>
    <div id="signup-error" class="error"></div>
    <div id="signup-success" class="success"></div>
    <button class="btn btn-google" onclick="signupWithGoogle()">
      <svg viewBox="0 0 24 24"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 01-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>
      Sign up with Google
    </button>
    <div class="divider">or</div>
    <div class="form-group">
      <label>Name</label>
      <input type="text" id="signup-name" placeholder="Your name">
    </div>
    <div class="form-group">
      <label>Email</label>
      <input type="email" id="signup-email" placeholder="you@example.com">
    </div>
    <div class="form-group">
      <label>Password</label>
      <input type="password" id="signup-password" placeholder="At least 8 characters">
    </div>
    <button class="btn btn-primary" onclick="doSignup()">Create Account</button>
    <p class="links">Already have an account? <a onclick="showView('signin')">Sign in</a></p>
  </div>

  <!-- Sign In Form -->
  <div id="signin-view" class="card hidden">
    <h2>Sign In</h2>
    <p class="subtitle">Welcome back to OmniLink</p>
    <div id="signin-error" class="error"></div>
    <button class="btn btn-google" onclick="signinWithGoogle()">
      <svg viewBox="0 0 24 24"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 01-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>
      Sign in with Google
    </button>
    <div class="divider">or</div>
    <div class="form-group">
      <label>Email</label>
      <input type="email" id="signin-email" placeholder="you@example.com">
    </div>
    <div class="form-group">
      <label>Password</label>
      <input type="password" id="signin-password" placeholder="Your password">
    </div>
    <button class="btn btn-primary" onclick="doSignin()">Sign In</button>
    <p class="links"><a onclick="showView('forgot')">Forgot password?</a></p>
    <p class="links">Don't have an account? <a onclick="showView('signup')">Sign up</a></p>
  </div>

  <!-- Verify Email -->
  <div id="verify-view" class="card hidden">
    <h2>Verify Email</h2>
    <p class="subtitle">Enter the 6-digit code sent to your email</p>
    <div id="verify-error" class="error"></div>
    <div class="code-inputs">
      <input type="text" maxlength="1" class="code-digit" data-idx="0">
      <input type="text" maxlength="1" class="code-digit" data-idx="1">
      <input type="text" maxlength="1" class="code-digit" data-idx="2">
      <input type="text" maxlength="1" class="code-digit" data-idx="3">
      <input type="text" maxlength="1" class="code-digit" data-idx="4">
      <input type="text" maxlength="1" class="code-digit" data-idx="5">
    </div>
    <button class="btn btn-primary" onclick="doVerify()">Verify</button>
    <p class="links"><a onclick="resendCode()">Resend code</a></p>
  </div>

  <!-- Forgot Password -->
  <div id="forgot-view" class="card hidden">
    <h2>Reset Password</h2>
    <p class="subtitle">Enter your email to receive a reset code</p>
    <div id="forgot-error" class="error"></div>
    <div id="forgot-success" class="success"></div>
    <div id="forgot-step1">
      <div class="form-group">
        <label>Email</label>
        <input type="email" id="forgot-email" placeholder="you@example.com">
      </div>
      <button class="btn btn-primary" onclick="doForgot()">Send Code</button>
    </div>
    <div id="forgot-step2" class="hidden">
      <div class="form-group">
        <label>Code</label>
        <input type="text" id="reset-code" placeholder="6-digit code" maxlength="6">
      </div>
      <div class="form-group">
        <label>New Password</label>
        <input type="password" id="reset-password" placeholder="New password">
      </div>
      <button class="btn btn-primary" onclick="doReset()">Reset Password</button>
    </div>
    <p class="links"><a onclick="showView('signin')">Back to sign in</a></p>
  </div>

  <!-- Account Dashboard -->
  <div id="dashboard-view" class="card hidden">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
      <h2>Account</h2>
      <button class="btn btn-secondary" style="width:auto;padding:6px 14px;font-size:12px" onclick="doSignout()">Sign out</button>
    </div>
    <div id="user-info" style="margin-bottom:16px"></div>
    <div class="storage-bar"><div class="storage-fill" id="storage-fill" style="width:0%"></div></div>
    <p class="storage-text" id="storage-text">0 / 5 GB used</p>

    <div class="settings">
      <h3>API Keys</h3>
      <p style="font-size:12px;color:var(--text2);margin-bottom:12px">Add keys for AI providers. These are stored securely and used when you chat.</p>
      <div class="form-group" style="display:flex;gap:8px">
        <select id="key-provider" style="flex:1;padding:8px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:13px">
          <option value="groq">Groq</option>
          <option value="gemini">Google Gemini</option>
          <option value="openai">OpenAI</option>
          <option value="anthropic">Anthropic</option>
          <option value="openrouter">OpenRouter</option>
          <option value="mistral">Mistral</option>
          <option value="together">Together AI</option>
          <option value="deepseek">DeepSeek</option>
          <option value="xai">xAI</option>
          <option value="cohere">Cohere</option>
        </select>
        <input type="password" id="key-value" placeholder="API key" style="flex:2">
        <button class="btn btn-primary" style="width:auto;padding:8px 16px" onclick="saveApiKey()">Save</button>
      </div>
      <div class="key-list" id="key-list"></div>
    </div>

    <div class="tutorial">
      <h4>Getting Started</h4>
      <ol>
        <li>Add your API keys above (get them from provider websites)</li>
        <li>Go to <a href="https://use.omniilink.workers.dev" style="color:var(--accent)">use.omniilink.workers.dev</a></li>
        <li>Sign in with the same account</li>
        <li>Start chatting with AI models!</li>
      </ol>
    </div>
  </div>
</div>

<script>
const API = '';
let currentEmail = '';
let verifyPurpose = 'signup';

function showView(view) {
  document.querySelectorAll('.card').forEach(c => c.classList.add('hidden'));
  document.getElementById(view + '-view').classList.remove('hidden');
}

async function api(path, method = 'GET', body = null) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  const token = localStorage.getItem('omnilink_token');
  if (token) opts.headers['Authorization'] = 'Bearer ' + token;
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(API + path, opts);
  return r.json();
}

// Code digit auto-advance
document.querySelectorAll('.code-digit').forEach((input, i, arr) => {
  input.addEventListener('input', () => {
    if (input.value && i < arr.length - 1) arr[i + 1].focus();
  });
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Backspace' && !input.value && i > 0) arr[i - 1].focus();
  });
});

function getCode() {
  return Array.from(document.querySelectorAll('.code-digit')).map(i => i.value).join('');
}

function showError(id, msg) {
  const el = document.getElementById(id);
  el.textContent = msg;
  el.style.display = 'block';
}

function showSuccess(id, msg) {
  const el = document.getElementById(id);
  el.textContent = msg;
  el.style.display = 'block';
}

async function doSignup() {
  const name = document.getElementById('signup-name').value;
  const email = document.getElementById('signup-email').value;
  const password = document.getElementById('signup-password').value;
  if (password.length < 8) return showError('signup-error', 'Password must be at least 8 characters');
  currentEmail = email;
  const r = await api('/api/signup', 'POST', { name, email, password });
  if (r.error) return showError('signup-error', r.error);
  verifyPurpose = 'signup';
  showView('verify');
}

async function doSignin() {
  const email = document.getElementById('signin-email').value;
  const password = document.getElementById('signin-password').value;
  currentEmail = email;
  const r = await api('/api/signin', 'POST', { email, password });
  if (r.error) {
    if (r.needsVerification) { verifyPurpose = 'signup'; showView('verify'); return; }
    return showError('signin-error', r.error);
  }
  localStorage.setItem('omnilink_token', r.token);
  localStorage.setItem('omnilink_email', email);
  loadDashboard();
}

async function doVerify() {
  const code = getCode();
  const r = await api('/api/verify', 'POST', { email: currentEmail, code });
  if (r.error) return showError('verify-error', r.error);
  localStorage.setItem('omnilink_token', r.token);
  localStorage.setItem('omnilink_email', currentEmail);
  loadDashboard();
}

async function resendCode() {
  await api('/api/signup', 'POST', { email: currentEmail, password: 'resend' });
}

async function doForgot() {
  const email = document.getElementById('forgot-email').value;
  currentEmail = email;
  const r = await api('/api/forgot-password', 'POST', { email });
  if (r.error) return showError('forgot-error', r.error);
  showSuccess('forgot-success', 'Code sent! Check your email.');
  document.getElementById('forgot-step1').classList.add('hidden');
  document.getElementById('forgot-step2').classList.remove('hidden');
}

async function doReset() {
  const code = document.getElementById('reset-code').value;
  const newPassword = document.getElementById('reset-password').value;
  const r = await api('/api/reset-password', 'POST', { email: currentEmail, code, newPassword });
  if (r.error) return showError('forgot-error', r.error);
  showView('signin');
  showSuccess('signin-success', 'Password reset! Sign in with your new password.');
}

async function loadDashboard() {
  showView('dashboard');
  const r = await api('/api/user');
  if (r.error) { showView('signin'); return; }
  const u = r.user;
  document.getElementById('user-info').innerHTML =
    '<div style="font-size:14px;font-weight:600">' + (u.name || u.email) + '</div>' +
    '<div style="font-size:12px;color:var(--text2)">' + u.email + '</div>';
  const used = (u.storage_used_bytes / 1073741824).toFixed(2);
  const limit = (u.storage_limit_bytes / 1073741824).toFixed(0);
  const pct = (u.storage_used_bytes / u.storage_limit_bytes * 100).toFixed(1);
  document.getElementById('storage-fill').style.width = pct + '%';
  document.getElementById('storage-text').textContent = used + ' / ' + limit + ' GB used';
  loadKeys();
}

async function loadKeys() {
  const r = await api('/api/api-keys');
  const list = document.getElementById('key-list');
  if (!r.keys || r.keys.length === 0) { list.innerHTML = '<p style="font-size:12px;color:var(--text2)">No API keys added yet</p>'; return; }
  list.innerHTML = r.keys.map(k =>
    '<div class="key-item"><span class="provider">' + k.provider + '</span><span class="date">Added ' + new Date(k.created_at).toLocaleDateString() + '</span><button class="del" onclick="deleteKey(' + k.id + ')">&times;</button></div>'
  ).join('');
}

async function saveApiKey() {
  const provider = document.getElementById('key-provider').value;
  const api_key = document.getElementById('key-value').value;
  if (!api_key) return;
  await api('/api/api-keys', 'POST', { provider, api_key });
  document.getElementById('key-value').value = '';
  loadKeys();
}

async function deleteKey(id) {
  await api('/api/api-keys/' + id, 'DELETE');
  loadKeys();
}

function doSignout() {
  localStorage.removeItem('omnilink_token');
  localStorage.removeItem('omnilink_email');
  showView('signin');
}

function signupWithGoogle() {
  window.location.href = 'https://accounts.google.com/o/oauth2/auth?client_id=YOUR_GOOGLE_CLIENT_ID&redirect_uri=' + encodeURIComponent(window.location.origin + '/api/google/callback') + '&scope=email+profile&response_type=code';
}

function signinWithGoogle() {
  signupWithGoogle();
}

// Auto-login if token exists
window.addEventListener('load', () => {
  if (localStorage.getItem('omnilink_token')) loadDashboard();
});
</script>
</body>
</html>`;
}
