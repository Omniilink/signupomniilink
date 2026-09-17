// Omniilink Signup Worker - signup.omniilink.workers.dev
// Handles authentication, account management, API key storage

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // Tunnel update endpoint - must be before catch-all /api/ route
      if (path === '/api/tunnel-update' && request.method === 'POST') {
        const body = await request.json();
        const validSecret = env.TUNNEL_SECRET || 'omnilink-tunnel-2024';
        if (body.secret !== validSecret) {
          return new Response(JSON.stringify({ error: 'Unauthorized' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
          });
        }
        if (!body.url || !body.url.startsWith('https://')) {
          return new Response(JSON.stringify({ error: 'Invalid URL' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
          });
        }
        try {
          await env.DB.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)')
            .bind('backend_url', body.url).run();
          await env.DB.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)')
            .bind('backend_url_updated_at', new Date().toISOString()).run();
        } catch (dbErr) {
          console.error('D1 write failed:', dbErr);
          return new Response(JSON.stringify({ error: 'Database write failed' }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
          });
        }
        return new Response(JSON.stringify({ ok: true, url: body.url }), {
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }

      // All other API routes
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
      console.error('Worker error:', err);
      return new Response(JSON.stringify({ error: 'Internal server error' }), {
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
  const json = (data, status = 200) =>
    new Response(JSON.stringify(data), {
      status,
      headers: { 'Content-Type': 'application/json' },
    });

  try {
    // POST /api/signup
    if (path === '/api/signup' && request.method === 'POST') {
      const { email, password, name } = await request.json();
      if (!email || !password) return json({ error: 'Email and password are required' }, 400);
      if (password.length < 8) return json({ error: 'Password must be at least 8 characters' }, 400);

      const existingUser = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
      if (existingUser) return json({ error: 'An account with this email already exists' }, 409);

      const hash = await hashPassword(password);

      await env.DB.prepare('DELETE FROM pending_signups WHERE email = ?').bind(email).run();
      await env.DB.prepare('DELETE FROM verification_codes WHERE email = ? AND purpose = ?').bind(email, 'signup').run();

      await env.DB.prepare('INSERT INTO pending_signups (email, password_hash, name) VALUES (?, ?, ?)')
        .bind(email, hash, name || '').run();

      const code = generateCode();
      const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();
      await env.DB.prepare('INSERT INTO verification_codes (email, code, purpose, expires_at) VALUES (?, ?, ?, ?)')
        .bind(email, code, 'signup', expires).run();

      await sendEmail(env, email, 'Omniilink Verification Code', `Your verification code is: ${code}\n\nThis code expires in 10 minutes.`);

      return json({ success: true, message: 'Verification code sent to your email' });
    }

    // POST /api/resend-code
    if (path === '/api/resend-code' && request.method === 'POST') {
      const { email } = await request.json();
      if (!email) return json({ error: 'Email is required' }, 400);

      const user = await env.DB.prepare('SELECT id FROM pending_signups WHERE email = ?').bind(email).first();
      if (!user) return json({ error: 'No unverified signup found for this email' }, 400);

      const code = generateCode();
      const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();
      await env.DB.prepare('UPDATE verification_codes SET used = 1 WHERE email = ? AND purpose = ?').bind(email, 'signup').run();
      await env.DB.prepare('INSERT INTO verification_codes (email, code, purpose, expires_at) VALUES (?, ?, ?, ?)')
        .bind(email, code, 'signup', expires).run();

      await sendEmail(env, email, 'Omniilink Verification Code', `Your verification code is: ${code}\n\nThis code expires in 10 minutes.`);
      return json({ success: true, message: 'A new verification code has been sent' });
    }

    // POST /api/verify
    if (path === '/api/verify' && request.method === 'POST') {
      const { email, code } = await request.json();
      if (!email || !code) return json({ error: 'Email and verification code are required' }, 400);

      const record = await env.DB.prepare(
        'SELECT id FROM verification_codes WHERE email = ? AND code = ? AND purpose = ? AND used = 0 AND expires_at > datetime(\'now\')'
      ).bind(email, code, 'signup').first();

      if (!record) return json({ error: 'Invalid or expired verification code' }, 400);

      const pending = await env.DB.prepare('SELECT email, password_hash, name FROM pending_signups WHERE email = ?').bind(email).first();
      if (!pending) return json({ error: 'No pending signup found. Please sign up again.' }, 400);

      await env.DB.prepare('INSERT INTO users (email, password_hash, name, email_verified) VALUES (?, ?, ?, 1)')
        .bind(pending.email, pending.password_hash, pending.name).run();

      await env.DB.prepare('UPDATE verification_codes SET used = 1 WHERE id = ?').bind(record.id).run();
      await env.DB.prepare('DELETE FROM pending_signups WHERE email = ?').bind(email).run();

      const user = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
      const token = await createSession(env, user.id);

      return json({ success: true, token, message: 'Email verified successfully' });
    }

    // POST /api/signin
    if (path === '/api/signin' && request.method === 'POST') {
      const { email, password } = await request.json();
      if (!email || !password) return json({ error: 'Email and password are required' }, 400);

      const user = await env.DB.prepare('SELECT id, password_hash, email_verified FROM users WHERE email = ?').bind(email).first();
      if (!user) return json({ error: 'Invalid email or password' }, 401);

      const valid = await verifyPassword(password, user.password_hash);
      if (!valid) return json({ error: 'Invalid email or password' }, 401);

      if (!user.email_verified) {
        const code = generateCode();
        const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();
        await env.DB.prepare('INSERT INTO verification_codes (email, code, purpose, expires_at) VALUES (?, ?, ?, ?)')
          .bind(email, code, 'signup', expires).run();
        await sendEmail(env, email, 'Omniilink Verification Code', `Your verification code is: ${code}\n\nThis code expires in 10 minutes.`);
        return json({ error: 'Email not verified', needsVerification: true }, 403);
      }

      const token = await createSession(env, user.id);
      return json({ success: true, token });
    }

    // POST /api/forgot-password
    if (path === '/api/forgot-password' && request.method === 'POST') {
      const { email } = await request.json();
      const user = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
      if (!user) return json({ success: true, message: 'If the email exists, a reset code was sent' });

      const code = generateCode();
      const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();
      await env.DB.prepare('INSERT INTO verification_codes (email, code, purpose, expires_at) VALUES (?, ?, ?, ?)')
        .bind(email, code, 'reset', expires).run();
      await sendEmail(env, email, 'Omniilink Password Reset', `Your password reset code is: ${code}\n\nThis code expires in 10 minutes.`);
      return json({ success: true, message: 'If the email exists, a reset code was sent' });
    }

    // POST /api/reset-password
    if (path === '/api/reset-password' && request.method === 'POST') {
      const { email, code, newPassword } = await request.json();
      if (!email || !code || !newPassword) return json({ error: 'Email, code, and new password are required' }, 400);
      if (newPassword.length < 8) return json({ error: 'Password must be at least 8 characters' }, 400);

      const record = await env.DB.prepare(
        'SELECT id FROM verification_codes WHERE email = ? AND code = ? AND purpose = ? AND used = 0 AND expires_at > datetime(\'now\')'
      ).bind(email, code, 'reset').first();
      if (!record) return json({ error: 'Invalid or expired reset code' }, 400);

      const hash = await hashPassword(newPassword);
      await env.DB.prepare('UPDATE users SET password_hash = ? WHERE email = ?').bind(hash, email).run();
      await env.DB.prepare('UPDATE verification_codes SET used = 1 WHERE id = ?').bind(record.id).run();
      return json({ success: true, message: 'Password has been reset successfully' });
    }

    // Authenticated routes below
    const user = await authenticateUser(request, env);
    if (!user) return json({ error: 'Authentication required' }, 401);

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
        if (newPassword.length < 8) return json({ error: 'New password must be at least 8 characters' }, 400);
        if (!currentPassword) return json({ error: 'Current password is required' }, 400);
        const u = await env.DB.prepare('SELECT password_hash FROM users WHERE id = ?').bind(user.id).first();
        if (!await verifyPassword(currentPassword, u.password_hash)) return json({ error: 'Current password is incorrect' }, 400);
        await env.DB.prepare('UPDATE users SET password_hash = ? WHERE id = ?').bind(await hashPassword(newPassword), user.id).run();
      }
      if (name !== undefined) {
        await env.DB.prepare('UPDATE users SET name = ? WHERE id = ?').bind(name, user.id).run();
      }
      return json({ success: true, message: 'Profile updated' });
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
      if (!provider || !api_key) return json({ error: 'Provider and API key are required' }, 400);

      const existing = await env.DB.prepare('SELECT id FROM user_api_keys WHERE user_id = ? AND provider = ?')
        .bind(user.id, provider).first();
      if (existing) {
        await env.DB.prepare('UPDATE user_api_keys SET api_key = ?, updated_at = datetime(\'now\') WHERE id = ?')
          .bind(api_key, existing.id).run();
      } else {
        await env.DB.prepare('INSERT INTO user_api_keys (user_id, provider, api_key) VALUES (?, ?, ?)')
          .bind(user.id, provider, api_key).run();
      }
      return json({ success: true, message: 'API key saved' });
    }

    // DELETE /api/api-keys/:id
    if (path.startsWith('/api/api-keys/') && request.method === 'DELETE') {
      const id = path.split('/').pop();
      await env.DB.prepare('DELETE FROM user_api_keys WHERE id = ? AND user_id = ?').bind(id, user.id).run();
      return json({ success: true, message: 'API key deleted' });
    }

    // GET /api/backend-url
    if (path === '/api/backend-url' && request.method === 'GET') {
      const setting = await env.DB.prepare('SELECT value FROM settings WHERE key = ?').bind('backend_url').first();
      return json({ url: setting?.value || '' });
    }

    return json({ error: 'Endpoint not found' }, 404);
  } catch (err) {
    console.error('API error:', err);
    return json({ error: 'An unexpected error occurred' }, 500);
  }
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

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function generateCode() {
  const bytes = new Uint8Array(4);
  crypto.getRandomValues(bytes);
  const num = (bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]) >>> 0;
  return (100000 + (num % 900000)).toString();
}

function generateToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function createSession(env, userId) {
  const token = generateToken();
  const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
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
    const resp = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + env.RESEND_API_KEY,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: 'Omniilink <onboarding@resend.dev>',
        to: [to],
        subject,
        text: body,
      }),
    });
    const data = await resp.json();
    if (data.id) {
      console.log('Email sent:', data.id);
    } else {
      console.log('Email send failed:', JSON.stringify(data));
    }
  } catch (e) {
    console.log('Email send error:', e.message);
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
<title>Omniilink - Account</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#09090b;--bg2:#111113;--bg3:#18181b;--border:#27272a;--text:#fafafa;--text2:#a1a1aa;--accent:#2563eb;--accent2:#3b82f6;--success:#22c55e;--error:#ef4444;--radius:10px}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;line-height:1.5}
.container{width:100%;max-width:420px}
.logo{display:flex;align-items:center;gap:12px;margin-bottom:32px;justify-content:center}
.logo-icon{width:40px;height:40px;background:var(--accent);border-radius:10px;display:flex;align-items:center;justify-content:center}
.logo-icon svg{width:24px;height:24px;fill:none;stroke:#fff;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.logo-text{font-size:24px;font-weight:700;letter-spacing:-0.5px}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:32px}
h2{font-size:20px;margin-bottom:4px;font-weight:600}
.subtitle{color:var(--text2);font-size:14px;margin-bottom:24px}
.form-group{margin-bottom:16px}
label{display:block;font-size:13px;color:var(--text2);margin-bottom:6px;font-weight:500}
input,select{width:100%;padding:10px 14px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:14px;outline:none;transition:border-color 0.15s;font-family:inherit}
input:focus,select:focus{border-color:var(--accent)}
select{cursor:pointer;-webkit-appearance:none;appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%23a1a1aa' stroke-width='2'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 12px center;padding-right:36px}
.btn{width:100%;padding:10px;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;transition:all 0.15s;font-family:inherit}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:var(--accent2)}
.btn-secondary{background:var(--bg3);color:var(--text);border:1px solid var(--border)}
.btn-secondary:hover{border-color:var(--accent)}
.links{text-align:center;margin-top:16px;font-size:13px;color:var(--text2)}
.links a{color:var(--accent);text-decoration:none;cursor:pointer}
.links a:hover{text-decoration:underline}
.error{color:var(--error);font-size:13px;margin-bottom:12px;display:none}
.success{color:var(--success);font-size:13px;margin-bottom:12px;display:none}
.hidden{display:none !important}
.code-inputs{display:flex;gap:8px;justify-content:center;margin:20px 0}
.code-inputs input{width:48px;text-align:center;font-size:20px;padding:12px 0;font-family:monospace}
.settings{padding:20px 0}
.settings h3{font-size:16px;margin-bottom:12px;font-weight:600}
.key-list{margin:12px 0}
.key-item{display:flex;align-items:center;justify-content:space-between;padding:10px 14px;background:var(--bg);border:1px solid var(--border);border-radius:8px;margin-bottom:8px;font-size:13px}
.key-item .provider{font-weight:600;color:var(--accent)}
.key-item .date{color:var(--text2);font-size:11px}
.key-item .del{color:var(--error);cursor:pointer;border:none;background:none;font-size:18px;padding:0 4px;line-height:1}
.tutorial{margin-top:24px;padding:20px;background:var(--bg);border:1px solid var(--border);border-radius:8px}
.tutorial h4{margin-bottom:8px;font-size:14px;font-weight:600}
.tutorial p{font-size:13px;color:var(--text2);line-height:1.6;margin-bottom:8px}
.tutorial ol{font-size:13px;color:var(--text2);line-height:1.8;padding-left:20px}
.tutorial a{color:var(--accent);text-decoration:none}
.tutorial a:hover{text-decoration:underline}
.storage-bar{height:6px;background:var(--bg);border-radius:3px;overflow:hidden;margin:8px 0}
.storage-fill{height:100%;background:var(--accent);border-radius:3px;transition:width 0.3s}
.storage-text{font-size:12px;color:var(--text2)}
</style>
</head>
<body>
<div class="container">
  <div class="logo">
    <div class="logo-icon"><svg viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg></div>
    <span class="logo-text">Omniilink</span>
  </div>

  <!-- Sign Up Form -->
  <div id="signup-view" class="card">
    <h2>Create Account</h2>
    <p class="subtitle">Get started with Omniilink</p>
    <div id="signup-error" class="error"></div>
    <div id="signup-success" class="success"></div>
    <div class="form-group">
      <label for="signup-name">Name</label>
      <input type="text" id="signup-name" placeholder="Your name">
    </div>
    <div class="form-group">
      <label for="signup-email">Email</label>
      <input type="email" id="signup-email" placeholder="you@example.com">
    </div>
    <div class="form-group">
      <label for="signup-password">Password</label>
      <input type="password" id="signup-password" placeholder="At least 8 characters">
    </div>
    <button class="btn btn-primary" onclick="doSignup()">Create Account</button>
    <p class="links">Already have an account? <a onclick="showView('signin')">Sign in</a></p>
  </div>

  <!-- Sign In Form -->
  <div id="signin-view" class="card hidden">
    <h2>Sign In</h2>
    <p class="subtitle">Welcome back to Omniilink</p>
    <div id="signin-error" class="error"></div>
    <div class="form-group">
      <label for="signin-email">Email</label>
      <input type="email" id="signin-email" placeholder="you@example.com">
    </div>
    <div class="form-group">
      <label for="signin-password">Password</label>
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
        <label for="forgot-email">Email</label>
        <input type="email" id="forgot-email" placeholder="you@example.com">
      </div>
      <button class="btn btn-primary" onclick="doForgot()">Send Code</button>
    </div>
    <div id="forgot-step2" class="hidden">
      <div class="form-group">
        <label for="reset-code">Code</label>
        <input type="text" id="reset-code" placeholder="6-digit code" maxlength="6">
      </div>
      <div class="form-group">
        <label for="reset-password">New Password</label>
        <input type="password" id="reset-password" placeholder="At least 8 characters">
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
        <select id="key-provider" style="flex:1">
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
        <li>Go to <a href="https://useomniilink.omniilink.workers.dev" onclick="launchApp(event)">useomniilink.omniilink.workers.dev</a></li>
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
  document.querySelectorAll('.card').forEach(function(c) { c.classList.add('hidden'); });
  document.getElementById(view + '-view').classList.remove('hidden');
}

async function api(path, method, body) {
  method = method || 'GET';
  body = body || null;
  var opts = { method: method, headers: { 'Content-Type': 'application/json' } };
  var token = localStorage.getItem('omniilink_token');
  if (token) opts.headers['Authorization'] = 'Bearer ' + token;
  if (body) opts.body = JSON.stringify(body);
  var r = await fetch(API + path, opts);
  return r.json();
}

document.querySelectorAll('.code-digit').forEach(function(input, i, arr) {
  input.addEventListener('input', function() {
    if (input.value && i < arr.length - 1) arr[i + 1].focus();
  });
  input.addEventListener('keydown', function(e) {
    if (e.key === 'Backspace' && !input.value && i > 0) arr[i - 1].focus();
  });
});

function getCode() {
  return Array.from(document.querySelectorAll('.code-digit')).map(function(i) { return i.value; }).join('');
}

function showError(id, msg) {
  var el = document.getElementById(id);
  el.textContent = msg;
  el.style.display = 'block';
}

function hideError(id) {
  var el = document.getElementById(id);
  el.style.display = 'none';
}

function showSuccess(id, msg) {
  var el = document.getElementById(id);
  el.textContent = msg;
  el.style.display = 'block';
}

function hideSuccess(id) {
  var el = document.getElementById(id);
  el.style.display = 'none';
}

async function doSignup() {
  hideError('signup-error');
  hideSuccess('signup-success');
  var name = document.getElementById('signup-name').value.trim();
  var email = document.getElementById('signup-email').value.trim();
  var password = document.getElementById('signup-password').value;
  if (!email || !password) return showError('signup-error', 'Email and password are required');
  if (password.length < 8) return showError('signup-error', 'Password must be at least 8 characters');
  currentEmail = email;
  var r = await api('/api/signup', 'POST', { name: name, email: email, password: password });
  if (r.error) return showError('signup-error', r.error);
  verifyPurpose = 'signup';
  showView('verify');
}

async function doSignin() {
  hideError('signin-error');
  var email = document.getElementById('signin-email').value.trim();
  var password = document.getElementById('signin-password').value;
  if (!email || !password) return showError('signin-error', 'Email and password are required');
  currentEmail = email;
  var r = await api('/api/signin', 'POST', { email: email, password: password });
  if (r.error) {
    if (r.needsVerification) { verifyPurpose = 'signup'; showView('verify'); return; }
    return showError('signin-error', r.error);
  }
  localStorage.setItem('omniilink_token', r.token);
  localStorage.setItem('omniilink_email', email);
  loadDashboard();
}

async function doVerify() {
  hideError('verify-error');
  var code = getCode();
  if (code.length !== 6) return showError('verify-error', 'Please enter the full 6-digit code');
  var r = await api('/api/verify', 'POST', { email: currentEmail, code: code });
  if (r.error) return showError('verify-error', r.error);
  localStorage.setItem('omniilink_token', r.token);
  localStorage.setItem('omniilink_email', currentEmail);
  loadDashboard();
}

async function resendCode() {
  hideError('verify-error');
  var r = await api('/api/resend-code', 'POST', { email: currentEmail });
  if (r.error) return showError('verify-error', r.error);
  showSuccess('verify-success', 'A new code has been sent to your email');
}

async function doForgot() {
  hideError('forgot-error');
  hideSuccess('forgot-success');
  var email = document.getElementById('forgot-email').value.trim();
  if (!email) return showError('forgot-error', 'Email is required');
  currentEmail = email;
  var r = await api('/api/forgot-password', 'POST', { email: email });
  if (r.error) return showError('forgot-error', r.error);
  showSuccess('forgot-success', 'If the email exists, a reset code was sent');
  document.getElementById('forgot-step1').classList.add('hidden');
  document.getElementById('forgot-step2').classList.remove('hidden');
}

async function doReset() {
  hideError('forgot-error');
  var code = document.getElementById('reset-code').value.trim();
  var newPassword = document.getElementById('reset-password').value;
  if (!code) return showError('forgot-error', 'Reset code is required');
  if (!newPassword) return showError('forgot-error', 'New password is required');
  if (newPassword.length < 8) return showError('forgot-error', 'Password must be at least 8 characters');
  var r = await api('/api/reset-password', 'POST', { email: currentEmail, code: code, newPassword: newPassword });
  if (r.error) return showError('forgot-error', r.error);
  showView('signin');
  showSuccess('signin-success', 'Password reset successful. Please sign in with your new password.');
}

async function loadDashboard() {
  showView('dashboard');
  var r = await api('/api/user');
  if (r.error) { showView('signin'); return; }
  var u = r.user;
  document.getElementById('user-info').innerHTML =
    '<div style="font-size:14px;font-weight:600">' + escapeHtml(u.name || u.email) + '</div>' +
    '<div style="font-size:12px;color:var(--text2)">' + escapeHtml(u.email) + '</div>';
  var used = (u.storage_used_bytes / 1073741824).toFixed(2);
  var limit = (u.storage_limit_bytes / 1073741824).toFixed(0);
  var pct = (u.storage_used_bytes / u.storage_limit_bytes * 100).toFixed(1);
  document.getElementById('storage-fill').style.width = pct + '%';
  document.getElementById('storage-text').textContent = used + ' / ' + limit + ' GB used';
  loadKeys();
}

async function loadKeys() {
  var r = await api('/api/api-keys');
  var list = document.getElementById('key-list');
  if (!r.keys || r.keys.length === 0) {
    list.innerHTML = '<p style="font-size:12px;color:var(--text2)">No API keys added yet</p>';
    return;
  }
  list.innerHTML = r.keys.map(function(k) {
    return '<div class="key-item">' +
      '<span class="provider">' + escapeHtml(k.provider) + '</span>' +
      '<span class="date">Added ' + new Date(k.created_at).toLocaleDateString() + '</span>' +
      '<button class="del" onclick="deleteKey(' + parseInt(k.id, 10) + ')">&times;</button>' +
    '</div>';
  }).join('');
}

async function saveApiKey() {
  var provider = document.getElementById('key-provider').value;
  var api_key = document.getElementById('key-value').value.trim();
  if (!api_key) return;
  await api('/api/api-keys', 'POST', { provider: provider, api_key: api_key });
  document.getElementById('key-value').value = '';
  loadKeys();
}

async function deleteKey(id) {
  await api('/api/api-keys/' + id, 'DELETE');
  loadKeys();
}

function launchApp(e) {
  e.preventDefault();
  var token = localStorage.getItem('omniilink_token');
  if (token) {
    window.location.href = 'https://useomniilink.omniilink.workers.dev?token=' + token;
  } else {
    window.location.href = 'https://useomniilink.omniilink.workers.dev';
  }
}

function doSignout() {
  localStorage.removeItem('omniilink_token');
  localStorage.removeItem('omniilink_email');
  showView('signin');
}

window.addEventListener('load', function() {
  if (localStorage.getItem('omniilink_token')) loadDashboard();
});
</script>
</body>
</html>`;
}
