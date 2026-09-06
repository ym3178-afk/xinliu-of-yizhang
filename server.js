const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = Number(process.env.PORT || 8787);
const STATE_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const connections = new Map();

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

const allowedOrigins = String(process.env.APP_ORIGIN || '')
  .split(',').map(x => x.trim()).filter(Boolean);
app.use(cors({
  origin(origin, cb) {
    if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) return cb(null, true);
    return cb(new Error('Origin not allowed by APP_ORIGIN'));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Accept']
}));

function base64url(input) {
  return Buffer.from(input).toString('base64url');
}
function signState(payload) {
  const body = base64url(JSON.stringify(payload));
  const sig = crypto.createHmac('sha256', STATE_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}
function readState(value) {
  const [body, sig] = String(value || '').split('.');
  if (!body || !sig) throw new Error('invalid state');
  const expected = crypto.createHmac('sha256', STATE_SECRET).update(body).digest('base64url');
  if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
    throw new Error('state signature mismatch');
  }
  const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  if (!payload.ts || Date.now() - payload.ts > 10 * 60 * 1000) throw new Error('state expired');
  return payload;
}
function env(name, fallback = '') { return process.env[name] || fallback; }

const providers = {
  baidu: {
    label: '百度网盘',
    clientId: () => env('BAIDU_CLIENT_ID'),
    clientSecret: () => env('BAIDU_CLIENT_SECRET'),
    redirectUri: () => env('BAIDU_REDIRECT_URI'),
    authorize(state) {
      const u = new URL('https://openapi.baidu.com/oauth/2.0/authorize');
      u.searchParams.set('response_type', 'code');
      u.searchParams.set('client_id', this.clientId());
      u.searchParams.set('redirect_uri', this.redirectUri());
      u.searchParams.set('scope', env('BAIDU_SCOPE', 'basic,netdisk'));
      u.searchParams.set('state', state);
      return u.toString();
    },
    async exchange(code) {
      const body = new URLSearchParams({
        grant_type: 'authorization_code', code,
        client_id: this.clientId(), client_secret: this.clientSecret(),
        redirect_uri: this.redirectUri()
      });
      return fetchJson('https://openapi.baidu.com/oauth/2.0/token', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body
      });
    },
    async profile(token) {
      const u = new URL('https://openapi.baidu.com/rest/2.0/passport/users/getInfo');
      u.searchParams.set('access_token', token);
      const p = await fetchJson(u);
      return { id: p.userid || p.openid || '', name: p.username || p.realname || '百度用户' };
    },
    token(data) { return data.access_token; },
    refresh(data) { return data.refresh_token || ''; },
    expires(data) { return Number(data.expires_in || 0); }
  },
  yuque: {
    label: '语雀文档',
    clientId: () => env('YUQUE_CLIENT_ID'),
    clientSecret: () => env('YUQUE_CLIENT_SECRET'),
    redirectUri: () => env('YUQUE_REDIRECT_URI'),
    authorize(state) {
      const u = new URL('https://www.yuque.com/oauth2/authorize');
      u.searchParams.set('client_id', this.clientId());
      u.searchParams.set('scope', env('YUQUE_SCOPE', 'group,book,design,sheet,doc,repo'));
      u.searchParams.set('state', state);
      u.searchParams.set('response_type', 'code');
      return u.toString();
    },
    async exchange(code) {
      const payload = { client_id: this.clientId(), client_secret: this.clientSecret(), code, grant_type: 'authorization_code' };
      return fetchJson('https://www.yuque.com/oauth2/token', {
        method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(payload)
      });
    },
    async profile(token) {
      const p = await fetchJson('https://www.yuque.com/api/v2/user', { headers: { 'X-Auth-Token': token, Accept: 'application/json' } });
      const d = p.data || p;
      return { id: d.id || '', name: d.name || d.login || '语雀用户', login: d.login || '' };
    },
    token(data) { return data.access_token || data.data?.access_token; },
    refresh(data) { return data.refresh_token || data.data?.refresh_token || ''; },
    expires(data) { return Number(data.expires_in || data.data?.expires_in || 0); }
  },
  feishu: {
    label: '飞书文档',
    clientId: () => env('FEISHU_CLIENT_ID'),
    clientSecret: () => env('FEISHU_CLIENT_SECRET'),
    redirectUri: () => env('FEISHU_REDIRECT_URI'),
    authorize(state) {
      const u = new URL('https://accounts.feishu.cn/open-apis/authen/v1/authorize');
      u.searchParams.set('app_id', this.clientId());
      u.searchParams.set('redirect_uri', this.redirectUri());
      u.searchParams.set('state', state);
      const scope = env('FEISHU_SCOPE'); if (scope) u.searchParams.set('scope', scope);
      return u.toString();
    },
    async exchange(code) {
      const payload = {
        grant_type: 'authorization_code', client_id: this.clientId(), client_secret: this.clientSecret(),
        code, redirect_uri: this.redirectUri()
      };
      return fetchJson('https://open.feishu.cn/open-apis/authen/v2/oauth/token', {
        method: 'POST', headers: { 'Content-Type': 'application/json; charset=utf-8', Accept: 'application/json' }, body: JSON.stringify(payload)
      });
    },
    async profile(token) {
      const p = await fetchJson('https://open.feishu.cn/open-apis/authen/v1/user_info', {
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' }
      });
      const d = p.data || p;
      return { id: d.open_id || d.user_id || '', name: d.name || d.en_name || '飞书用户' };
    },
    token(data) { return data.access_token || data.data?.access_token; },
    refresh(data) { return data.refresh_token || data.data?.refresh_token || ''; },
    expires(data) { return Number(data.expires_in || data.data?.expires_in || 0); }
  },
  dingtalk: {
    label: '钉钉文档',
    clientId: () => env('DINGTALK_CLIENT_ID'),
    clientSecret: () => env('DINGTALK_CLIENT_SECRET'),
    redirectUri: () => env('DINGTALK_REDIRECT_URI'),
    authorize(state) {
      const u = new URL('https://login.dingtalk.com/oauth2/auth');
      u.searchParams.set('redirect_uri', this.redirectUri());
      u.searchParams.set('response_type', 'code');
      u.searchParams.set('client_id', this.clientId());
      u.searchParams.set('scope', env('DINGTALK_SCOPE', 'openid'));
      u.searchParams.set('state', state);
      u.searchParams.set('prompt', 'consent');
      return u.toString();
    },
    async exchange(code) {
      const payload = { clientId: this.clientId(), clientSecret: this.clientSecret(), code, grantType: 'authorization_code' };
      return fetchJson('https://api.dingtalk.com/v1.0/oauth2/userAccessToken', {
        method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(payload)
      });
    },
    async profile(token) {
      const p = await fetchJson('https://api.dingtalk.com/v1.0/contact/users/me', {
        headers: { 'x-acs-dingtalk-access-token': token, Accept: 'application/json' }
      });
      return { id: p.openId || p.unionId || '', name: p.nick || p.name || '钉钉用户' };
    },
    token(data) { return data.accessToken || data.access_token || data.data?.accessToken; },
    refresh(data) { return data.refreshToken || data.refresh_token || ''; },
    expires(data) { return Number(data.expireIn || data.expires_in || 0); }
  }
};

async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  const text = await response.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }
  if (!response.ok) {
    const msg = data.error_description || data.error || data.message || data.msg || `HTTP ${response.status}`;
    throw new Error(msg);
  }
  if (data.code && data.code !== 0 && !data.access_token && !data.accessToken && !data.data?.access_token) {
    throw new Error(data.msg || data.message || `Provider error ${data.code}`);
  }
  return data;
}

function validateProvider(name) {
  const p = providers[name];
  if (!p) throw new Error('不支持的授权平台');
  const missing = [];
  if (!p.clientId()) missing.push('CLIENT_ID');
  if (!p.clientSecret()) missing.push('CLIENT_SECRET');
  if (!p.redirectUri()) missing.push('REDIRECT_URI');
  if (missing.length) {
    const err = new Error(`${p.label} OAuth 尚未配置：${missing.join(', ')}`);
    err.status = 503;
    throw err;
  }
  return p;
}

app.get('/api/health', (req, res) => res.json({ ok: true, providers: Object.keys(providers) }));

app.get('/api/oauth/status', (req, res) => {
  const sessionId = String(req.query.sessionId || '');
  const bucket = connections.get(sessionId) || {};
  const result = {};
  for (const name of Object.keys(providers)) {
    const c = bucket[name];
    result[name] = c ? { connected: true, account: c.account?.name || '', connectedAt: c.connectedAt } : { connected: false };
  }
  res.json({ providers: result });
});

app.get('/api/oauth/:provider/start', (req, res) => {
  try {
    const providerName = req.params.provider;
    const p = validateProvider(providerName);
    const sessionId = String(req.query.sessionId || '').trim();
    if (!sessionId || sessionId.length > 200) return res.status(400).json({ error: '缺少有效 sessionId' });
    let returnOrigin = String(req.query.returnOrigin || '').trim();
    if (returnOrigin === '*') returnOrigin = '';
    if (allowedOrigins.length && returnOrigin && !allowedOrigins.includes(returnOrigin)) {
      return res.status(403).json({ error: 'returnOrigin 不在 APP_ORIGIN 白名单中' });
    }
    const state = signState({ provider: providerName, sessionId, returnOrigin, ts: Date.now() });
    res.json({ authorizationUrl: p.authorize(state) });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message || '启动授权失败' });
  }
});

app.get('/api/oauth/:provider/callback', async (req, res) => {
  const providerName = req.params.provider;
  try {
    const p = validateProvider(providerName);
    if (req.query.error) throw new Error(String(req.query.error_description || req.query.error));
    const code = String(req.query.code || '');
    if (!code) throw new Error('授权回调缺少 code');
    const state = readState(req.query.state);
    if (state.provider !== providerName) throw new Error('provider 与 state 不一致');

    const tokenData = await p.exchange(code);
    const accessToken = p.token(tokenData);
    if (!accessToken) throw new Error('平台未返回 access token');
    let account = { name: p.label.replace('文档', '').replace('网盘', '') + '用户' };
    try { account = await p.profile(accessToken); } catch (profileErr) { console.warn('profile fetch failed:', profileErr.message); }

    const bucket = connections.get(state.sessionId) || {};
    bucket[providerName] = {
      accessToken,
      refreshToken: p.refresh(tokenData),
      expiresAt: p.expires(tokenData) ? Date.now() + p.expires(tokenData) * 1000 : null,
      account,
      connectedAt: new Date().toISOString()
    };
    connections.set(state.sessionId, bucket);

    const targetOrigin = state.returnOrigin || '*';
    res.type('html').send(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>授权成功</title><body style="font-family:system-ui;padding:32px"><h2>✓ ${escapeHtml(p.label)} 已关联</h2><p>可以关闭此窗口并返回心流。</p><script>try{window.opener&&window.opener.postMessage(${JSON.stringify({type:'iflow-oauth-success', provider:providerName, account})},${JSON.stringify(targetOrigin)});}catch(e){} setTimeout(()=>window.close(),500);<\/script></body></html>`);
  } catch (err) {
    console.error(providerName, 'oauth callback failed:', err);
    res.status(400).type('html').send(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>授权失败</title><body style="font-family:system-ui;padding:32px"><h2>授权失败</h2><p>${escapeHtml(err.message || '未知错误')}</p><p>请关闭窗口后重试。</p></body></html>`);
  }
});

app.post('/api/oauth/:provider/disconnect', (req, res) => {
  const providerName = req.params.provider;
  if (!providers[providerName]) return res.status(404).json({ error: '不支持的平台' });
  const sessionId = String(req.body.sessionId || '');
  const bucket = connections.get(sessionId) || {};
  delete bucket[providerName];
  if (Object.keys(bucket).length) connections.set(sessionId, bucket); else connections.delete(sessionId);
  res.json({ ok: true });
});

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>'"]/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[ch]));
}

app.use(express.static(path.join(__dirname), { extensions: ['html'] }));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.listen(PORT, () => {
  console.log(`iFlow OAuth server running at http://localhost:${PORT}`);
  console.log('Configured providers:', Object.entries(providers).filter(([,p]) => p.clientId() && p.clientSecret() && p.redirectUri()).map(([k]) => k).join(', ') || 'none');
});
