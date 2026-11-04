// Vault setup wizard — OAuth token-exchange relay.
//
// Cloudflare's OAuth token endpoint (dash.cloudflare.com/oauth2/token) does
// not return CORS headers, so a browser page can complete the authorization
// step but can never read the token-exchange response. This stateless Worker
// forwards the exchange server-side and returns the result with CORS headers
// for the wizard origins in ALLOWED_ORIGINS (comma-separated env var).
//
// It stores nothing, logs nothing and has no secrets: the OAuth client is
// public (PKCE), and the authorization code it forwards is single-use and
// seconds-lived. Deploy one per wizard copy (see the vault README,
// "enable Cloudflare login").
const TOKEN_URL = 'https://dash.cloudflare.com/oauth2/token';
const DEFAULT_ORIGINS = 'https://aminsh35322088-ctrl.github.io';

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const allowed = (env.ALLOWED_ORIGINS || DEFAULT_ORIGINS)
      .split(',').map((s) => s.trim()).filter(Boolean);
    const ok = allowed.includes(origin);
    const cors = ok ? {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Vary': 'Origin',
    } : {};
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }
    if (request.method !== 'POST') {
      return new Response('Method not allowed', { status: 405, headers: cors });
    }
    if (!ok) return new Response('Origin not allowed', { status: 403 });
    let form;
    try {
      form = await request.formData();
    } catch {
      return new Response('Bad request', { status: 400, headers: cors });
    }
    const body = new URLSearchParams();
    for (const k of ['code', 'redirect_uri', 'client_id', 'code_verifier']) {
      const v = form.get(k);
      if (v) body.set(k, v);
    }
    body.set('grant_type', 'authorization_code');
    const res = await fetch(TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
    const text = await res.text();
    return new Response(text, {
      status: res.status,
      headers: { ...cors, 'Content-Type': 'application/json' },
    });
  },
};
