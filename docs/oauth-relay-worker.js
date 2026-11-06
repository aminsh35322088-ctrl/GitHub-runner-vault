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
// seconds-lived. Deploy one per wizard copy and set ALLOWED_ORIGINS to its
// exact HTTPS origin.
const TOKEN_URL = 'https://dash.cloudflare.com/oauth2/token';

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const allowed = (typeof env.ALLOWED_ORIGINS === 'string' ? env.ALLOWED_ORIGINS : '')
      .split(',').map((value) => value.trim()).filter((value) => {
        try {
          const parsed = new URL(value);
          return parsed.protocol === 'https:' && parsed.origin === value &&
            parsed.pathname === '/' && !parsed.search && !parsed.hash;
        } catch {
          return false;
        }
      });
    // This relay handles authorization codes for a browser origin. Without
    // an explicit allowlist it must fail closed, never inherit the source
    // repository owner's GitHub Pages origin in a fork.
    if (!allowed.length) return new Response('Relay origin allowlist is not configured', { status: 503 });
    const ok = Boolean(origin) && allowed.includes(origin);
    const cors = ok ? {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Vary': 'Origin',
    } : {};
    if (!ok) return new Response('Origin not allowed', { status: 403 });
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }
    if (request.method !== 'POST') {
      return new Response('Method not allowed', { status: 405, headers: cors });
    }
    let form;
    try {
      form = await request.formData();
    } catch {
      return new Response('Bad request', { status: 400, headers: cors });
    }
    const body = new URLSearchParams();
    for (const k of ['code', 'redirect_uri', 'client_id', 'code_verifier']) {
      const v = form.get(k);
      if (typeof v === 'string' && v) body.set(k, v);
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
