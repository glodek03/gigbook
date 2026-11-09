// Gigbook – serwer (Cloudflare Worker)
//  • pośrednik do setlist.fm (klucz API w sekrecie SETLIST_API_KEY)
//  • konta: nick + hasło, dane koncertów w KV (powiązanie o nazwie GIGBOOK)
// Odpowiada tylko aplikacji z adresów w ALLOWED_ORIGINS.

// 'null' = aplikacja otwarta z pliku na komputerze (podgląd przed publikacją)
const ALLOWED_ORIGINS = ['https://glodek03.github.io', 'null'];
const SETLIST = 'https://api.setlist.fm/rest/1.0';
const ITER = 20000;               // PBKDF2 – dopasowane do limitu CPU darmowego planu
const TOKEN_DAYS = 365;
const MAX_FAILS = 10;             // po 10 złych hasłach – 15 minut blokady
const MAX_DATA = 5 * 1024 * 1024; // 5 MB na konto
const MAX_PHOTO = 900 * 1024;     // jedno zdjęcie (JPEG jako data URL)
const MAX_FRIENDS = 100;

const enc = new TextEncoder();
const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromB64u = s => { const t = s.replace(/-/g, '+').replace(/_/g, '/'); return Uint8Array.from(atob(t + '='.repeat((4 - t.length % 4) % 4)), c => c.charCodeAt(0)); };

function cors(req) {
  const h = {
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Accept, Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
  const o = req.headers.get('Origin');
  if (o && ALLOWED_ORIGINS.includes(o)) h['Access-Control-Allow-Origin'] = o;
  return h;
}
const json = (req, obj, status = 200) => new Response(JSON.stringify(obj), {
  status, headers: { ...cors(req), 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
});
const fail = (req, status, error) => json(req, { error }, status);

async function hashPassword(password, salt, iter = ITER) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, key, 256);
  return b64u(bits);
}
function sameString(a, b) {
  if (a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
let hmacCache = null;
async function hmacKey(env) {
  if (!hmacCache) {
    // TOKEN_SECRET (opcjonalny sekret) albo klucz pochodny od SETLIST_API_KEY
    const base = env.TOKEN_SECRET || ('gigbook-token|' + env.SETLIST_API_KEY);
    hmacCache = crypto.subtle.importKey('raw', enc.encode(base), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  }
  return hmacCache;
}
async function makeToken(env, u) {
  const payload = b64u(enc.encode(JSON.stringify({ u, exp: Date.now() + TOKEN_DAYS * 864e5 })));
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(env), enc.encode(payload));
  return payload + '.' + b64u(sig);
}
async function readToken(env, req) {
  const m = (req.headers.get('Authorization') || '').match(/^Bearer\s+([\w-]+)\.([\w-]+)$/);
  if (!m) return null;
  try {
    const ok = await crypto.subtle.verify('HMAC', await hmacKey(env), fromB64u(m[2]), enc.encode(m[1]));
    if (!ok) return null;
    const p = JSON.parse(new TextDecoder().decode(fromB64u(m[1])));
    return p.exp > Date.now() ? p.u : null;
  } catch (e) { return null; }
}
async function readBody(req) { try { return await req.json(); } catch (e) { return null; } }
const cleanName = u => String(u || '').trim().toLowerCase();
const validName = u => /^[a-z0-9_.-]{3,24}$/.test(u);

async function register(req, env) {
  const b = await readBody(req); if (!b) return fail(req, 400, 'Błędne dane.');
  const u = cleanName(b.username), p = String(b.password || '');
  if (!validName(u)) return fail(req, 400, 'Nick: 3–24 znaki, tylko litery bez polskich znaków, cyfry, . _ -');
  if (p.length < 6 || p.length > 200) return fail(req, 400, 'Hasło musi mieć co najmniej 6 znaków.');
  if (await env.GIGBOOK.get('user:' + u)) return fail(req, 409, 'Ten nick jest już zajęty.');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await hashPassword(p, salt);
  await env.GIGBOOK.put('user:' + u, JSON.stringify({ salt: b64u(salt), hash, iter: ITER, created: Date.now() }));
  return json(req, { username: u, token: await makeToken(env, u) });
}

async function login(req, env) {
  const b = await readBody(req); if (!b) return fail(req, 400, 'Błędne dane.');
  const u = cleanName(b.username), p = String(b.password || '');
  const fails = Number(await env.GIGBOOK.get('fail:' + u)) || 0;
  if (fails >= MAX_FAILS) return fail(req, 429, 'Za dużo prób. Spróbuj ponownie za 15 minut.');
  const raw = validName(u) ? await env.GIGBOOK.get('user:' + u) : null;
  if (raw) {
    const user = JSON.parse(raw);
    const hash = await hashPassword(p, fromB64u(user.salt), user.iter || ITER);
    if (sameString(hash, user.hash)) return json(req, { username: u, token: await makeToken(env, u) });
  }
  if (validName(u)) await env.GIGBOOK.put('fail:' + u, String(fails + 1), { expirationTtl: 900 });
  return fail(req, 401, 'Zły nick lub hasło.');
}

async function data(req, env) {
  const u = await readToken(env, req);
  if (!u) return fail(req, 401, 'Zaloguj się ponownie.');
  if (req.method === 'GET') {
    const raw = await env.GIGBOOK.get('data:' + u);
    return json(req, raw ? JSON.parse(raw) : { data: null, updatedAt: 0 });
  }
  if (req.method === 'PUT') {
    const text = await req.text();
    if (text.length > MAX_DATA) return fail(req, 413, 'Za dużo danych (limit 5 MB).');
    let b; try { b = JSON.parse(text); } catch (e) { return fail(req, 400, 'Błędne dane.'); }
    if (!b || !b.data || !Array.isArray(b.data.concerts)) return fail(req, 400, 'Błędne dane.');
    const rec = { data: b.data, updatedAt: Date.now() };
    await env.GIGBOOK.put('data:' + u, JSON.stringify(rec));
    return json(req, { ok: true, updatedAt: rec.updatedAt });
  }
  return fail(req, 405, 'Niedozwolona metoda.');
}

const getList = async (env, key) => { try { return JSON.parse(await env.GIGBOOK.get(key)) || []; } catch (e) { return []; } };

async function friends(req, env, u) {
  if (req.method === 'GET') {
    const mine = await getList(env, 'friends:' + u);
    const followers = await getList(env, 'followers:' + u);
    return json(req, {
      friends: mine.map(f => ({ u: f, mutual: followers.includes(f) })),
      requests: followers.filter(f => !mine.includes(f)),
    });
  }
  if (req.method === 'POST') {
    const b = await readBody(req) || {};
    const add = cleanName(b.add), remove = cleanName(b.remove);
    let mine = await getList(env, 'friends:' + u);
    if (add) {
      if (!validName(add) || add === u) return fail(req, 400, 'Niepoprawny nick.');
      if (!(await env.GIGBOOK.get('user:' + add))) return fail(req, 404, 'Nie ma takiego użytkownika.');
      if (!mine.includes(add)) {
        if (mine.length >= MAX_FRIENDS) return fail(req, 400, 'Za dużo znajomych.');
        mine.push(add); await env.GIGBOOK.put('friends:' + u, JSON.stringify(mine));
        const fol = await getList(env, 'followers:' + add);
        if (!fol.includes(u)) { fol.push(u); await env.GIGBOOK.put('followers:' + add, JSON.stringify(fol)); }
      }
    } else if (remove) {
      if (mine.includes(remove)) { mine = mine.filter(f => f !== remove); await env.GIGBOOK.put('friends:' + u, JSON.stringify(mine)); }
      const fol = await getList(env, 'followers:' + remove);
      if (fol.includes(u)) await env.GIGBOOK.put('followers:' + remove, JSON.stringify(fol.filter(f => f !== u)));
    } else return fail(req, 400, 'Błędne dane.');
    return json(req, { ok: true });
  }
  return fail(req, 405, 'Niedozwolona metoda.');
}

// Kolekcja znajomego – tylko gdy obie strony się dodały; bez prywatnych notatek
async function friendData(req, env, u, other) {
  other = cleanName(other);
  const [mine, theirs] = await Promise.all([getList(env, 'friends:' + u), getList(env, 'friends:' + other)]);
  if (!mine.includes(other) || !theirs.includes(u)) return fail(req, 403, 'Kolekcję widać dopiero, gdy oboje dodacie się do znajomych.');
  const raw = await env.GIGBOOK.get('data:' + other);
  const d = raw ? JSON.parse(raw).data : null;
  const concerts = d && Array.isArray(d.concerts) ? d.concerts.map(c => { const { note, photos, ...rest } = c; return rest; }) : [];
  return json(req, { u: other, concerts });
}

async function photo(req, env, u, id) {
  if (!/^[\w-]{6,40}$/.test(id)) return fail(req, 400, 'Błędny identyfikator zdjęcia.');
  const key = 'photo:' + u + ':' + id;
  if (req.method === 'GET') {
    const v = await env.GIGBOOK.get(key);
    return v ? json(req, { data: v }) : fail(req, 404, 'Brak zdjęcia.');
  }
  if (req.method === 'PUT') {
    const text = await req.text();
    if (text.length > MAX_PHOTO) return fail(req, 413, 'Zdjęcie jest za duże.');
    if (!/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(text)) return fail(req, 400, 'To nie jest obrazek.');
    await env.GIGBOOK.put(key, text);
    return json(req, { ok: true });
  }
  if (req.method === 'DELETE') { await env.GIGBOOK.delete(key); return json(req, { ok: true }); }
  return fail(req, 405, 'Niedozwolona metoda.');
}

async function setlist(req, env, url) {
  const allowed = /^\/(search\/setlists|setlist\/[\w-]+|artist\/[\w-]+\/setlists)$/;
  if (!allowed.test(url.pathname)) return fail(req, 404, 'Nie ma takiej ścieżki.');
  if (!env.SETLIST_API_KEY) return fail(req, 500, 'Brak sekretu SETLIST_API_KEY.');
  const r = await fetch(SETLIST + url.pathname + url.search, {
    headers: { 'x-api-key': env.SETLIST_API_KEY, 'Accept': 'application/json', 'Accept-Language': 'pl' },
    cf: { cacheTtl: url.pathname.startsWith('/setlist/') ? 21600 : 3600, cacheEverything: true },
  });
  return new Response(r.body, {
    status: r.status,
    headers: { ...cors(req), 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'public, max-age=3600' },
  });
}

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { headers: cors(req) });
    const url = new URL(req.url);
    if (url.pathname === '/') return new Response('Gigbook działa 🤘' + (env.GIGBOOK ? '' : ' (brak powiązania KV GIGBOOK!)'), { headers: { ...cors(req), 'Content-Type': 'text/plain; charset=utf-8' } });
    try {
      if (url.pathname.startsWith('/auth/') || url.pathname === '/data' || /^\/(friends|friend\/|photo\/)/.test(url.pathname)) {
        if (!env.GIGBOOK) return fail(req, 500, 'Serwer: brak powiązania KV „GIGBOOK”.');
        if (url.pathname === '/auth/register' && req.method === 'POST') return await register(req, env);
        if (url.pathname === '/auth/login' && req.method === 'POST') return await login(req, env);
        if (url.pathname === '/data') return await data(req, env);
        const me = await readToken(env, req);
        if (!me) return fail(req, 401, 'Zaloguj się ponownie.');
        if (url.pathname === '/friends') return await friends(req, env, me);
        let m;
        if ((m = url.pathname.match(/^\/friend\/([\w.-]+)$/)) && req.method === 'GET') return await friendData(req, env, me, m[1]);
        if ((m = url.pathname.match(/^\/photo\/([\w-]+)$/))) return await photo(req, env, me, m[1]);
        return fail(req, 404, 'Nie ma takiej ścieżki.');
      }
      if (req.method !== 'GET') return fail(req, 405, 'Niedozwolona metoda.');
      return await setlist(req, env, url);
    } catch (e) {
      return fail(req, 500, 'Błąd serwera.');
    }
  },
};
