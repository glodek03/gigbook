// Gigbook – pośrednik do setlist.fm (Cloudflare Worker)
// Klucz API trzymany jest w sekrecie SETLIST_API_KEY, nigdy w aplikacji.
export default {
  async fetch(request, env) {
    const cors = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Accept',
    };
    if (request.method === 'OPTIONS') return new Response(null, { headers: cors });
    if (request.method !== 'GET') return new Response('Tylko GET', { status: 405, headers: cors });

    const url = new URL(request.url);
    if (url.pathname === '/') return new Response('Gigbook proxy działa 🤘', { headers: cors });

    // Przepuszczamy tylko to, czego potrzebuje aplikacja
    const allowed = /^\/(search\/setlists|setlist\/[\w-]+|artist\/[\w-]+\/setlists)$/;
    if (!allowed.test(url.pathname)) return new Response('Nie ma takiej ścieżki', { status: 404, headers: cors });

    if (!env.SETLIST_API_KEY) return new Response('Brak sekretu SETLIST_API_KEY', { status: 500, headers: cors });

    const r = await fetch('https://api.setlist.fm/rest/1.0' + url.pathname + url.search, {
      headers: { 'x-api-key': env.SETLIST_API_KEY, 'Accept': 'application/json', 'Accept-Language': 'pl' },
      cf: { cacheTtl: 3600, cacheEverything: true },
    });
    return new Response(r.body, {
      status: r.status,
      headers: { ...cors, 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'public, max-age=3600' },
    });
  },
};
