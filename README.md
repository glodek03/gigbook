# Gigbook 🤘

Pamiętnik koncertowy: kolekcja koncertów, setlisty z setlist.fm, osiągnięcia i roczny Wrapped.

- `index.html` – cała aplikacja
- `manifest.json`, `sw.js`, ikony – instalacja na telefonie (PWA) i działanie offline
- `worker.js` – kod pośrednika do setlist.fm (Cloudflare Worker); klucz API trzymany jest w sekrecie `SETLIST_API_KEY` w Cloudflare, nigdy w tym repozytorium

Dane koncertów: [setlist.fm](https://www.setlist.fm)
