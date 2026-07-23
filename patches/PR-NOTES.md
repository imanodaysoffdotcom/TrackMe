# TrackMe upstream patch set

Twenty-one contributions (sections 01–21) against **pagpeter/TrackMe**, generated as `git diff`
from base commit **`ce37e12`** ("Merge pull request #43 from 0x676e67/patch-1").
All are deployed and verified live on the self-hosted clone
(`https://209.97.157.76.sslip.io`). §01 is a small JA4 spec-correctness bug fix; the rest are
features a maintainer may want behind a flag — passive fingerprinting (SPHBI, QOSF QUIC-OS),
Redis-backed client history + the analysis UIs, and cross-layer / consistency detection (the
Redis history is already flag-gated: `redis_enable` / `history_public`).

| Patch | Kind | Files | Apply onto |
|---|---|---|---|
| `01-ja4-spec-fix.patch` | bug fix | 2 (`ja4.go`, `fingerprint_tls.go`) | `ce37e12` |
| `02-sphbi-feature.patch` | feature | 8 (7 mod + new `sphbi_quic.go`) | `ce37e12` (apply 01 first or independently) |
| `03-redis-store-pkg.patch` | feature (new pkg only) | new `pkg/store/{keys,store}.go` + `go.mod/go.sum` | on top of 02 |
| `00-all-changes.patch` | **all sections 01–21, combined** | 33 files (13 mod + 20 new) | the full diff; use this to reproduce the live server |

Note: `01`/`02`/`03` are the early standalone patches; every feature after that (sections **04–21**,
including QOSF) is interleaved across shared files and lives only in `00-all-changes.patch`, the
canonical artifact. It is regenerated as `git diff` from `ce37e12` with every untracked **source**
file intent-added (`git add -N`), so it now bundles the previously-missing new files
(`sphbi_quic.go`, `ja4t.go`, `exp.go`, `qosf*.go`, `geo.go`, …) and **applies + compiles standalone**
onto a clean `ce37e12` (verified via `git worktree` + `git apply --check` + a full `go build ./...`
+ `go test` across all 4 test packages). Build artifacts and `.bak`/`.mmdb` files are excluded.

Apply with:
```bash
git checkout ce37e12
git apply --check patches/01-ja4-spec-fix.patch   # dry-run
git apply         patches/01-ja4-spec-fix.patch
```

---

## 01 — JA4 spec-correctness fix (bug)

TrackMe's JA4_a is not byte-correct vs the FoxIO spec; `tls.peet.ws` shares the bug.

**Root cause** — `pkg/tls/ja4.go` `ja4aWithProto`:
1. cipher/extension counts are formatted with `%v`, so counts < 10 are **not
   zero-padded**. JA4_a must be a fixed 10 chars: `ptype ver sni {cipher:02d}
   {ext:02d} alpn`. e.g. curl emits `t13d497h2` where the spec requires
   `t13d4907h2` (ext count `7` → `07`).
2. On the QUIC/h3 path the **ALPN is dropped** because `CalculatePeetPrint`
   (`pkg/tls/fingerprint_tls.go`) had no `h3` case, leaving the PeetPrint ALPN field
   empty so `firstALPN=""`.

**Fix** — `%v…` → `%s%s%s%02d%02d%s` with `min(n,99)` clamping; add the `h3 → "3"`
ALPN case. JA4_b/JA4_c hashes were already correct.

**Verified** against the canonical FoxIO reference (`FoxIO-LLC/ja4` `python/ja4.py`)
on the same ClientHello (matched by src port):
- curl: was `t13d497h2_0d8feac7bc37_7395dae3b2f3` → now
  `t13d4907h2_0d8feac7bc37_7395dae3b2f3` (exact match).
- Chrome QUIC: now `q13d0311h3_55b375c5d22e_653d80c3fe9d` (spec-correct; note
  Wireshark itself emits a non-spec `u` prefix for QUIC instead of `q`).

---

## 02 — SPHBI: Single-Packet Header Binary Image (feature)

Implements the fingerprint image from **El-Sherif et al. 2025, "A single packet header
trick to detect bots," _Cybersecurity_ 8:104** — a per-client 12×12 (144-bit) binary
image built from selected header bytes (white pixel = 1 bit, black = 0), excluding
addresses/checksums/seq-ack so it captures stack/OS behaviour rather than identity.
Adds a **SPHBI tab** to the homepage that renders the image for the current visitor
from **real captured traffic — no synthetic data**. Three transport variants:

- **IPv4 (paper-exact):** the 18 Table-2 bytes — IP `[0:10]` + TCP `[0:4]` (ports) +
  TCP `[12:16]` (offset/flags/window) — captured from the client SYN via the existing
  libpcap path (`pkg/tcp/tcp.go`, `tcp.SYN && !tcp.ACK`).
- **IPv6:** RFC 8200 has no IHL/total-length/ID/flags/header-checksum, so the 18-byte
  recipe can't map 1:1. Uses the **8 non-address IPv6 header bytes**
  (version/traffic-class/flow-label, payload-length, next-header, hop-limit) + 4 TCP
  ports + 4 TCP offset/flags/window + the **2-byte MSS option** to backfill to 144 bits.
  Requires dual-stack listening (config `host: ""` → `*:443`; no code change — Go maps
  v4-mapped addresses back to dotted-quad so IPv4 correlation is unaffected).
- **QUIC/h3:** QUIC has no TCP SYN, so a header image doesn't apply. Instead images the
  discriminative QUIC signal: the client's `quic_transport_parameters` extension
  (`0x0039`, varint TLV per RFC 9000 §18). 15 canonical parameter slots + 1 GREASE slot
  × 9 bits = `[present:1][value XOR-fold:8]` = 144 bits. Random-valued params
  (e.g. `initial_source_connection_id`) are imaged presence-only — same principle that
  excludes IP addresses. New file `pkg/tls/sphbi_quic.go`.

**Files:** `pkg/tcp/tcp.go` (SYN capture + IPv4/IPv6 builders), `pkg/tls/sphbi_quic.go`
(new — QUIC parse + image), `pkg/tls/parse_client_hello.go` (parse the `0x0039` ext),
`pkg/server/{server.go,router.go,connection_handler.go}` (SPHBI store keyed by IP:port
and IP, correlation, h3 wiring), `pkg/types/structs.go` (`SPHBIDetails`,
`QUICTransportParam`, `Response.SPHBI`), `static/index.html` (kind-aware tab).

**Verified** end-to-end: IPv4 and IPv6 byte-for-byte vs `tshark` on real SYNs; QUIC in a
real Chrome — homepage renders `QUIC Initial · transport params`, 12×12 canvas, hex
`e2e16e1e0f07824927000000000806040100`, 13 real Chrome params, identical across
`/api/all`, the homepage injection, and the rendered canvas.

**Caveat (documented, not a regression):** QUIC SPHBI — like QUIC JA4 — only populates
on a **full handshake**. quic-go doesn't expose `ClientHello` on 0-RTT/resumed
connections, so a returning Chrome reusing a QUIC session shows no image until a fresh
handshake (incognito / first visit / after restart). An earlier experiment forcing full
handshakes via `SessionTicketsDisabled`/`Allow0RTT:false` was **reverted** — it didn't
help and disrupted the fork's ClientHello capture.

### Implementation note worth flagging in the PR
The h3 `TLSDetails` literal in `connection_handler.go` (`HandleHTTP3`) must copy
`QUICTransportParameters: parsedClientHello.QUICTransportParams`. The TCP-path literal
copies it too (harmless — TCP carries no QUIC params), but the h3 path is the one that
matters; omitting it silently yields an empty image while the per-extension display
still looks correct (separate parse), which masks the bug.

---

## 03 — Redis client-history storage + "Previous Clients" browser (feature)

Persists every fingerprinted visit to Redis and adds a homepage tab to browse historical
clients (each one's SPHBI image beside its identifying info). Off by default-friendly via
config; the live server runs it on.

**New package `pkg/store`** (`keys.go` + `store.go`):
- Identity: `ConnKey` = TLS/QUIC ClientRandom (unique per connection); `ClientKey` =
  `sha256(JA4·PeetPrint·Akamai·UA·SPHBI·TCP-opts)`, IP-independent, so a client groups
  across connections/ports/IPs and distinct stacks behind one NAT stay separate.
- **Async, non-blocking writes:** `Router()` drops the finished `Response` on a buffered
  channel (`Enqueue`); a background goroutine pipelines it into three views — a `visits`
  Stream (`MAXLEN ~200000`), `conn:<connKey>` HASH (90-day TTL), and a `client:<clientKey>`
  HASH + `:ips`/`:ports` sets + `:conns` ZSET (trimmed to 1000), with `idx:clients`/`idx:ip`/
  `idx:ja4` ZSETs. Response latency is untouched; on overflow/Redis-down it logs and drops.
- Reads: `ListClients`/`GetClient` serve `/api/clients?page=N` and `/api/client?key=…` in
  2 pipelined round-trips (denormalized `summary_json` avoids N `HGETALL`s; no `KEYS`/`SCAN`).

**Wiring (shared files, in `00-all-changes.patch`):** `Server.State.Store` + `InitStore`/
`GetStore`/`computeAdmin` (`server.go`); enqueue + `getAllPaths` method + `res.IsAdmin`
(`router.go`); two closure handlers gated by `history_public || res.IsAdmin` (`routes.go`);
`Config.{RedisAddr,RedisPassword,RedisEnable,HistoryPublic}` (pointers default-true) +
`Response.IsAdmin json:"-"` (`structs.go`); `srv.InitStore()` in init (`main.go`);
"Previous Clients" master-detail tab (`static/index.html`).

**Security (operational, in `redis-setup.sh`, not the Go patch):** Redis bound to
`127.0.0.1`/`::1`, `requirepass`, AOF, data dir `750`, env file `640`, fed to the unit via
`EnvironmentFile=/etc/trackme/redis.env`; the default `cors_key` (`"X-CORS"`) is replaced
with a random value. Display is **public** by design here (`history_public=true`) — flip to
`false` to gate the endpoints + tab behind `IsLocal()`/`X-CORS`. The frontend renders every
stored value with `textContent` (never `innerHTML` interpolation), so a hostile
`User-Agent` cannot execute — verified: an `<img onerror>` UA produces 0 injected `<img>`
elements and shows as escaped text.

**Verified live:** 3 views populate (`XLEN visits`, `ZCARD idx:clients`), conn TTL ≈ 90d,
both endpoints return correct JSON, the tab renders rows + SPHBI thumbnails and a detail
pane with the image beside identifying info, `is_admin` is not leaked in `/api/all`, and
Redis is unreachable externally. Unit tests: `go test ./pkg/store/` (6 pass).

**Note for upstreaming:** route handlers don't receive `*Server`, so the read handlers are
closures over the store (the existing `staticFile()` pattern) and `getAllPaths` became a
method — a minimal, backward-compatible change. Detail uses query-string params
(`?key=…`) to fit TrackMe's exact-match router (no router rewrite).

---

## 04 — Trusted request-parameter capture (feature, in `00-all-changes.patch`)

Captures the **actual client request** (method, target, parsed query, ordered headers,
and the **body**) and stores it inside the connection record, so request parameters join
the very fingerprint they were observed with — for model-training data pulls. **Strictly
opt-in:** a request is captured only when it carries header `X-Collect: <secret>` whose
value matches `COLLECT_SECRET` (constant-time compare; **fail-closed** when the secret is
unset). Ordinary traffic and internet scanners are never captured.

**Capture (`pkg/server/connection_handler.go`):** `collectAuthorized` gates on the header
across h1/h2/h3 (reuses the `computeAdmin` header-walk, now factored into `collectHeaders`).
Body per protocol: **h1** reads it from the buffered request bytes, reading the remainder
off the open connection via `Content-Length` (bounded by a 256 KiB cap + a 3 s deadline);
**h2** reassembles it from the DATA-frame payloads the frame loop *already* collects (zero
change to h2 fingerprinting); **h3** reads `r.Body` (`LimitReader`). Body is stored
base64 (binary-safe); our own `X-Collect` header is redacted from the record so the secret
never lands in the dataset.

**Types/store/route:** `Response.Request *RequestDetails` (serialized, so it rides in the
existing `conn:<connKey>` JSON alongside the fingerprint) + `Config.{CollectKey,CollectSecret}`
(`structs.go`); `idx:collected` ZSET index (capped at 100 k, trimmed like `:conns`) +
`ListCollected` reader (`store.go`); `/api/collected` export endpoint, same
`history_public || res.IsAdmin` gate as the other history endpoints (`routes.go`).

**Deploy:** `COLLECT_SECRET` added to `/etc/trackme/redis.env` (the existing systemd
`EnvironmentFile`); `CollectKey` defaults to `X-Collect`, no config change needed.

**Previous Clients view:** the captured request is also surfaced per-client in the UI.
`writeVisit` stores it as an explicit `request_json` conn field + increments `collected_count`
on the client; `GetClient` attaches `request` to each connection and `ListClients` returns
`collected`. The detail pane renders a prominent amber **"Captured request parameters"**
card (method, target, query table, collapsed headers, decoded body) and the client list
shows a **`REQ n`** badge on clients that have captured requests. Because trusted requests
are rare among thousands of scanner clients, an **"Only with captured requests"** filter
(`/api/clients?collected=1`, server-side over the whole dataset) surfaces them instantly —
without it the captured clients are buried pages deep and effectively invisible. The detail
pane's sections (identity, fingerprints, captured requests, map, connections, network, QUIC)
are **drag-reorderable** via a per-section grip handle (HTML5 DnD; order persisted in
`localStorage`, with a header "↺ reset"), and every collapsible `<details>` **auto-expands**
on render. All frontend-only (`static/index.html`).

**Verified live:** trusted h2 + h1 POSTs (incl. a 4000-byte body exercising the h1
read-remainder path) appear in `/api/collected` joined to their JA4/PeetPrint/Akamai/IP/UA,
and in the Previous Clients detail pane (browser-verified: the card renders the query/
headers/body with `X-Collect` redacted); non-trusted and wrong-secret POSTs capture nothing.
Unit tests: `go test ./pkg/server/` (capture + auth, all pass).

---

## 05 — Password-gated history deletion (feature, in `00-all-changes.patch`)

Two destructive admin actions, both gated by a password: **delete one client** and **wipe
all history**. The password lives in the environment (`DELETE_PASSWORD`); empty **disables
deletion entirely** (fail closed). The UI sends it in the `X-Delete-Password` header; the
server compares it constant-time. Endpoints are **POST-only** and use their OWN gate
(`Server.deleteAuthorized`), independent of the `history_public` read gate — so deletes stay
locked even when the read view is public.

**Store (`pkg/store/store.go`):** `DeleteClient(clientKey)` removes every key unique to a
client — the rollup hash, `:ips`/`:ports`/`:conns` sets, each `conn:<connKey>` (+ its
`idx:collected` entry), and memberships in `idx:clients`/`idx:ip:*`/`idx:ja4:*` — returning
the connection count (idempotent). `DeleteAll()` wipes the whole keyspace via batched
SCAN+DEL over `client:*`/`conn:*`/`idx:*`/`exp:*` plus the `visits` stream (no `FLUSHDB`, so
unrelated keys survive).

**Route/config (`routes.go`, `structs.go`, `server.go`):** `POST /api/client/delete?key=…`
and `POST /api/clients/delete_all`; `Config.DeletePassword` (env `DELETE_PASSWORD`);
`deleteAuthorized` mirrors the collect/exp constant-time pattern.

**UI (`static/index.html`):** a red **"🗑 Delete all"** button (double-confirm), a per-row
**✕**, and a **"🗑 Delete client"** button in the detail header — all prompt for the password
once (cached in-memory for the session, cleared on a 403) and confirm before POSTing.

**Verified:** miniredis unit tests (`pkg/store/delete_test.go`) prove `DeleteClient` removes
exactly what `writeVisit` creates (all indexes), leaves other clients intact, and `DeleteAll`
empties the keyspace. Live: every auth gate rejects (GET / no-password / wrong-password); a
real single-delete removed the client + its `idx:clients` membership (redis-confirmed); the UI
buttons POST to the right endpoints with the header (browser-verified). `delete_all` was NOT
run against live data. Adds a test-only dep: `github.com/alicebob/miniredis/v2`.

---

## 06 — ASN (network-operator) lookup (feature, in `00-all-changes.patch`)

Shows the autonomous-system info (ASN, operator/ISP, country) for the **current visitor** and
for **previous clients**. Lookups go through **free, key-less APIs** called **server-side and
cached in Redis** (`asn:<ip>`, 30-day TTL) — so there's no CORS/mixed-content issue, no
per-visitor third-party leak, and a provider is hit at most once per IP.

**Redundancy (real-time provider fallback):** `fetchASN` walks an ordered chain of **three**
free, key-less providers — **ip-api.com** (primary, richest data) → **ipwho.is** → **ipapi.co**
(HTTPS fallbacks with different rate-limit profiles). The instant a provider returns **HTTP 429**
(rate-limited) or errors, it switches to the next *within the same request*, so the caller is
still fulfilled from a fallback. A 429'd provider is parked in a short **Redis cooldown**
(`asn:cooldown:<name>`, TTL from its `X-Ttl`/`Retry-After`, capped 5 min) so subsequent lookups
skip it until it recovers. `ASNInfo.source` records which provider answered. Adding a provider is
one entry in `asnProviders()` + a parser.

**Store (`pkg/store/store.go`):** `LookupASN(ip)` (cache-or-chain → JSON); `fetchASN` /
`tryASNProvider` / `asnCoolingDown`; per-provider parsers `parseIPAPI` (splits
`"AS15169 Google LLC"`), `parseIPWhois` (ipwho.is `connection.asn`), `parseIPAPICo` (ipapi.co
`asn`/`org`); `HasIP(ip)` (idx:ip membership).
`ASNInfo{asn,as_name,isp,org,country,country_code,available,source}`.

**Backfill:** since the cache only warms on-view, `BackfillASN(pace)` scans every observed IP
(`idx:ip:*`), resolves the not-yet-cached ones in a paced **background goroutine** (1.4 s/IP,
within rate limits; a Redis lock `asn:backfill:lock` blocks overlapping runs), and returns
`{total_ips, scheduled, already_cached}`. Exposed at **`POST /api/asn/backfill`** (password-
gated like the deletes) and a **"⚲ Backfill ASN"** button in the Previous-Clients header.
Verified live: a run on the live box reported `175 scheduled / 10 already cached / 185 total`
and the background goroutine warmed the `asn:<ip>` cache to **all 185 IPs** (`warmed 175 of
185`, ~1.4 s/IP, all served by the primary), with diverse real data (Amazon, Microsoft, TWC,
various ISPs). The gates reject GET/wrong-password; the lock rejects a concurrent run. Unit
test `TestASNBackfillTargetsAndLock` covers target selection (skips already-cached) + the lock.

**Route (`routes.go`):** `GET /api/asn` — no `?ip=` resolves the **caller's own** IP (current-
client view); an explicit `?ip=` is honored **only for IPs we've actually observed** (`HasIP`
guard), so it can't be used as an open lookup proxy for arbitrary addresses.

**UI (`static/index.html`):** the homepage "Your IP" banner gains an **ASN** field
(`#client-asn`, async `/api/asn`), and the Previous Clients detail gains a draggable **"ASN ·
network operator"** section that resolves each of the client's IPs (`/api/asn?ip=…`, capped at
8) into an IP/ASN/Operator/Country table.

**Verified:** unit tests (`pkg/store/asn_test.go`) cover `parseIPAPI` (success/fail/partial),
`LookupASN` (caches after one API hit; `HasIP` guard), **primary-429→fallback** (switches +
parks the primary in cooldown + skips it next time), and **both-fail→third-provider** (reaches
ipapi.co) — all via httptest stubs + miniredis. Live: self + known-IP lookups return ASN (e.g.
`AS2711 SPIRITTEL-AS US`), an unknown IP is rejected, results cache in Redis; the full chain was
exercised live by forcing cooldowns in Redis — one cooldown → `source=ipwho.is`, two cooldowns →
`source=ipapi.co`, none → `source=ip-api.com` (all three agreed on the ASN). Browser shows the
banner ASN and the detail table.

---

## 07 — URL query parameters retained + shown (bug fix + feature, in `00-all-changes.patch`)

A normal visit's `?query` wasn't visible on the Previous Clients page. Two causes, both fixed:

1. **h3 dropped the query.** The HTTP/3 handler stored `r.URL.Path` (no query) while h1/h2 kept
   it. Fixed to `r.URL.RequestURI()` (`connection_handler.go`) so h3 retains `?query` like the
   others. Confirmed live: an h3 client now stores `/?dee=money`.
2. **Per-connection path was overwritten.** Browsers reuse one connection for the page load and
   the homepage's `/api/asn` fetch, so the conn's single `path` ended up as `/api/asn`. Added a
   **per-client, per-request path set** — `client:<ck>:paths` ZSET (deduped, newest `pathsKeep`
   = 50; written in `writeVisit`, cleaned in `DeleteClient`, returned by `GetClient` as
   `recent_paths`). This keeps each distinct request target, so the visit's `?query` survives.

**UI (`static/index.html`):** a draggable blue **"URL query parameters"** section parses the
query off each `recent_paths` entry (skipping the page's own `/api/` calls) into a
Param / Value / Path / When table — so `?dee=money` shows as `dee = money`. Params with **no
corresponding value** (bare keys like `?foo` or empty `?foo=`) are omitted (the row count reflects
only valued params; Playwright-verified: `?withval=yes&noval=&bare&dee=money&scraping-header=…`
renders exactly the 3 valued params).

**Filtering:** the Previous Clients filter bar gains **Query param** + **Query value** inputs
(`/api/clients?qparam=&qvalue=`). `ListClients` gained `qparam, qvalue` — when set, it
pipelines each candidate's `:paths` and keeps clients where some non-`/api/` path has a query
parameter whose name contains `qparam` AND value contains `qvalue` (same param; either may be
empty). `pathsMatchQuery` does the matching. The `:paths` fetch is conditional, so there's no
overhead when the filter is unused.

**Verified:** unit tests `TestRecentPathsRetainQuery` (a query path survives a later same-client
request) and `TestListClientsQueryParamFilter` (param/value/both/neither + `/api/` excluded);
live — a curl (h2) and a browser (h3) visit to `/?dee=money` both land in `recent_paths` and
render in the section, and the filter `qparam=dee&qvalue=money` narrows the live list to exactly
the 3 iPhone (h3) clients that visited it (browser-confirmed, "Showing 1–3 of 3"). Note: visits
recorded *before* the h3/path fix kept no query, so a client must re-visit to populate it.

---

## 08 — Faceted `scraping-header` multi-select filter (feature, in `00-all-changes.patch`)

A dynamic, multi-select dropdown to filter Previous Clients by the values of the
`scraping-header` query param — where **new values become options in real time** with no
intervention or code change.

**Real-time facet index (`pkg/store/store.go`):** `writeVisit` parses each non-`/api/` request
path and, for any param in `facetParams` (default `{scraping-header}`), records each distinct
value in `idx:qval:<param>` (ZSET by ts, capped `qvalCap`=1000 newest). So a never-seen value
is indexed the instant it arrives. `QueryValues(param)` returns the distinct values (newest
first) as a JSON array; `pathsMatchFacet` does exact param-name + exact value-in-set matching.

**API:** `GET /api/qvalues?param=scraping-header` → the option list (read-gated like the other
history endpoints). `GET /api/clients?shvalues=v1&shvalues=v2` → keep clients whose
`scraping-header` value is **any** of the selected (multi-select = OR); `ListClients` gained
`shvalues []string`, applied alongside the free-text `qparam`/`qvalue`.

**UI (`static/index.html`):** a custom checkbox dropdown (`pc-sh-*`) — button shows "N selected",
panel has a search box + a checkbox per value + "clear", **refetches `/api/qvalues` every time
it opens** so new values appear without a reload. Selections feed `shvalues` into the list query.

**Verified:** unit test `TestScrapingHeaderFacet` (distinct-value indexing, `/api/` exclusion,
single/multi/unknown filtering, non-facet param → `[]`). Live: 4 values sent → all returned by
`/api/qvalues`; `shvalues=scrapy` → 1, `scrapy`+`puppeteer` → 2 (OR), unknown → 0; **a
brand-new value appeared as an option immediately**; the browser dropdown loaded all values
(incl. the new one), and selecting two narrowed the list ("Showing 1–2 of 2"). Adding another
facet param later is a one-line change to `facetParams`.

---

## 09 — Comparative Analysis tab (feature, frontend-only, in `00-all-changes.patch`)

A new top-level tab for **side-by-side visual comparison of SPHBI images**, selected from a
filtered pool. Frontend-only (`static/index.html`) — reuses the existing `/api/clients` list
(whose `summary_json` already carries each client's `sphbi.bits/kind`).

**Shared filters (the requirement):** rather than duplicate the filter controls, the **single
existing Previous-Clients filter bar is physically relocated** (`showTab` moves the
`#pc-filterbar` node into the Comparative tab's slot while active, and back to its
`#pc-filterbar-home` anchor otherwise). One source of truth → filters are always in lockstep
between the two tabs with zero sync code. The filter→query builder was factored into
`pcAddFilterParams(qs)`, reused by both `pcFetchList` and the new `caFetchPool`; any filter
change (incl. the scraping-header multi-select) live-refreshes whichever tab is active.

**UI:** left = scrollable **pool** of SPHBI thumbnails (clients matching filters that have an
image; first 100, with a "refine filters" hint); click toggles selection (teal ring + ✓).
Right = **comparison tray** rendering each selected image at 120px with kind badge / UA /
client-key / remove. For ≥2 same-kind selections it also shows a **pairwise Hamming-distance
matrix** (the metric from the §research above; green ≤8, yellow ≤24), and flags mixed-kind
selections as not comparable.

**Verified (browser):** tab renders; the shared bar moves in/out correctly; pool loads (100 of
354); selecting images fills the tray + Hamming matrix; setting a UA filter on the Comparative
tab narrowed the pool to 5, and switching to Previous Clients showed the **same** filter applied
("Showing 1–5 of 5") with the bar moved home — confirming true bidirectional filter sharing.

---

## 10 — Similar clients: exact SPHBI k-NN in the detail pane (feature, in `00-all-changes.patch`)

Clicking a previous client now surfaces the **N closest other clients by SPHBI image** — a
"who else looks like this stack?" view — directly in the detail pane. The metric is the same
**flat Hamming distance over the 144-bit image** used by the Comparative tab's matrix; the
algorithm is an **exact brute-force k-NN** (no ML, no ANN index), which the §research above
validated as real-time correct to 100 k+ clients (MIH/LSH only pay off at 1 M–1 B).

**Why brute force is right here:** distance is XOR + popcount over **3× `uint64`** (the 18-byte
image zero-padded to 24 and packed big-endian), i.e. 3 `math/bits.OnesCount64` calls per
candidate — a full scan of the live pool is sub-millisecond. Comparisons are **within-kind only**
(`ipv4`/`ipv6`/`quic` images are incomparable, exactly as in the Comparative matrix).

**Real-time candidate index (`pkg/store/store.go`):** `writeVisit` maintains a per-kind hash
`idx:sphbi:<kind>` mapping `clientKey → 18-byte hex image`, written idempotently (clientKey is
stable, so re-visits just re-`HSET` the same field) and `HDEL`-cleaned in `DeleteClient`
(`DeleteAll`'s existing `idx:*` SCAN already catches it). One `HGETALL` yields the whole
candidate pool in a single round-trip — no `KEYS`/`SCAN`, no per-client fetch.

**Query (`SimilarClients(clientKey, n)`):** read the query client's `sphbi_json` → pack →
`HGETALL idx:sphbi:<kind>` → popcount-distance every candidate (skipping self) → `sort.Slice`
by distance asc with a deterministic clientKey tie-break → truncate to `n` (default 12, clamped
1–100) → one pipelined `HGET summary_json` per neighbor to attach its `sphbi`/`user_agent`/
`last_seen`. Returns `{kind, query_key, neighbors:[{client_key, distance, similarity, …}]}`,
where `similarity = (144−distance)·100/144`. A missing/invalid query image returns an empty,
well-formed result (`{"kind":"","query_key":"","neighbors":[]}`), never an error.

**Route (`routes.go`):** `GET /api/client/similar?key=…&n=…`, same `history_public || res.IsAdmin`
read gate as the other history endpoints; exact-match router so it doesn't collide with
`/api/client`.

**UI (`static/index.html`):** a draggable **"Similar clients (SPHBI)"** detail section
(`pcFillSimilar`) renders each neighbor as a clickable 48px SPHBI thumbnail with a
distance badge (color-graded: green ≤8, yellow ≤24, grey beyond — matching the Comparative
matrix thresholds) and a `% match`. **Clicking a neighbor navigates the detail pane to that
client** (`pcSelect`), which in turn shows *its* neighbors — so you can walk the
neighbourhood. The section only renders for clients that actually have an image.

**Verified:** unit test `TestSimilarClients` (miniredis) seeds a query (all-zeros), a `d=1`
near, a `d=8` far, and a same-bits **`quic`** client, and asserts kind `ipv4`, exactly two
neighbors ordered near→far, self + cross-kind excluded, and `similarity=(144−1)·100/144`. Live
(`/api/client/similar`): an ipv4 key returned 5 neighbors with **ascending** distances
(34/34/34/35/37), no self-reference, every neighbor carrying renderable `sphbi.bits`, and the
similarity math correct; the missing-key and bogus-key paths return the documented error / empty
shapes. Browser (Playwright, live): selecting a client rendered the section with **7 neighbor
thumbnails** (7 canvases, 7 `% match` labels, distance badges ascending d=33/34/34), and
**clicking a neighbor navigated the detail pane to exactly that client** (`matches_target:true`),
with 0 console errors.

---

## 11 — Comparative tab: unique SPHBI images per scraping-header group (feature, frontend-only, in `00-all-changes.patch`)

An option on the Comparative Analysis tab — checkbox **"Unique images per scraping-header
group"** — that reshapes the image pool into **per-scraping-header groups, each showing only
one client per distinct SPHBI image**. Purpose: compare the *distinct* stacks each scraping
tool produces without the pool being flooded by many identical images from the same tool.

**Frontend-only (`static/index.html`), no backend change** — keeps the §09 design property and
reuses the existing server filter. When the box is checked, `caFetchPoolGrouped()`:
1. picks the group set = the **selected** `scraping-header` multi-select values, or **all** values
   from `/api/qvalues?param=scraping-header` when none are selected (capped at `CA_MAX_GROUPS`=50,
   with a "first 50 groups" note);
2. fetches each group with the existing `GET /api/clients?…&shvalues=<one value>` (other active
   filters — kind/IP/JA4/UA/query/collected — still apply), **in parallel**;
3. dedupes each group's clients by distinct image key **`kind + ":" + sphbi.bits`** (so `ipv4` vs
   `quic` images never collide), keeping the first (most-recent) representative;
4. renders each group under a teal header **`scraping-header = <value> · N unique`**, flattening
   to `caPool` for selection bookkeeping (a client legitimately appearing in two groups is one
   selection — `caSelected` keys by `client_key`).

The pool cell was factored into `caCell(c)`, shared by the flat and grouped renderers; unchecking
restores the original flat single-fetch pool (`caGroups=null`). Live filter changes and tab
switches route through `caFetchPool()`, which branches on the checkbox.

**PERFORMANCE REWORK (later):** the original implementation fetched `/api/clients?shvalues=<v>`
**once per scraping-header value** (up to `CA_MAX_GROUPS`=50 requests), and *each* call made
`ListClients` re-scan the whole client population (up to `listCandCap`=5000, 4 Redis ops + a JSON
parse each) — i.e. **O(values × clients)** over N HTTP round-trips. On a ~4,900-client DB this took
~4–5 s. Replaced with a single server endpoint **`GET /api/sphbi/grouped`** backed by
`store.GroupedUniqueByScrapingHeader`, which scans the population **once** (2 Redis ops/client —
`summary_json` + `:paths`), groups by `scraping-header` value via `pathsFacetValues`, dedupes by
`kind+":"+bits`, and returns **slim** representative cards (`client_key` + `sphbi` + `user_agent`).
The frontend `caFetchPoolGrouped` now makes **one** request and filters to the selected groups
client-side. Result: **~0.6 s vs ~4–5 s (~8× faster)**, one round-trip. `ListClients` is left
untouched (the scan is duplicated, not shared) so its tests/behavior are unaffected. Trade-off
(documented): the `ip` and "only-with-captured-requests" filters are **not** applied in grouped mode
(kept lean); `kind`/`ja4`/`ua`/`qparam`/`qvalue` still apply. Future option for capture-plan scale:
a write-time `idx:sphbiuniq:<value>` index → O(distinct images), no scan.

**BUGFIX — "losing previous clients" / fewer images when grouped (later):** once the DB grew past
`listCandCap`=5000 (observed at **6,304** clients), the grouped scan (which used the same 5,000-newest
cap) silently dropped older labelled captures — e.g. the `camoufox`/`curl_cffi`/`selenium_driverless`
scraper groups went to **0 images** because newer runs (a 696-image `browserstack-device-sweep` + mobile
scraper variants) pushed them past rank 5,000. **Not** caused by the perf rework (the old per-value path
hit the identical cap via `ListClients`). Fix: `GroupedUniqueByScrapingHeader` now scans **all** clients
(`ZRevRange idx:clients 0 -1`), not just the newest 5,000 — so no labelled image ages out. That made the
response huge (766 images × the full summary `sphbi` ≈ **800 KB**), which then tripped the server's
HTTP/2 writer (it blasts DATA frames ignoring flow control — fine for small bodies, truncates large ones
at ~160 KB for small-window clients like curl). Two-part fix: (1) ship a **truly slim** sphbi
(`{bits,kind,size}` only — drop `hex` + the 11-field byte breakdown; card 1040 B → **306 B**); (2) **cap
rendered images per group at 200** while reporting the true distinct count as `total` (UI shows
"`N unique (showing 200)`"). Response: 800 KB → **~101 KB**, valid over default h2. Verified: scrapers
restored (camoufox/curl_cffi total=3 shown=3), `browserstack-device-sweep` total=696 shown=200,
chrome149-tcp=1, slim card 306 B, ~0.79 s over 6,304 clients; `go test ./pkg/store/` green.
NOTE: `ListClients` (Previous Clients tab + flat pool) ALSO hit this 5,000 cap — see the audit
follow-up below, where it was fixed the same way.

**Verified (Playwright, live):** with the box on, the pool rendered **26 group headers / 240
unique images**, and the dedupe is demonstrable — the `real_browser_denny` group, which has **3
clients but only 2 distinct images**, correctly showed **"· 2 unique"** (the other 25 groups had
no dup-collapsing). Selecting a grouped thumbnail fed the comparison tray ("(1 selected)", 1
canvas); toggling the box **off** restored the flat pool ("100 images (first 100 of 401)", 0 group
headers) and the selection **survived** the mode switch; 0 console errors. **Perf rework verified
(server-side):** `/api/sphbi/grouped` returns identical grouped/deduped counts to the old per-value
path (chrome149-tcp 1=1, camoufox 3=3, selenium_driverless 3=3) at ~0.6 s for 29 groups / 84 images
over a 4,924-client DB; `go test ./pkg/store/` still green (ListClients untouched).

**AUDIT FOLLOW-UP (adversarial review of the grouped fix — two confirmed issues fixed):**

1. **Selection regression introduced by the grouped fix (fixed).** The grouped scan sorts groups by
   first-appearance order then truncates to `cap` (=50) **before** the frontend applied the user's
   scraping-header selection client-side (it sent `cap=50` and deleted `shvalues`). With >50 distinct
   groups, selecting a value whose group sorts past rank 50 returned **"No groups match"** even though
   its images exist in Redis. Fix: plumb `shvalues` through to `GroupedUniqueByScrapingHeader`
   (`q["shvalues"]` in `routes.go`); when a selection is active the server returns **exactly** those
   groups and **bypasses** the `cap` truncation (and reports `truncated:false`), so a selected group
   can never be dropped. Frontend stops deleting `shvalues`. Verified by simulating the >50 case with
   `cap=1`: unselected → late group dropped (`truncated:true`); selected → late group survives
   (`truncated:false`, images returned); multi-select returns both. Unfiltered view unchanged (30
   groups). Also fixes the low-severity "misleading `(first 50 groups)` banner under selection."

2. **`ListClients` 5,000-cap aging-out (fixed — the literal "losing previous clients").** The same
   `listCandCap`=5000 bounded the **Previous Clients tab** and the **flat Comparative pool**: live
   `ZCARD idx:clients`=**6,588** but the tab reported `total`=**5,000**, the oldest ~1,500 clients were
   unreachable (no page), and `first_seen`-asc sort returned the oldest-of-the-newest-5,000 rather than
   the genuinely oldest record — all silently, no error. Fix: `ListClients` now scans **all** clients
   (`ZRevRange idx:clients 0 -1`), mirroring the grouped view; `total = len(cands)` is then the true
   population (no filter) or true filtered count. The now-unused `listCandCap` const was removed.
   Verified live: `total` 5,000 → **7,054** (= `ZCARD`); page 264 (clients ~6,575, beyond the old
   5,000/200-page ceiling) now returns rows; oldest reachable client `first_seen`=**2026-06-16** (days
   old, previously hidden); newest-first default intact; `go vet` + `go test ./pkg/store/` green.
   Cost: a Previous Clients page now scans ~6.6k clients/3 ops each in one pipeline RTT vs the old 5,000
   (~1.3×) — accepted as the cheapest correct fix (scan-all), consistent with the grouped view.

**Still open (noted, not in this fix):** the custom **HTTP/2 writer ignores flow control**
(`connection_handler.go` — `SplitBytesIntoChunks` + `fr.WriteData` loop, WINDOW_UPDATE captured but
discarded), which is why large aggregate responses truncate ~160 KB for small-window clients (the
reason the grouped payload was slimmed). Proper fix = honor the client's send window / WINDOW_UPDATE
(or serve h2 via `http2.Server.ServeConn`); bounding response sizes is a stopgap. Also several
**unbounded-growth** indexes (`idx:clients`, `idx:ja4set` 5,000 dropdown ceiling) — fine at ~7k,
worth a write-time `idx:sphbiuniq:<value>` index before orders-of-magnitude growth.

---

## 12 — Comparative tray: scraping-header "category" per selected card (feature, frontend-only, in `00-all-changes.patch`)

Each card in the comparison tray now shows the **scraping-header value the image belongs to** — its
"category" — and **clicking the SPHBI image reveals a prominent "Category" banner** with the full
value. Frontend-only (`static/index.html`), no backend change.

**Where the category comes from** (`caResolveCategories`): a card selected in grouped mode already
carries the group it was picked from (`_shGroup`) → used directly, no fetch. A flat-mode pick is
resolved lazily from the client's own request history: `GET /api/client?key=…` → parse
`recent_paths` for the `?scraping-header=` query value(s) (`caScrapingHeadersFromPaths`, distinct),
cached per `client_key` so each client is fetched at most once; the tray re-renders when it lands.
A client legitimately tied to several scraping-header values shows all of them.

**UI:** an always-visible **`🏷 <value>`** chip on each card showing the **full** scraping-header
value — long values **wrap across multiple lines** (`break-all`, full-card width) rather than being
truncated — plus a hidden teal **"Category" banner** that the card's canvas (now `cursor-pointer`,
titled "Click to show category") **toggles**, also full-value and wrapping. While a flat-mode value
is resolving the chip reads `resolving…`; a client with no scraping-header reads `no scraping-header`.

**Verified (Playwright, live):** grouped-mode pick of a `real_browser_denny` image → chip
`🏷 real_browser_denny`, canvas `cursor-pointer`, banner hidden by default and **revealed on canvas
click** (label "Category" + value). Flat-mode pick of a `scrapy` client with **no `_shGroup`** →
`caResolveCategories` fetched `/api/client`, parsed `recent_paths`, and resolved
`["scrapy"]` → chip `🏷 scrapy`. A long value (`simple-scraper.identifier.selenium_driverless`, 45
chars) renders **in full, wrapped across 2 lines** with no ellipsis and nothing clipped
(`word-break: break-all`, `scrollHeight == clientHeight`); 0 console errors.

---

## 13 — JA4 filter: dropdown of unique collected fingerprints (feature, in `00-all-changes.patch`)

The shared **"JA4 contains"** filter (used by both Previous Clients and the Comparative tab) gains a
**▾ dropdown of every distinct JA4 fingerprint collected so far** — so you can pick a known
fingerprint instead of remembering its prefix. The set **grows automatically** as new fingerprints
arrive and each value is listed **once across all clients**. Manual substring typing is unchanged;
the picker just fills the same input with the full fingerprint.

**Real-time distinct-JA4 index (`pkg/store/store.go`):** `writeVisit` adds each JA4 to a single
ZSET `idx:ja4set` (score = recency, member = the fingerprint) right beside the existing per-value
`idx:ja4:<v>` filter index — so a never-seen fingerprint becomes an option the instant it arrives,
deduped by the ZSET, capped at `ja4Cap` (5000) most-recent distinct values. `JA4Values()` returns
them as a JSON array (mirrors `QueryValues`). No `KEYS`/`SCAN` on the read path.

**API (`routes.go`):** `GET /api/ja4values` → the option list, same `history_public || res.IsAdmin`
read gate as the other history endpoints.

**UI (`static/index.html`):** the JA4 field becomes an input + a **▾ picker** (`pcJa4*`): the panel
**refetches `/api/ja4values` every time it opens** (new fingerprints appear with no reload), has a
search box (client-side substring filter over a potentially long list, with an "N of M unique"
count), and each entry is a monospace row; **clicking one fills `#pc-f-ja4` with the full
fingerprint and applies the filter** (the entry matching the current input is highlighted). Because
the existing `ja4` filter is a `Contains` substring match, a picked full fingerprint matches exactly
that JA4 while a typed prefix still matches broadly. Lives in the **shared** `#pc-filterbar`, so it
works on both tabs (and stays in lockstep, per §09). Outside-click closes the panel.

**Backfill:** since `idx:ja4set` only fills from new visits, the pre-existing distinct JA4s were
seeded once on the droplet (`redis-cli --scan --pattern 'idx:ja4:*'` → `ZADD idx:ja4set`), so all
**16** already-collected fingerprints showed immediately; `DeleteAll`'s `idx:*` SCAN wipes the set
on a full reset.

**Verified:** unit test `TestJA4Values` (miniredis) — empty store → `[]`; 3 visits with 2 distinct
JA4s (one repeated across two clients) → exactly the **2 deduped** fingerprints. Live
(`/api/ja4values`): 16 unique values (QUIC `q13d…` + TCP `t12d…`/`t13d…`), all distinct. Browser
(Playwright, Comparative tab): the picker is present in the moved filter bar, opens to **16 options**
("16 of 16 unique"), the in-panel search `q13d` narrowed to the **4 QUIC** fingerprints, **picking
one filled the input with the full value, closed the panel, and narrowed the pool to "1 image"**;
manual typing `t13d17` filtered the pool to "15 images" (substring `Contains` still works). The
option count was observed to **grow 16 → 17 live** when a fresh fingerprint (the test browser's own)
arrived — confirming automatic growth. 0 console errors.

---

## 14 — Blueprint tab: SPHBI image-matrix field maps (feature, frontend-only, in `00-all-changes.patch`)

Two static reference diagrams added to the **Blueprint** tab showing how the 18 selected TCP/IP
header bytes map onto the **12×12 / 144-bit SPHBI image** — i.e. which header signal drives each
pixel. One diagram for **IPv4**, one for **IPv6**, exactly mirroring `pkg/tcp/tcp.go`
`buildSPHBI` / `buildSPHBIv6` / `renderSPHBI` (bit *i* → pixel `x=i%12, y=i/12`, each byte
MSB-first, packed row-major; addresses, checksums and TCP seq/ack excluded).

**UI (`static/index.html`, no backend change):** `renderSphbiMatrix(hostId, kind)` builds each
diagram from a `SPHBI_FIELD_MAP` table (`{name, firstByte, byteCount, layer, os}`) — a 12×12 grid
whose cells are coloured by the field whose bits land on them (cool = IP/IPv6 base header, warm =
TCP header, shared TCP fields share colour across both diagrams), each field's first cell numbered,
every cell carrying a `<title>` tooltip (`#n field — byte/bytes, bits a–b`), plus a layer-grouped
legend with byte+bit ranges and a ★ on the high OS/stack-signal fields (TTL/hop-limit, window, MSS,
flags, flow-label, IP-ID). Rendered once from `renderBlueprint`. IPv4 = 11 fields over bytes 0–17
(IP[0:10]+TCP ports+TCP off/flags/window); IPv6 = 11 fields (IPv6[0:8]+TCP ports+TCP
off/flags/window+**MSS option** backfilling to 144 bits).

The explanatory note is rendered as an **HTML `<p>` caption below each SVG** (not inside it), so its
long lines wrap responsively and can't overlap the right-hand legend; the SVG height is just
`max(gridBottom, legendBottom)`.

**Verified (Playwright, live):** both `#bp-sphbi-ipv4` and `#bp-sphbi-ipv6` render an SVG with
**exactly 144 titled cells**, 11 distinct fields, 11 legend swatches; field→bit mapping correct
(IPv4 TTL = byte 8 / bits 64–71; IPv6 hop-limit = byte 7 / bits 56–63); **row-major placement exact**
(TTL bit 64 → grid col 4, row 5 → SVG x=154, y=177); the note is an HTML caption below the SVG
(0 footnote `<text>` left inside the SVG, so no legend overlap); 0 console errors.

---

## 15 — Visual Analysis tab: SPHBI-by-JA4 lineage graph (feature, in `00-all-changes.patch`)

A 6th top-level tab **"Visual Analysis"** that, for one selected JA4 fingerprint, draws a
**React Flow** graph of every distinct SPHBI image linked to that JA4: **scrapers on the left**,
the **JA4 in the middle**, **BrowserStack devices on the right**. It makes the core integrity
insight visible — the *same* TLS JA4 can front many *different* TCP/IP SYN images across real
devices and scraper tools, so JA4 alone can't separate a real device from an impersonator.

**Backend (`pkg/store/store.go` + `pkg/server/routes.go`):**
- `Store.SPHBIByJA4(ctx, ja4, capN)` scans the whole client population once
  (`ZRevRange idx:clients 0 -1`, 2 ops/client — mirrors `GroupedUniqueByScrapingHeader`), keeps
  clients whose JA4 matches exactly **and** that carry an SPHBI image, and splits each by its
  `scraping-header` value: `browserstack-device-sweep` → **right** (device/os/os_version pulled
  from the same path via new helper `pathBrowserstackDevice`); any other value → **left** scraper.
- **One node per distinct image (`kind:bits`) per side**, accumulating the distinct contributor
  labels (scraper names left, `device · os ver` right) with an `×N` count — so an image shared by
  several tools/devices collapses to one multi-label node (surfaces clients indistinguishable by
  SPHBI under the same JA4). Per-side cap (default 400) with `left_truncated`/`right_truncated`.
- Endpoint `GET /api/sphbi/by-ja4?ja4=<full>&cap=<n>` (same `history_public||IsAdmin` gate);
  missing `ja4` → 400-style JSON error.
- Test `TestSPHBIByJA4` (miniredis): left/right split, image dedup with count, device extraction,
  cap+truncation, exact-JA4 match, and ignore of no-header / no-image / other-JA4 clients.

**Frontend (`static/index.html`):**
- New tab `tab-visualanalysis` / `panel-visualanalysis` (indigo accent), added to `showTab`'s list;
  panel = a JA4 `<select>` (populated from `/api/ja4values`) + a `#va-flow` graph container.
- **React Flow is loaded LAZILY** via dynamic `import()` from `esm.sh` on first tab open — React
  18.3.1 + `@xyflow/react@12.11.0` + `htm` (a single pinned React via `?deps=` so there is exactly
  one React instance), plus the React Flow stylesheet injected as a `<link>`. This mirrors the
  existing on-demand Leaflet injection — **no build step**, nothing fetched until the tab is used.
- A `<script type="module">` owns the graph and exposes `window.VA = {mount, render}`. Custom node
  draws the **12×12 SPHBI canvas** (same algorithm as `pcDrawCanvas`) + label + `×N` badge. Manual
  two-column layout (scrapers x<0, JA4 at x=0, devices x>0) that **wraps into sub-columns past 16
  per side** so a large right side (hundreds of device images) stays navigable with pan/zoom;
  `fitView` on init, on JA4 switch, and on tab re-show (`va:shown` event). Empty/no-image and
  error states handled. All labels render as React-escaped text children (no innerHTML on stored
  data) — XSS-safe against attacker-controlled device names / scraper values / JA4.

**Verified (Playwright, live):** opened the tab → dropdown populated with **169 JA4s**; selecting
the Android-Chrome JA4 `t13d1516h2_8daaf6152771_d8a2da3f94cd` lazy-loaded React Flow (CSS + single
React) and rendered **295 nodes (294 SPHBI + 1 JA4), 294 edges, 294 canvases** — 21 scraper images
left, 273 device images right — info text "21 scraper images · 273 device images", **0 console
errors**. Endpoint also verified via curl (left_total=21, right_total=273; missing-ja4 + unknown-ja4
error/empty paths). Spec at `docs/2026-06-21-visual-analysis-tab-design.md`.

**Adversarial review follow-up (2 fixes, both verified):** (1) *Right-side device
under-count* — `SPHBIByJA4` iterated the de-duplicated scraping-header value and extracted
only the FIRST device, so when several BrowserStack devices collapse to one `clientKey`
(device/os aren't in `ClientKey`) every device but one was silently dropped — the exact
multi-device-per-image case the tab exists to show. Fixed: new `pathBrowserstackDevices`
returns every distinct device on the client, and the right branch adds a label per device
(regression test `TestSPHBIByJA4MultiDevicePerClient`). (2) *`cap` had no upper bound* —
now clamped to 400 (`if capN < 1 || capN > 400`), matching the siblings and the UI promise.
Refuted in review: no XSS (labels render as React-escaped text children, no innerHTML sink)
and no DoS (output is intrinsically bounded by distinct `kind:bits` images / client
population; `cap` only truncates the already-built result).

**Dropdown-source fix (2026-06-21):** the JA4 `<select>` was populated from `/api/ja4values`
(every JA4 ever seen, 169), so most picks rendered an empty graph — many JA4s have no SPHBI
image (QUIC/h3 without a full handshake) or no scraping-header label. Added
`Store.JA4ImageSummary` + endpoint **`GET /api/sphbi/ja4values`** (gated): one scan returning
only the JA4s that have ≥1 client with BOTH an image and a scraping-header (i.e. that produce a
non-empty graph), each with distinct-image counts per side, richest first. The dropdown now
fetches this (label `ja4 · N scraper / M device`). Live: 169 → **52** JA4s, 0 empty entries,
sorted desc. Test `TestJA4ImageSummary` (excludes image-less + label-less JA4s, asserts counts +
order). `/api/ja4values` is unchanged (still backs the Previous-Clients / Comparative filter bars).

---

## 16 — QOSF: QUIC OS Fingerprint (feature, in `00-all-changes.patch`)

A readable, non-hashed **QUIC-only** passive fingerprint, computed **alongside** the QUIC JA4/SPHBI
and **never** touching the JA4/TCP/TLS path. The load-bearing idea: the QUIC transport parameters
fingerprint the userspace **library** (segments B/C/D), so the **OS signal** must come from the
kernel **TTL/hop-limit** on the UDP datagram (segment A), read by the packet tap. Format:

```
q<ttl><ip><ecn><df><flow>_<stack><ver><order><grease><scid>_<tp-set>_<tp-values>
  A: kernel / OS          B: userspace stack        C: tp id-set   D: tp values
```

Valid only when the server is the **first-hop QUIC terminator** (TrackMe is, via quic-go).

**New module (self-contained, mirrors the JA4 code):**
- `pkg/tls/qosf.go` — `CalculateQOSF(params, quicVersion, remoteIP, kern)` + the four segment builders
  and all canonicalization: TTL as *observed→inferred* (round the observed value up to the nearest of
  {32,64,128,255} → code 3/6/1/2); the tp id-set **sorted ascending** with reserved-GREASE ids
  (`id%31==27`, RFC 9000 §18.1) collapsed to a single `G`; QUIC-varint decode of segment-D values
  (reuses `sphbi_quic.go`'s `readQUICVarint`); lowercase hex, no `0x`.
- `pkg/tls/qosf_stacks.go` — a **data-driven** stack classifier. It ships with exactly ONE verified,
  generalizable signature — `ch` (Chromium) when a Google-custom QUIC transport parameter
  (`0x3127`/`0x3128`) is present, which no other stack sends — grounded from the server's own
  UA-labelled live captures. Apple is deliberately left out (unverified); anything unmatched → `xx`.
- `pkg/tls/qosf_test.go` — 14 tests: a golden fully-observed record, the **no-fabrication** proof, the
  socket-only degradation, IPv6, every mapping table, GREASE collapse, and the grounded classifier.

**No-fabrication rule (enforced + tested):** a transport parameter the client did **not** send renders
`-` in segment D — **never** its RFC 9000 default. (This deliberately diverges from an illustrative
example that showed defaults; the rule wins.) Every unobserved field is `-`.

**Observability / capture (additive, QUIC-only):**
- `pkg/types/structs.go` — `QOSFKernel` (tap observation), `QOSFField`, `QOSFDetails`, and
  `Response.QOSF *QOSFDetails json:"qosf,omitempty"` (absent for TCP).
- `pkg/server/server.go` — `State.QOSFKernel sync.Map` + `GetQOSFKernel()` (mirrors `GetSPHBI`/`GetJA4T`).
- `pkg/tcp/tcp.go` — a **purely additive** UDP branch in `SniffTCP`: when a packet has no TCP layer,
  `captureQOSFKernel` reads the outer IP header (TTL/ECN/DF/flow) and `parseQUICLongHeader` reads the
  cleartext QUIC long header (version + connection-ID lengths, RFC 8999), storing a `QOSFKernel` keyed
  by `IP:port` **and** `IP` — exactly like the SPHBI/JA4T maps. The TCP-SYN path is byte-for-byte
  unchanged; this branch only ever runs for non-TCP packets.
- `pkg/server/router.go` — QOSF is computed **only** inside the existing `HTTPVersion == "h3"` block
  (the QUIC-only gate, next to the QUIC JA4/SPHBI): it looks up the `QOSFKernel` by IP (then a
  by-IP fallback), takes the negotiated QUIC version from `Http3.Version`, and calls `CalculateQOSF`.
  `kern == nil` (tap didn't see the flow) degrades to `source: "socket-only"` — segment A + `scid`
  render `-`, but `ip` (from the address), `ver`, and the transport-param segments still populate.

Two observability facts confirmed against the quic-go fork while implementing: `ver` is exposed via
`quic.ConnectionState.Version`, and `scid` is read from the long-header parse — so the Level-2 tap
lights up **every** segment except the derived stack code.

**OS inference (`pkg/tls/qosf_os.go` → `QOSFDetails.OS`):** a simple, honest OS-family guess derived
from the fingerprint — primarily the kernel **initial TTL** (segment A), since the transport params
identify the *library*, not the OS. `inferOS(kern, stack)` maps the inferred initial TTL to a
**family + candidate OSes + confidence**, never a hard label: `128 → Windows` (moderate),
`64 → Unix-like {Linux, Android, macOS, iOS, BSD}` (low — TTL 64 is shared and can't be narrowed),
`255 → network gear / Unix server` (low), `32 → legacy Windows / embedded` (low), and **unknown**
when the flow was seen socket-only (no TTL). Every observed guess carries a spoofable caveat (the TTL
is client-settable and hop count varies). Chromium is noted as cross-platform (doesn't narrow the OS);
the hook to narrow by an OS-specific stack (e.g. Apple's) is present but dormant. Tests in
`qosf_os_test.go`. Surfaced in the UI and appended to the Fingerprints-card note.

**Kernel space vs. user space (`QOSFDetails.KernelSpace`/`UserSpace` + `QOSFField.Space`):** each
field and the fingerprint as a whole are tagged by *where they are produced* — the OS **kernel** writes
the IP/UDP header (segment A: `ttl/ip/ecn/df/flow`), while the userspace **QUIC library** writes
segments B/C/D (version, connection IDs, transport parameters). `/api/all` now exposes
`qosf.kernel_space` (`{segments:["A"], value:"q…-"}`), `qosf.user_space`
(`{segments:["B","C","D"], value}`), and `space: "kernel" | "user"` on every `fields[]` entry — making
QOSF's whole premise legible: QUIC runs in user space, so the OS signal has to come from the
kernel-written TTL, not from anything QUIC sends. The UI renders a **kernel-vs-user summary card**,
splits the "how it's built" flow into two labelled **zones** (🧬 kernel = segment A, 🧩 user = B/C/D),
and puts a `kernel space` / `user space` pill on each field card. Test `TestQOSFSpaces`.

**Cross-layer consistency — anti-mimic signal (`QOSFDetails.Consistency`, vs. uQUIC):** motivated by
studying [enetx/uquic](https://github.com/enetx/uquic) (a quic-go fork that forges the QUIC Initial to
mimic Chrome/Firefox). uQUIC customizes only the *unencrypted Initial Packet* — transport parameters,
connection-ID lengths, GREASE, even Google's custom TPs — so it can make QOSF segments B/C/D (and the
QUIC JA4) byte-identical to a real browser, and it defeats the `ch` stack signature (its Chrome parrot
sends `google_connection_options 0x3128`). What it **cannot** forge is the kernel-written initial TTL
(segment A): uQUIC has no IP-layer knob (`grep` for `IP_TTL`/hop-limit is empty; DF is just quic-go's
`IP_PMTUDISC_DO`). So QOSF now cross-checks the two layers: `InferConsistency(kern, userAgent)` compares
the OS the **kernel TTL** implies (Windows→128, Unix-like→64) against the OS the **User-Agent** claims,
emitting `qosf.consistency = {verdict: "consistent"|"mismatch"|"unknown", claimed_os, kernel_os, detail}`.
A Linux host (TTL 64) presenting a Windows UA — the exact uQUIC-on-a-server case — yields **`mismatch`**
("a mimic such as uQUIC can forge the whole QUIC fingerprint yet cannot forge the kernel TTL … consistent
with a userspace QUIC mimic, a proxy, or a VPN" — honest: a proxy/VPN also triggers it). Computed in the
router (has both `kern` and `res.UserAgent`); the UI shows a verdict card (red on mismatch) and appends
`⚠ OS mismatch` to the Fingerprints-card note. Tests `TestUAOSFamily` / `TestInferConsistency` /
`TestConsistencyMismatchMentionsMimic`. Live-verified: real macOS/h3 → `consistent`; the mismatch payload
demonstrated via the exported function (Windows UA + TTL 52 → `mismatch`). Analysis:
`../muaa-alumni/research/qosf-vs-uquic.md`.

**QUIC Initial packet structure (`QOSFDetails.InitialPacket`, from studying [0x4D31/finch](https://github.com/0x4D31/finch)):**
finch's "experimental QUIC fingerprinting" decrypts the Initial and computes the **QUIC JA4** — the exact
fingerprint TrackMe already produces, entirely user-space, a strict subset of QOSF (and less robust: its
passive decryptor only handles quic-go clients, not real Chrome/curl). So finch buys no better fingerprint.
The one enrichment it + uQUIC point to is the **Initial packet structure** (what finch reads through and
uQUIC's `InitialPacketSpec` forges): QOSF now surfaces `qosf.initial_packet = {quic_version, dcid_length,
scid_length, udp_datagram_size}`, captured by the pcap tap (`DCIDLen` was already captured; the UDP datagram
size added to `QOSFKernel`). **Informational and NOT part of the canonical QOSF string** (fingerprint
stability preserved — test asserts the string is unchanged); honestly user-space / spoofable — it sharpens
browser-family discrimination, not evasion-resistance. UI shows a small "QUIC Initial packet (on the wire)"
card. Test `TestQOSFInitialPacket`. Analysis: `../muaa-alumni/research/qosf-vs-finch.md`.

**UI (`static/index.html`, frontend-only, no rebuild):**
- A **QOSF card** on the Fingerprints tab (`#qosf` + note) showing the current user's record.
- A new **"QOSF · QUIC OS" tab** (`tab-qosf`/`panel-qosf`, purple accent, added to `showTab`) = a
  **diagram view for the current user**: the color-segmented canonical string (A red / B blue / C
  green / D purple) + a source badge; an **Inferred OS** card (family · candidates · confidence +
  rationale, red-bordered like segment A); a "How your QOSF is built" flow (first-flight → four
  color-coded segment cards with live value + source → the assembled QOSF); and a per-field
  breakdown grouped by segment, each field carrying an **observed / derived / absent** status chip,
  its value, the note, and a plain-English doc (segment C is shown as id chips). Because QOSF is
  QUIC-only and the inline page-load is usually h2, `applyQOSF` **auto-refetches `/api/all` once**
  (browsers upgrade to h3 via `Alt-Svc`) with a manual **↻ recheck** button; XSS-safe
  (textContent/createElement).

**Verified:** 14 unit tests + full `go test ./...` green; a 5-lens adversarial review returned **0
confirmed findings**. Live on the droplet — h2/TCP `/api/all` has JA4 and **no `qosf`** (gate holds);
a real external Chromium over h3 yields `source: pcap+quic`, e.g.
`q64n1-_ch1gt00_01.03.04.05.06.07.08.09.0f.11.20.3127.G_30000.-.-.-.1472.15728640.100` — `ttl=6`
(observed hop-limit **50 → inferred 64**, cross-checked against tcpdump `ttl 50`), `scid=00` from the
long header, `acid/madelay/adexp = -` (no-fabrication), and `stack=ch` because that session sent the
Google TP `0x3127`. The **Inferred OS** card reads *Unix-like · low confidence* (initial TTL 64),
correctly listing macOS among the candidates, and the Fingerprints-card note shows
`· inferred OS: Unix-like`. Both the diagram tab and the Fingerprints card render it; 0 console errors.
Plan/results doc: `../muaa-alumni/research/qosf-integration-plan.md`.

---

## 17 — JA4T card on the SPHBI tab (feature, frontend-only, in `00-all-changes.patch`)

A **"JA4T · TCP client fingerprint"** card on the **SPHBI · Packet Image** tab (`panel-sphbi`),
populated in `renderSPHBI(sphbi, ja4t)` from `/api/all`'s `tcpip.ja4t`. It reinforces that the JA4T
and the SPHBI image both derive from the **same captured TCP SYN** (`pkg/tcp/tcp.go`'s `SniffTCP`
computes `JA4TFromSYN(tcp)` right next to `buildSPHBI(tcp)`): the image encodes the 18 header bytes,
JA4T encodes the TCP options (`window_options-order_MSS_wscale`). Kind-aware: a QUIC/h3 connection
(no TCP SYN) shows **"— not applicable (QUIC / HTTP-3 has no TCP SYN; JA4T is TCP-only)"** rather than
a blank. Frontend-only — deployed by replacing `/opt/trackme/static/index.html` (served from disk via
`utils.ReadFile`), **no rebuild**. (JA4T itself — the `pkg/tcp/ja4t.go` computation + `TCPIPDetails.JA4T`
+ the router correlation + the original Fingerprints-tab card — landed earlier; this section is just
the additional SPHBI-tab surfacing.)

---

## 18 — ASN filter on Previous Clients / Comparative (feature, in `00-all-changes.patch`)

Filter the client list by **autonomous system**: substring match across the **AS number** *and* the
operator (`as_name` / `org` / `isp`), plus a facet **dropdown of ASNs seen so far** that grows in real
time (clones the JA4-picker pattern).

**Backend (`pkg/store/store.go` + `pkg/server/routes.go`):**
- `idx:asnset` ZSET (member e.g. `"AS7018 · ATT-INTERNET4"`, score = recency, cap `asnSetCap = 2000`),
  written in `LookupASN`'s cache-success path so every resolved ASN becomes a dropdown option.
- `Store.ASNValues(ctx)` reader → `GET /api/asnvalues` (read-gated, `history_public || IsAdmin`).
- `ListClients` gained a trailing `asnQ string` parameter → `/api/clients?asn=<q>`. When set, each
  candidate's `asn:<ip>` records are pipelined and matched by `asnMatchesAny` (AS number + operator,
  case-insensitive substring). Clients whose IP has **no cached ASN are excluded** while the filter is
  active. Tests `TestASNValues` + `TestListClientsASNFilter`.

**Frontend (`static/index.html`):** an ASN input `#pc-f-asn` + `pcAsn*` picker in the shared filter bar,
wired into `pcAddFilterParams` / `pcClearFilters`, so it applies on both **Previous Clients** and the
**Comparative** flat pool.

**Scope:** flat pool only — the grouped "unique per scraping-header" view does **not** apply ASN
(consistent with the `ip` filter); the filter reads only the cached `asn:*` records, so run **Backfill
ASN** first to warm them. Live-verified: `/api/asnvalues` = 20 distinct; `?asn=AS7018` narrowed
13,882 → 90, operator substring `att-` → 93, no-match → 0. Requires a rebuild (new store/routes code).
Spec `docs/2026-07-15-comparative-asn-filter-design.md`.

---

## 19 — Blueprint tab: QUIC transport-param images by client stack (feature, frontend-only, in `00-all-changes.patch`)

A static reference panel on the **Blueprint** tab (`#bp-quic-stacks` + `renderQuicStacks()` /
`BP_QUIC_STACKS` in `static/index.html`) that shows the **QUIC transport-parameter SPHBI fingerprints
the QUIC *library*, not the OS** — the opposite of the TCP-SYN SPHBI/JA4T, which are OS-kernel
fingerprints, because QUIC is user-space. It renders **three REAL captures from one macOS machine**
(same OS, different browsers) as per-stack 12×12 SVG grids with their QUIC JA4:
- **Chrome / Chromium** — `q13d0313h3_55b375c5d22e_226f3f127bbe` (38 / 144 bits on)
- **Safari / Apple Network.framework** — `q13d0311h3_55b375c5d22e_0e9637bee5d3` (19)
- **Firefox / neqo** — `q13d0315h3_55b375c5d22e_dc5437974b47` (30)

Shared JA4 cipher core, differing extension counts (11 / 13 / 15), pairwise Hamming ≈ 24–25 of 144 —
i.e. three clearly distinct images from ONE OS, demonstrating the library-not-OS point that motivated
QOSF (§16). The bits are hardcoded from the real captures (nothing synthetic); frontend-only, deployed
by static-file replace, **no rebuild**. **Gotcha recorded:** BrowserStack **cannot** capture QUIC —
its device cloud drops UDP/443 to an arbitrary origin, so devices fall back to h2; real QUIC diversity
needs real devices on a normal network.

---

## 20 — Stack Analysis: live cross-layer "contradiction stack" (feature, frontend-only, in `00-all-changes.patch`)

A new **"Stack Analysis"** tab (red accent) that renders, for **the current visitor**, a live
cross-layer contradiction stack: the actual value extracted at each network layer and a rule verdict on
whether it agrees with the L7 claim. The premise (per the reference design): faking the top of the stack
(the User-Agent) is cheap, but every faked signal must stay consistent with the harder-to-fake signals
beneath it — so a lower-layer disagreement is a strong spoof signal.

Frontend-only (`static/index.html`) — it composes signals TrackMe **already exposes** (`/api/all` +
`/api/asn`), so no backend change and no rebuild. Five layers, each checked against the L7 claim:

- **L7 · USER-AGENT** — the claim. `saParseUA` → OS + browser/library + device (e.g. "iPhone · Safari",
  or an honest library like "python-requests"). Verdict `THE CLAIM`.
- **L5-6 · TLS / JA4** — `saBrowserTLS` flags **browser-only ClientHello extensions** that automation
  libraries never send: GREASE, **ALPS** (`application_settings` 17613), **ECH** (65037), cert
  compression (27). (GREASE alone is unreliable — it's filtered from `/api/all`'s readable ciphers, and
  absent on the h3 path — so the marker set is the real tell.) A browser-claiming UA with none of these →
  **contradiction** (library TLS stack).
- **H2 · FRAMING** — the Akamai HTTP/2 fingerprint's **pseudo-header order** (last `|`-field): Chrome/Edge
  `m,a,s,p`, Firefox `m,p,a,s`, Safari `m,s,a,p`. A browser-claiming UA whose order ≠ its browser's → not
  that browser's framing → **contradiction**.
- **L3-4 · TCP/IP** — kernel OS from the SYN's **TTL** (`tcpip.ip.ttl`; 128 = Windows, 64 = Unix-like);
  for QUIC (no SYN) it reuses the **QOSF** kernel signal + consistency verdict. Claimed OS vs kernel OS
  (Windows↔Unix) → **contradiction**.
- **L1-3 · NETWORK · ASN** — `/api/asn` → datacenter/hosting vs residential/ISP (`SA_DATACENTER` keyword
  list on AS-name/ISP/org). A real-browser claim from a datacenter (AWS/GCP/DO/…) → **contradiction**.

Overall banner: **COHERENT** (0 contradictions) or **N CONTRADICTIONS**. Honest — a proxy/VPN/privacy
tool can also cause a mismatch, stated in the UI (a strong signal, not proof). Rows match the reference
design (mono accent-coloured layer label · observed value · raw evidence · right-aligned verdict badge
`THE CLAIM`/`CONSISTENT`/`CONTRADICTION`/`UNRESOLVED`). XSS-safe via the existing `pcEl` (textContent).

Live-verified: a real macOS/Chrome (h3) browser → **COHERENT** (TLS ALPS/ECH/cert-compression, framing
`m,a,s,p`, Unix-like kernel via QOSF, residential ASN — all consistent, 0 console errors); and a
synthetic spoofer (iPhone-Safari UA + library TLS + Go framing + Windows TTL + AWS ASN) → **4
contradictions**, reproducing the reference contradiction stack exactly.

**Two compared values per layer + Previous-Clients detail pane (follow-up).** Each layer now shows
**both** values it's comparing — `CLAIM EXPECTS <x>  ≈/≠  OBSERVED <y>` — instead of a single observed
string (`saLayers` emits `expected` + `actual`; `saRenderInto` renders the pair with a ≈/≠/? arrow
coloured by verdict). The rendering + `saLayers` are factored into shared helpers so the same stack
appears in a new **draggable "Stack Analysis · contradiction stack" section of the Previous-Clients
detail pane** (`saInputFromClient(d)` adapts a stored record — top-level `akamai_fingerprint` → framing;
resolves the client's primary IP via `/api/asn?ip=` for L1-3). To make the stored analysis as accurate
as the live one, **`store.GetClient` now exposes the latest connection's full `TLS` (extensions/ciphers —
needed for the ALPS/ECH browser-marker check) and `QOSF` (kernel signal for stored QUIC clients)**, where
before it kept only `quic_transport_parameters` (one small backend change; store tests green). Live-verified
on a stored macOS-Chrome client: L5-6/H2/L3-4 **consistent** (each showing expected≈observed) and L1-3 a
**genuine contradiction** — its stored IP is `18.88.45.155` (AMAZON-02/AWS), i.e. a "macOS Chrome" whose
network is a datacenter.

---

## 21 — Controlled-experiment `?exp=` token capture (feature, in `00-all-changes.patch`)

*(Shipped early with the browser-fleet → SPHBI experiment tooling; documented here.)* Lets a fleet driver
tag its requests with a signed `?exp=<token>` so the server can join a device's fingerprint back to the
orchestrator's manifest for a labelled dataset.

- **`pkg/tls/exp.go` `ValidExp(token, secret)`** verifies a token of the form
  `cell_id.nonce_b32.sig_b32`, where `sig = lower(b32-nopad(HMAC-SHA256(secret, "cell_id.nonce")[:8]))` —
  byte-identical to the Python minter (`fleet/fpdriver/token_mint.py`). Tests `pkg/tls/exp_test.go`
  (`TestValidExp*`: Python-parity, wrong-secret, tampered, malformed) + `exp:tok1` coverage in
  `pkg/store/store_test.go`.
- **Router gate** (`pkg/server/router.go`): when `?exp=` is present, `Response.Exp` is set iff
  **`EXP_SECRET` is unset (captures any value — fail-open) OR the token is HMAC-valid**; internet-scanner
  garbage is dropped once the secret is configured. `Config.ExpSecret` ← env **`EXP_SECRET`**
  (`pkg/types/structs.go`, wired in `cmd/main.go`).
- **Store**: `exp:<token>` HASH `{sphbi, ja3, ja4, ja4t, akamai, ua, ip, source_port, http_version}` +
  `idx:experiments` set; readers `Store.GetExp` / `Store.ListExp`; `exp:*` is wiped by `DeleteAll`.
- **Endpoints** (`pkg/server/routes.go`, same `history_public || IsAdmin` read gate): `GET /api/exp?token=`
  (one token) and `GET /api/exp/all` (full dump, for the join tool).

Design note: the tag rides in the **query string, not a header** — header injection is Chromium-only and
would break Safari/Firefox/mobile fleet devices. Works over h1/h2/h3 (the h3 handler passes
`r.URL.RequestURI()`, keeping the query).
