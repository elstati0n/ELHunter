# ElHunter — Threat Intelligence Browser Extension

<p align="center">
  <img src="icons/icon128.png" width="150" alt="ElHunter"/>
</p>

<p align="center">
  <b>Real-time domain & IP threat analysis directly in your browser.</b><br/>
  VirusTotal · AbuseIPDB · Geo Intelligence · AI Phishing Detection · Telegram Alerts
</p>

---

## What is ElHunter?

ElHunter is a Chrome extension that silently monitors every website you visit and every email you read — checking URLs, domains and IP addresses against multiple threat intelligence sources in real time. If something malicious is detected, it blocks the page **instantly** using Chrome's `declarativeNetRequest` API and shows a detailed threat report. For emails, it scans embedded links (including hidden button hrefs) and optionally analyzes the full content with AI.

Designed for security professionals, IT administrators, journalists, and privacy-conscious users who want enterprise-grade threat visibility without enterprise-grade complexity.

---

## Features

### 🔴 Real-time Site Blocking

Every navigation is checked against VirusTotal and AbuseIPDB. If the domain or IP is flagged as malicious, the tab is immediately redirected to a detailed block page showing:

- Blocked URL
- VirusTotal vendor count (e.g. `15/94 flagged`)
- AbuseIPDB confidence score with visual progress bar
- Resolved IP address
- Country and ISP/Organization
- Cloudflare detection (CDN vs Direct IP)
- Reason for block (VT/AbuseIPDB or country rule)

#### Two-phase blocking engine

**Phase 1** — VirusTotal + AbuseIPDB are queried immediately on navigation. If malicious, the tab is blocked before the page loads. A `declarativeNetRequest` dynamic rule is also written so that **all future visits to the same host are blocked at the network level** — before any JavaScript runs, with zero page flash.

**Phase 2** — Runs in the background after Phase 1. Resolves the domain to an IP via DNS, geolocates it, checks AbuseIPDB on the resolved IP. If Phase 2 upgrades the threat level to malicious, **the currently open tab is blocked immediately** — no refresh needed.

#### Instant blocking on repeat visits

DNR rules are restored every time the service worker starts (browser launch, extension reload, update). Cached malicious hosts are blocked instantly on the very first navigation attempt — no API call needed.

---

### 🔒 Block Page & Bypass Controls

When a site is blocked the tab is redirected to `blocked.html` with full threat intelligence.

**Go Back to Safety** — navigates back to the previous page.

**Proceed anyway** — temporarily removes the DNR block rule, allows access for **1 hour**, then automatically re-adds the block rule. The cache entry stays malicious — the host will block again after the hour expires.

> The Proceed anyway button is handled entirely in the background: the DNR rule is removed first, then the tab is navigated. This guarantees no redirect loop.

---

### 🔓 Cache Lock / Unlock

In the **Cache tab**, every malicious or blocked entry has a lock icon:

| Icon | State | Behaviour |
|------|-------|-----------|
| 🔒 (dim) | Blocked | Click to permanently unblock and open the site immediately |
| 🔓 (green) | Unblocked | Click to re-lock — next visit will block again |

- **Permanent unblock** (from cache) — host is added to `UNBLOCKED_HOSTS`, persisted to `chrome.storage.local`, DNR rule removed. Survives extension reloads. Active until the cache entry expires (14 days) or you manually re-lock.
- **Proceed anyway** (from block page) — 1-hour temporary allow. Cache entry and DNR rule are untouched. After 1 hour the block is automatically restored.
- **Re-lock** — immediately re-adds the DNR rule. Host blocks on the very next navigation.

---

### 🔔 Smart Notifications

Chrome notifications fire for suspicious and malicious sites — even without opening the popup. Configurable per country rule or globally.

---

### 📧 Email Phishing Detection

On Gmail, Outlook Web, Yahoo Mail and ProtonMail — two independent detection layers activate when you open an email.

**Regex URL Check (default ON)**

Links are extracted from two sources simultaneously:
1. **Plain text regex** — `http://` and `https://` URLs found in the email body text
2. **DOM href scan** — `href` attributes on all `<a>` elements, including button-style links with redirect URLs (e.g. `https://accounts.google.com/AccountChooser?continue=...`)

All discovered hosts are deduplicated and checked against VirusTotal + AbuseIPDB. Results appear inline at the top of the page:
- ✓ `github.com` clean
- ✕ `evil-domain.com` (VT:5/72  Abuse:85%)

The result bar auto-dismisses after 7 seconds if all links are clean. If any threat is found, it stays until you close it (✕) or navigate away from the email.

**Bars are automatically removed** when you close an email or navigate back to the inbox — no stale results linger between messages.

**AI Analysis (requires API key, default OFF)**

A bar appears at the top of the open email asking "Analyze with AI?". On confirmation, the email content is sent to your configured AI provider which returns a 0–100% phishing probability score and a one-sentence explanation.

Supports: OpenAI, Anthropic, Google Gemini, Mistral, Groq, OpenRouter, Ollama (local), LM Studio (local) and any OpenAI-compatible endpoint.

---

### 🌍 Geo Intelligence

Every domain is resolved to its IP via [networkcalc.com](https://networkcalc.com) DNS lookup, then geolocated via [ipinfo.io](https://ipinfo.io). Country, ISP, organization and Cloudflare status are enriched in the background. Clicking country, IP or Cloudflare rows in the popup opens a Whois lookup for the host.

---

### ☁️ Cloudflare Detection

Resolved IPs are matched against Cloudflare's published CIDR ranges (IPv4 and IPv6). Shows "YES — Cloudflare" or "NO — Direct IP" in the popup and on block pages.

---

### 🌐 Country Rules

Country Rules let you define custom behavior for traffic originating from specific countries. When at least one rule exists, **only those countries trigger alerts** — all others are silently ignored.

Each rule supports:
- **IP ON** — match by server hosting country (geo IP lookup)
- **TLD ON** — match by domain extension (e.g. `.ru`, `.cn`) — no geo lookup needed
- **Notify ON/OFF** — Chrome notification on threat
- **Mode** — Suspicious only / All events
- **Block ON/OFF** — block all access from this country regardless of VT/AbuseIPDB scores
- **TG ON/OFF** — send Telegram alert for this rule

---

### ✈️ Telegram Alerts

Send threat alerts to a Telegram bot. Configure bot token + chat ID in API Keys. Each alert includes: threat level emoji, VT score, AbuseIPDB score, country flag, resolved IP and Cloudflare status.

---

### 💾 14-Day Cache

All scan results are cached in `chrome.storage.local` with a 14-day TTL. The **Cache tab** shows a real-time breakdown (clean / suspicious / malicious / blocked). Click any chip to expand an inline list — the popup grows naturally to fit the content. Each row shows domain, country, VT, AbuseIPDB, Cloudflare status and age. Per-row delete (🗑) and lock toggle (🔒/🔓) are available.

---

## Classification Logic

| Condition | Level | Action |
|-----------|-------|--------|
| VT flagged ≥ 4 vendors | `malicious` | Instant block + DNR rule |
| AbuseIPDB ≥ 55% | `malicious` | Instant block + DNR rule |
| VT flagged 1–3 vendors | `suspicious` | Notification |
| AbuseIPDB 1–54% | `suspicious` | Notification |
| No flags | `clean` | Silent |

> AbuseIPDB is checked on the **resolved IP** for domains (Phase 2). The threshold is 55% — below this, the site is flagged as suspicious but not blocked.

---

## Architecture

```
Browser Navigation
       │
       ▼
  background.js (Service Worker)
       │
       ├── restoreDNRRules() ──────────── runs at top-level on SW start
       │   Reads all malicious cache entries → writes DNR rules immediately
       │   before any navigation event fires
       │
       ├─── webNavigation.onBeforeNavigate ─── cache-hit instant block
       │    If host is cached as malicious → blockTab() before page loads
       │
       ├─── tabs.onUpdated (loading) ──────── first-visit flow
       │    │
       │    ├─── Phase 1 ──────────────────────────────────────────────────┐
       │    │    VirusTotal API       → malicious/suspicious/harmless count │
       │    │    AbuseIPDB API        → confidence score (IP only)          │
       │    │    classify()           → 'clean'|'suspicious'|'malicious'    │
       │    │    cacheSet(host)       → saved to chrome.storage.local       │
       │    │    addDNRBlock(host)    → network-level block for future visits│
       │    │    If malicious → blockTab() immediately                      │
       │    │                                                                │
       │    └─── Phase 2 (background) ──────────────────────────────────────┘
       │         networkcalc.com DNS  → domain → IP
       │         ipinfo.io            → IP → country, ISP, org
       │         AbuseIPDB (on IP)    → upgrade level if score ≥ 55%
       │         If upgraded to malicious → blockTab() current tab immediately
       │         isCF(ip)             → Cloudflare CIDR match
       │         notifDecision()      → 'block'|'notify'|'skip'|'wait'
       │
       └─── Email tabs (phishing-content.js injected)
            extractUrls(text)         → regex from email body text
            extractUrlsFromDOM(body)  → href attributes on all <a> elements
            CHECK_EMAIL_URLS          → VT + AbuseIPDB per unique host
            showRegexResult()         → inline bar, auto-hides if clean
            MutationObserver          → removes bars when email is closed
            CHECK_EMAIL_LLM           → email content → AI provider → score
            showLLMResult()           → inline bar with % and reason
```

---

## External APIs

| Service | Purpose | Auth | Free Limit |
|---------|---------|------|------------|
| [VirusTotal](https://virustotal.com) | Domain/IP threat scan | API key | 4 req/min, 500/day |
| [AbuseIPDB](https://abuseipdb.com) | IP abuse confidence | API key | 1,000 req/day |
| [networkcalc.com](https://networkcalc.com) | DNS A record lookup | None | No public limit |
| [ipinfo.io](https://ipinfo.io) | IP geo + ISP lookup | None | 1,000 req/day |
| [api.telegram.org](https://core.telegram.org/bots) | Send alert messages | Bot token | No limit |
| AI providers | Phishing content analysis | API key | Varies |

---

## AI Provider Support

| Provider | Default Model |
|----------|--------------|
| OpenAI | `gpt-4o-mini` |
| Anthropic | `claude-haiku-4-5-20251001` |
| Google Gemini | `gemini-2.0-flash` |
| Mistral | `mistral-small-latest` |
| Groq | `llama-3.1-8b-instant` |
| OpenRouter | `openai/gpt-4o-mini` |
| Ollama (local) | `llama3.2` |
| LM Studio (local) | configurable |
| Custom (OpenAI-compat.) | configurable |

---

## Installation

### From Source (Developer Mode)

1. Download and unzip this repository
2. Open Chrome → `chrome://extensions`
3. Enable **Developer mode** (top right)
4. Click **Load unpacked** → select the `ElHunter` folder
5. The extension icon appears in the toolbar

### Configuration

Open the popup → **API Keys** tab:

| Key | Where to get | Required for |
|-----|-------------|--------------|
| VirusTotal | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) | Domain/IP scanning |
| AbuseIPDB | [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api) | IP abuse scoring |
| Telegram Bot Token | [@BotFather](https://t.me/BotFather) | Telegram alerts |
| Telegram Chat ID | [@userinfobot](https://t.me/userinfobot) | Telegram alerts |
| AI API Key | Provider dashboard | Email AI analysis |

> **Geo intelligence runs without any key.** Country, IP, ISP and Cloudflare detection use networkcalc.com + ipinfo.io — both free, no registration.

---

## File Structure

```
ElHunter/
├── manifest.json          # MV3 manifest — permissions, host_permissions, icons
├── background.js          # Service worker — analysis, cache, DNR rules, blocking
├── popup.html             # Extension popup UI
├── popup.js               # Popup logic — tabs, key widgets, rules, inline cache
├── blocked.html           # Block page UI
├── blocked.js             # Block page — reads params, polls enrichment, Proceed Anyway
├── phishing-content.js    # Content script — injected into email pages only
└── icons/
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

---

## Permissions

| Permission | Reason |
|------------|--------|
| `storage` | API keys, settings, cache, unblocked host list |
| `tabs` | Read current tab URL, navigate tabs for blocking/proceed |
| `webNavigation` | `onBeforeNavigate` for cache-hit instant blocking |
| `scripting` | Inject phishing content script into email tabs |
| `notifications` | Show threat alerts |
| `declarativeNetRequest` | Network-level instant blocking for malicious hosts |
| `<all_urls>` | Analyze any navigated URL |

---

## Privacy & Security

- **No data collected by ElHunter.** All settings and API keys stored in `chrome.storage.sync` (encrypted by Chrome, synced to your Google account).
- **API keys never leave your browser** except as authorization headers to their respective services.
- **Email content** sent to AI only when you explicitly click "Analyze" — never automatic.
- **Phishing detection** runs only on: `mail.google.com`, `outlook.live.com`, `outlook.office.com`, `outlook.office365.com`, `mail.yahoo.com`, `mail.proton.me`, `protonmail.com`.
- All HTML injected into pages is XSS-sanitized via `ehEscape()`.
- Hostnames from emails validated against `/^[a-zA-Z0-9._-]{1,253}$/` before any API call.
- DNR redirect targets point only to the extension's own `blocked.html`.

---

## Limitations

- Chrome only (Manifest V3). Firefox not supported.
- VirusTotal free API: 4 requests/minute, 500/day.
- ipinfo.io free tier: 1,000 requests/day — covered by 14-day cache.
- AbuseIPDB checks IP addresses only — domains without a resolved IP show N/A.
- Email detection works on supported webmail clients only, not desktop apps.
- Local LLM providers (Ollama, LM Studio) must be running before clicking Analyze.

---

## Acknowledgements

- [VirusTotal](https://virustotal.com) — multi-engine malware scanning
- [AbuseIPDB](https://abuseipdb.com) — IP reputation database
- [networkcalc.com](https://networkcalc.com) — free DNS lookup API
- [ipinfo.io](https://ipinfo.io) — IP geolocation and ASN data
- [Space Grotesk](https://fonts.google.com/specimen/Space+Grotesk) + [JetBrains Mono](https://fonts.google.com/specimen/JetBrains+Mono) — fonts

---

## License

MIT License. See [LICENSE](LICENSE) for details.
