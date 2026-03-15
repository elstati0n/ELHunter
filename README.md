# ElHunter — Threat Intelligence Browser Extension

<p align="center">
  <img src="icons/icon128.png" width="96" alt="ElHunter"/>
</p>

<p align="center">
  <b>Real-time domain & IP threat analysis directly in your browser.</b><br/>
  VirusTotal · AbuseIPDB · Geo Intelligence · AI Phishing Detection · Telegram Alerts
</p>

---

## What is ElHunter?

ElHunter is a Chrome extension that silently monitors every website you visit and every email you read — checking URLs, domains and IP addresses against multiple threat intelligence sources in real time. If something malicious is detected, it blocks the page instantly and shows a detailed threat report. For emails, it scans embedded links and optionally analyzes the full content with AI.

It is designed for security professionals, IT administrators, journalists, and privacy-conscious users who want enterprise-grade threat visibility without enterprise-grade complexity.

---

## Features

### 🔴 Real-time Site Blocking
Every navigation is checked against VirusTotal and AbuseIPDB. If the domain or IP is flagged as malicious, the tab is immediately redirected to a detailed block page showing:
- Blocked URL
- VirusTotal vendor count (e.g. `5/72 flagged`)
- AbuseIPDB confidence score with visual progress bar
- Resolved IP address
- Country and ISP/Organization
- Cloudflare detection (CDN vs Direct IP)
- Reason for block (VT/AbuseIPDB or country rule)

### 🔔 Smart Notifications
Chrome notifications fire for suspicious and malicious sites — even without opening the popup. Configurable per country rule or globally.

### 📧 Email Phishing Detection
On Gmail, Outlook Web, Yahoo Mail and ProtonMail — two independent detection layers activate when you open an email:

**Regex URL Check (default ON)**
All `http://` and `https://` links in the email body are extracted and checked against VirusTotal + AbuseIPDB. Results are shown inline at the top of the page:
- ✓ `github.com` clean
- ✕ `evil-domain.ru` (VT:5/72  Abuse:85%)

**AI Analysis (requires API key, default OFF)**
A bar appears at the top of the open email asking "Analyze with AI?". On confirmation, the email content is sent to your configured AI provider which returns a 0–100% phishing probability score and a one-sentence explanation. Supports OpenAI, Anthropic, Google Gemini, Mistral, Groq, OpenRouter, Ollama (local), LM Studio (local) and any OpenAI-compatible endpoint.

### 🌍 Geo Intelligence
Every domain is resolved to its IP via [networkcalc.com](https://networkcalc.com) DNS lookup, then the IP is geolocated via [ipinfo.io](https://ipinfo.io). Country, ISP, organization and Cloudflare status are enriched in the background after phase 1 scanning completes. All results are cached for 14 days.

### ☁️ Cloudflare Detection
Resolved IPs are matched against Cloudflare's published CIDR ranges (IPv4 and IPv6). Displays "YES — Cloudflare" or "NO — Direct IP" in the popup and on block pages.

### 🌐 Country Rules

Country Rules let you define custom behavior for traffic originating from specific countries. When at least one country rule exists, **only those countries trigger alerts** — all other countries are silently ignored (no notification, no block).

#### How a Country is Matched

Each rule has two independent matching modes that can be used together or separately:

**IP ON (IP-based match)**
The server's hosting country is determined by geo-locating its IP address. For example, if `example.com` resolves to an IP hosted in Russia, and you have a Russia rule with IP ON — it matches. This catches servers hosted in a country regardless of what domain name they use.

**`.ru` ON (Domain TLD match)**
The domain's top-level extension is checked directly — no geo lookup needed. If the visited URL ends in `.ru`, `.cn`, `.ir` etc. and you have the matching country rule with TLD ON — it matches instantly. This is faster and catches domains even if their hosting IP is in another country (e.g. a `.ru` site hosted on Cloudflare in the US).

Both can be ON simultaneously — either match is enough to trigger the rule.

---

#### What Happens When a Rule Matches

**Notify ON / Notify OFF**
- **ON** — a Chrome notification fires when a suspicious or malicious site from this country is visited. The notification appears even if the browser is minimized or the popup is closed.
- **OFF** — the visit is completely silent. No alert, no badge. Useful if you want to block a country without being notified about every single site.

**Mode: Suspicious only / All events**
This controls *which threat levels* trigger a notification (only visible when Notify is ON):
- **Suspicious only** — notification fires only if VirusTotal flags 1+ vendors OR AbuseIPDB score is above 0. Clean sites from this country are silent.
- **All events** — notification fires for *every* site from this country, even completely clean ones. Useful for high-risk countries where you want visibility into all traffic, not just flagged sites.

**Block ON / Block OFF**
- **ON** — access to any site from this country is immediately blocked, regardless of VT/AbuseIPDB results. The tab is redirected to the ElHunter block page with the reason shown (e.g. "Blocked: country rule (Russia)" or "Blocked: domain rule (.ru)"). The user can still choose "Proceed anyway" if needed.
- **OFF** — sites are not blocked. Only notifications apply.

> Note: When Block is ON, Notify and Telegram are automatically disabled for that rule — because a blocked site never loads, there is nothing to notify about separately.

**TG ON / TG OFF**
- **ON** — in addition to the Chrome notification, an alert is also sent to your configured Telegram bot. Includes threat level emoji, VT score, AbuseIPDB score, country flag, resolved IP and Cloudflare status.
- **OFF** — Telegram is not used for this rule. Chrome notification still fires if Notify is ON.

---

#### Practical Examples

| Scenario | IP | TLD | Notify | Mode | Block | TG |
|---|---|---|---|---|---|---|
| Monitor Russia, alert on threats | ON | ON | ON | Suspicious only | OFF | OFF |
| Block all .cn domains silently | OFF | ON | OFF | — | ON | OFF |
| Alert on everything from Iran + Telegram | ON | ON | ON | All events | OFF | ON |
| Block known bad country, notify yourself on Telegram | ON | OFF | OFF | — | ON | ON |

#### Relationship with Default Mode

When no country rules are configured, the **Default Mode** (Rules tab → Default Mode card) applies to all countries globally. Once you add even one country rule, the Default Mode becomes a **fallback** — it applies only to countries that do not match any rule. All other countries fall through silently.

### ✈️ Telegram Alerts
Send threat alerts to a Telegram bot. Configure bot token + chat ID in API Keys. Can be enabled globally or per country rule. Each alert includes threat level, VT score, AbuseIPDB score, country flag, resolved IP and Cloudflare status.

### 💾 14-Day Cache
All scan results are cached locally in `chrome.storage.local` with a 14-day TTL. Revisiting a domain never triggers a new API call until the cache expires. Cache stats are visible in the Cache tab — filterable by clean / suspicious / malicious / blocked.

---

## Architecture

```
Browser Navigation
       │
       ▼
  background.js (Service Worker)
       │
       ├─── Phase 1 ─────────────────────────────────────────────────────────┐
       │    VirusTotal API          → malicious/suspicious/harmless count     │
       │    AbuseIPDB API           → confidence score (IP only)              │
       │    classify()              → 'clean' | 'suspicious' | 'malicious'   │
       │    cacheSet(host, entry)   → saved to chrome.storage.local           │
       │                                                                       │
       │    If malicious → blockTab() immediately                             │
       │                                                                       │
       ├─── Phase 2 (background) ────────────────────────────────────────────┘
       │    networkcalc.com DNS     → domain → IP
       │    ipinfo.io               → IP → country, ISP, org
       │    isCF(ip)                → Cloudflare CIDR match
       │    notifDecision()         → 'block' | 'notify' | 'skip' | 'wait'
       │    fireNotif() or blockTab()
       │
       └─── Email tabs (phishing-content.js injected)
            extractUrls()           → regex from email body
            CHECK_EMAIL_URLS        → VT + AbuseIPDB per host
            showRegexResult()       → inline bar with per-link status
            CHECK_EMAIL_LLM         → email content → AI provider → score
            showLLMResult()         → inline bar with % and reason
```

### Request Flow per Navigation

```
User visits example.com
  │
  ├─ cacheGet("example.com")
  │    └─ Hit → return cached result, skip all API calls
  │
  └─ Miss →
       ├─ VirusTotal: GET /api/v3/domains/example.com
       ├─ AbuseIPDB:  GET /api/v2/check?ipAddress=example.com
       ├─ classify(vt, abuse) → level
       │
       ├─ [Phase 2, async]
       │    ├─ networkcalc.com: GET /api/dns/lookup/example.com  → IP
       │    ├─ ipinfo.io:       GET /{ip}/json                   → geo
       │    └─ isCF(ip)                                          → cloudflare
       │
       └─ cacheSet("example.com", enriched entry)
```

### Classification Logic

| Condition | Level |
|---|---|
| VT flagged ≥ 4 vendors OR AbuseIPDB ≥ 40% | `malicious` |
| VT flagged 1–3 vendors OR AbuseIPDB 1–39% | `suspicious` |
| No flags | `clean` |

Malicious → immediate block. Suspicious → notification (configurable). Clean → silent.

---

## External APIs

| Service | Purpose | Auth | Limit (free) | Protocol |
|---|---|---|---|---|
| [VirusTotal](https://virustotal.com) | Domain/IP threat scan | API key required | 4 req/min, 500/day | HTTPS |
| [AbuseIPDB](https://abuseipdb.com) | IP abuse confidence | API key required | 1,000 req/day | HTTPS |
| [networkcalc.com](https://networkcalc.com) | DNS A record lookup | No key | No public limit | HTTPS |
| [ipinfo.io](https://ipinfo.io) | IP geo + ISP lookup | No key needed | 1,000 req/day (shared) | HTTPS |
| [api.telegram.org](https://core.telegram.org/bots/api) | Send alert messages | Bot token | No limit | HTTPS |
| AI providers | Phishing content analysis | API key required | Varies per provider | HTTPS |

> **Note:** All external requests are made from the service worker (background context), not from page content. No request is made from within the email page itself.

### AI Provider Support

| Provider | Endpoint | Auth | Default Model |
|---|---|---|---|
| OpenAI | `api.openai.com` | Bearer token | `gpt-4o-mini` |
| Anthropic | `api.anthropic.com` | `x-api-key` header | `claude-haiku-4-5-20251001` |
| Google Gemini | `generativelanguage.googleapis.com` | Query param `?key=` | `gemini-2.0-flash` |
| Mistral | `api.mistral.ai` | Bearer token | `mistral-small-latest` |
| Groq | `api.groq.com` | Bearer token | `llama-3.1-8b-instant` |
| OpenRouter | `openrouter.ai` | Bearer token | `openai/gpt-4o-mini` |
| Ollama (local) | `http://localhost:11434` | None | `llama3.2` |
| LM Studio (local) | `http://localhost:1234` | None | configurable |
| Custom | Any OpenAI-compatible URL | Optional | configurable |

---

## Privacy & Security

- **No data is collected by ElHunter.** All settings and API keys are stored in `chrome.storage.sync` (your Google account, encrypted by Chrome).
- **API keys never leave your browser** except as authorization headers to their respective services.
- **Email content** is sent to your configured AI provider only when you explicitly click "Analyze" — never automatically.
- **Phishing content script** only runs on known email domains: `mail.google.com`, `outlook.live.com`, `outlook.office.com`, `outlook.office365.com`, `mail.yahoo.com`, `mail.proton.me`, `protonmail.com`.
- **All domain/IP data** sent to VirusTotal, AbuseIPDB, networkcalc and ipinfo.io is the domain/IP of the site being visited — no personal data.
- All HTML injected into email pages is XSS-sanitized via `ehEscape()` before insertion.
- Host names extracted from email bodies are validated against `/^[a-zA-Z0-9._-]{1,253}$/` before any API call.

---

## Installation

### From Source (Developer Mode)

1. Download and unzip this repository
2. Open Chrome → `chrome://extensions`
3. Enable **Developer mode** (top right toggle)
4. Click **Load unpacked**
5. Select the unzipped `ElHunter` folder
6. The extension icon appears in the toolbar

### Configuration

Open the popup by clicking the ElHunter icon, then go to **API Keys** tab:

| Key | Where to get | Required for |
|---|---|---|
| VirusTotal | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) | Domain/IP scanning |
| AbuseIPDB | [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api) | IP abuse scoring |
| Telegram Bot Token | Create via [@BotFather](https://t.me/BotFather) | Telegram alerts |
| Telegram Chat ID | Get from [@userinfobot](https://t.me/userinfobot) | Telegram alerts |
| AI API Key | Provider dashboard (see table above) | Email AI analysis |

> **Geo intelligence works without any key.** Country, IP, ISP and Cloudflare detection all run for free via networkcalc.com + ipinfo.io.

---

## Tabs Overview

### Main Tab
Shows threat analysis for the currently active tab. Displays threat level badge, VT score, AbuseIPDB score, country with flag, Cloudflare status and resolved IP. Polls every 600ms until geo enrichment completes.

### API Keys Tab
Save/edit/remove keys for: VirusTotal, AbuseIPDB, AI Model (with provider + model selection), Telegram bot.

### Rules Tab
**Phishing Detection card** — toggle Regex URL Check and AI Analysis for email pages.

**Default Mode card** — global notification mode (Suspicious only / All events / Off) and global Telegram toggle.

**Country Rules card** — add countries, configure per-country behavior (IP-based match, domain TLD match, notify, block, Telegram, mode).

### Cache Tab
Shows total entries and breakdown by level (clean / suspicious / malicious / blocked). Click any chip to open a detailed overlay with domain, country, VT score, Cloudflare status and age. Clear all cache button available.

---

## Block Page

When a site is blocked, the tab is redirected to `blocked.html` with full threat intelligence:

- Animated threat indicator with pulsing rings
- Blocked URL
- VirusTotal flagged vendor count
- AbuseIPDB confidence score with color-coded bar
- Country, ISP, Resolved IP, Cloudflare status (enriched asynchronously)
- **Go Back to Safety** — navigates back
- **Proceed anyway** — shows confirmation dialog, adds URL to allow-once set, then navigates

---

## File Structure

```
ElHunter/
├── manifest.json          # MV3 manifest — permissions, host_permissions, icons
├── background.js          # Service worker — all analysis logic, API calls, cache
├── popup.html             # Extension popup UI
├── popup.js               # Popup logic — tabs, key widgets, rules, cache stats
├── blocked.html           # Block page UI
├── blocked.js             # Block page logic — reads URL params, polls for enrichment
├── phishing-content.js    # Content script — injected into email pages only
└── icons/
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

---

## Permissions

| Permission | Reason |
|---|---|
| `storage` | Store API keys, settings and cache |
| `tabs` | Read current tab URL for analysis |
| `webNavigation` | Detect navigation events |
| `scripting` | Inject phishing content script into email tabs |
| `notifications` | Show threat alerts |
| `<all_urls>` | Analyze any navigated URL (required for universal coverage) |

---

## Limitations

- Requires Chrome (Manifest V3). Firefox support not implemented.
- VirusTotal free API: 4 requests/minute, 500/day. Heavy browsing may hit limits.
- ipinfo.io free tier: 1,000 requests/day (shared by IP). Covered by 14-day cache.
- AbuseIPDB checks IP addresses only — domain-only sites without resolved IPs show N/A.
- Email phishing detection works only on supported webmail clients, not desktop email apps.
- Local LLM providers (Ollama, LM Studio) must be running before clicking Analyze.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Acknowledgements

- [VirusTotal](https://virustotal.com) — multi-engine malware scanning
- [AbuseIPDB](https://abuseipdb.com) — IP reputation database
- [networkcalc.com](https://networkcalc.com) — free DNS lookup API
- [ipinfo.io](https://ipinfo.io) — IP geolocation and ASN data
- [Space Grotesk](https://fonts.google.com/specimen/Space+Grotesk) + [JetBrains Mono](https://fonts.google.com/specimen/JetBrains+Mono) — fonts
