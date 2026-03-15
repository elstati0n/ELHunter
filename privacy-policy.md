# Privacy Policy — ElHunter

**Last updated: March 15, 2026**

ElHunter ("the Extension") is a browser extension for Google Chrome that provides real-time threat intelligence and phishing detection. This Privacy Policy explains what data is processed, how it is used, and what is never collected.

---

## 1. Data We Do Not Collect

ElHunter does **not** collect, store, transmit, or sell any personal data to the developer or any third party controlled by the developer. There are no analytics, telemetry, tracking pixels, or usage statistics sent to any server owned or operated by the developer.

---

## 2. Data Stored Locally on Your Device

The following data is stored exclusively in `chrome.storage.sync` (encrypted by Chrome and synced via your Google account) or `chrome.storage.local` (on-device only):

- **API keys** — VirusTotal, AbuseIPDB, Telegram bot token, Telegram chat ID, AI provider key. These are stored locally and never transmitted to the developer.
- **Settings** — notification preferences, country rules, phishing toggle states, AI provider and model selection.
- **Scan cache** — domain and IP scan results (threat level, VT score, AbuseIPDB score, country, ISP, Cloudflare status) cached locally for up to 14 days to avoid redundant API calls.

---

## 3. Data Sent to Third-Party Services

To perform threat analysis, the Extension sends data directly from your browser to the following third-party services. The developer has no access to these requests or their responses.

| Service | Data sent | Purpose |
|---|---|---|
| [VirusTotal](https://www.virustotal.com/gui/help/privacy) | Domain name or IP address of visited site | Multi-engine malware/threat scanning |
| [AbuseIPDB](https://www.abuseipdb.com/privacy-policy) | IP address of visited site | IP abuse confidence scoring |
| [networkcalc.com](https://networkcalc.com) | Domain name of visited site | DNS A record resolution (domain → IP) |
| [ipinfo.io](https://ipinfo.io/privacy) | Resolved IP address of visited site | Geolocation, ISP and ASN lookup |
| [Telegram Bot API](https://telegram.org/privacy) | Threat alert text (domain, scores, country) | Optional alert delivery to user's Telegram |
| AI providers (OpenAI, Anthropic, Google, etc.) | Email body text (when user clicks Analyze) | Phishing probability analysis |

**No personal data** (name, email address, browsing history, credentials) is included in any of these requests. Only the domain name or IP address of the site being visited is sent to VirusTotal, AbuseIPDB, networkcalc and ipinfo.io.

---

## 4. Email Content

The Extension injects a content script into the following webmail domains only:

- `mail.google.com`
- `outlook.live.com`, `outlook.office.com`, `outlook.office365.com`
- `mail.yahoo.com`
- `mail.proton.me`, `protonmail.com`

**Automatic URL scanning:** Links (URLs) extracted from email bodies are sent to VirusTotal and AbuseIPDB for threat checking. Only the domain/IP portion of each URL is transmitted — no email text, subject, sender, or recipient data.

**AI analysis:** The full email body text is sent to your configured AI provider **only when you explicitly click the "Analyze" button**. This action is never automatic. The developer has no access to this data.

---

## 5. API Keys

API keys you enter (VirusTotal, AbuseIPDB, Telegram, AI provider) are:
- Stored in `chrome.storage.sync` — encrypted by Chrome, synced via your Google account
- Transmitted only as authorization headers to their respective services
- Never transmitted to the developer or any server controlled by the developer

---

## 6. Children's Privacy

The Extension is not directed at children under the age of 13 and does not knowingly collect any information from children.

---

## 7. Changes to This Policy

If this Privacy Policy changes, the updated version will be published at this URL with a new "Last updated" date.

---

## 8. Contact

For questions about this Privacy Policy, open an issue on the [GitHub repository](https://github.com/your-username/ElHunter).
