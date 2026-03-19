'use strict';

// ── Security helper: escape HTML before injecting into innerHTML ──
function ehEscape(str) {
  return String(str)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&#39;');
}

// Guard against double-injection (tab updated fires more than once)
if (!window.__EH_PHISH__) {
window.__EH_PHISH__ = true;

const EH_EMAIL_DOMAINS = new Set([
  'mail.google.com',
  'outlook.live.com', 'outlook.office.com', 'outlook.office365.com',
  'outlook.cloud.microsoft',
  'mail.yahoo.com',
  'mail.proton.me', 'protonmail.com'
]);

if (!EH_EMAIL_DOMAINS.has(location.hostname)) {
  window.__EH_PHISH__ = false;
  throw new Error('[EH] not an email page');
}

// ─── Detect which platform we are on ─────────────────────────
const EH_HOST = location.hostname;
const IS_GMAIL    = EH_HOST === 'mail.google.com';
const IS_OUTLOOK  = EH_HOST.includes('outlook.') || EH_HOST === 'outlook.cloud.microsoft';
const IS_YAHOO    = EH_HOST === 'mail.yahoo.com';
const IS_PROTON   = EH_HOST.includes('proton');

// ─── Find the open email body in the DOM ──────────────────────
function getEmailBody() {

  // ── Gmail ──────────────────────────────────────────────────
  if (IS_GMAIL) {
    const el =
      document.querySelector('.a3s.aiL') ||
      document.querySelector('.ii.gt .a3s') ||
      document.querySelector('[data-message-id] .a3s') ||
      document.querySelector('.gs .ii.gt div[dir]');
    if (el && (el.innerText || '').trim().length > 30) return el;
  }

  // ── Outlook Web ────────────────────────────────────────────
  if (IS_OUTLOOK) {
    // Try selectors from newest to oldest Outlook Web builds
    const candidates = [
      // New Outlook (2024+)
      '[data-automation-id="messageBody"]',
      '[data-automation-id="messageBodyContent"]',
      // Outlook via aria
      '[aria-label="Message body"]',
      // Role-based (most resilient)
      '.allowTextSelection',
      '[role="document"].allowTextSelection',
      // Reading pane variants
      '.ReadingPaneContent [role="document"]',
      '[class*="readingPane"] [role="document"]',
      '[class*="ReadingPane"] [role="document"]',
      // Testid (older builds)
      '[data-testid="message-body"]',
      // Very generic fallback within reading area
      '[role="document"]',
    ];
    for (const sel of candidates) {
      try {
        const el = document.querySelector(sel);
        if (el && (el.innerText || '').trim().length > 30) return el;
      } catch(e) {}
    }
    // Last resort: find biggest role=document
    const docs = document.querySelectorAll('[role="document"]');
    let best = null, bestLen = 30;
    docs.forEach(el => {
      const len = (el.innerText || '').trim().length;
      if (len > bestLen) { best = el; bestLen = len; }
    });
    if (best) return best;
  }

  // ── Yahoo Mail ─────────────────────────────────────────────
  if (IS_YAHOO) {
    const el =
      document.querySelector('[data-test-id="message-body"]') ||
      document.querySelector('[data-test-id="messageBody"]') ||
      document.querySelector('.msg-body') ||
      document.querySelector('[class*="message-body"]') ||
      document.querySelector('[class*="msg-body"]') ||
      document.querySelector('article[data-test-id]');
    if (el && (el.innerText || '').trim().length > 30) return el;
  }

  // ── ProtonMail ─────────────────────────────────────────────
  if (IS_PROTON) {
    // ProtonMail renders email in an iframe (proton-iframe) in some views
    // Try direct selectors first
    const el =
      document.querySelector('[data-testid="message-content"]') ||
      document.querySelector('[data-testid="message:body"]') ||
      document.querySelector('.message-content') ||
      document.querySelector('[class*="message-content"]') ||
      document.querySelector('[class*="MessageContent"]') ||
      document.querySelector('.proton-message-body');
    if (el && (el.innerText || '').trim().length > 30) return el;

    // Try reading from iframe (same-origin only)
    const frames = document.querySelectorAll('iframe');
    for (const frame of frames) {
      try {
        const fdoc = frame.contentDocument || frame.contentWindow?.document;
        if (!fdoc) continue;
        const fel = fdoc.querySelector('body') || fdoc.documentElement;
        if (fel && (fel.innerText || '').trim().length > 30) return fel;
      } catch(e) {} // cross-origin blocked
    }
  }

  return null;
}

// ─── Extract URLs from plain text ─────────────────────────────
const URL_RE = /https?:\/\/[^\s<>"'()\[\]{}\\]+/gi;
function extractUrls(text) {
  const raw = text.match(URL_RE) || [];
  return [...new Set(raw.map(u => u.replace(/[.,;:!?)\]]+$/, '')))];
}
function extractUrlsFromDOM(emailBody) {
  const hrefs = [];
  try {
    emailBody.querySelectorAll('a[href], area[href]').forEach(el => {
      const href = el.getAttribute('href');
      if (href && /^https?:\/\//i.test(href)) hrefs.push(href.replace(/[.,;:!?)\]]+$/, ''));
    });
  } catch(e) {}
  return hrefs;
}
function getHost(url) { try { return new URL(url).hostname; } catch { return null; } }

// ─── LLM bar helpers ──────────────────────────────────────────
function removeLLMBar() {
  const b = document.getElementById('eh-llm-bar');
  if (b) b.remove();
}

const BAR_STYLE = 'position:fixed;top:0;left:0;right:0;z-index:2147483647;' +
  'background:linear-gradient(90deg,#0a0f1a,#0f1a2e);' +
  'border-bottom:1px solid rgba(59,158,255,.3);padding:9px 16px;' +
  'display:flex;align-items:center;gap:10px;' +
  'font-family:system-ui,-apple-system,sans-serif;font-size:12px;' +
  'color:#d8e8f8;box-shadow:0 2px 20px rgba(0,0,0,.6);box-sizing:border-box;';

const BTN_STYLE = 'border:none;border-radius:6px;padding:5px 12px;cursor:pointer;' +
  'font-size:11px;font-weight:600;font-family:inherit;';

function showLLMResult(bar, score, reason, isError) {
  let color, label, bgGrad;
  if (isError) {
    color  = '#f5a623'; label = '⚠ AI ERROR';
    bgGrad = 'linear-gradient(90deg,#1a1200,#251800)';
  } else {
    color  = score >= 50 ? '#ff4466' : score >= 20 ? '#f5a623' : '#0dcc88';
    label  = score >= 50 ? '🚨 HIGH RISK' : score >= 20 ? '⚠ SUSPICIOUS' : '✓ LIKELY SAFE';
    bgGrad = score >= 50 ? 'linear-gradient(90deg,#1a0010,#250020)'
           : score >= 20 ? 'linear-gradient(90deg,#1a1000,#251500)'
           :               'linear-gradient(90deg,#001a0f,#001a15)';
  }
  bar.style.background = bgGrad;
  bar.innerHTML =
    '<span style="font-size:15px">🤖</span>' +
    '<span style="flex:1">' +
      '<strong style="color:' + color + '">' + ehEscape(label) +
      (isError ? '' : ' — ' + score + '% phishing probability') + '</strong>' +
      (reason ? '<span style="color:' + (isError ? '#f5a623' : '#7a94b0') +
        ';font-size:10px;margin-left:10px">' + ehEscape(reason) + '</span>' : '') +
    '</span>' +
    (isError
      ? '<button id="eh-llm-retry" style="' + BTN_STYLE + 'background:rgba(245,166,35,.15);color:#f5a623;border:1px solid rgba(245,166,35,.3);margin-right:6px">Retry</button>'
      : '') +
    '<button id="eh-llm-close" style="' + BTN_STYLE + 'background:transparent;color:#7a94b0;border:1px solid rgba(255,255,255,.12);">✕</button>';
  document.getElementById('eh-llm-close').addEventListener('click', removeLLMBar);
  if (isError) {
    const retryBtn = document.getElementById('eh-llm-retry');
    if (retryBtn) {
      retryBtn.addEventListener('click', () => {
        const emailBody = getEmailBody();
        if (emailBody) injectLLMBar(emailBody);
      });
    }
  }
}

function showNoKeysBar() {
  const old = document.getElementById('eh-regex-bar');
  if (old) old.remove();
  const bar = document.createElement('div');
  bar.id = 'eh-regex-bar';
  bar.setAttribute('style',
    'position:fixed;top:' + (document.getElementById('eh-llm-bar') ? '44px' : '0') + ';left:0;right:0;z-index:2147483646;' +
    'background:linear-gradient(90deg,#1a1200,#251800);border-bottom:1px solid rgba(245,166,35,.3);padding:7px 16px;' +
    'display:flex;align-items:center;gap:10px;' +
    'font-family:system-ui,-apple-system,sans-serif;font-size:12px;' +
    'color:#d8e8f8;box-shadow:0 2px 12px rgba(0,0,0,.5);box-sizing:border-box;');
  bar.innerHTML =
    '<span style="flex:1">' +
      '<strong style="color:#f5a623">⚠ API keys not configured</strong>' +
      '<span style="color:#7a94b0;font-size:10px;margin-left:10px">VirusTotal / AbuseIPDB keys missing — link scan unavailable. Add keys in ElHunter settings.</span>' +
    '</span>' +
    '<button id="eh-regex-close" style="border:none;border-radius:6px;padding:4px 10px;cursor:pointer;' +
    'font-size:11px;font-weight:600;background:transparent;color:#7a94b0;' +
    'border:1px solid rgba(255,255,255,.12);flex-shrink:0;">✕</button>';
  document.body.prepend(bar);
  document.getElementById('eh-regex-close').addEventListener('click', () => bar.remove());
}

function showRegexResult(allHosts, flagged) {
  const old = document.getElementById('eh-regex-bar');
  if (old) old.remove();
  const bar = document.createElement('div');
  bar.id = 'eh-regex-bar';

  const isSafe     = flagged.length === 0;
  // Determine worst level among flagged hosts
  const hasMalicious  = allHosts.some(h => h.level === 'malicious');
  const hasSuspicious = allHosts.some(h => h.level === 'suspicious');
  const worstLevel    = hasMalicious ? 'malicious' : hasSuspicious ? 'suspicious' : 'clean';

  const bgGrad    = isSafe        ? 'linear-gradient(90deg,#001a0f,#001a15)'
                  : hasMalicious  ? 'linear-gradient(90deg,#1a0010,#250020)'
                  :                 'linear-gradient(90deg,#1a1000,#251500)';  // orange for suspicious
  const borderClr = isSafe        ? '#0dcc8833'
                  : hasMalicious  ? '#ff446633'
                  :                 '#f5a62333';

  const headerColor = isSafe ? '#0dcc88' : hasMalicious ? '#ff4466' : '#f5a623';
  const headerIcon  = isSafe ? '🔗' : hasMalicious ? '🚨' : '⚠';
  const headerText  = isSafe
    ? headerIcon + ' ' + allHosts.length + ' link' + (allHosts.length > 1 ? 's' : '') + ' checked'
    : headerIcon + ' ' + flagged.length + ' ' + (hasMalicious ? 'malicious' : 'suspicious') + ', ' + (allHosts.length - flagged.length) + ' clean';
  const header = '<strong style="color:' + headerColor + '">' + headerText + '</strong>';

  const rows = allHosts.map(h => {
    if (h.clean) {
      return '<span style="display:inline-flex;align-items:center;gap:4px;margin-right:10px;font-size:11px">'
           + '<span style="color:#0dcc88">✓</span>'
           + '<span style="font-family:monospace;color:#b8cce0">' + ehEscape(h.host) + '</span>'
           + '<span style="color:#0dcc88;font-size:10px">clean</span>'
           + '</span>';
    } else {
      const isMal = h.level === 'malicious';
      const rowColor = isMal ? '#ff4466' : '#f5a623';
      const rowIcon  = isMal ? '✕' : '⚠';
      const parts = [];
      if (h.vtBad)      parts.push('VT:' + h.vtBad + '/' + h.vtTotal);
      if (h.abuseScore) parts.push('Abuse:' + h.abuseScore + '%');
      return '<span style="display:inline-flex;align-items:center;gap:4px;margin-right:10px;font-size:11px">'
           + '<span style="color:' + rowColor + '">' + rowIcon + '</span>'
           + '<span style="font-family:monospace;color:' + rowColor + '">' + ehEscape(h.host) + '</span>'
           + (parts.length ? '<span style="color:#7a94b0;font-size:10px">(' + parts.join(' ') + ')</span>' : '')
           + '</span>';
    }
  }).join('');

  bar.setAttribute('style',
    'position:fixed;top:' + (document.getElementById('eh-llm-bar') ? '44px' : '0') + ';left:0;right:0;z-index:2147483646;' +
    'background:' + bgGrad + ';border-bottom:1px solid ' + borderClr + ';padding:7px 16px;' +
    'display:flex;align-items:flex-start;gap:10px;' +
    'font-family:system-ui,-apple-system,sans-serif;font-size:12px;' +
    'color:#d8e8f8;box-shadow:0 2px 12px rgba(0,0,0,.5);box-sizing:border-box;');
  bar.innerHTML =
    '<span style="flex:1;line-height:1.8">'
    + header
    + '<div style="margin-top:4px;flex-wrap:wrap;display:flex">' + rows + '</div>'
    + '</span>'
    + '<button id="eh-regex-close" style="border:none;border-radius:6px;padding:4px 10px;cursor:pointer;'
    + 'font-size:11px;font-weight:600;background:transparent;color:#7a94b0;'
    + 'border:1px solid rgba(255,255,255,.12);flex-shrink:0;align-self:flex-start;">✕</button>';

  document.body.prepend(bar);
  document.getElementById('eh-regex-close').addEventListener('click', () => bar.remove());
  if (isSafe) setTimeout(() => { if (bar.isConnected) bar.remove(); }, 7000);
}

function injectLLMBar(emailBody) {
  removeLLMBar();
  const bar = document.createElement('div');
  bar.id = 'eh-llm-bar';
  bar.setAttribute('style', BAR_STYLE);
  bar.innerHTML =
    '<span style="font-size:15px">🤖</span>' +
    '<span style="flex:1">ElHunter — Analyze this email for phishing with AI?</span>' +
    '<button id="eh-llm-yes" style="' + BTN_STYLE + 'background:linear-gradient(135deg,#1155cc,#1a88cc);color:#fff;">Analyze</button>' +
    '<button id="eh-llm-no"  style="' + BTN_STYLE + 'background:transparent;color:#7a94b0;border:1px solid rgba(255,255,255,.12);">✕</button>';
  document.body.prepend(bar);

  document.getElementById('eh-llm-no').addEventListener('click', removeLLMBar);
  document.getElementById('eh-llm-yes').addEventListener('click', () => {
    const content = (emailBody.innerText || emailBody.textContent || '').slice(0, 4000);
    const yBtn = document.getElementById('eh-llm-yes');
    if (!yBtn) return;
    yBtn.textContent = 'Analyzing…'; yBtn.disabled = true;

    chrome.runtime.sendMessage({ type: 'CHECK_EMAIL_LLM', content }, res => {
      if (chrome.runtime.lastError || !res) {
        showLLMResult(bar, 0, 'No response from extension. Try reloading.', true);
        return;
      }
      if (res.error) { showLLMResult(bar, 0, res.error, true); return; }
      showLLMResult(bar, res.score, res.reason, false);
    });
  });
}

// ─── Main: called whenever an email appears open ───────────────
let lastEmailText = '';

function onEmailOpened(emailBody) {
  const text = (emailBody.innerText || emailBody.textContent || '').trim();
  if (!text || text === lastEmailText) return;
  lastEmailText = text;
  removeLLMBar();

  chrome.runtime.sendMessage({ type: 'GET_PHISHING_SETTINGS' }, s => {
    if (!s || chrome.runtime.lastError) return;

    if (s.regexEnabled) {
      const textUrls = extractUrls(text);
      const domUrls  = extractUrlsFromDOM(emailBody);
      const allUrls  = [...new Set([...textUrls, ...domUrls])];
      let hosts = allUrls.map(getHost).filter(h => h && h !== 'localhost' && h !== '127.0.0.1');
      hosts = [...new Set(hosts)];
      if (hosts.length > 0) {
        chrome.runtime.sendMessage({ type: 'CHECK_EMAIL_URLS', hosts }, res => {
          if (!res) return;
          if (res.noKeys) { showNoKeysBar(); return; }
          showRegexResult(res.all || hosts.map(h => ({ host: h, clean: true })), res.flagged || []);
        });
      }
    }

    if (s.llmEnabled) {
      injectLLMBar(emailBody);
    }
  });
}

// ─── Retry helper: try getEmailBody() several times with delay ─
// Outlook and Yahoo are SPAs — email body might not render instantly
function tryGetEmailBody(attempts, interval, onFound) {
  let tries = 0;
  const poll = setInterval(() => {
    const body = getEmailBody();
    if (body) {
      clearInterval(poll);
      onFound(body);
      return;
    }
    if (++tries >= attempts) clearInterval(poll);
  }, interval);
}

// ─── DOM observer — detect email opens AND closes ─────────────
let debounceTimer = null;

// Outlook needs a longer debounce — it re-renders several times during navigation
const DEBOUNCE_MS = IS_OUTLOOK ? 900 : IS_YAHOO ? 800 : 600;

const observer = new MutationObserver(() => {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    const body = getEmailBody();
    if (body) {
      onEmailOpened(body);
    } else {
      // Email closed / navigated away — remove all bars and reset
      removeLLMBar();
      const regexBar = document.getElementById('eh-regex-bar');
      if (regexBar) regexBar.remove();
      lastEmailText = '';
    }
  }, DEBOUNCE_MS);
});

observer.observe(document.body, { childList: true, subtree: true });

// Initial check — Outlook/Yahoo may not be ready yet, retry up to 10 times / 500ms
setTimeout(() => {
  const body = getEmailBody();
  if (body) {
    onEmailOpened(body);
  } else if (IS_OUTLOOK || IS_YAHOO || IS_PROTON) {
    // Slower SPAs — poll for up to 5 seconds
    tryGetEmailBody(10, 500, onEmailOpened);
  }
}, IS_GMAIL ? 1200 : 1800);

} // end guard
