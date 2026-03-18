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
  'mail.yahoo.com',
  'mail.proton.me', 'protonmail.com'
]);

// Only run on actual email pages
if (!EH_EMAIL_DOMAINS.has(location.hostname)) {
  window.__EH_PHISH__ = false; // allow re-injection if navigated
  throw new Error('[EH] not an email page');
}

// ─── Find the open email body in the DOM ──────────────────────
function getEmailBody() {
  // Gmail — reading pane body
  let el = document.querySelector('.a3s.aiL') || document.querySelector('.ii.gt .a3s');
  if (el && (el.innerText || '').trim().length > 30) return el;
  // Outlook Web — message body
  el = document.querySelector('[data-testid="message-body"]') ||
       document.querySelector('[aria-label="Message body"]') ||
       document.querySelector('.ReadingPaneContent [role="document"]');
  if (el && (el.innerText || '').trim().length > 30) return el;
  // Yahoo Mail
  el = document.querySelector('[data-test-id="message-body"]') || document.querySelector('.msg-body');
  if (el && (el.innerText || '').trim().length > 30) return el;
  // ProtonMail
  el = document.querySelector('.message-content') || document.querySelector('[data-testid="message-content"]');
  if (el && (el.innerText || '').trim().length > 30) return el;
  return null;
}

// ─── Extract URLs from plain text ─────────────────────────────
const URL_RE = /https?:\/\/[^\s<>"'()\[\]{}\\]+/gi;
function extractUrls(text) {
  const raw = text.match(URL_RE) || [];
  return [...new Set(raw.map(function(u) { return u.replace(/[.,;:!?)\]]+$/, ''); }))];
}
function extractUrlsFromDOM(emailBody) {
  // Collect hrefs from all <a> and <button> elements inside email body
  const hrefs = [];
  try {
    emailBody.querySelectorAll('a[href], area[href]').forEach(function(el) {
      const href = el.getAttribute('href');
      if (href && /^https?:\/\//i.test(href)) hrefs.push(href.replace(/[.,;:!?)\]]+$/, ''));
    });
  } catch(e) {}
  return hrefs;
}
function getHost(url) { try { return new URL(url).hostname; } catch { return null; } }

// ─── LLM bar helpers ──────────────────────────────────────────
function removeLLMBar() {
  var b = document.getElementById('eh-llm-bar');
  if (b) b.remove();
}

var BAR_STYLE = 'position:fixed;top:0;left:0;right:0;z-index:2147483647;' +
  'background:linear-gradient(90deg,#0a0f1a,#0f1a2e);' +
  'border-bottom:1px solid rgba(59,158,255,.3);padding:9px 16px;' +
  'display:flex;align-items:center;gap:10px;' +
  'font-family:system-ui,-apple-system,sans-serif;font-size:12px;' +
  'color:#d8e8f8;box-shadow:0 2px 20px rgba(0,0,0,.6);box-sizing:border-box;';

var BTN_STYLE = 'border:none;border-radius:6px;padding:5px 12px;cursor:pointer;' +
  'font-size:11px;font-weight:600;font-family:inherit;';

function showLLMResult(bar, score, reason, isError) {
  var color, label, bgGrad;
  if (isError) {
    color   = '#f5a623';
    label   = '⚠ AI ERROR';
    bgGrad  = 'linear-gradient(90deg,#1a1200,#251800)';
  } else {
    color   = score >= 50 ? '#ff4466' : score >= 20 ? '#f5a623' : '#0dcc88';
    label   = score >= 50 ? '🚨 HIGH RISK' : score >= 20 ? '⚠ SUSPICIOUS' : '✓ LIKELY SAFE';
    bgGrad  = score >= 50 ? 'linear-gradient(90deg,#1a0010,#250020)'
            : score >= 20 ? 'linear-gradient(90deg,#1a1000,#251500)'
            :               'linear-gradient(90deg,#001a0f,#001a15)';
  }
  bar.style.background = bgGrad;
  bar.innerHTML =
    '<span style="font-size:15px">🤖</span>' +
    '<span style="flex:1">' +
      '<strong style="color:' + color + '">' + ehEscape(label) + (isError ? '' : ' — ' + score + '% phishing probability') + '</strong>' +
      (reason ? '<span style="color:' + (isError ? '#f5a623' : '#7a94b0') + ';font-size:10px;margin-left:10px">' + ehEscape(reason) + '</span>' : '') +
    '</span>' +
    (isError
      ? '<button id="eh-llm-retry" style="' + BTN_STYLE + 'background:rgba(245,166,35,.15);color:#f5a623;border:1px solid rgba(245,166,35,.3);margin-right:6px">Retry</button>'
      : '') +
    '<button id="eh-llm-close" style="' + BTN_STYLE + 'background:transparent;color:#7a94b0;border:1px solid rgba(255,255,255,.12);">✕</button>';
  document.getElementById('eh-llm-close').addEventListener('click', removeLLMBar);
  if (isError) {
    var retryBtn = document.getElementById('eh-llm-retry');
    if (retryBtn) {
      retryBtn.addEventListener('click', function() {
        // Re-show the offer bar so user can click Analyze again
        var emailBody = getEmailBody();
        if (emailBody) injectLLMBar(emailBody);
      });
    }
  }
}

function showNoKeysBar() {
  var old = document.getElementById('eh-regex-bar');
  if (old) old.remove();

  var bar = document.createElement('div');
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
  document.getElementById('eh-regex-close').addEventListener('click', function() { bar.remove(); });
}

function showRegexResult(allHosts, flagged) {
  var old = document.getElementById('eh-regex-bar');
  if (old) old.remove();

  var bar = document.createElement('div');
  bar.id = 'eh-regex-bar';

  var isSafe    = flagged.length === 0;
  var bgGrad    = isSafe ? 'linear-gradient(90deg,#001a0f,#001a15)' : 'linear-gradient(90deg,#1a0010,#250020)';
  var borderClr = isSafe ? '#0dcc8833' : '#ff446633';

  // Header line
  var header = isSafe
    ? '<strong style="color:#0dcc88">🔗 ' + allHosts.length + ' link' + (allHosts.length>1?'s':'') + ' checked</strong>'
    : '<strong style="color:#ff4466">🚨 ' + flagged.length + ' suspicious, ' + (allHosts.length - flagged.length) + ' clean</strong>';

  // Per-link rows
  var rows = allHosts.map(function(h) {
    if (h.clean) {
      return '<span style="display:inline-flex;align-items:center;gap:4px;margin-right:10px;font-size:11px">'
           + '<span style="color:#0dcc88">✓</span>'
           + '<span style="font-family:monospace;color:#b8cce0">' + ehEscape(h.host) + '</span>'
           + '<span style="color:#0dcc88;font-size:10px">clean</span>'
           + '</span>';
    } else {
      var parts = [];
      if (h.vtBad)      parts.push('VT:' + h.vtBad + '/' + h.vtTotal);
      if (h.abuseScore) parts.push('Abuse:' + h.abuseScore + '%');
      return '<span style="display:inline-flex;align-items:center;gap:4px;margin-right:10px;font-size:11px">'
           + '<span style="color:#ff4466">✕</span>'
           + '<span style="font-family:monospace;color:#ff4466">' + ehEscape(h.host) + '</span>'
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
  document.getElementById('eh-regex-close').addEventListener('click', function() { bar.remove(); });

  if (isSafe) setTimeout(function() { if (bar.isConnected) bar.remove(); }, 7000);
}

function injectLLMBar(emailBody) {
  removeLLMBar();
  var bar = document.createElement('div');
  bar.id = 'eh-llm-bar';
  bar.setAttribute('style', BAR_STYLE);
  bar.innerHTML =
    '<span style="font-size:15px">🤖</span>' +
    '<span style="flex:1">ElHunter — Analyze this email for phishing with AI?</span>' +
    '<button id="eh-llm-yes" style="' + BTN_STYLE + 'background:linear-gradient(135deg,#1155cc,#1a88cc);color:#fff;">Analyze</button>' +
    '<button id="eh-llm-no"  style="' + BTN_STYLE + 'background:transparent;color:#7a94b0;border:1px solid rgba(255,255,255,.12);">✕</button>';
  document.body.prepend(bar);

  document.getElementById('eh-llm-no').addEventListener('click', removeLLMBar);

  document.getElementById('eh-llm-yes').addEventListener('click', function() {
    var content = (emailBody.innerText || emailBody.textContent || '').slice(0, 4000);
    var yBtn = document.getElementById('eh-llm-yes');
    if (!yBtn) return;
    yBtn.textContent = 'Analyzing…'; yBtn.disabled = true;

    chrome.runtime.sendMessage({ type: 'CHECK_EMAIL_LLM', content: content }, function(res) {
      if (chrome.runtime.lastError || !res) {
        showLLMResult(bar, 0, 'No response from extension. Try reloading.', true);
        return;
      }
      if (res.error) {
        showLLMResult(bar, 0, res.error, true);
        return;
      }
      showLLMResult(bar, res.score, res.reason, false);
    });
  });
}

// ─── Main: called whenever an email appears open ───────────────
var lastEmailText = '';

function onEmailOpened(emailBody) {
  var text = (emailBody.innerText || emailBody.textContent || '').trim();
  if (!text || text === lastEmailText) return;
  lastEmailText = text;
  removeLLMBar();

  chrome.runtime.sendMessage({ type: 'GET_PHISHING_SETTINGS' }, function(s) {
    if (!s || chrome.runtime.lastError) return;

    // ── Regex URL check (default ON) ──────────────────────────
    if (s.regexEnabled) {
      // Collect URLs from both plain text AND href attributes (catches button/link redirects)
      var textUrls  = extractUrls(text);
      var domUrls   = extractUrlsFromDOM(emailBody);
      var allUrls   = [...new Set([...textUrls, ...domUrls])];
      var hosts = allUrls.map(getHost).filter(function(h) {
        return h && h !== 'localhost' && h !== '127.0.0.1';
      });
      hosts = [...new Set(hosts)];
      if (hosts.length > 0) {
        chrome.runtime.sendMessage({ type: 'CHECK_EMAIL_URLS', hosts: hosts }, function(res) {
          if (!res) return;
          if (res.noKeys) {
            showNoKeysBar();
            return;
          }
          showRegexResult(res.all || hosts.map(function(h){ return {host:h,clean:true}; }), res.flagged || []);
        });
      }
    }

    // ── LLM bar (only if key set and toggle ON) ───────────────
    if (s.llmEnabled) {
      injectLLMBar(emailBody);
    }
  });
}

// ─── DOM observer — detect email opens AND closes ─────────────
var debounceTimer = null;
var observer = new MutationObserver(function() {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(function() {
    var body = getEmailBody();
    if (body) {
      onEmailOpened(body);
    } else {
      // Email closed / navigated away — remove all bars and reset
      removeLLMBar();
      var regexBar = document.getElementById('eh-regex-bar');
      if (regexBar) regexBar.remove();
      lastEmailText = ''; // reset so next email triggers fresh scan
    }
  }, 600);
});
observer.observe(document.body, { childList: true, subtree: true });

// Initial check (for pages already showing an email)
setTimeout(function() {
  var body = getEmailBody();
  if (body) onEmailOpened(body);
}, 1500);

} // end guard
