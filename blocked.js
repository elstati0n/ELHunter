'use strict';

(function () {
  const p = new URLSearchParams(location.search);

  const origUrl     = p.get('url')         || '';
  const verdict     = String(p.get('verdict') || '').toLowerCase();
  const category    = p.get('category')    || '';
  const blockReason = p.get('blockReason') || '';

  let country = p.get('country') || '';
  let isp     = p.get('isp')     || '';
  let ip      = p.get('ip')      || '';
  let cf      = p.get('cf')      || '';

  document.getElementById('rUrl').textContent = origUrl || '(unknown)';

  if (blockReason) {
    const badge = document.createElement('div');
    badge.style.cssText = 'background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.3);color:#ef4444;font-size:11px;border-radius:6px;padding:5px 12px;text-align:center;margin-bottom:4px;font-weight:600;letter-spacing:.03em';
    badge.textContent = '\uD83D\uDEAB ' + blockReason;
    document.querySelector('.tcard')?.prepend(badge);
  }

  const verdictLabel = document.querySelector('#rDetections')?.closest('.trow')?.querySelector('.trow-label');
  if (verdictLabel) verdictLabel.textContent = 'ZeroScan - Verdict';

  const rDetections = document.getElementById('rDetections');
  if (verdict === 'malicious' || verdict === 'suspicious' || verdict === 'clean') {
    rDetections.textContent = verdict.toUpperCase();
    rDetections.classList.add(verdict === 'clean' ? 'ok' : 'bad');
  } else {
    rDetections.textContent = 'UNKNOWN';
    rDetections.classList.add('na');
  }

  const rCategory = document.getElementById('rCategory');
  if (category) {
    rCategory.textContent = category;
    rCategory.classList.add('bad');
  } else {
    rCategory.textContent = 'N/A';
    rCategory.classList.add('na');
  }

  function applyEnrichment() {
    const rCountry = document.getElementById('rCountry');
    rCountry.textContent = country || 'N/A';
    rCountry.className = 'trow-val' + (!country ? ' na' : '');

    const rIsp = document.getElementById('rIsp');
    rIsp.textContent = isp || 'N/A';
    rIsp.className = 'trow-val' + (!isp ? ' na' : '');

    const rIpRow = document.getElementById('rIpRow');
    const rIp    = document.getElementById('rIp');
    if (ip) { rIpRow.style.display = ''; rIp.textContent = ip; }
    else    { rIpRow.style.display = 'none'; }

    const rCfRow = document.getElementById('rCfRow');
    const rCf    = document.getElementById('rCf');
    if (cf === '1') {
      rCfRow.style.display = '';
      rCf.textContent = '\u2601 YES \u2014 Cloudflare';
      rCf.className = 'trow-val cf';
    } else if (cf === '0') {
      rCfRow.style.display = '';
      rCf.textContent = '\u1F5A5 NO \u2014 Direct IP';
      rCf.className = 'trow-val';
    } else {
      rCfRow.style.display = 'none';
    }
  }

  applyEnrichment();

  if (!country || !ip) {
    let host = '';
    try { host = new URL(origUrl).hostname; } catch {}
    if (host) {
      let attempts = 0;
      const tid = setInterval(() => {
        attempts++;
        chrome.runtime.sendMessage({ type: 'GET_CF', host }, (res) => {
          if (!res) return;
          if (res.country)    country = res.country;
          if (res.resolvedIP) ip      = res.resolvedIP;
          if (res.isp)        isp     = res.isp;
          if (res.cloudflare === true)  cf = '1';
          if (res.cloudflare === false) cf = '0';
          applyEnrichment();
          if (res.enriched || attempts >= 20) clearInterval(tid);
        });
      }, 600);
    }
  }

  document.getElementById('btnBack').addEventListener('click', function () {
    chrome.runtime.sendMessage({ type: 'GO_BACK' }, function () {
      if (chrome.runtime.lastError) window.location.href = 'chrome://newtab';
    });
  });

  document.getElementById('btnProceed').addEventListener('click', function () {
    if (!origUrl) return;
    chrome.tabs.getCurrent(function(tab) {
      chrome.runtime.sendMessage({ type: 'PROCEED_ANYWAY', url: origUrl, tabId: tab && tab.id });
    });
  });

})();
