'use strict';

(function () {
  const p = new URLSearchParams(location.search);

  const origUrl     = p.get('url')         || '';
  const vtM         = parseInt(p.get('vtM')    || '0', 10);
  const vtS         = parseInt(p.get('vtS')    || '0', 10);
  const abuseS      = parseInt(p.get('abuseS') || '0', 10);
  const vtTotal     = parseInt(p.get('vtTotal') || '0', 10);
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
    document.querySelector('.report-card')?.prepend(badge);
  }

  const rVt   = document.getElementById('rVt');
  const total = vtM + vtS;
  if (total > 0) {
    rVt.textContent = total + (vtTotal > 0 ? ' / ' + vtTotal : '') + ' vendors flagged';
    rVt.classList.add('bad');
  } else {
    rVt.textContent = 'Not flagged';
    rVt.classList.add('ok');
  }

  const rAbuse    = document.getElementById('rAbuse');
  const scoreFill = document.getElementById('scoreFill');
  if (abuseS > 0) {
    rAbuse.textContent = abuseS + '% confidence';
    rAbuse.classList.add('bad');
    const hue = Math.max(0, 120 - abuseS * 1.2);
    scoreFill.style.width      = Math.min(100, abuseS) + '%';
    scoreFill.style.background = 'hsl(' + hue + ',90%,55%)';
    scoreFill.style.boxShadow  = '0 0 6px hsl(' + hue + ',90%,55%)';
  } else {
    rAbuse.textContent = 'N/A (domain)';
    rAbuse.classList.add('na');
    document.getElementById('scoreWrap').style.justifyContent = 'flex-end';
    document.getElementById('scoreFill').parentElement.style.display = 'none';
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
    // Get our own tabId first, then send it with the message
    chrome.tabs.getCurrent(function(tab) {
      chrome.runtime.sendMessage({ type: 'PROCEED_ANYWAY', url: origUrl, tabId: tab && tab.id });
    });
  });

})();
