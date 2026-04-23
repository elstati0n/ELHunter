'use strict';

const CACHE_TTL = 14 * 24 * 60 * 60 * 1000;
const CACHE_PFX = 'eh_';
const URL_CACHE_PFX = 'ehurl_';
const SKIP      = new Set(['localhost','127.0.0.1','::1','0.0.0.0']);
const IN_FLIGHT      = new Map();
const LAST_URL       = new Map();
const ALLOWED_HOSTS  = new Map();   // host → expiry ms (Proceed Anyway = 1 hour)
const NOTIF_SENT     = new Map();
const PHASE2_RUNNING = new Set();

const ALLOW_TTL = 60 * 60 * 1000; // 1 hour
function isTemporarilyAllowed(host) {
  const exp = ALLOWED_HOSTS.get(host);
  if (!exp) return false;
  if (Date.now() > exp) { ALLOWED_HOSTS.delete(host); return false; }
  return true;
}

// Persistent host allowlist (user clicked "Unblock" from cache)
let UNBLOCKED_HOSTS = new Set();
async function saveUnblocked() {
  await chrome.storage.local.set({ eh_unblocked: [...UNBLOCKED_HOSTS] });
}
async function loadUnblocked() {
  try {
    const r = await chrome.storage.local.get('eh_unblocked');
    if (Array.isArray(r.eh_unblocked)) r.eh_unblocked.forEach(h => UNBLOCKED_HOSTS.add(h));
  } catch {}
}

function normalizeVerdict(verdict) {
  const v = String(verdict || '').trim().toLowerCase();
  return v === 'clean' || v === 'suspicious' || v === 'malicious' ? v : 'unknown';
}
function getEntryVerdict(entry) {
  const verdict = normalizeVerdict(entry?.zs?.verdict);
  if (verdict !== 'unknown') return verdict;
  if (entry?.level === 'blocked') return 'blocked';
  return normalizeVerdict(entry?.level);
}
function levelRank(level) {
  return level === 'blocked' ? 4
    : level === 'malicious' ? 3
    : level === 'suspicious' ? 2
    : level === 'clean' ? 1
    : 0;
}
function shouldScanExactUrl(url) {
  try {
    const u = new URL(url);
    return ['http:','https:'].includes(u.protocol) && ((u.pathname || '/') !== '/' || !!u.search);
  } catch {
    return false;
  }
}
function mergeThreatEntries(baseEntry, overrideEntry) {
  if (!baseEntry) return overrideEntry;
  if (!overrideEntry) return baseEntry;
  const useOverride =
    levelRank(overrideEntry.level) > levelRank(baseEntry.level) ||
    (levelRank(overrideEntry.level) === levelRank(baseEntry.level) &&
      !!overrideEntry.zs?.category &&
      !baseEntry.zs?.category);
  if (!useOverride) return baseEntry;
  return {
    ...baseEntry,
    ...overrideEntry,
    zs: overrideEntry.zs || baseEntry.zs || null,
    blockReason: overrideEntry.blockReason || baseEntry.blockReason || '',
    cloudflare: baseEntry.cloudflare ?? overrideEntry.cloudflare ?? null,
    resolvedIP: baseEntry.resolvedIP || overrideEntry.resolvedIP || '',
    country: baseEntry.country || overrideEntry.country || '',
    countryCode: baseEntry.countryCode || overrideEntry.countryCode || '',
    isp: baseEntry.isp || overrideEntry.isp || '',
    enriched: baseEntry.enriched || overrideEntry.enriched || false
  };
}

// ─── declarativeNetRequest helpers ────────────────────────────────────────────
function hostToRuleId(host) {
  let h = 5381;
  for (let i = 0; i < host.length; i++) h = (((h << 5) + h) + host.charCodeAt(i)) >>> 0;
  return (h % 900000) + 1000;
}
async function addDNRBlock(host, origUrl, entry) {
  try {
    const p = new URLSearchParams({
      url: origUrl || 'https://'+host,
      verdict:      getEntryVerdict(entry),
      category:     entry.zs?.category       || '',
      country:      entry.country            || entry.zs?.country_code || '',
      isp:          entry.isp                || entry.zs?.isp          || '',
      ip:           entry.resolvedIP         || '',
      cf:           entry.cloudflare===true?'1':entry.cloudflare===false?'0':'',
      blockReason:  'ZeroScan: malicious'
    });
    const rId = hostToRuleId(host);
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: [rId],
      addRules: [{
        id: rId, priority: 1,
        action: { type: 'redirect', redirect: { url: chrome.runtime.getURL('blocked.html')+'?'+p } },
        condition: { requestDomains: [host], resourceTypes: ['main_frame'] }
      }]
    });
  } catch(e) { console.warn('[EH DNR add]', host, e.message); }
}
async function removeDNRBlock(host) {
  try {
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [hostToRuleId(host)] });
  } catch(e) { console.warn('[EH DNR remove]', host, e.message); }
}

// ─── Restore DNR rules immediately when SW starts ─────────────────────────────
// Called at TOP LEVEL so it runs the instant the service worker loads —
// before any navigation events can fire. onInstalled/onStartup are too late.
async function restoreDNRRules() {
  try {
    const [allStorage] = await Promise.all([
      chrome.storage.local.get(null),
      loadUnblocked()   // also loads UNBLOCKED_HOSTS in same pass
    ]);
    const promises = [];
    for (const [k, v] of Object.entries(allStorage)) {
      if (!k.startsWith(CACHE_PFX)) continue;
      if (v.level !== 'malicious') continue;
      const host = k.slice(CACHE_PFX.length);
      if (UNBLOCKED_HOSTS.has(host)) continue;
      if (Date.now() - (v.ts || 0) > CACHE_TTL) continue;
      promises.push(addDNRBlock(host, 'https://' + host, v));
    }
    if (promises.length) await Promise.allSettled(promises);
    console.log('[EH] DNR restored:', promises.length, 'rules');
  } catch(e) { console.warn('[EH] restoreDNRRules:', e.message); }
}

// ← TOP-LEVEL CALL: runs immediately when service worker starts, not in any handler
restoreDNRRules();

// onInstalled/onStartup as secondary safety net (e.g. after browser restart)
chrome.runtime.onStartup.addListener(() => restoreDNRRules().catch(() => {}));
chrome.runtime.onInstalled.addListener(() => restoreDNRRules().catch(() => {}));

// ─── Settings ─────────────────────────────────────────────────
async function getSettings() {
  const s = await chrome.storage.sync.get(['notifMode','tgEnabled','countryRules']);
  return {
    notifMode:    s.notifMode || 'off',
    tgEnabled:    s.tgEnabled === true,   // must be strictly true
    countryRules: (s.countryRules||[]).map(r => ({
      mode:'suspicious_only', notify:true, block:false, telegram:false, ...r
    })),
  };
}

// ─── Notification decision ────────────────────────────────────
// Returns: 'block' | 'notify' | 'skip' | 'wait'
function notifDecision(level, cc, host, settings) {
  const rules = settings.countryRules;
  if (rules.length > 0) {
    // If domain already matches, no need to wait for geo
    const hasDomainMatch = rules.some(r => ruleMatchesByDomain(r, host));
    // If there are IP-based rules that could match and we don't have cc yet → wait
    const needsGeo = rules.some(r => r.ipBased !== false && !hasDomainMatch);
    if (!hasDomainMatch && needsGeo && !cc) return 'wait';

    const rule = findMatchingRule(cc, host, settings);
    if (!rule) return 'skip';
    if (rule.block) return 'block';
    if (!rule.notify) return 'skip';
    const mode = rule.mode || 'suspicious_only';
    if (mode === 'all_events') return 'notify';
    return (level === 'suspicious' || level === 'malicious') ? 'notify' : 'skip';
  }
  const mode = settings.notifMode;
  if (mode === 'off') return 'skip';
  if (mode === 'all_events') return 'notify';
  return (level === 'suspicious' || level === 'malicious') ? 'notify' : 'skip';
}

// ─── Telegram decision ────────────────────────────────────────
function tgDecision(cc, host, settings) {
  if (!settings.tgEnabled) return false;
  const rules = settings.countryRules;
  if (rules.length > 0) {
    const rule = findMatchingRule(cc, host, settings);
    if (!rule || !rule.notify || rule.block) return false;
    return rule.telegram === true;
  }
  return true;
}

// ─── Cloudflare detection ─────────────────────────────────────
// ─── CC → TLD map (exceptions only) ──────────────────────────
const _CC_TLD = { GB:'uk', UK:'uk' };
function ccToTld(cc) { return (_CC_TLD[cc] || cc).toLowerCase(); }

// ─── Rule matching helpers ────────────────────────────────────
function ruleMatchesByDomain(r, host) {
  if (!r.domainBased) return false;
  const tld = ccToTld(r.cc);
  return !!(host && (host === tld || host.endsWith('.' + tld)));
}
function ruleMatchesByIP(r, cc) {
  // ipBased defaults true if neither flag set (backward compat)
  const ip = (r.ipBased !== false) && !r.domainBased || r.ipBased === true;
  return ip && !!(cc && r.cc === cc);
}
function findMatchingRule(cc, host, settings) {
  const rules = settings.countryRules;
  if (!rules.length) return null;
  for (const r of rules) {
    if (ruleMatchesByDomain(r, host) || ruleMatchesByIP(r, cc)) return r;
  }
  return null;
}

const CF_V6 = ['2400:cb00:','2606:4700:','2803:f800:','2405:b500:','2405:8100:','2a06:98c0:','2c0f:f248:'];
const CF_CIDRS = [[0x67155000,20],[0x6715F400,22],[0x6716C800,22],[0x671F0400,22],[0x68100000,13],[0x68180000,14],[0x6CA2C000,18],[0x83004800,22],[0x8D654000,18],[0xA29E0000,15],[0xAC400000,13],[0xADF53000,20],[0xBC726000,20],[0xBE5DF000,20],[0xC5EAF000,22],[0xC6298000,17]];
function ipInt(ip){const p=ip.split('.').map(Number);if(p.length!==4||p.some(x=>isNaN(x)||x<0||x>255))return null;return((p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3])>>>0;}
function isCF(ip){if(!ip)return null;if(ip.includes(':'))return CF_V6.some(p=>ip.toLowerCase().startsWith(p));const n=ipInt(ip);if(n===null)return null;return CF_CIDRS.some(([b,bits])=>{const m=bits===32?0xFFFFFFFF:(~(0xFFFFFFFF>>>bits))>>>0;return(n&m)===(b&m);});}

// ─── Helpers ──────────────────────────────────────────────────
function shouldAnalyse(url){try{const{protocol,hostname}=new URL(url);if(!['http:','https:'].includes(protocol))return false;if(SKIP.has(hostname)||hostname.startsWith('chrome'))return false;return true;}catch{return false;}}
function getHost(url){try{return new URL(url).hostname;}catch{return null;}}
function isIP(h){return/^(\d{1,3}\.){3}\d{1,3}$/.test(h);}
async function fetchT(url,opts,ms){return fetch(url,{...opts,signal:AbortSignal.timeout(ms)});}

// ─── Cache ────────────────────────────────────────────────────
async function readCacheEntry(key){try{const r=await chrome.storage.local.get(key);const e=r[key];if(!e)return null;if(Date.now()-e.ts>CACHE_TTL){chrome.storage.local.remove(key);return null;}return e;}catch{return null;}}
async function writeCacheEntry(key,data){await chrome.storage.local.set({[key]:{...data,ts:Date.now()}});}
async function cacheGet(host){return readCacheEntry(CACHE_PFX+host);}
async function cacheSet(host,data){return writeCacheEntry(CACHE_PFX+host,data);}
async function urlCacheGet(url){return readCacheEntry(URL_CACHE_PFX+url);}
async function urlCacheSet(url,data){return writeCacheEntry(URL_CACHE_PFX+url,data);}

// ─── API calls ────────────────────────────────────────────────
async function checkZeroScan(target, key) {
  try {
    const r = await fetchT(
      'https://zeroscan.az/api/lookup?q=' + encodeURIComponent(target),
      { headers: { 'X-API-Key': key } },
      10000
    );
    if (!r.ok) return null;
    const j = await r.json();
    // Normalize to internal format
    return {
      verdict:      normalizeVerdict(j.verdict),
      is_malicious: j.is_malicious === true,
      category:     j.category     || '',
      detections:   j.detections   || 0,
      total_vendors:j.total_vendors|| 0,
      country_code: j.country_code || '',
      isp:          j.isp          || '',
      is_tor:       j.is_tor       === true,
    };
  } catch { return null; }
}
const CC_NAMES={"AF":"Afghanistan","AL":"Albania","DZ":"Algeria","AR":"Argentina","AM":"Armenia","AU":"Australia","AT":"Austria","AZ":"Azerbaijan","BH":"Bahrain","BD":"Bangladesh","BY":"Belarus","BE":"Belgium","BO":"Bolivia","BA":"Bosnia","BR":"Brazil","BG":"Bulgaria","KH":"Cambodia","CA":"Canada","CL":"Chile","CN":"China","CO":"Colombia","HR":"Croatia","CU":"Cuba","CY":"Cyprus","CZ":"Czech Republic","DK":"Denmark","EG":"Egypt","EE":"Estonia","FI":"Finland","FR":"France","GE":"Georgia","DE":"Germany","GH":"Ghana","GR":"Greece","HU":"Hungary","IN":"India","ID":"Indonesia","IR":"Iran","IQ":"Iraq","IE":"Ireland","IL":"Israel","IT":"Italy","JP":"Japan","JO":"Jordan","KZ":"Kazakhstan","KE":"Kenya","KW":"Kuwait","LV":"Latvia","LB":"Lebanon","LY":"Libya","LT":"Lithuania","MY":"Malaysia","MX":"Mexico","MD":"Moldova","MA":"Morocco","MM":"Myanmar","NL":"Netherlands","NZ":"New Zealand","NG":"Nigeria","NO":"Norway","PK":"Pakistan","PE":"Peru","PH":"Philippines","PL":"Poland","PT":"Portugal","QA":"Qatar","RO":"Romania","RU":"Russia","SA":"Saudi Arabia","RS":"Serbia","SG":"Singapore","SK":"Slovakia","ZA":"South Africa","KR":"South Korea","ES":"Spain","SE":"Sweden","CH":"Switzerland","SY":"Syria","TW":"Taiwan","TH":"Thailand","TR":"Turkey","UA":"Ukraine","AE":"UAE","GB":"United Kingdom","US":"United States","UZ":"Uzbekistan","VN":"Vietnam"};
async function geoLookup(host){
  try{
    let ip = host;

    // Step 1: if domain, resolve to IP via networkcalc.com
    if(!isIP(host)){
      const dnsUrl = 'https://networkcalc.com/api/dns/lookup/'+encodeURIComponent(host);
      const dr = await fetchT(dnsUrl,{},8000);
      if(!dr.ok){ return null; }
      const dj = await dr.json();
      const aRecords = dj?.records?.A;
      if(!aRecords||!aRecords.length){ return null; }
      ip = aRecords[0].address;
    }

    // Step 2: geo lookup via ipinfo.io (HTTPS, free 50k/month, no key needed)
    const geoUrl = 'https://ipinfo.io/'+encodeURIComponent(ip)+'/json';
    const gr = await fetchT(geoUrl,{},8000);
    if(!gr.ok) return null;
    const gj = await gr.json();
    if(!gj.ip) return null;
    const isp = (gj.org||'').replace(/^AS\d+\s*/,'');
    return{
      ip:          gj.ip||ip,
      country:     CC_NAMES[gj.country]||gj.country||'',
      countryCode: gj.country||'',
      isp:         isp
    };
  }catch(e){ return null; }
}
// ZeroScan verdict: malicious → malicious, suspicious → suspicious, clean → clean
function classify(zs) {
  if (!zs) return 'clean';
  const verdict = normalizeVerdict(zs.verdict);
  if (zs.is_malicious || verdict === 'malicious') return 'malicious';
  if (verdict === 'suspicious') return 'suspicious';
  return 'clean';
}

// ─── Badge ────────────────────────────────────────────────────
async function setBadge(tabId,level){const map={malicious:{text:'!!!',color:'#e53935'},suspicious:{text:'!',color:'#f59e0b'}};const cfg=map[level]||{text:'',color:'#00000000'};try{await chrome.action.setBadgeText({text:cfg.text,tabId});await chrome.action.setBadgeBackgroundColor({color:cfg.color,tabId});}catch{}}

// ─── Chrome Notification ──────────────────────────────────────
function sendChromeNotif(id, title, message){chrome.notifications.create(id,{type:'basic',iconUrl:chrome.runtime.getURL('icons/icon128.png'),title,message,priority:0},()=>{if(chrome.runtime.lastError){}});}

// ─── Telegram ─────────────────────────────────────────────────
async function sendTelegramLegacy(host, entry) {
  try {
    const keys = await chrome.storage.sync.get(['tgBotToken','tgChatId','tgEnabled']);
    if (!keys.tgBotToken || !keys.tgChatId) {
      console.warn('[EH TG] missing token or chatId');
      return;
    }
    if (keys.tgEnabled !== true) {
      console.log('[EH TG] disabled');
      return;
    }
    const emo = {malicious:'🔴',suspicious:'🟡',clean:'🟢',unknown:'⚪'};
    const detections = entry.zs ? entry.zs.detections : null;
    const flag = entry.countryCode && entry.countryCode.length===2
      ? entry.countryCode.toUpperCase().split('').map(c=>String.fromCodePoint(0x1F1E6-65+c.charCodeAt(0))).join('')
      : '';
    const lines = [
      (emo[entry.level]||'⚪')+' <b>ElHunter — '+(entry.level||'unknown').toUpperCase()+'</b>',
      '🌐 <code>'+host+'</code>',
      detections!==null ? '🔬 ZeroScan: <b>'+detections+'/'+(entry.zs.total_vendors||0)+'</b> detections' : '🔬 ZeroScan: no key',
      entry.zs?.category ? '🏷 Category: <b>'+entry.zs.category+'</b>' : '',
      entry.country ? flag+' '+entry.country : '',
      entry.resolvedIP ? '🖥 <code>'+entry.resolvedIP+'</code>' : '',
      entry.cloudflare===true ? '☁️ Cloudflare' : entry.cloudflare===false ? '🖥 Direct IP' : '',
    ].filter(Boolean).join('\n');
    const url = 'https://api.telegram.org/bot'+keys.tgBotToken+'/sendMessage';
    const r = await fetchT(url, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({chat_id: String(keys.tgChatId), text:lines, parse_mode:'HTML'}),
    }, 8000);
    if (!r.ok) {
      const err = await r.text();
      console.warn('[EH TG] API error:', r.status, err);
    } else {
      console.log('[EH TG] sent OK for', host);
    }
  } catch(e){ console.warn('[EH TG] exception:', e.message); }
}

// ─── Fire notification (Chrome + Telegram) ────────────────────
function fireNotifLegacy(host, tabId, entry, settings) {
  if (NOTIF_SENT.has(host)) chrome.notifications.clear(NOTIF_SENT.get(host));
  const id = 'eh_'+Date.now()+'_'+Math.random().toString(36).slice(2);
  NOTIF_SENT.set(host, id);
  setBadge(tabId, entry.level==='malicious'?'malicious':'suspicious');

  const detections = entry.zs ? entry.zs.detections : null;
  const text = [
    '🌐 '+host,
    detections!==null ? '🔬 ZeroScan: '+detections+'/'+(entry.zs.total_vendors||0)+' detections' : '🔬 ZeroScan: No key',
    entry.zs?.category ? '🏷 '+entry.zs.category : '',
    entry.country ? '🌍 '+entry.country : '',
    entry.resolvedIP ? '🖥 '+entry.resolvedIP : '',
    entry.cloudflare===true ? '☁ Cloudflare' : entry.cloudflare===false ? '🖥 Direct IP' : '',
  ].filter(Boolean).join('\n');

  const labels={malicious:'✕ MALICIOUS',suspicious:'⚠ SUSPICIOUS',clean:'✓ CLEAN',unknown:'? UNKNOWN'};
  sendChromeNotif(id, labels[entry.level]||'ElHunter Alert', text);

  // Telegram (fire-and-forget)
  const cc = entry.countryCode || '';
  const doTg = settings ? tgDecision(cc, host || '', settings) : false;
  if (doTg) sendTelegram(host, entry);
}

function dismissNotif(host) {
  const id = NOTIF_SENT.get(host);
  if (id) { chrome.notifications.clear(id); NOTIF_SENT.delete(host); }
}

// ─── Block tab ────────────────────────────────────────────────
async function blockTab(tabId, origUrl, entry, blockReason) {
  const p = new URLSearchParams({
    url:          origUrl,
    verdict:      getEntryVerdict(entry),
    category:     entry.zs?.category       || '',
    country:      entry.country            || entry.zs?.country_code || '',
    isp:          entry.isp                || entry.zs?.isp          || '',
    ip:           entry.resolvedIP         || '',
    cf:           entry.cloudflare===true?'1':entry.cloudflare===false?'0':'',
    blockReason:  blockReason||''
  });
  try { await chrome.tabs.update(tabId, {url:chrome.runtime.getURL('blocked.html')+'?'+p}); } catch {}
}

// ─── Phase 2: geo enrichment + single notification decision ───
async function phase2(host, tabId, origUrl, threatOverride = null) {
  if (PHASE2_RUNNING.has(host)) return;
  PHASE2_RUNNING.add(host);
  try {
    let entry = await cacheGet(host);
    if (!entry) return;

    // Only do geo lookup if not already enriched
    if (!entry.enriched) {
      const geo       = await geoLookup(host);
      const resolvedIP  = geo?.ip || '';
      const cloudflare  = resolvedIP ? isCF(resolvedIP) : null;
      const country     = geo?.country || '';
      const countryCode = geo?.countryCode || '';
      const isp         = geo?.isp || '';

      // For IPs: also re-check resolved IP with ZeroScan if not yet checked
      if (resolvedIP && !isIP(host)) {
        const keys = await chrome.storage.sync.get(['zeroscanApiKey']);
        if (keys.zeroscanApiKey && !entry.zs) {
          const zr = await checkZeroScan(resolvedIP, keys.zeroscanApiKey);
          if (zr) {
            entry.zs    = zr;
            entry.level = classify(zr);
          }
        }
      }

      entry.cloudflare  = cloudflare;
      entry.resolvedIP  = resolvedIP;
      entry.country     = country || entry.country;
      entry.countryCode = countryCode || entry.countryCode;
      entry.isp         = isp || entry.isp;
      entry.enriched    = true;
      await cacheSet(host, entry);
      console.log('[EH P2]', host, '| CC:', entry.countryCode, '| IP:', resolvedIP, '| level:', entry.level);

      // ── If ZeroScan just upgraded level to malicious, block immediately ──
      if (entry.level === 'malicious' && !UNBLOCKED_HOSTS.has(host) && !isTemporarilyAllowed(host)) {
        // Find the tab still sitting on this host
        let blockTid = tabId;
        let blockUrl = origUrl;
        if (!blockTid) {
          for (const [id, u] of LAST_URL.entries()) {
            try { if (new URL(u).hostname === host) { blockTid = id; blockUrl = u; break; } } catch {}
          }
        }
        if (blockTid && blockUrl) {
          try {
            await chrome.tabs.get(blockTid);
            await blockTab(blockTid, blockUrl, entry, 'ZeroScan: malicious');
          } catch {}
        }
        // Add DNR for all future visits
        addDNRBlock(host, blockUrl || 'https://'+host, entry).catch(() => {});
        return; // skip notification logic below — we already blocked
      }
    }

    // Resolve tabId if not provided
    let tid = tabId;
    if (!tid) {
      for (const [id, url] of LAST_URL.entries()) {
        try { if (new URL(url).hostname === host) { tid = id; break; } } catch {}
      }
    }

    // ── SINGLE notification decision ──
    const settings = await getSettings();
    const decision  = notifDecision(entry.level, entry.countryCode, host, settings);
    console.log('[EH P2 decision]', decision, host, 'cc='+entry.countryCode, 'level='+entry.level);

    if (decision === 'block') {
      const matchedRule = findMatchingRule(entry.countryCode, host, settings);
      const isDomain    = matchedRule?.domainBased;
      entry.blockReason = isDomain
        ? 'domain:' + ccToTld(matchedRule.cc)
        : 'country:' + entry.countryCode;
      entry.level = 'blocked';
      await cacheSet(host, entry);
      const reason = isDomain
        ? 'Blocked: domain rule (.' + ccToTld(matchedRule.cc) + ')'
        : 'Blocked: country rule (' + (entry.country || entry.countryCode) + ')';
      if (tid && origUrl) {
        try { await chrome.tabs.get(tid); await blockTab(tid, origUrl, entry, reason); } catch {}
      }
      return;
    }
    if (decision === 'notify') {
      fireNotif(host, tid, entry, settings);
      return;
    }
    dismissNotif(host);

  } catch (e) {
    console.error('[EH P2 err]', host, e.message);
    try { const c = await cacheGet(host); if (c && !c.enriched) { c.enriched = true; await cacheSet(host, c); } } catch {}
  } finally {
    PHASE2_RUNNING.delete(host);
  }
}

// ─── Phase 1: ZeroScan only ────────────────────────────────────
async function phase1(host) {
  const cached = await cacheGet(host);
  if (cached) {
    if (cached.level === 'malicious' && !UNBLOCKED_HOSTS.has(host)) {
      addDNRBlock(host, 'https://' + host, cached).catch(() => {});
    }
    return cached;
  }
  const keys = await chrome.storage.sync.get(['zeroscanApiKey']);
  let zs = null;
  if (keys.zeroscanApiKey) {
    zs = await checkZeroScan(host, keys.zeroscanApiKey);
  }
  const level = classify(zs);
  const entry = { level, zs, cloudflare: null, resolvedIP: '', country: '', countryCode: '', isp: '', enriched: false };
  await cacheSet(host, entry);
  console.log('[EH P1]', host, 'level='+level);
  return entry;
}

// ─── Tab listener ─────────────────────────────────────────────
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'loading') return;
  const url = tab.url || changeInfo.url;
  if (!url || !shouldAnalyse(url)) return;
  const host = getHost(url);
  if (!host) return;
  if (isTemporarilyAllowed(host) || UNBLOCKED_HOSTS.has(host)) return;
  if (LAST_URL.get(tabId) === url && IN_FLIGHT.has(tabId)) return;
  const prevUrl = LAST_URL.get(tabId);
  if (prevUrl && prevUrl !== url) { try { dismissNotif(new URL(prevUrl).hostname); } catch {} }
  LAST_URL.set(tabId, url);
  NOTIF_SENT.delete(host); // Reset per navigation — allows one fresh notification
  IN_FLIGHT.delete(tabId);
  const promise = handleNavigation(tabId, url, host)
    .catch(e => console.warn('[EH nav]', host, e.message))
    .finally(() => IN_FLIGHT.delete(tabId));
  IN_FLIGHT.set(tabId, promise);
});

async function sendTelegram(host, entry) {
  try {
    const keys = await chrome.storage.sync.get(['tgBotToken','tgChatId','tgEnabled']);
    if (!keys.tgBotToken || !keys.tgChatId) {
      console.warn('[EH TG] missing token or chatId');
      return;
    }
    if (keys.tgEnabled !== true) {
      console.log('[EH TG] disabled');
      return;
    }
    const levelLabel = (entry.level || 'unknown').toUpperCase();
    const verdict = getEntryVerdict(entry).toUpperCase();
    const flag = entry.countryCode && entry.countryCode.length === 2
      ? entry.countryCode.toUpperCase().split('').map(c => String.fromCodePoint(0x1F1E6 - 65 + c.charCodeAt(0))).join('')
      : '';
    const lines = [
      'ElHunter - ' + levelLabel,
      'URL: ' + host,
      entry.zs ? 'ZeroScan: ' + verdict : 'ZeroScan: no key',
      entry.zs?.category ? 'Category: ' + entry.zs.category : '',
      entry.country ? (flag ? flag + ' ' : '') + entry.country : '',
      entry.resolvedIP ? 'IP: ' + entry.resolvedIP : '',
      entry.cloudflare === true ? 'Cloudflare' : entry.cloudflare === false ? 'Direct IP' : '',
    ].filter(Boolean).join('\n');
    const url = 'https://api.telegram.org/bot' + keys.tgBotToken + '/sendMessage';
    const r = await fetchT(url, {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({chat_id: String(keys.tgChatId), text:lines})
    }, 8000);
    if (!r.ok) {
      const err = await r.text();
      console.warn('[EH TG] API error:', r.status, err);
    } else {
      console.log('[EH TG] sent OK for', host);
    }
  } catch(e){ console.warn('[EH TG] exception:', e.message); }
}

function fireNotif(host, tabId, entry, settings) {
  if (NOTIF_SENT.has(host)) chrome.notifications.clear(NOTIF_SENT.get(host));
  const id = 'eh_' + Date.now() + '_' + Math.random().toString(36).slice(2);
  NOTIF_SENT.set(host, id);
  setBadge(tabId, entry.level === 'malicious' ? 'malicious' : 'suspicious');

  const verdict = getEntryVerdict(entry).toUpperCase();
  const text = [
    'URL: ' + host,
    entry.zs ? 'ZeroScan: ' + verdict : 'ZeroScan: No key',
    entry.zs?.category ? 'Category: ' + entry.zs.category : '',
    entry.country ? 'Country: ' + entry.country : '',
    entry.resolvedIP ? 'IP: ' + entry.resolvedIP : '',
    entry.cloudflare === true ? 'Cloudflare' : entry.cloudflare === false ? 'Direct IP' : '',
  ].filter(Boolean).join('\n');

  const labels = {malicious:'MALICIOUS',suspicious:'SUSPICIOUS',clean:'CLEAN',unknown:'UNKNOWN'};
  sendChromeNotif(id, labels[entry.level] || 'ElHunter Alert', text);

  const cc = entry.countryCode || '';
  const doTg = settings ? tgDecision(cc, host || '', settings) : false;
  if (doTg) sendTelegram(host, entry);
}

async function handleNavigation(tabId, url, host) {
  try { await chrome.tabs.get(tabId); } catch { return; }

  // Skip if user permanently unblocked or has an active 1-hour Proceed Anyway
  if (UNBLOCKED_HOSTS.has(host) || isTemporarilyAllowed(host)) return;

  const { hostEntry, urlEntry, entry } = await analyseTarget(host, url);

  // ── Real malicious (VT/Abuse confirmed) ──
  if (entry.level === 'malicious') {
    try { await chrome.tabs.get(tabId); } catch { return; }
    await blockTab(tabId, url, entry, 'ZeroScan: malicious');

    // ZeroScan confirmed malicious → add DNR for instant block on future visits
    if (hostEntry.level === 'malicious') addDNRBlock(host, url, hostEntry).catch(() => {});

    // Enrich in background for block page details
    phase2Site(host, null, null, urlEntry).catch(() => {});
    return;
  }

  // ── Cached 'blocked' entry (country/domain rule previously applied) ──
  if (hostEntry.level === 'blocked' && hostEntry.blockReason) {
    try { await chrome.tabs.get(tabId); } catch { return; }
    await blockTab(tabId, url, hostEntry, hostEntry.blockReason);
    return;
  }

  // ── All other decisions (notify / skip / block-by-country) → phase2 ──
  // phase2 fires ONE notification with complete geo data
  phase2Site(host, tabId, url, urlEntry).catch(() => {});
}

async function safeBlockTab(tabId, url, entry, reason) {
  try { await chrome.tabs.get(tabId); } catch { return; }
  await blockTab(tabId, url, entry, reason);
}

chrome.tabs.onRemoved.addListener(tabId => {
  LAST_URL.delete(tabId);
  chrome.action.setBadgeText({ text: '', tabId }).catch(() => {});
});

// ─── webNavigation: instant block for cached malicious entries ────────────────
// Fires BEFORE the browser starts loading — eliminates the "page flashes then redirects" problem
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return; // main frame only
  const url = details.url;
  if (!shouldAnalyse(url)) return;
  const host = getHost(url);
  if (!host) return;
  if (UNBLOCKED_HOSTS.has(host) || isTemporarilyAllowed(host)) return;

  const cached = await cacheGet(host);
  if (!cached) return; // not in cache — tabs.onUpdated will handle via API call

  if (cached.level === 'malicious') {
    try {
      await chrome.tabs.get(details.tabId);
      await blockTab(details.tabId, url, cached, 'ZeroScan: malicious');
    } catch {}
  } else if (cached.level === 'blocked' && cached.blockReason) {
    try {
      await chrome.tabs.get(details.tabId);
      await blockTab(details.tabId, url, cached, cached.blockReason);
    } catch {}
  }
});

async function phase1Url(url) {
  if (!shouldAnalyse(url) || !shouldScanExactUrl(url)) return null;
  const cached = await urlCacheGet(url);
  if (cached) return cached;
  const keys = await chrome.storage.sync.get(['zeroscanApiKey']);
  if (!keys.zeroscanApiKey) return null;
  const zs = await checkZeroScan(url, keys.zeroscanApiKey);
  if (!zs) return null;
  const entry = {
    level: classify(zs),
    zs,
    cloudflare: null,
    resolvedIP: '',
    country: '',
    countryCode: '',
    isp: '',
    enriched: false
  };
  await urlCacheSet(url, entry);
  console.log('[EH P1 URL]', url, 'level=' + entry.level);
  return entry;
}

async function analyseTarget(host, url) {
  let hostEntry = await cacheGet(host);
  if (!hostEntry) hostEntry = await phase1(host);
  const urlEntry = url ? await phase1Url(url) : null;
  return {
    hostEntry,
    urlEntry,
    entry: mergeThreatEntries(hostEntry, urlEntry) || hostEntry
  };
}

async function phase2Site(host, tabId, origUrl, threatOverride = null) {
  if (PHASE2_RUNNING.has(host)) return;
  PHASE2_RUNNING.add(host);
  try {
    let entry = await cacheGet(host);
    if (!entry) return;

    if (!entry.enriched) {
      const geo = await geoLookup(host);
      const resolvedIP = geo?.ip || '';
      const cloudflare = resolvedIP ? isCF(resolvedIP) : null;
      const country = geo?.country || '';
      const countryCode = geo?.countryCode || '';
      const isp = geo?.isp || '';

      if (resolvedIP && !isIP(host)) {
        const keys = await chrome.storage.sync.get(['zeroscanApiKey']);
        if (keys.zeroscanApiKey && !entry.zs) {
          const zr = await checkZeroScan(resolvedIP, keys.zeroscanApiKey);
          if (zr) {
            entry.zs = zr;
            entry.level = classify(zr);
          }
        }
      }

      entry.cloudflare = cloudflare;
      entry.resolvedIP = resolvedIP;
      entry.country = country || entry.country;
      entry.countryCode = countryCode || entry.countryCode;
      entry.isp = isp || entry.isp;
      entry.enriched = true;
      await cacheSet(host, entry);
      console.log('[EH P2]', host, '| CC:', entry.countryCode, '| IP:', resolvedIP, '| level:', entry.level);
    }

    const effectiveEntry = mergeThreatEntries(entry, threatOverride);
    if (effectiveEntry.level === 'malicious' && !UNBLOCKED_HOSTS.has(host) && !isTemporarilyAllowed(host)) {
      let blockTid = tabId;
      let blockUrl = origUrl;
      if (!blockTid) {
        for (const [id, currentUrl] of LAST_URL.entries()) {
          try { if (new URL(currentUrl).hostname === host) { blockTid = id; blockUrl = currentUrl; break; } } catch {}
        }
      }
      if (blockTid && blockUrl) {
        try {
          await chrome.tabs.get(blockTid);
          await blockTab(blockTid, blockUrl, effectiveEntry, 'ZeroScan: malicious');
        } catch {}
      }
      if (entry.level === 'malicious') {
        addDNRBlock(host, blockUrl || 'https://' + host, entry).catch(() => {});
      }
      return;
    }

    let tid = tabId;
    if (!tid) {
      for (const [id, currentUrl] of LAST_URL.entries()) {
        try { if (new URL(currentUrl).hostname === host) { tid = id; break; } } catch {}
      }
    }

    const settings = await getSettings();
    const decision = notifDecision(effectiveEntry.level, effectiveEntry.countryCode, host, settings);
    console.log('[EH P2 decision]', decision, host, 'cc=' + effectiveEntry.countryCode, 'level=' + effectiveEntry.level);

    if (decision === 'block') {
      const matchedRule = findMatchingRule(effectiveEntry.countryCode, host, settings);
      const isDomain = matchedRule?.domainBased;
      const blockedEntry = {
        ...entry,
        blockReason: isDomain
          ? 'domain:' + ccToTld(matchedRule.cc)
          : 'country:' + effectiveEntry.countryCode,
        level: 'blocked'
      };
      await cacheSet(host, blockedEntry);
      const displayEntry = mergeThreatEntries(blockedEntry, threatOverride);
      const reason = isDomain
        ? 'Blocked: domain rule (.' + ccToTld(matchedRule.cc) + ')'
        : 'Blocked: country rule (' + (effectiveEntry.country || effectiveEntry.countryCode) + ')';
      if (tid && origUrl) {
        try { await chrome.tabs.get(tid); await blockTab(tid, origUrl, displayEntry, reason); } catch {}
      }
      return;
    }
    if (decision === 'notify') {
      fireNotif(host, tid, effectiveEntry, settings);
      return;
    }
    dismissNotif(host);
  } catch (e) {
    console.error('[EH P2 err]', host, e.message);
    try {
      const c = await cacheGet(host);
      if (c && !c.enriched) {
        c.enriched = true;
        await cacheSet(host, c);
      }
    } catch {}
  } finally {
    PHASE2_RUNNING.delete(host);
  }
}
chrome.runtime.onMessage.addListener((msg, sender, respond) => {
  if (msg.type==='ANALYSE_HOST' || msg.type==='ANALYSE_SITE') {
    (async()=>{
      const host = msg.host || getHost(msg.url || '');
      if (!host) {
        respond({level:'unknown',zs:null,cloudflare:null,resolvedIP:'',country:'',countryCode:'',isp:'',enriched:false});
        return;
      }
      const { hostEntry, urlEntry, entry } = await analyseTarget(host, msg.url || '');
      respond(entry||{level:'unknown',zs:null,cloudflare:null,resolvedIP:'',country:'',countryCode:'',isp:'',enriched:false});
      if(hostEntry && !hostEntry.enriched) phase2Site(host,null,null,urlEntry).catch(()=>{});
    })();
    return true;
  }
  if (msg.type==='GET_CF') {
    cacheGet(msg.host).then(c=>{
      respond({cloudflare:c?.cloudflare??null,resolvedIP:c?.resolvedIP??'',country:c?.country??'',countryCode:c?.countryCode??'',isp:c?.isp??'',enriched:c?.enriched??false,abuse:c?.abuse??null,level:c?.level??'unknown'});
    });
    return true;
  }
  if (msg.type==='GO_BACK') {
    const t=sender.tab?.id;
    if(t) chrome.tabs.goBack(t).catch(()=>chrome.tabs.update(t,{url:'chrome://newtab'}).catch(()=>{}));
    respond({ok:true}); return true;
  }
  if (msg.type==='PROCEED_ANYWAY') {
    if (msg.url) {
      const h = getHost(msg.url);
      if (h) {
        ALLOWED_HOSTS.set(h, Date.now() + ALLOW_TTL);
        const tabId = msg.tabId || sender.tab?.id;
        (async () => {
          await removeDNRBlock(h);
          if (tabId) {
            try { await chrome.tabs.update(tabId, { url: msg.url }); } catch {}
          }
          setTimeout(() => {
            if (!isTemporarilyAllowed(h) && !UNBLOCKED_HOSTS.has(h)) {
              cacheGet(h).then(e => {
                if (e && e.level === 'malicious') addDNRBlock(h, msg.url, e).catch(() => {});
              }).catch(() => {});
            }
          }, ALLOW_TTL + 5000);
        })();
      }
    }
    respond({ok:true}); return true;
  }
  if (msg.type==='CLEAR_CACHE') {
    chrome.storage.local.get(null).then(all=>{
      const keys=Object.keys(all).filter(k=>k.startsWith(CACHE_PFX) || k.startsWith(URL_CACHE_PFX));
      chrome.storage.local.remove(keys).then(()=>respond({ok:true,count:keys.length}));
    });
    return true;
  }
  if (msg.type==='CLEAR_COUNTRY_CACHE') {
    chrome.storage.local.get(null).then(all=>{
      const tld = ccToTld(msg.cc);
      const toRemove=Object.entries(all).filter(([k,v])=>k.startsWith(CACHE_PFX)&&(
        v.blockReason==='country:'+msg.cc || v.blockReason==='domain:'+tld
      )).map(([k])=>k);
      if(!toRemove.length){respond({cleared:0});return;}
      chrome.storage.local.remove(toRemove,()=>respond({cleared:toRemove.length}));
    });
    return true;
  }
  if (msg.type==='GET_CACHE_STATS') {
    chrome.storage.local.get(null).then(all=>{
      const entries=Object.entries(all).filter(([k])=>k.startsWith(CACHE_PFX)).map(([k,v])=>({
        target:k.slice(CACHE_PFX.length),level:v.level||'unknown',country:v.country||'',countryCode:v.countryCode||'',
        cloudflare:v.cloudflare??null,resolvedIP:v.resolvedIP||'',isp:v.isp||'',
        verdict:getEntryVerdict(v),
        category:v.zs?.category||'',
        ts:v.ts||0,
      })).sort((a,b)=>b.ts-a.ts);
      respond({entries});
    });
    return true;
  }
  // Delete a single cache entry by target (domain or IP)
  if (msg.type==='DELETE_CACHE_ENTRY') {
    const key = CACHE_PFX + (msg.target || '');
    chrome.storage.local.remove(key, () => respond({ ok: true }));
    return true;
  }
  // Permanently unblock a host (added to persistent allowlist, removes DNR rule)
  if (msg.type==='UNBLOCK_HOST') {
    const host = msg.host || '';
    if (host) {
      UNBLOCKED_HOSTS.add(host);
      ALLOWED_HOSTS.set(host, Infinity); // permanent session allow
      saveUnblocked().catch(() => {});
      removeDNRBlock(host).catch(() => {});
    }
    respond({ ok: true });
    return true;
  }
  // Get unblocked host list (for popup display)
  if (msg.type==='GET_UNBLOCKED_HOSTS') {
    respond({ hosts: [...UNBLOCKED_HOSTS] });
    return true;
  }
  // Get temp-allowed hosts (Proceed Anyway, with expiry) for popup lock icon
  if (msg.type==='GET_TEMP_ALLOWED_HOSTS') {
    const now = Date.now();
    const hosts = [];
    for (const [h, exp] of ALLOWED_HOSTS.entries()) {
      if (exp === Infinity) continue; // permanent unblocks handled separately
      if (exp > now) hosts.push(h);
    }
    respond({ hosts });
    return true;
  }
  // Re-block a previously unblocked host
  if (msg.type==='REBLOCK_HOST') {
    const host = msg.host || '';
    if (host) {
      UNBLOCKED_HOSTS.delete(host);
      ALLOWED_HOSTS.delete(host);
      saveUnblocked().catch(() => {});
      // Re-add DNR rule so next visit is blocked instantly
      cacheGet(host).then(e => {
        if (e && e.level === 'malicious') addDNRBlock(host, 'https://'+host, e).catch(() => {});
      }).catch(() => {});
    }
    respond({ ok: true });
    return true;
  }
  if (msg.type==='CLEAR_STALE_CACHE') {
    chrome.storage.local.get(null, all => {
      const toRemove = Object.entries(all)
        .filter(([k, v]) => {
          if (!k.startsWith(CACHE_PFX)) return false;
          if (msg.keyType === 'zeroscan') return v.zs === null || v.zs === undefined;
          return false;
        })
        .map(([k]) => k);
      if (!toRemove.length) { respond({ cleared: 0 }); return; }
      chrome.storage.local.remove(toRemove, () => respond({ cleared: toRemove.length }));
    });
    return true;
  }
});

// ═══════════════════════════════════════════════════════════════
// PHISHING DETECTION — added block (existing code above untouched)
// ═══════════════════════════════════════════════════════════════

const EH_EMAIL_DOMAINS = new Set([
  'mail.google.com',
  'outlook.live.com', 'outlook.office.com', 'outlook.office365.com',
  'outlook.cloud.microsoft',
  'mail.yahoo.com',
  'mail.proton.me', 'protonmail.com'
]);

// ─── Inject phishing content script into email tabs ───────────
chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
  if (changeInfo.status !== 'complete') return;
  let hostname = '';
  try { hostname = new URL(tab.url || '').hostname; } catch { return; }
  if (!EH_EMAIL_DOMAINS.has(hostname)) return;

  chrome.storage.sync.get(['phishingRegex', 'phishingLLM'], function(s) {
    // Regex is ON by default; inject if either feature is active
    const regexOn = s.phishingRegex !== false;
    const llmOn   = s.phishingLLM === true;
    if (!regexOn && !llmOn) return;
    chrome.scripting.executeScript({
      target: { tabId: tabId },
      files:  ['phishing-content.js']
    }).catch(function() {});
  });
});

// ─── Phishing message handlers ────────────────────────────────
chrome.runtime.onMessage.addListener(function(msg, sender, respond) {

  // Return current phishing toggle state to content script
  if (msg.type === 'GET_PHISHING_SETTINGS') {
    chrome.storage.sync.get(['phishingRegex', 'phishingLLM', 'llmApiKey'], function(s) {
      respond({
        regexEnabled: s.phishingRegex !== false,        // default ON
        llmEnabled:   s.phishingLLM === true && !!s.llmApiKey, // BOTH required
        llmKey:       !!s.llmApiKey
      });
    });
    return true;
  }

  // Check a list of hosts extracted from email body
  if (msg.type === 'CHECK_EMAIL_URLS') {
    (async function() {
      const keys    = await chrome.storage.sync.get(['zeroscanApiKey']);
      const flagged = [];
      const hosts   = (msg.hosts || []).slice(0, 8); // cap at 8 per email to limit API cost
      const SAFE_HOST_RE = /^[a-zA-Z0-9._-]{1,253}$/;

      for (const host of hosts) {
        if (!SAFE_HOST_RE.test(host)) continue;
        if (SKIP.has(host)) continue;
        try {
          let cached = await cacheGet(host);
          if (!cached) {
            const zs = keys.zeroscanApiKey ? await checkZeroScan(host, keys.zeroscanApiKey) : null;
            cached = {
              level: classify(zs), zs,
              cloudflare: null, resolvedIP: '', country: '',
              countryCode: '', isp: '', enriched: false
            };
            await cacheSet(host, cached);
          }
          if (cached.level === 'suspicious' || cached.level === 'malicious') {
            flagged.push({
              host,
              verdict: getEntryVerdict(cached),
              category: cached.zs?.category || '',
              level: cached.level
            });
          }
        } catch (_) { /* skip broken hosts */ }
      }

      if (flagged.length > 0) {
        const details = flagged.map(function(f) {
          const parts = [];
          if (f.verdict)    parts.push('ZeroScan: ' + String(f.verdict).toUpperCase());
          if (f.category)   parts.push(f.category);
          return f.host + (parts.length ? ' (' + parts.join(', ') + ')' : '');
        }).join('\n');
        sendChromeNotif(
          'eh_phish_' + Date.now(),
          '⚠ Suspicious Links in Email',
          'Flagged URLs detected:\n' + details
        );
      }
      const allResults = hosts.map(function(host) {
        const f = flagged.find(function(x){ return x.host === host; });
        if (f) return { host, clean: false, verdict: f.verdict, category: f.category, level: f.level };
        return { host, clean: true, level: 'clean' };
      });
      respond({ flagged, all: allResults });
    })();
    return true;
  }

  // Send email content to LLM for phishing scoring (multi-provider)
  if (msg.type === 'CHECK_EMAIL_LLM') {
    (async function() {
      const cfg = await chrome.storage.sync.get(['llmApiKey','llmProvider','llmModel','llmCustomUrl']);
      if (!cfg.llmApiKey) {
        respond({ error: 'No AI API key. Go to API Keys tab and save a key.' });
        return;
      }

      const provider  = cfg.llmProvider  || 'openai';
      const customUrl = cfg.llmCustomUrl || '';

      // Default models per provider
      const DEFAULT_MODELS = {
        openai:     'gpt-4o-mini',
        anthropic:  'claude-haiku-4-5-20251001',
        gemini:     'gemini-2.0-flash',
        mistral:    'mistral-small-latest',
        groq:       'llama-3.1-8b-instant',
        openrouter: 'openai/gpt-4o-mini',
        ollama:     'llama3.2',
        lmstudio:   'local-model',
        custom:     'gpt-4o-mini'
      };
      const LOCAL_BASE_URLS = {
        ollama:   'http://localhost:11434',
        lmstudio: 'http://localhost:1234'
      };
      const model = (cfg.llmModel || '').trim() || DEFAULT_MODELS[provider] || 'gpt-4o-mini';
      const baseUrl = (cfg.llmCustomUrl || '').trim() || LOCAL_BASE_URLS[provider] || '';

      const SYSTEM_PROMPT = 'You are a JSON API. Output ONLY a JSON object. No prose, no markdown, no explanation. Just the JSON.';
      const USER_PROMPT   = 'Analyze this email for phishing risk. Respond with ONLY this JSON object, nothing before or after it:\n{"score":<integer 0-100>,"reason":"<max 80 chars>"}\nscore: 0=safe 100=phishing\n\nEmail:\n' +
                            (msg.content || '').slice(0, 2500);

      try {
        let url, headers, body;

        if (provider === 'anthropic') {
          // ── Anthropic Messages API ──────────────────────────
          url = 'https://api.anthropic.com/v1/messages';
          headers = {
            'Content-Type':      'application/json',
            'x-api-key':         cfg.llmApiKey,
            'anthropic-version': '2023-06-01'
          };
          body = JSON.stringify({
            model:      model,
            max_tokens: 150,
            system:     SYSTEM_PROMPT,
            messages: [{ role: 'user', content: USER_PROMPT }]
          });

        } else if (provider === 'gemini') {
          // ── Google Gemini generateContent ───────────────────
          url = 'https://generativelanguage.googleapis.com/v1beta/models/' + model + ':generateContent?key=' + cfg.llmApiKey;
          headers = { 'Content-Type': 'application/json' };
          body = JSON.stringify({
            systemInstruction: { parts: [{ text: SYSTEM_PROMPT }] },
            contents: [{ role: 'user', parts: [{ text: USER_PROMPT }] }],
            generationConfig: { maxOutputTokens: 300 }
          });

        } else if (provider === 'ollama') {
          // ── Ollama native API (/api/chat) ───────────────────
          url = baseUrl + '/api/chat';
          headers = { 'Content-Type': 'application/json' };
          body = JSON.stringify({
            model:  model,
            stream: false,
            format: 'json',   // forces JSON output regardless of model size
            messages: [
              { role: 'system', content: SYSTEM_PROMPT },
              { role: 'user',   content: USER_PROMPT }
            ]
          });

        } else {
          // ── OpenAI-compatible (OpenAI / Mistral / Groq / OpenRouter / LM Studio / Custom) ──
          const FIXED_ENDPOINTS = {
            openai:     'https://api.openai.com/v1/chat/completions',
            mistral:    'https://api.mistral.ai/v1/chat/completions',
            groq:       'https://api.groq.com/openai/v1/chat/completions',
            openrouter: 'https://openrouter.ai/api/v1/chat/completions'
          };
          if (FIXED_ENDPOINTS[provider]) {
            url = FIXED_ENDPOINTS[provider];
          } else {
            // lmstudio or custom — use baseUrl
            url = baseUrl.replace(/\/+$/, '') + '/v1/chat/completions';
          }
          headers = {
            'Content-Type':  'application/json',
            'Authorization': 'Bearer ' + (cfg.llmApiKey || 'local')
          };
          if (provider === 'openrouter') {
            headers['HTTP-Referer'] = 'chrome-extension://elhunter';
          }
          body = JSON.stringify({
            model:      model,
            max_tokens: 150,
            messages: [
              { role: 'system', content: SYSTEM_PROMPT },
              { role: 'user',   content: USER_PROMPT }
            ]
          });
        }

        if (!url) {
          respond({ error: 'Custom URL not configured. Go to API Keys tab and set a URL.' });
          return;
        }

        // Helper: single attempt
        async function doRequest() {
          return fetchT(url, { method: 'POST', headers, body }, 25000);
        }

        let r;
        try {
          r = await doRequest();
        } catch (connErr) {
          const isLocal = provider === 'ollama' || provider === 'lmstudio';
          respond({ error: isLocal
            ? provider + ' is not running. Start it and try again.'
            : 'Could not reach the API — check your network.' });
          return;
        }

        // Auto-retry once on 429 after 3 seconds
        if (r.status === 429) {
          await new Promise(function(res){ setTimeout(res, 3000); });
          try { r = await doRequest(); } catch(e) {
            respond({ error: 'Rate limit — retry also failed.' }); return;
          }
        }

        if (!r.ok) {
          let errBody = '';
          try { errBody = await r.text(); } catch {}
          let hint = 'API error ' + r.status;
          if (r.status === 401) hint = 'Invalid API key (401). Check your key in API Keys tab.';
          else if (r.status === 403) hint = 'Access denied (403). Check API key permissions.';
          else if (r.status === 404) hint = 'Model not found (404). Check the model name.';
          else if (r.status === 429) hint = 'Rate limit — please wait 30s and retry.';
          else {
            try {
              const ej = JSON.parse(errBody);
              const msg = ej?.error?.message || ej?.message || '';
              if (msg) hint = msg.length > 120 ? msg.slice(0,117)+'...' : msg;
            } catch {}
          }
          console.warn('[EH LLM] API error', r.status, errBody);
          respond({ error: hint });
          return;
        }

        const j = await r.json();
        let raw = '';

        if (provider === 'anthropic') {
          raw = (j?.content?.[0]?.text || '');
        } else if (provider === 'gemini') {
          // Gemini 1.x / 2.x: candidates[0].content.parts[0].text
          const cand = j?.candidates?.[0];
          raw = cand?.content?.parts?.[0]?.text
             || cand?.content?.parts?.map(function(p){ return p.text||''; }).join('')
             || '';
          // If responseMimeType=application/json was honored, raw IS the JSON already
        } else if (provider === 'ollama') {
          raw = (j?.message?.content || j?.choices?.[0]?.message?.content || '');
        } else {
          raw = (j?.choices?.[0]?.message?.content || '');
        }

        // raw response logged only in dev builds

        // Strip markdown fences and whitespace
        raw = raw.replace(/```json\s*/gi, '').replace(/```/g, '').trim();

        // Strategy 1: parse whole raw as JSON
        let parsed = null;
        try { parsed = JSON.parse(raw); } catch(_) {}

        // Strategy 2: find the outermost {...} block (greedy)
        if (!parsed) {
          const m = raw.match(/\{[\s\S]+\}/);
          if (m) { try { parsed = JSON.parse(m[0]); } catch(_) {} }
        }

        // Strategy 3: field-by-field regex extraction
        if (!parsed) {
          const sm = raw.match(/"score"\s*:\s*(\d{1,3})/);
          const rm = raw.match(/"reason"\s*:\s*"((?:[^"\\]|\\.)*)"/);
          if (sm) parsed = { score: parseInt(sm[1]), reason: rm ? rm[1] : '' };
        }

        if (!parsed) {
          console.warn('[EH LLM] all parse strategies failed. raw:', raw.slice(0, 400));
          respond({ error: 'AI returned unexpected format. Raw: ' + raw.slice(0, 80) });
          return;
        }

        respond({
          score:  Math.min(100, Math.max(0, parseInt(parsed.score) || 0)),
          reason: (parsed.reason || '').slice(0, 140)
        });

      } catch (e) {
        console.warn('[EH LLM] exception:', e.message);
        respond({ error: e.message || 'Unknown error' });
      }
    })();
    return true;
  }
});
