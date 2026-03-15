'use strict';

function toast(msg) {
  var el = document.getElementById('toast');
  el.textContent = msg; el.classList.add('show');
  clearTimeout(el._t);
  el._t = setTimeout(function(){ el.classList.remove('show'); }, 2400);
}

// ── Tabs + memory ─────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(function(btn) {
  btn.addEventListener('click', function() {
    document.querySelectorAll('.tab').forEach(function(t){ t.classList.remove('active'); });
    document.querySelectorAll('.panel').forEach(function(p){ p.classList.remove('active'); });
    this.classList.add('active');
    document.getElementById('tab-' + this.dataset.tab).classList.add('active');
    chrome.storage.local.set({ eh_last_tab: this.dataset.tab });
  });
});
chrome.storage.local.get('eh_last_tab', function(r) {
  var name = r.eh_last_tab;
  if (name && name !== 'main') {
    var btn = document.querySelector('.tab[data-tab="'+name+'"]');
    if (btn) btn.click();
  }
});

// ── Helpers ──────────────────────────────────────────────────
function maskKey(k) { return k ? k.slice(0,6) + '••••••••••••' + k.slice(-4) : ''; }
function flagEmoji(cc) {
  if (!cc || cc.length !== 2) return '';
  return cc.toUpperCase().split('').map(function(c){ return String.fromCodePoint(0x1F1E6 - 65 + c.charCodeAt(0)); }).join('');
}

// ── Dot ──────────────────────────────────────────────────────
function updateDot() {
  chrome.storage.sync.get(['vtApiKey','abuseApiKey'], function(s){
    document.getElementById('gDot').className = (s.vtApiKey || s.abuseApiKey) ? 'sdot' : 'sdot dead';
  });
}

// ── Site analysis ─────────────────────────────────────────────
var pollTimer = null;
function hideSite() {
  document.getElementById('siteWrap').style.display = 'none';
  document.getElementById('siteEmpty').style.display = 'block';
}
function showLoading(host) {
  document.getElementById('siteEmpty').style.display = 'none';
  document.getElementById('siteWrap').style.display = 'block';
  document.getElementById('siteHostLabel').textContent = host;
  document.getElementById('siteLoading').style.display = 'flex';
  document.getElementById('siteRows').style.display = 'none';
}
function renderCF(cloudflare, enriched) {
  var el = document.getElementById('siteCFBadge');
  if (cloudflare === true)       { el.className='bdg bdg-cf'; el.textContent='YES — Cloudflare'; }
  else if (cloudflare === false) { el.className='bdg bdg-ip'; el.textContent='NO — Direct IP'; }
  else if (enriched)             { el.className='bdg bdg-dim'; el.textContent='N/A'; }
  else { el.className='bdg bdg-dim'; el.innerHTML='<span class="spin" style="width:9px;height:9px;border-width:1.5px"></span>'; }
}
function renderCtry(cc, name, enriched) {
  var el = document.getElementById('siteCountry');
  if (cc || name) { el.textContent = (flagEmoji(cc)||'') + ' ' + (name||cc); el.className='srow-val'; }
  else if (enriched) { el.textContent='N/A'; el.className='srow-val v-dim'; }
  else { el.textContent='Checking...'; el.className='srow-val v-dim'; }
}
function applyEnrich(res) {
  renderCF(res.cloudflare, res.enriched);
  renderCtry(res.countryCode||'', res.country||'', res.enriched);
  if (res.abuse) {
    var sc=res.abuse.score||0, a=document.getElementById('siteAbuse');
    if(sc===0){a.textContent='0% — Clean';a.className='srow-val v-ok';}
    else if(sc<20){a.textContent=sc+'% confidence';a.className='srow-val v-warn';}
    else{a.textContent=sc+'% confidence';a.className='srow-val v-bad';}
  }
  if (res.resolvedIP) { document.getElementById('siteIP').textContent=res.resolvedIP; document.getElementById('siteIPRow').style.display='flex'; }
}
function renderSite(host, r) {
  document.getElementById('siteLoading').style.display = 'none';
  document.getElementById('siteRows').style.display = 'block';
  var lm={clean:['bdg bdg-clean','CLEAN'],suspicious:['bdg bdg-warn','SUSPICIOUS'],malicious:['bdg bdg-bad','MALICIOUS'],blocked:['bdg bdg-blocked','BLOCKED'],unknown:['bdg bdg-dim','UNKNOWN']};
  var lv=r.level||'unknown', l=lm[lv]||lm.unknown;
  document.getElementById('siteLevelBadge').className=l[0]; document.getElementById('siteLevelBadge').textContent=l[1];
  var vt=document.getElementById('siteVT');
  if(r.vt){var f=(r.vt.malicious||0)+(r.vt.suspicious||0),t=r.vt.total||0;if(f===0){vt.textContent='0/'+t+' — Clean';vt.className='srow-val v-ok';}else{vt.textContent=f+'/'+t+' flagged';vt.className=f>=3?'srow-val v-bad':'srow-val v-warn';}}
  else{vt.textContent='No key';vt.className='srow-val v-dim';}
  var ab=document.getElementById('siteAbuse');
  if(r.abuse){var sc=r.abuse.score||0;if(sc===0){ab.textContent='0% — Clean';ab.className='srow-val v-ok';}else if(sc<20){ab.textContent=sc+'% confidence';ab.className='srow-val v-warn';}else{ab.textContent=sc+'% confidence';ab.className='srow-val v-bad';}}
  else{ab.textContent='N/A (domain)';ab.className='srow-val v-dim';}
  applyEnrich(r);
  if (!r.enriched) startPoll(host);
}
function startPoll(host) {
  clearInterval(pollTimer); var n=0;
  pollTimer = setInterval(function(){
    n++;
    chrome.runtime.sendMessage({type:'GET_CF',host:host}, function(res){
      if(!res) return; applyEnrich(res);
      if(res.enriched || n>=25) clearInterval(pollTimer);
    });
  }, 600);
}
function loadCurrentSite() {
  clearInterval(pollTimer);
  chrome.tabs.query({active:true,currentWindow:true}, function(tabs){
    var tab=tabs&&tabs[0];
    if(!tab||!tab.url){hideSite();return;}
    var host;
    try{
      var u=new URL(tab.url);
      if(u.protocol==='chrome-extension:'&&u.pathname.includes('blocked.html')){
        var bu=u.searchParams.get('url'); if(bu) host=new URL(bu).hostname; else{hideSite();return;}
      } else host=u.hostname;
    }catch(e){hideSite();return;}
    if(!host||host.startsWith('chrome')||host==='localhost'||host==='127.0.0.1'){hideSite();return;}
    showLoading(host);
    chrome.runtime.sendMessage({type:'ANALYSE_HOST',host:host}, function(res){
      if(!res){hideSite();return;} renderSite(host,res);
    });
  });
}

// ── Generic key widget ───────────────────────────────────────
function initKey(cfg) {
  var inp=document.getElementById(cfg.inpId), saveBtn=document.getElementById(cfg.saveId),
      iRow=document.getElementById(cfg.inputRowId), sArea=document.getElementById(cfg.savedAreaId),
      prev=document.getElementById(cfg.previewId), editBtn=document.getElementById(cfg.editId),
      delBtn=document.getElementById(cfg.delId), tag=document.getElementById(cfg.tagId);
  function showSaved(k){iRow.style.display='none';sArea.style.display='flex';prev.textContent=maskKey(k);tag.textContent='ACTIVE';tag.className='key-status ks-on';if(cfg.onSaved)cfg.onSaved(k);updateDot();}
  function showEmpty(){iRow.style.display='flex';sArea.style.display='none';inp.value='';inp.type='password';tag.textContent='NOT SET';tag.className='key-status ks-off';updateDot();}
  saveBtn.addEventListener('click', function(){
    var v=inp.value.trim(); if(!v){toast('Enter a value');return;}
    saveBtn.disabled=true;saveBtn.textContent='...';
    chrome.storage.sync.set({[cfg.storageKey]:v}, function(){saveBtn.disabled=false;saveBtn.textContent='Save';toast(cfg.label+' saved');showSaved(v);if(cfg.onChange)cfg.onChange();});
  });
  editBtn.addEventListener('click', function(){
    chrome.storage.sync.get(cfg.storageKey, function(r){inp.value=r[cfg.storageKey]||'';inp.type='text';iRow.style.display='flex';sArea.style.display='none';tag.textContent='EDITING';tag.className='key-status';tag.style.cssText='background:rgba(245,166,35,.1);color:#f5a623;border:1px solid rgba(245,166,35,.25)';inp.focus();inp.select();});
  });
  delBtn.addEventListener('click', function(){
    chrome.storage.sync.remove(cfg.storageKey, function(){tag.removeAttribute('style');toast(cfg.label+' removed');showEmpty();if(cfg.onChange)cfg.onChange();});
  });
  inp.addEventListener('keydown', function(e){if(e.key==='Enter')saveBtn.click();});
  chrome.storage.sync.get(cfg.storageKey, function(r){if(r[cfg.storageKey])showSaved(r[cfg.storageKey]);else showEmpty();});
}

// Update telegram key status tag + auto-enable when both keys present
function updateTgTag() {
  chrome.storage.sync.get(['tgBotToken','tgChatId'], function(s){
    var tag = document.getElementById('tgTag');
    if (s.tgBotToken && s.tgChatId) {
      tag.textContent='ACTIVE'; tag.className='key-status ks-on';
      // Auto-enable telegram notifications when both keys are present
      chrome.storage.sync.get('tgEnabled', function(e) {
        if (e.tgEnabled !== true) {
          chrome.storage.sync.set({tgEnabled: true}, function() {
            // Update toggle visual
            var tog = document.getElementById('tgGlobalToggle');
            if (tog) { tog.textContent='✈ ON'; tog.className='tog t-notif-on'; }
            if (settings) settings.tgEnabled = true;
          });
        }
      });
    } else {
      tag.textContent='NOT SET'; tag.className='key-status ks-off';
    }
  });
}

// ── Cache ─────────────────────────────────────────────────────
var cacheEntries=[];
function loadCache(){
  chrome.runtime.sendMessage({type:'GET_CACHE_STATS'}, function(res){
    if(!res)return; cacheEntries=res.entries||[];
    var cl=0,su=0,ma=0,bl=0; cacheEntries.forEach(function(x){if(x.level==='clean')cl++;else if(x.level==='suspicious')su++;else if(x.level==='malicious')ma++;else if(x.level==='blocked')bl++;});
    document.getElementById('chipTotal').textContent=cacheEntries.length+' entries';
    document.getElementById('chipClean').textContent=cl+' clean';
    document.getElementById('chipSusp').textContent=su+' susp';
    document.getElementById('chipMal').textContent=ma+' mal';
    document.getElementById('chipBlocked').textContent=bl+' blocked';
  });
}
function openStats(filter){
  var list=filter==='all'?cacheEntries:cacheEntries.filter(function(x){return x.level===filter;});
  var labels={all:'All Entries',clean:'Clean',suspicious:'Suspicious',malicious:'Malicious',blocked:'Blocked'};
  var colors={all:'#94a3b8',clean:'#10b981',suspicious:'#f59e0b',malicious:'#ef4444',blocked:'#ff8c00'};
  var sf=document.getElementById('statsPanelFilter'); sf.textContent=labels[filter]||filter; sf.style.color=colors[filter]||'#94a3b8';
  var rows=document.getElementById('statsRows');
  if(!list.length){rows.innerHTML='<div style="padding:20px;text-align:center;color:#7a94b0;font-size:11px">No entries</div>';return;}
  rows.innerHTML=list.map(function(x){
    var lc=x.level==='clean'?'#10b981':x.level==='suspicious'?'#f59e0b':x.level==='malicious'?'#ef4444':x.level==='blocked'?'#ff8c00':'#64748b';
    var dot='<span style="display:inline-block;width:6px;height:6px;border-radius:50%;background:'+lc+';margin-right:5px"></span>';
    var dm=x.target.length>24?x.target.slice(0,22)+'...':x.target;
    var flag=flagEmoji(x.countryCode); var ctry=flag?(flag+' '+x.countryCode):(x.country||'-');
    var vtTxt=x.vtTotal>0?(x.vtFlagged+'/'+x.vtTotal):'-';
    var vtColor=x.vtFlagged>=3?'#ef4444':x.vtFlagged>0?'#f59e0b':'#10b981';
    var cfTxt=x.cloudflare===true?'C':x.cloudflare===false?'D':'-';
    var diff=x.ts?Math.round((Date.now()-x.ts)/60000):0; var ago=diff<60?diff+'m ago':Math.round(diff/60)+'h ago';
    return '<div class="ov-row"><div><div style="display:flex;align-items:center">'+dot+'<span style="font-family:monospace;font-size:10.5px;color:#e2e8f0">'+dm+'</span></div>'
      +(x.resolvedIP?'<div style="font-size:9px;color:#7a94b0;margin-top:2px">'+x.resolvedIP+'</div>':'')
      +'<div style="font-size:9px;color:#7a94b0;margin-top:1px">'+ago+'</div></div>'
      +'<div style="text-align:center;font-size:11px">'+ctry+'</div>'
      +'<div style="text-align:center;font-size:10.5px;font-weight:600;color:'+vtColor+'">'+vtTxt+'</div>'
      +'<div style="text-align:right;font-size:13px">'+cfTxt+'</div></div>';
  }).join('');
  document.getElementById('statsOverlay').classList.add('show');
}

// ── Rules ─────────────────────────────────────────────────────
var settings = { notifMode:'suspicious_only', tgEnabled:false, countryRules:[] };
var ALL_COUNTRIES=[{cc:'AF',name:'Afghanistan'},{cc:'AL',name:'Albania'},{cc:'DZ',name:'Algeria'},{cc:'AR',name:'Argentina'},{cc:'AM',name:'Armenia'},{cc:'AU',name:'Australia'},{cc:'AT',name:'Austria'},{cc:'AZ',name:'Azerbaijan'},{cc:'BH',name:'Bahrain'},{cc:'BD',name:'Bangladesh'},{cc:'BY',name:'Belarus'},{cc:'BE',name:'Belgium'},{cc:'BO',name:'Bolivia'},{cc:'BA',name:'Bosnia'},{cc:'BR',name:'Brazil'},{cc:'BG',name:'Bulgaria'},{cc:'KH',name:'Cambodia'},{cc:'CM',name:'Cameroon'},{cc:'CA',name:'Canada'},{cc:'CL',name:'Chile'},{cc:'CN',name:'China'},{cc:'CO',name:'Colombia'},{cc:'CR',name:'Costa Rica'},{cc:'HR',name:'Croatia'},{cc:'CU',name:'Cuba'},{cc:'CY',name:'Cyprus'},{cc:'CZ',name:'Czech Republic'},{cc:'DK',name:'Denmark'},{cc:'DO',name:'Dominican Republic'},{cc:'EC',name:'Ecuador'},{cc:'EG',name:'Egypt'},{cc:'EE',name:'Estonia'},{cc:'ET',name:'Ethiopia'},{cc:'FI',name:'Finland'},{cc:'FR',name:'France'},{cc:'GE',name:'Georgia'},{cc:'DE',name:'Germany'},{cc:'GH',name:'Ghana'},{cc:'GR',name:'Greece'},{cc:'GT',name:'Guatemala'},{cc:'HU',name:'Hungary'},{cc:'IS',name:'Iceland'},{cc:'IN',name:'India'},{cc:'ID',name:'Indonesia'},{cc:'IR',name:'Iran'},{cc:'IQ',name:'Iraq'},{cc:'IE',name:'Ireland'},{cc:'IL',name:'Israel'},{cc:'IT',name:'Italy'},{cc:'JP',name:'Japan'},{cc:'JO',name:'Jordan'},{cc:'KZ',name:'Kazakhstan'},{cc:'KE',name:'Kenya'},{cc:'KW',name:'Kuwait'},{cc:'LA',name:'Laos'},{cc:'LV',name:'Latvia'},{cc:'LB',name:'Lebanon'},{cc:'LY',name:'Libya'},{cc:'LT',name:'Lithuania'},{cc:'LU',name:'Luxembourg'},{cc:'MY',name:'Malaysia'},{cc:'ML',name:'Mali'},{cc:'MT',name:'Malta'},{cc:'MX',name:'Mexico'},{cc:'MD',name:'Moldova'},{cc:'MN',name:'Mongolia'},{cc:'ME',name:'Montenegro'},{cc:'MA',name:'Morocco'},{cc:'MM',name:'Myanmar'},{cc:'NP',name:'Nepal'},{cc:'NL',name:'Netherlands'},{cc:'NZ',name:'New Zealand'},{cc:'NG',name:'Nigeria'},{cc:'NO',name:'Norway'},{cc:'OM',name:'Oman'},{cc:'PK',name:'Pakistan'},{cc:'PA',name:'Panama'},{cc:'PY',name:'Paraguay'},{cc:'PE',name:'Peru'},{cc:'PH',name:'Philippines'},{cc:'PL',name:'Poland'},{cc:'PT',name:'Portugal'},{cc:'QA',name:'Qatar'},{cc:'RO',name:'Romania'},{cc:'RU',name:'Russia'},{cc:'SA',name:'Saudi Arabia'},{cc:'SN',name:'Senegal'},{cc:'RS',name:'Serbia'},{cc:'SG',name:'Singapore'},{cc:'SK',name:'Slovakia'},{cc:'SI',name:'Slovenia'},{cc:'SO',name:'Somalia'},{cc:'ZA',name:'South Africa'},{cc:'KR',name:'South Korea'},{cc:'ES',name:'Spain'},{cc:'LK',name:'Sri Lanka'},{cc:'SD',name:'Sudan'},{cc:'SE',name:'Sweden'},{cc:'CH',name:'Switzerland'},{cc:'SY',name:'Syria'},{cc:'TW',name:'Taiwan'},{cc:'TJ',name:'Tajikistan'},{cc:'TZ',name:'Tanzania'},{cc:'TH',name:'Thailand'},{cc:'TN',name:'Tunisia'},{cc:'TR',name:'Turkey'},{cc:'TM',name:'Turkmenistan'},{cc:'UA',name:'Ukraine'},{cc:'AE',name:'UAE'},{cc:'GB',name:'United Kingdom'},{cc:'US',name:'United States'},{cc:'UY',name:'Uruguay'},{cc:'UZ',name:'Uzbekistan'},{cc:'VE',name:'Venezuela'},{cc:'VN',name:'Vietnam'},{cc:'YE',name:'Yemen'},{cc:'ZM',name:'Zambia'},{cc:'ZW',name:'Zimbabwe'}];

function saveSettings(){
  chrome.storage.sync.set({notifMode:settings.notifMode, tgEnabled:settings.tgEnabled, countryRules:settings.countryRules});
  var n=settings.countryRules.length;
  document.getElementById('rulesCountTag').textContent=n+(n===1?' country':' countries');
  document.getElementById('defaultModeTag').textContent=n>0?'FALLBACK':'GLOBAL';
  var tgToggle=document.getElementById("tgGlobalToggle");
  tgToggle.textContent=settings.tgEnabled?'ON':'OFF';
  tgToggle.className='tog '+(settings.tgEnabled?'t-tg-on':'t-tg-off');
}

function renderRules(){
  var c=document.getElementById('countryRulesList'), noMsg=document.getElementById('noRulesMsg'), rules=settings.countryRules;
  if(!rules.length){c.innerHTML='';if(noMsg)noMsg.style.display='block';return;}
  if(noMsg)noMsg.style.display='none';
  c.innerHTML=rules.map(function(r,i){
    var flag=flagEmoji(r.cc), mode=r.mode||'suspicious_only';
    var notifyOn=r.notify&&!r.block, blockOn=r.block, tgOn=r.telegram&&r.notify&&!r.block;
    var ipOn=r.ipBased!==false; var domainOn=!!r.domainBased;
    var tldLabel='.'+({GB:'uk',UK:'uk'}[r.cc]||r.cc).toLowerCase();
    var ipTip   = 'Match by server hosting country (IP geo lookup)';
    var domTip  = 'Match by domain TLD ('+tldLabel+' endings only)';
    var notTip  = blockOn?'Disable block first to change this':'Toggle Chrome browser notifications';
    var blkTip  = 'Block all access to sites from this country';
    var tgTip   = 'Toggle Telegram alerts for this rule';
    var modeTip = 'Which threat levels trigger a notification';
    return '<div class="cr-item">'
      +'<div class="cr-row1"><span class="cr-flag">'+flag+'</span><span class="cr-name">'+r.name+'</span>'
      +'<button class="cr-rm" data-idx="'+i+'">X</button></div>'
      +'<div class="cr-row2">'
      +'<span class="tog '+(ipOn?'t-ip-on':'t-ip-off')+'" data-type="ip" data-idx="'+i+'" data-tip="'+ipTip+'">'+(ipOn?'IP ON':'IP OFF')+'</span>'
      +'<span class="tog '+(domainOn?'t-domain-on':'t-domain-off')+'" data-type="domain" data-idx="'+i+'" data-tip="'+domTip+'">'+(domainOn?tldLabel+' ON':tldLabel+' OFF')+'</span>'
      +'<span class="tog '+(notifyOn?'t-notif-on':'t-notif-off')+'" data-type="notify" data-idx="'+i+'" data-tip="'+notTip+'">'+(notifyOn?'Notify ON':'Notify OFF')+'</span>'
      +(notifyOn?'<select class="cr-mode-sel show" data-idx="'+i+'" title="'+modeTip+'">'
        +'<option value="suspicious_only"'+(mode==='suspicious_only'?' selected':'')+'>Susp</option>'
        +'<option value="all_events"'+(mode==='all_events'?' selected':'')+'>All</option>'
        +'</select>':'')
      +(notifyOn?'<span class="tog '+(tgOn?'t-tg-on':'t-tg-off')+'" data-type="telegram" data-idx="'+i+'" data-tip="'+tgTip+'">'+(tgOn?'TG ON':'TG OFF')+'</span>':'')
      +'<span class="tog '+(blockOn?'t-block-on':'t-block-off')+'" data-type="block" data-idx="'+i+'" data-tip="'+blkTip+'">'+(blockOn?'Block ON':'Block OFF')+'</span>'
      +'</div></div>';
  }).join('');

  c.querySelectorAll('.tog[data-type="ip"]').forEach(function(el){
    el.addEventListener('click', function(){
      var idx=parseInt(this.dataset.idx), r=settings.countryRules[idx];
      r.ipBased=!(r.ipBased!==false);
      if(r.block) chrome.runtime.sendMessage({type:'CLEAR_COUNTRY_CACHE',cc:r.cc});
      saveSettings(); renderRules();
    });
  });

  c.querySelectorAll('.tog[data-type="domain"]').forEach(function(el){
    el.addEventListener('click', function(){
      var idx=parseInt(this.dataset.idx), r=settings.countryRules[idx];
      r.domainBased=!r.domainBased;
      if(r.block) chrome.runtime.sendMessage({type:'CLEAR_COUNTRY_CACHE',cc:r.cc});
      saveSettings(); renderRules();
    });
  });

  c.querySelectorAll('.tog[data-type="notify"]').forEach(function(el){
    el.addEventListener('click', function(){
      var idx=parseInt(this.dataset.idx), r=settings.countryRules[idx];
      if(r.block){toast('Disable block first');return;}
      r.notify=!r.notify; if(!r.notify)r.telegram=false;
      saveSettings(); renderRules();
    });
  });
  c.querySelectorAll('.cr-mode-sel').forEach(function(sel){
    sel.addEventListener('change', function(){
      settings.countryRules[parseInt(this.dataset.idx)].mode=this.value;
      saveSettings();
    });
  });
  c.querySelectorAll('.tog[data-type="telegram"]').forEach(function(el){
    el.addEventListener('click', function(){
      var idx=parseInt(this.dataset.idx), r=settings.countryRules[idx];
      r.telegram=!r.telegram; saveSettings(); renderRules();
    });
  });
  c.querySelectorAll('.tog[data-type="block"]').forEach(function(el){
    el.addEventListener('click', function(){
      var idx=parseInt(this.dataset.idx), r=settings.countryRules[idx];
      if(!r.block){r.block=true;r.notify=false;r.telegram=false;}
      else{r.block=false;chrome.runtime.sendMessage({type:'CLEAR_COUNTRY_CACHE',cc:r.cc});}
      saveSettings(); renderRules();
    });
  });
  c.querySelectorAll('.cr-rm').forEach(function(el){
    el.addEventListener('click', function(){
      var idx=parseInt(this.dataset.idx), r=settings.countryRules[idx];
      if(r&&r.block) chrome.runtime.sendMessage({type:'CLEAR_COUNTRY_CACHE',cc:r.cc});
      settings.countryRules.splice(idx,1); saveSettings(); renderRules();
    });
  });
}

function initRules(){
  chrome.storage.sync.get(['notifMode','tgEnabled','countryRules'], function(s){
    settings.notifMode=s.notifMode||'suspicious_only';
    settings.tgEnabled=!!s.tgEnabled;
    settings.countryRules=(s.countryRules||[]).map(function(r){return Object.assign({mode:'suspicious_only',notify:true,block:false,telegram:false,ipBased:true,domainBased:false},r);});
    document.getElementById('notifMode').value=settings.notifMode;
    var n=settings.countryRules.length;
    document.getElementById('rulesCountTag').textContent=n+(n===1?' country':' countries');
    document.getElementById('defaultModeTag').textContent=n>0?'FALLBACK':'GLOBAL';
    var tgToggle=document.getElementById("tgGlobalToggle");
    tgToggle.textContent=settings.tgEnabled?'ON':'OFF';
    tgToggle.className='tog '+(settings.tgEnabled?'t-tg-on':'t-tg-off');
    renderRules();
    var dl=document.getElementById('countrySuggest');
    ALL_COUNTRIES.forEach(function(c){var o=document.createElement('option');o.value=c.name+' ('+c.cc+')';dl.appendChild(o);});
  });

  document.getElementById('notifMode').addEventListener('change',function(){settings.notifMode=this.value;saveSettings();toast('Default mode saved');});

  document.getElementById("tgGlobalToggle").addEventListener('click', function(){
    settings.tgEnabled=!settings.tgEnabled; saveSettings(); toast('Telegram global: '+(settings.tgEnabled?'ON':'OFF'));
  });

  document.getElementById('addCountryBtn').addEventListener('click',function(){
    var row=document.getElementById('addCountryRow');row.classList.toggle('open');
    if(row.classList.contains('open'))document.getElementById('countrySearch').focus();
  });
  document.getElementById('cancelAddCountry').addEventListener('click',function(){
    document.getElementById('addCountryRow').classList.remove('open');document.getElementById('countrySearch').value='';
  });
  function doAdd(){
    var val=document.getElementById('countrySearch').value, found=null;
    var m=val.match(/\(([A-Z]{2})\)$/); if(m) found=ALL_COUNTRIES.find(function(c){return c.cc===m[1];});
    if(!found) found=ALL_COUNTRIES.find(function(c){return c.cc===val.trim().toUpperCase()||c.name.toLowerCase()===val.trim().toLowerCase();});
    if(!found){toast('Country not found');return;}
    if(settings.countryRules.find(function(r){return r.cc===found.cc;})){toast(found.name+' already added');return;}
    settings.countryRules.push({cc:found.cc,name:found.name,notify:true,block:false,telegram:false,mode:'suspicious_only',ipBased:true,domainBased:false});
    saveSettings();renderRules();
    document.getElementById('addCountryRow').classList.remove('open');document.getElementById('countrySearch').value='';
    toast('Added: '+found.name);
  }
  document.getElementById('confirmAddCountry').addEventListener('click',doAdd);
  document.getElementById('countrySearch').addEventListener('keydown',function(e){if(e.key==='Enter')doAdd();});
}

// ── Boot ──────────────────────────────────────────────────────
updateDot(); loadCache(); loadCurrentSite(); initRules();

initKey({storageKey:'vtApiKey',inpId:'vtInp',saveId:'vtSave',inputRowId:'vtInputRow',savedAreaId:'vtSavedArea',previewId:'vtPreview',editId:'vtEdit',delId:'vtDel',tagId:'vtTag',label:'VirusTotal',onChange:loadCurrentSite});
initKey({storageKey:'abuseApiKey',inpId:'abuseInp',saveId:'abuseSave',inputRowId:'abuseInputRow',savedAreaId:'abuseSavedArea',previewId:'abusePreview',editId:'abuseEdit',delId:'abuseDel',tagId:'abuseTag',label:'AbuseIPDB',onChange:loadCurrentSite});
initKey({storageKey:'tgBotToken',inpId:'tgTokenInp',saveId:'tgTokenSave',inputRowId:'tgTokenInputRow',savedAreaId:'tgTokenSavedArea',previewId:'tgTokenPreview',editId:'tgTokenEdit',delId:'tgTokenDel',tagId:'tgTag',label:'Telegram Token',onChange:updateTgTag});
initKey({storageKey:'tgChatId',inpId:'tgChatInp',saveId:'tgChatSave',inputRowId:'tgChatInputRow',savedAreaId:'tgChatSavedArea',previewId:'tgChatPreview',editId:'tgChatEdit',delId:'tgChatDel',tagId:'tgTag',label:'Telegram Chat ID',onChange:updateTgTag});
updateTgTag();

document.getElementById('chipTotal').addEventListener('click',function(){openStats('all');});
document.getElementById('chipClean').addEventListener('click',function(){openStats('clean');});
document.getElementById('chipSusp').addEventListener('click',function(){openStats('suspicious');});
document.getElementById('chipMal').addEventListener('click',function(){openStats('malicious');});
document.getElementById('chipBlocked').addEventListener('click',function(){openStats('blocked');});
document.getElementById('clearBtn').addEventListener('click',function(){
  chrome.runtime.sendMessage({type:'CLEAR_CACHE'},function(res){if(res&&res.ok){toast('Cleared '+res.count+' entries');loadCache();loadCurrentSite();}});
});
document.getElementById('statsClose').addEventListener('click',function(){document.getElementById('statsOverlay').classList.remove('show');});
document.getElementById('statsOverlay').addEventListener('click',function(e){if(e.target===this)this.classList.remove('show');});

// ═══════════════════════════════════════════════════════════════
// PHISHING SETTINGS — added block (existing code above untouched)
// ═══════════════════════════════════════════════════════════════

// Default models per provider
var LLM_DEFAULTS = {
  openai:      'gpt-4o-mini',
  anthropic:   'claude-haiku-4-5-20251001',
  gemini:      'gemini-2.0-flash',
  mistral:     'mistral-small-latest',
  groq:        'llama-3.1-8b-instant',
  openrouter:  'openai/gpt-4o-mini',
  ollama:      'llama3.2',
  lmstudio:    'local-model',
  custom:      ''
};

// Pre-filled base URLs for local providers (shown in custom URL field)
var LLM_LOCAL_URLS = {
  ollama:   'http://localhost:11434',
  lmstudio: 'http://localhost:1234'
};

// ── AI (LLM) key + provider/model widget — fully self-contained ──
function updateLLMPhishTag() {
  chrome.storage.sync.get(['llmApiKey', 'phishingLLM'], function(s) {
    var tag    = document.getElementById('llmPhishTag');
    var toggle = document.getElementById('phishLLMToggle');
    if (!tag || !toggle) return;
    var hasKey = !!s.llmApiKey;
    var llmOn  = s.phishingLLM === true;
    tag.textContent  = hasKey ? 'ACTIVE' : 'NEEDS KEY';
    tag.className    = 'key-status ' + (hasKey ? 'ks-on' : 'ks-off');
    toggle.textContent = llmOn ? 'ON' : 'OFF';
    toggle.className   = 'tog ' + (llmOn ? 't-notif-on' : 't-notif-off');
    toggle.style.opacity = hasKey ? '' : '0.45';
    toggle.style.pointerEvents = hasKey ? '' : 'none';
  });
}

function initLLMWidget() {
  var provSel    = document.getElementById('llmProvider');
  var modelInp   = document.getElementById('llmModel');
  var customRow  = document.getElementById('llmCustomUrlRow');
  var customUrl  = document.getElementById('llmCustomUrl');
  var keyInp     = document.getElementById('llmInp');
  var saveBtn    = document.getElementById('llmSave');
  var inputRow   = document.getElementById('llmInputRow');
  var savedArea  = document.getElementById('llmSavedArea');
  var preview    = document.getElementById('llmPreview');
  var editBtn    = document.getElementById('llmEdit');
  var delBtn     = document.getElementById('llmDel');
  var tag        = document.getElementById('llmTag');
  if (!provSel || !modelInp || !saveBtn) return;

  function setUrlRow(prov) {
    var show = (prov === 'custom' || prov === 'ollama' || prov === 'lmstudio');
    if (customRow) customRow.style.display = show ? 'flex' : 'none';
  }

  function showSaved(key, prov, model) {
    inputRow.style.display  = 'none';
    savedArea.style.display = 'flex';
    // Show  "provider · model"  in the preview line
    var provLabel = provSel.options[provSel.selectedIndex]
      ? provSel.options[provSel.selectedIndex].text
      : prov;
    preview.textContent = provLabel + '  ·  ' + (model || LLM_DEFAULTS[prov] || '?') + '   ' + maskKey(key);
    tag.textContent = 'ACTIVE';
    tag.className   = 'key-status ks-on';
    updateLLMPhishTag();
    updateDot();
  }

  function showEmpty() {
    inputRow.style.display  = 'flex';
    savedArea.style.display = 'none';
    keyInp.value = '';
    keyInp.type  = 'password';
    tag.textContent = 'NOT SET';
    tag.className   = 'key-status ks-off';
    updateLLMPhishTag();
    updateDot();
  }

  // Load all saved settings on open
  chrome.storage.sync.get(['llmApiKey','llmProvider','llmModel','llmCustomUrl'], function(s) {
    var prov  = s.llmProvider || 'openai';
    var model = s.llmModel    || '';
    provSel.value = prov;
    modelInp.placeholder = 'e.g. ' + (LLM_DEFAULTS[prov] || 'model-name');
    modelInp.value = model;
    setUrlRow(prov);
    if (customUrl) customUrl.value = s.llmCustomUrl || LLM_LOCAL_URLS[prov] || '';
    if (s.llmApiKey) {
      modelInp.disabled = true;
      provSel.disabled  = true;
      showSaved(s.llmApiKey, prov, model);
    } else {
      modelInp.disabled = false;
      provSel.disabled  = false;
      showEmpty();
    }
  });

  // Persist model name on every keystroke so it survives popup close
  modelInp.addEventListener('input', function() {
    chrome.storage.sync.set({ llmModel: this.value.trim() });
  });

  // Provider change → update placeholder, clear model field, auto-fill URL
  provSel.addEventListener('change', function() {
    var prov = this.value;
    modelInp.placeholder = 'e.g. ' + (LLM_DEFAULTS[prov] || 'model-name');
    modelInp.value = '';
    modelInp.disabled = false;
    setUrlRow(prov);
    if (customUrl) customUrl.value = LLM_LOCAL_URLS[prov] || '';
    chrome.storage.sync.set({ llmProvider: prov, llmModel: '' });
  });

  // Save — persists key + provider + model + customUrl, then locks model field
  saveBtn.addEventListener('click', function() {
    var keyVal    = keyInp.value.trim();
    var prov      = provSel.value;
    var modelVal  = modelInp.value.trim() || LLM_DEFAULTS[prov] || '';
    var customVal = customUrl ? customUrl.value.trim() : '';

    if (!keyVal && prov !== 'ollama' && prov !== 'lmstudio') {
      toast('Enter an API key'); return;
    }

    saveBtn.disabled = true; saveBtn.textContent = '...';
    chrome.storage.sync.set({
      llmApiKey:    keyVal,
      llmProvider:  prov,
      llmModel:     modelVal,
      llmCustomUrl: customVal,
      phishingLLM:  true
    }, function() {
      saveBtn.disabled = false; saveBtn.textContent = 'Save';
      modelInp.value    = modelVal;
      modelInp.disabled = true;   // lock model field after save
      provSel.disabled  = true;   // lock provider too
      toast('AI key saved — AI Analysis enabled');
      showSaved(keyVal, prov, modelVal);
      updateLLMPhishTag();
      var llmToggle = document.getElementById('phishLLMToggle');
      if (llmToggle) {
        llmToggle.textContent = 'ON';
        llmToggle.className   = 'tog t-notif-on';
        llmToggle.style.opacity = '';
        llmToggle.style.pointerEvents = '';
      }
    });
  });

  // Edit — re-enable fields and show input row with saved values
  editBtn.addEventListener('click', function() {
    chrome.storage.sync.get(['llmApiKey','llmProvider','llmModel','llmCustomUrl'], function(s) {
      var prov = s.llmProvider || 'openai';
      provSel.value     = prov;
      provSel.disabled  = false;
      modelInp.placeholder = 'e.g. ' + (LLM_DEFAULTS[prov] || 'model-name');
      modelInp.value    = s.llmModel || '';
      modelInp.disabled = false;
      setUrlRow(prov);
      if (customUrl) customUrl.value = s.llmCustomUrl || LLM_LOCAL_URLS[prov] || '';
      keyInp.value = s.llmApiKey || '';
      keyInp.type  = 'text';
      inputRow.style.display  = 'flex';
      savedArea.style.display = 'none';
      tag.textContent = 'EDITING';
      tag.className   = '';
      tag.style.cssText = 'background:rgba(245,166,35,.1);color:#f5a623;border:1px solid rgba(245,166,35,.25)';
      keyInp.focus(); keyInp.select();
    });
  });

  // Remove — clears api key + model + resets to default provider
  delBtn.addEventListener('click', function() {
    chrome.storage.sync.remove(['llmApiKey','llmModel','llmProvider','llmCustomUrl'], function() {
      // Also turn off AI analysis since there's no key
      chrome.storage.sync.set({ phishingLLM: false });
      provSel.value    = 'openai';
      provSel.disabled = false;
      modelInp.value    = '';
      modelInp.disabled = false;
      modelInp.placeholder = 'e.g. ' + LLM_DEFAULTS['openai'];
      if (customRow) customRow.style.display = 'none';
      if (customUrl) customUrl.value = '';
      tag.removeAttribute('style');
      toast('AI key removed — AI Analysis disabled');
      showEmpty();
      // Sync the Rules tab toggle
      var llmToggle = document.getElementById('phishLLMToggle');
      if (llmToggle) {
        llmToggle.textContent = 'OFF';
        llmToggle.className   = 'tog t-notif-off';
        llmToggle.style.opacity = '0.45';
        llmToggle.style.pointerEvents = 'none';
      }
    });
  });

  keyInp.addEventListener('keydown', function(e) { if (e.key === 'Enter') saveBtn.click(); });
}

initLLMWidget();

// ── Phishing toggles ─────────────────────────────────────────
function initPhishing() {
  chrome.storage.sync.get(['phishingRegex', 'phishingLLM'], function(s) {
    var regexOn = s.phishingRegex !== false;
    var regexToggle = document.getElementById('phishRegexToggle');
    if (regexToggle) {
      regexToggle.textContent = regexOn ? 'ON' : 'OFF';
      regexToggle.className   = 'tog ' + (regexOn ? 't-notif-on' : 't-notif-off');
    }
  });
  updateLLMPhishTag();

  var regexToggle = document.getElementById('phishRegexToggle');
  if (regexToggle) {
    regexToggle.addEventListener('click', function() {
      chrome.storage.sync.get('phishingRegex', function(s) {
        var newVal = s.phishingRegex === false;
        chrome.storage.sync.set({ phishingRegex: newVal }, function() {
          regexToggle.textContent = newVal ? 'ON' : 'OFF';
          regexToggle.className   = 'tog ' + (newVal ? 't-notif-on' : 't-notif-off');
          toast('Regex phishing: ' + (newVal ? 'ON' : 'OFF'));
        });
      });
    });
  }

  var llmToggle = document.getElementById('phishLLMToggle');
  if (llmToggle) {
    llmToggle.addEventListener('click', function() {
      chrome.storage.sync.get(['phishingLLM', 'llmApiKey'], function(s) {
        if (!s.llmApiKey) { toast('Set an AI API key first (API Keys tab)'); return; }
        var newVal = !s.phishingLLM;
        chrome.storage.sync.set({ phishingLLM: newVal }, function() {
          llmToggle.textContent = newVal ? 'ON' : 'OFF';
          llmToggle.className   = 'tog ' + (newVal ? 't-notif-on' : 't-notif-off');
          toast('AI phishing analysis: ' + (newVal ? 'ON' : 'OFF'));
        });
      });
    });
  }
}

initPhishing();
