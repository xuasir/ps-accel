'use strict';
'require view';
'require rpc';
'require poll';
'require ui';

var callStatus = rpc.declare({ object: 'ps-accel', method: 'status', expect: {} });
var callDetails = rpc.declare({ object: 'ps-accel', method: 'details', expect: {} });
var callDevices = rpc.declare({ object: 'ps-accel', method: 'devices', expect: {} });
var callDeviceSave = rpc.declare({ object: 'ps-accel', method: 'device_save',
 params: [ 'bridge', 'portal_ip', 'ps5_ip' ], expect: {} });
var callLogs = rpc.declare({ object: 'ps-accel', method: 'logs', params: [ 'kind' ], expect: {} });
var callConfigure = rpc.declare({ object: 'ps-accel', method: 'configure',
 params: [ 'bridge', 'address', 'ps5_ip', 'portal_ip', 'profile' ], expect: {} });
var callProfile = rpc.declare({ object: 'ps-accel', method: 'profile', params: [ 'profile' ], expect: {} });
var callStart = rpc.declare({ object: 'ps-accel', method: 'start', params: [ 'autostart' ], expect: {} });
var callDiagnostics = rpc.declare({ object: 'ps-accel', method: 'diagnostics', expect: {} });
var callProxyDiagnostics = rpc.declare({ object: 'ps-accel', method: 'proxy_diagnostics', expect: {} });
var callLogging = rpc.declare({ object: 'ps-accel', method: 'logging', params: [ 'mode', 'domains', 'tag' ], expect: {} });
var callDomains = rpc.declare({ object: 'ps-accel', method: 'domains', params: [ 'incident' ], expect: {} });
var callDomainMonitor = rpc.declare({ object: 'ps-accel', method: 'domain_monitor', params: [ 'batch', 'incident' ], expect: {} });
var callDomainBatchStart = rpc.declare({ object: 'ps-accel', method: 'domain_batch_start', expect: {} });
var callIncident = rpc.declare({ object: 'ps-accel', method: 'incident', params: [ 'note' ], expect: {} });
var policyFields = [ 'domains', 'exclusions', 'node' ];
var proxyActions = [ 'psportal_apply', 'psportal_direct', 'psportal_release' ];
var maxPolicyRules = 4096;
var callPolicyStatus = rpc.declare({ object: 'ps-accel', method: 'psportal_status', expect: {} });
var callPolicySave = rpc.declare({ object: 'ps-accel', method: 'psportal_save', params: policyFields.concat(['revision']), expect: {} });
var callPolicyApply = rpc.declare({ object: 'ps-accel', method: 'psportal_apply', params: policyFields.concat(['revision']), expect: {} });
var callPolicyDirect = rpc.declare({ object: 'ps-accel', method: 'psportal_direct', params: ['revision'], expect: {} });
var callPolicyRelease = rpc.declare({ object: 'ps-accel', method: 'psportal_release', params: ['revision'], expect: {} });
var calls = {};
[ 'baseline', 'trial', 'stop', 'repair', 'doctor' ].forEach(function(name) {
 calls[name] = rpc.declare({ object: 'ps-accel', method: name, expect: {} });
});
var actionNames = { device_save: '确认设备', configure: '检查码率配置', profile: '应用码率', baseline: '连接测试',
 trial: '试运行', start: '启动码率增强', stop: '停止任务', repair: '网络恢复', doctor: '环境检查',
 psportal_apply: '应用设备规则', psportal_direct: '两设备全部直连', psportal_release: '解除设备接管' };
var profilePhases = { stopping: '正在恢复旧连接', saving: '正在保存新码率',
 starting: '正在启动新档位', rollback: '正在恢复原档位',
 waiting_exit: '正在等待进程退出', repairing: '正在恢复与清理网络' };
var evidenceNames = { new_domain: '首次发现', dns_query: 'DNS 查询', dns_ok: 'DNS 解析完成',
 dns_empty: 'DNS 无地址响应', dns_truncated: 'DNS 响应截断', dns_error: 'DNS 错误',
 dns_timeout: 'DNS 观测超时', tcp_ok: 'TCP 握手响应', tcp_reset: 'TCP 建连被重置',
 tcp_timeout: 'TCP 建连观测超时', tls_sni: 'TLS 域名可见', unreachable: '网络不可达响应' };
function localTime(value) {
 if (!value) return '—';
 var date = new Date(value);
 return isNaN(date.getTime()) ? '—' : date.toLocaleString('zh-CN', { hour12: false });
}
function jobFeature(action) {
 return action && action.indexOf('psportal_') === 0 ? 'proxy' : action === 'device_save' ? 'devices' : 'bitrate';
}
function policyHosts(text) {
 return (text || '').split('\n').map(function(name) { return name.trim().toLowerCase().replace(/^full:/, '').replace(/\.$/, ''); })
  .filter(function(name, index, names) { return validHost(name.replace(/^domain:/, '')) && names.indexOf(name) === index; });
}
function validHost(name) {
 return name.length <= 253 && name.indexOf('.') > 0 && !/^\d+(\.\d+){3}$/.test(name) &&
  name.split('.').every(function(part) { return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(part); });
}
function policyMatches(host, rules) {
 host = host.toLowerCase().replace(/\.$/, '');
 return !!host && rules.some(function(rule) { return rule.indexOf('domain:') === 0 ?
  host === rule.slice(7) || host.endsWith('.' + rule.slice(7)) : host === rule; });
}
function policyListEdit(text, domain, remove) {
 var lines = (text || '').split('\n').filter(function(line) {
  return line.trim().toLowerCase().replace(/^full:/, '').replace(/\.$/, '') !== domain;
 });
 while (lines.length && !lines[lines.length - 1].trim()) lines.pop();
 if (!remove) lines.push(domain);
 return lines.join('\n') + (lines.length ? '\n' : '');
}
function policyRuleCount(text) {
 return (text || '').split('\n').filter(function(line) { return line.trim() && line.trim().charAt(0) !== '#'; }).length;
}
function dnsFailed(row) {
 var counts = row.counts || {};
 return !!row.dns_failed || !!(counts.dns_error || counts.dns_timeout);
}
function domainNames(rows, failed) {
 return rows.filter(function(row) { return !failed || dnsFailed(row); }).map(function(row) { return row.domain; })
  .filter(function(name, index, all) { return validHost(name) && all.indexOf(name) === index; }).sort();
}
var largeProxyBytes = 100 * 1024 * 1024;
function formatBytes(value) {
 value = typeof value === 'number' && isFinite(value) && value >= 0 ? value : 0;
 var units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'], index = 0;
 while (value >= 1024 && index < units.length - 1) { value /= 1024; index++; }
 return (index ? value.toFixed(value < 10 ? 2 : 1) : Math.round(value)) + ' ' + units[index];
}
function rowBytes(row, proxy) {
 var traffic = row.traffic || {};
 return Number(traffic[proxy ? 'proxy_upload_bytes' : 'upload_bytes'] || 0) +
  Number(traffic[proxy ? 'proxy_download_bytes' : 'download_bytes'] || 0);
}
function proxyRelated(row) {
 var traffic = row.traffic || {};
 return !!(traffic.has_proxy || traffic.proxy_rules_seen || rowBytes(row, true));
}
function copyText(text) {
 function fallback() {
  var input = E('textarea', { readonly: '', style: 'position:fixed;left:-9999px;top:0' });
  var focused = document.activeElement;
  input.value = text; document.body.appendChild(input);
  try {
   input.select();
   if (!document.execCommand || !document.execCommand('copy')) throw new Error('浏览器剪贴板权限待确认');
  } finally {
   input.remove();
   if (focused && focused.focus) focused.focus();
  }
 }
 var clipboard = window.navigator && window.navigator.clipboard;
 return clipboard && clipboard.writeText ? Promise.resolve().then(function() { return clipboard.writeText(text); })
  .catch(fallback) : Promise.resolve().then(fallback);
}

function rpcRequest(request) {
 return new Promise(function(resolve, reject) {
  var timer = window.setTimeout(function() {
   reject(new Error('请求等待超时，可重试停止或恢复网络。'));
  }, 12000);
  Promise.resolve().then(request).then(function(result) {
   window.clearTimeout(timer);
   if (!result || !result.ok) reject(new Error(result && result.error || '操作执行失败，请查看日志。'));
   else resolve(result);
  }, function(error) { window.clearTimeout(timer); reject(error); });
 });
}

// Keep layout local; LuCI and the active theme style native controls and tabs.
var styles = `
.ps-accel{min-width:0}.ps-accel [hidden]{display:none!important}
.ps-accel .pa-choice{position:relative;min-width:0}.ps-accel .pa-choice-row{display:flex;gap:8px;align-items:center}
.ps-accel .pa-choice-row>.cbi-input-text{flex:1;min-width:0}.ps-accel .pa-choice-button{display:flex;justify-content:space-between;gap:12px;align-items:center;min-height:40px;text-align:left}
.ps-accel .pa-choice:not(.pa-choice-manual) .pa-choice-button{width:100%}.ps-accel .pa-choice-menu{position:fixed;inset:auto;margin:0;z-index:1000;background:var(--background-color-high,#fff);color:inherit;border:1px solid var(--border-color-medium,#ccc);border-radius:6px;padding:10px;box-sizing:border-box;box-shadow:0 8px 24px #0003}
.ps-accel .pa-choice-menu::backdrop{background:transparent;pointer-events:none}
.ps-accel .pa-choice-list{max-height:260px;overflow:auto;margin-top:8px}.ps-accel .pa-choice-option{display:block;width:100%;min-height:44px;text-align:left;border:0;border-radius:4px;padding:8px;background:transparent;color:inherit;cursor:pointer}
.ps-accel .pa-choice-option:hover,.ps-accel .pa-choice-option:focus{background:var(--background-color-medium,#80808020)}.ps-accel .pa-choice-option[aria-selected=true]{font-weight:600}.ps-accel .pa-choice-option small{display:block;opacity:.7;margin-top:3px}.ps-accel .pa-choice-option:disabled{opacity:.55;cursor:default}
.ps-accel .pa-notice:empty,.ps-accel .pa-caption:empty{display:none}.ps-accel .pa-node-row{display:flex;gap:8px;align-items:flex-end}.ps-accel .pa-node-row>.pa-field{flex:1;min-width:0;margin-bottom:0}
.ps-accel .pa-basic{max-width:960px}.ps-accel .pa-basic>.pa-panel,.ps-accel .pa-basic>.pa-stage-panel{margin:16px 0}.ps-accel .pa-basic .pa-disclosure>.pa-grid{margin-top:12px}
.ps-accel .pa-grid{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(0,1fr);gap:16px;align-items:start}
.ps-accel .pa-stack{display:flex;flex-direction:column;gap:16px;min-width:0}
.ps-accel .pa-panel{min-width:0;margin:0}.ps-accel .pa-panel-body{min-width:0}
.ps-accel .pa-panel-head{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:12px}
.ps-accel .pa-panel-head h3{margin:0}.ps-accel .pa-panel-head .cbi-button{max-width:100%}
.ps-accel .pa-main-tabs>li{height:auto;max-width:100%}.ps-accel .pa-main-tab{line-height:1.5}
.ps-accel .pa-nav-state{display:block;font-size:.85em;line-height:1.5;font-weight:normal}
.ps-accel .pa-feature-head{margin:16px 0}.ps-accel .pa-feature-head h3{margin-bottom:6px}
.ps-accel .pa-tab-panel,.ps-accel .pa-stage-panel{min-width:0}
.ps-accel .pa-scope{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin:12px 0}
.ps-accel .pa-scope-copy{display:flex;gap:16px;flex-wrap:wrap}.ps-accel .pa-scope-copy b{margin-right:6px}
.ps-accel .pa-form,.ps-accel .pa-device-form{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}
.ps-accel .pa-field{display:block;margin:12px 0;min-width:0}
.ps-accel .pa-field>.cbi-value-title{display:block;float:none;text-align:left;width:auto;padding:0}
.ps-accel .pa-field>.cbi-value-field{display:block;margin:6px 0 0;min-width:0}
.ps-accel .cbi-input-text,.ps-accel .cbi-input-select,.ps-accel .cbi-input-textarea{width:100%;max-width:100%;min-width:0;box-sizing:border-box}
.ps-accel .cbi-input-textarea{resize:vertical}.ps-accel .pa-device-card{min-width:0}
.ps-accel .pa-device-title{display:flex;align-items:baseline;justify-content:space-between;gap:12px;flex-wrap:wrap}
.ps-accel .pa-device-title h4{margin:12px 0 0}
.ps-accel .pa-actions,.ps-accel .pa-domain-row-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:12px 0}
.ps-accel .pa-btn,.ps-accel .pa-link,.ps-accel .pa-profile{white-space:normal;max-width:100%}
.ps-accel .pa-config-foot{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-top:16px}
.ps-accel .pa-profiles{display:flex;gap:8px;flex-wrap:wrap;margin:16px 0}.ps-accel .pa-profile{flex:1 1 90px}
.ps-accel .pa-profile span{display:block;font-size:.85em;line-height:1.5}
.ps-accel .pa-profile strong{font-size:inherit}.ps-accel .pa-selection{margin-bottom:12px}
.ps-accel .pa-toggle{display:inline-flex;gap:8px;align-items:center;flex-wrap:wrap;margin:12px 0}
.ps-accel .pa-notice{margin:12px 0;overflow-wrap:anywhere}.ps-accel .pa-notice:empty{display:none}
.ps-accel .pa-muted,.ps-accel .pa-mini,.ps-accel .pa-detail,.ps-accel .pa-device-identity,.ps-accel .pa-domain-time,.ps-accel .pa-record-detail{color:var(--text-color-medium,var(--muted,inherit));font-size:.9em;line-height:1.6;overflow-wrap:anywhere}
.ps-accel .pa-caption{margin:8px 0;overflow-wrap:anywhere}
.ps-accel .pa-domain-problem,.ps-accel [data-error="true"]{color:var(--error-color-high,var(--err,inherit))}
.ps-accel .pa-status-pill{font-size:inherit}.ps-accel .pa-stats{margin:16px 0;width:100%}
.ps-accel .pa-stats td{vertical-align:top}.ps-accel .pa-stats td:first-child{width:25%}
.ps-accel .pa-number{white-space:nowrap}.ps-accel .pa-number small{font-size:inherit;margin-left:6px}
.ps-accel .pa-bars{display:flex;align-items:flex-end;gap:3px;height:22px;max-width:200px;margin-top:6px}
.ps-accel .pa-bars i{flex:1;min-width:2px;height:2px;background:currentColor;opacity:.5}
.ps-accel .pa-feature-status{width:100%;margin:12px 0}.ps-accel .pa-feature-status td:first-child{width:30%}
.ps-accel .pa-kv{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;padding:10px 0;border-bottom:1px solid var(--border-color-medium,var(--line,currentColor))}
.ps-accel .pa-kv>span:last-child{text-align:right;overflow-wrap:anywhere}.ps-accel .pa-kv:last-child{border-bottom:0}
.ps-accel .pa-device-inventory .pa-kv{flex-wrap:wrap}.ps-accel .pa-device-inventory .pa-actions{margin:0}
.ps-accel .pa-disclosure{margin:16px 0}.ps-accel .pa-disclosure>summary{cursor:pointer;font-weight:600;margin-bottom:8px}
.ps-accel .pa-step{display:flex;align-items:flex-start;gap:10px;margin:12px 0}.ps-accel .pa-step-icon{flex-shrink:0;font-weight:600}
.ps-accel .pa-step-title{font-weight:600}.ps-accel .pa-step-desc{margin-top:4px}
.ps-accel .pa-flow{display:grid;grid-template-columns:minmax(0,1fr) 16px minmax(0,1fr) 16px minmax(0,1fr);align-items:center;gap:6px;margin:16px 0}
.ps-accel .pa-device{min-width:0;overflow-wrap:anywhere}.ps-accel .pa-device b,.ps-accel .pa-device span{display:block}.ps-accel .pa-arrow{text-align:center}
.ps-accel .pa-log-tools{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap}
.ps-accel .pa-log-tools .pa-log-tabs{margin-top:0}.ps-accel .pa-log{height:240px;min-height:0;max-height:240px;overflow:auto;overscroll-behavior:contain;white-space:pre-wrap;overflow-wrap:anywhere;box-sizing:border-box}
.ps-accel .pa-domain-tools{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:12px 0}.ps-accel .pa-domain-tools .cbi-input-text{flex:1 1 180px}
.ps-accel .pa-domain-tools .pa-toggle{margin:0}.ps-accel .pa-domain-table{overflow-x:auto;max-width:100%}
.ps-accel .pa-domain-table .table{width:100%;margin:12px 0}.ps-accel .pa-domain-list .table{min-width:540px}
.ps-accel .pa-domain-table td{vertical-align:top;overflow-wrap:anywhere}.ps-accel .pa-domain-list{max-height:320px;overflow:auto;overscroll-behavior:contain}.ps-accel .pa-domain-name{overflow-wrap:anywhere;font-weight:600}
.ps-accel .pa-domain-new{display:inline-block;margin-left:6px;font-size:.85em;font-weight:normal}
.ps-accel .pa-domain-action-notice{margin:12px 0}.ps-accel .pa-domain-candidate{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;margin:12px 0}
.ps-accel .pa-domain-empty{padding:12px 0}.ps-accel .pa-incident{margin-top:16px}.ps-accel .pa-foot{margin-top:20px;padding:12px 0;font-size:.85em}
.ps-accel .pa-domain-monitor{max-width:1200px}.ps-accel .pa-traffic-summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:14px 0}
.ps-accel .pa-traffic-summary b,.ps-accel .pa-traffic-summary span{display:block}.ps-accel .pa-traffic-summary span{margin-top:5px;font-size:1.2em;font-weight:600}.ps-accel .pa-traffic-value{white-space:nowrap;font-weight:600}
.ps-accel .pa-domain-heavy{color:var(--error-color-high,var(--err,inherit))}.ps-accel .pa-domain-tools>.pa-choice{min-width:210px}.ps-accel .pa-domain-list .pa-domain-total,.ps-accel .pa-domain-list .pa-domain-proxy{min-width:120px}
@media(max-width:900px){.ps-accel .pa-grid{grid-template-columns:1fr}.ps-accel .pa-domain-list .table{min-width:0}}
@media(max-width:700px){.ps-accel .pa-traffic-summary{grid-template-columns:repeat(2,minmax(0,1fr))}.ps-accel .pa-domain-tools>.pa-choice{width:100%}.ps-accel .pa-domain-list .table,.ps-accel .pa-domain-list tbody{display:block;min-width:0}.ps-accel .pa-domain-list thead{display:none}.ps-accel .pa-domain-list tbody>.tr{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);grid-template-areas:'name name' 'total proxy' 'dns dns' 'rules time';border-bottom:1px solid var(--border-color-medium,#ccc);padding:8px 0}.ps-accel .pa-domain-list .td{min-width:0;padding:8px}.ps-accel .pa-domain-list .td:nth-child(1){grid-area:name}.ps-accel .pa-domain-list .td:nth-child(2){grid-area:dns}.ps-accel .pa-domain-list .td:nth-child(3){grid-area:total}.ps-accel .pa-domain-list .td:nth-child(4){grid-area:proxy}.ps-accel .pa-domain-list .td:nth-child(5){grid-area:rules}.ps-accel .pa-domain-list .td:nth-child(6){grid-area:time}.ps-accel .pa-domain-total:before,.ps-accel .pa-domain-proxy:before{content:attr(data-title);display:block;font-size:.85em;margin-bottom:6px}}
@media(max-width:600px){.ps-accel .pa-form,.ps-accel .pa-device-form{grid-template-columns:1fr}.ps-accel .pa-main-tabs>li{flex:1 1 auto}.ps-accel .pa-main-tab{width:100%}.ps-accel .pa-nav-state{white-space:normal}.ps-accel .pa-stats td:first-child{width:30%}.ps-accel .pa-flow{grid-template-columns:minmax(0,1fr) 12px minmax(0,1fr) 12px minmax(0,1fr);gap:3px}.ps-accel .pa-domain-list thead{display:none}.ps-accel .pa-domain-list tr{display:block;padding:10px 0;border-bottom:1px solid var(--border-color-medium,var(--line,currentColor))}.ps-accel .pa-domain-list td{display:block;width:100%;border:0;text-align:left;box-sizing:border-box}.ps-accel .pa-domain-list td:first-child{width:100%}.ps-accel .pa-log-tools{gap:8px}}
`;

function buttonClass(kind) {
 return 'pa-btn btn cbi-button ' + (kind === 'danger' ? 'cbi-button-reset' :
  kind === 'primary' ? 'cbi-button-action important' : 'cbi-button-neutral');
}

function luciControl(tag, attrs, children) {
 attrs = Object.assign({}, attrs);
 if (attrs.type !== 'hidden') {
  var kind = tag === 'input' ? (attrs.type === 'checkbox' || attrs.type === 'radio' ? attrs.type : 'text') :
   tag === 'select' ? 'select' : 'textarea';
  attrs['class'] = ((attrs['class'] || '') + ' cbi-input-' + kind).trim();
 }
 return E(tag, attrs, children);
}

function choiceControl(input, placeholder, manual) {
 var choices = [], signature = '', deferred = null, buttons = [], popoverOpen = false;
 var label = E('span', {}, placeholder);
 var trigger = E('button', { type: 'button', 'class': buttonClass() + ' pa-choice-button',
  'aria-label': placeholder, 'aria-haspopup': 'listbox', 'aria-expanded': 'false' }, [label, E('span', {}, '▾')]);
 var search = luciControl('input', { type: 'text', placeholder: '搜索名称或地址', autocomplete: 'off',
  'aria-label': '搜索' + placeholder });
 var list = E('div', { 'class': 'pa-choice-list', role: 'listbox', 'aria-label': placeholder });
 var menu = E('div', { 'class': 'pa-choice-menu' }, [search, list]); menu.hidden = true;
 var root = E('div', { 'class': 'pa-choice' + (manual ? ' pa-choice-manual' : '') }, [
  E('div', { 'class': 'pa-choice-row' }, manual ? [input, trigger] : [trigger, input]), menu]);
 function positionMenu() {
  if (menu.hidden || !root.getBoundingClientRect) return;
  var rect = root.getBoundingClientRect(), viewport = window.visualViewport;
  var left = viewport ? viewport.offsetLeft : 0, top = viewport ? viewport.offsetTop : 0;
  var width = viewport ? viewport.width : document.documentElement.clientWidth;
  var height = viewport ? viewport.height : document.documentElement.clientHeight;
  if (rect.bottom <= top || rect.top >= top + height) { close(); return; }
  menu.style.width = Math.min(rect.width, width - 16) + 'px';
  menu.style.left = Math.max(left + 8, Math.min(rect.left, left + width - menu.offsetWidth - 8)) + 'px';
  list.style.maxHeight = '260px';
  var below = top + height - rect.bottom - 16, above = rect.top - top - 16;
  var upwards = below < menu.offsetHeight && above > below;
  list.style.maxHeight = Math.max(44, Math.min(260, (upwards ? above : below) - search.offsetHeight - 30)) + 'px';
  menu.style.top = (upwards ? rect.top - menu.offsetHeight - 8 : rect.bottom + 8) + 'px';
 }
 function watchPosition(open) {
  var method = open ? 'addEventListener' : 'removeEventListener';
  if (!window[method]) return;
  window[method]('resize', positionMenu); window[method]('scroll', positionMenu, true);
  if (window.visualViewport) {
   window.visualViewport[method]('resize', positionMenu); window.visualViewport[method]('scroll', positionMenu);
  }
 }
 function close() {
  watchPosition(false);
  if (popoverOpen) { menu.hidePopover(); popoverOpen = false; }
  menu.hidden = true; trigger.setAttribute('aria-expanded', 'false');
  if (deferred) { var next = deferred; deferred = null; picker.setOptions(next); }
 }
 function render() {
  var query = search.value.trim().toLowerCase(); buttons = [];
  var matches = choices.filter(function(item) {
   return !query || (item.label + ' ' + item.value + ' ' + (item.detail || '')).toLowerCase().indexOf(query) >= 0;
  });
  list.replaceChildren.apply(list, matches.length ? matches.slice(0, 100).map(function(item) {
   var button = E('button', { type: 'button', 'class': 'pa-choice-option', role: 'option',
    'aria-selected': String(item.value === input.value), 'data-value': item.value, click: function() {
     if (input.disabled || item.available === false) return;
     input.value = item.value; close(); picker.sync();
     if (input.choiceChanged) input.choiceChanged();
     (manual ? input : trigger).focus();
    }, keydown: function(event) {
     if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return;
     event.preventDefault();
     var index = buttons.indexOf(button), step = event.key === 'ArrowDown' ? 1 : -1;
     for (var count = 0; count < buttons.length; count++) {
      index = (index + step + buttons.length) % buttons.length;
      if (!buttons[index].disabled) { buttons[index].focus(); break; }
     }
    } }, [E('span', {}, item.label), item.detail ? E('small', {}, item.detail) : null]);
   button.disabled = item.available === false; buttons.push(button); return button;
  }) : [E('p', { 'class': 'pa-caption' }, choices.length ? '当前搜索结果为空' : '刷新后选择，设备地址也可手动填写')]);
  positionMenu();
 }
 var picker = { input: input, root: root, trigger: trigger, menu: menu, search: search, list: list,
  setOptions: function(items) {
   if (!menu.hidden) { deferred = items; return; }
   var nextSignature = JSON.stringify(items);
   if (signature !== nextSignature) { signature = nextSignature; choices = items; render(); }
   picker.sync();
  },
  getOptions: function() { return choices; },
  setValue: function(value) { input.value = value || ''; picker.sync(); },
  sync: function() {
   trigger.disabled = !!input.disabled;
   var selected = choices.filter(function(item) { return item.value === input.value; })[0];
   label.textContent = manual ? placeholder : selected ? selected.label : input.value ? '已保存的选择 · 待刷新' : placeholder;
   trigger.setAttribute('aria-label', placeholder + (!manual && selected ? ' · ' + selected.label : ''));
   if (input.id) { list.id = input.id + '-choices'; trigger.setAttribute('aria-controls', list.id); }
   if (input.disabled && !menu.hidden) close();
  }, close: close };
 input.choicePicker = picker;
 trigger.addEventListener('click', function() {
  if (input.disabled) return;
  if (!menu.hidden) { close(); return; }
  menu.hidden = false; search.value = ''; render(); trigger.setAttribute('aria-expanded', 'true');
  if (window.getComputedStyle) {
   for (var surface = root; surface; surface = surface.parentElement) {
    var color = window.getComputedStyle(surface).backgroundColor;
    if (color !== 'transparent' && color !== 'rgba(0, 0, 0, 0)') { menu.style.backgroundColor = color; break; }
   }
  }
  if (menu.showPopover) { menu.setAttribute('popover', 'manual'); menu.showPopover(); popoverOpen = true; }
  positionMenu(); watchPosition(true);
 });
 trigger.addEventListener('keydown', function(event) {
  if (event.key === 'ArrowDown') { event.preventDefault(); if (menu.hidden) trigger.click(); search.focus(); }
 });
 search.addEventListener('input', render);
 search.addEventListener('keydown', function(event) {
  if (event.key === 'ArrowDown') { event.preventDefault(); var first = buttons.filter(function(button) { return !button.disabled; })[0]; if (first) first.focus(); }
 });
 root.addEventListener('keydown', function(event) {
  if (event.key === 'Escape' && !menu.hidden) { event.preventDefault(); close(); trigger.focus(); }
 });
 if (document.addEventListener) document.addEventListener('click', function(event) { if (!root.contains(event.target)) close(); });
 return input;
}

function formField(input, label, help) {
 return E('div', { 'class': 'cbi-value pa-field' }, [
  E('label', { 'class': 'cbi-value-title', 'for': input.id }, label),
  E('div', { 'class': 'cbi-value-field' }, [input.choicePicker ? input.choicePicker.root : input,
   help ? E('div', { 'class': 'cbi-value-description pa-caption' }, help) : E('span')])
 ]);
}

function setTabState(tab, selected) {
 tab.setAttribute('aria-selected', String(selected));
 tab.tabIndex = selected ? 0 : -1;
 tab.parentNode.setAttribute('class', selected ? 'cbi-tab' : 'cbi-tab-disabled');
}


return view.extend({
 load: function() {
  var self = this;
  return Promise.all([
   rpcRequest(callDetails).then(function(data) {
    self.detailsRevision = data.details_revision; self.detailsKnown = true; return data;
   }).catch(function(error) {
    self.detailsKnown = false;
    return { ok: true, details_warnings: [ error.message ], baseline_valid: false };
   }),
   rpcRequest(callStatus).catch(function(error) {
    self.connectionError = error.message;
    return { ok: true, state_known: false, status_warnings: [ error.message ] };
   })
  ]).then(function(values) { return Object.assign({}, values[0], values[1]); });
 },

 refreshDetails: function() {
  var self = this;
  if (this.detailsRequest) return this.detailsRequest;
  this.detailsRequest = rpcRequest(callDetails).then(function(data) {
   self.detailsRevision = data.details_revision; self.detailsKnown = true;
   self.update(Object.assign({}, self.latest, data, { details_revision: self.latest.details_revision }));
  }).catch(function(error) {
   self.detailsKnown = false;
   self.update(Object.assign({}, self.latest, { details_warnings: [ error.message ] }));
  }).finally(function() { self.detailsRequest = null; });
  return this.detailsRequest;
 },

 activeLog: function() {
  if (this.activeTab === 'devices' && this.deviceLogDetails.open) return { kind: 'devices', node: this.deviceLogNode };
  if (this.activeTab === 'bitrate' && this.stagePanels.bitrate.logs.open)
   return { kind: this.logTab, node: this.logNode };
  if (this.activeTab === 'proxy' && this.stagePanels.proxy.logs.open)
   return { kind: 'proxy', node: this.proxyLogNode };
  return null;
 },

 refreshLogs: function(force) {
  var context = this.activeLog();
  if (!context) return Promise.resolve();
  var self = this, kind = context.kind;
  if (this.logRequests[kind]) return this.logRequests[kind];
  if (!force && Date.now() < (this.nextLogRead[kind] || 0)) return Promise.resolve();
  this.nextLogRead[kind] = Date.now() + ((this.latest.logging || {}).mode === 'verbose' ? 2000 : 10000);
  this.logRequests[kind] = rpcRequest(function() { return callLogs(kind); }).then(function(data) {
   self.logContent[kind] = data.text;
   var active = self.activeLog();
   if (!active || active.kind !== kind) return;
   var bottom = active.node.scrollHeight - active.node.scrollTop - active.node.clientHeight < 40;
   var empty = { devices: '保存设备配置后，地址确认结果显示在这里。',
    bitrate: '配置检查、连接测试、启停与恢复结果显示在这里。',
    events: '码率增强启动后，握手修改与运行事件显示在这里。',
    proxy: '本机 PassWall 名单保存、应用与恢复结果显示在这里。' };
   active.node.textContent = data.text || empty[kind];
   if (bottom) active.node.scrollTop = active.node.scrollHeight;
  }).catch(function(error) {
   var active = self.activeLog();
   if (active && active.kind === kind) active.node.textContent = '日志读取失败：' + error.message;
  }).finally(function() { delete self.logRequests[kind]; });
  return this.logRequests[kind];
 },

 refreshDomains: function(force, anyStage) {
  if (anyStage) return rpcRequest(function() { return callDomains(''); });
  if (this.activeTab !== 'monitor') return Promise.resolve();
  if (this.domainRequest) return this.domainRequest;
  if (!force && Date.now() < (this.nextDomainRead || 0)) return Promise.resolve();
  var self = this, selected = this.incidentId || '', batch = this.batchId || '';
  function current() { return (self.incidentId || '') === selected && (self.batchId || '') === batch; }
  this.nextDomainRead = Date.now() + 2000;
  this.domainRequest = rpcRequest(function() { return callDomainMonitor(batch, selected); }).then(function(data) {
   if (!current()) return;
   self.domainSelectionPending = false;
   self.domainData = data;
   self.renderDomains(data);
   if (data.batch && data.batch.state === 'pending') self.nextDomainRead = Date.now() + 1000;
   return data;
  }).catch(function(error) {
   if (current()) self.domainState.textContent = '域名记录读取失败：' + error.message;
  }).finally(function() {
   self.domainRequest = null;
   if (!current()) self.refreshDomains(true);
  });
  return this.domainRequest;
 },

 selectLogTab: function(name, focus) {
  if (name === 'domains') { this.selectTab('monitor', focus); return this.refreshDomains(); }
  var proxy = name === 'proxy', tabs = proxy ? this.proxyLogTabs : this.logTabs;
  if (!tabs[name]) return;
  if (proxy) this.proxyLogTab = name;
  else this.logTab = name;
  Object.keys(tabs).forEach(function(key) {
   setTabState(tabs[key], key === name);
  });
  if (!proxy) this.logNode.setAttribute('aria-labelledby', tabs[name].id || tabs[name].attributes && tabs[name].attributes.id);
  if (focus) tabs[name].focus();
  (proxy ? this.proxyLogNode : this.logNode).textContent = this.logContent[name] || '正在读取日志…';
  return this.refreshLogs(true);
 },

 refreshDevices: function(force) {
  if (this.deviceRequest) return this.deviceRequest;
  if (this.activeTab !== 'devices' && !force) return Promise.resolve();
  if (!force && Date.now() < (this.nextDeviceRead || 0)) return Promise.resolve();
  var self = this;
  this.nextDeviceRead = Date.now() + 10000;
  this.deviceRequest = rpcRequest(callDevices).then(function(data) {
   self.deviceData = data; self.deviceError = null;
   self.renderDevices(data); self.update(self.latest);
  }).catch(function(error) {
   self.deviceError = error.message;
   self.update(self.latest);
  }).finally(function() { self.deviceRequest = null; self.update(self.latest); });
  return this.deviceRequest;
 },

 renderDevices: function(data) {
  var devices = data.devices || [], binding = data.binding || {}, choices = [];
  devices.forEach(function(device) {
   device.addresses.filter(function(ip) { return ip.indexOf(':') < 0; }).forEach(function(ip) {
    choices.push({value: ip, label: (device.label || device.mac) + ' · ' + ip,
     detail: device.mac + ' · ' + (device.source === 'dhcp' ? 'DHCP' : '邻居记录')});
   });
  });
  ['portal_ip', 'ps5_ip'].forEach(function(key) { this.fields[key].choicePicker.setOptions(choices); }, this);
  this.deviceConfirmed.textContent = binding.confirmed_at ? '上次保存 ' + localTime(binding.confirmed_at * 1000) :
   data.configured ? '设备地址已确认' : '';
  this.renderDeviceIdentity();
 },

 renderDeviceIdentity: function() {
  var data = this.deviceData || {}, devices = data.devices || [], binding = data.binding || {};
  ['portal', 'ps5'].forEach(function(role) {
   var ip = this.fields[role + '_ip'].value.trim();
   var matches = devices.filter(function(device) { return device.addresses.indexOf(ip) >= 0; });
   var mac = matches.length === 1 ? matches[0].mac :
    (binding.config || {})[role + '_ip'] === ip ? binding[role + '_mac'] : '';
   this.deviceIdentity[role].textContent = mac ? '设备 MAC · ' + mac : '保存时确认设备身份';
  }, this);
 },

 deviceSelectors: function() {
  var config = this.latest.config || {}, saved = this.latest.device_selectors || {};
  return { portal: saved.portal || config.portal_ip || '', ps5: saved.ps5 || config.ps5_ip || '' };
 },

 invalidatePolicy: function() {
  this.updatePolicyControls();
 },

 addDomainToPolicy: function(domain, target) {
  domain = domain.trim().toLowerCase().replace(/^full:/, '').replace(/\.$/, '');
  var busy = this.readonly || this.policyPending || this.pending || !!(this.latest.job || {}).busy;
  if (busy || !(this.policyData || {}).available || this.policyRequest || !validHost(domain) ||
      policyFields.indexOf(target) < 0) return;
  var hosts = policyHosts(this.policyInputs[target].value);
  var parents = policyHosts(this.policyInputs.exclusions.value).filter(function(rule) { return rule !== domain; });
  if (target === 'domains' && policyMatches(domain, parents)) {
   this.domainActionText.textContent = domain + ' 命中直连父域规则，请在名单中调整该规则后加入代理。';
   this.domainActionNotice.hidden = false; this.domainActionNotice.setAttribute('data-error', 'true'); return;
  }
  if (hosts.indexOf(domain) < 0 && policyRuleCount(this.policyInputs[target].value) >= maxPolicyRules) {
   this.domainActionText.textContent = '每份名单最多 4096 条规则，请先整理名单。';
   this.domainActionNotice.hidden = false; this.domainActionNotice.setAttribute('data-error', 'true'); return;
  }
  var other = target === 'domains' ? 'exclusions' : 'domains';
  this.policyInputs[target].value = policyListEdit(this.policyInputs[target].value, domain, false);
  this.policyInputs[other].value = policyListEdit(this.policyInputs[other].value, domain, true);
  this.policyTouched[target] = this.policyTouched[other] = true;
  this.policyConfigNotice.textContent = this.policyDraftState.textContent = '设备名单草稿已调整，应用设备规则后生效。';
  this.policyConfigNotice.setAttribute('data-error', 'false');
  this.domainActionText.textContent = domain + (target === 'domains' ? ' 已加入代理名单草稿。' : ' 已移出代理并加入直连名单草稿。') +
   '应用设备规则后由 PassWall 加载。';
  this.domainActionNotice.hidden = false; this.domainActionNotice.setAttribute('data-error', 'false');
  this.updatePolicyControls();
  if (this.domainData) this.renderDomains(this.domainData);
 },

 removeDomainFromPolicy: function(domain) {
  this.addDomainToPolicy(domain, 'exclusions');
 },

 selectBatch: function(id) {
  this.batchId = id;
  this.domainSelectionPending = true;
  this.domainCopyNotice.textContent = '';
  this.domainRulePreview.hidden = true;
  this.batchTitle.textContent = '正在读取连接批次…'; this.batchSummary.textContent = '';
  this.domainList.replaceChildren(E('p', { 'class': 'pa-caption' }, '正在读取所选连接批次…'));
  this.updateDomainControls();
  return this.refreshDomains(true);
 },

 startDomainBatch: function() {
  if (this.batchStartButton.disabled || this.batchPending) return Promise.resolve();
  var self = this;
  this.batchPending = true; this.updateDomainControls();
  return rpcRequest(callDomainBatchStart).then(function(data) {
   self.incidentId = '';
   self.batchNotice.textContent = '已新建 ' + localTime(data.time) + ' 的监控批次，请发起本次连接。';
   return self.selectBatch(data.id);
  }).catch(function(error) {
   self.batchNotice.textContent = '新建批次失败：' + error.message;
  }).finally(function() { self.batchPending = false; self.updateDomainControls(); });
 },

 updateDomainControls: function() {
  if (!this.copyAllDomains) return;
  var data = this.domainData || {}, rows = data.domains || [], observer = data.observer || {};
  var pending = this.domainSelectionPending || this.copyPending;
  this.copyAllDomains.disabled = !!pending || !domainNames(rows, false).length;
  this.copyFailedDomains.disabled = !!pending || !domainNames(rows, true).length;
  this.batchStartButton.disabled = this.readonly || !!this.batchPending || !!this.domainSelectionPending || !observer.fresh || observer.state !== 'observing' ||
   !!(data.batch && data.batch.state === 'pending');
 },

 copyDomainRules: function(failed) {
  if (this.domainSelectionPending || this.copyPending) return Promise.resolve();
  var names = domainNames((this.domainData || {}).domains || [], failed), self = this;
  if (!names.length) return Promise.resolve();
  var text = names.join('\n') + '\n';
  this.copyPending = true; this.updateDomainControls();
  this.domainRuleText.value = text;
  return copyText(text).then(function() {
   self.domainCopyNotice.textContent = '已复制' + (failed ? '失败' : '全部') + '域名，共 ' + names.length + ' 行，可粘贴到 PassWall 规则列表。';
   self.domainRulePreview.hidden = true;
  }).catch(function() {
   self.domainCopyNotice.textContent = '浏览器剪贴板权限待确认，选中下方规则后按 Ctrl+C 或 ⌘C 复制。';
   self.domainRulePreview.hidden = false; self.domainRuleText.focus(); self.domainRuleText.select();
  }).finally(function() { self.copyPending = false; self.updateDomainControls(); });
 },

 domainRuleActions: function(domain) {
  var self = this, names = policyHosts(this.policyInputs.domains.value), direct = policyHosts(this.policyInputs.exclusions.value);
  var excluded = policyMatches(domain, direct), included = policyMatches(domain, names);
  return E('div', {}, [ E('div', { 'class': 'pa-domain-rule' }, (Object.keys(this.policyTouched).length ||
   (this.policyData || {}).pending_apply || !(this.policyData || {}).loaded ? '草稿 · ' : '设备名单 · ') +
   (excluded ? '直连名单' : included ? '代理名单' : '默认直连')),
   E('div', { 'class': 'pa-domain-row-actions' }, [['domains', '加入代理'], ['remove', '移出代理']].map(function(item) {
    var chosen = item[0] === 'domains' ? included && !excluded : excluded && names.indexOf(domain) < 0;
    var disabled = self.readonly || self.policyPending || self.pending || !!(self.latest.job || {}).busy ||
     !(self.policyData || {}).available || !!self.policyRequest || chosen || !validHost(domain);
    var button = E('button', { type: 'button', 'class': buttonClass(), click: function() {
     if (item[0] === 'remove') self.removeDomainFromPolicy(domain);
     else self.addDomainToPolicy(domain, item[0]);
    } }, chosen ? (item[0] === 'domains' ? '已加入代理' : '已转为直连') : item[1]);
    button.disabled = !!disabled; button.dataset.chosen = String(chosen); button.dataset.domain = domain;
    self.domainActionButtons.push(button); return button;
   })) ]);
 },

 saveLogging: function(feature) {
  var self = this;
  this.loggingPending = true; this.update(this.latest);
  return rpcRequest(function() {
   return callLogging((feature === 'proxy' ? self.proxyLogMode : self.logMode).value,
    self.domainEnabled.checked ? 1 : 0, self.logTag.value.trim());
  }).then(function(data) {
   self.loggingTouched = false;
   self.update(Object.assign({}, self.latest, { logging: data.logging }));
   self.loggingNotice.textContent = self.proxyLoggingNotice.textContent =
    data.observer_warning || '日志策略已保存，后台将在 10 秒内应用。';
   return Promise.all([ self.refreshDetails(), self.refreshDomains(true) ]);
  }).catch(function(error) {
   self.loggingNotice.textContent = self.proxyLoggingNotice.textContent = '日志策略保存失败：' + error.message;
  }).finally(function() { self.loggingPending = false; self.update(self.latest); });
 },

 markIncident: function() {
  var self = this;
  this.incidentPending = true; this.update(this.latest);
  return rpcRequest(function() { return callIncident(self.incidentNote.value.trim() || 'Portal 连接失败'); }).then(function(data) {
   self.incidentId = data.id;
   self.selectTab('monitor');
   self.incidentNotice.textContent = '已标记 ' + localTime(data.time) + '，正在收集后 15 秒的观测证据。';
   return self.refreshDomains(true);
  }).catch(function(error) {
   self.incidentNotice.textContent = '失败标记保存失败：' + error.message;
  }).finally(function() { self.incidentPending = false; self.update(self.latest); });
 },

 renderDomains: function(data) {
  if (this.domainSelectionPending) return;
  var self = this, observer = data.observer || {}, rows = data.domains || [], batch = data.batch;
  this.domainActionButtons = [];
  var names = { observing: observer.fresh ? '正在观察设备域名' : '观察状态待确认',
   disabled: '域名记录已关闭', waiting: '等待设备配对与网桥就绪', stopped: '观察服务已停止' };
  this.domainState.textContent = (names[observer.state] || '等待观察服务') + ' · 保留 ' + (data.batches || []).length + ' 个连接批次' +
   (data.logging && data.logging.tag ? ' · 标记：' + data.logging.tag : '') +
   (observer.error ? '。' + observer.error : '');
  var health = observer.health || {}, io = observer.observability || {};
  this.domainHealth.textContent = '观测丢弃 ' + Number(observer.capture_drops || 0) +
   ' · 限速舍弃 ' + Number(observer.rate_drops || 0) + ' · 缓存舍弃 ' + Number(health.capacity_drops || 0) +
   ' · 解析舍弃 ' + Number(health.malformed || 0) + ' · 报文截断 ' + Number(health.snaplen_limited || 0) +
   ' · 合并重复 ' + Number(health.suppressed_events || 0) + ' · 写入错误 ' + Number(io.write_errors || 0) +
   (observer.snapshot_truncated || batch && batch.truncated ? ' · 部分历史上下文已精简' : '') +
   (io.last_error ? '。' + io.last_error : '。');
  var allNames = domainNames(rows, false), failedNames = domainNames(rows, true);
  this.batchTitle.textContent = this.batchId === 'inventory' ? '历史累计清单' : batch ? localTime(batch.time) : '等待首个连接批次';
  this.batchSummary.textContent = batch ?
   ({collecting:'本批次正在采集', archived:'本批次已归档', pending:'本批次正在准备采集'}[batch.state] || '本批次记录') +
    ' · ' + allNames.length + ' 个域名 · ' + failedNames.length + ' 个失败解析域名' +
    (batch.ended_at ? ' · 结束 ' + localTime(batch.ended_at) : '') +
    (batch.truncated ? '。记录容量已达上限，明细优先保留异常。' : '') :
   this.batchId === 'inventory' ? '展示已保存的累计域名与解析证据。' : '由 Portal 或 PS5 发起连接，域名活动会自动创建批次。';
  var totals = batch && batch.traffic || {}, unknown = batch && batch.unattributed_traffic || {};
  var totalProxy = Number(totals.proxy_upload_bytes || 0) + Number(totals.proxy_download_bytes || 0);
  this.batchTrafficSummary.replaceChildren.apply(this.batchTrafficSummary, [
   ['核心上传', totals.upload_bytes], ['核心下载', totals.download_bytes], ['代理累计', totalProxy],
   ['代理采样速率', totals.fresh ? totals.proxy_rate : null]
  ].map(function(item, index) {
   return E('div', {}, [E('b', {}, item[0]), E('span', {},
    totals.sampled ? item[1] !== null ? formatBytes(item[1]) + (index === 3 ? '/s' : '') : '—' : '等待样本')]);
  }));
  this.domainTrafficNotice.textContent = (observer.traffic || {}).limit || '流量按本批次累计，来源为本机已有连接统计接口。设备直达流量与短连接影响覆盖。';
  this.domainTrafficNotice.textContent +=
   (batch && batch.state === 'collecting' && (observer.traffic || {}).state === 'waiting' ? ' 当前等待核心流量样本。' : '') +
   (totals.sampled && !totals.fresh ? ' 当前显示已保存的采样累计。' : '') +
   (totals.coverage_limited ? ' 部分连接以首个采样值为起点；短连接或采样中断会影响覆盖。' : '');
  var unknownProxy = Number(unknown.proxy_upload_bytes || 0) + Number(unknown.proxy_download_bytes || 0);
  this.domainTrafficUnassigned.textContent = unknownProxy ? '域名归属待确认的代理流量 · ' + formatBytes(unknownProxy) + '，已计入本批次合计。' : '';
  if (batch && batch.traffic_details_trimmed) this.domainTrafficUnassigned.textContent += ' 精简域名明细涉及的流量保留在批次合计中。';
  this.domainTrafficUnassigned.setAttribute('data-error', String(unknownProxy >= largeProxyBytes));
  this.domainNavNode.textContent = (data.batches || []).length + ' 个批次 · ' + (observer.state === 'observing' ? '采集中' : '已保存记录');
  var batchChoices = [{value:'', label:'最近连接批次 · 自动跟随'}].concat((data.batches || []).map(function(item) {
   return {value:item.id, label:localTime(item.time) + ' · ' + item.domain_count + ' 个域名 / ' + item.failed_count + ' 个失败',
    detail: (item.state === 'collecting' ? '采集中' : item.state === 'pending' ? '准备采集' : '已归档') +
     (item.traffic && item.traffic.sampled ? ' · 代理 ' + formatBytes(Number(item.traffic.proxy_upload_bytes || 0) + Number(item.traffic.proxy_download_bytes || 0)) : '')};
  }));
  if (data.inventory_count) batchChoices.push({value:'inventory', label:'历史累计清单', detail:'跨批次保存的域名记录'});
  this.batchSelect.choicePicker.setOptions(batchChoices);
  this.batchSelect.choicePicker.setValue(this.batchId || '');
  this.domainAllButton.textContent = '全部域名 ' + allNames.length;
  this.domainFailedButton.textContent = '失败解析 ' + failedNames.length;
  this.domainAllButton.setAttribute('aria-pressed', String(!this.domainOnlyProblems.checked));
  this.domainFailedButton.setAttribute('aria-pressed', String(this.domainOnlyProblems.checked));
  this.updateDomainControls();
  var incidentChoices = [{value:'', label:'选择历史失败回溯'}].concat((data.incidents || []).map(function(item) {
   return {value:item.id, label:localTime(item.time) + ' · ' + item.note};
  }));
  this.incidentSelect.choicePicker.setOptions(incidentChoices);
  this.incidentSelect.choicePicker.setValue(this.incidentId || '');
  var search = this.domainSearch.value.trim().toLowerCase();
  var filtered = rows.filter(function(row) {
   return (!search || (row.domain || '').indexOf(search) >= 0) &&
    (!self.domainOnlyProblems.checked || dnsFailed(row)) &&
    (!self.domainOnlyProxy.checked || proxyRelated(row)) &&
    (!self.domainOnlyLargeProxy.checked || rowBytes(row, true) >= largeProxyBytes);
  });
  filtered.sort(function(a, b) {
   var sort = self.domainTrafficSort.value;
   return (sort === 'recent' ? Number(b.last_epoch || 0) - Number(a.last_epoch || 0) :
    rowBytes(b, sort === 'proxy') - rowBytes(a, sort === 'proxy')) ||
    Number(b.last_epoch || 0) - Number(a.last_epoch || 0) || a.domain.localeCompare(b.domain);
  });
  var table = E('table', { 'class': 'table' }, [ E('thead', {}, E('tr', { 'class': 'tr' },
   [ '设备 / 域名', '解析记录 / 地址', '本批次核心流量', '本批次代理流量', '透明代理清单', '最近出现' ].map(function(title) { return E('th', { 'class': 'th' }, title); }))),
   E('tbody', {}, filtered.map(function(row) {
    var counts = row.counts || {}, observed = Object.keys(evidenceNames).filter(function(key) {
     return key !== 'new_domain' && counts[key];
    }).map(function(key) { return evidenceNames[key] + ' ' + counts[key]; });
    var addresses = (row.addresses || []).map(function(item) {
     return item.address + (item.ttl !== undefined ? ' · TTL ' + item.ttl + ' 秒' : '');
    }).join('\n');
    var failed = dnsFailed(row);
    var traffic = row.traffic || {}, proxyBytes = rowBytes(row, true);
    var qtypes = (row.qtypes || []).map(function(value) { return ({1:'A',28:'AAAA',5:'CNAME',65:'HTTPS'}[value] || 'TYPE' + value); });
    return E('tr', { 'class': 'tr' }, [ E('td', { 'class': 'td' }, [ E('div', { 'class': 'pa-domain-name', title: addresses },
     [ (row.device === 'ps5' ? 'PS5' : 'Portal') + ' · ' + row.domain,
      row.new_since_tag ? E('span', { 'class': 'pa-domain-new' }, '本轮新增') : E('span') ]),
     E('div', { 'class': 'pa-muted' }, row.category_label || '其他'),
     E('div', { 'class': 'pa-domain-time' }, '首次 ' + localTime(row.first_seen)) ]),
     E('td', { 'class': 'td ' + (failed ? 'pa-domain-problem' : '') }, [
      E('div', {}, (failed ? '本批次解析失败 ' + Number(row.dns_failures || (counts.dns_error || 0) + (counts.dns_timeout || 0) || 1) + ' 次。' : '') +
       (observed.join(' · ') || '首次可见')),
      qtypes.length ? E('div', { 'class': 'pa-caption' }, '查询类型 · ' + qtypes.join(' / ')) : E('span'),
      row.last_rcode ? E('div', { 'class': 'pa-caption' }, '失败响应 · ' +
       ({2:'SERVFAIL',3:'NXDOMAIN',5:'REFUSED'}[row.last_rcode] || 'DNS ' + row.last_rcode)) : E('span'),
      addresses ? E('div', { 'class': 'pa-domain-time', style: 'white-space:pre-wrap' }, addresses) : E('span') ]),
     E('td', { 'class': 'td pa-domain-total', 'data-title': '本批次核心流量' }, [
      E('div', { 'class': 'pa-traffic-value' }, traffic.sampled ? formatBytes(rowBytes(row, false)) : '等待样本'),
      traffic.sampled ? E('div', { 'class': 'pa-domain-time' }, '↑ ' + formatBytes(traffic.upload_bytes) + ' · ↓ ' + formatBytes(traffic.download_bytes)) : E('span'),
      Number(traffic.direct_upload_bytes || 0) + Number(traffic.direct_download_bytes || 0) ? E('div', { 'class': 'pa-domain-time' },
       '直连累计 · ' + formatBytes(Number(traffic.direct_upload_bytes || 0) + Number(traffic.direct_download_bytes || 0))) : E('span'),
      traffic.fresh ? E('div', { 'class': 'pa-domain-time' }, '采样 ' + formatBytes(Number(traffic.upload_rate || 0) + Number(traffic.download_rate || 0)) + '/s') : E('span'),
      traffic.coverage_limited ? E('div', { 'class': 'pa-domain-time' }, '部分采样') : E('span') ]),
     E('td', { 'class': 'td pa-domain-proxy ' + (proxyBytes >= largeProxyBytes ? 'pa-domain-heavy' : ''), 'data-title': '本批次代理流量' }, [
      E('div', { 'class': 'pa-traffic-value' }, traffic.sampled ? formatBytes(proxyBytes) : '等待样本'),
      traffic.has_proxy ? E('div', { 'class': 'pa-domain-time' }, '↑ ' + formatBytes(traffic.proxy_upload_bytes) + ' · ↓ ' + formatBytes(traffic.proxy_download_bytes)) : E('span'),
      traffic.has_proxy ? E('div', { 'class': 'pa-domain-time' }, '本批次曾走代理') :
       traffic.proxy_rules_seen ? E('div', { 'class': 'pa-domain-time' }, '本批次曾在代理名单') : E('span'),
      traffic.last_route && traffic.last_route !== 'unknown' ? E('div', { 'class': 'pa-domain-time' },
       (traffic.fresh ? '当前出口 · ' : '最近出口 · ') + ({proxy:'PassWall 代理',selected:'代理',previous:'此前代理',other_proxy:'PassWall 代理',direct:'直连',original:'PassWall 默认策略'}[traffic.last_route] || '待确认')) : E('span'),
      traffic.fresh ? E('div', { 'class': 'pa-domain-time' }, '代理连接 ' + Number(traffic.proxy_active_connections || 0) + ' · ' + formatBytes(traffic.proxy_rate) + '/s') : E('span'),
      proxyBytes >= largeProxyBytes ? E('strong', {}, '代理大流量 ≥100 MiB') : E('span') ]),
     E('td', { 'class': 'td' }, self.domainRuleActions(row.domain)),
     E('td', { 'class': 'td pa-domain-time' }, localTime(row.last_seen)) ]);
   })) ]);
  this.domainList.replaceChildren(filtered.length ? table : E('div', { 'class': 'pa-domain-empty' },
   rows.length ? '当前筛选条件下暂无记录。' : '完成设备配对后，由 PS5 或 Portal 发起本次连接，解析记录会显示在这里。'));
  this.domainCount.textContent = '显示 ' + filtered.length + ' 项设备域名；复制按当前所选批次去重，覆盖完整清单。';
  this.domainEvents.textContent = (batch && batch.events || []).filter(function(event) {
   return (!search || (event.domains || []).some(function(name) { return name.indexOf(search) >= 0; })) &&
    (!self.domainOnlyProblems.checked || event.kind === 'dns_error' || event.kind === 'dns_timeout' || event.dns_unreachable);
  }).map(function(event) {
   return localTime(event.time) + ' ' + (event.device === 'ps5' ? 'PS5' : 'Portal') + ' ' +
    (evidenceNames[event.kind] || event.kind) + ' ' + (event.domains || []).join(' → ') +
    (event.qtype ? ' · ' + ({1:'A',28:'AAAA',65:'HTTPS'}[event.qtype] || 'TYPE' + event.qtype) : '') +
    (event.rcode ? ' · ' + ({2:'SERVFAIL',3:'NXDOMAIN',5:'REFUSED'}[event.rcode] || 'DNS ' + event.rcode) : '') +
    (event.address ? ' · ' + event.address : '') +
    ((event.addresses || []).length ? ' · ' + event.addresses.map(function(value) {
     return value.address + ' (TTL ' + value.ttl + ' 秒)';
    }).join('、') : '') + (event.retries ? ' · 重试 ' + event.retries + ' 次' : '');
  }).join('\n') || '本批次暂无当前筛选范围内的解析明细。';
  var selected = data.selected, evidence = selected && selected.evidence;
  this.incidentPanel.hidden = !selected;
  if (selected) {
   this.incidentTitle.textContent = localTime(selected.time) + ' · ' + selected.note;
   this.incidentSummary.textContent = '回溯前 180 秒、后 15 秒。' +
    (evidence && evidence.evidence_complete ? '观测窗口已结束。' : '正在补齐后续观测。') +
    (evidence && evidence.coverage_limited ? '采集启动时间或记录容量影响了窗口覆盖。' : '') +
    (evidence && evidence.truncated ? '部分历史上下文已精简，优先保留异常。' : '') +
    ' 下列域名按异常证据排序，结合设备错误提示确认原因。';
   var candidates = (evidence && evidence.candidates || []).map(function(item) {
    return E('div', { 'class': 'pa-domain-candidate' }, [
     E('div', {}, [ E('strong', { 'class': 'pa-domain-name' }, (item.device === 'ps5' ? 'PS5' : 'Portal') + ' · ' + item.domain),
      E('p', { 'class': 'pa-caption' }, (item.errors ? '异常 ' + item.errors + ' 次 · ' : '') +
       (item.evidence || []).map(function(kind) { return evidenceNames[kind] || kind; }).join(' / ')) ]),
     self.domainRuleActions(item.domain) ]);
   });
   this.incidentCandidates.replaceChildren.apply(this.incidentCandidates, candidates.length ? candidates :
    [ E('p', { 'class': 'pa-caption' }, '当前窗口的域名证据较少，请结合采集状态、覆盖范围和设备提示检查。') ]);
   this.incidentEvents.textContent = (evidence && evidence.events || []).map(function(item) {
    return localTime(item.time) + ' ' + (item.device === 'ps5' ? 'PS5' : 'Portal') + ' ' +
     (evidenceNames[item.kind] || item.kind) + ' ' + (item.domains || []).join('、') +
     (item.rcode ? ' · DNS ' + ({ 2: 'SERVFAIL', 3: 'NXDOMAIN', 5: 'REFUSED' }[item.rcode] || item.rcode) : '') +
     (item.address ? ' · ' + item.address + (item.port ? ':' + item.port : '') : '') +
     (item.retries ? ' · 重试 ' + item.retries + ' 次' : '') +
     (item.repeated ? ' · 合并 ' + item.count + ' 次' : '');
   }).join('\n') || '当前窗口暂无可见域名事件。';
   var coreEvidence = selected.core_evidence || {};
   if ((coreEvidence.connections || []).length) this.incidentEvents.textContent += '\n\n核心连接证据：\n' + coreEvidence.connections.map(function(row) {
    return (row.device === 'ps5' ? 'PS5' : 'Portal') + ' ' + row.domain + ' · ' + row.phase +
     ' · ' + ({proxy:'PassWall 代理',selected:'代理',direct:'直连',original:'PassWall 默认策略'}[row.route] || '出口待确认') +
     (row.failure ? ' · 上游响应待检查' : '');
   }).join('\n');
  }
 },

 refresh: function(forceDetails) {
  var self = this;
  if (forceDetails) this.refreshDetails();
  if (this.statusRequest) return this.statusRequest;
  this.statusRequest = rpcRequest(callStatus).then(function(data) {
   self.connectionError = null;
   self.update(Object.assign({}, self.latest, data));
   if (!self.detailsKnown || self.detailsRevision !== data.details_revision) self.refreshDetails();
   self.refreshLogs(); self.refreshDevices(); self.refreshDomains();
   self.refreshPolicy();
  }).catch(function(error) {
   self.connectionError = error.message;
   self.update(self.latest);
  }).finally(function() { self.statusRequest = null; });
  return this.statusRequest;
 },

 button: function(name, label, kind) {
  var self = this;
  // Pending requests and background jobs share the disabled state in update().
  var button = E('button', { type: 'button', 'class': buttonClass(kind),
   click: function() { return self.run(name); } }, label);
  this.buttons[name] = button;
  return button;
 },

 field: function(name, label, input, help) {
  var self = this;
  input.id = 'psa-' + name;
  function changed() {
   self.fieldTouched[name] = true;
   if (name !== 'address') self.renderDeviceIdentity();
   self.update(self.latest);
  }
  input.addEventListener('input', changed); input.choiceChanged = changed;
  this.fields[name] = input;
  return formField(input, label, help);
 },

 panel: function(title, content, extra, classes) {
  return E('section', { 'class': 'cbi-section pa-panel ' + (classes || '') }, E('div', { 'class': 'cbi-section-node pa-panel-body' }, [
   E('div', { 'class': 'pa-panel-head' }, [ E('h3', {}, title), extra || E('span') ])
  ].concat(content)));
 },

 navigation: function(items, registry, prefix, classes, select) {
  var self = this;
  return items.map(function(item, index) {
   var tab = E('a', { href: '#' + prefix + '-pane-' + item[0], id: prefix + '-tab-' + item[0], 'class': classes, role: 'tab',
    'aria-controls': prefix + '-pane-' + item[0], click: function(event) {
     event.preventDefault(); select.call(self, item[0], false);
    },
    keydown: function(event) {
     var position = index;
     if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault(); select.call(self, item[0], false); return;
     }
     if (event.key === 'ArrowRight') position = (index + 1) % items.length;
     else if (event.key === 'ArrowLeft') position = (index + items.length - 1) % items.length;
     else if (event.key === 'Home') position = 0;
     else if (event.key === 'End') position = items.length - 1;
     else return;
     event.preventDefault(); select.call(self, items[position][0], true);
    } }, item[1]);
   registry[item[0]] = tab;
   return E('li', { 'class': 'cbi-tab-disabled', role: 'presentation', 'data-tab': item[0] }, tab);
  });
 },

 selectTab: function(name, focus) {
  name = { stream: 'bitrate', psportal: 'proxy' }[name] || name;
  if (!this.mainTabs[name]) return;
  this.activeTab = name;
  Object.keys(this.mainTabs).forEach(function(key) {
   setTabState(this.mainTabs[key], key === name);
   this.mainPanels[key].hidden = key !== name;
  }, this);
  if (focus) this.mainTabs[name].focus();
  if (name === 'devices') this.refreshDevices(true);
  if (name === 'proxy' || name === 'monitor') this.refreshPolicy(true);
  if (name === 'monitor') this.refreshDomains(true);
  this.refreshLogs();
 },

 selectStage: function(feature, name, focus) {
  if (!this.stagePanels[feature] || !this.stagePanels[feature][name]) return;
  var logsVisible = this.activeTab === feature && this.stagePanels[feature].logs.open;
  this.activeStages[feature] = name;
  if (name === 'logs') this.stagePanels[feature].logs.open = true;
  if (this.activeTab !== feature) this.selectTab(feature);
  if (focus) this.mainTabs[feature].focus();
  if (name === 'logs' && !logsVisible) this.refreshLogs(true);
 },

 showLog: function(feature, kind) {
  this.selectStage(feature, 'logs');
  this.selectLogTab(kind || (feature === 'proxy' ? 'proxy' : 'bitrate'));
 },

 policyValues: function() {
  var self = this;
  return policyFields.map(function(key) { return self.policyInputs[key].value; }).concat([this.policyRevision || '']);
 },

 reloadPolicyLists: function() {
  var self = this;
  if (this.policyPending || this.pending || (this.latest.job || {}).busy) return Promise.resolve();
  if (this.policyRequest) return this.policyRequest.then(function() { return self.reloadPolicyLists(); });
  this.policyTouched = {}; this.policyConflict = false;
  this.policyConfigNotice.textContent = this.policyDraftState.textContent = '';
  return this.refreshPolicy(true);
 },

 refreshPolicy: function(force) {
  if (this.policyRequest) return this.policyRequest;
  if ((!force && this.activeTab !== 'proxy' && this.activeTab !== 'monitor') || this.policyPending) return Promise.resolve();
  if (!force && Date.now() < (this.nextPolicyRead || 0)) return Promise.resolve();
  this.nextPolicyRead = Date.now() + 12000;
  var self = this;
  this.policyRequest = rpcRequest(callPolicyStatus).then(function(data) {
   self.policyData = data; self.policyEnvironmentError = false;
   var environment = data.environment || {}, config = data.config || {}, receipt = data.receipt || {};
   var state = !data.available ? '等待本机 PassWall' : data.policy_mode === 'released' ? '设备接管已解除' :
    !data.loaded ? '设备配置等待加载' : data.policy_mode === 'direct' ? '两设备全部直连' : '设备域名代理';
   self.policyState.textContent = self.proxyNavNode.textContent = state;
   self.policyEnvironment.textContent = '分流核心 · ' + (environment.selected_core || '选择本机代理出口后确定') +
    ' · 配置由 PassWall 原生生成';
   self.policyRequirements.textContent = (data.warnings || []).join('；');
   self.policyBlockers.textContent = (data.blockers || []).join('；') ||
    (data.available && !data.devices_ready ? '在设备配置确认 Portal 和 PS5 后，应用设备接管。' : '');
   self.policyBlockers.hidden = !self.policyBlockers.textContent;
   var touched = Object.keys(self.policyTouched).length;
   self.policyNodePicker.setOptions((data.nodes || []).map(function(node) {
    return {value:node.id,label:node.label,detail:(node.core || '其他类型') + ' · ' + (node.protocol || '') +
     (node.reason ? ' · ' + node.reason : ''),available:node.available !== false};
   }));
   if (!touched && data.available) {
    policyFields.forEach(function(key) { self.policyInputs[key].value = typeof config[key] === 'string' ? config[key] : ''; });
    self.policyRevision = data.revision; self.policyConflict = false;
   } else if (touched && data.available) {
    if (self.policyModeRefresh) { self.policyRevision = data.revision; self.policyConflict = false; }
    else self.policyConflict = self.policyRevision !== data.revision;
   }
   self.policyModeRefresh = false;
   self.policyNodePicker.setValue(self.policyInputs.node.value);
   if (self.policyConflict) {
    self.policyConfigNotice.textContent = '设备规则或 PassWall 配置已发生外部修改，当前编辑已保留。重新读取后整理并保存。';
    self.policyConfigNotice.setAttribute('data-error', 'true');
   }
   self.policyFileCounts.textContent = '设备名单 · 代理 ' + Number((data.counts || {}).domains || 0) +
    ' 条规则 · 直连 ' + Number((data.counts || {}).exclusions || 0) + ' 条规则';
   var group = data.device_group || {};
   self.policyCoverage.textContent = ['portal', 'ps5'].map(function(role) {
    var device = group[role] || {};
    return (role === 'portal' ? 'Portal' : 'PS5') + ' · ' + (device.ip || '待确认') + ' · ' + (device.mac || '待确认 MAC');
   }).join('；');
   self.policyPendingState.textContent = data.policy_mode === 'direct' && data.loaded ?
    '两台设备全部直连，域名名单保留为下次启用分流的草稿。' : data.policy_mode === 'released' ?
    '两台设备沿用原 PassWall 策略，应用设备规则后启用专属接管。' :
    data.pending_apply ? '草稿或设备配置存在待加载修改，点击应用设备规则。' :
    '直连名单优先，代理名单使用所选出口，其余流量默认直连。';
   self.policyDraftState.textContent = touched ? '设备名单草稿正在编辑，应用设备规则后生效。' :
    data.config_source === 'empty' ? '两份名单初始为空，可手动填写或从域名监控加入。' : '';
   self.policyRulesPath.textContent = '专属规则组 · ' + (environment.rules_path || '待确认');
   self.policyAppliedTime.textContent = receipt.applied_at ? '最近应用 · ' + localTime(receipt.applied_at * 1000) : '等待应用设备接管';
   var telemetry = data.telemetry || {};
   self.policyCoreSummary.textContent = telemetry.fresh && telemetry.sampled_cores ?
    '域名流量正在按批次采样，详情见域名监控。' : telemetry.limit || '域名流量等待本机可用的连接统计接口。';
   if ((telemetry.errors || []).length) self.policyCoreSummary.textContent += ' ' + telemetry.errors.join('；');
   if (self.domainData) self.renderDomains(self.domainData);
  }).catch(function(error) {
   self.policyEnvironmentError = true;
   self.policyState.textContent = self.proxyNavNode.textContent = '设备规则读取待确认';
   self.policyBlockers.textContent = '设备规则读取失败：' + error.message; self.policyBlockers.hidden = false;
  }).finally(function() { self.policyRequest = null; self.updatePolicyControls(); });
  return this.policyRequest;
 },

 updatePolicyControls: function() {
  if (!this.policyButtons) return;
  var job = ((this.latest || {}).job || {}), data = this.policyData || {};
  var busy = !!this.policyPending || !!this.pending || !!job.busy;
  var ready = !!data.available && !!this.policyRevision && !this.policyEnvironmentError;
  var scopeReady = ready && !!data.devices_ready && !(data.blockers || []).length && !this.policyConflict;
  var node = (data.nodes || []).find(function(item) { return item.id === this.policyInputs.node.value; }, this);
  this.policyEnvironment.textContent = '分流核心 · ' + (node && node.available !== false ? node.core : '选择本机代理出口后确定') +
   ' · 配置由 PassWall 原生生成';
  this.policyButtons.save.disabled = this.readonly || busy || !ready || !!this.policyConflict;
  this.policyButtons.apply.disabled = this.readonly || busy || !scopeReady || !node || node.available === false;
  this.policyButtons.direct.disabled = this.readonly || busy || !scopeReady || (data.policy_mode === 'direct' && data.loaded);
  this.policyButtons.release.disabled = this.readonly || busy || !ready || !data.can_release || !!this.policyConflict;
  this.policyButtons.reload.disabled = busy || !!this.policyRequest;
  this.policyButtons.cancel.hidden = !job.busy || proxyActions.indexOf(job.action) < 0;
  this.policyButtons.cancel.disabled = this.readonly || this.pendingAction === 'stop' || !job.busy || proxyActions.indexOf(job.action) < 0;
  policyFields.forEach(function(key) { this.policyInputs[key].disabled = this.readonly || busy || !ready; }, this);
  this.policyNodePicker.sync();
  (this.domainActionButtons || []).forEach(function(button) {
   button.disabled = this.readonly || busy || !ready || !!this.policyRequest || this.domainSelectionPending ||
    button.dataset.chosen === 'true' || !validHost(button.dataset.domain);
  }, this);
 },

 policyAction: function(name) {
  if (name === 'cancel') return !this.policyButtons.cancel.disabled ? this.run('stop') : Promise.resolve();
  if (['save', 'apply', 'direct', 'release'].indexOf(name) < 0 || this.policyButtons[name].disabled || this.policyPending ||
      this.readonly || this.pending || !!(this.latest.job || {}).busy) return Promise.resolve();
  var self = this, values = this.policyValues(), revision = this.policyRevision;
  this.policyPending = true; this.update(this.latest);
  return rpcRequest(function() {
   if (name === 'direct') return callPolicyDirect(revision);
   if (name === 'release') return callPolicyRelease(revision);
   return (name === 'save' ? callPolicySave : callPolicyApply).apply(null, values);
  }).then(function(result) {
   if (name === 'save') {
    self.policyTouched = {}; self.policyConflict = false; self.policyRevision = result.revision;
    policyFields.forEach(function(key) { self.policyInputs[key].value = result.config[key]; });
    self.policyNodePicker.setValue(result.config.node);
   }
   self.policyNotice.textContent = self.policyConfigNotice.textContent = name === 'save' ? result.notice :
    '正在' + ({apply:'应用设备规则',direct:'将两设备切换为全部直连',release:'解除设备接管'}[name]) + '，请等待任务完成。';
   self.policyNotice.setAttribute('data-error', 'false'); self.policyConfigNotice.setAttribute('data-error', 'false');
   if (name !== 'save') self.selectStage('proxy', 'runtime');
  }).catch(function(error) {
   self.policyNotice.textContent = self.policyConfigNotice.textContent = error.message;
   self.policyNotice.setAttribute('data-error', 'true'); self.policyConfigNotice.setAttribute('data-error', 'true');
  }).finally(function() {
   self.policyPending = false; self.update(self.latest);
   self.refreshPolicy(true); self.refresh();
  });
 },

 renderPolicy: function() {
  var self = this;
  this.policyInputs = {}; this.policyButtons = {}; this.policyTouched = {};
  this.policyState = E('strong', { 'class': 'pa-status-pill' }, '正在读取');
  this.policyEnvironment = E('p', { 'class': 'pa-caption' });
  this.policyRequirements = E('p', { 'class': 'pa-caption', role: 'status' });
  this.policyBlockers = E('div', { 'class': 'pa-notice alert-message notice', role: 'status', 'data-error': 'true', hidden: '' });
  this.policyCoverage = E('p', { 'class': 'pa-caption' });
  this.policyCoreSummary = E('p', { 'class': 'pa-caption', role: 'status' });
  this.policyFileCounts = E('p', { 'class': 'pa-caption' });
  this.policyPendingState = E('p', { 'class': 'pa-caption' });
  this.policyRulesPath = E('p', { 'class': 'pa-caption' });
  this.policyAppliedTime = E('p', { 'class': 'pa-caption' });
  this.policyDraftState = E('p', { 'class': 'pa-caption' });
  this.policyConfigNotice = E('p', { 'class': 'pa-caption', role: 'status', 'aria-live': 'polite' });
  this.policyNotice = E('div', { 'class': 'pa-notice alert-message notice', role: 'status', 'aria-live': 'polite' });
  function field(key, label, input, help) {
   input.id = 'psa-policy-' + key; self.policyInputs[key] = input;
   function changed() {
    self.policyTouched[key] = true;
    self.policyConfigNotice.textContent = self.policyDraftState.textContent = '设备规则草稿已调整，应用设备规则后生效。';
    self.policyConfigNotice.setAttribute('data-error', 'false');
    self.updatePolicyControls();
    if (self.domainData) self.renderDomains(self.domainData);
   }
   input.addEventListener('input', changed); input.addEventListener('change', changed); input.choiceChanged = changed;
   return formField(input, label, help);
  }
  function button(name, label, kind) {
   var node = E('button', { type: 'button', 'class': buttonClass(kind), click: function() {
    return name === 'reload' ? self.reloadPolicyLists() : self.policyAction(name);
   } }, label);
   self.policyButtons[name] = node; return node;
  }
  var nodeInput = choiceControl(luciControl('input', { type: 'hidden' }), '选择本机代理出口', false);
  this.policyNodePicker = nodeInput.choicePicker;
  var config = this.panel('两设备专属域名规则', [
   field('node', '代理出口', nodeInput, '引用 PassWall 已保存的 Xray / Sing-box 节点，分流组使用其中的实际出口。'),
   E('div', { 'class': 'pa-form' }, [
    field('domains', '代理域名', luciControl('textarea', { rows:8,maxlength:262144,spellcheck:'false' }), '初始为空，每行完整域名，默认精确匹配。'),
    field('exclusions', '直连域名', luciControl('textarea', { rows:8,maxlength:262144,spellcheck:'false' }), '初始为空，每行完整域名，直连优先。')]),
   E('p', { 'class': 'pa-caption' }, '普通域名写入为 full: 精确分流规则；domain:example.com 显式匹配主域与子域。现有注释及 geosite: 条目保留。'),
   E('div', { 'class': 'pa-actions' }, [button('save', '保存设备草稿'), button('apply', '应用设备规则', 'primary'),
    button('reload', '重新读取设备规则')]),
   E('p', { 'class': 'pa-caption' }, '应用会调用 PassWall 重新加载，现有连接可能重连。PassWall 的开机启动和 IPv6 转发沿用本机设置。'),
   this.policyDraftState, this.policyConfigNotice
  ]);
  var runtime = this.panel('Portal / PS5 专属接管', [
   this.policyCoverage, this.policyEnvironment, this.policyFileCounts, this.policyPendingState, this.policyRequirements,
   E('p', { 'class': 'pa-caption' }, '局域网串流与默认出口保持直连；两份名单仅供当前设备组使用。'),
   this.policyNotice, this.policyBlockers,
   E('div', { 'class': 'pa-actions' }, [button('direct', '两设备全部直连'), button('release', '解除设备接管'),
    E('a', { 'class': buttonClass(), href:L.url ? L.url('admin','services','passwall','acl') :
     '/cgi-bin/luci/admin/services/passwall/acl' }, 'PassWall 访问控制'), button('cancel', '取消接管任务')])
  ], this.policyState);
  return {config:config,runtime:runtime,diagnostics:E('div', {}, [this.policyCoreSummary,this.policyRulesPath,this.policyAppliedTime])};
 },

 run: function(name) {
  if (this.readonly && name !== 'diagnostics' && name !== 'proxy_diagnostics') return Promise.resolve();
  if (name === 'logging') return this.saveLogging('bitrate');
  if (name === 'proxy_logging') return this.saveLogging('proxy');
  if (name === 'incident') return this.markIncident();
  if (this.buttons[name] && this.buttons[name].disabled && name !== 'stop') return Promise.resolve();
  var self = this, request;
  if (name === 'device_save') {
   this.deviceSaveError = null;
   var deviceValues = ['bridge', 'portal_ip', 'ps5_ip'].map(function(key) { return self.fields[key].value.trim(); });
   if (deviceValues.some(function(value) { return !value; })) {
    this.deviceSaveError = '请选择 LAN 网桥并填写 Portal / PS5 的内网地址。';
    this.update(this.latest); return Promise.resolve();
   }
   request = function() { return callDeviceSave.apply(null, deviceValues); };
  }
  else if (name === 'configure') {
   var config = this.latest.config || {};
   var values = [config.bridge || '', this.fields.address.value.trim(), config.ps5_ip || '', config.portal_ip || ''];
   if (values.some(function(value) { return !value; })) {
    this.bitrateConfigNotice.textContent = '确认设备配置后，填写中继独立地址并保存。'; return Promise.resolve();
   }
   values.push(this.selectedProfile);
   request = function() { return callConfigure.apply(null, values); };
  }
  else if (name === 'profile') request = function() { return callProfile(self.selectedProfile); };
  else if (name === 'start') request = function() { return callStart(self.autostart.checked ? 1 : 0); };
  else if (name === 'diagnostics') request = callDiagnostics;
  else if (name === 'proxy_diagnostics') request = callProxyDiagnostics;
  else request = calls[name];
  var pendingToken = {};
  this.pending = true; this.pendingAction = name; this.pendingToken = pendingToken;
  this.update(this.latest);
  return rpcRequest(request).then(function(result) {
   if (name === 'diagnostics' || name === 'proxy_diagnostics') {
    if (name === 'diagnostics') {
     delete result.domain_diagnostics;
     result.privacy = '诊断包含码率增强配置、运行计数、测试有效性与恢复状态；设备地址与 MAC 已遮盖。';
    }
    var url = URL.createObjectURL(new Blob([ JSON.stringify(result, null, 2) + '\n' ], { type: 'application/json' }));
    var link = E('a', { href: url, download: name === 'proxy_diagnostics' ? 'ps-accel-proxy-diagnostics.json' : 'ps-accel-bitrate-diagnostics.json' });
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(function() { URL.revokeObjectURL(url); }, 1000);
   }
   if (name === 'start') self.bootTouched = false;
   if (name === 'device_save') self.deviceNotice.textContent = '正在确认设备地址与 MAC，请等待保存结果。';
   else if (name === 'doctor') self.showLog('bitrate');
   else if (name !== 'diagnostics' && name !== 'proxy_diagnostics' && name !== 'stop') self.selectStage('bitrate', 'runtime');
   return self.refresh(name !== 'diagnostics' && name !== 'proxy_diagnostics');
  }).catch(function(error) {
   if (name === 'device_save') self.deviceSaveError = error.message || String(error);
   ui.addNotification(null, E('p', error.message || String(error)), 'danger');
  }).finally(function() {
   if (self.pendingToken === pendingToken) {
    self.pending = false; self.pendingAction = null;
   }
   self.update(self.latest);
  });
 },

 updateQuality: function(data) {
  var quality = data.quality || {}, relay = quality.relay || {}, advice = quality.advice || {};
  var labels = { waiting: '等待反馈', collecting: '采集中', healthy: '反馈平稳', degraded: '持续丢失',
   relay_overload: '中继待检查', stale: '数据过期', unsupported: '格式待适配',
   disconnected: '连接已结束', stopped: '等待启动', unavailable: '采集异常' };
  var state = data.running ? quality.state || 'waiting' : 'stopped';
  var fresh = !!(data.running && data.quality && quality.report_fresh !== false &&
   (data.observability || {}).status_fresh !== false && data.state_known !== false && !this.connectionError);
  if (data.running && !fresh) state = 'stale';
  var feedbackFresh = fresh && quality.feedback_fresh === true;
  var loss = quality.loss_percent;
  this.qualityNode.textContent = feedbackFresh && typeof loss === 'number' && isFinite(loss) ? loss.toFixed(2) + '%' : labels[state] || '等待反馈';
  this.qualityDetail.textContent = feedbackFresh ? (labels[state] || '采集中') + ' · 近 12 秒 · 接收 ' +
   Number(quality.received || 0) + ' / 丢失 ' + Number(quality.lost || 0) + ' · 坏帧报告 ' +
   Number(quality.corrupt_reports || 0) + ' / 关键帧请求 ' + Number(quality.idr_requests || 0) :
   state === 'unsupported' ? '已收到质量报文，等待适配客户端反馈格式。' : '等待当前连接的有效接收／丢失反馈。';
  var p95 = relay.processing_p95_ms;
  this.relayQualityNode.textContent = fresh && typeof p95 === 'number' && isFinite(p95) ? '≤ ' + p95 + ' ms' : '—';
  this.relayQualityDetail.textContent = fresh ? '近 12 秒转发处理 p95 · ' +
   (relay.receive_stats_available ? '接收队列丢包 ' + Number(relay.dropped || 0) + '（累计 ' + Number(relay.dropped_total || 0) + '）' :
    '接收队列统计待支持') : '等待中继处理与接收队列采样。';
  var kind = advice.kind || 'wait', reason = advice.reason || 'waiting_feedback';
  var profile = quality.requested_profile || (data.config || {}).profile || '65';
  var message = '等待 Portal 回传质量信息，积累至少 6 秒有效样本后评估档位。';
  if (!data.running) {
   kind = 'stopped'; message = '启动增强并重新连接 Portal，开始采集当前连接的质量。';
  } else if (!fresh || state === 'stale') {
   kind = 'wait'; message = '质量数据已过期，等待新反馈后重新评估档位。';
  } else if (state === 'unsupported') {
   kind = 'wait'; message = '客户端反馈格式待适配，继续结合 Portal 画面与按键表现观察。';
  } else if (state === 'unavailable') {
   kind = 'unavailable'; message = '质量采集暂时异常，转发与恢复继续按服务状态运行。';
  } else if (kind === 'check_relay') {
   message = reason === 'receive_drops' ? '中继接收队列出现丢包，优先检查路由器负载与并行任务，再复测当前档位。' :
    '中继转发处理出现多次停顿，优先检查路由器负载与并行任务，再复测当前档位。';
  } else if (data.mode === 'baseline' || kind === 'baseline') {
   kind = 'baseline'; message = '连接测试正在采集质量；正式启动增强后，再评估当前档位。';
  } else if (reason === 'session_ended') {
   kind = 'wait'; message = '本次连接已结束，等待重新连接后采集。';
  } else if (reason === 'waiting_startup') {
   kind = 'wait'; message = '已采集当前串流质量。重新连接 Portal，观察到当前档位的新连接后再评估降档。';
  } else if (kind === 'lower' && feedbackFresh && advice.profile) {
   if (profile !== (data.config || {}).profile) {
    kind = 'wait'; message = '档位正在切换，等待新连接的质量反馈。';
   } else {
    var evidenceLoss = typeof advice.loss_percent === 'number' ? '，报告丢失 ' + advice.loss_percent.toFixed(2) + '%' : '';
    message = '客户端连续 ' + Number(advice.sustained_seconds || 6) + ' 秒出现丢失' + evidenceLoss +
     (reason === 'loss_and_frames' ? '，伴随坏帧或关键帧请求' : '') + '。建议试用 ' + advice.profile +
     ' Mbps：在码率配置中选择并保存，重新连接 Portal 后比较画面与按键。';
   }
  } else if (kind === 'minimum' && feedbackFresh) {
   message = '当前 ' + profile + ' Mbps 已是最低档位；优先改善无线信号、减少同一 AP 争用后重连复测。';
  } else if (kind === 'keep' && feedbackFresh) {
   message = '近期客户端反馈平稳，继续使用 ' + profile + ' Mbps，并结合 Portal 画面与按键表现观察。';
  } else if (reason === 'collecting_evidence') {
   message = '正在积累质量样本；持续丢失或丢失伴随坏帧时，会建议试用下一低档。';
  }
  this.qualityAdvice.textContent = message;
  this.qualityAdvice.setAttribute('data-advice', kind);
 },

 update: function(data) {
  if (!data || !data.ok) return;
  var previousConfig = (this.latest || {}).config || {};
  var job = data.job || {}, config = data.config || {}, env = data.environment || {};
  var featureJobs = data.feature_jobs || {};
  var relayJob = featureJobs.bitrate || (jobFeature(job.action) === 'bitrate' ? job : {});
  var proxyJob = featureJobs.proxy || (jobFeature(job.action) === 'proxy' ? job : {});
  var deviceJob = featureJobs.devices || (jobFeature(job.action) === 'devices' ? job : {});
  if (this.selectedProfile === previousConfig.profile) this.selectedProfile = config.profile || '65';
  if (job.action === 'profile' && !job.busy && job.applied_profile && job.id !== this.appliedJob) {
   this.selectedProfile = job.applied_profile;
   this.appliedJob = job.id;
  }
  this.latest = data;
  this.scopeNodes.forEach(function(nodes) {
   nodes.portal.textContent = config.portal_ip || '等待配置'; nodes.ps5.textContent = config.ps5_ip || '等待配置';
  });
  this.updatePolicyControls();
  this.updateDomainControls();
  if (proxyActions.indexOf(proxyJob.action) >= 0) {
   if (proxyJob.busy) this.policyConfigNotice.textContent = this.policyNotice.textContent = actionNames[proxyJob.action] + '中，请等待完成。';
   else if (proxyJob.id !== this.policyJob) {
    this.policyJob = proxyJob.id;
    if (proxyJob.state === 'complete') {
     if (proxyJob.action === 'psportal_apply') { this.policyTouched = {}; this.domainActionNotice.hidden = true; }
     else this.policyModeRefresh = true;
     this.policyConflict = false;
    }
    this.policyConfigNotice.textContent = this.policyNotice.textContent = proxyJob.state === 'failed' ? proxyJob.error || '设备接管失败，请查看任务日志。' :
     proxyJob.state === 'cancelled' ? '设备接管任务已取消，原策略已恢复。' : proxyJob.pending_apply ?
     '设备配置已保存，PassWall 启动后加载。' : ({psportal_apply:'两设备域名规则已应用，其余流量默认直连。',
      psportal_direct:'Portal 和 PS5 已切换为全部直连。',psportal_release:'设备接管已解除，两台设备恢复原 PassWall 策略。'}[proxyJob.action]);
    this.policyNotice.setAttribute('data-error', String(proxyJob.state === 'failed'));
    this.policyConfigNotice.setAttribute('data-error', String(proxyJob.state === 'failed'));
    this.nextPolicyRead = 0; this.refreshPolicy(true);
   }
  }
  this.updatePolicyControls();
  if (relayJob.action === 'configure' && relayJob.state === 'complete' && relayJob.id !== this.configuredJob) {
   delete this.fieldTouched.address; this.configuredJob = relayJob.id;
  }
  if (deviceJob.action === 'device_save' && deviceJob.state === 'complete' && deviceJob.id !== this.deviceConfiguredJob) {
   ['bridge', 'portal_ip', 'ps5_ip'].forEach(function(key) { delete this.fieldTouched[key]; }, this);
   this.deviceConfiguredJob = deviceJob.id; this.nextDeviceRead = 0;
   if (this.activeTab === 'devices') this.refreshDevices(true);
  }
  Object.keys(this.fields).forEach(function(key) {
   var input = this.fields[key];
   if (!this.fieldTouched[key] && typeof config[key] === 'string' && input.value !== config[key]) {
    if (key === 'bridge' && !input.choicePicker && config[key] && !Array.prototype.some.call(input.options, function(option) {
     return option.value === config[key];
    })) input.appendChild(E('option', { value: config[key] }, config[key]));
    input.value = config[key];
   }
  }, this);
  var busy = !!job.busy || !!this.pending || !!this.policyPending;
  var locked = this.readonly || busy || !!this.connectionError || data.state_known === false || this.detailsKnown === false;
  var blocked = !!(data.running || data.engine_alive || data.recovery_required || data.foreign_relay || job.orphan_active);
  var profileBlocked = !!(data.recovery_required || data.foreign_relay ||
   (data.running && data.mode !== 'active') || (data.engine_alive && !data.running) || job.orphan_active);
  var deviceBlocked = locked || blocked || !!(this.deviceData || {}).proxy_enabled;
  Object.keys(this.fields).forEach(function(key) {
   this.fields[key].disabled = key === 'address' ? locked || blocked : deviceBlocked;
   if (this.fields[key].choicePicker) this.fields[key].choicePicker.sync();
  }, this);
  this.deviceRefreshButton.disabled = !!this.deviceRequest;
  var devicesReady = !!config.portal_ip && !!config.ps5_ip && data.devices_configured !== false;
  this.buttons.device_save.disabled = deviceBlocked;
  var addressChanged = this.fields.address.value.trim() !== (config.address || '');
  this.buttons.configure.hidden = !!data.configured && !addressChanged;
  this.buttons.profile.hidden = !data.configured || addressChanged;
  this.profileButtons.forEach(function(button) {
   button.disabled = locked || profileBlocked;
   var selected = button.dataset.profile === this.selectedProfile;
   button.setAttribute('aria-checked', String(selected));
   button.setAttribute('class', 'pa-profile btn cbi-button ' +
    (selected ? 'cbi-button-action important' : 'cbi-button-neutral'));
   button.tabIndex = selected ? 0 : -1;
  }, this);
  this.buttons.configure.disabled = locked || blocked || !devicesReady;
  this.buttons.profile.disabled = locked || profileBlocked || !data.configured || this.selectedProfile === config.profile;
  this.buttons.profile.textContent = data.running ? '保存并自动重启' : '保存码率';
  this.buttons.start.disabled = locked || blocked || !devicesReady || !data.configured;
  this.buttons.doctor.disabled = this.readonly || busy;
  this.buttons.repair.disabled = !!(this.readonly || busy || data.running || data.engine_alive || data.foreign_relay || job.orphan_active);
  this.buttons.stop.disabled = this.readonly || this.pendingAction === 'stop' ||
   (job.busy && jobFeature(job.action) !== 'bitrate') ||
   !(job.busy || this.pending || data.running || data.engine_alive || job.orphan_active || data.recovery_required ||
     job.state === 'failed' || this.connectionError || data.state_known === false);
  this.buttons.diagnostics.disabled = this.pendingAction === 'diagnostics';
  this.buttons.proxy_diagnostics.disabled = this.pendingAction === 'proxy_diagnostics';
  this.buttons.logging.disabled = this.buttons.proxy_logging.disabled = this.readonly || !!this.loggingPending;
  this.buttons.incident.disabled = this.readonly || !!this.incidentPending;
  this.logMode.disabled = this.proxyLogMode.disabled = this.domainEnabled.disabled = this.logTag.disabled = this.buttons.logging.disabled;
  this.logMode.choicePicker.sync(); this.proxyLogMode.choicePicker.sync();
  this.incidentNote.disabled = this.buttons.incident.disabled;
  if (!this.loggingTouched) {
   var preferences = data.logging || { mode: 'compact', domains: true, tag: '' };
   this.logMode.choicePicker.setValue(preferences.mode); this.proxyLogMode.choicePicker.setValue(preferences.mode); this.domainEnabled.checked = preferences.domains;
   this.logTag.value = preferences.tag || '';
  }
  this.autostart.disabled = locked || data.running;
  if (!this.bootTouched) this.autostart.checked = !!data.autostart;

  var state = data.running ? (data.mode === 'baseline' ? '连接测试中' : '运行中') : '已停止';
  if (relayJob.busy) state = (actionNames[relayJob.action] || '操作') + '中';
  if (relayJob.busy && relayJob.action === 'profile') state = profilePhases[relayJob.phase] || '正在应用码率';
  if (relayJob.busy && (relayJob.action === 'stop' || relayJob.action === 'repair'))
   state = profilePhases[relayJob.phase] || '正在停止与恢复';
  if (relayJob.stopping) state = '正在恢复';
  if (!relayJob.busy && data.recovery_required) state = '待恢复';
  if (!relayJob.busy && data.cleanup_pending) state = '清理待重试';
  if (data.state_known === false) state = '状态待确认';
  if (this.connectionError) state = '状态连接中断';
  if (data.foreign_relay) state = '其他中继占用';
  this.stateNode.textContent = state;
  this.bitrateNavNode.textContent = (config.profile || '65') + ' Mbps · ' + state;
  this.deviceState.textContent = data.devices_configured || data.configured ? '已确认' : '等待配置';
  this.deviceNavNode.textContent = data.devices_configured || data.configured ? '已确认 2 台设备' : '等待确认地址';
  var deviceMessage = '确认两台设备的内网地址，保存后供码率增强、透明代理与域名日志使用。';
  if (this.pendingAction === 'device_save') {
   this.deviceState.textContent = this.deviceNavNode.textContent = '正在保存设备';
   deviceMessage = '正在提交设备配置，请等待地址确认结果。';
  } else if (this.deviceSaveError) deviceMessage = this.deviceSaveError;
  else if (this.deviceError) deviceMessage = '设备列表读取失败：' + this.deviceError + '。可手动填写地址。';
  else if (deviceJob.action === 'device_save') {
   if (deviceJob.busy) {
    this.deviceState.textContent = this.deviceNavNode.textContent = '正在确认设备';
    deviceMessage = '正在确认内网地址与 MAC，请保持两台设备开机。';
   } else if (deviceJob.state === 'complete') deviceMessage = '设备配置已保存，码率增强与域名监控共用已确认的地址。';
   else if (deviceJob.state === 'failed') deviceMessage = deviceJob.error || '设备确认失败，请刷新设备并查看配置日志。';
  }
  if (!deviceJob.busy && (data.running || data.engine_alive))
   deviceMessage += ' 码率增强运行中，停止并完成网络恢复后可保存设备配置。';
  if (!deviceJob.busy && (this.deviceData || {}).proxy_enabled)
   deviceMessage += ' 设备专属访问控制正在接管，先在透明代理中解除接管后保存设备配置。';
  this.deviceNotice.textContent = deviceMessage;
  this.deviceNotice.setAttribute('data-error', String(this.pendingAction !== 'device_save' &&
   (!!this.deviceSaveError || deviceJob.action === 'device_save' && deviceJob.state === 'failed')));
  this.renderDeviceIdentity();
  this.root.setAttribute('data-running', String(!!data.running));
  this.profileNode.textContent = config.profile || '65';
  var observability = data.observability || {}, delayed = data.running && observability.status_fresh === false;
  this.countNode.textContent = delayed ? '—' : String(data.modified || 0);
  this.rateNode.textContent = delayed ? '—' : Number(data.control_mbps || 0).toFixed(3);
  var seconds = Math.max(0, Math.floor(data.uptime_seconds || 0));
  this.uptimeNode.textContent = data.running ? '已运行 ' + Math.floor(seconds / 3600) + ' 时 ' + Math.floor(seconds % 3600 / 60) + ' 分' : '启动后重新连接 Portal';
  var selected = (data.profiles || []).filter(function(profile) { return profile.value === this.selectedProfile; }, this)[0];
  this.selectionNode.textContent = (selected ? selected.description + '。' : '') +
   (this.selectedProfile === config.profile ? ' 当前已保存。' :
    data.running ? ' 保存后自动重启中继，重新连接 Portal 即可应用。' : ' 保存后，在下一次新连接应用。');
  this.routerNode.textContent = config.bridge || 'LAN 网桥';
  this.portalNode.textContent = config.portal_ip || '待配对';
  this.ps5Node.textContent = config.ps5_ip || '待配对';
  this.bridgeNode.textContent = config.address || '待设置独立地址';
  this.packetNode.textContent = String((data.counts || {}).forwarded_out || 0) + ' 个包';
  this.kernelNode.textContent = env.kernel || '—';
  this.archNode.textContent = env.target || env.architecture || '—';
  this.packageNode.textContent = env.package_manager || '—';
  this.modelNode.textContent = env.model || 'OpenWrt 主路由';
  this.versionNode.textContent = 'PS Accel ' + (env.version || '0.1.5');
  this.telemetryNode.textContent = delayed ? '采样延迟' : Number(observability.write_errors || 0) > 0 ? '记录异常' : '后台记录正常';
  this.telemetryDetail.textContent = '写入错误 ' + Number(observability.write_errors || 0) +
   ' 次 · 舍弃日志 ' + Number(observability.dropped_logs || 0) + ' 条 · 合并快照 ' +
   Number(observability.coalesced_snapshots || 0) + ' 次' +
   ' · 合并事件 ' + Number(observability.suppressed_logs || 0) + ' 条' +
   (observability.last_error ? '。最近记录错误：' + observability.last_error : '。');
  this.updateQuality(data);

  var message = data.configured ? '配置已就绪。启动增强后重新连接 Portal，检查画面与按键；调整码率后重新连接生效。' :
   devicesReady ? '填写中继独立地址并保存配置，然后启动增强。' : '进入设备配置，保存 Portal / PS5 的内网地址。';
  if (data.running) message = '中继已运行，新连接使用 ' + config.profile + ' Mbps 目标。停止时会自动恢复设备直达路径。';
  if (relayJob.busy && relayJob.action === 'configure') message = '正在探测中继地址并配对设备，请保持 PS5 与 Portal 开机。';
  if (relayJob.busy && relayJob.action === 'baseline') message = '等待日志出现 BASELINE READY，再连接 Portal，检查画面与按键。';
  if (relayJob.busy && relayJob.action === 'trial') message = '等待日志出现 AUTO READY，再重新连接。90 秒后自动结束并恢复网络。';
  if (relayJob.busy && relayJob.action === 'start') message = '正在等待 LAN 网桥就绪并启动中继。';
  if (relayJob.busy && relayJob.action === 'profile') message = (profilePhases[relayJob.phase] || '正在应用码率') +
   '。本次操作自动完成网络恢复、保存和重启，请等待完成。';
  if (relayJob.state === 'complete' && relayJob.action === 'profile') message = relayJob.restarted && data.running ?
   '码率已保存，中继已自动重启。重新连接 Portal 即可使用 ' + config.profile + ' Mbps 目标。' :
   '码率已保存。启动增强后重新连接 Portal。';
  if (relayJob.state === 'complete' && relayJob.action === 'trial') message = '试运行完成。确认画面与按键体验后，可启动常驻中继。';
  if (relayJob.state === 'cancelled') message = '操作已停止，网络恢复完成。';
  if (relayJob.state === 'failed') message = relayJob.error || '操作失败，请查看日志与诊断摘要。';
  if (relayJob.state === 'failed' && relayJob.rolled_back) message += ' 原档位已恢复，中继已重新启动。';
  if (delayed && !relayJob.busy && relayJob.state !== 'failed') message += ' 统计采样延迟，中继进程保持运行。详情见增强日志。';
  if (data.recovery_required && !relayJob.busy) message = (relayJob.state === 'failed' ? message + ' ' : '') +
   (data.cleanup_pending ? '网络清理待重试，点击“恢复网络”继续完成清理。' :
    '需要完成网络恢复。点击停止，待退出后重试恢复网络。');
  if (relayJob.cleanup_error && !relayJob.busy && relayJob.cleanup_error !== relayJob.error)
   message += ' 恢复详情：' + relayJob.cleanup_error;
  if (relayJob.rollback_error && !relayJob.busy && relayJob.rollback_error !== relayJob.cleanup_error)
   message += ' 原档位恢复详情：' + relayJob.rollback_error;
  if (relayJob.orphan_active && !relayJob.busy) message += ' 前次进程仍在退出，点击停止继续完成恢复。';
  if (data.foreign_relay) message = '协议引擎由其他提码率插件占用。先在原插件中停止服务，再启动 PS Accel。';
  if (relayJob.stopping || (relayJob.busy && relayJob.action === 'stop')) message =
   (profilePhases[relayJob.phase] || '正在停止中继') + '，完成后恢复设备连接。';
  var warnings = (data.status_warnings || []).concat(data.details_warnings || []);
  if (warnings.length) message += ' 状态读取提示：' + warnings.join('；') + '。停止与恢复入口可继续重试。';
  if (this.connectionError) message = '状态连接中断：' + this.connectionError + ' 停止与恢复入口保持可重试。';
  this.messageNode.textContent = message;
  if (relayJob.action === 'configure' || relayJob.action === 'profile') this.bitrateConfigNotice.textContent = message;
  this.messageNode.setAttribute('data-error', String(relayJob.state === 'failed' || (!!data.recovery_required && !relayJob.busy)));
  if (data.sample_time && data.sample_time !== this.lastSample) {
   this.lastSample = data.sample_time;
   this.history.push(Number(data.control_mbps || 0));
   if (this.history.length > 24) this.history.shift();
   var max = Math.max.apply(Math, [ .001 ].concat(this.history));
   this.bars.forEach(function(bar, i) {
    var value = this.history[i - (24 - this.history.length)] || 0;
    bar.style.height = Math.max(2, value / max * 22) + 'px';
   }, this);
  }
 },

 render: function(data) {
  var self = this, config = data.config || {};
  this.latest = data; this.fields = {}; this.fieldTouched = {}; this.buttons = {};
  this.history = []; this.bars = []; this.logTab = 'bitrate'; this.proxyLogTab = 'proxy';
  this.logRequests = {}; this.logContent = {}; this.nextLogRead = {}; this.logTabs = {}; this.proxyLogTabs = {};
  this.incidentId = ''; this.batchId = ''; this.mainTabs = {}; this.mainPanels = {}; this.stageTabs = {}; this.stagePanels = {};
  this.activeStages = { bitrate: data.configured ? 'runtime' : 'config', proxy: 'config' };
  this.scopeNodes = []; this.domainActionButtons = [];
  this.deviceSaveError = null;
  this.readonly = !L.hasViewPermission(); this.selectedProfile = config.profile || '65';
  this.deviceNavNode = E('span', { 'class': 'pa-nav-state' }, '等待确认地址');
  this.bitrateNavNode = E('span', { 'class': 'pa-nav-state' }, '等待运行');
  this.proxyNavNode = E('span', { 'class': 'pa-nav-state' }, '点击查看状态');
  this.domainNavNode = E('span', { 'class': 'pa-nav-state' }, '点击查看批次');
  this.stateNode = E('span', {}, '正在读取'); this.profileNode = E('span'); this.countNode = E('span');
  this.rateNode = E('span'); this.uptimeNode = E('div', { 'class': 'pa-detail' });
  this.qualityNode = E('span'); this.qualityDetail = E('div', { 'class': 'pa-detail' });
  this.relayQualityNode = E('span'); this.relayQualityDetail = E('div', { 'class': 'pa-detail' });
  this.qualityAdvice = E('div', { 'class': 'pa-notice alert-message notice', role: 'status', 'aria-live': 'polite' });
  this.selectionNode = E('div', { 'class': 'pa-selection' });
  this.routerNode = E('b'); this.portalNode = E('span'); this.ps5Node = E('span'); this.bridgeNode = E('span');
  this.baselineNode = E('div', { 'class': 'pa-step-desc' }); this.recoveryNode = E('div', { 'class': 'pa-step-desc' });
  this.packetNode = E('span'); this.kernelNode = E('span'); this.archNode = E('span'); this.packageNode = E('span');
  this.modelNode = E('span'); this.versionNode = E('span');
  this.telemetryNode = E('span'); this.telemetryDetail = E('div', { 'class': 'pa-record-detail' });
  this.messageNode = E('div', { 'class': 'pa-notice alert-message notice', role: 'status', 'aria-live': 'polite' });
  this.deviceNotice = E('div', { 'class': 'pa-notice alert-message notice', role: 'status', 'aria-live': 'polite' },
   '确认两台设备的内网地址，保存后供码率增强、透明代理与域名日志使用。');
  this.deviceState = E('span', { 'class': 'pa-status-pill' }); this.deviceConfirmed = E('p', { 'class': 'pa-caption' });
  this.deviceIdentity = { portal: E('div', { 'class': 'pa-device-identity' }), ps5: E('div', { 'class': 'pa-device-identity' }) };
  this.deviceLogNode = E('pre', { 'class': 'pa-log', 'aria-label': '设备配置日志' }, '保存设备配置后查看地址确认结果。');
  this.deviceLogDetails = E('details', { 'class': 'pa-disclosure', toggle: function() {
   if (self.deviceLogDetails.open) self.refreshLogs(true);
  } }, [E('summary', {}, '设备配置日志'), this.deviceLogNode]);
  this.deviceLogDetails.open = true;
  this.logNode = E('pre', { 'class': 'pa-log', id: 'psa-bitrate-log-content', role: 'tabpanel',
   'aria-label': '码率增强日志' }, '正在读取日志…');
  this.proxyLogNode = E('pre', { 'class': 'pa-log', id: 'psa-proxy-log-pane-proxy', role: 'tabpanel',
   'aria-labelledby': 'psa-proxy-log-tab-proxy', 'aria-label': '透明代理名单应用日志' }, '正在读取日志…');
  function logMode(id) {
   var input = choiceControl(luciControl('input', { type: 'hidden', id: id }), '选择日志模式', false);
   input.choicePicker.setOptions([{value:'compact', label:'简洁'}, {value:'verbose', label:'详细'}]);
   return input;
  }
  this.logMode = logMode('psa-log-mode'); this.proxyLogMode = logMode('psa-proxy-log-mode');
  this.logTag = luciControl('input', { id: 'psa-log-tag', type: 'text', maxlength: 64, placeholder: '例如 Portal 升级 4.0' });
  this.domainEnabled = luciControl('input', { id: 'psa-domain-enabled', type: 'checkbox' });
  [ this.logMode, this.proxyLogMode, this.logTag, this.domainEnabled ].forEach(function(node) {
   function changed() {
    self.loggingTouched = true;
    if (node === self.logMode) self.proxyLogMode.choicePicker.setValue(node.value);
    if (node === self.proxyLogMode) self.logMode.choicePicker.setValue(node.value);
   }
   node.addEventListener('input', changed); node.addEventListener('change', changed); node.choiceChanged = changed;
  });
  this.loggingNotice = E('p', { 'class': 'pa-caption', role: 'status', 'aria-live': 'polite' });
  this.proxyLoggingNotice = E('p', { 'class': 'pa-caption', role: 'status', 'aria-live': 'polite' });
  this.incidentNote = luciControl('input', { id: 'psa-incident-note', type: 'text', maxlength: 300,
   value: 'Portal 连接失败', placeholder: '设备提示、错误码或复现步骤' });
  this.incidentNotice = E('p', { 'class': 'pa-caption', role: 'status', 'aria-live': 'polite' });
  this.domainState = E('p', { 'class': 'pa-caption', role: 'status' }, '正在读取域名监控记录…');
  this.domainHealth = E('p', { 'class': 'pa-caption' });
  this.batchSelect = choiceControl(luciControl('input', { type: 'hidden', id: 'psa-domain-batch' }), '选择连接批次', false);
  this.batchSelect.choiceChanged = function() { self.selectBatch(self.batchSelect.value); };
  this.batchSelect.addEventListener('change', this.batchSelect.choiceChanged);
  this.batchStartButton = E('button', { type: 'button', 'class': buttonClass(), click: function() {
   return self.startDomainBatch();
  } }, '新建连接批次');
  this.batchTitle = E('h4'); this.batchSummary = E('p', { 'class': 'pa-caption' });
  this.batchTrafficSummary = E('div', { 'class': 'pa-traffic-summary' });
  this.domainTrafficNotice = E('p', { 'class': 'pa-caption' });
  this.domainTrafficUnassigned = E('p', { 'class': 'pa-caption', role: 'status' });
  this.batchNotice = E('p', { 'class': 'pa-caption', role: 'status', 'aria-live': 'polite' });
  this.domainSearch = luciControl('input', { type: 'text', maxlength: 253, placeholder: '筛选域名',
   'aria-label': '筛选域名', input: function() { if (self.domainData) self.renderDomains(self.domainData); } });
  this.domainOnlyProblems = luciControl('input', { type: 'checkbox', change: function() {
   if (self.domainData) self.renderDomains(self.domainData);
  } });
  this.domainOnlyProxy = luciControl('input', { type: 'checkbox', change: function() {
   if (self.domainData) self.renderDomains(self.domainData);
  } });
  this.domainOnlyLargeProxy = luciControl('input', { type: 'checkbox', change: function() {
   if (self.domainData) self.renderDomains(self.domainData);
  } });
  this.domainTrafficSort = choiceControl(luciControl('input', { type: 'hidden', id: 'psa-domain-traffic-sort' }), '流量排序', false);
  this.domainTrafficSort.choicePicker.setOptions([{value:'proxy',label:'代理流量从高到低'},
   {value:'total',label:'核心总流量从高到低'}, {value:'recent',label:'最近出现优先'}]);
  this.domainTrafficSort.choicePicker.setValue('proxy');
  this.domainTrafficSort.choiceChanged = function() { if (self.domainData) self.renderDomains(self.domainData); };
  this.domainTrafficSort.addEventListener('change', this.domainTrafficSort.choiceChanged);
  this.domainAllButton = E('button', { type: 'button', 'class': buttonClass(), 'aria-pressed': 'true', click: function() {
   self.domainOnlyProblems.checked = self.domainOnlyProxy.checked = self.domainOnlyLargeProxy.checked = false;
   self.domainSearch.value = ''; if (self.domainData) self.renderDomains(self.domainData);
  } }, '全部域名 0');
  this.domainFailedButton = E('button', { type: 'button', 'class': buttonClass(), 'aria-pressed': 'false', click: function() {
   self.domainOnlyProblems.checked = true; self.domainOnlyProxy.checked = self.domainOnlyLargeProxy.checked = false;
   self.domainSearch.value = ''; if (self.domainData) self.renderDomains(self.domainData);
  } }, '失败解析 0');
  this.copyAllDomains = E('button', { type: 'button', 'class': buttonClass(), click: function() { return self.copyDomainRules(false); } }, '复制全部域名规则');
  this.copyFailedDomains = E('button', { type: 'button', 'class': buttonClass(), click: function() { return self.copyDomainRules(true); } }, '复制失败域名规则');
  this.domainCopyNotice = E('p', { 'class': 'pa-caption', role: 'status', 'aria-live': 'polite' });
  this.domainRuleText = luciControl('textarea', { rows: 6, readonly: '', 'aria-label': '域名复制规则', style: 'width:100%;box-sizing:border-box' });
  this.domainRulePreview = E('div', { hidden: '' }, this.domainRuleText);
  this.domainEvents = E('pre', { 'class': 'pa-log', 'aria-label': '本批次解析明细' });
  this.incidentSelect = choiceControl(luciControl('input', { type: 'hidden' }), '选择失败记录', false);
  this.incidentSelect.choiceChanged = function() { self.incidentId = self.incidentSelect.value; self.refreshDomains(true); };
  this.incidentSelect.addEventListener('change', this.incidentSelect.choiceChanged);
  this.domainList = E('div', { 'class': 'pa-domain-table pa-domain-list' });
  this.domainCount = E('p', { 'class': 'pa-caption' });
  this.domainActionText = E('span');
  this.domainActionNotice = E('div', { 'class': 'pa-domain-action-notice', hidden: '', role: 'status', 'aria-live': 'polite' },
   [this.domainActionText, E('button', { type: 'button', 'class': 'pa-link btn cbi-button cbi-button-neutral', click: function() {
    self.selectStage('proxy', 'config'); self.policyInputs.domains.focus();
   } }, '检查代理配置')]);
  this.incidentTitle = E('h4'); this.incidentSummary = E('p', { 'class': 'pa-caption' });
  this.incidentCandidates = E('div'); this.incidentEvents = E('pre', { 'class': 'pa-log', 'aria-label': '失败窗口域名事件' });
  this.incidentPanel = E('div', { 'class': 'pa-incident', hidden: '' },
   [ this.incidentTitle, this.incidentSummary, this.incidentCandidates, this.incidentEvents ]);
  this.domainPanel = E('div', { id: 'psa-domain-records' }, [
   E('div', { 'class': 'pa-domain-tools' }, [this.domainAllButton, this.domainFailedButton,
    this.copyAllDomains, this.copyFailedDomains]),
   E('div', { 'class': 'pa-domain-tools' }, [ this.domainSearch,
    E('label', { 'class': 'pa-toggle' }, [ this.domainOnlyProblems, '仅看本批次失败解析' ]),
    E('button', { type: 'button', 'class': buttonClass(), click: function() { self.refreshDomains(true); } }, '刷新域名') ]),
   E('div', { 'class': 'pa-domain-tools' }, [this.domainTrafficSort.choicePicker.root,
    E('label', { 'class': 'pa-toggle' }, [this.domainOnlyProxy, '仅看本批次代理相关']),
    E('label', { 'class': 'pa-toggle' }, [this.domainOnlyLargeProxy, '代理累计 ≥100 MiB'])]),
   this.domainCopyNotice, this.domainRulePreview,
   this.domainActionNotice, this.domainList, this.domainCount,
   E('p', { 'class': 'pa-caption' }, '复制内容每行一个完整域名，可粘贴到 PassWall 普通规则列表或透明代理清单。批次内曾出现解析错误或观测超时的域名保留在失败清单。'),
   E('details', { 'class': 'pa-disclosure' }, [E('summary', {}, '查看本批次解析明细'), this.domainEvents]),
   E('details', { 'class': 'pa-disclosure' }, [ E('summary', {}, '采集状态与证据范围'), this.domainHealth,
    E('p', { 'class': 'pa-caption' }, '配置归属以当前草稿为准，调整后通过预览应用。域名记录提供可见 DNS、TCP 与 TLS 证据。'),
    E('p', { 'class': 'pa-caption' }, '观测超时表示窗口内缺少响应；共享 IP、加密 DNS、TLS ECH 和硬件加速会影响覆盖。HTTPS 业务错误结合设备提示判断。') ]) ]);
  this.autostart = luciControl('input', { type: 'checkbox', id: 'psa-autostart', change: function() { self.bootTouched = true; } });
  var profiles = data.profiles || ['35', '45', '65', '100', '200'].map(function(value) {
   return { value: value, label: value + ' Mbps', description: '', experimental: value === '200' };
  });
  this.profileButtons = profiles.map(function(profile, index) {
   var button = E('button', { type: 'button', 'class': 'pa-profile btn cbi-button cbi-button-neutral', role: 'radio',
    'data-profile': profile.value, 'aria-label': profile.value + ' Mbps，' + (profile.description || ''),
    click: function() { self.selectedProfile = profile.value; self.update(self.latest); },
    keydown: function(event) {
     var position;
     if (event.key === 'ArrowRight' || event.key === 'ArrowDown') position = (index + 1) % profiles.length;
     else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') position = (index + profiles.length - 1) % profiles.length;
     else return;
     event.preventDefault();
     if (!self.profileButtons[position].disabled) {
      self.selectedProfile = profiles[position].value; self.update(self.latest); self.profileButtons[position].focus();
     }
    } }, [ E('strong', {}, profile.value), E('span', {}, 'Mbps'),
    E('span', {}, profile.value === '65' ? '推荐起点' : profile.experimental ? '实验档位' : '\u00a0') ]);
   return button;
  });
  function panel(title, content, extra, classes) { return self.panel(title, content, extra, classes); }
  function stat(label, value, unit, detail) {
   return E('tr', { 'class': 'tr' }, [E('td', { 'class': 'td' }, label),
    E('td', { 'class': 'td pa-number' }, [value, unit ? E('small', {}, unit) : E('span')]),
    E('td', { 'class': 'td' }, detail)]);
  }
  function detail(text) { return E('div', { 'class': 'pa-detail' }, text); }
  var bridgeNames = (data.bridges || []).slice(), bridgeName = config.bridge || 'br-lan';
  if (bridgeNames.indexOf(bridgeName) < 0) bridgeNames.unshift(bridgeName);
  var bridge = choiceControl(luciControl('input', { type: 'hidden' }), '选择 LAN 网桥', false);
  bridge.choicePicker.setOptions(bridgeNames.map(function(name) { return {value:name, label:name}; }));
  bridge.choicePicker.setValue(bridgeName);
  function input(value, placeholder) {
   return luciControl('input', { type: 'text', value: value || '', placeholder: placeholder, maxlength: 80,
    spellcheck: 'false', autocomplete: 'off' });
  }
  var deviceCards = ['portal', 'ps5'].map(function(role) {
   var name = role === 'portal' ? 'Portal' : 'PS5';
   var address = choiceControl(input(config[role + '_ip'], role === 'portal' ? '10.0.0.101' : '10.0.0.100'),
    '选择' + name, true);
   return E('div', { 'class': 'pa-device-card' }, [
    self.field(role + '_ip', name + ' 内网地址', address), self.deviceIdentity[role] ]);
  });
  this.deviceRefreshButton = E('button', { type: 'button', 'class': buttonClass(), click: function() {
   return self.refreshDevices(true);
  } }, '刷新设备');
  var deviceLayout = E('div', { 'class': 'pa-basic' }, panel('设备配置', [
   this.deviceNotice, E('div', { 'class': 'pa-device-form' }, deviceCards),
   this.field('bridge', 'LAN 网桥', bridge),
   E('div', { 'class': 'pa-actions' }, [this.button('device_save', '保存设备配置', 'primary'), this.deviceRefreshButton]),
   this.deviceConfirmed, this.deviceLogDetails ], this.deviceState));
  this.bitrateConfigNotice = E('p', { 'class': 'pa-caption', role: 'status', 'aria-live': 'polite' });
  var bitrateConfig = panel('码率增强配置', [
   E('p', { 'class': 'pa-caption' }, '从 65 Mbps 起步，结合游戏画面、无线余量与连接稳定性逐档调整。'),
   E('div', { 'class': 'pa-profiles', role: 'radiogroup', 'aria-label': '目标码率' }, this.profileButtons),
   this.selectionNode,
   E('div', { style: 'margin-top:22px' }, this.field('address', '中继独立地址',
    input(config.address, '10.0.0.250/24'), '使用同一 LAN 的空闲 IPv4 地址并填写前缀，避开主路由地址与 DHCP 动态池。')),
   this.bitrateConfigNotice,
   E('div', { 'class': 'pa-config-foot' }, [E('span', { 'class': 'pa-muted' }, '保存配置后启动增强，再重新连接 Portal。'),
    E('div', { 'class': 'pa-actions' }, [this.button('configure', '保存配置', 'primary'),
     this.button('profile', '保存码率', 'primary')])])
  ]);
  var bars = E('div', { 'class': 'pa-bars', 'aria-label': '最近控制转发速率采样' });
  for (var i = 0; i < 24; i++) { var bar = E('i'); this.bars.push(bar); bars.appendChild(bar); }
  var bitrateStats = E('table', { 'class': 'table pa-stats' }, E('tbody', {}, [
   stat('增强状态', this.stateNode, '', this.uptimeNode),
   stat('目标请求码率', this.profileNode, 'Mbps', detail('新连接握手使用的请求值')),
   stat('已增强连接', this.countNode, '次', detail('同一握手的重传合并计数')),
   stat('控制转发', this.rateNode, 'Mbps', bars),
   stat('客户端报告丢失', this.qualityNode, '', this.qualityDetail),
   stat('中继处理', this.relayQualityNode, '', this.relayQualityDetail) ]));
  var bitrateRuntime = panel('运行状态', [bitrateStats, this.qualityAdvice,
   E('p', { 'class': 'pa-caption' }, '客户端回传计数用于评估接收质量；降档建议保持只读，实际画质与响应结合 Portal 表现复测。'),
   this.messageNode,
   E('div', { 'class': 'pa-actions' }, [this.button('start', '启动增强', 'primary'), this.button('stop', '停止并恢复', 'danger'),
    this.button('doctor', '环境检查'), this.button('repair', '恢复网络', 'danger')]),
   E('label', { 'class': 'pa-toggle', 'for': 'psa-autostart' }, [this.autostart, '开机启用'])
  ]);
  var bitrateLogTabs = this.navigation([['bitrate', '任务输出'], ['events', '增强事件']],
   this.logTabs, 'psa-bitrate-log', 'pa-log-tab', this.selectLogTab);
  Object.keys(this.logTabs).forEach(function(key) { self.logTabs[key].setAttribute('aria-controls', 'psa-bitrate-log-content'); });
  var bitrateLogs = E('div', { 'class': 'pa-grid' }, [
   panel('码率增强日志', [
    E('div', { 'class': 'pa-log-tools' }, [
     E('ul', { 'class': 'cbi-tabmenu pa-log-tabs', role: 'tablist', 'aria-label': '码率增强日志类型' }, bitrateLogTabs),
     E('button', { type: 'button', 'class': 'pa-link btn cbi-button cbi-button-neutral', click: function() { self.refreshLogs(true); } }, '刷新日志')]),
    this.logNode,
    E('p', { 'class': 'pa-caption' }, '任务输出记录保存、启停与恢复；增强事件记录新连接的握手修改。')
   ], this.button('diagnostics', '导出增强诊断'), 'pa-log-panel'),
   E('div', { 'class': 'pa-stack' }, [
    panel('日志设置', [
     formField(this.logMode, '日志详细程度'),
     E('p', { 'class': 'pa-caption' }, '简洁模式保留启停、连接修改与异常。详细模式适合临时复现问题，共用于增强与域名观察。'),
     E('div', { 'class': 'pa-actions', style: 'margin-top:16px' }, this.button('logging', '保存日志设置')),
     this.loggingNotice]),
    panel('记录状态', [
     E('div', { 'class': 'pa-kv' }, [E('span', {}, '日志与统计'), this.telemetryNode]),
     E('div', { 'class': 'pa-kv' }, [E('span', {}, '事件日志容量'), E('span', {}, '1 MiB / 份 · 2 份备份')]),
     this.telemetryDetail,
     E('p', { 'class': 'pa-caption' }, '记录延迟与增强运行状态分别展示，采样延迟时可继续检查进程状态。')])
   ])
  ]);
  var policy = this.renderPolicy();
  var proxyLogTabs = this.navigation([['proxy', '名单应用日志']],
   this.proxyLogTabs, 'psa-proxy-log', 'pa-log-tab', this.selectLogTab);
  var proxyLogs = E('div', { 'class': 'pa-stack' }, [
   panel('透明代理日志', [
    E('div', { 'class': 'pa-log-tools' }, [
     E('ul', { 'class': 'cbi-tabmenu pa-log-tabs', role: 'tablist', 'aria-label': '透明代理日志类型' }, proxyLogTabs),
     E('button', { type: 'button', 'class': 'pa-link btn cbi-button cbi-button-neutral', click: function() { self.refreshLogs(true); } }, '刷新日志')]),
    policy.diagnostics, this.proxyLogNode
   ], this.button('proxy_diagnostics', '导出代理诊断'), 'pa-log-panel')
  ]);
  var monitorSettings = panel('域名采集设置', [
     E('label', { 'class': 'pa-toggle', 'for': 'psa-domain-enabled', style: 'margin-top:0' },
      [this.domainEnabled, '记录 Portal / PS5 域名解析与连接批次']),
     E('p', { 'class': 'pa-caption' }, '域名采集独立运行，便于连接前后比较。关闭后保留已有记录。'),
     formField(this.proxyLogMode, '日志详细程度'),
     formField(this.logTag, '本轮排查标记'),
     E('p', { 'class': 'pa-caption' }, '升级或调整配置前保存新标记，随后首次出现的域名标为“本轮新增”。'),
     E('div', { 'class': 'pa-actions', style: 'margin-top:16px' }, this.button('proxy_logging', '保存采集设置')),
     this.proxyLoggingNotice]);
  var monitorFailures = panel('连接失败回溯', [
     formField(this.incidentNote, '设备提示或失败描述'),
     E('div', { 'class': 'pa-actions', style: 'margin-top:14px' }, this.button('incident', '记录这次失败')),
     this.incidentNotice,
     E('p', { 'class': 'pa-caption' }, '回溯前 180 秒、后 15 秒。结合异常域名调整代理清单，保留最近 32 次记录。'),
     formField(this.incidentSelect, '历史失败记录'), this.incidentPanel]);
  function heading(title, caption) {
   return E('div', { 'class': 'pa-feature-head' }, [E('div', {}, [
    E('h3', {}, title), E('p', { 'class': 'pa-caption' }, caption)])]);
  }
  function scope() {
   var portal = E('span'), ps5 = E('span'); self.scopeNodes.push({portal: portal, ps5: ps5});
   return E('div', { 'class': 'pa-scope' }, [
    E('div', { 'class': 'pa-scope-copy' }, [
     E('span', {}, [E('b', {}, 'Portal'), portal]), E('span', {}, [E('b', {}, 'PS5'), ps5])]),
    E('button', { type: 'button', 'class': 'pa-link btn cbi-button cbi-button-neutral', click: function() { self.selectTab('devices'); } }, '设备配置')]);
  }
  function feature(name, panels) {
   self.stageTabs[name] = {}; self.stagePanels[name] = {};
   var config = E('div', { 'class': 'pa-stage-panel' }, panels.config);
   var runtime = E('div', { 'class': 'pa-stage-panel' }, panels.runtime);
   var logs = E('details', { 'class': 'pa-disclosure', toggle: function() {
    self.activeStages[name] = logs.open ? 'logs' : 'config';
    if (logs.open) self.refreshLogs(true);
   } }, [E('summary', {}, '日志与诊断'), panels.logs]); logs.open = true;
   self.stagePanels[name] = {config:config, runtime:runtime, logs:logs};
   return E('div', { id: 'psa-pane-' + name, 'class': 'pa-tab-panel pa-basic', role: 'tabpanel',
    'aria-labelledby': 'psa-tab-' + name }, [scope(), runtime, config, logs]);
  }
  this.mainPanels.devices = E('div', { id: 'psa-pane-devices', 'class': 'pa-tab-panel', role: 'tabpanel',
   'aria-labelledby': 'psa-tab-devices' }, [
    deviceLayout]);
  this.mainPanels.bitrate = feature('bitrate', {config: bitrateConfig, runtime: bitrateRuntime, logs: bitrateLogs});
  this.mainPanels.proxy = feature('proxy', {config: policy.config, runtime: policy.runtime, logs: proxyLogs});
  this.mainPanels.monitor = E('div', { id: 'psa-pane-monitor', 'class': 'pa-tab-panel pa-basic pa-domain-monitor', role: 'tabpanel',
   'aria-labelledby': 'psa-tab-monitor' }, [scope(),
   panel('连接批次', [this.domainState,
    formField(this.batchSelect, '选择本次连接记录'),
    E('div', { 'class': 'pa-actions' }, [this.batchStartButton,
     E('button', { type: 'button', 'class': buttonClass(), click: function() { self.selectBatch(''); } }, '查看最近批次')]),
    this.batchTitle, this.batchSummary, this.batchTrafficSummary, this.domainTrafficNotice, this.domainTrafficUnassigned, this.batchNotice,
    E('p', { 'class': 'pa-caption' }, '首次域名活动自动创建批次，串流连接标记用于区分连接与重连。连续 60 秒无可见活动后归档，连续重试可新建批次。保留最近 32 批记录。')]),
   panel('域名解析记录', [this.domainPanel]),
   E('div', { 'class': 'pa-grid' }, [monitorSettings, monitorFailures])]);
  var mainItems = [
   ['devices', [E('span', {}, '设备配置'), this.deviceNavNode]],
   ['bitrate', [E('span', {}, '码率增强'), this.bitrateNavNode]],
   ['proxy', [E('span', {}, '透明代理'), this.proxyNavNode]],
   ['monitor', [E('span', {}, '域名监控'), this.domainNavNode]]
  ];
  var mainTabs = this.navigation(mainItems, this.mainTabs, 'psa', 'pa-main-tab', this.selectTab);
  this.root = E('div', { 'class': 'cbi-map ps-accel' }, [
   E('style', {}, styles),
   E('h2', {}, 'PS Accel'),
   this.readonly ? E('div', { 'class': 'pa-readonly alert-message notice' }, '当前为只读权限，可查看状态、日志、域名名单并复制域名规则。') : E('span'),
   E('ul', { 'class': 'cbi-tabmenu pa-main-tabs', role: 'tablist', 'aria-label': '一级功能' }, mainTabs),
   this.mainPanels.devices, this.mainPanels.bitrate, this.mainPanels.proxy, this.mainPanels.monitor,
   E('footer', { 'class': 'pa-foot' }, this.versionNode)
  ]);
  this.selectLogTab('bitrate'); this.selectLogTab('proxy');
  this.update(data);
  var hash = (window.location && window.location.hash || '').replace(/^#/, '').split('/');
  var initial = {stream: 'bitrate', psportal: 'proxy', domains: 'monitor'}[hash[0]] || hash[0];
  this.selectTab(this.mainTabs[initial] ? initial : (data.devices_configured || data.configured ? 'bitrate' : 'devices'));
  if (hash[1] && this.stagePanels[this.activeTab]) this.selectStage(this.activeTab, hash[1]);
  if (hash[2]) this.selectLogTab(hash[2]);
  poll.add(function() { return self.refresh(); }, 3);
  return this.root;
 },
 handleSaveApply: null,
 handleSave: null,
 handleReset: null
});
