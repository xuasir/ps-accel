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
var callIncident = rpc.declare({ object: 'ps-accel', method: 'incident', params: [ 'note' ], expect: {} });
var policyFields = [ 'portal', 'ps5', 'node', 'domains', 'ports', 'exclusions' ];
var callPolicyStatus = rpc.declare({ object: 'ps-accel', method: 'psportal_status', expect: {} });
var callPolicyPreview = rpc.declare({ object: 'ps-accel', method: 'psportal_preview', params: policyFields, expect: {} });
var callPolicySave = rpc.declare({ object: 'ps-accel', method: 'psportal_save', params: policyFields, expect: {} });
var callPolicyApply = rpc.declare({ object: 'ps-accel', method: 'psportal_apply',
 params: policyFields.concat([ 'token', 'confirm_restart' ]), expect: {} });
var callPolicyDisable = rpc.declare({ object: 'ps-accel', method: 'psportal_disable', expect: {} });
var callPolicyProbe = rpc.declare({ object: 'ps-accel', method: 'psportal_probe', expect: {} });
var callPolicyAutostart = rpc.declare({ object: 'ps-accel', method: 'psportal_autostart', params: [ 'autostart' ], expect: {} });
var calls = {};
[ 'baseline', 'trial', 'stop', 'repair', 'doctor' ].forEach(function(name) {
 calls[name] = rpc.declare({ object: 'ps-accel', method: name, expect: {} });
});
var actionNames = { device_save: '确认设备', configure: '检查码率配置', profile: '应用码率', baseline: '连接测试',
 trial: '试运行', start: '启动码率增强', stop: '停止任务', repair: '网络恢复', doctor: '环境检查',
 psportal_apply: '启用透明代理', psportal_disable: '停用透明代理', psportal_probe: '检测出口连通性' };
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
 return (text || '').split('\n').map(function(name) { return name.trim().toLowerCase().replace(/^full:/, ''); })
  .filter(function(name, index, names) { return name && name.charAt(0) !== '#' && names.indexOf(name) === index; });
}
function validHost(name) {
 return name.length <= 253 && name.indexOf('.') > 0 && !/^\d+(\.\d+){3}$/.test(name) &&
  name.split('.').every(function(part) { return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(part); });
}
function policyMatches(host, rules) {
 host = host.toLowerCase().replace(/\.$/, '');
 return !!host && rules.some(function(rule) {
  var pattern = rule.split('*').map(function(part) { return part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }).join('.*');
  return new RegExp('^' + pattern + '$').test(host);
 });
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
@media(max-width:900px){.ps-accel .pa-grid{grid-template-columns:1fr}.ps-accel .pa-domain-list .table{min-width:0}}
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
   return { kind: this.proxyLogTab, node: this.proxyLogNode };
  return null;
 },

 refreshLogs: function(force) {
  var context = this.activeLog();
  if (!context) return Promise.resolve();
  if (context.kind === 'domains') return this.refreshDomains(force);
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
    proxy: '透明代理的启用、更新、停用与回滚结果显示在这里。' };
   active.node.textContent = data.text || empty[kind];
   if (bottom) active.node.scrollTop = active.node.scrollHeight;
  }).catch(function(error) {
   var active = self.activeLog();
   if (active && active.kind === kind) active.node.textContent = '日志读取失败：' + error.message;
  }).finally(function() { delete self.logRequests[kind]; });
  return this.logRequests[kind];
 },

 refreshDomains: function(force, anyStage) {
  if (!anyStage && (this.activeTab !== 'proxy' || !this.stagePanels.proxy.logs.open || this.proxyLogTab !== 'domains'))
   return Promise.resolve();
  if (this.domainRequest) return this.domainRequest;
  if (!force && Date.now() < (this.nextDomainRead || 0)) return Promise.resolve();
  var self = this, selected = this.incidentId || '';
  this.nextDomainRead = Date.now() + ((this.latest.logging || {}).mode === 'verbose' ? 2000 : 10000);
  this.domainRequest = rpcRequest(function() { return callDomains(selected); }).then(function(data) {
   if ((self.incidentId || '') !== selected) return;
   self.domainData = data;
   self.renderDomains(data);
   return data;
  }).catch(function(error) {
   if ((self.incidentId || '') === selected) self.domainState.textContent = '域名记录读取失败：' + error.message;
  }).finally(function() {
   self.domainRequest = null;
   if ((self.incidentId || '') !== selected) self.refreshDomains(true);
  });
  return this.domainRequest;
 },

 selectLogTab: function(name, focus) {
  var proxy = name === 'domains' || name === 'proxy', tabs = proxy ? this.proxyLogTabs : this.logTabs;
  if (!tabs[name]) return;
  if (proxy) this.proxyLogTab = name;
  else this.logTab = name;
  Object.keys(tabs).forEach(function(key) {
   setTabState(tabs[key], key === name);
  });
  if (proxy) {
   this.proxyLogNode.hidden = name === 'domains';
   this.domainPanel.hidden = name !== 'domains';
  }
  if (!proxy) this.logNode.setAttribute('aria-labelledby', tabs[name].id || tabs[name].attributes && tabs[name].attributes.id);
  if (focus) tabs[name].focus();
  if (name !== 'domains') (proxy ? this.proxyLogNode : this.logNode).textContent = this.logContent[name] || '正在读取日志…';
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
  this.policyPlan = null;
  if (this.policyConfirm) this.policyConfirm.checked = false;
  if (this.policyConfirmation) this.policyConfirmation.hidden = true;
  if (this.policyPreview) this.policyPreview.hidden = true;
  this.updatePolicyControls();
 },

 dynamicDomainRules: function() {
  return ((this.policyData || {}).dynamic_rules || (this.domainData || {}).dynamic_rules || [])
   .map(function(rule) { return rule.domain; });
 },

 addDomainToPolicy: function(domain, target) {
  domain = domain.trim().toLowerCase().replace(/^full:/, '');
  var busy = this.readonly || this.policyPending || this.pending || !!(this.latest.job || {}).busy;
  if (busy || ['domains', 'exclusions'].indexOf(target) < 0) return;
  var hosts = policyHosts(this.policyInputs[target].value);
  if (target === 'domains' && policyMatches(domain, policyHosts(this.policyInputs.exclusions.value).filter(function(rule) {
   return rule !== domain;
  }))) {
   this.domainActionText.textContent = domain + ' 命中泛匹配排除规则，请在代理配置中调整该规则后加入。';
   this.domainActionNotice.hidden = false; this.domainActionNotice.setAttribute('data-error', 'true'); return;
  }
  if (!validHost(domain) || (hosts.indexOf(domain) < 0 && hosts.length >= 32)) {
   this.domainActionText.textContent = validHost(domain) ? '每份清单最多 32 个域名，请先整理代理配置。' :
    '请从日志选择有效的完整主机名。';
   this.domainActionNotice.hidden = false; this.domainActionNotice.setAttribute('data-error', 'true'); return;
  }
  if (hosts.indexOf(domain) < 0) hosts.push(domain);
  var other = target === 'domains' ? 'exclusions' : 'domains';
  this.policyInputs[target].value = hosts.join('\n');
  this.policyInputs[other].value = policyHosts(this.policyInputs[other].value).filter(function(name) {
   return name !== domain;
  }).join('\n');
  this.policyTouched[target] = this.policyTouched[other] = true;
  this.invalidatePolicy();
  this.policyConfigNotice.textContent = this.policyDraftState.textContent =
   '代理草稿已调整，保存并生成新预览后应用。';
  this.policyConfigNotice.setAttribute('data-error', 'false');
  this.domainActionText.textContent = domain + ' 已加入' + (target === 'domains' ? '代理清单' : '排除清单') +
   '。检查配置并生成预览后应用。';
  this.domainActionNotice.hidden = false; this.domainActionNotice.setAttribute('data-error', 'false');
  if (this.domainData) this.renderDomains(this.domainData);
 },

 domainRuleActions: function(domain) {
  var self = this, names = policyHosts(this.policyInputs.domains.value), exclusions = policyHosts(this.policyInputs.exclusions.value);
  var excluded = policyMatches(domain, exclusions), dynamic = policyMatches(domain, this.dynamicDomainRules());
  var included = policyMatches(domain, names) || dynamic;
  return E('div', {}, [ E('div', { 'class': 'pa-domain-rule' }, '草稿 · ' +
   (excluded ? '排除清单 / 原有策略' : dynamic ? '动态匹配 / 所选节点' : included ? '代理清单 / 所选节点' : '沿用原有策略')),
   E('div', { 'class': 'pa-domain-row-actions' }, [['domains', '加入代理'], ['exclusions', '加入排除']].map(function(item) {
    var chosen = item[0] === 'domains' ? included && !excluded : excluded;
    var disabled = self.readonly || self.policyPending || self.pending || !!(self.latest.job || {}).busy || chosen || !validHost(domain);
    var button = E('button', { type: 'button', 'class': buttonClass(), click: function() {
     self.addDomainToPolicy(domain, item[0]);
    } }, chosen ? (item[0] === 'domains' ? '已覆盖代理' : '已加入排除') : item[1]);
    button.disabled = !!disabled; button.dataset.chosen = String(chosen); button.dataset.domain = domain;
    self.domainActionButtons.push(button); return button;
   })) ]);
 },

 addSuggestedDomains: function() {
  var self = this;
  if (this.readonly || this.policyPending || this.pending || !!(this.latest.job || {}).busy) return Promise.resolve();
  return this.refreshDomains(true, true).then(function(data) {
   if (!data) { self.policyCandidateSummary.textContent = '域名候选读取待确认，请重新读取。'; return; }
   if (self.readonly || self.policyPending || self.pending || !!(self.latest.job || {}).busy) return;
   var hosts = policyHosts(self.policyInputs.domains.value), excluded = policyHosts(self.policyInputs.exclusions.value);
   var covered = hosts.concat(self.dynamicDomainRules());
   var additions = ((self.domainData || {}).candidates || []).filter(function(row) { return row.suggestion === 'proxy'; }).map(function(row) { return row.domain; }).filter(function(host, index, all) {
    return validHost(host) && !policyMatches(host, excluded) && !policyMatches(host, covered) && all.indexOf(host) === index;
   });
   if (hosts.length + additions.length > 32) {
    self.policyCandidateSummary.textContent = '必要候选共 ' + additions.length + ' 项，合并后超过 32 项；从日志逐项整理。'; return;
   }
   if (additions.length) {
    self.policyInputs.domains.value = hosts.concat(additions).join('\n');
    self.policyTouched.domains = true; self.invalidatePolicy();
    self.policyConfigNotice.textContent = self.policyDraftState.textContent = '必要域名已加入草稿，保存并生成新预览后应用。';
   }
   self.policyCandidateSummary.textContent = additions.length ? '已加入 ' + additions.length + ' 个完整主机名：' + additions.join('、') :
    '当前认证、信令与连通探测候选均已覆盖；排除清单继续生效。';
   if (self.domainData) self.renderDomains(self.domainData);
  });
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
   self.selectStage('proxy', 'logs'); self.selectLogTab('domains');
   self.incidentNotice.textContent = '已标记 ' + localTime(data.time) + '，正在收集后 15 秒的观测证据。';
   return self.refreshDomains(true);
  }).catch(function(error) {
   self.incidentNotice.textContent = '失败标记保存失败：' + error.message;
  }).finally(function() { self.incidentPending = false; self.update(self.latest); });
 },

 renderDomains: function(data) {
  var self = this, observer = data.observer || {}, rows = data.domains || [];
  this.domainActionButtons = [];
  var names = { observing: observer.fresh ? '正在观察设备域名' : '观察状态待确认',
   disabled: '域名记录已关闭', waiting: '等待设备配对与网桥就绪', stopped: '观察服务已停止' };
  this.domainState.textContent = (names[observer.state] || '等待观察服务') + ' · 已记录 ' + rows.length + ' 个设备域名' +
   (data.logging && data.logging.tag ? ' · 标记：' + data.logging.tag : '') +
   (observer.error ? '。' + observer.error : '');
  var health = observer.health || {}, io = observer.observability || {};
  this.domainHealth.textContent = '观测丢弃 ' + Number(observer.capture_drops || 0) +
   ' · 限速舍弃 ' + Number(observer.rate_drops || 0) + ' · 缓存舍弃 ' + Number(health.capacity_drops || 0) +
   ' · 解析舍弃 ' + Number(health.malformed || 0) + ' · 报文截断 ' + Number(health.snaplen_limited || 0) +
   ' · 合并重复 ' + Number(health.suppressed_events || 0) + ' · 写入错误 ' + Number(io.write_errors || 0) +
   (observer.snapshot_truncated ? ' · 部分历史上下文已精简' : '') +
   (io.last_error ? '。' + io.last_error : '。');
  var incidentChoices = [{value:'', label:'当前域名清单'}].concat((data.incidents || []).map(function(item) {
   return {value:item.id, label:localTime(item.time) + ' · ' + item.note};
  }));
  this.incidentSelect.choicePicker.setOptions(incidentChoices);
  this.incidentSelect.choicePicker.setValue(this.incidentId || '');
  var search = this.domainSearch.value.trim().toLowerCase();
  var filtered = rows.filter(function(row) {
   return (!search || (row.domain || '').indexOf(search) >= 0) &&
    (!self.domainOnlyProblems.checked || row.last_problem);
  });
  var table = E('table', { 'class': 'table' }, [ E('thead', {}, E('tr', { 'class': 'tr' },
   [ '设备 / 域名', '可见证据', '代理草稿', '最近出现' ].map(function(title) { return E('th', { 'class': 'th' }, title); }))),
   E('tbody', {}, filtered.slice(0, 100).map(function(row) {
    var counts = row.counts || {}, observed = Object.keys(evidenceNames).filter(function(key) {
     return key !== 'new_domain' && counts[key];
    }).map(function(key) { return evidenceNames[key] + ' ' + counts[key]; });
    var addresses = (row.addresses || []).map(function(item) { return item.address; }).join('、');
    return E('tr', { 'class': 'tr' }, [ E('td', { 'class': 'td' }, [ E('div', { 'class': 'pa-domain-name', title: addresses },
     [ (row.device === 'ps5' ? 'PS5' : 'Portal') + ' · ' + row.domain,
      row.new_since_tag ? E('span', { 'class': 'pa-domain-new' }, '本轮新增') : E('span') ]),
     E('div', { 'class': 'pa-muted' }, row.category_label || '其他'),
     E('div', { 'class': 'pa-domain-time' }, '首次 ' + localTime(row.first_seen)) ]),
     E('td', { 'class': 'td ' + (row.last_problem ? 'pa-domain-problem' : '') },
      (row.last_problem ? evidenceNames[row.last_problem] + '。' : '') + (observed.join(' · ') || '首次可见')),
     E('td', { 'class': 'td' }, self.domainRuleActions(row.domain)),
     E('td', { 'class': 'td pa-domain-time' }, localTime(row.last_seen)) ]);
   })) ]);
  this.domainList.replaceChildren(filtered.length ? table : E('div', { 'class': 'pa-domain-empty' },
   rows.length ? '当前筛选条件下暂无记录。' : '完成设备配对后，由 PS5 或 Portal 发起连接，域名记录会显示在这里。'));
  this.domainCount.textContent = filtered.length > 100 ? '显示最近 100 项，共 ' + filtered.length + ' 项；输入域名缩小范围。' : '';
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
     ' · ' + ({selected:'所选节点',direct:'原有直连',original:'原有出口'}[row.route] || '出口待确认') +
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
   self.refreshLogs(); self.refreshDevices();
   var job = data.job || {};
   if (job.action && job.action.indexOf('psportal_') === 0 && job.action !== 'psportal_probe' && !job.busy && self.policyJob !== job.id) {
    self.policyJob = job.id; self.policyTouched = {}; self.policyPlan = null;
    self.refreshPolicy(true);
   } else self.refreshPolicy();
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
  if (name === 'proxy') this.refreshPolicy(true);
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
  var selectors = this.deviceSelectors();
  return policyFields.map(function(key) { return key === 'portal' || key === 'ps5' ? selectors[key] : self.policyInputs[key].value.trim(); });
 },

 refreshPolicy: function(force) {
  if (this.policyRequest) return this.policyRequest;
  if ((!force && this.activeTab !== 'proxy') || this.policyPending) return Promise.resolve();
  if (!force && Date.now() < (this.nextPolicyRead || 0)) return Promise.resolve();
  var self = this;
  this.nextPolicyRead = Date.now() + 10000;
  this.policyRequest = rpcRequest(callPolicyStatus).then(function(data) {
   self.policyData = data; self.policyEnvironmentError = false;
   if (self.deviceData) self.deviceData.proxy_enabled = !!data.enabled;
   if ((data.blockers || []).length && self.policyPlan) self.invalidatePolicy();
   var config = data.config || {}, environment = data.environment || {}, active = data.active_config || {};
   var state = (data.receipt || {}).state === 'recovery_required' ? 'PassWall 恢复待检查' : data.enabled ?
    (environment.attached_cores ? '规则已载入' : '已启用 · 等待入口加载') : '已停用';
   self.policyState.textContent = self.proxyNavNode.textContent = state;
   self.policyEnvironment.textContent = 'PassWall ' + (environment.passwall || '待确认') +
    ' · Sing-box ' + (environment.singbox || '待确认') + ' · 活动入口 ' + Number(environment.active_cores || 0);
   self.policyRequirements.textContent = (data.blockers || []).join('；');
   self.policyBlockers.textContent = data.node_error ? '节点读取失败。请在 PassWall 中确认节点已保存，再点击“刷新节点”。' :
    (data.blockers || [])[0] || '';
   self.policyCoverage.textContent = ((data.entry_scope || {}).notices || []).join('；');
   self.renderProxyTelemetry(data);
   var selected = self.policyTouched.node ? self.policyInputs.node.value : config.node || '';
   self.policyNodePicker.setOptions((data.nodes || []).map(function(node) {
    return {value:node.id, label:node.label, detail:node.reason || node.protocol,
     available:node.available !== false};
   }));
   self.policyNodePicker.setValue(selected);
   var usable = (data.nodes || []).filter(function(node) { return node.available !== false; }).length;
   self.policyNodeState.textContent = data.node_error ? '节点读取失败，详情见日志与诊断。' : ((data.nodes || []).length ?
    '本地 ' + data.nodes.length + ' 个节点 · 可用 ' + usable + ' 个' : '本机 PassWall 节点清单为空，请刷新节点。');
   self.policyNodeState.setAttribute('data-error', String(!!data.node_error));
   self.policyAutostart.checked = data.autostart !== false;
   policyFields.forEach(function(key) {
    if (key !== 'portal' && key !== 'ps5' && !self.policyTouched[key] && typeof config[key] === 'string')
     self.policyInputs[key].value = config[key];
   });
   var selectors = self.deviceSelectors();
   self.policyInputs.portal.value = selectors.portal; self.policyInputs.ps5.value = selectors.ps5;
   var sources = data.sources || {};
   self.policySourceState.textContent = '当前规则来源 · Portal ' + ((sources.portal || []).join(' / ') || '等待当前地址') +
    '；PS5 ' + ((sources.ps5 || []).join(' / ') || '等待当前地址');
   var activeNode = (data.nodes || []).filter(function(node) { return node.id === active.node; })[0];
   self.policyActiveNode.textContent = data.enabled ? activeNode && activeNode.label || active.node || '待确认' : '等待启用';
   self.policyActiveDomains.textContent = data.enabled ? policyHosts(active.domains).length + ' 条配置 + ' +
    self.dynamicDomainRules().length + ' 条动态规则' : '等待启用';
   self.policyDynamicRules.textContent = '内置动态认证 / 信令规则 · ' + self.dynamicDomainRules().join('、');
   self.policyAppliedTime.textContent = (data.receipt || {}).time ? localTime(data.receipt.time * 1000) : '等待应用';
   self.policyRuntimeSummary.textContent = data.enabled ?
    '透明代理已启用。重新连接 Portal，日志会显示设备使用的节点与连接结果。' :
    '选择本地节点并启用透明代理，连接记录会显示在这里。';
   self.policyDraftState.textContent = Object.keys(self.policyTouched).length ? '配置已调整，点击启用或应用修改。' :
    data.enabled && ['node', 'domains', 'ports', 'exclusions'].some(function(key) { return config[key] !== active[key]; }) ?
     '新配置已保存，点击应用修改使其生效。' : data.enabled ? '当前配置已生效。' : '选择节点后即可启用。';
   if (!self.policyPlan) self.policyButtons.apply.textContent = data.enabled ? '更新透明代理' : '启用透明代理';
   if (self.domainData) self.renderDomains(self.domainData);
   self.update(self.latest);
  }).catch(function(error) {
   self.policyEnvironmentError = true; self.invalidatePolicy();
   self.policyState.textContent = self.proxyNavNode.textContent = '状态待确认';
   self.policyBlockers.textContent = '代理环境读取失败：' + error.message; self.policyBlockers.hidden = false;
   self.policyNodeState.textContent = '节点读取失败：' + error.message;
   self.updatePolicyControls();
  }).finally(function() { self.policyRequest = null; self.updatePolicyControls(); });
  return this.policyRequest;
 },

 renderProxyTelemetry: function(data) {
  var telemetry = data.telemetry || {}, probes = data.probes || {};
  this.policyCoreSummary.textContent = telemetry.fresh && telemetry.sampled_cores ?
   '当前所选节点正在处理 ' + Number(telemetry.matched_connections || 0) + ' 条设备连接。' :
   data.enabled ? '等待设备连接。重新连接 Portal 后，可查看使用的节点与连接结果。' : '启用透明代理后，设备连接与异常会显示在日志中。';
  if ((telemetry.errors || []).length) this.policyCoreSummary.textContent += '。' + telemetry.errors.join('；');
  var phases = {AUTH:'认证连接',SIGNALING:'信令连接',CONNECTED:'连接传输',DISCONNECTED:'连接结束'};
  var routes = {selected:'所选节点',previous:'此前节点',direct:'原有直连',original:'原有出口',unknown:'出口待确认'};
  var rows = (telemetry.connections || []).slice(0, 10).map(function(row) {
   return E('tr', { 'class': 'tr' }, [
    E('td', { 'class': 'td' }, [(row.device === 'ps5' ? 'PS5' : 'Portal') + ' · ', E('span', { 'class': 'pa-domain-name' }, row.domain || row.address)]),
    E('td', { 'class': 'td' }, phases[row.phase] || row.phase),
    E('td', { 'class': 'td' }, routes[row.route] || '出口待确认'),
    E('td', { 'class': 'td' }, row.failure ? '上游响应待检查' :
     '↑ ' + Math.round(Number(row.bytes_up || 0) / 1024) + ' KB / ↓ ' + Math.round(Number(row.bytes_down || 0) / 1024) + ' KB')]);
  });
  this.policyConnections.replaceChildren(rows.length ? E('table', { 'class': 'table' }, [
   E('thead', {}, E('tr', { 'class': 'tr' }, ['设备 / 域名','推断阶段','实际出口','传输 / 异常'].map(function(label) {
    return E('th', { 'class': 'th' }, label);
   }))), E('tbody', {}, rows)]) : E('p', { 'class': 'pa-caption' }, '新的设备连接将在这里显示；阶段依据域名与核心记录推断。'));
  this.policyProbeState.textContent = probes.epoch ? '最近检测 ' + localTime(probes.epoch * 1000) +
   (probes.cancelled ? ' · 检测已取消' : probes.current_config === false ? ' · 此前配置检测，重新检测当前出口' :
    probes.healthy ? ' · 节点连接正常' : ' · 部分连接失败，请查看下方检测结果') : '连接异常时可点击“检测连接”，检查节点是否可用。';
  this.policyProbeResults.replaceChildren.apply(this.policyProbeResults, (probes.targets || []).map(function(row) {
   var parts = ['路由器 DNS ' + (row.dns && row.dns.ok ? '通过' : '待检查'), '目标 TCP ' + (row.tcp ? '通过' : '待检查')];
   if (row.tls !== null) parts.push('TLS ' + (row.tls ? '通过' : '待检查'));
   var failures = {target_connect_failure:'目标连接失败',probe_entry_failure:'检测入口待检查',tls_failure:'TLS 握手失败',certificate_validation:'证书校验失败'};
   return E('p', { 'class': 'pa-caption' }, [(row.category_label || '') + ' · ', E('span', { 'class': 'pa-domain-name' }, row.domain),
    ' · ' + (probes.current_config === false ? '此前配置出口' : row.path === 'direct' ? '直连' : '所选节点') + ' · ' + parts.join(' / '),
    row.failure ? ' · ' + (failures[row.failure] || '检查连接') : '']);
  }));
 },

 updatePolicyControls: function() {
  if (!this.policyButtons) return;
  var job = ((this.latest || {}).job || {});
  var busy = !!this.policyPending || !!this.pending || !!job.busy;
  var showPrerequisite = !!this.policyBlockers.textContent && !busy && this.policyNotice.dataset.error !== 'true';
  this.policyBlockers.hidden = !showPrerequisite;
  this.policyNotice.hidden = showPrerequisite;
  var selectors = this.deviceSelectors(), ready = !!selectors.portal && !!selectors.ps5 &&
   this.latest.devices_configured !== false;
  this.policyButtons.preview.disabled = busy || !ready;
  var node = ((this.policyData || {}).nodes || []).filter(function(item) { return item.id === this.policyInputs.node.value; }, this)[0];
  this.policyButtons.enable.disabled = this.readonly || busy || !ready || !node || node.available === false || !!this.policyEnvironmentError;
  this.policyButtons.enable.textContent = (this.policyData || {}).enabled ? '应用修改' : '启用透明代理';
  this.policyAutostart.disabled = this.readonly || busy || !!this.policyEnvironmentError;
  this.policyNodeRefresh.disabled = !!this.policyRequest;
  this.policyButtons.save.disabled = this.readonly || busy || !ready;
  this.policyButtons.apply.disabled = this.readonly || busy || !!this.policyEnvironmentError || !this.policyPlan ||
   !this.policyPlan.can_apply || (this.policyPlan.restart_required && !this.policyConfirm.checked);
  this.policyButtons.disable.disabled = this.readonly || busy || !(this.policyData || {}).enabled;
  this.policyButtons.probe.disabled = this.readonly || busy || !(this.policyData || {}).enabled;
  this.policyButtons.candidates.disabled = this.readonly || busy || !ready;
  this.policyButtons.disable.hidden = !(this.policyData || {}).enabled;
  this.policyButtons.cancel.hidden = !job.busy || jobFeature(job.action) !== 'proxy';
  this.policyButtons.cancel.disabled = this.readonly || this.pendingAction === 'stop' ||
   !job.busy || jobFeature(job.action) !== 'proxy';
  policyFields.forEach(function(key) { this.policyInputs[key].disabled = this.readonly || busy; }, this);
  this.policyNodePicker.sync();
  this.policyConfirm.disabled = this.readonly || busy;
  (this.domainActionButtons || []).forEach(function(button) {
   button.disabled = this.readonly || busy || button.dataset.chosen === 'true' || !validHost(button.dataset.domain);
  }, this);
 },

 policyAction: function(name) {
  if (name === 'cancel') {
   if (!this.policyButtons.cancel.disabled) return this.run('stop');
   return Promise.resolve();
  }
  if (this.policyPending || (this.readonly && name !== 'preview') || this.pending || !!(this.latest.job || {}).busy)
   return Promise.resolve();
  var self = this;
  if (name === 'enable') {
   if (this.policyButtons.enable.disabled) return Promise.resolve();
   if (this.policyPlan && this.policyPlan.can_apply) {
    if (this.policyPlan.restart_required && !this.policyConfirm.checked) {
     this.policyNotice.textContent = '勾选重启确认后，再次点击启用。'; return Promise.resolve();
    }
    return this.policyAction('apply');
   }
   return this.policyAction('preview').then(function() {
    if (self.policyPlan && self.policyPlan.can_apply) {
     if (!self.policyPlan.restart_required) return self.policyAction('apply');
     self.policyNotice.textContent = '本次启用需要重启 PassWall，勾选确认后再次点击启用。';
    }
   });
  }
  var values = this.policyValues(), operation;
  if (name === 'autostart') {
   var autostart = this.policyAutostart.checked ? 1 : 0;
   operation = function() { return callPolicyAutostart(autostart); };
  }
  else
  if (name === 'preview') operation = function() { return callPolicyPreview.apply(null, values); };
  else if (name === 'save') operation = function() { return callPolicySave.apply(null, values); };
  else if (name === 'disable') operation = callPolicyDisable;
  else if (name === 'probe') operation = callPolicyProbe;
  else {
   if (!this.policyPlan || !this.policyPlan.can_apply || this.policyEnvironmentError ||
       (this.policyPlan.restart_required && !this.policyConfirm.checked)) return Promise.resolve();
   values = values.concat([ this.policyPlan.token, this.policyConfirm.checked ? 1 : 0 ]);
   operation = function() { return callPolicyApply.apply(null, values); };
  }
  if (name === 'preview') { this.invalidatePolicy(); this.selectStage('proxy', 'runtime'); }
  this.policyPending = true; this.update(this.latest);
  return rpcRequest(operation).then(function(result) {
   if (name === 'preview') {
    self.policyPlan = result; self.policyConfirm.checked = false;
    self.policyConfirmation.hidden = !result.restart_required;
    var previewSources = result.sources || {};
    self.policyPreviewSources.textContent = '预览设备范围 · Portal ' + ((previewSources.portal || []).join(' / ') || '等待当前地址') +
     '；PS5 ' + ((previewSources.ps5 || []).join(' / ') || '等待当前地址');
    self.policyPreviewNotice.textContent = (result.notice || '') +
     (result.validation ? '。保留 ' + Number(result.validation.protection_rules || 0) + ' 条原有直连 / 阻断保护条件。' : '') +
     ' ' + (((result.entry_scope || {}).notices || []).join('；'));
    self.policyPreviewBody.replaceChildren.apply(self.policyPreviewBody, (result.rules || []).concat((result.direct_rules || []).map(function(rule) {
     return Object.assign({}, rule, { direct: true });
    })).map(function(rule) {
     return E('tr', { 'class': 'tr' }, [ E('td', { 'class': 'td' }, rule.domain + (rule.builtin ? ' · 内置动态' : '')),
      E('td', { 'class': 'td' }, 'TCP ' + rule.ports),
      E('td', { 'class': 'td' }, rule.direct ? '设备直连 · 原有阻断优先' : rule.excluded ? '排除清单 · 原有策略' :
       '所选节点 · 排除 / 直连 / 阻断优先') ]);
    }));
    self.policyPreview.hidden = false;
    self.policyNotice.textContent = (result.blockers || []).join('；') || '预览已生成，核对范围后启用透明代理。';
    self.policyNotice.setAttribute('data-error', String(!result.can_apply));
    self.policyButtons.apply.textContent = result.restart_required ? '应用并重启 PassWall' :
     (self.policyData || {}).enabled ? '热更新配置' : '启用透明代理';
   } else if (name === 'autostart') {
    self.policyData = Object.assign({}, self.policyData, {autostart:result.autostart});
    self.policyBootNotice.textContent = result.autostart ? '开机启用已开启' : '开机启用已关闭';
    self.invalidatePolicy();
   } else if (name === 'probe') {
    self.policyNotice.textContent = '正在检测出口连通性，请等待检测结果。';
    self.policyNotice.setAttribute('data-error', 'false');
    self.selectStage('proxy', 'runtime');
   } else {
    self.invalidatePolicy();
    self.policyNotice.textContent = self.policyConfigNotice.textContent = name === 'save' ?
     '代理配置已保存，可直接启用。' : name === 'disable' ?
      '正在停用透明代理，新连接将使用原有策略。' : '正在校验并启用透明代理，请等待任务完成。';
    self.policyNotice.setAttribute('data-error', 'false');
    self.policyConfigNotice.setAttribute('data-error', 'false');
    if (name === 'save') self.policyTouched = {};
    else self.selectStage('proxy', 'runtime');
   }
  }).catch(function(error) {
   self.policyNotice.textContent = self.policyConfigNotice.textContent = error.message;
   self.policyNotice.setAttribute('data-error', 'true');
   self.policyConfigNotice.setAttribute('data-error', 'true');
   if (name === 'autostart') self.policyAutostart.checked = (self.policyData || {}).autostart !== false;
   if (name === 'apply') self.invalidatePolicy();
  }).finally(function() {
   self.policyPending = false; self.update(self.latest);
   if (name !== 'preview') { self.refreshPolicy(true); self.refresh(); }
  });
 },

 renderPolicy: function() {
  var self = this;
  this.policyInputs = {}; this.policyButtons = {}; this.policyTouched = {};
  this.policyInputs.portal = luciControl('input', { type: 'hidden' });
  this.policyInputs.ps5 = luciControl('input', { type: 'hidden' });
  this.policyState = E('strong', { 'class': 'pa-status-pill' }, '正在读取');
  this.policyEnvironment = E('p', { 'class': 'pa-caption' });
  this.policyRequirements = E('p', { 'class': 'pa-caption pa-domain-problem' });
  this.policyBlockers = E('div', { 'class': 'pa-notice alert-message notice', role: 'status', 'data-error': 'true' });
  this.policyNodeState = E('p', { 'class': 'pa-caption', role: 'status' });
  this.policySourceState = E('p', { 'class': 'pa-caption' });
  this.policyCoverage = E('p', { 'class': 'pa-caption' });
  this.policyCoreSummary = E('p', { 'class': 'pa-caption', role: 'status' });
  this.policyConnections = E('div', { 'class': 'pa-domain-table' });
  this.policyProbeState = E('p', { 'class': 'pa-caption', role: 'status' });
  this.policyProbeResults = E('div');
  this.policyCandidateSummary = E('p', { 'class': 'pa-caption', role: 'status' });
  this.policyRuntimeSummary = E('p', { 'class': 'pa-caption' });
  this.policyDraftState = E('p', { 'class': 'pa-caption' });
  this.policyConfigNotice = E('p', { 'class': 'pa-caption', role: 'status', 'aria-live': 'polite' });
  this.policyNotice = E('div', { 'class': 'pa-notice alert-message notice', role: 'status', 'aria-live': 'polite' },
   '选择节点后启用透明代理。');
  this.policyActiveNode = E('span'); this.policyActiveDomains = E('span'); this.policyAppliedTime = E('span');
  function field(key, label, input, help) {
   input.id = 'psa-policy-' + key; self.policyInputs[key] = input;
   function changed() {
    self.policyTouched[key] = true; self.invalidatePolicy();
    self.policyNotice.textContent = self.policyConfigNotice.textContent = self.policyDraftState.textContent =
     '配置已调整，点击启用应用。';
    self.policyConfigNotice.setAttribute('data-error', 'false');
    if (self.domainData) self.renderDomains(self.domainData);
   }
   input.addEventListener('input', changed); input.addEventListener('change', changed); input.choiceChanged = changed;
   return formField(input, label, help);
  }
  function button(name, label, kind) {
   var node = E('button', { type: 'button', 'class': buttonClass(kind),
    click: function() { return self.policyAction(name); } }, label);
   self.policyButtons[name] = node; return node;
  }
  var nodeInput = choiceControl(luciControl('input', { type: 'hidden' }), '选择代理节点', false);
  this.policyNodePicker = nodeInput.choicePicker;
  this.policyNodeRefresh = E('button', { type: 'button', 'class': buttonClass(),
   click: function() { return self.refreshPolicy(true); } }, '刷新节点');
  this.policyAutostart = luciControl('input', { type: 'checkbox', id: 'psa-policy-autostart',
   change: function() { return self.policyAction('autostart'); } });
  this.policyAutostart.checked = true;
  this.policyBootNotice = E('p', { 'class': 'pa-caption', role: 'status' });
  this.policyDynamicRules = E('p', { 'class': 'pa-caption' });
  this.policyButtons.candidates = E('button', { type: 'button', 'class': buttonClass(),
   click: function() { return self.addSuggestedDomains(); } }, '补齐必要域名');
  this.policyConfirm = luciControl('input', { type: 'checkbox', id: 'psa-policy-confirm',
   change: function() { self.updatePolicyControls(); } });
  this.policyConfirmation = E('label', { 'class': 'pa-toggle', 'for': 'psa-policy-confirm', hidden: '' },
   [ this.policyConfirm, '确认重启 PassWall，当前网络连接可能重连' ]);
  this.policyPreviewSources = E('p', { 'class': 'pa-caption' });
  this.policyPreviewNotice = E('p', { 'class': 'pa-caption' }); this.policyPreviewBody = E('tbody');
  this.policyPreview = E('div', { hidden: '' }, [this.policyPreviewSources,
   E('div', { 'class': 'pa-domain-table pa-policy-table' }, E('table', { 'class': 'table' }, [
    E('thead', {}, E('tr', { 'class': 'tr' }, ['域名 / 匹配规则', '端口', '路径'].map(function(label) {
     return E('th', { 'class': 'th' }, label);
    }))), this.policyPreviewBody ])), this.policyPreviewNotice, button('apply', '应用已检查的配置') ]);
  this.policyRules = E('details', { 'class': 'pa-disclosure' }, [E('summary', {}, '域名与端口'),
   field('ports', 'TCP 端口', luciControl('input', { type: 'text', maxlength: 128, placeholder: '443' }), '默认 443'),
   E('div', { 'class': 'pa-form' }, [
    field('domains', '代理域名', luciControl('textarea', { rows: 5, maxlength: 8192, spellcheck: 'false' }), '每行一个域名或 *.example.com'),
    field('exclusions', '排除域名', luciControl('textarea', { rows: 5, maxlength: 8192, spellcheck: 'false' })) ]),
   E('p', { 'class': 'pa-caption' }, '已自动补充 PlayStation 认证、信令与连接域名。'),
   this.policyCandidateSummary, this.policyButtons.candidates ]);
  this.policyRules.open = true;
  var config = this.panel('透明代理配置', [
   E('div', { 'class': 'pa-node-row' }, [field('node', '代理节点', nodeInput), this.policyNodeRefresh]), this.policyNodeState,
   this.policyRules, E('div', { 'class': 'pa-actions' }, button('save', '保存配置')), this.policyConfigNotice,
   this.policyInputs.portal, this.policyInputs.ps5
  ]);
  var runtime = this.panel('运行状态', [
   E('p', { 'class': 'pa-caption' }, [E('b', {}, '当前节点：'), this.policyActiveNode]),
   this.policyNotice, this.policyBlockers,
   E('div', { 'class': 'pa-actions' }, [button('enable', '启用透明代理', 'primary'),
    button('disable', '停用代理', 'danger'), button('cancel', '取消任务')]),
   E('label', { 'class': 'pa-toggle', 'for': 'psa-policy-autostart' }, [this.policyAutostart, '开机启用']),
   this.policyBootNotice, this.policyConfirmation
  ], this.policyState);
  var diagnostics = E('div', {}, [this.policyCoreSummary, this.policyProbeState, this.policyProbeResults,
   E('div', { 'class': 'pa-actions' }, button('probe', '检测连接')),
   E('details', { 'class': 'pa-disclosure' }, [E('summary', {}, '诊断详情'),
    this.policyRuntimeSummary, this.policySourceState,
    E('p', { 'class': 'pa-caption' }, [this.policyActiveDomains, ' · ', this.policyAppliedTime]),
    this.policyConnections, this.policyEnvironment, this.policyCoverage, this.policyRequirements,
    this.policyDynamicRules, this.policyDraftState, button('preview', '查看规则'), this.policyPreview ])]);
  return {config: config, runtime: runtime, diagnostics: diagnostics};
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
  var oldSelectors = (this.latest || {}).device_selectors || {};
  var changedDevices = ['portal_ip', 'ps5_ip', 'bridge'].some(function(key) { return previousConfig[key] !== config[key]; }) ||
   ['portal', 'ps5'].some(function(key) { return oldSelectors[key] !== (data.device_selectors || {})[key]; });
  this.latest = data;
  if (changedDevices) this.invalidatePolicy();
  var selectors = this.deviceSelectors();
  this.policyInputs.portal.value = selectors.portal; this.policyInputs.ps5.value = selectors.ps5;
  this.scopeNodes.forEach(function(nodes) {
   nodes.portal.textContent = config.portal_ip || '等待配置'; nodes.ps5.textContent = config.ps5_ip || '等待配置';
  });
  this.updatePolicyControls();
  if (proxyJob.action === 'psportal_apply' || proxyJob.action === 'psportal_disable') {
   if (proxyJob.busy) this.policyConfigNotice.textContent = this.policyNotice.textContent =
    actionNames[proxyJob.action] + '中，请等待完成。';
   else if (proxyJob.id !== this.policyJob) {
    this.policyJob = proxyJob.id; this.invalidatePolicy();
    if (proxyJob.action === 'psportal_apply' && proxyJob.state === 'complete') {
     this.policyTouched = {};
     this.domainActionNotice.hidden = true;
    }
    this.policyConfigNotice.textContent = this.policyNotice.textContent = proxyJob.state === 'failed' ? proxyJob.error || '操作失败，请查看任务日志。' :
     proxyJob.state === 'cancelled' ? '透明代理任务已取消，规则恢复完成。' :
     proxyJob.action === 'psportal_disable' ? '透明代理已停用，新连接继续执行原有策略。' : '透明代理已启用，可重新连接 Portal 验证。';
    this.policyNotice.setAttribute('data-error', String(proxyJob.state === 'failed'));
    this.policyConfigNotice.setAttribute('data-error', String(proxyJob.state === 'failed'));
    this.nextPolicyRead = 0; this.refreshPolicy(true);
   }
  } else if (proxyJob.action === 'psportal_probe') {
   if (proxyJob.busy) this.policyNotice.textContent = '正在检测出口连通性，请等待检测结果。';
   else if (proxyJob.id !== this.policyProbeJob) {
    this.policyProbeJob = proxyJob.id;
    this.policyNotice.textContent = proxyJob.state === 'failed' ? proxyJob.error || '出口检测失败，请查看启用日志。' :
     proxyJob.state === 'cancelled' ? '连接检测已取消，代理规则继续运行。' : '连接检测完成，结果见日志与诊断。';
    this.policyNotice.setAttribute('data-error', String(proxyJob.state === 'failed'));
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
   } else if (deviceJob.state === 'complete') deviceMessage = '设备配置已保存，两项功能与域名日志共用已确认的地址。';
   else if (deviceJob.state === 'failed') deviceMessage = deviceJob.error || '设备确认失败，请刷新设备并查看配置日志。';
  }
  if (!deviceJob.busy && (data.running || data.engine_alive))
   deviceMessage += ' 码率增强运行中，停止并完成网络恢复后可保存设备配置。';
  if (!deviceJob.busy && (this.deviceData || {}).proxy_enabled)
   deviceMessage += ' 透明代理已启用，停用后可保存设备配置。';
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
  this.history = []; this.bars = []; this.logTab = 'bitrate'; this.proxyLogTab = 'domains';
  this.logRequests = {}; this.logContent = {}; this.nextLogRead = {}; this.logTabs = {}; this.proxyLogTabs = {};
  this.incidentId = ''; this.mainTabs = {}; this.mainPanels = {}; this.stageTabs = {}; this.stagePanels = {};
  this.activeStages = { bitrate: data.configured ? 'runtime' : 'config', proxy: 'config' };
  this.scopeNodes = []; this.domainActionButtons = [];
  this.deviceSaveError = null;
  this.readonly = !L.hasViewPermission(); this.selectedProfile = config.profile || '65';
  this.deviceNavNode = E('span', { 'class': 'pa-nav-state' }, '等待确认地址');
  this.bitrateNavNode = E('span', { 'class': 'pa-nav-state' }, '等待运行');
  this.proxyNavNode = E('span', { 'class': 'pa-nav-state' }, '点击查看状态');
  this.stateNode = E('span', {}, '正在读取'); this.profileNode = E('span'); this.countNode = E('span');
  this.rateNode = E('span'); this.uptimeNode = E('div', { 'class': 'pa-detail' });
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
   'aria-labelledby': 'psa-proxy-log-tab-proxy', 'aria-label': '透明代理启用日志' }, '正在读取日志…');
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
  this.domainState = E('p', { 'class': 'pa-caption', role: 'status' }, '正在读取域名访问日志…');
  this.domainHealth = E('p', { 'class': 'pa-caption' });
  this.domainSearch = luciControl('input', { type: 'text', maxlength: 253, placeholder: '筛选域名',
   'aria-label': '筛选域名', input: function() { if (self.domainData) self.renderDomains(self.domainData); } });
  this.domainOnlyProblems = luciControl('input', { type: 'checkbox', change: function() {
   if (self.domainData) self.renderDomains(self.domainData);
  } });
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
  this.domainPanel = E('div', { id: 'psa-proxy-log-pane-domains', role: 'tabpanel',
   'aria-labelledby': 'psa-proxy-log-tab-domains' }, [
   this.domainState,
   E('div', { 'class': 'pa-domain-tools' }, [ this.domainSearch,
    E('label', { 'class': 'pa-toggle' }, [ this.domainOnlyProblems, '仅看最近异常' ]),
    E('button', { type: 'button', 'class': buttonClass(), click: function() { self.refreshDomains(true); } }, '刷新域名') ]),
   this.domainActionNotice, this.domainList, this.domainCount,
   E('div', { 'class': 'pa-domain-tools' }, this.incidentSelect.choicePicker.root), this.incidentPanel,
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
   stat('控制转发', this.rateNode, 'Mbps', bars) ]));
  var bitrateRuntime = panel('运行状态', [bitrateStats, this.messageNode,
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
  var proxyLogTabs = this.navigation([['domains', '域名访问'], ['proxy', '启用日志']],
   this.proxyLogTabs, 'psa-proxy-log', 'pa-log-tab', this.selectLogTab);
  var proxyLogs = E('div', { 'class': 'pa-grid' }, [
   panel('透明代理日志', [
    E('div', { 'class': 'pa-log-tools' }, [
     E('ul', { 'class': 'cbi-tabmenu pa-log-tabs', role: 'tablist', 'aria-label': '透明代理日志类型' }, proxyLogTabs),
     E('button', { type: 'button', 'class': 'pa-link btn cbi-button cbi-button-neutral', click: function() { self.refreshLogs(true); } }, '刷新日志')]),
    policy.diagnostics, this.proxyLogNode, this.domainPanel
   ], this.button('proxy_diagnostics', '导出代理诊断'), 'pa-log-panel'),
   E('div', { 'class': 'pa-stack' }, [
    panel('域名日志设置', [
     E('label', { 'class': 'pa-toggle', 'for': 'psa-domain-enabled', style: 'margin-top:0' },
      [this.domainEnabled, '记录 Portal / PS5 域名访问']),
     E('p', { 'class': 'pa-caption' }, '透明代理停用期间也可采集，便于连接前后比较。关闭后保留已有记录。'),
     formField(this.proxyLogMode, '日志详细程度'),
     formField(this.logTag, '本轮排查标记'),
     E('p', { 'class': 'pa-caption' }, '升级或调整配置前保存新标记，随后首次出现的域名标为“本轮新增”。'),
     E('div', { 'class': 'pa-actions', style: 'margin-top:16px' }, this.button('proxy_logging', '保存域名日志设置')),
     this.proxyLoggingNotice]),
    panel('连接失败回溯', [
     formField(this.incidentNote, '设备提示或失败描述'),
     E('div', { 'class': 'pa-actions', style: 'margin-top:14px' }, this.button('incident', '记录这次失败')),
     this.incidentNotice,
     E('p', { 'class': 'pa-caption' }, '回溯前 180 秒、后 15 秒。结合异常域名调整代理清单，保留最近 32 次记录。')])
   ])
  ]);
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
  var mainItems = [
   ['devices', [E('span', {}, '设备配置'), this.deviceNavNode]],
   ['bitrate', [E('span', {}, '码率增强'), this.bitrateNavNode]],
   ['proxy', [E('span', {}, '透明代理'), this.proxyNavNode]]
  ];
  var mainTabs = this.navigation(mainItems, this.mainTabs, 'psa', 'pa-main-tab', this.selectTab);
  this.root = E('div', { 'class': 'cbi-map ps-accel' }, [
   E('style', {}, styles),
   E('h2', {}, 'PS Accel'),
   this.readonly ? E('div', { 'class': 'pa-readonly alert-message notice' }, '当前为只读权限，可查看状态、日志与代理预览。') : E('span'),
   E('ul', { 'class': 'cbi-tabmenu pa-main-tabs', role: 'tablist', 'aria-label': '一级功能' }, mainTabs),
   this.mainPanels.devices, this.mainPanels.bitrate, this.mainPanels.proxy,
   E('footer', { 'class': 'pa-foot' }, this.versionNode)
  ]);
  this.selectLogTab('bitrate'); this.selectLogTab('domains');
  this.update(data);
  var hash = (window.location && window.location.hash || '').replace(/^#/, '').split('/');
  var initial = {stream: 'bitrate', psportal: 'proxy'}[hash[0]] || hash[0];
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
