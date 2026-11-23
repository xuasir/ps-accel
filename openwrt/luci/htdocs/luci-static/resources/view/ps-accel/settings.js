'use strict';
'require view';
'require rpc';
'require poll';
'require ui';

var callStatus = rpc.declare({ object: 'ps-accel', method: 'status', expect: {} });
var callDetails = rpc.declare({ object: 'ps-accel', method: 'details', expect: {} });
var callLogs = rpc.declare({ object: 'ps-accel', method: 'logs', params: [ 'kind' ], expect: {} });
var callConfigure = rpc.declare({ object: 'ps-accel', method: 'configure',
 params: [ 'bridge', 'address', 'ps5_ip', 'portal_ip', 'profile' ], expect: {} });
var callProfile = rpc.declare({ object: 'ps-accel', method: 'profile', params: [ 'profile' ], expect: {} });
var callStart = rpc.declare({ object: 'ps-accel', method: 'start', params: [ 'autostart' ], expect: {} });
var callDiagnostics = rpc.declare({ object: 'ps-accel', method: 'diagnostics', expect: {} });
var calls = {};
[ 'baseline', 'trial', 'stop', 'repair', 'doctor' ].forEach(function(name) {
 calls[name] = rpc.declare({ object: 'ps-accel', method: name, expect: {} });
});
var actionNames = { configure: '设备检测', profile: '应用码率', baseline: '连接测试',
 trial: '试运行', start: '启动中继', stop: '停止中继', repair: '网络恢复', doctor: '环境检查' };
var profilePhases = { stopping: '正在恢复旧连接', saving: '正在保存新码率',
 starting: '正在启动新档位', rollback: '正在恢复原档位',
 waiting_exit: '正在等待进程退出', repairing: '正在恢复与清理网络' };

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

var styles = `
.ps-accel{--pa-bg:#f4f6f8;--pa-card:#fff;--pa-text:#19212e;--pa-muted:#6b7483;--pa-line:#e3e7ed;--pa-accent:#b8dc48;--pa-tint:#eef5d6;--pa-danger:#bd4c4c;color:var(--pa-text);max-width:1180px;margin:0 auto;font-family:inherit}
.ps-accel[data-theme="dark"]{--pa-bg:#101214;--pa-card:#191c20;--pa-text:#edf0f4;--pa-muted:#949da9;--pa-line:#30353b;--pa-tint:#293019;--pa-danger:#f29393}
.ps-accel *{box-sizing:border-box}.ps-accel h2,.ps-accel h3,.ps-accel p{margin:0;color:inherit}.ps-accel button,.ps-accel input,.ps-accel select{font:inherit}
.pa-head{display:flex;align-items:center;justify-content:space-between;gap:20px;padding:12px 0 24px}.pa-brand{display:flex;align-items:center;gap:14px}.pa-mark{display:grid;place-items:center;width:46px;height:46px;border-radius:15px;background:var(--pa-accent);color:#202810;font-size:24px;font-weight:900}.pa-brand h2{font-size:27px;letter-spacing:-1px;font-weight:750;line-height:1.3}.pa-sub{font-size:12px;color:var(--pa-muted);margin-top:4px}.pa-chip{display:inline-flex;align-items:center;gap:7px;border:1px solid var(--pa-line);border-radius:99px;padding:7px 11px;font-size:12px;white-space:nowrap}.pa-dot{height:7px;width:7px;border-radius:50%;background:var(--pa-muted)}[data-running="true"] .pa-dot{background:var(--pa-accent);box-shadow:0 0 0 3px var(--pa-tint)}
.pa-stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:18px}.pa-stat{background:var(--pa-card);border:1px solid var(--pa-line);border-radius:16px;padding:19px 20px;min-height:116px}.pa-label{font-size:12px;color:var(--pa-muted);margin-bottom:12px}.pa-number{font-size:28px;font-weight:700;line-height:1.25;letter-spacing:-.8px;font-variant-numeric:tabular-nums}.pa-number small{font-size:12px;font-weight:400;letter-spacing:0;margin-left:5px;color:var(--pa-muted)}.pa-detail{font-size:11px;color:var(--pa-muted);margin-top:8px;line-height:1.6}
.pa-grid{display:grid;grid-template-columns:minmax(0,1.55fr) minmax(0,1fr);gap:18px}.pa-stack{display:flex;flex-direction:column;gap:18px;min-width:0}.pa-panel{border:1px solid var(--pa-line);background:var(--pa-card);border-radius:17px;overflow:hidden}.pa-panel-body{padding:22px}.pa-panel-head{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:18px}.pa-panel h3{font-size:16px;font-weight:650}.pa-caption{font-size:12px;color:var(--pa-muted);line-height:1.8;margin-top:5px}.pa-mini{color:var(--pa-muted);font-size:11px}.pa-profiles{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:8px;margin:18px 0}.pa-profile{border:1px solid var(--pa-line);border-radius:12px;background:var(--pa-bg);color:var(--pa-text);padding:16px 6px;text-align:center;cursor:pointer;position:relative}.pa-profile strong{font-size:23px;display:block;line-height:1.4;letter-spacing:-.6px}.pa-profile span{display:block;font-size:10px;color:var(--pa-muted);margin-top:3px}.pa-profile[aria-checked="true"]{border-color:var(--pa-accent);background:var(--pa-tint);box-shadow:inset 0 0 0 1px var(--pa-accent)}.pa-profile[aria-checked="true"] strong{color:var(--pa-text)}.pa-profile:disabled{cursor:default;opacity:.6}.pa-selection{font-size:12px;color:var(--pa-muted);line-height:1.7;min-height:21px;margin-bottom:16px}
.ps-accel [hidden]{display:none!important}.pa-main-tabs{display:flex;gap:4px;width:fit-content;max-width:100%;padding:5px;margin-bottom:18px;border:1px solid var(--pa-line);border-radius:12px;background:var(--pa-card)}.pa-main-tab{border:0;border-radius:8px;background:transparent;color:var(--pa-muted);padding:11px 23px;font-size:12px;font-weight:600;cursor:pointer;white-space:nowrap}.pa-main-tab[aria-selected="true"]{background:var(--pa-tint);color:var(--pa-text)}.pa-main-tab:focus-visible,.pa-log-tab:focus-visible{outline:2px solid var(--pa-accent);outline-offset:2px}.pa-tab-panel{min-width:0}.pa-record-detail{margin-top:13px;font-size:11px;color:var(--pa-muted);line-height:1.9;overflow-wrap:anywhere}
.pa-actions{display:flex;flex-wrap:wrap;align-items:center;gap:9px}.pa-btn{border:1px solid var(--pa-line);border-radius:9px;padding:10px 15px;background:var(--pa-bg);color:var(--pa-text);cursor:pointer;font-size:12px;font-weight:550;line-height:1.3;white-space:normal}.pa-btn.primary{background:var(--pa-accent);border-color:var(--pa-accent);color:#263016}.pa-btn.danger{color:var(--pa-danger);background:transparent}.pa-btn:disabled{opacity:.4;cursor:default}.pa-btn:hover:enabled{filter:brightness(.96)}.pa-btn:focus-visible,.pa-profile:focus-visible{outline:2px solid var(--pa-accent);outline-offset:3px}.pa-toggle{display:flex;gap:8px;align-items:center;font-size:12px;margin:18px 0;color:var(--pa-muted)}.pa-toggle input{accent-color:#99b939;width:16px;height:16px;margin:0}
.pa-flow{display:grid;grid-template-columns:minmax(0,1fr) 20px minmax(0,1fr) 20px minmax(0,1fr);align-items:center;margin-top:18px}.pa-device{border:1px solid var(--pa-line);background:var(--pa-bg);border-radius:11px;padding:13px 8px;text-align:center;min-width:0}.pa-device b{font-size:12px;display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.pa-device span{font-size:10px;color:var(--pa-muted);display:block;margin-top:6px;word-break:break-all}.pa-device.router{border-color:var(--pa-accent)}.pa-arrow{text-align:center;color:var(--pa-muted);font-size:13px}.pa-path-note{font-size:11px;color:var(--pa-muted);text-align:center;margin-top:12px;line-height:1.8}
.pa-step{display:flex;align-items:flex-start;gap:10px;padding:13px 0;border-bottom:1px solid var(--pa-line)}.pa-step:last-child{border-bottom:0}.pa-step-icon{width:23px;height:23px;border-radius:50%;display:grid;place-items:center;font-size:11px;background:var(--pa-bg);color:var(--pa-muted);flex-shrink:0}.pa-step[data-ready="true"] .pa-step-icon{background:var(--pa-tint);color:var(--pa-text)}.pa-step-title{font-size:12px;font-weight:600}.pa-step-desc{font-size:11px;color:var(--pa-muted);margin-top:4px;line-height:1.7}.pa-notice{font-size:12px;line-height:1.8;padding:14px 16px;border-radius:10px;background:var(--pa-bg);color:var(--pa-muted);margin-bottom:18px;border-left:3px solid var(--pa-accent)}.pa-notice[data-error="true"]{border-left-color:var(--pa-danger);color:var(--pa-danger)}
.pa-form{display:grid;grid-template-columns:1fr 1fr;gap:15px}.pa-field{display:flex;flex-direction:column;gap:7px;min-width:0}.pa-field label{font-size:12px;font-weight:550}.pa-field input,.pa-field select{border:1px solid var(--pa-line);border-radius:8px;background:var(--pa-bg);color:var(--pa-text);width:100%;min-width:0;padding:10px 11px;min-height:39px;font-size:12px;box-shadow:none}.pa-field input:focus,.pa-field select:focus{border-color:var(--pa-accent);outline:1px solid var(--pa-accent)}.pa-field .pa-caption{font-size:10px;line-height:1.6;margin:0}.pa-form-footer{margin-top:18px}
.pa-log-tabs{display:flex;gap:14px;margin-bottom:14px}.pa-log-tab{background:none;border:0;border-bottom:2px solid transparent;color:var(--pa-muted);font-size:12px;padding:0 0 7px;cursor:pointer}.pa-log-tab[aria-selected="true"]{border-bottom-color:var(--pa-accent);color:var(--pa-text)}.pa-log{background:var(--pa-bg);border:1px solid var(--pa-line);color:var(--pa-muted);padding:14px;border-radius:10px;min-height:135px;max-height:265px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;font-size:11px;line-height:1.9;margin:0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.pa-kv{display:flex;justify-content:space-between;gap:10px;font-size:11px;padding:9px 0;border-bottom:1px solid var(--pa-line);color:var(--pa-muted)}.pa-kv:last-child{border-bottom:0}.pa-kv span:last-child{text-align:right;color:var(--pa-text);word-break:break-word}.pa-foot{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:23px 1px;color:var(--pa-muted);font-size:10px;line-height:1.8}.pa-bars{display:flex;align-items:end;gap:3px;height:22px;margin-top:8px;overflow:hidden}.pa-bars i{flex:1;height:2px;min-width:2px;border-radius:2px;background:var(--pa-accent);opacity:.6}
@media(max-width:800px){.pa-grid{grid-template-columns:1fr;gap:14px}.pa-stack{gap:14px}.pa-main-tabs{width:100%}.pa-main-tab{flex:1;padding:11px 8px}.pa-stats{grid-template-columns:repeat(2,minmax(0,1fr))}.pa-stat{padding:16px;min-height:106px}.pa-panel-body{padding:18px}.pa-head{padding:8px 0 18px}.pa-brand h2{font-size:23px}.pa-mark{width:40px;height:40px;border-radius:12px}.pa-sub{font-size:10px}.pa-number{font-size:25px}.pa-profiles{gap:6px}.pa-profile{padding:13px 3px}.pa-profile strong{font-size:21px}.pa-chip{font-size:10px;padding:6px 9px}.pa-form{gap:12px}}
@media(max-width:380px){.pa-form{grid-template-columns:1fr}.pa-profiles{grid-template-columns:repeat(3,minmax(0,1fr))}.pa-chip{display:none}.pa-flow{grid-template-columns:minmax(0,1fr) 14px minmax(0,1fr) 14px minmax(0,1fr)}}
`;

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

 refreshLogs: function() {
  if (this.activeTab !== 'logs') return Promise.resolve();
  var self = this, kind = this.logTab;
  if (this.logRequests[kind]) return this.logRequests[kind];
  this.logRequests[kind] = rpcRequest(function() { return callLogs(kind); }).then(function(data) {
   self.logContent[kind] = data.text;
   if (self.activeTab !== 'logs' || self.logTab !== kind) return;
   var bottom = self.logNode.scrollHeight - self.logNode.scrollTop - self.logNode.clientHeight < 40;
   self.logNode.textContent = data.text || (kind === 'events' ?
    '中继启动后，新连接事件会显示在这里。' : '设备配对、连接测试与维护操作的输出会显示在这里。');
   if (bottom) self.logNode.scrollTop = self.logNode.scrollHeight;
  }).catch(function(error) {
   if (self.activeTab === 'logs' && self.logTab === kind)
    self.logNode.textContent = '日志读取失败：' + error.message;
  }).finally(function() { delete self.logRequests[kind]; });
  return this.logRequests[kind];
 },

 refresh: function(forceDetails) {
  var self = this;
  if (forceDetails) this.refreshDetails();
  if (this.statusRequest) return this.statusRequest;
  this.statusRequest = rpcRequest(callStatus).then(function(data) {
   self.connectionError = null;
   self.update(Object.assign({}, self.latest, data));
   if (!self.detailsKnown || self.detailsRevision !== data.details_revision) self.refreshDetails();
   self.refreshLogs();
  }).catch(function(error) {
   self.connectionError = error.message;
   self.update(self.latest);
  }).finally(function() { self.statusRequest = null; });
  return this.statusRequest;
 },

 button: function(name, label, kind) {
  var button = E('button', { type: 'button', 'class': 'pa-btn ' + (kind || ''),
   click: ui.createHandlerFn(this, this.run, name) }, label);
  this.buttons[name] = button;
  return button;
 },

 field: function(name, label, input, help) {
  var self = this;
  input.id = 'psa-' + name;
  input.addEventListener('input', function() { self.fieldTouched[name] = true; });
  this.fields[name] = input;
  return E('div', { 'class': 'pa-field' }, [
   E('label', { 'for': input.id }, label), input, E('div', { 'class': 'pa-caption' }, help || '')
  ]);
 },

 selectTab: function(name, focus) {
  if (!this.mainTabs[name]) return;
  this.activeTab = name;
  Object.keys(this.mainTabs).forEach(function(key) {
   this.mainTabs[key].setAttribute('aria-selected', String(key === name));
   this.mainTabs[key].tabIndex = key === name ? 0 : -1;
   this.mainPanels[key].hidden = key !== name;
  }, this);
  if (focus) this.mainTabs[name].focus();
  if (name === 'logs') this.refreshLogs();
 },

 run: function(name) {
  var self = this, request;
  if (name === 'configure') {
   var values = [ 'bridge', 'address', 'ps5_ip', 'portal_ip' ].map(function(key) {
    return self.fields[key].value.trim();
   });
   if (values.some(function(value) { return !value; })) {
    ui.addNotification(null, E('p', '请填写中继、PS5 和 Portal 的地址，并选择 LAN 网桥。'), 'warning');
    return Promise.resolve();
   }
   values.push(this.selectedProfile);
   request = function() { return callConfigure.apply(null, values); };
  }
  else if (name === 'profile') request = function() { return callProfile(self.selectedProfile); };
  else if (name === 'start') request = function() { return callStart(self.autostart.checked ? 1 : 0); };
  else if (name === 'diagnostics') request = callDiagnostics;
  else request = calls[name];
  var pendingToken = {};
  this.pending = true; this.pendingAction = name; this.pendingToken = pendingToken;
  this.update(this.latest);
  return rpcRequest(request).then(function(result) {
   if (name === 'diagnostics') {
    var url = URL.createObjectURL(new Blob([ JSON.stringify(result, null, 2) + '\n' ], { type: 'application/json' }));
    var link = E('a', { href: url, download: 'ps-accel-diagnostics.json' });
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(function() { URL.revokeObjectURL(url); }, 1000);
   }
   if (name === 'start') self.bootTouched = false;
   return self.refresh(name !== 'diagnostics');
  }).catch(function(error) {
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
  if (this.selectedProfile === previousConfig.profile) this.selectedProfile = config.profile || '65';
  if (job.action === 'profile' && !job.busy && job.applied_profile && job.id !== this.appliedJob) {
   this.selectedProfile = job.applied_profile;
   this.appliedJob = job.id;
  }
  this.latest = data;
  if (job.action === 'configure' && job.state === 'complete' && job.id !== this.configuredJob) {
   this.fieldTouched = {}; this.configuredJob = job.id;
  }
  Object.keys(this.fields).forEach(function(key) {
   var input = this.fields[key];
   if (!this.fieldTouched[key] && typeof config[key] === 'string' && input.value !== config[key]) {
    if (key === 'bridge' && config[key] && !Array.prototype.some.call(input.options, function(option) {
     return option.value === config[key];
    })) input.appendChild(E('option', { value: config[key] }, config[key]));
    input.value = config[key];
   }
  }, this);
  var busy = !!job.busy || !!this.pending;
  var locked = this.readonly || busy || !!this.connectionError || data.state_known === false || this.detailsKnown === false;
  var blocked = !!(data.running || data.engine_alive || data.recovery_required || data.foreign_relay || job.orphan_active);
  var profileBlocked = !!(data.recovery_required || data.foreign_relay ||
   (data.running && data.mode !== 'active') || (data.engine_alive && !data.running) || job.orphan_active);
  Object.keys(this.fields).forEach(function(key) { this.fields[key].disabled = locked || blocked; }, this);
  this.profileButtons.forEach(function(button) {
   button.disabled = locked || profileBlocked;
   button.setAttribute('aria-checked', String(button.dataset.profile === this.selectedProfile));
  }, this);
  this.buttons.configure.disabled = locked || blocked;
  this.buttons.profile.disabled = locked || profileBlocked || !data.configured || this.selectedProfile === config.profile;
  this.buttons.profile.textContent = data.running ? '保存并自动重启' : '保存码率';
  this.buttons.baseline.disabled = locked || blocked || !data.configured;
  this.buttons.trial.disabled = locked || blocked || !data.baseline_valid;
  this.buttons.start.disabled = locked || blocked || !data.baseline_valid;
  this.buttons.doctor.disabled = this.readonly || busy;
  this.buttons.repair.disabled = !!(this.readonly || busy || data.running || data.engine_alive || data.foreign_relay || job.orphan_active);
  this.buttons.stop.disabled = this.readonly || this.pendingAction === 'stop' ||
   !(job.busy || this.pending || data.running || data.engine_alive || job.orphan_active || data.recovery_required ||
     job.state === 'failed' || this.connectionError || data.state_known === false);
  this.buttons.diagnostics.disabled = this.pendingAction === 'diagnostics';
  this.autostart.disabled = locked || data.running;
  if (!this.bootTouched) this.autostart.checked = !!data.autostart;

  var state = data.running ? (data.mode === 'baseline' ? '连接测试中' : '运行中') : '已停止';
  if (job.busy) state = (actionNames[job.action] || '操作') + '中';
  if (job.busy && job.action === 'profile') state = profilePhases[job.phase] || '正在应用码率';
  if (job.busy && (job.action === 'stop' || job.action === 'repair'))
   state = profilePhases[job.phase] || '正在停止与恢复';
  if (job.stopping) state = '正在恢复';
  if (!job.busy && data.recovery_required) state = '待恢复';
  if (!job.busy && data.cleanup_pending) state = '清理待重试';
  if (data.state_known === false) state = '状态待确认';
  if (this.connectionError) state = '状态连接中断';
  if (data.foreign_relay) state = '其他中继占用';
  this.stateNode.textContent = state;
  this.root.setAttribute('data-running', String(!!data.running));
  this.profileNode.textContent = config.profile || '65';
  var observability = data.observability || {}, delayed = data.running && observability.status_fresh === false;
  this.countNode.textContent = delayed ? '—' : String(data.modified || 0);
  this.rateNode.textContent = delayed ? '—' : Number(data.control_mbps || 0).toFixed(3);
  var seconds = Math.max(0, Math.floor(data.uptime_seconds || 0));
  this.uptimeNode.textContent = data.running ? '已运行 ' + Math.floor(seconds / 3600) + ' 时 ' + Math.floor(seconds % 3600 / 60) + ' 分' : '完成连接测试后启动';
  var selected = (data.profiles || []).filter(function(profile) { return profile.value === this.selectedProfile; }, this)[0];
  this.selectionNode.textContent = (selected ? selected.description + '。' : '') +
   (this.selectedProfile === config.profile ? ' 当前已保存。' :
    data.running ? ' 保存后自动重启中继，重新连接 Portal 即可应用。' : ' 保存后，在下一次新连接应用。');
  this.routerNode.textContent = config.bridge || 'LAN 网桥';
  this.portalNode.textContent = config.portal_ip || '待配对';
  this.ps5Node.textContent = config.ps5_ip || '待配对';
  this.bridgeNode.textContent = config.address || '待设置独立地址';
  this.steps[0].setAttribute('data-ready', String(!!data.configured));
  this.steps[1].setAttribute('data-ready', String(!!data.baseline_valid));
  this.steps[2].setAttribute('data-ready', String(!data.recovery_required && !data.foreign_relay));
  this.baselineNode.textContent = data.baseline_reason || '尚未完成连接测试';
  this.recoveryNode.textContent = data.foreign_relay ? '先停止当前运行的其他提码率插件' : data.recovery_required ? '停止后执行网络恢复' : data.running ? '恢复进程随中继运行' : '设备使用直达连接';
  this.packetNode.textContent = String((data.counts || {}).forwarded_out || 0) + ' 个包';
  this.kernelNode.textContent = env.kernel || '—';
  this.archNode.textContent = env.target || env.architecture || '—';
  this.packageNode.textContent = env.package_manager || '—';
  this.modelNode.textContent = env.model || 'OpenWrt 主路由';
  this.versionNode.textContent = 'PS Accel ' + (env.version || '0.1.2');
  this.telemetryNode.textContent = delayed ? '采样延迟' : Number(observability.write_errors || 0) > 0 ? '记录异常' : '后台记录正常';
  this.telemetryDetail.textContent = '写入错误 ' + Number(observability.write_errors || 0) +
   ' 次 · 舍弃日志 ' + Number(observability.dropped_logs || 0) + ' 条 · 合并快照 ' +
   Number(observability.coalesced_snapshots || 0) + ' 次' +
   (observability.last_error ? '。最近记录错误：' + observability.last_error : '。');

  var message = data.configured ? '连接测试通过后，进行 90 秒试运行，再启动常驻中继。' : '进入设备配置，填写地址并完成设备配对。';
  if (data.baseline_valid) message = '连接准备就绪。选择目标码率，启动中继后重新连接 Portal。';
  if (data.running) message = '中继已运行，新连接使用 ' + config.profile + ' Mbps 目标。停止时会自动恢复设备直达路径。';
  if (job.busy && job.action === 'configure') message = '正在探测中继地址并配对设备，请保持 PS5 与 Portal 开机。';
  if (job.busy && job.action === 'baseline') message = '等待日志出现 BASELINE READY，再连接 Portal，检查画面与按键。';
  if (job.busy && job.action === 'trial') message = '等待日志出现 AUTO READY，再重新连接。90 秒后自动结束并恢复网络。';
  if (job.busy && job.action === 'start') message = '正在等待 LAN 网桥就绪并启动中继。';
  if (job.busy && job.action === 'profile') message = (profilePhases[job.phase] || '正在应用码率') +
   '。本次操作自动完成网络恢复、保存和重启，请等待完成。';
  if (job.state === 'complete' && job.action === 'profile') message = job.restarted && data.running ?
   '码率已保存，中继已自动重启。重新连接 Portal 即可使用 ' + config.profile + ' Mbps 目标。' :
   '码率已保存，连接测试记录保留。启动中继后重新连接 Portal。';
  if (job.state === 'complete' && job.action === 'trial') message = '试运行完成。确认画面与按键体验后，可启动常驻中继。';
  if (job.state === 'cancelled') message = '操作已停止，网络恢复完成。';
  if (job.state === 'failed') message = job.error || '操作失败，请查看日志与诊断摘要。';
  if (job.state === 'failed' && job.rolled_back) message += ' 原档位已恢复，中继已重新启动。';
  if (delayed && !job.busy && job.state !== 'failed') message += ' 统计采样延迟，中继进程保持运行。详情见日志诊断。';
  if (data.recovery_required && !job.busy) message = (job.state === 'failed' ? message + ' ' : '') +
   (data.cleanup_pending ? '网络清理待重试，点击“恢复网络”继续完成清理。' :
    '需要完成网络恢复。点击停止，待退出后重试恢复网络。');
  if (job.cleanup_error && !job.busy && job.cleanup_error !== job.error)
   message += ' 恢复详情：' + job.cleanup_error;
  if (job.rollback_error && !job.busy && job.rollback_error !== job.cleanup_error)
   message += ' 原档位恢复详情：' + job.rollback_error;
  if (job.orphan_active && !job.busy) message += ' 前次进程仍在退出，点击停止继续完成恢复。';
  if (data.foreign_relay) message = '协议引擎由其他提码率插件占用。先在原插件中停止服务，再启动 PS Accel。';
  if (job.stopping || (job.busy && job.action === 'stop')) message =
   (profilePhases[job.phase] || '正在停止中继') + '，完成后恢复设备连接。';
  var warnings = (data.status_warnings || []).concat(data.details_warnings || []);
  if (warnings.length) message += ' 状态读取提示：' + warnings.join('；') + '。停止与恢复入口可继续重试。';
  if (this.connectionError) message = '状态连接中断：' + this.connectionError + ' 停止与恢复入口保持可重试。';
  this.messageNode.textContent = message;
  this.messageNode.setAttribute('data-error', String(job.state === 'failed' || (!!data.recovery_required && !job.busy)));
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
  this.fields = {}; this.fieldTouched = {}; this.buttons = {}; this.history = []; this.bars = []; this.logTab = 'log';
  this.logRequests = {}; this.logContent = {};
  this.mainTabs = {}; this.mainPanels = {};
  this.readonly = !L.hasViewPermission();
  this.selectedProfile = config.profile || '65';
  this.stateNode = E('span', {}, '正在读取'); this.profileNode = E('span'); this.countNode = E('span');
  this.rateNode = E('span'); this.uptimeNode = E('div', { 'class': 'pa-detail' });
  this.selectionNode = E('div', { 'class': 'pa-selection' });
  this.routerNode = E('b'); this.portalNode = E('span'); this.ps5Node = E('span'); this.bridgeNode = E('span');
  this.baselineNode = E('div', { 'class': 'pa-step-desc' }); this.recoveryNode = E('div', { 'class': 'pa-step-desc' });
  this.packetNode = E('span'); this.kernelNode = E('span'); this.archNode = E('span'); this.packageNode = E('span');
  this.modelNode = E('span'); this.versionNode = E('span');
  this.telemetryNode = E('span'); this.telemetryDetail = E('div', { 'class': 'pa-record-detail' });
  this.messageNode = E('div', { 'class': 'pa-notice', role: 'status', 'aria-live': 'polite' });
  this.logNode = E('pre', { 'class': 'pa-log', 'aria-label': '操作日志' }, '正在读取日志…');
  this.autostart = E('input', { type: 'checkbox', id: 'psa-autostart', change: function() { self.bootTouched = true; } });
  var profiles = data.profiles || ['35', '45', '65', '100', '200'].map(function(value) {
   return { value: value, label: value + ' Mbps', experimental: value === '200' };
  });
  this.profileButtons = profiles.map(function(profile) {
   var button = E('button', { type: 'button', 'class': 'pa-profile', role: 'radio',
    'data-profile': profile.value, 'aria-label': profile.label + '，' + profile.description,
    click: function() { self.selectedProfile = profile.value; self.update(self.latest); } }, [
    E('strong', {}, profile.value), E('span', {}, 'Mbps'),
    E('span', {}, profile.value === '65' ? '推荐' : profile.experimental ? '实验' : '\u00a0')
   ]);
   return button;
  });
  function panel(title, content, extra) {
   var classes = { '画质与码率': 'pa-bitrate', '中继控制': 'pa-control', '本地连接路径': 'pa-topology',
    '日志与诊断': 'pa-logs', '主路由环境': 'pa-environment' };
   return E('section', { 'class': 'pa-panel ' + (classes[title] || '') }, E('div', { 'class': 'pa-panel-body' }, [
    E('div', { 'class': 'pa-panel-head' }, [ E('h3', {}, title), extra || E('span') ])
   ].concat(content)));
  }
  function stat(label, value, unit, detail) {
   return E('div', { 'class': 'pa-stat' }, [ E('div', { 'class': 'pa-label' }, label),
    E('div', { 'class': 'pa-number' }, [ value, unit ? E('small', {}, unit) : E('span') ]), detail ]);
  }
  function detail(text) { return E('div', { 'class': 'pa-detail' }, text); }
  function step(number, title, description) {
   return E('div', { 'class': 'pa-step' }, [ E('span', { 'class': 'pa-step-icon' }, number),
    E('div', {}, [ E('div', { 'class': 'pa-step-title' }, title), description ]) ]);
  }
  this.steps = [ step('1', '设备配对', E('div', { 'class': 'pa-step-desc' }, 'PS5 与 Portal 使用固定地址')),
   step('2', '连接测试', this.baselineNode), step('3', '网络恢复', this.recoveryNode) ];
  var bridgeNames = (data.bridges || []).slice(), bridgeName = config.bridge || 'br-lan';
  if (bridgeNames.indexOf(bridgeName) < 0) bridgeNames.unshift(bridgeName);
  var bridge = E('select', {}, bridgeNames.map(function(name) { return E('option', { value: name }, name); }));
  bridge.value = bridgeName;
  function input(value, placeholder) {
   return E('input', { type: 'text', value: value || '', placeholder: placeholder,
    maxlength: 80, spellcheck: 'false', autocomplete: 'off' });
  }
  var deviceSettings = panel('设备与网桥', [
    E('div', { 'class': 'pa-form' }, [
     this.field('bridge', 'LAN 网桥', bridge, '选择 PS5 与 Portal 所在的网桥。'),
     this.field('address', '中继独立地址', input(config.address, '10.0.0.250/24'), '使用空闲地址，避开主路由地址和 DHCP 动态池。'),
     this.field('ps5_ip', 'PS5 地址', input(config.ps5_ip, '10.0.0.100'), '建议在主路由设置 DHCP 静态租约。'),
     this.field('portal_ip', 'Portal 地址', input(config.portal_ip, '10.0.0.101'), '检测时保持两台设备开机。')
    ]), E('div', { 'class': 'pa-form-footer pa-actions' }, [ this.button('configure', '保存并检测设备'),
     E('span', { 'class': 'pa-mini' }, '停止中继后修改地址，并重新完成连接测试。') ])
   ]);
  var bars = E('div', { 'class': 'pa-bars', 'aria-label': '最近控制转发速率采样' });
  for (var i = 0; i < 24; i++) { var bar = E('i'); this.bars.push(bar); bars.appendChild(bar); }
  var tabs = [ [ 'log', '任务输出' ], [ 'events', '中继事件' ] ].map(function(item) {
   return E('button', { type: 'button', 'class': 'pa-log-tab', role: 'tab', 'aria-selected': String(item[0] === 'log'),
    click: function(event) {
     self.logTab = item[0];
     Array.prototype.forEach.call(event.currentTarget.parentNode.children, function(tab) {
      tab.setAttribute('aria-selected', String(tab === event.currentTarget));
     });
     self.logNode.textContent = self.logContent[item[0]] || '正在读取日志…';
     self.refreshLogs();
    } }, item[1]);
  });
  this.mainPanels.stream = E('div', { id: 'psa-pane-stream', 'class': 'pa-tab-panel pa-grid',
   role: 'tabpanel', 'aria-labelledby': 'psa-tab-stream' }, [
   panel('画质与码率', [ E('p', { 'class': 'pa-caption' }, '从稳定档位起步，结合实际游戏场景逐档调整。'),
    E('div', { 'class': 'pa-profiles', role: 'radiogroup', 'aria-label': '目标码率' }, this.profileButtons),
    this.selectionNode, E('div', { 'class': 'pa-actions' }, [ this.button('profile', '保存码率'),
     E('span', { 'class': 'pa-mini' }, '保留有效连接测试记录') ]) ]),
   panel('中继控制', [ E('div', {}, this.steps),
    E('div', { 'class': 'pa-actions', style: 'margin-top:18px' }, [ this.button('baseline', '连接测试 · 60 秒'),
     this.button('trial', '试运行 · 90 秒') ]),
    E('label', { 'class': 'pa-toggle', 'for': 'psa-autostart' }, [ this.autostart, '随主路由开机启动' ]),
    E('div', { 'class': 'pa-actions' }, [ this.button('start', '启动中继', 'primary'), this.button('stop', '停止', 'danger') ]) ])
  ]);
  this.mainPanels.devices = E('div', { id: 'psa-pane-devices', 'class': 'pa-tab-panel pa-grid',
   role: 'tabpanel', 'aria-labelledby': 'psa-tab-devices' }, [ deviceSettings,
   E('div', { 'class': 'pa-stack' }, [
    panel('本地连接路径', [ E('p', { 'class': 'pa-caption' }, '控制流经过主路由的独立网络空间。'),
     E('div', { 'class': 'pa-flow' }, [ E('div', { 'class': 'pa-device' }, [ E('b', {}, 'Portal'), this.portalNode ]),
      E('span', { 'class': 'pa-arrow' }, '→'), E('div', { 'class': 'pa-device router' }, [ this.routerNode, this.bridgeNode ]),
      E('span', { 'class': 'pa-arrow' }, '→'), E('div', { 'class': 'pa-device' }, [ E('b', {}, 'PS5'), this.ps5Node ]) ]),
     E('div', { 'class': 'pa-path-note' }, '视频回程：PS5 → Portal 直达'),
     E('div', { 'class': 'pa-kv', style: 'margin-top:13px' }, [ E('span', {}, '控制转发累计'), this.packetNode ]) ]),
    panel('主路由环境', [ E('div', { 'class': 'pa-kv' }, [ E('span', {}, '设备'), this.modelNode ]),
     E('div', { 'class': 'pa-kv' }, [ E('span', {}, '目标平台'), this.archNode ]),
     E('div', { 'class': 'pa-kv' }, [ E('span', {}, '内核'), this.kernelNode ]),
     E('div', { 'class': 'pa-kv' }, [ E('span', {}, '包管理器'), this.packageNode ]) ])
   ])
  ]);
  this.mainPanels.logs = E('div', { id: 'psa-pane-logs', 'class': 'pa-tab-panel pa-grid',
   role: 'tabpanel', 'aria-labelledby': 'psa-tab-logs' }, [
   panel('日志与诊断', [ E('div', { 'class': 'pa-log-tabs', role: 'tablist', 'aria-label': '日志类型' }, tabs),
    this.logNode, E('p', { 'class': 'pa-caption', style: 'margin-top:12px' },
     '导出包含运行与恢复摘要，设备地址及原始报文保留在本机。')
   ], this.button('diagnostics', '导出诊断')),
   E('div', { 'class': 'pa-stack' }, [
    panel('记录状态', [ E('div', { 'class': 'pa-kv' }, [ E('span', {}, '日志与统计'), this.telemetryNode ]),
     E('div', { 'class': 'pa-kv' }, [ E('span', {}, '事件日志容量'), E('span', {}, '每份 1 MiB · 保留 2 份备份') ]),
     this.telemetryDetail, E('p', { 'class': 'pa-caption', style: 'margin-top:12px' },
      '写入延迟会合并统计快照。记录状态与中继运行状态分别显示。') ]),
    panel('维护操作', [ E('p', { 'class': 'pa-caption', style: 'margin-bottom:15px' },
     '检查主路由依赖，或在中继停止后恢复设备直达路径。'),
     E('div', { 'class': 'pa-actions' }, [ this.button('doctor', '环境检查'), this.button('repair', '恢复网络', 'danger') ]) ])
   ])
  ]);
  var mainItems = [ [ 'stream', '串流控制' ], [ 'devices', '设备配置' ], [ 'logs', '日志诊断' ] ];
  var mainTabs = mainItems.map(function(item, index) {
   var button = E('button', { id: 'psa-tab-' + item[0], type: 'button', 'class': 'pa-main-tab',
    role: 'tab', 'aria-controls': 'psa-pane-' + item[0],
    click: function() { self.selectTab(item[0]); },
    keydown: function(event) {
     var position = index;
     if (event.key === 'ArrowRight') position = (index + 1) % mainItems.length;
     else if (event.key === 'ArrowLeft') position = (index + mainItems.length - 1) % mainItems.length;
     else if (event.key === 'Home') position = 0;
     else if (event.key === 'End') position = mainItems.length - 1;
     else return;
     event.preventDefault();
     self.selectTab(mainItems[position][0], true);
    } }, item[1]);
   self.mainTabs[item[0]] = button;
   return button;
  });
  this.root = E('div', { 'class': 'ps-accel' }, [ E('style', {}, styles),
   E('header', { 'class': 'pa-head' }, [ E('div', { 'class': 'pa-brand' }, [ E('div', { 'class': 'pa-mark' }, 'P'),
    E('div', {}, [ E('h2', {}, 'PS Accel'), E('div', { 'class': 'pa-sub' }, 'PS5 × Portal · 本地串流控制') ]) ]),
    E('span', { 'class': 'pa-chip' }, [ E('i', { 'class': 'pa-dot' }), 'OpenWrt 主路由' ]) ]),
   E('div', { 'class': 'pa-stats' }, [ stat('中继状态', this.stateNode, '', this.uptimeNode),
    stat('目标码率', this.profileNode, 'Mbps', detail('下一次新连接使用的请求值')),
    stat('已修改连接', this.countNode, '次', detail('每次握手重传合并计数')),
    stat('控制转发', this.rateNode, 'Mbps', bars) ]),
   E('nav', { 'class': 'pa-main-tabs', role: 'tablist', 'aria-label': '控制台功能' }, mainTabs),
   this.messageNode, this.mainPanels.stream, this.mainPanels.devices, this.mainPanels.logs,
   E('footer', { 'class': 'pa-foot' }, [ this.versionNode,
    E('span', {}, '本地运行 · 原生 LuCI · 主路由网络隔离') ])
  ]);
  var rgb = window.getComputedStyle(document.body).color.match(/\d+/g);
  this.root.setAttribute('data-theme', rgb && Number(rgb[0]) + Number(rgb[1]) + Number(rgb[2]) > 480 ? 'dark' : 'light');
  this.selectTab(data.configured ? 'stream' : 'devices');
  this.update(data);
  poll.add(function() { return self.refresh(); }, 3);
  return this.root;
 },
 handleSaveApply: null,
 handleSave: null,
 handleReset: null
});
