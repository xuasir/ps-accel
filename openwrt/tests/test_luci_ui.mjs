import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const source = readFileSync(new URL('../luci/htdocs/luci-static/resources/view/ps-accel/settings.js', import.meta.url), 'utf8');
const settle = () => new Promise(resolve => setImmediate(resolve));
const nodeText = element => element.textContent + element.children.map(nodeText).join('');

class Element {
 constructor(tag) {
  this.tag = tag; this.children = []; this.dataset = {}; this.attributes = {};
  this.handlers = {}; this.style = {}; this.textContent = ''; this.disabled = false;
  this.value = ''; this.scrollHeight = 0; this.scrollTop = 0; this.clientHeight = 0;
 }
 setAttribute(key, value) {
  this.attributes[key] = String(value);
  if (key.startsWith('data-')) this.dataset[key.slice(5)] = String(value);
  if (key === 'value') this.value = String(value);
  if (key === 'id') this.id = String(value);
 }
 appendChild(child) { this.children.push(child); child.parentNode = this; return child; }
 replaceChildren(...children) {
  this.children = []; this.textContent = '';
  children.forEach(child => child instanceof Element ? this.appendChild(child) : this.textContent += String(child));
 }
 addEventListener(name, handler) { this.handlers[name] = handler; }
 get options() { return this.children.filter(child => child.tag === 'option'); }
 focus() { this.focused = true; }
 select() { this.selected = true; }
 click() { if (!this.disabled) return this.handlers.click?.({ currentTarget: this, preventDefault() {} }); }
 remove() {
  this.removed = true;
  if (this.parentNode) this.parentNode.children = this.parentNode.children.filter(child => child !== this);
 }
}

function E(tag, attrs, children) {
 if (typeof attrs === 'string' || Array.isArray(attrs) || attrs instanceof Element) {
  children = attrs; attrs = {};
 }
 const element = new Element(tag);
 for (const [key, value] of Object.entries(attrs || {})) {
  if (typeof value === 'function') element.addEventListener(key, value);
  else element.setAttribute(key, value);
 }
 function append(child) {
  if (Array.isArray(child)) child.forEach(append);
  else if (child instanceof Element) element.appendChild(child);
  else if (child != null) element.textContent += String(child);
 }
 append(children);
 return element;
}

function harness({ manualTimers = false, permission = true } = {}) {
 const calls = [], notifications = [], handlers = {}, timers = new Map(), clipboardWrites = [];
 let timerId = 0;
 const details = { ok: true, details_revision: 'v1', details_warnings: [],
  config: { bridge: 'br-lan', address: '10.0.0.250/24', ps5_ip: '10.0.0.100', portal_ip: '10.0.0.101', profile: '65' },
  configured: true, devices_configured: true,
  device_selectors: { portal: '02:00:00:00:00:01', ps5: '02:00:00:00:00:02' }, baseline_valid: true, baseline_reason: '校验通过', bridges: ['br-lan'],
  autostart: false, profiles: ['35', '45', '65', '100', '200'].map(value => ({ value, description: value+' Mbps' })),
  environment: { version: '0.1.3' }, logging: { mode: 'compact', domains: true, tag: '' } };
 const domainData = { ok: true, logging: details.logging, domains: [
  { device: 'portal', domain: 'api.sony.example', first_seen: '2026-11-23T10:00:00Z',
   last_seen: '2026-11-23T10:01:00Z', counts: { dns_ok: 1 }, addresses: [], last_problem: '', new_since_tag: true }
 ], observer: { state: 'observing', fresh: true, health: {}, observability: {} }, incidents: [], selected: null };
 domainData.batch = {id:'d'.repeat(32),time:'2026-11-23T10:00:00Z',state:'collecting',domains:domainData.domains,events:[],event_count:1};
 domainData.batches = [{id:domainData.batch.id,time:domainData.batch.time,state:'collecting',domain_count:1,failed_count:0}];
 domainData.inventory_count = domainData.domains.length;
 const status = { ok: true, details_revision: 'v1', state_known: true, status_warnings: [],
  running: false, engine_alive: false, recovery_required: false, cleanup_pending: false,
  mode: 'active', counts: {}, foreign_relay: false,
  job: { id: 'initial', state: 'complete', busy: false, action: 'baseline' } };
 const policyData = { ok:true,available:true,mode:'device_acl',enabled:true,running:true,
  controlled:true,loaded:true,policy_mode:'proxy',devices_ready:true,can_apply:true,can_direct:true,can_release:true,
  revision:'a'.repeat(64),config:{domains:'auth.api.playstation.com\n',exclusions:'dwc.dl.playstation.net\n',node:'xray_a'},
  device_group:{portal:{ip:'10.0.0.101',mac:details.device_selectors.portal},ps5:{ip:'10.0.0.100',mac:details.device_selectors.ps5}},
  environment:{cores:['xray'],selected_core:'xray',rules_path:'PassWall UCI · ps_accel_devices'},
  nodes:[{id:'xray_a',label:'已有 Xray 出口',core:'xray',protocol:'vless',available:true},
   {id:'sing_a',label:'已有 Sing-box 出口',core:'sing-box',protocol:'anytls',available:true}],
  counts:{domains:1,exclusions:1},warnings:[],blockers:[],receipt:{},pending_apply:false };
 policyData.file_config=structuredClone(policyData.config);
 const deviceData = { ok: true, configured: true, proxy_enabled: false,
  config: { bridge: details.config.bridge, portal_ip: details.config.portal_ip, ps5_ip: details.config.ps5_ip },
  binding: { config: { bridge: details.config.bridge, portal_ip: details.config.portal_ip, ps5_ip: details.config.ps5_ip },
   portal_mac: details.device_selectors.portal, ps5_mac: details.device_selectors.ps5 },
  devices: [{ mac: details.device_selectors.portal, label: 'Portal', addresses: [details.config.portal_ip], source: 'dhcp' },
   { mac: details.device_selectors.ps5, label: 'PS5', addresses: [details.config.ps5_ip], source: 'dhcp' }] };
 const window = {
  navigator: {clipboard: {writeText: text => { clipboardWrites.push(text); return Promise.resolve(); }}},
  setTimeout: manualTimers ? fn => { timers.set(++timerId, fn); return timerId; } : setTimeout,
  clearTimeout: manualTimers ? id => timers.delete(id) : clearTimeout };
 const rpc = { declare: spec => (...args) => {
  calls.push({ method: spec.method, args });
  if (handlers[spec.method]) return handlers[spec.method](...args);
  if (spec.method === 'details') return Promise.resolve(structuredClone(details));
  if (spec.method === 'status') return Promise.resolve(structuredClone(status));
  if (spec.method === 'logs') return Promise.resolve({ ok: true, kind: args[0], text: args[0]+' output' });
  if (spec.method === 'devices') return Promise.resolve(structuredClone(deviceData));
  if (spec.method === 'domains') return Promise.resolve(structuredClone(domainData));
  if (spec.method === 'domain_monitor') return Promise.resolve(structuredClone(domainData));
  if (spec.method === 'psportal_status') return Promise.resolve(structuredClone(policyData));
  if (spec.method === 'psportal_save') {
   policyData.config = {domains: args[0], exclusions: args[1], node: args[2]};
   policyData.file_config = structuredClone(policyData.config);
   policyData.revision = 'b'.repeat(64); policyData.pending_apply = true;
   return Promise.resolve({ok:true,config:policyData.config,revision:policyData.revision,pending_apply:true,
    notice:'设备草稿已保存，应用设备规则后生效。'});
  }
  return Promise.resolve({ ok: true });
 } };
 const poll = { add: (callback, seconds) => { poll.callback = callback; poll.seconds = seconds; } };
 const ui = { createHandlerFn: (object, fn, name) => event => {
  // LuCI disables the clicked control before invoking the application handler.
  const target = event.currentTarget;
  target.disabled = true;
  Promise.resolve(fn.call(object, name, event)).finally(() => { target.disabled = false; });
 },
  addNotification: (_id, element) => notifications.push(element.textContent) };
 const document = { body: new Element('body') };
 const app = new Function('view', 'rpc', 'poll', 'ui', 'E', 'window', 'document', 'L', source)(
  { extend: object => object }, rpc, poll, ui, E, window, document,
  { hasViewPermission: () => permission });
 return { app, calls, handlers, status, details, domainData, policyData, deviceData, notifications, timers, poll,
  clipboardWrites, window, document,
  init: async () => { app.render(await app.load()); await settle(); },
  expire: () => { for (const [id, fn] of [...timers]) { timers.delete(id); fn(); } } };
}

async function policyTab(h) {
 h.app.selectTab('proxy');
 await h.app.policyRequest;
 await settle();
}

test('native list controls follow the configured node core', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 assert.deepEqual(Object.keys(h.app.policyInputs), ['node', 'domains', 'exclusions']);
 assert.deepEqual(Object.keys(h.app.policyButtons), ['save', 'apply', 'reload', 'direct', 'release', 'cancel']);
 assert.equal(h.app.policyButtons.apply.disabled, false);
 assert.match(nodeText(h.app.mainPanels.proxy), /两设备专属域名规则|应用设备规则/);
 assert.doesNotMatch(nodeText(h.app.mainPanels.proxy), /选择代理节点|检测出口|TCP 端口|开机启用/);
 assert.match(h.app.policyEnvironment.textContent, /xray/);
 h.policyData.config.node = 'sing_a';
 h.policyData.file_config.node = 'sing_a';
 h.policyData.environment.selected_core = 'sing-box'; h.policyData.enabled = false; h.policyData.running = false;
 await h.app.refreshPolicy(true);
 assert.equal(h.app.policyInputs.node.value, 'sing_a');
 assert.match(h.app.policyEnvironment.textContent, /sing-box/);
 assert.equal(h.app.policyButtons.apply.disabled, false);
});

test('native list reads load on demand and polling retains the current form', async () => {
 const h = harness(); await h.init();
 assert.equal(h.calls.some(call => call.method === 'psportal_status'), false);
 await policyTab(h); h.calls.length = 0;
 await h.app.refresh(); await settle();
 assert.deepEqual(h.calls.map(call => call.method), ['status']);
 h.app.policyInputs.domains.value += 'new.example.com\n'; h.app.policyInputs.domains.handlers.input();
 await h.app.refreshPolicy(true);
 assert.match(h.app.policyInputs.domains.value, /new.example.com/);
});

test('list save sends both native lists and their original revision', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 h.app.policyInputs.domains.value += 'new.example.com\n'; h.app.policyInputs.domains.handlers.input();
 await h.app.policyAction('save'); await settle();
 const call = h.calls.find(call => call.method === 'psportal_save');
 assert.deepEqual(call.args, ['auth.api.playstation.com\nnew.example.com\n', 'dwc.dl.playstation.net\n', 'xray_a', 'a'.repeat(64)]);
 assert.equal(h.app.policyRevision, 'b'.repeat(64));
 assert.deepEqual(h.app.policyTouched, {});
 assert.equal(h.calls.some(call => call.method === 'psportal_apply'), false);
});

test('save and apply submits a list transaction and reports its own completion', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 await h.app.policyAction('apply'); await settle();
 assert.equal(h.calls.filter(call => call.method === 'psportal_apply').length, 1);
 assert.equal(h.calls.some(call => call.method === 'psportal_preview'), false);
 assert.equal(h.calls.find(call => call.method === 'psportal_apply').args.length, 4);
 h.status.job = {id:'applied',action:'psportal_apply',state:'complete',busy:false,reloaded:false,pending_apply:true};
 await h.app.refresh(); await settle();
 assert.match(h.app.policyNotice.textContent, /启动后/);
});

test('external list edits preserve the draft and require a deliberate reread', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 h.app.policyInputs.domains.value = 'edited.example.com\n'; h.app.policyInputs.domains.handlers.input();
 h.policyData.config.domains = 'external.example.com\n'; h.policyData.revision = 'c'.repeat(64);
 await h.app.refreshPolicy(true);
 assert.equal(h.app.policyInputs.domains.value, 'edited.example.com\n');
 assert.equal(h.app.policyRevision, 'a'.repeat(64));
 assert.equal(h.app.policyButtons.save.disabled, true);
 assert.match(h.app.policyConfigNotice.textContent, /外部修改/);
 await h.app.reloadPolicyLists();
 assert.equal(h.app.policyInputs.domains.value, 'external.example.com\n');
 assert.equal(h.app.policyRevision, 'c'.repeat(64));
 assert.equal(h.app.policyButtons.save.disabled, false);
});

test('native list saving works before device and bitrate enrollment', async () => {
 const h = harness(); h.details.configured = h.details.devices_configured = false;
 h.details.device_selectors = {}; h.details.config.portal_ip = h.details.config.ps5_ip = ''; h.policyData.devices_ready = false;
 await h.init(); await policyTab(h);
 assert.equal(h.app.policyButtons.save.disabled, false);
 h.app.selectTab('devices'); await h.app.refreshDevices(true);
 assert.equal(h.app.buttons.device_save.disabled, false);
});

test('read-only users can reread lists and keep their write boundary', async () => {
 const h = harness({permission:false}); await h.init(); await policyTab(h);
 assert.equal(h.app.policyButtons.save.disabled, true);
 assert.equal(h.app.policyButtons.apply.disabled, true);
 assert.equal(h.app.policyButtons.reload.disabled, false);
 await h.app.policyAction('apply'); await h.app.reloadPolicyLists();
 assert.equal(h.calls.some(call => call.method === 'psportal_apply'), false);
});

test('native list writers wait for management jobs and recover from a failed read', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 h.status.job = {id:'trial',action:'trial',busy:true,state:'running'}; await h.app.refresh();
 assert.equal(h.app.policyButtons.apply.disabled, true);
 await h.app.policyAction('apply');
 assert.equal(h.calls.some(call => call.method === 'psportal_apply'), false);
 h.status.job.busy = false; await h.app.refresh();
 h.handlers.psportal_status = () => Promise.reject(new Error('read failed'));
 await h.app.refreshPolicy(true);
 assert.equal(h.app.policyButtons.save.disabled, true);
 assert.equal(h.app.policyButtons.reload.disabled, false);
 delete h.handlers.psportal_status; await h.app.reloadPolicyLists();
 assert.equal(h.app.policyButtons.save.disabled, false);
});

test('moving native domains preserves comments and geosite entries in both lists', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 h.app.policyInputs.domains.value = '# keep proxy\ngeosite:google\nother.example.com\n';
 h.app.policyInputs.exclusions.value = '# keep direct\ngeosite:cn\napi.example.com\n';
 h.app.addDomainToPolicy('api.example.com', 'domains');
 assert.equal(h.app.policyInputs.domains.value, '# keep proxy\ngeosite:google\nother.example.com\napi.example.com\n');
 assert.equal(h.app.policyInputs.exclusions.value, '# keep direct\ngeosite:cn\n');
 h.app.removeDomainFromPolicy('api.example.com');
 assert.equal(h.app.policyInputs.domains.value, '# keep proxy\ngeosite:google\nother.example.com\n');
 assert.equal(h.app.policyInputs.exclusions.value, '# keep direct\ngeosite:cn\napi.example.com\n');
});

test('native parent domains use suffix matching while a direct parent remains visible', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 h.app.policyInputs.domains.value = 'domain:example.com\n';
 assert.match(nodeText(h.app.domainRuleActions('api.example.com')), /已加入代理/);
 assert.match(nodeText(h.app.domainRuleActions('example.com.attacker.net')), /默认直连/);
 h.app.policyInputs.exclusions.value = 'domain:example.com\n';
 const original = h.app.policyInputs.domains.value;
 h.app.addDomainToPolicy('api.example.com','domains');
 assert.equal(h.app.policyInputs.domains.value, original);
 assert.match(h.app.domainActionText.textContent, /直连父域/);
 assert.match(nodeText(h.app.domainRuleActions('api.example.com')), /直连名单/);
});

test('hidden log panels generate only dynamic status polls', async () => {
 const h = harness(); await h.init(); h.calls.length = 0;
 await h.app.refresh(); await settle();
 assert.deepEqual(h.calls.map(call => call.method), ['status']);
 assert.equal(h.poll.seconds, 3);
 h.app.selectStage('bitrate', 'logs'); await h.app.refreshLogs(true);
 assert.equal(h.app.logNode.textContent, 'bitrate output');
 assert.deepEqual(h.calls.filter(call => call.method === 'logs').map(call => call.args), [['bitrate']]);
 h.app.logTab = 'events'; await h.app.refreshLogs();
 assert.equal(h.app.logNode.textContent, 'events output');
 h.app.selectTab('bitrate'); h.calls.length = 0;
 await h.app.refresh(); await settle();
 assert.deepEqual(h.calls.map(call => call.method), ['status']);
});

test('cleanup failure leaves stop and repair available and a successful retry unlocks start', async () => {
 const h = harness(); await h.init();
 Object.assign(h.status, { recovery_required: true, cleanup_pending: true,
  job: { id: 'failed-stop', action: 'stop', state: 'failed', busy: false, error: 'namespace deletion failed' } });
 await h.app.refresh();
 assert.equal(h.app.stateNode.textContent, '清理待重试');
 assert.equal(h.app.buttons.stop.disabled, false);
 assert.equal(h.app.buttons.repair.disabled, false);
 assert.equal(h.app.buttons.start.disabled, true);
 h.handlers.repair = () => {
  Object.assign(h.status, { recovery_required: false, cleanup_pending: false,
   job: { id: 'repair', action: 'repair', state: 'complete', busy: false } });
  return Promise.resolve({ ok: true });
 };
 await h.app.run('repair'); await settle();
 assert.equal(h.app.pending, false);
 assert.equal(h.app.buttons.start.disabled, false);
});

test('process query errors keep recovery actions available while primary actions wait', async () => {
 const h = harness(); await h.init();
 Object.assign(h.status, { state_known: false, status_warnings: ['进程查询超时'] });
 await h.app.refresh();
 assert.equal(h.app.stateNode.textContent, '状态待确认');
 assert.equal(h.app.buttons.stop.disabled, false);
 assert.equal(h.app.buttons.repair.disabled, false);
 assert.equal(h.app.buttons.start.disabled, true);
 assert.equal(h.app.buttons.profile.disabled, true);
});

test('status transport errors retain retry controls and recover on the next response', async () => {
 const h = harness(); await h.init();
 h.handlers.status = () => Promise.reject(new Error('RPC unavailable'));
 await h.app.refresh();
 assert.equal(h.app.stateNode.textContent, '状态连接中断');
 assert.equal(h.app.buttons.stop.disabled, false);
 assert.equal(h.app.buttons.repair.disabled, false);
 assert.equal(h.app.buttons.start.disabled, true);
 delete h.handlers.status;
 await h.app.refresh();
 assert.equal(h.app.connectionError, null);
 assert.equal(h.app.buttons.start.disabled, false);
});

test('a request that never responds releases pending controls at its deadline', async () => {
 const h = harness({ manualTimers: true }); await h.init();
 h.handlers.doctor = () => new Promise(() => {});
 const operation = h.app.run('doctor'); await settle();
 assert.equal(h.app.pending, true);
 assert.equal(h.app.buttons.stop.disabled, false);
 h.expire(); await operation;
 assert.equal(h.app.pending, false);
 assert.equal(h.app.buttons.repair.disabled, false);
 assert.match(h.notifications[0], /等待超时/);
});

test('an older request finishing leaves the newer stop request pending', async () => {
 const h = harness({ manualTimers: true }); await h.init();
 let finishDoctor, finishStop;
 h.handlers.doctor = () => new Promise(resolve => { finishDoctor = resolve; });
 h.handlers.stop = () => new Promise(resolve => { finishStop = resolve; });
 const doctor = h.app.run('doctor'); await settle();
 const stop = h.app.run('stop'); await settle();
 finishDoctor({ ok: true }); await doctor;
 assert.equal(h.app.pending, true);
 assert.equal(h.app.pendingAction, 'stop');
 finishStop({ ok: true }); await stop;
 assert.equal(h.app.pending, false);
});

test('a blocked log response allows status polling and service controls to continue', async () => {
 const h = harness({ manualTimers: true }); await h.init();
 h.handlers.logs = () => new Promise(() => {});
 h.app.selectStage('bitrate', 'logs'); const log = h.app.refreshLogs(true); await settle();
 h.status.modified = 42;
 await h.app.refresh();
 assert.equal(h.app.countNode.textContent, '42');
 assert.equal(h.app.statusRequest, null);
 assert.equal(h.app.buttons.start.disabled, false);
 h.expire(); await log;
 assert.match(h.app.logNode.textContent, /日志读取失败/);
 assert.equal(h.app.buttons.start.disabled, false);
});

test('read-only sessions retain permission gates during recovery errors', async () => {
 const h = harness({ permission: false }); await h.init();
 Object.assign(h.status, { state_known: false, recovery_required: true, cleanup_pending: true,
  job: { state: 'failed', busy: false, action: 'stop' } });
 await h.app.refresh();
 assert.equal(h.app.buttons.stop.disabled, true);
 assert.equal(h.app.buttons.repair.disabled, true);
});

test('configuration revision changes refresh details and preserve the latest dynamic state', async () => {
 const h = harness(); await h.init(); h.calls.length = 0;
 h.status.details_revision = 'v2'; h.status.modified = 73;
 h.details.details_revision = 'v2'; h.details.config.profile = '100';
 await h.app.refresh(); await settle();
 assert.equal(h.app.profileNode.textContent, '100');
 assert.equal(h.app.countNode.textContent, '73');
 assert.deepEqual(h.calls.map(call => call.method), ['status', 'details']);
 h.calls.length = 0; await h.app.refresh(); await settle();
 assert.deepEqual(h.calls.map(call => call.method), ['status']);
});

test('initial details failure recovers the device fields and profile controls', async () => {
 const h = harness();
 h.handlers.details = () => Promise.reject(new Error('details unavailable'));
 await h.init();
 assert.equal(h.app.detailsKnown, false);
 assert.equal(h.app.profileButtons.length, 5);
 delete h.handlers.details;
 await h.app.refreshDetails();
 assert.equal(h.app.fields.address.value, '10.0.0.250/24');
 assert.equal(h.app.buttons.start.disabled, false);
});

test('background details updates preserve device settings being edited', async () => {
 const h = harness(); await h.init();
 h.app.fields.address.value = '10.0.0.249/24'; h.app.fields.address.handlers.input();
 h.details.config.address = '10.0.0.248/24';
 await h.app.refreshDetails();
 assert.equal(h.app.fields.address.value, '10.0.0.249/24');
});

test('a remaining orphan enables stop and keeps repair waiting for its exit', async () => {
 const h = harness(); await h.init();
 h.status.job = { id: 'failed-stop', state: 'failed', busy: false, action: 'stop', orphan_active: true };
 await h.app.refresh();
 assert.equal(h.app.buttons.stop.disabled, false);
 assert.equal(h.app.buttons.repair.disabled, true);
 assert.equal(h.app.buttons.configure.disabled, true);
});

const elementText = node => node.textContent + node.children.map(elementText).join(' ');

function qualitySample() {
 return { state: 'degraded', source: 'client_feedback', requested_profile: '65', request_observed: true,
  feedback_fresh: true, report_fresh: true, loss_percent: 3, received: 2910, lost: 90,
  corrupt_reports: 2, idr_requests: 1, feedback_samples: 30,
  relay: { receive_stats_available: true, dropped: 0, dropped_total: 0, processing_p95_ms: .25 },
  advice: { kind: 'lower', reason: 'sustained_loss', profile: '45', sustained_seconds: 6, loss_percent: 3 } };
}

test('quality advice renders without selecting a profile or sending writes', async () => {
 const h = harness(); await h.init();
 h.status.running = h.status.engine_alive = true; h.status.quality = qualitySample();
 h.calls.length = 0; await h.app.refresh();
 assert.equal(h.app.qualityNode.textContent, '3.00%');
 assert.match(h.app.qualityDetail.textContent, /坏帧报告 2 \/ 关键帧请求 1/);
 assert.match(h.app.relayQualityNode.textContent, /0.25 ms/);
 assert.match(h.app.qualityAdvice.textContent, /建议试用 45 Mbps/);
 assert.equal(h.app.qualityAdvice.dataset.advice, 'lower');
 assert.equal(h.app.selectedProfile, '65');
 assert.equal(h.app.buttons.profile.disabled, true);
 assert.deepEqual(h.calls.map(call => call.method), ['status']);
 h.status.quality.request_observed = false;
 h.status.quality.advice = {kind:'wait',reason:'waiting_startup',profile:null};
 await h.app.refresh();
 assert.match(h.app.qualityAdvice.textContent, /重新连接 Portal/);
 assert.equal(h.app.selectedProfile, '65');
});

test('quality expiry and relay drops replace the profile recommendation', async () => {
 const h = harness(); await h.init();
 h.status.running = h.status.engine_alive = true; h.status.quality = qualitySample();
 h.status.quality.state = 'stale'; h.status.quality.feedback_fresh = false;
 await h.app.refresh();
 assert.equal(h.app.qualityNode.textContent, '数据过期');
 assert.equal(h.app.qualityAdvice.dataset.advice, 'wait');
 assert.doesNotMatch(h.app.qualityAdvice.textContent, /45 Mbps/);
 h.status.quality = qualitySample(); h.status.quality.state = 'relay_overload';
 h.status.quality.relay.dropped = h.status.quality.relay.dropped_total = 3;
 h.status.quality.advice = { kind: 'check_relay', reason: 'receive_drops', profile: null };
 await h.app.refresh();
 assert.match(h.app.qualityAdvice.textContent, /优先检查路由器负载/);
 assert.match(h.app.relayQualityDetail.textContent, /接收队列丢包 3/);
 assert.equal(h.app.qualityAdvice.dataset.advice, 'check_relay');
 assert.equal(h.app.selectedProfile, '65');
});

test('read-only users see quality states while existing profile controls retain permissions', async () => {
 const h = harness({ permission: false }); await h.init();
 h.status.running = h.status.engine_alive = true; h.status.quality = qualitySample();
 await h.app.refresh();
 assert.match(h.app.qualityAdvice.textContent, /建议试用 45 Mbps/);
 assert.equal(h.app.profileButtons.every(button => button.disabled), true);
 assert.equal(h.app.buttons.profile.disabled, true);
 for (const [state, label] of [['waiting', '等待反馈'], ['unsupported', '格式待适配'], ['unavailable', '采集异常']]) {
  h.status.quality = { state, report_fresh: true, feedback_fresh: false, advice: { kind: 'wait' } };
  await h.app.refresh();
  assert.equal(h.app.qualityNode.textContent, label);
  assert.doesNotMatch(h.app.qualityAdvice.textContent, /45 Mbps/);
 }
 h.status.running = false; await h.app.refresh();
 assert.equal(h.app.qualityNode.textContent, '等待启动');
});

test('domain views load on demand and polling reuses the current sample', async () => {
 const h = harness(); await h.init(); h.calls.length = 0;
 await h.app.refresh(); await settle();
 assert.deepEqual(h.calls.map(call => call.method), ['status']);
 h.app.selectStage('proxy', 'logs'); h.app.selectLogTab('domains');
 await h.app.refreshDomains(); await settle();
 assert.match(elementText(h.app.domainList), /api\.sony\.example/);
 assert.match(elementText(h.app.domainList), /本轮新增/);
 assert.equal(h.app.mainPanels.monitor.hidden, false);
 assert.equal(h.app.mainPanels.proxy.hidden, true);
 h.calls.length = 0;
 await h.app.refresh(); await settle();
 assert.deepEqual(h.calls.map(call => call.method), ['status']);
 h.app.selectTab('bitrate'); h.calls.length = 0;
 await h.app.refresh(); await settle();
 assert.deepEqual(h.calls.map(call => call.method), ['status']);
});

test('a blocked domain response leaves dynamic status and recovery controls available', async () => {
 const h = harness({ manualTimers: true }); await h.init();
 h.handlers.domain_monitor = () => new Promise(() => {});
 h.app.selectStage('proxy', 'logs'); h.app.selectLogTab('domains');
 const request = h.app.refreshDomains(); await settle();
 h.status.modified = 91; await h.app.refresh();
 assert.equal(h.app.countNode.textContent, '91');
 assert.equal(h.app.buttons.start.disabled, false);
 h.expire(); await request;
 assert.match(h.app.domainState.textContent, /域名记录读取失败/);
 assert.equal(h.app.buttons.start.disabled, false);
});

test('log policy changes remain available during a running trial without invoking relay controls', async () => {
 const h = harness(); await h.init();
 h.status.running = true; h.status.mode = 'baseline';
 h.status.job = { id: 'trial', action: 'baseline', state: 'running', busy: true };
 await h.app.refresh();
 assert.equal(h.app.buttons.logging.disabled, false);
 assert.equal(h.app.buttons.incident.disabled, false);
 h.app.logMode.value = 'verbose'; h.app.logTag.value = 'Portal 升级'; h.app.loggingTouched = true;
 h.handlers.logging = (mode, domains, tag) => {
  h.details.logging = { mode, domains: !!domains, tag };
  return Promise.resolve({ ok: true, logging: h.details.logging });
 };
 h.calls.length = 0; await h.app.run('logging');
 assert.equal(h.app.logMode.value, 'verbose');
 assert.equal(h.app.pending, undefined);
 assert.equal(h.app.latest.job.busy, true);
 assert.deepEqual(h.calls.map(call => call.method), ['logging', 'details']);
 assert.deepEqual(h.calls[0].args, ['verbose', 1, 'Portal 升级']);
});

test('the domain capture switch saves independently while the relay remains running', async () => {
 const h = harness(); await h.init();
 h.status.running = true; h.status.engine_alive = true;
 await h.app.refresh(); h.app.selectStage('proxy', 'logs'); h.app.selectLogTab('domains');
 await h.app.refreshDomains(); h.calls.length = 0;
 h.handlers.logging = (mode, domains, tag) => {
  h.details.logging = { mode, domains: Boolean(domains), tag };
  h.domainData.logging = h.details.logging;
  h.domainData.observer.state = domains ? 'observing' : 'disabled';
  return Promise.resolve({ ok: true, logging: h.details.logging });
 };
 h.app.domainEnabled.checked = false;
 h.app.domainEnabled.handlers.change();
 await h.app.saveLogging(); await settle();
 assert.equal(h.calls.find(call => call.method === 'logging').args[1], 0);
 assert.match(h.app.domainState.textContent, /域名记录已关闭/);
 assert.match(elementText(h.app.domainList), /api\.sony\.example/);
 assert.equal(h.app.latest.running, true);
 h.app.domainEnabled.checked = true;
 h.app.domainEnabled.handlers.change();
 await h.app.saveLogging(); await settle();
 assert.match(h.app.domainState.textContent, /正在观察设备域名/);
 assert.equal(h.app.latest.running, true);
 assert.equal(h.calls.some(call => ['start', 'stop', 'repair', 'profile'].includes(call.method)), false);
});

test('marking a device failure during a trial selects its DNS evidence immediately', async () => {
 const h = harness(); await h.init();
 h.status.job = { id: 'trial', action: 'trial', state: 'running', busy: true }; await h.app.refresh();
 const id = 'a'.repeat(32);
 h.handlers.incident = note => {
  const incident = { id, note, time: '2026-11-23T10:01:00Z', evidence: {
   evidence_complete: false, candidates: [{ device: 'portal', domain: 'new.sony.example', errors: 1, evidence: ['dns_error'] }],
   events: [{ time: '2026-11-23T10:00:59Z', device: 'portal', kind: 'dns_error', domains: ['new.sony.example'], rcode: 3 }]
  } };
  h.domainData.incidents = [incident]; h.domainData.selected = incident;
  return Promise.resolve({ ok: true, id, time: incident.time });
 };
 h.app.selectStage('proxy', 'logs'); await h.app.run('incident'); await settle();
 assert.equal(h.app.incidentId, id);
 assert.equal(h.app.incidentPanel.hidden, false);
 assert.match(elementText(h.app.incidentCandidates), /new\.sony\.example/);
 assert.match(h.app.incidentEvents.textContent, /NXDOMAIN/);
 assert.equal(h.app.latest.job.busy, true);
 assert.equal(h.app.buttons.stop.disabled, false);
});

test('an older domain request cannot replace the newer failure selection', async () => {
 const h = harness(); await h.init();
 let finish;
 h.handlers.domain_monitor = (_batch, selected) => selected ? Promise.resolve({ ...h.domainData, selected: {
  id: selected, note: '新失败', time: '2026-11-23T10:01:00Z', evidence: { candidates: [], events: [] }
 } }) : new Promise(resolve => { finish = resolve; });
 h.app.selectStage('proxy', 'logs'); h.app.selectLogTab('domains'); const old = h.app.refreshDomains(); await settle();
 h.app.incidentId = 'b'.repeat(32);
 finish({ ...h.domainData, selected: null }); await old; await settle();
 assert.equal(h.app.domainData.selected.id, 'b'.repeat(32));
 assert.match(h.app.incidentTitle.textContent, /新失败/);
});

test('domain filtering preserves failure evidence and renders names as text', async () => {
 const h = harness(); await h.init();
 h.domainData.domains.push({ device: 'ps5', domain: '<script>alert(1)</script>.example',
  counts: { dns_error: 2 }, addresses: [], last_problem: 'dns_error' });
 h.app.selectStage('proxy', 'logs'); h.app.selectLogTab('domains'); await h.app.refreshDomains();
 h.app.domainOnlyProblems.checked = true; h.app.renderDomains(h.domainData);
 assert.doesNotMatch(elementText(h.app.domainList), /api\.sony\.example/);
 assert.match(elementText(h.app.domainList), /<script>alert\(1\)<\/script>/);
 assert.equal(h.app.domainList.children[0].tag, 'table');
});

test('read-only sessions keep log policy and failure marking disabled', async () => {
 const h = harness({ permission: false }); await h.init();
 assert.equal(h.app.buttons.logging.disabled, true);
 assert.equal(h.app.buttons.incident.disabled, true);
 assert.equal(h.app.logMode.disabled, true);
});

test('batch rule copies cover every domain and retain recovered DNS failures across filters', async () => {
 const h = harness(); await h.init();
 const rows = Array.from({length:130}, (_, index) => ({device:'portal', domain:'host'+String(index).padStart(3,'0')+'.example',
  counts:{dns_ok:1}, addresses:[], last_problem:''}));
 rows[129].counts.dns_error = 2;
 rows.push({...rows[129],device:'ps5'});
 rows.push({device:'portal',domain:'tcp-only.example',counts:{dns_ok:1,tcp_reset:1},addresses:[]});
 h.domainData.domains = h.domainData.batch.domains = rows;
 h.app.selectTab('monitor'); await h.app.refreshDomains(); await settle();
 h.app.domainSearch.value = 'host000'; h.app.renderDomains(h.domainData);
 await h.app.copyAllDomains.click();
 assert.equal(h.clipboardWrites[0].trim().split('\n').length, 131);
 assert.match(h.clipboardWrites[0], /host129\.example\n/);
 assert.equal(h.clipboardWrites[0].includes('full:'), false);
 h.app.domainFailedButton.click();
 await h.app.copyFailedDomains.click();
 assert.equal(h.clipboardWrites[1], 'host129.example\n');
 assert.match(h.app.domainCopyNotice.textContent, /共 1 行/);
 assert.equal(h.app.domainOnlyProblems.checked, true);
});

test('read-only domain copies use the HTTP clipboard fallback and clean up the temporary control', async () => {
 const h = harness({permission:false}); await h.init();
 h.app.selectTab('monitor'); await h.app.refreshDomains(); await settle();
 h.window.navigator.clipboard.writeText = () => Promise.reject(new Error('HTTP'));
 h.document.execCommand = command => {
  assert.equal(command, 'copy');
  const input = h.document.body.children.at(-1);
  assert.equal(input.selected, true);
  h.clipboardWrites.push(input.value); return true;
 };
 await h.app.copyAllDomains.click();
 assert.equal(h.clipboardWrites[0], 'api.sony.example\n');
 assert.equal(h.document.body.children.length, 0);
 assert.equal(h.app.batchStartButton.disabled, true);
 assert.equal(h.app.domainActionButtons.every(button => button.disabled), true);
});

test('removing a covered native domain keeps the parent rule and adds a direct exception', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 const host = 'region.auth.np.ac.playstation.net';
 h.app.policyInputs.domains.value = 'domain:auth.np.ac.playstation.net\n'+host+'\n';
 h.app.domainRuleActions(host).children[1].children[1].click();
 assert.equal(h.app.policyInputs.domains.value, 'domain:auth.np.ac.playstation.net\n');
 assert.match(h.app.policyInputs.exclusions.value, /region\.auth\.np\.ac\.playstation\.net/);
 assert.match(h.app.domainActionText.textContent, /加入直连名单草稿/);
 h.app.domainRuleActions(host).children[1].children[0].click();
 assert.doesNotMatch(h.app.policyInputs.exclusions.value, /region\.auth/);
 assert.match(h.app.policyInputs.domains.value, /region\.auth/);
});

test('a changed batch selection blocks stale copies and ignores an older response', async () => {
 const h = harness(); await h.init();
 let finish;
 const id = 'c'.repeat(32), row = {device:'ps5',domain:'new-batch.example',counts:{dns_ok:1},addresses:[]};
 h.handlers.domain_monitor = batch => batch === id ? Promise.resolve({...h.domainData, domains:[row],
  batch:{id,time:'2026-11-23T11:00:00Z',state:'archived',domains:[row],events:[]}}) : new Promise(resolve => {finish=resolve;});
 h.app.selectTab('monitor'); await settle();
 const older = h.app.domainRequest;
 h.app.selectBatch(id);
 assert.equal(h.app.copyAllDomains.disabled, true);
 await h.app.copyDomainRules(false);
 assert.equal(h.clipboardWrites.length, 0);
 finish(h.domainData); await older; await settle();
 assert.equal(h.app.domainData.batch.id, id);
 await h.app.copyAllDomains.click();
 assert.equal(h.clipboardWrites[0], 'new-batch.example\n');
});

test('manual connection batches start independently during a management job', async () => {
 const h = harness(); await h.init(); h.app.selectTab('monitor'); await h.app.refreshDomains(); await settle();
 h.status.job = {id:'trial',action:'trial',busy:true,state:'running'}; await h.app.refresh();
 const id = 'e'.repeat(32);
 h.handlers.domain_batch_start = () => Promise.resolve({ok:true,id,time:'2026-11-23T11:00:00Z'});
 h.handlers.domain_monitor = () => Promise.resolve({...h.domainData, domains:[],
  batch:{id,time:'2026-11-23T11:00:00Z',state:'collecting',domains:[],events:[]}});
 h.calls.length = 0;
 await h.app.batchStartButton.click();
 assert.equal(h.app.batchId, id);
 assert.equal(h.app.latest.job.busy, true);
 assert.equal(h.app.copyAllDomains.disabled, true);
 assert.deepEqual(h.calls.map(call => call.method), ['domain_batch_start','domain_monitor']);
});

test('batch traffic sorts by proxy bytes and keeps historical proxy flows visible after removal', async () => {
 const h = harness(); await h.init();
 const mib = 1024*1024;
 function row(domain, down, proxyDown, hasProxy) {
  return {device:'portal',domain,counts:{dns_ok:1},addresses:[],traffic:{sampled:true,fresh:false,
   upload_bytes:1024,download_bytes:down,proxy_upload_bytes:hasProxy?1024:0,proxy_download_bytes:proxyDown,
   has_proxy:hasProxy,proxy_rules_seen:hasProxy,proxy_rate:10*mib,proxy_active_connections:0}};
 }
 const rows = [row('direct.example',500*mib,0,false), row('small.example',2*mib,2*mib,true),
  row('large.example',256*mib,256*mib,true)];
 h.domainData.domains = h.domainData.batch.domains = rows;
 h.domainData.batch.traffic = {sampled:true,fresh:false,upload_bytes:3072,download_bytes:886*mib,
  proxy_upload_bytes:2048,proxy_download_bytes:386*mib};
 h.domainData.batch.unattributed_traffic = {proxy_download_bytes:128*mib};
 h.app.selectTab('monitor'); await h.app.refreshDomains(); await settle();
 let tableRows = h.app.domainList.children[0].children[1].children;
 assert.match(elementText(tableRows[0]), /large\.example/);
 assert.match(elementText(tableRows[0].children[3]), /256\.0 MiB|代理大流量/);
 assert.match(elementText(tableRows[1].children[3]), /本批次曾走代理/);
 assert.doesNotMatch(elementText(tableRows[1].children[3]), /\/s/);
 assert.match(h.app.domainTrafficUnassigned.textContent, /128\.0 MiB/);
 assert.equal(h.app.domainTrafficUnassigned.dataset.error, 'true');
 h.app.domainOnlyProxy.checked = true; h.app.renderDomains(h.domainData);
 assert.equal(h.app.domainList.children[0].children[1].children.length, 2);
 h.app.domainOnlyLargeProxy.checked = true; h.app.renderDomains(h.domainData);
 tableRows = h.app.domainList.children[0].children[1].children;
 assert.equal(tableRows.length, 1); assert.match(elementText(tableRows[0]), /large\.example/);
 h.app.domainOnlyProxy.checked = h.app.domainOnlyLargeProxy.checked = false;
 h.app.domainTrafficSort.choicePicker.setValue('total'); h.app.renderDomains(h.domainData);
 assert.match(elementText(h.app.domainList.children[0].children[1].children[0]), /direct\.example/);
});

test('the main features show runtime, configuration and open bounded logs in order', async () => {
 const h = harness(); await h.init();
 assert.deepEqual(Object.keys(h.app.mainTabs), ['devices', 'bitrate', 'proxy', 'monitor']);
 assert.deepEqual(Object.keys(h.app.stageTabs.bitrate), []);
 assert.deepEqual(Object.keys(h.app.stageTabs.proxy), []);
 assert.equal(h.app.logTabs.domains, undefined);
 assert.equal(h.app.proxyLogTabs.domains, undefined);
 assert.deepEqual(Object.keys(h.app.proxyLogTabs), ['proxy']);
 assert.match(elementText(h.app.mainPanels.monitor), /连接批次|复制全部域名规则|复制失败域名规则/);
 assert.doesNotMatch(elementText(h.app.mainPanels.proxy), /域名采集设置|连接失败回溯/);
 assert.doesNotMatch(elementText(h.app.mainPanels.devices), /中继独立地址/);
 assert.doesNotMatch(elementText(h.app.mainPanels.devices), /局域网设备|主路由/);
 assert.match(elementText(h.app.stagePanels.bitrate.config), /中继独立地址/);
 assert.doesNotMatch(elementText(h.app.stagePanels.proxy.config), /已有 MAC 或当前 IP/);
 for (const feature of ['bitrate', 'proxy']) {
  assert.equal(h.app.mainPanels[feature].children[1], h.app.stagePanels[feature].runtime);
  assert.equal(h.app.mainPanels[feature].children[2], h.app.stagePanels[feature].config);
  assert.equal(h.app.mainPanels[feature].children[3], h.app.stagePanels[feature].logs);
  assert.equal(h.app.stagePanels[feature].logs.open, true);
 }
 assert.equal(h.app.deviceLogDetails.open, true);
 assert.equal(h.app.fields.bridge.choicePicker.root.parentNode.parentNode.parentNode.tag, 'div');
 assert.deepEqual(Object.keys(h.app.policyInputs), ['node', 'domains', 'exclusions']);
 assert.equal(h.app.buttons.baseline, undefined);
 assert.equal(h.app.buttons.trial, undefined);
 h.details.baseline_valid = false; await h.app.refreshDetails();
 assert.equal(h.app.buttons.start.disabled, false);
 h.app.selectStage('bitrate', 'config');
 assert.notEqual(h.app.stagePanels.bitrate.runtime.hidden, true);
 assert.equal(h.app.stagePanels.bitrate.logs.open, true);
 h.app.selectStage('proxy', 'logs');
 assert.equal(h.app.mainPanels.bitrate.hidden, true);
 assert.equal(h.app.stagePanels.proxy.logs.open, true);
});

test('first-time setup starts at shared devices while domain monitoring works before bitrate enrollment', async () => {
 const h = harness();
 h.details.configured = false; h.details.devices_configured = false;
 h.details.device_selectors = {}; h.details.config.portal_ip = ''; h.details.config.ps5_ip = ''; h.details.config.address = '';
 await h.init();
 assert.equal(h.app.activeTab, 'devices');
 assert.equal(h.app.policyButtons.save.disabled, true);
 h.details.devices_configured = true;
 h.details.config.portal_ip = '10.0.0.101'; h.details.config.ps5_ip = '10.0.0.100';
 h.details.device_selectors = {portal:'02:00:00:00:00:01', ps5:'02:00:00:00:00:02'};
 await h.app.refreshDetails();
 h.app.selectTab('monitor'); await h.app.refreshDomains(); await settle();
 assert.match(elementText(h.app.domainList), /api\.sony\.example/);
 assert.equal(h.app.buttons.start.disabled, true);
 assert.equal(h.app.policyButtons.save.disabled, false);
});

test('saving shared device addresses leaves the relay address and bitrate profile in their own configuration', async () => {
 const h = harness(); await h.init();
 h.app.fields.portal_ip.value = '10.0.0.111'; h.app.fields.portal_ip.handlers.input();
 h.calls.length = 0;
 await h.app.run('device_save'); await settle();
 assert.deepEqual(h.calls.find(call => call.method === 'device_save').args, ['br-lan', '10.0.0.111', '10.0.0.100']);
 assert.equal(h.calls.some(call => ['configure','profile','psportal_save','psportal_apply'].includes(call.method)), false);
});

test('clicking save submits first-time devices and stays locked until the job completes', async () => {
 const h = harness();
 h.details.configured = false; h.details.devices_configured = false; h.details.device_selectors = {};
 h.details.config.portal_ip = ''; h.details.config.ps5_ip = ''; h.details.config.address = '';
 h.deviceData.configured = false; h.deviceData.binding = {};
 await h.init();
 for (const [key, value] of Object.entries({portal_ip:'10.0.0.101', ps5_ip:'10.0.0.100'})) {
  h.app.fields[key].value = value; h.app.fields[key].handlers.input();
 }
 let resolveSave;
 h.handlers.device_save = () => new Promise(resolve => { resolveSave = resolve; });
 h.calls.length = 0;
 const saving = h.app.buttons.device_save.click(); await settle();
 assert.deepEqual(h.calls.find(call => call.method === 'device_save')?.args,
  ['br-lan', '10.0.0.101', '10.0.0.100']);
 assert.equal(h.app.buttons.device_save.disabled, true);
 h.app.buttons.device_save.click(); await settle();
 assert.equal(h.calls.filter(call => call.method === 'device_save').length, 1);
 h.status.job = {id:'saved-devices', action:'device_save', state:'running', busy:true};
 resolveSave({ok:true, id:'saved-devices'}); await saving; await settle();
 assert.equal(h.app.buttons.device_save.disabled, true);
 h.status.job = {...h.status.job, state:'complete', busy:false};
 h.details.config.portal_ip = '10.0.0.101'; h.details.config.ps5_ip = '10.0.0.100';
 h.details.devices_configured = true; h.deviceData.configured = true;
 await h.app.refresh(true); await settle();
 assert.equal(h.app.buttons.device_save.disabled, false);
 assert.equal(h.app.fields.portal_ip.value, '10.0.0.101');
 assert.equal(h.app.fields.ps5_ip.value, '10.0.0.100');
 assert.match(h.app.deviceNotice.textContent, /设备配置已保存/);
 assert.equal(h.app.activeTab, 'devices');
});

test('device choices open with one click and polling preserves the open list', async () => {
 const h = harness(); await h.init(); h.app.selectTab('devices');
 h.deviceData.devices[0].addresses.push('10.0.0.111');
 await h.app.refreshDevices(true); await settle();
 const picker = h.app.fields.portal_ip.choicePicker;
 picker.trigger.click();
 assert.equal(picker.menu.hidden, false);
 assert.equal(picker.trigger.attributes['aria-expanded'], 'true');
 picker.search.value = '10.0.0.111'; picker.search.handlers.input();
 const choice = picker.list.children[0];
 h.deviceData.devices[0].label = 'Portal updated';
 await h.app.refreshDevices(true); await settle();
 assert.equal(picker.menu.hidden, false);
 assert.equal(picker.list.children[0], choice);
 choice.click();
 assert.equal(h.app.fields.portal_ip.value, '10.0.0.111');
 assert.equal(h.app.fieldTouched.portal_ip, true);
 assert.equal(picker.menu.hidden, true);
});

test('device save errors remain visible in the device page after polling', async () => {
 const h = harness(); await h.init();
 h.handlers.device_save = () => Promise.resolve({ok:false, error:'设备地址与 MAC 待确认'});
 await h.app.buttons.device_save.click(); await settle();
 await h.app.refresh(); await settle();
 assert.match(h.app.deviceNotice.textContent, /设备地址与 MAC 待确认/);
 assert.equal(h.app.deviceNotice.attributes['data-error'], 'true');
 assert.equal(h.app.buttons.device_save.disabled, false);
});

test('bitrate enrollment uses saved device addresses and preserves an unfinished device edit', async () => {
 const h = harness(); await h.init();
 h.app.fields.portal_ip.value = '10.0.0.111'; h.app.fields.portal_ip.handlers.input();
 h.app.fields.address.value = '10.0.0.249/24'; h.app.fields.address.handlers.input();
 h.calls.length = 0;
 await h.app.run('configure'); await settle();
 assert.deepEqual(h.calls.find(call => call.method === 'configure').args,
  ['br-lan', '10.0.0.249/24', '10.0.0.100', '10.0.0.101', '65']);
 assert.equal(h.app.fields.portal_ip.value, '10.0.0.111');
 assert.equal(h.app.activeStages.bitrate, 'runtime');
});

test('domain evidence edits a native draft and the apply action submits it directly', async () => {
 const h = harness(); await h.init(); await policyTab(h); h.calls.length = 0;
 h.app.addDomainToPolicy('api.sony.example', 'domains');
 assert.equal(h.calls.length, 0);
 assert.match(h.app.policyInputs.domains.value, /api\.sony\.example/);
 assert.equal(h.app.domainActionNotice.hidden, false);
 assert.match(h.app.domainActionText.textContent, /应用设备规则/);
 await h.app.policyAction('apply'); await settle();
 assert.match(h.calls.find(call => call.method === 'psportal_apply').args[0], /api\.sony\.example/);
});

test('moving a domain between proxy and exclusion lists keeps one draft interpretation', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 h.app.addDomainToPolicy('dwc.dl.playstation.net', 'domains');
 assert.match(h.app.policyInputs.domains.value, /dwc\.dl\.playstation\.net/);
 assert.doesNotMatch(h.app.policyInputs.exclusions.value, /dwc\.dl\.playstation\.net/);
 h.app.addDomainToPolicy('dwc.dl.playstation.net', 'domains');
 assert.equal(h.app.policyInputs.domains.value.split('\n').filter(name => name === 'dwc.dl.playstation.net').length, 1);
 h.app.addDomainToPolicy('dwc.dl.playstation.net', 'exclusions');
 assert.doesNotMatch(h.app.policyInputs.domains.value, /dwc\.dl\.playstation\.net/);
 assert.match(h.app.policyInputs.exclusions.value, /dwc\.dl\.playstation\.net/);
});

test('removing the firmware host restores its direct download exclusion', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 const host = 'dwc.dl.playstation.net';
 h.app.addDomainToPolicy(host, 'domains');
 assert.doesNotMatch(h.app.policyInputs.exclusions.value, /dwc\.dl/);
 h.app.removeDomainFromPolicy(host);
 assert.doesNotMatch(h.app.policyInputs.domains.value, /dwc\.dl/);
 assert.equal(h.app.policyInputs.exclusions.value.split('\n').filter(rule => rule === host).length, 1);
});

test('domain additions retain list limits, read-only permissions and active job boundaries', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 h.app.policyInputs.domains.value = Array.from({length:4096}, (_, i) => 'host'+i+'.example').join('\n');
 h.app.addDomainToPolicy('new.example', 'domains');
 assert.match(h.app.domainActionText.textContent, /最多 4096/);
 assert.equal(h.app.policyInputs.domains.value.split('\n').length, 4096);
 const saved = h.app.policyInputs.domains.value;
 h.status.job = {id:'proxy',action:'psportal_apply',busy:true,state:'running'}; await h.app.refresh();
 h.app.addDomainToPolicy('new.example', 'exclusions');
 assert.equal(h.app.policyInputs.domains.value, saved);
 const ro = harness({permission:false}); await ro.init(); await policyTab(ro);
 const original = ro.app.policyInputs.domains.value;
 ro.app.addDomainToPolicy('new.example', 'domains');
 assert.equal(ro.app.policyInputs.domains.value, original);
});

test('feature logs request their own output and retain earlier results across navigation', async () => {
 const h = harness(); await h.init();
 h.app.selectStage('bitrate', 'logs'); await h.app.refreshLogs();
 assert.equal(h.app.logNode.textContent, 'bitrate output');
 h.app.showLog('proxy'); await h.app.refreshLogs(); await settle();
 assert.equal(h.app.proxyLogNode.textContent, 'proxy output');
 assert.equal(h.app.logNode.textContent, 'bitrate output');
 assert.deepEqual(h.calls.filter(call => call.method === 'logs').map(call => call.args[0]), ['bitrate', 'proxy']);
 h.app.selectTab('devices'); await h.app.refreshDevices(true);
 h.app.deviceLogDetails.open = true; await h.app.refreshLogs(true);
 assert.equal(h.app.deviceLogNode.textContent, 'devices output');
});

test('a proxy error reports in proxy status while bitrate state retains its running evidence', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 h.status.running = true; h.status.mode = 'active';
 h.status.job = {id:'proxy-fail',action:'psportal_apply',state:'failed',busy:false,error:'proxy validation failed'};
 await h.app.refresh(); await settle();
 assert.match(h.app.policyNotice.textContent, /proxy validation failed/);
 assert.doesNotMatch(h.app.messageNode.textContent, /proxy validation failed/);
 assert.equal(h.app.stateNode.textContent, '运行中');
});

test('device replacement waits for the shared services to stop while inventory remains readable', async () => {
 const h = harness(); await h.init(); h.app.selectTab('devices'); await h.app.refreshDevices(true);
 h.deviceData.proxy_enabled = true; await h.app.refreshDevices(true);
 assert.equal(h.app.buttons.device_save.disabled, true);
 assert.equal(h.app.fields.portal_ip.disabled, true);
 assert.equal(h.app.deviceRefreshButton.disabled, false);
 assert.match(h.app.deviceNotice.textContent, /设备专属访问控制正在接管/);
 h.deviceData.proxy_enabled = false; await h.app.refreshDevices(true);
 assert.equal(h.app.buttons.device_save.disabled, false);
});

test('proxy cancellation uses the shared cancellation API and displays its own result', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 h.status.job = {id:'proxy-running',action:'psportal_apply',state:'running',busy:true};
 await h.app.refresh();
 assert.equal(h.app.policyButtons.cancel.disabled, false);
 assert.equal(h.app.buttons.stop.disabled, true);
 h.handlers.stop = () => {
  h.status.job = {id:'proxy-running',action:'psportal_apply',state:'cancelled',busy:false};
  return Promise.resolve({ok:true,stopping:true});
 };
 await h.app.policyAction('cancel'); await settle();
 assert.match(h.app.policyNotice.textContent, /设备接管任务已取消/);
 assert.equal(h.calls.filter(call => call.method === 'stop').length, 1);
});

test('main navigation preserves keyboard focus and logs expand in place', async () => {
 const h = harness(); await h.init();
 let prevented = 0;
 h.app.mainTabs.devices.handlers.keydown({key:'End',preventDefault(){prevented++;}});
 assert.equal(h.app.activeTab, 'monitor'); assert.equal(h.app.mainTabs.monitor.focused, true);
 h.app.selectStage('proxy', 'logs', true);
 assert.equal(h.app.activeStages.proxy, 'logs');
 assert.equal(h.app.mainTabs.proxy.focused, true);
 assert.notEqual(h.app.stagePanels.proxy.config.hidden, true);
 assert.equal(h.app.stagePanels.proxy.logs.open, true);
 assert.equal(prevented, 1);
});

test('restored feature results retain each failure after a task in another feature', async () => {
 const h = harness(); await h.init();
 h.status.job = {id:'proxy-complete', action:'psportal_apply', state:'complete', busy:false};
 h.status.feature_jobs = {
  bitrate:{id:'bitrate-failure',action:'configure',state:'failed',busy:false,error:'relay address unavailable'},
  devices:{id:'device-failure',action:'device_save',state:'failed',busy:false,error:'device address unavailable'},
  proxy:h.status.job
 };
 await h.app.refresh(); await settle();
 assert.match(h.app.messageNode.textContent, /relay address unavailable/);
 assert.match(h.app.deviceNotice.textContent, /device address unavailable/);
 assert.match(h.app.policyNotice.textContent, /两设备域名规则已应用/);
});


test('the two-device direct action retains an edited draft and advances its owned revision', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 h.app.policyInputs.domains.value += 'edited.example.com\n'; h.app.policyInputs.domains.handlers.input();
 await h.app.policyAction('direct'); await settle();
 assert.deepEqual(h.calls.find(call => call.method === 'psportal_direct').args, ['a'.repeat(64)]);
 h.policyData.policy_mode='direct'; h.policyData.revision='c'.repeat(64); h.policyData.loaded=true;
 h.status.job={id:'direct-done',action:'psportal_direct',state:'complete',busy:false,policy_mode:'direct'};
 await h.app.refresh(); await settle();
 assert.match(h.app.policyInputs.domains.value, /edited.example.com/);
 assert.equal(h.app.policyConflict, false);
 assert.equal(h.app.policyRevision, 'c'.repeat(64));
 assert.match(h.app.policyNotice.textContent, /全部直连/);
});

test('release uses its own revision-bound action and leaves the bitrate service running', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 h.status.running=true; await h.app.refresh();
 await h.app.policyAction('release'); await settle();
 assert.deepEqual(h.calls.find(call => call.method === 'psportal_release').args, ['a'.repeat(64)]);
 assert.equal(h.calls.some(call => call.method === 'stop'), false);
 h.policyData.policy_mode='released'; h.policyData.loaded=false; h.policyData.can_release=false;
 h.status.job={id:'released',action:'psportal_release',state:'complete',busy:false};
 await h.app.refresh(); await settle();
 assert.match(h.app.policyNotice.textContent, /恢复原 PassWall 策略/);
 assert.equal(h.app.stateNode.textContent, '运行中');
});

test('node selection uses both native cores and keeps the current search during polling', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 assert.deepEqual(h.app.policyNodePicker.getOptions().map(row=>row.value), ['xray_a','sing_a']);
 h.app.policyNodePicker.trigger.click();
 h.app.policyNodePicker.list.children.find(row => row.attributes['data-value'] === 'sing_a').click();
 await h.app.refreshPolicy(true);
 assert.equal(h.app.policyInputs.node.value, 'sing_a');
 assert.match(h.app.policyEnvironment.textContent, /sing-box/);
 assert.equal(h.app.policyButtons.apply.disabled, false);
 await h.app.policyAction('apply'); await settle();
 assert.equal(h.calls.find(call => call.method === 'psportal_apply').args[2], 'sing_a');
});

test('unavailable native exits stay disabled in the node picker', async () => {
 const h = harness();
 h.policyData.nodes.push({id:'stock_shunt',label:'已有分流组',core:'xray',protocol:'_shunt',
  available:false,reason:'选择其中的实际出口'});
 await h.init(); await policyTab(h);
 h.app.policyNodePicker.trigger.click();
 const option = h.app.policyNodePicker.list.children.find(row => row.attributes['data-value'] === 'stock_shunt');
 assert.equal(option.disabled, true);
 option.click();
 assert.equal(h.app.policyInputs.node.value, 'xray_a');
});

test('empty device lists stay empty after the first policy read', async () => {
 const h = harness();
 h.policyData.config = {node:'xray_a',domains:'',exclusions:''};
 h.policyData.config_source = 'empty';
 await h.init(); await policyTab(h);
 assert.equal(h.app.policyInputs.domains.value, '');
 assert.equal(h.app.policyInputs.exclusions.value, '');
 assert.match(h.app.policyDraftState.textContent, /初始为空/);
});
