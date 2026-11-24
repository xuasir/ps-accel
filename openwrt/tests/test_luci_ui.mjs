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
 click() { this.handlers.click?.({ currentTarget: this, preventDefault() {} }); }
 remove() { this.removed = true; }
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
 const calls = [], notifications = [], handlers = {}, timers = new Map();
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
 const status = { ok: true, details_revision: 'v1', state_known: true, status_warnings: [],
  running: false, engine_alive: false, recovery_required: false, cleanup_pending: false,
  mode: 'active', counts: {}, foreign_relay: false,
  job: { id: 'initial', state: 'complete', busy: false, action: 'baseline' } };
 const policyData = { ok: true, enabled: false,
  config: { portal: '02:00:00:00:00:01', ps5: '02:00:00:00:00:02', node: 'nodeA',
   domains: 'auth.api.playstation.com', ports: '443', exclusions: 'dwc.dl.playstation.net' },
  environment: { passwall: '26.11.11-r376', singbox: '1.14.4', compatible: true, active_cores: 1, attached_cores: 0 },
  devices: [{ mac: '02:00:00:00:00:01', label: 'Portal', addresses: ['10.0.0.101'] }],
  nodes: [{ id: 'nodeA', label: '已有订阅节点', protocol: 'trojan' }], sources: {}, blockers: [],
  dynamic_rules: ['*.auth.np.ac.playstation.net', '*.np.communication.playstation.net', 'gsconnect.*',
   '*.gsconnect.playstation.net', '*signaling*', '*.remoteplay.playstation.net'].map(domain => ({domain,builtin:true})) };
 const deviceData = { ok: true, configured: true, proxy_enabled: false,
  config: { bridge: details.config.bridge, portal_ip: details.config.portal_ip, ps5_ip: details.config.ps5_ip },
  binding: { config: { bridge: details.config.bridge, portal_ip: details.config.portal_ip, ps5_ip: details.config.ps5_ip },
   portal_mac: details.device_selectors.portal, ps5_mac: details.device_selectors.ps5 },
  devices: [{ mac: details.device_selectors.portal, label: 'Portal', addresses: [details.config.portal_ip], source: 'dhcp' },
   { mac: details.device_selectors.ps5, label: 'PS5', addresses: [details.config.ps5_ip], source: 'dhcp' }] };
 const window = {
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
  if (spec.method === 'psportal_status') return Promise.resolve(structuredClone(policyData));
  if (spec.method === 'psportal_preview') return Promise.resolve({ ok: true, token: 'a'.repeat(64),
   can_apply: true, restart_required: true, blockers: [], rules: [{ domain: args[3], ports: args[4] }],
   validation: { protection_rules: 2 }, notice: '首次接入需要重启 PassWall' });
  return Promise.resolve({ ok: true });
 } };
 const poll = { add: (callback, seconds) => { poll.callback = callback; poll.seconds = seconds; } };
 const ui = { createHandlerFn: (object, fn, name) => () => fn.call(object, name),
  addNotification: (_id, element) => notifications.push(element.textContent) };
 const document = { body: new Element('body') };
 const app = new Function('view', 'rpc', 'poll', 'ui', 'E', 'window', 'document', 'L', source)(
  { extend: object => object }, rpc, poll, ui, E, window, document,
  { hasViewPermission: () => permission });
 return { app, calls, handlers, status, details, domainData, policyData, deviceData, notifications, timers, poll,
  init: async () => { app.render(await app.load()); await settle(); },
  expire: () => { for (const [id, fn] of [...timers]) { timers.delete(id); fn(); } } };
}

async function policyTab(h) {
 h.app.selectTab('proxy');
 await h.app.policyRequest;
 await settle();
}

test('policy device choices, node choices and preview rows render as DOM nodes', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 h.app.selectTab('devices'); await h.app.refreshDevices(true);
 assert.deepEqual(h.app.deviceChoices.options.map(node => node.value), ['10.0.0.101', '10.0.0.100']);
 await policyTab(h);
 assert.equal(h.app.policyInputs.portal.value, h.details.device_selectors.portal);
 assert.deepEqual(h.app.policyInputs.node.options.map(node => node.value), ['', 'nodeA']);
 await h.app.policyAction('preview');
 const row = h.app.policyPreviewBody.children[0];
 assert.equal(row.tag, 'tr');
 assert.deepEqual(row.children.map(node => node.tag), ['td', 'td', 'td']);
 assert.equal(row.children[0].textContent, 'auth.api.playstation.com');
});

test('precise routing tab loads policy only when visible and throttles status reads', async () => {
 const h = harness(); await h.init();
 assert.equal(h.calls.some(call => call.method === 'psportal_status'), false);
 await policyTab(h);
 assert.equal(h.app.mainPanels.proxy.hidden, false);
 assert.equal(h.app.mainPanels.bitrate.hidden, true);
 assert.equal(h.app.mainTabs.proxy.attributes['aria-selected'], 'true');
 assert.equal(h.app.policyInputs.node.value, 'nodeA');
 h.calls.length = 0;
 await h.app.refresh(); await settle();
 assert.deepEqual(h.calls.map(call => call.method), ['status']);
 h.app.selectTab('bitrate'); await h.app.refresh(); await settle();
 assert.equal(h.calls.some(call => call.method === 'psportal_status'), false);
});

test('first attachment needs an explicit shared restart check after preview', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 await h.app.policyAction('preview');
 assert.equal(h.app.policyConfirmation.hidden, false);
 assert.equal(h.app.policyButtons.apply.disabled, true);
 assert.equal(h.app.policyConfirm.checked, false);
 assert.match(h.app.policyPreviewNotice.textContent, /2 条原有直连/);
 h.app.policyConfirm.checked = true; h.app.policyConfirm.handlers.change();
 assert.equal(h.app.policyButtons.apply.disabled, false);
 await h.app.policyAction('apply'); await settle();
 const call = h.calls.find(call => call.method === 'psportal_apply');
 assert.equal(call.args.at(-1), 1);
 assert.equal(call.args.at(-2), 'a'.repeat(64));
 assert.equal(h.app.policyPlan, null);
});

test('editing a scoped host invalidates the preview and restart consent', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 await h.app.policyAction('preview');
 h.app.policyConfirm.checked = true; h.app.policyConfirm.handlers.change();
 h.app.policyInputs.domains.value = 'np.ac.playstation.net';
 h.app.policyInputs.domains.handlers.input();
 assert.equal(h.app.policyPlan, null);
 assert.equal(h.app.policyPreview.hidden, true);
 assert.equal(h.app.policyConfirm.checked, false);
 assert.equal(h.app.policyButtons.apply.disabled, true);
 await h.app.refreshPolicy(true);
 assert.equal(h.app.policyInputs.domains.value, 'np.ac.playstation.net');
});

test('same-node hot update sends no shared restart consent', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 h.policyData.enabled = true; h.policyData.active_config = structuredClone(h.policyData.config);
 await h.app.refreshPolicy(true);
 h.handlers.psportal_preview = () => Promise.resolve({ ok: true, token: 'b'.repeat(64), can_apply: true,
  restart_required: false, blockers: [], rules: [], validation: { protection_rules: 1 } });
 await h.app.policyAction('preview');
 assert.equal(h.app.policyConfirmation.hidden, true);
 assert.equal(h.app.policyButtons.apply.disabled, false);
 assert.equal(h.app.policyButtons.apply.textContent, '热更新配置');
 await h.app.policyAction('apply'); await settle();
 assert.equal(h.calls.find(call => call.method === 'psportal_apply').args.at(-1), 0);
});

test('proxy drafts use shared device identities while device edits stay in their own form', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 h.app.fields.portal_ip.value = '10.0.0.111'; h.app.fields.portal_ip.handlers.input();
 h.app.policyInputs.domains.value = 'new.sony.example'; h.app.policyInputs.domains.handlers.input();
 h.calls.length = 0;
 await h.app.policyAction('save'); await settle();
 const call = h.calls.find(call => call.method === 'psportal_save');
 assert.equal(call.args[0], h.details.device_selectors.portal);
 assert.equal(call.args[3], 'new.sony.example');
 assert.equal(h.calls.some(call => ['device_save', 'configure', 'psportal_apply'].includes(call.method)), false);
 assert.equal(h.app.fields.portal_ip.value, '10.0.0.111');
});

test('read-only users can preview a saved policy and retain RPC write boundaries', async () => {
 const h = harness({ permission: false }); await h.init(); await policyTab(h);
 assert.equal(h.app.policyInputs.domains.disabled, true);
 assert.equal(h.app.policyButtons.save.disabled, true);
 assert.equal(h.app.policyButtons.preview.disabled, false);
 await h.app.policyAction('preview');
 assert.equal(h.app.policyButtons.apply.disabled, true);
 assert.equal(h.app.policyConfirm.disabled, true);
 h.calls.length = 0;
 await h.app.policyAction('save'); await h.app.policyAction('apply'); await h.app.policyAction('disable');
 assert.equal(h.calls.length, 0);
});

test('policy writers wait for existing management jobs and pending form submissions', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 h.status.job.busy = true;
 await h.app.refresh();
 assert.equal(h.app.policyButtons.save.disabled, true);
 h.calls.length = 0;
 await h.app.policyAction('save');
 assert.equal(h.calls.length, 0);
 h.status.job.busy = false;
 await h.app.refresh();
 h.app.pending = true; h.app.updatePolicyControls();
 assert.equal(h.app.policyButtons.save.disabled, true);
});

test('environment failure discards a usable preview and keeps detection retryable', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 await h.app.policyAction('preview');
 h.app.policyConfirm.checked = true;
 h.handlers.psportal_status = () => Promise.reject(new Error('router unavailable'));
 await h.app.refreshPolicy(true);
 assert.equal(h.app.policyPlan, null);
 assert.equal(h.app.policyButtons.apply.disabled, true);
 assert.match(h.app.policyBlockers.textContent, /router unavailable/);
 assert.equal(h.app.policyButtons.preview.disabled, false);
 delete h.handlers.psportal_status;
 await h.app.refreshPolicy(true);
 assert.equal(h.app.policyEnvironmentError, false);
});

test('policy state blockers invalidate a previously approved preview', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 await h.app.policyAction('preview');
 h.policyData.blockers = ['PassWall 节点已变化'];
 await h.app.refreshPolicy(true);
 assert.equal(h.app.policyPlan, null);
 assert.equal(h.app.policyButtons.apply.disabled, true);
});

test('backend rejects expired previews with a fresh-preview path', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 await h.app.policyAction('preview');
 h.app.policyConfirm.checked = true;
 h.handlers.psportal_apply = () => Promise.resolve({ ok: false, error: '状态已变化，请重新生成预览' });
 await h.app.policyAction('apply'); await settle();
 assert.match(h.app.policyNotice.textContent, /重新生成预览/);
 assert.equal(h.app.policyPlan, null);
 assert.equal(h.app.policyPending, false);
});

test('completed policy jobs report their own result in the policy tab', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 h.app.addDomainToPolicy('api.sony.example', 'domains');
 h.policyData.config.domains = h.app.policyInputs.domains.value;
 h.policyData.enabled = true; h.policyData.environment.attached_cores = 1;
 h.status.job = { id: 'policy-job', action: 'psportal_apply', state: 'complete', busy: false };
 await h.app.refresh(); await settle();
 assert.match(h.app.policyNotice.textContent, /透明代理已启用/);
 assert.equal(h.app.policyConfigNotice.textContent, h.app.policyNotice.textContent);
 assert.equal(h.app.domainActionNotice.hidden, true);
 assert.match(h.app.policyState.textContent, /载入/);
 assert.equal(h.app.policyButtons.disable.disabled, false);
});

test('a completed apply shows the canonical MAC that follows the selected IP', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 h.app.policyInputs.portal.value = '10.0.0.101';
 h.policyData.config.portal = '02:00:00:00:00:01';
 h.status.job = { id: 'canonical-job', action: 'psportal_apply', state: 'complete', busy: false };
 await h.app.refresh(); await settle();
 assert.equal(h.app.policyInputs.portal.value, '02:00:00:00:00:01');
});

test('a proxy task finishing on the device page refreshes its main status and device editing state', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 h.policyData.enabled = true; h.policyData.environment.attached_cores = 1;
 await h.app.refreshPolicy(true);
 h.deviceData.proxy_enabled = true;
 h.app.selectTab('devices'); await h.app.refreshDevices(true); await settle();
 assert.equal(h.app.buttons.device_save.disabled, true);
 h.policyData.enabled = false; h.policyData.environment.attached_cores = 0;
 h.status.job = {id:'disabled-away',action:'psportal_disable',state:'complete',busy:false};
 h.calls.length = 0;
 await h.app.refresh(); await settle();
 assert.equal(h.app.activeTab, 'devices');
 assert.equal(h.calls.some(call => call.method === 'psportal_status'), true);
 assert.equal(h.app.proxyNavNode.textContent, '已停用');
 assert.equal(h.app.fields.portal_ip.disabled, false);
 assert.equal(h.app.buttons.device_save.disabled, false);
});

test('hidden log panels generate only dynamic status polls', async () => {
 const h = harness(); await h.init(); h.calls.length = 0;
 await h.app.refresh(); await settle();
 assert.deepEqual(h.calls.map(call => call.method), ['status']);
 assert.equal(h.poll.seconds, 3);
 h.app.selectStage('bitrate', 'logs'); await h.app.refreshLogs();
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
 h.app.selectStage('bitrate', 'logs'); const log = h.app.refreshLogs(); await settle();
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

test('domain views load on demand and compact polling reuses the ten-second sample', async () => {
 const h = harness(); await h.init(); h.calls.length = 0;
 await h.app.refresh(); await settle();
 assert.deepEqual(h.calls.map(call => call.method), ['status']);
 h.app.selectStage('proxy', 'logs'); h.app.selectLogTab('domains');
 await h.app.refreshDomains(); await settle();
 assert.match(elementText(h.app.domainList), /api\.sony\.example/);
 assert.match(elementText(h.app.domainList), /本轮新增/);
 assert.equal(h.app.proxyLogNode.hidden, true);
 h.calls.length = 0;
 await h.app.refresh(); await settle();
 assert.deepEqual(h.calls.map(call => call.method), ['status']);
 h.app.selectTab('bitrate'); h.calls.length = 0;
 await h.app.refresh(); await settle();
 assert.deepEqual(h.calls.map(call => call.method), ['status']);
});

test('a blocked domain response leaves dynamic status and recovery controls available', async () => {
 const h = harness({ manualTimers: true }); await h.init();
 h.handlers.domains = () => new Promise(() => {});
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
 h.handlers.domains = selected => selected ? Promise.resolve({ ...h.domainData, selected: {
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

test('the three main features keep configuration, runtime and logs in their own panels', async () => {
 const h = harness(); await h.init();
 assert.deepEqual(Object.keys(h.app.mainTabs), ['devices', 'bitrate', 'proxy']);
 assert.deepEqual(Object.keys(h.app.stageTabs.bitrate), ['config', 'runtime', 'logs']);
 assert.deepEqual(Object.keys(h.app.stageTabs.proxy), ['config', 'runtime', 'logs']);
 assert.equal(h.app.logTabs.domains, undefined);
 assert.equal(h.app.proxyLogTabs.domains.tag, 'a');
 assert.equal(h.app.proxyLogTabs.domains.parentNode.tag, 'li');
 assert.equal(h.app.proxyLogTabs.domains.parentNode.attributes['class'], 'cbi-tab');
 assert.doesNotMatch(elementText(h.app.mainPanels.devices), /中继独立地址/);
 assert.match(elementText(h.app.stagePanels.bitrate.config), /中继独立地址/);
 assert.doesNotMatch(elementText(h.app.stagePanels.proxy.config), /已有 MAC 或当前 IP/);
 h.app.selectStage('bitrate', 'config');
 assert.equal(h.app.stagePanels.bitrate.runtime.hidden, true);
 h.app.selectStage('proxy', 'logs');
 assert.equal(h.app.mainPanels.bitrate.hidden, true);
 assert.equal(h.app.stagePanels.proxy.logs.hidden, false);
});

test('first-time setup starts at shared devices while proxy logs work before bitrate enrollment', async () => {
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
 h.app.selectStage('proxy', 'logs'); await h.app.refreshDomains(); await settle();
 assert.match(elementText(h.app.domainList), /api\.sony\.example/);
 assert.equal(h.app.buttons.baseline.disabled, true);
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

test('a shared identity update invalidates proxy previews and clears restart consent', async () => {
 const h = harness(); await h.init(); await policyTab(h); await h.app.policyAction('preview');
 h.app.policyConfirm.checked = true;
 h.details.device_selectors.portal = '02:00:00:00:00:11';
 h.details.config.portal_ip = '10.0.0.111';
 await h.app.refreshDetails();
 assert.equal(h.app.policyPlan, null);
 assert.equal(h.app.policyConfirm.checked, false);
 assert.equal(h.app.policyInputs.portal.value, '02:00:00:00:00:11');
 assert.match(elementText(h.app.mainPanels.bitrate), /10\.0\.0\.111/);
 assert.match(elementText(h.app.mainPanels.proxy), /10\.0\.0\.111/);
});

test('domain evidence enters the proxy draft before explicit preview and application', async () => {
 const h = harness(); await h.init(); await policyTab(h); await h.app.policyAction('preview');
 h.app.policyConfirm.checked = true;
 h.calls.length = 0;
 h.app.addDomainToPolicy('api.sony.example', 'domains');
 assert.equal(h.calls.length, 0);
 assert.match(h.app.policyInputs.domains.value, /api\.sony\.example/);
 assert.equal(h.app.policyPlan, null);
 assert.equal(h.app.policyConfirm.checked, false);
 assert.equal(h.app.domainActionNotice.hidden, false);
 assert.match(h.app.domainActionText.textContent, /检查配置并生成预览/);
 assert.match(h.app.policyConfigNotice.textContent, /代理草稿已调整/);
 await h.app.policyAction('preview');
 h.app.policyConfirm.checked = true;
 await h.app.policyAction('apply'); await settle();
 assert.match(h.calls.find(call => call.method === 'psportal_apply').args[3], /api\.sony\.example/);
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

test('domain additions retain list limits, read-only permissions and active job boundaries', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 h.app.policyInputs.domains.value = Array.from({length:32}, (_, i) => 'host'+i+'.example').join('\n');
 h.app.addDomainToPolicy('new.example', 'domains');
 assert.match(h.app.domainActionText.textContent, /最多 32/);
 assert.equal(h.app.policyInputs.domains.value.split('\n').length, 32);
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
 assert.match(h.app.deviceNotice.textContent, /停用后/);
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
 assert.match(h.app.policyNotice.textContent, /任务已取消/);
 assert.equal(h.calls.filter(call => call.method === 'stop').length, 1);
});

test('main navigation and stage navigation each preserve keyboard focus and selected panels', async () => {
 const h = harness(); await h.init();
 let prevented = 0;
 h.app.mainTabs.devices.handlers.keydown({key:'End',preventDefault(){prevented++;}});
 assert.equal(h.app.activeTab, 'proxy'); assert.equal(h.app.mainTabs.proxy.focused, true);
 h.app.stageTabs.proxy.config.handlers.keydown({key:'ArrowRight',preventDefault(){prevented++;}});
 assert.equal(h.app.activeStages.proxy, 'runtime');
 assert.equal(h.app.stageTabs.proxy.runtime.focused, true);
 assert.equal(h.app.stagePanels.proxy.config.hidden, true);
 assert.equal(prevented, 2);
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
 assert.match(h.app.policyNotice.textContent, /透明代理已启用/);
});

test('a proxy preview shows resolved device addresses alongside the host and port scope', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 h.handlers.psportal_preview = () => Promise.resolve({ok:true,can_apply:true,token:'a'.repeat(64),
  restart_required:false,rules:[],sources:{portal:['10.0.0.111'],ps5:['10.0.0.100']}});
 await h.app.policyAction('preview');
 assert.match(h.app.policyPreviewSources.textContent, /10\.0\.0\.111/);
 assert.match(h.app.policyPreviewSources.textContent, /10\.0\.0\.100/);
});

test('built-in dynamic coverage skips candidate additions while connectivity completes the draft', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 h.app.selectStage('proxy', 'config');
 h.domainData.candidates = [
  {domain:'region.np.communication.playstation.net',suggestion:'proxy'},
  {domain:'www.google.com',suggestion:'proxy'},
  {domain:'excluded.auth.np.ac.playstation.net',suggestion:'proxy'},
  {domain:'example.com',suggestion:'review'} ];
 h.app.policyInputs.exclusions.value = 'excluded.auth.np.ac.playstation.net';
 h.app.policyPlan = {token:'old',can_apply:true}; h.app.policyConfirm.checked = true;
 await h.app.addSuggestedDomains();
 assert.doesNotMatch(h.app.policyInputs.domains.value, /region\.np\.communication\.playstation\.net/);
 assert.match(h.app.policyInputs.domains.value, /www\.google\.com/);
 assert.doesNotMatch(h.app.policyInputs.domains.value, /excluded|example\.com/);
 assert.equal(h.app.policyPlan, null);
 assert.equal(h.app.policyConfirm.checked, false);
 assert.equal(h.policyData.active_config?.domains, undefined);
 assert.equal(h.calls.filter(call => call.method === 'psportal_apply').length, 0);
});

test('candidate capacity and read-only boundaries leave the draft unchanged', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 h.domainData.candidates = Array.from({length:33}, (_, i) => ({domain:'d'+i+'.example.com',suggestion:'proxy'}));
 const before = h.app.policyInputs.domains.value;
 await h.app.addSuggestedDomains();
 assert.equal(h.app.policyInputs.domains.value, before);
 assert.match(h.app.policyCandidateSummary.textContent, /超过 32/);
 const readonly = harness({permission:false}); await readonly.init(); await policyTab(readonly);
 assert.equal(readonly.app.policyButtons.candidates.disabled, true);
 assert.equal(readonly.app.policyButtons.probe.disabled, true);
 const count = readonly.calls.length; await readonly.app.addSuggestedDomains();
 assert.equal(readonly.calls.length, count);
});

test('unseen dynamic hosts and wildcard exclusions render the same draft interpretation', async () => {
 const h = harness(); await h.init(); await policyTab(h);
 assert.match(h.app.policyDynamicRules.textContent, /\*\.auth\.np\.ac\.playstation\.net/);
 const host = 'unseen.auth.np.ac.playstation.net';
 let actions = h.app.domainRuleActions(host);
 assert.match(elementText(actions), /动态匹配/);
 assert.equal(actions.children[1].children[0].disabled, true);
 h.app.policyInputs.exclusions.value = '*.auth.np.ac.playstation.net';
 actions = h.app.domainRuleActions(host);
 assert.match(elementText(actions), /排除清单/);
 assert.equal(actions.children[1].children[1].disabled, true);
 const original = h.app.policyInputs.domains.value;
 h.app.addDomainToPolicy(host, 'domains');
 assert.equal(h.app.policyInputs.domains.value, original);
 assert.match(h.app.domainActionText.textContent, /泛匹配排除规则/);
 h.domainData.candidates = [{domain:host,suggestion:'proxy'}, {domain:'www.google.com',suggestion:'proxy'}];
 h.app.policyInputs.domains.value = '*.google.com';
 await h.app.addSuggestedDomains();
 assert.equal(h.app.policyInputs.domains.value, '*.google.com');
 assert.match(h.app.policyCandidateSummary.textContent, /均已覆盖/);
 h.handlers.psportal_preview = () => Promise.resolve({ok:true,can_apply:true,token:'a'.repeat(64),restart_required:false,
  rules:[{domain:'*.auth.np.ac.playstation.net',builtin:true,excluded:true,ports:'443'}]});
 await h.app.policyAction('preview');
 assert.match(h.app.policyPreviewBody.children[0].children[0].textContent, /内置动态/);
 assert.match(h.app.policyPreviewBody.children[0].children[2].textContent, /排除清单/);
});

test('actual core routes and fixed-target probe stages render with separate evidence', async () => {
 const h = harness(); await h.init();
 h.policyData.telemetry = {fresh:true,sampled_cores:1,matched_connections:1,connections:[
  {device:'portal',domain:'region.np.communication.playstation.net',phase:'CONNECTED',route:'selected',bytes_up:2048,bytes_down:4096},
  {device:'ps5',domain:'dwc.dl.playstation.net',phase:'CONNECTED',route:'direct',bytes_down:8192} ]};
 h.policyData.probes = {epoch:1800000000,healthy:false,targets:[
  {domain:'auth.api.playstation.com',category_label:'认证',path:'proxy',dns:{ok:true},tcp:true,tls:false,failure:'certificate_validation'} ]};
 await policyTab(h);
 assert.match(h.app.policyCoreSummary.textContent, /命中 1/);
 assert.match(nodeText(h.app.policyConnections), /所选节点/);
 assert.match(nodeText(h.app.policyConnections), /原有直连/);
 assert.match(nodeText(h.app.policyProbeResults), /证书校验失败/);
 h.policyData.probes.current_config = false;
 await h.app.refreshPolicy(true);
 assert.match(h.app.policyProbeState.textContent, /此前配置检测/);
 assert.match(nodeText(h.app.policyProbeResults), /此前配置出口/);
});

test('a completed connectivity probe preserves an edited proxy draft', async () => {
 const h = harness(); await h.init(); h.policyData.enabled = true; await policyTab(h);
 h.app.policyInputs.domains.value = 'edited.auth.np.ac.playstation.net';
 h.app.policyInputs.domains.handlers.input();
 h.status.job = {id:'probe-complete',action:'psportal_probe',state:'complete',busy:false};
 await h.app.policyAction('probe'); await settle();
 assert.ok(h.calls.some(call => call.method === 'psportal_probe'));
 assert.equal(h.app.policyInputs.domains.value, 'edited.auth.np.ac.playstation.net');
 assert.equal(h.app.policyTouched.domains, true);
 assert.match(h.app.policyNotice.textContent, /出口检测完成/);
 h.app.update({...h.app.latest,job:{id:'probe-cancelled',action:'psportal_probe',state:'cancelled',busy:false}});
 assert.match(h.app.policyNotice.textContent, /出口检测已取消/);
 h.app.update({...h.app.latest,job:{id:'probe-failed',action:'psportal_probe',state:'failed',busy:false,error:'检测入口待检查'}});
 assert.equal(h.app.policyNotice.textContent, '检测入口待检查');
 assert.equal(h.app.policyNotice.attributes['data-error'], 'true');
});
