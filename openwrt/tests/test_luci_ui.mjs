import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const source = readFileSync(new URL('../luci/htdocs/luci-static/resources/view/ps-accel/settings.js', import.meta.url), 'utf8');
const settle = () => new Promise(resolve => setImmediate(resolve));

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
 }
 appendChild(child) { this.children.push(child); child.parentNode = this; return child; }
 addEventListener(name, handler) { this.handlers[name] = handler; }
 get options() { return this.children.filter(child => child.tag === 'option'); }
 focus() { this.focused = true; }
 click() { this.handlers.click?.({ currentTarget: this }); }
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
  configured: true, baseline_valid: true, baseline_reason: '校验通过', bridges: ['br-lan'],
  autostart: false, profiles: ['35', '45', '65', '100', '200'].map(value => ({ value, description: value+' Mbps' })),
  environment: { version: '0.1.2' } };
 const status = { ok: true, details_revision: 'v1', state_known: true, status_warnings: [],
  running: false, engine_alive: false, recovery_required: false, cleanup_pending: false,
  mode: 'active', counts: {}, foreign_relay: false,
  job: { id: 'initial', state: 'complete', busy: false, action: 'baseline' } };
 const window = { getComputedStyle: () => ({ color: 'rgb(10, 10, 10)' }),
  setTimeout: manualTimers ? fn => { timers.set(++timerId, fn); return timerId; } : setTimeout,
  clearTimeout: manualTimers ? id => timers.delete(id) : clearTimeout };
 const rpc = { declare: spec => (...args) => {
  calls.push({ method: spec.method, args });
  if (handlers[spec.method]) return handlers[spec.method](...args);
  if (spec.method === 'details') return Promise.resolve(structuredClone(details));
  if (spec.method === 'status') return Promise.resolve(structuredClone(status));
  if (spec.method === 'logs') return Promise.resolve({ ok: true, kind: args[0], text: args[0]+' output' });
  return Promise.resolve({ ok: true });
 } };
 const poll = { add: (callback, seconds) => { poll.callback = callback; poll.seconds = seconds; } };
 const ui = { createHandlerFn: (object, fn, name) => () => fn.call(object, name),
  addNotification: (_id, element) => notifications.push(element.textContent) };
 const document = { body: new Element('body') };
 const app = new Function('view', 'rpc', 'poll', 'ui', 'E', 'window', 'document', 'L', source)(
  { extend: object => object }, rpc, poll, ui, E, window, document,
  { hasViewPermission: () => permission });
 return { app, calls, handlers, status, details, notifications, timers, poll,
  init: async () => { app.render(await app.load()); await settle(); },
  expire: () => { for (const [id, fn] of [...timers]) { timers.delete(id); fn(); } } };
}

test('hidden log panels generate only dynamic status polls', async () => {
 const h = harness(); await h.init(); h.calls.length = 0;
 await h.app.refresh(); await settle();
 assert.deepEqual(h.calls.map(call => call.method), ['status']);
 assert.equal(h.poll.seconds, 3);
 h.app.selectTab('logs'); await h.app.refreshLogs();
 assert.equal(h.app.logNode.textContent, 'log output');
 assert.deepEqual(h.calls.filter(call => call.method === 'logs').map(call => call.args), [['log']]);
 h.app.logTab = 'events'; await h.app.refreshLogs();
 assert.equal(h.app.logNode.textContent, 'events output');
 h.app.selectTab('stream'); h.calls.length = 0;
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
 h.app.selectTab('logs'); const log = h.app.refreshLogs(); await settle();
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
