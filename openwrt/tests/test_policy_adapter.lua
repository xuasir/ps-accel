-- Run with OpenWrt's Lua/LuCI runtime; all inputs and converters are in memory.
local json = require('luci.jsonc')
local adapter_path = arg[1] or '/usr/lib/ps-accel/psportal_adapter.lua'
arg[1] = nil
local adapter = dofile(adapter_path)
local TAG = 'ps-accel-psportal'
local tests = 0
local function same(actual, expected)
    if type(actual) ~= type(expected) then return false end
    if type(actual) ~= 'table' then return actual == expected end
    for key, value in pairs(actual) do if not same(value, expected[key]) then return false end end
    for key in pairs(expected) do if actual[key] == nil then return false end end
    return true
end
local function equal(actual, expected)
    assert(same(actual, expected), json.stringify(actual) .. ' != ' .. json.stringify(expected))
end
local function fails(fn, message)
    local ok, err = pcall(fn)
    assert(not ok and tostring(err):find(message, 1, true), tostring(err))
end
local function test(name, fn)
    fn()
    tests = tests + 1
    print('ok ' .. tests .. ' - ' .. name)
end
local function manifest()
    return {version=1,enabled=true,config={node='nodeA'},rules_path='/tmp/test-rules.json'}
end
local function core()
    return {
        inbounds={{type='redirect',tag='redirect_tcp'},{type='tproxy',tag='tproxy_udp',network='udp'},
                  {type='socks',tag='socks-in'}},
        outbounds={{type='direct',tag='direct'},{type='socks',tag='default',server='127.0.0.1',server_port=1080}},
        dns={servers={{type='local',tag='direct'}},final='direct'},
        route={final='default',rules={
            {action='hijack-dns',inbound={'dns-in'}},
            {action='sniff',inbound={'redirect_tcp','tproxy_udp'}},
            {action='route-options',udp_connect=true},
            {domain={'other.example'},action='route',outbound='default'},
            {domain_suffix={'.download.example'},port={443},action='route',outbound='direct'},
            {domain={'blocked.example'},action='reject',method='drop'},
            {source_ip_cidr={'10.0.0.200/32'},action='route',outbound='default'}
        },rule_set={{type='local',tag='original',path='/tmp/original.srs',format='binary'}}}
    }
end
local function converter()
    return {type='socks',tag=TAG,server='127.0.0.1',server_port=1081}
end

test('boot preference and current session activation remain independent', function()
    assert(adapter.active(manifest(), nil))
    local current = manifest()
    current.autostart = false
    assert(not adapter.active(current, nil))
    assert(adapter.active(current, {enabled=true}))
    current.autostart = true
    assert(not adapter.active(current, {enabled=false}))
    assert(adapter.active(current, nil))
    current.enabled = false
    assert(not adapter.active(current, {enabled=true}))
end)

test('original rules, DNS and final remain intact after scoped insertion', function()
    local original, config = core(), core()
    adapter.transform(config, manifest(), converter)
    equal(config.dns, original.dns)
    equal(config.route.final, original.route.final)
    for i=1,3 do equal(config.route.rules[i], original.route.rules[i]) end
    for i=4,#original.route.rules do equal(config.route.rules[i+3], original.route.rules[i]) end
    equal(config.route.rule_set[1], original.route.rule_set[1])
end)

test('target route is limited to transparent TCP inbounds', function()
    local config = adapter.transform(core(), manifest(), converter)
    equal(config.route.rules[6], {rule_set={TAG},inbound={'redirect_tcp'},action='route',outbound=TAG})
end)

test('serialized copies retain original matches and every scoped inbound', function()
    local config = json.parse(json.stringify(adapter.transform(core(), manifest(), converter)))
    equal(config.route.rules[4].rules[1].inbound, {'redirect_tcp'})
    equal(config.route.rules[5].rules[1].inbound, {'redirect_tcp'})
    equal(config.route.rules[6].inbound, {'redirect_tcp'})
    equal(config.route.rules[8].domain_suffix, {'.download.example'})
    equal(config.route.rules[9].domain, {'blocked.example'})
end)

test('original direct and reject conditions retain their entire matches', function()
    local config = adapter.transform(core(), manifest(), converter)
    equal(config.route.rules[4], {type='logical',mode='and',rules={
        {rule_set={TAG},inbound={'redirect_tcp'}}, {domain_suffix={'.download.example'},port={443}}
    },action='route',outbound='direct'})
    equal(config.route.rules[5].method, 'drop')
    equal(config.route.rules[5].rules[2], {domain={'blocked.example'}})
end)

test('an inverted direct rule stays inverted inside its scoped guard', function()
    local config = core()
    config.route.rules[5].invert = true
    adapter.transform(config, manifest(), converter)
    assert(config.route.rules[4].rules[2].invert)
end)

test('repeated injection leaves one owned outbound, set and target route', function()
    local active = manifest()
    active.owned = true
    local config = adapter.transform(core(), active, converter)
    local once = json.parse(json.stringify(config))
    adapter.transform(config, active, converter)
    equal(config, once)
end)

test('reserved tags on an existing outbound or set block first attachment', function()
    local config = core()
    config.outbounds[#config.outbounds+1] = converter()
    fails(function() adapter.transform(config, manifest(), converter) end, 'reserved outbound')
    config = core()
    config.route.rule_set[1].tag = TAG
    fails(function() adapter.transform(config, manifest(), converter) end, 'reserved rule-set')
end)

test('unsupported protection options stop generation before widening the match', function()
    local config = core()
    config.route.rules[5].future_match = 'keep'
    fails(function() adapter.transform(config, manifest(), converter) end, 'unsupported direct/reject')
end)

test('a disabled manifest returns the untouched original configuration', function()
    local active, original = manifest(), core()
    active.enabled = false
    equal(adapter.transform(core(), active, function() error('unused') end), original)
end)

test('UDP-only and explicit proxy cores require a transparent TCP entry', function()
    local config = core()
    table.remove(config.inbounds, 1)
    fails(function() adapter.transform(config, manifest(), converter) end, 'transparent TCP inbound')
end)

test('node resolver and detour references must already exist in the original core', function()
    fails(function() adapter.transform(core(), manifest(), function()
        local outbound = converter()
        outbound.domain_resolver = {server='missing'}
        return outbound
    end) end, 'DNS resolver missing')
    fails(function() adapter.transform(core(), manifest(), function()
        local outbound = converter()
        outbound.detour = 'default'
        return outbound
    end) end, 'existing direct outbound')
end)

test('native conversion strips internal fields and restores generation flags', function()
    local old_api, old_native = package.loaded['luci.passwall.api'], package.loaded['luci.passwall.util_sing-box']
    local node = {type='sing-box',protocol='socks',address='127.0.0.1'}
    local native = {NO_RUN=false}
    native.gen_outbound = function()
        assert(native.NO_RUN)
        return {type='socks',tag='with remark',server='127.0.0.1',server_port=1081,
                _id='nodeA',_flag='psportal',_flag_proxy_tag='internal',domain_resolver={server='direct'}}
    end
    package.loaded['luci.passwall.api'] = {uci_get_c=function() return node end, datatypes={hostname=function() return false end}}
    package.loaded['luci.passwall.util_sing-box'] = native
    local config = adapter.transform(core(), manifest())
    equal(config.outbounds[3], {type='socks',tag=TAG,server='127.0.0.1',server_port=1081,detour='direct',routing_mark=255})
    equal(native.NO_RUN, false)
    native.gen_outbound = function() error('secret node details') end
    fails(function() adapter.transform(core(), manifest()) end, 'node conversion failed')
    equal(native.NO_RUN, false)
    for key, value in pairs({chain_proxy='1',shadowtls='1',ech='1'}) do
        node[key] = value
        fails(function() adapter.transform(core(), manifest()) end, 'plain node')
        node[key] = nil
    end
    node.domain_resolver = 'https'
    node.domain_resolver_dns_https = 'https://dns.example/query'
    fails(function() adapter.transform(core(), manifest()) end, 'plain node')
    node.domain_resolver, node.domain_resolver_dns_https = nil, nil
    package.loaded['luci.passwall.api'], package.loaded['luci.passwall.util_sing-box'] = old_api, old_native
end)

local function diagnostic_manifest()
    local m = manifest()
    m.direct_rules_path = '/tmp/test-direct-rules.json'
    m.diagnostics = {secret=string.rep('a',48),cores={['redirect:redirect_tcp:0']={api_port=18780,probe_port=18781,api_owned=true}}}
    return m
end

test('diagnostic controller and authenticated probe listen only on loopback', function()
    local m = diagnostic_manifest()
    local config = adapter.transform(core(), m, converter)
    equal(config.experimental.clash_api.external_controller, '127.0.0.1:18780')
    equal(config.experimental.clash_api.secret, m.diagnostics.secret)
    local inbound = config.inbounds[#config.inbounds]
    equal(inbound.listen, '127.0.0.1')
    equal(inbound.users[1], {username='proxy',password=m.diagnostics.secret})
    equal(config.route.rules[1], {inbound={TAG..'-probe'},auth_user={'proxy'},action='route',outbound=TAG})
    equal(config.route.rules[2].outbound, 'direct')
end)

test('firmware direct routing stays within its device set and original rejects', function()
    local config = adapter.transform(core(), diagnostic_manifest(), converter)
    local index
    for i, rule in ipairs(config.route.rules) do
        if rule.rule_set and rule.rule_set[1] == TAG..'-direct' then index = i end
    end
    assert(index)
    equal(config.route.rules[index].inbound, {'redirect_tcp'})
    equal(config.route.rules[index].outbound, 'direct')
    equal(config.route.rules[index-1].action, 'reject')
    equal(config.route.rules[index-1].rules[1].rule_set, {TAG..'-direct'})
    equal(config.route.rules[index-1].rules[2], {domain={'blocked.example'}})
end)

test('repeated diagnostic attachment keeps original DNS and adds one private entry', function()
    local m = diagnostic_manifest(); m.owned = true
    local config = adapter.transform(core(), m, converter)
    local first = json.parse(json.stringify(config))
    adapter.transform(config, m, converter)
    equal(config, first)
    equal(config.dns, core().dns)
    equal(config.route.final, core().route.final)
end)

test('an existing authenticated controller retains its complete configuration', function()
    local config, m = core(), diagnostic_manifest()
    config.experimental = {cache_file={enabled=true},clash_api={external_controller='127.0.0.1:9090',secret='original',default_mode='rule'}}
    local original = json.parse(json.stringify(config.experimental))
    m.diagnostics.cores['redirect:redirect_tcp:0'].api_owned = false
    adapter.transform(config, m, converter)
    equal(config.experimental, original)
end)

test('foreign private entries and invalid credentials stop attachment', function()
    local config = core()
    config.inbounds[#config.inbounds+1] = {type='mixed',tag=TAG..'-probe'}
    fails(function() adapter.transform(config, diagnostic_manifest(), converter) end, 'reserved diagnostic inbound')
    local m = diagnostic_manifest(); m.diagnostics.secret = 'bad'
    fails(function() adapter.transform(core(), m, converter) end, 'invalid diagnostic credentials')
end)

local function guards(config)
    local result = {}
    for _, rule in ipairs(config.route.rules) do
        if rule.type == 'logical' then result[#result+1] = rule end
    end
    return result
end

test('a catch-all direct fallback acts as the default exit and adds no guard', function()
    for _, range in ipairs({'0:65535', '1:65535', ':'}) do
        local config = core()
        local fallback = {action='route',port_range={range},outbound='direct'}
        config.route.rules[#config.route.rules+1] = fallback
        adapter.transform(config, manifest(), converter)
        equal(#guards(config), 2)
        for _, guard in ipairs(guards(config)) do assert(not guard.rules[2].port_range, range) end
        equal(config.route.rules[6], {rule_set={TAG},inbound={'redirect_tcp'},action='route',outbound=TAG})
        equal(config.route.rules[#config.route.rules], fallback)
    end
end)

test('partial port ranges and combined conditions keep their scoped guards', function()
    local config = core()
    config.route.rules[#config.route.rules+1] = {action='route',port_range={'1000:2000'},outbound='direct'}
    config.route.rules[#config.route.rules+1] = {action='route',port_range={'0:65535'},domain={'lan.example'},outbound='direct'}
    config.route.rules[#config.route.rules+1] = {action='reject',port_range={'0:65535'},invert=true}
    adapter.transform(config, manifest(), converter)
    local found = guards(config)
    equal(#found, 5)
    equal(found[3].rules[2], {port_range={'1000:2000'}})
    equal(found[4].rules[2], {port_range={'0:65535'},domain={'lan.example'}})
    equal(found[5].rules[2], {port_range={'0:65535'},invert=true})
end)

test('a block default adds no empty guard to either owned rule set', function()
    local config = core()
    config.route.final = nil
    config.route.rules[#config.route.rules+1] = {action='reject'}
    adapter.transform(config, diagnostic_manifest(), converter)
    local found = guards(config)
    equal(#found, 3)
    for _, guard in ipairs(found) do assert(next(guard.rules[2]) ~= nil) end
    equal(config.route.rules[#config.route.rules], {action='reject'})
    equal(config.route.final, nil)
end)

print(tests .. ' adapter tests passed')
