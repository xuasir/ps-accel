-- Add one device-scoped rule set; retain the original DNS, route order and final.
local json = require('luci.jsonc')
local TAG = 'ps-accel-psportal'
local DIRECT_TAG = TAG .. '-direct'
local PROBE_TAG = TAG .. '-probe'
local MANIFEST = '/etc/ps-accel/psportal/manifest.json'
local ACTIVATION = '/tmp/ps-accel/psportal/activation.json'
local M = {}
local PLAIN = {shadowsocks=true,trojan=true,vless=true,vmess=true,hysteria2=true,tuic=true,anytls=true,socks=true,http=true}

local function clone(value)
    if type(value) ~= 'table' then return value end
    local result = {}
    for key, child in pairs(value) do result[key] = clone(child) end
    return result
end

local function read_manifest(path)
    local f = io.open(path or MANIFEST, 'r')
    if not f then return nil end
    local raw = f:read(65537)
    f:close()
    if #raw > 65536 then error('policy manifest too large') end
    return json.parse(raw)
end

local function owned(rule)
    for _, tag in ipairs(type(rule.inbound) == 'table' and rule.inbound or {}) do
        if tag == PROBE_TAG then return true end
    end
    if rule.rule_set then
        if rule.rule_set == TAG or rule.rule_set == DIRECT_TAG then return true end
        if type(rule.rule_set) == 'table' then
            for _, tag in ipairs(rule.rule_set) do if tag == TAG or tag == DIRECT_TAG then return true end end
        end
    end
    for _, child in ipairs(rule.rules or {}) do if owned(child) then return true end end
    return false
end

local function core_key(config)
    local keys = {}
    for _, inbound in ipairs(config.inbounds or {}) do
        if (inbound.type == 'redirect' or inbound.type == 'tproxy') and inbound.network ~= 'udp' then
            keys[#keys+1] = inbound.type .. ':' .. (inbound.tag or '') .. ':' .. tostring(inbound.listen_port or 0)
        end
    end
    table.sort(keys)
    return table.concat(keys, ',')
end

local MATCH = {}
for _, key in ipairs({'type','mode','rules','invert','inbound','ip_version','network','auth_user','protocol',
    'domain','domain_suffix','domain_keyword','domain_regex','source_ip_cidr','ip_cidr','source_ip_is_private',
    'ip_is_private','source_port','source_port_range','port','port_range','process_name','process_path',
    'process_path_regex','package_name','user','user_id','clash_mode','rule_set',
    'rule_set_ip_cidr_match_source','rule_set_ip_cidr_accept_empty'}) do MATCH[key] = true end

local function matcher(rule)
    local result = {}
    for key, value in pairs(rule) do
        if MATCH[key] then
            result[key] = clone(value)
        elseif key ~= 'action' and key ~= 'outbound' and key ~= 'method' and key ~= 'no_drop' then
            error('unsupported direct/reject rule option: ' .. key)
        end
    end
    return result
end

local function all_ports(ranges)
    for _, range in ipairs(type(ranges) == 'table' and ranges or {ranges}) do
        local first, last = tostring(range):match('^(%d*):(%d*)$')
        if first and (tonumber(first) or 0) <= 1 and (tonumber(last) or 65535) >= 65535 then return true end
    end
    return false
end

-- True when a rule has no condition, or only a port range that covers every port.
local function fallback(match)
    for key, value in pairs(match) do
        if key ~= 'port_range' or not all_ports(value) then return false end
    end
    return true
end

local function convert(node_id)
    local api = require('luci.passwall.api')
    local native = require('luci.passwall.util_sing-box')
    local node = api.uci_get_c(node_id)
    local core = node and (node.type or ''):lower():gsub('_', '-'):gsub(' ', '')
    if not node or (core ~= 'sing-box' and core ~= 'singbox') or not PLAIN[node.protocol] then
        error('native Sing-box node required')
    end
    if (node.chain_proxy and node.chain_proxy ~= '' and node.chain_proxy ~= '0') or
        (node.detour and node.detour ~= '') or node.shadowtls == '1' or node.ech == '1' or
        node.hysteria2_realms == '1' or (node.domain_resolver and node.domain_resolver ~= '' and
        ((node.domain_resolver_dns and node.domain_resolver_dns ~= '') or
         (node.domain_resolver_dns_https and node.domain_resolver_dns_https ~= ''))) then
        error('plain node with existing DNS required')
    end
    node.type = 'sing-box'
    local previous = native.NO_RUN
    native.NO_RUN = true
    local ok, outbound = pcall(native.gen_outbound, 'psportal', node, TAG)
    native.NO_RUN = previous
    if not ok then error('node conversion failed') end
    if not outbound then error('node conversion failed') end
    for key in pairs(outbound) do
        if key:sub(1,1) == '_' then outbound[key] = nil end
    end
    if outbound.server and not api.datatypes.hostname(outbound.server) then
        outbound.domain_resolver = nil
    end
    if not outbound.detour and not outbound.bind_interface and outbound.server then
        outbound.detour = 'direct'
    end
    outbound.tag = TAG
    outbound.routing_mark = 255
    return outbound
end

function M.transform(config, manifest, converter)
    if not manifest or not manifest.enabled then return config end
    if manifest.version ~= 1 or type(manifest.config) ~= 'table' or
        type(manifest.config.node) ~= 'string' or type(manifest.rules_path) ~= 'string' then
        error('invalid policy manifest')
    end
    local route = config.route or {}
    config.route = route
    local inbound_tags = {}
    for _, inbound in ipairs(config.inbounds or {}) do
        if (inbound.type == 'redirect' or inbound.type == 'tproxy') and inbound.network ~= 'udp' then
            inbound_tags[#inbound_tags+1] = inbound.tag
        end
    end
    if #inbound_tags == 0 then error('transparent TCP inbound required') end
    local outbounds, direct = {}, {}
    local direct_outbound
    for _, outbound in ipairs(config.outbounds or {}) do
        if outbound.tag == TAG and not manifest.owned then error('reserved outbound tag is already used') end
        if outbound.tag ~= TAG then
            outbounds[#outbounds+1] = outbound
            if outbound.type == 'direct' then direct[outbound.tag] = true; direct_outbound = direct_outbound or outbound.tag end
        end
    end
    local added = (converter or convert)(manifest.config.node)
    if added.domain_resolver then
        local resolver = type(added.domain_resolver) == 'table' and added.domain_resolver.server or added.domain_resolver
        local found = false
        for _, server in ipairs((config.dns or {}).servers or {}) do
            if server.tag == resolver then found = true end
        end
        if not found then error('node DNS resolver missing from original configuration') end
    end
    if added.detour and not direct[added.detour] then error('node requires an existing direct outbound') end
    outbounds[#outbounds+1] = added
    config.outbounds = outbounds
    if manifest.direct_rules_path and not direct_outbound then error('existing direct outbound required for downloads') end
    local diagnostic = manifest.diagnostics
    local spec = diagnostic and diagnostic.cores and diagnostic.cores[core_key(config)]
    if diagnostic and not spec then error('diagnostic core identity changed') end
    if spec then
        if type(diagnostic.secret) ~= 'string' or #diagnostic.secret ~= 48 or not diagnostic.secret:match('^[0-9a-f]+$') then
            error('invalid diagnostic credentials')
        end
        for _, key in ipairs({'api_port','probe_port'}) do
            if type(spec[key]) ~= 'number' or spec[key] < 1 or spec[key] > 65535 then error('invalid diagnostic port') end
        end
        if spec.api_owned then
            config.experimental = config.experimental or {}
            config.experimental.clash_api = {external_controller='127.0.0.1:' .. tostring(spec.api_port),secret=diagnostic.secret}
        end
        local inbounds = {}
        for _, inbound in ipairs(config.inbounds or {}) do
            if inbound.tag == PROBE_TAG and not manifest.owned then error('reserved diagnostic inbound is already used') end
            if inbound.tag ~= PROBE_TAG then inbounds[#inbounds+1] = inbound end
        end
        inbounds[#inbounds+1] = {type='mixed',tag=PROBE_TAG,listen='127.0.0.1',listen_port=spec.probe_port,
            users={{username='proxy',password=diagnostic.secret},{username='direct',password=diagnostic.secret}}}
        config.inbounds = inbounds
    end
    local definitions = {}
    for _, definition in ipairs(route.rule_set or {}) do
        if (definition.tag == TAG or definition.tag == DIRECT_TAG) and not manifest.owned then error('reserved rule-set tag is already used') end
        if definition.tag ~= TAG and definition.tag ~= DIRECT_TAG then definitions[#definitions+1] = definition end
    end
    definitions[#definitions+1] = {type='local',tag=TAG,format='source',path=manifest.rules_path}
    if manifest.direct_rules_path then
        definitions[#definitions+1] = {type='local',tag=DIRECT_TAG,format='source',path=manifest.direct_rules_path}
    end
    route.rule_set = definitions
    local original, guards, download_guards = {}, {}, {}
    for _, rule in ipairs(route.rules or {}) do
        if not owned(rule) then
            original[#original+1] = rule
            if rule.action == 'reject' or (rule.action == 'route' and direct[rule.outbound]) then
                local match = matcher(rule)
                -- A catch-all rule is the original default exit, like route.final; the scoped route overrides it.
                if not fallback(match) then
                    local guard = {type='logical',mode='and',rules={{rule_set={TAG},inbound=clone(inbound_tags)},match},action=rule.action}
                    if rule.outbound then guard.outbound = rule.outbound end
                    if rule.method then guard.method = rule.method end
                    if rule.no_drop ~= nil then guard.no_drop = rule.no_drop end
                    guards[#guards+1] = guard
                    if manifest.direct_rules_path and rule.action == 'reject' then
                        local download_guard = clone(guard)
                        download_guard.rules[1].rule_set = {DIRECT_TAG}
                        download_guards[#download_guards+1] = download_guard
                    end
                end
            end
        end
    end
    local result, inserted = {}, false
    local function insert()
        if inserted then return end
        for _, guard in ipairs(guards) do result[#result+1] = guard end
        for _, guard in ipairs(download_guards) do result[#result+1] = guard end
        if manifest.direct_rules_path then
            result[#result+1] = {rule_set={DIRECT_TAG},inbound=clone(inbound_tags),action='route',outbound=direct_outbound}
        end
        result[#result+1] = {rule_set={TAG},inbound=clone(inbound_tags),action='route',outbound=TAG}
        inserted = true
    end
    for _, rule in ipairs(original) do
        -- Keep sniff, DNS interception and route-options ahead of domain decisions.
        if rule.action == 'route' or rule.action == 'reject' then insert() end
        result[#result+1] = rule
    end
    insert()
    if spec then
        table.insert(result, 1, {inbound={PROBE_TAG},auth_user={'proxy'},action='route',outbound=TAG})
        table.insert(result, 2, {inbound={PROBE_TAG},auth_user={'direct'},action='route',outbound=direct_outbound})
    end
    route.rules = result
    return config
end

function M.active(manifest, activation)
    if not manifest or not manifest.enabled then return false end
    if type(activation) == 'table' and type(activation.enabled) == 'boolean' then
        return activation.enabled
    end
    return manifest.autostart ~= false
end

function M.patch(raw)
    local manifest = read_manifest()
    if not M.active(manifest, read_manifest(ACTIVATION)) then return raw end
    local config = json.parse(raw)
    if not config then error('invalid generated Sing-box configuration') end
    return json.stringify(M.transform(config, manifest), 1)
end

if arg and arg[0] and arg[0]:match('/?psportal_adapter%.lua$') and arg[1] == 'preview' then
    local data = io.read('*a')
    if #data > 2 * 1024 * 1024 then error('preview payload too large') end
    local request = json.parse(data)
    if not request then error('invalid preview payload') end
    print(json.stringify(M.transform(request.config, request.manifest), 1))
end
return M
