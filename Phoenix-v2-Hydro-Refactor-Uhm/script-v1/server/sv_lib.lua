Phoenix = Phoenix or {}
Phoenix.requires_ac = Phoenix.requires_ac or {}

function Phoenix.login_card_enabled()
    return Phoenix._login_card_enabled ~= false
end

function Phoenix.set_login_card_enabled(enabled)
    Phoenix._login_card_enabled = enabled ~= false
end

local encode = json.encode
local decode = json.decode

local function strip_prefix(value, prefix)
    if type(value) ~= 'string' then return nil end
    return (value:gsub('^' .. prefix, ''))
end

function Phoenix.strip_steam(value)
    return strip_prefix(value, 'steam:')
end

function Phoenix.msg(suffix)
    return Config.messages.prefix .. ' ' .. suffix
end

function Phoenix.api_url(endpoint)
    return Config.api.base_url .. Config.api.endpoints[endpoint]
end

local function api_headers()
    return {
        ['Content-Type'] = 'application/json',
        ['X-Server-Key'] = Config.api.server_key,
    }
end

function Phoenix.api_post(endpoint, payload, cb)
    PerformHttpRequest(Phoenix.api_url(endpoint), function(code, body)
        if code ~= 200 then
            if cb then cb(nil) end
            return
        end

        local ok, data = pcall(decode, body)
        if not ok or type(data) ~= 'table' then
            if cb then cb(nil) end
            return
        end

        if cb then cb(data) end
    end, 'POST', encode(payload), api_headers())
end

function Phoenix.await_api_post(endpoint, payload, timeout_ms)
    local done, result = false, nil

    Phoenix.api_post(endpoint, payload, function(data)
        done, result = true, data
    end)

    local waited = 0
    while not done and waited < timeout_ms do
        Wait(100)
        waited = waited + 100
    end

    return done and result or nil
end

function Phoenix.parse_identifiers(src)
    if not src or src == 0 then return nil end

    local ids = GetPlayerIdentifiers(src)
    if not ids then return nil end

    local steam, license, license2, discord

    for i = 1, #ids do
        local id = ids[i]
        if type(id) == 'string' then
            if id:sub(1, 6) == 'steam:' then
                steam = id:sub(7)
            elseif id:sub(1, 8) == 'license:' then
                license = id:sub(9)
            elseif id:sub(1, 9) == 'license2:' then
                license2 = id:sub(10)
            elseif id:sub(1, 8) == 'discord:' then
                discord = id:sub(9)
            end
        end
    end

    if not steam then return nil end

    return {
        steam_hex  = steam,
        license    = license,
        license2   = license2,
        discord_id = discord,
        name       = GetPlayerName(src),
    }
end

function Phoenix.collect_tokens(src, max_tokens)
    local tokens = {}
    local count = (GetNumPlayerTokens and GetNumPlayerTokens(src)) or 0
    local limit = math.min(count - 1, (max_tokens or 12) - 1)

    for i = 0, limit do
        local token = GetPlayerToken(src, i)
        if token and token ~= '' then
            tokens[#tokens + 1] = token
        end
    end

    return tokens
end

function Phoenix.collect_fingerprint(src)
    local ids = Phoenix.parse_identifiers(src)
    if not ids then return nil end

    ids.tokens = Phoenix.collect_tokens(src, Config.evasion.max_tokens)
    return ids
end

function Phoenix.collect_kill_profile(src)
    local ids = Phoenix.parse_identifiers(src)
    if not ids then return nil end

    local token = GetPlayerToken(src, 0)
    if token then
        token = (token:gsub('^%d+:', ''))
    end

    return {
        steam_hex  = ids.steam_hex,
        discord_id = ids.discord_id,
        license    = ids.license or ids.license2,
        token      = token,
        name       = ids.name,
    }
end

function Phoenix.resolve_steam_hex(src)
    for _ = 1, Config.connection.steam_resolve_attempts do
        local steam = GetPlayerIdentifierByType(src, 'steam')
        if steam then
            return Phoenix.strip_steam(steam)
        end

        local ids = GetPlayerIdentifiers(src)
        if ids then
            for i = 1, #ids do
                local id = ids[i]
                if type(id) == 'string' and id:sub(1, 6) == 'steam:' then
                    return Phoenix.strip_steam(id)
                end
            end
        end

        Wait(Config.connection.steam_resolve_delay_ms)
    end

    return nil
end

function Phoenix.steam_from_src(src)
    return Phoenix.strip_steam(GetPlayerIdentifierByType(src, 'steam'))
end

function Phoenix.weapon_hash_name(hash)
    if not hash or hash == 0 then return nil end
    return ('0x%X'):format(hash & 0xFFFFFFFF)
end
