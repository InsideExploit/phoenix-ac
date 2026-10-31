local armed        = {}
local tracked      = {}

Phoenix.set_login_card_enabled(Config.connection.login_card_enabled)

local function drop(src, reason)
    DropPlayer(src, Phoenix.msg(reason))
end

local function deny(deferrals, card_msg, done_msg, dismiss_ms)
    if Phoenix.login_card_enabled() then
        deferrals.presentCard(get_error_card(card_msg))
        Wait(dismiss_ms or Config.connection.card_dismiss_ms)
    end
    deferrals.done(Phoenix.msg(done_msg))
end

local function show_loading(deferrals, ms)
    if not Phoenix.login_card_enabled() then return end
    local frames = Config.cards.loading_frames
    local n = #frames
    local start = GetGameTimer()
    local i = 1

    while GetGameTimer() - start < ms do
        deferrals.presentCard(get_loading_card(frames[i]))
        i = (i % n) + 1
        Wait(Config.connection.loading_frame_ms)
    end
end

local function post_kick_webhook(name, steam, id)
    local cfg = Config.webhook
    if not cfg.enabled or not cfg.kick_url or cfg.kick_url == '' then return end

    PerformHttpRequest(cfg.kick_url, function() end, 'POST', json.encode({
        username = cfg.username,
        embeds = { {
            title       = cfg.kick_title,
            description = cfg.kick_description,
            color       = cfg.kick_color,
            fields = {
                { name = 'Nome',      value = ('`%s`'):format(name  or '?'), inline = true },
                { name = 'Steam HEX', value = ('`%s`'):format(steam or '?'), inline = true },
                { name = 'Player ID', value = ('`%s`'):format(id    or '?'), inline = true },
            },
            timestamp = os.date('!%Y-%m-%dT%H:%M:%SZ'),
        } },
    }), { ['Content-Type'] = 'application/json' })
end

local function await_check(steam)
    local cfg = Config.connection
    local attempts = cfg.connect_retry_attempts or 1
    local delay    = cfg.connect_retry_delay_ms or 0

    for i = 1, attempts do
        local result = Phoenix.await_api_post('server_check', { steam_hex = steam }, cfg.connect_timeout_ms)

        if result then
            if result.banned then return result end
            if not result.required or result.launcher_open then return result end
            if i >= attempts then return result end
        elseif i >= attempts then
            return nil
        end

        Wait(delay)
    end
end

local function evaluate(result)
    if not result.required then return true end
    if result.banned then
        return false, Config.messages.banned_card, Config.messages.banned_done
    end
    if not result.launcher_open then
        return false, Config.messages.launcher_closed_card, Config.messages.launcher_closed_done
    end
    return true
end

local function track(src, steam, required)
    src = tonumber(src) or src
    tracked[src] = { steam = steam, failures = 0, required = required ~= false }
end

local function ensure_tracked(src)
    if tracked[src] then return tracked[src] end

    local steam = Phoenix.steam_from_src(src)
    if not steam or not armed[steam] then return nil end

    track(src, steam)
    return tracked[src]
end

local function handle_result(src, entry, data)
    if not tracked[src] or not data then return end

    if data.banned then
        armed[entry.steam] = nil
        Phoenix.requires_ac[entry.steam] = nil
        tracked[src] = nil
        drop(src, Config.messages.banned_kick)
        return
    end

    if not data.required then
        armed[entry.steam] = nil
        Phoenix.requires_ac[entry.steam] = nil
        tracked[src] = nil
        return
    end

    if not data.launcher_open then
        entry.failures = entry.failures + 1
        if entry.failures >= Config.connection.kick_fail_threshold then
            armed[entry.steam] = nil
            Phoenix.requires_ac[entry.steam] = nil
            tracked[src] = nil
            post_kick_webhook(GetPlayerName(src), entry.steam, src)
            drop(src, Config.messages.launcher_kick)
        end
        return
    end

    entry.failures = 0
end

AddEventHandler('playerConnecting', function(_, _, deferrals)
    local src = source

    deferrals.defer()
    Wait(0)

    local steam = Phoenix.resolve_steam_hex(src)
    if not steam then
        return deny(deferrals,
            Config.messages.steam_missing_card,
            Config.messages.steam_missing_done,
            Config.connection.steam_missing_dismiss_ms)
    end

    show_loading(deferrals, Config.connection.loading_card_ms)

    local result = await_check(steam)
    if not result then
        if Config.connection.fail_open_on_api_error then
            print(('[Phoenix] API unreachable - allowing %s (%s)'):format(GetPlayerName(src) or '?', steam))
            TriggerEvent(Config.events.player_allowed, src, steam)
            deferrals.done()
            return
        end
        return deny(deferrals, Config.messages.api_error_card, Config.messages.api_error_done)
    end

    local ok, card_msg, done_msg = evaluate(result)
    if not ok then
        return deny(deferrals, card_msg, done_msg)
    end

    if result.required then
        armed[steam] = true
        Phoenix.requires_ac[steam] = true
    end
    TriggerEvent(Config.events.player_allowed, src, steam)
    deferrals.done()
end)

AddEventHandler('playerJoining', function()
    local src = source

    CreateThread(function()
        for _ = 1, Config.connection.steam_resolve_attempts do
            local steam = Phoenix.steam_from_src(src)
            if steam and armed[steam] then
                track(src, steam, true)
                return
            end
            Wait(Config.connection.steam_resolve_delay_ms)
        end
    end)
end)

AddEventHandler('playerDropped', function()
    local src = source
    local entry = tracked[src]
    if entry then
        armed[entry.steam] = nil
        Phoenix.requires_ac[entry.steam] = nil
    else
        local steam = Phoenix.steam_from_src(src)
        if steam then
            armed[steam] = nil
            Phoenix.requires_ac[steam] = nil
        end
    end
    tracked[src] = nil
end)

CreateThread(function()
    local cfg = Config.connection
    while true do
        Wait(cfg.watchdog_interval_ms)

        for _, raw in ipairs(GetPlayers()) do
            local src = tonumber(raw) or raw

            if not GetPlayerName(src) then
                tracked[src] = nil
            else
                local entry = ensure_tracked(src)
                if entry and entry.required then
                    local data = Phoenix.await_api_post(
                        'server_check',
                        { steam_hex = entry.steam },
                        cfg.watchdog_timeout_ms)
                    handle_result(src, entry, data)
                end
            end
        end
    end
end)

RegisterCommand('phoenixcard', function(source, args)
    if source ~= 0 then return end

    local arg = (args[1] or ''):lower()

    if arg == 'on' or arg == 'enable' or arg == '1' or arg == 'true' then
        Phoenix.set_login_card_enabled(true)
        print('[Phoenix] Login card enabled')
    elseif arg == 'off' or arg == 'disable' or arg == '0' or arg == 'false' then
        Phoenix.set_login_card_enabled(false)
        print('[Phoenix] Login card disabled')
    elseif arg == 'toggle' then
        Phoenix.set_login_card_enabled(not Phoenix.login_card_enabled())
        print('[Phoenix] Login card ' .. (Phoenix.login_card_enabled() and 'enabled' or 'disabled'))
    else
        print('[Phoenix] Login card is ' .. (Phoenix.login_card_enabled() and 'enabled' or 'disabled'))
        print('Usage: phoenixcard on|off|toggle')
    end
end, true)
