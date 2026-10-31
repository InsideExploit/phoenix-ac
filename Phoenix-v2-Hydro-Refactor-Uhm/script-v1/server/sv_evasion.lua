local seen = {}

local function fingerprint(src)
    if not Config.evasion.enabled or not src or src == 0 then return end

    SetTimeout(Config.evasion.delay_ms, function()
        if not GetPlayerName(src) then return end

        local payload = Phoenix.collect_fingerprint(src)
        if not payload or seen[payload.steam_hex] then return end

        seen[payload.steam_hex] = true
        Phoenix.api_post('fingerprint', payload)
    end)
end

AddEventHandler('playerConnecting', function()
    fingerprint(source)
end)

AddEventHandler(Config.events.player_allowed, function(src)
    fingerprint(src)
end)

AddEventHandler('playerDropped', function()
    local steam = Phoenix.steam_from_src(source)
    if steam then seen[steam] = nil end
end)
