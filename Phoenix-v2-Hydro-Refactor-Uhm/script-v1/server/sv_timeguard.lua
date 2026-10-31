local K_XOR    = 0xB7E15163
local K_WINDOW = 30

local last_valid = {}
local join_time  = {}

local function uint32(n)
    return n & 0xFFFFFFFF
end

local function steam_low32(steam_hex)
    if type(steam_hex) ~= 'string' or #steam_hex < 8 then return 0 end
    return uint32(tonumber(steam_hex:sub(-8), 16) or 0)
end

local function verify_token(token, steam_hex)
    local low = steam_low32(steam_hex)
    local ts  = uint32(token ~ K_XOR ~ low)
    return math.abs(os.time() - ts) <= K_WINDOW
end

RegisterNetEvent('phoenixac:timeguardReady', function()
    local src = tonumber(source)
    if src and src ~= 0 then
        join_time[src] = GetGameTimer()
    end
end)

AddEventHandler('playerDropped', function()
    local src = tonumber(source)
    last_valid[src] = nil
    join_time[src]  = nil
end)

RegisterNetEvent('phoenixac:timeguard', function(token)
    local src = tonumber(source)
    if not src or src == 0 then return end

    token = tonumber(token)
    if not token then return end
    token = uint32(token)

    local steam = Phoenix.steam_from_src(src)
    if not steam then return end

    if verify_token(token, steam) then
        last_valid[src] = GetGameTimer()
    end
end)

CreateThread(function()
    local cfg = Config.connection
    while true do
        Wait(cfg.watchdog_interval_ms)
        local now = GetGameTimer()

        for _, raw in ipairs(GetPlayers()) do
            local src = tonumber(raw)
            if not GetPlayerName(src) then goto continue end

            local steam = Phoenix.steam_from_src(src)
            if not steam or not Phoenix.requires_ac[steam] then goto continue end

            local joined = join_time[src]
            if not joined or (now - joined) < cfg.timeguard_warmup_ms then goto continue end

            local seen = last_valid[src]
            if not seen or (now - seen) > cfg.timeguard_timeout_ms then
                last_valid[src] = nil
                join_time[src]  = nil
                DropPlayer(src, Phoenix.msg(Config.messages.launcher_kick))
            end

            ::continue::
        end
    end
end)
