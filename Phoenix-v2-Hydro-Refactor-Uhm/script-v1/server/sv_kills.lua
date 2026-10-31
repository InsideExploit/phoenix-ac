local last_ingest = {}

local function ingest_key(killer, victim)
    return killer .. ':' .. victim
end

local function clear_ingest(src)
    local prefix = tostring(src) .. ':'
    local suffix = ':' .. tostring(src)
    for key in pairs(last_ingest) do
        if key:sub(1, #prefix) == prefix or key:sub(-#suffix) == suffix then
            last_ingest[key] = nil
        end
    end
end

RegisterNetEvent(Config.kills.event_name, function(killer_src, weapon_hash)
    if not Config.kills.enabled then return end

    local victim_src = source
    if not victim_src or victim_src == 0 then return end

    killer_src = tonumber(killer_src)
    if not killer_src or killer_src <= 0 or killer_src == victim_src then return end
    if not GetPlayerName(killer_src) or not GetPlayerName(victim_src) then return end

    local key = ingest_key(killer_src, victim_src)
    local now = GetGameTimer()
    if now - (last_ingest[key] or 0) < Config.kills.ingest_cooldown_ms then return end
    last_ingest[key] = now

    local killer = Phoenix.collect_kill_profile(killer_src)
    local victim = Phoenix.collect_kill_profile(victim_src)
    if not killer or not victim then return end
    if killer.steam_hex == victim.steam_hex then return end

    Phoenix.api_post('kill_event', {
        killer = killer,
        victim = victim,
        weapon = Phoenix.weapon_hash_name(weapon_hash),
    })
end)

AddEventHandler('playerDropped', function()
    clear_ingest(source)
end)
