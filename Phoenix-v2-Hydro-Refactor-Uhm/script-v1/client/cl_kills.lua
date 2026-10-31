if not Config.kills.enabled then return end

local PlayerPedId               = PlayerPedId
local PlayerId                  = PlayerId
local GetPedSourceOfDeath       = GetPedSourceOfDeath
local GetPedCauseOfDeath        = GetPedCauseOfDeath
local DoesEntityExist           = DoesEntityExist
local IsPedAPlayer              = IsPedAPlayer
local NetworkGetPlayerIndexFromPed = NetworkGetPlayerIndexFromPed
local GetPlayerServerId         = GetPlayerServerId
local IsEntityDead              = IsEntityDead
local IsPedFatallyInjured       = IsPedFatallyInjured

local function resolve_killer()
    local ped = PlayerPedId()
    local killer_ent, cause = 0, 0

    for _ = 1, Config.kills.death_resolve_attempts do
        killer_ent = GetPedSourceOfDeath(ped)
        cause      = GetPedCauseOfDeath(ped)

        if killer_ent ~= 0 and DoesEntityExist(killer_ent) then break end
        Wait(Config.kills.death_resolve_delay_ms)
    end

    if killer_ent == 0 or not DoesEntityExist(killer_ent) then return nil, cause end
    if not IsPedAPlayer(killer_ent) then return nil, cause end

    local killer_idx = NetworkGetPlayerIndexFromPed(killer_ent)
    if killer_idx == -1 or killer_idx == PlayerId() then return nil, cause end

    local killer_src = GetPlayerServerId(killer_idx)
    if not killer_src or killer_src <= 0 then return nil, cause end

    return killer_src, cause
end

CreateThread(function()
    local was_dead = false

    while true do
        local ped  = PlayerPedId()
        local dead = IsEntityDead(ped) or IsPedFatallyInjured(ped)

        if dead and not was_dead then
            was_dead = true
            Wait(Config.kills.post_death_delay_ms)

            local killer_src, weapon_hash = resolve_killer()
            if killer_src then
                TriggerServerEvent(Config.kills.event_name, killer_src, weapon_hash)
            end
        elseif not dead and was_dead then
            was_dead = false
        end

        Wait(Config.kills.poll_interval_ms)
    end
end)
