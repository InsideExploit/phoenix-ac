local SLOT_XOR_KEY = 0x7C4E91B6

local watched_players = {}
local player_last_heartbeat = {}
local player_last_value = {}
local err_c = {}
local pending_skip = {}

local function previewBody(body, maxLen)
    maxLen = maxLen or 256
    if body == nil then return '(nil)' end
    if body == '' then return '(empty)' end
    body = string.gsub(body, '%s+', ' ')
    if #body > maxLen then
        return string.sub(body, 1, maxLen) .. '...'
    end
    return body
end

local function logApi(msg)
    if Config.Debug and Config.Debug.Api then
        print('[PhoenixAC/api] ' .. msg)
    end
end

local function logSlot(msg)
    if Config.Debug and Config.Debug.Slot then
        print('[PhoenixAC/slot] ' .. msg)
    end
end

function get_loading_card(loading_text)
    return [==[
{
  "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
  "type": "AdaptiveCard",
  "version": "1.2",
  "body": [
    {
      "type": "Container",
      "items": [
        {
          "type": "Image",
          "url": "]==] .. Config.cards.logo_url .. [==[",
          "pixelWidth": 128,
          "pixelHeight": 128,
          "horizontalAlignment": "Center"
        },
        {
          "type": "TextBlock",
          "text": "]==] .. Config.cards.brand .. [==[",
          "size": "ExtraLarge",
          "weight": "Bolder",
          "horizontalAlignment": "Center",
          "spacing": "Small"
        },
        {
          "type": "TextBlock",
          "text": "]==] .. Config.cards.loading_subtitle .. [==[",
          "horizontalAlignment": "Center",
          "isSubtle": true,
          "spacing": "None"
        }
      ]
    },
    {
      "type": "Container",
      "spacing": "Large",
      "items": [
        {
          "type": "TextBlock",
          "text": "]==] .. loading_text .. [==[",
          "size": "ExtraLarge",
          "horizontalAlignment": "Center",
          "color": "Accent",
          "spacing": "Medium"
        },
        {
          "type": "TextBlock",
          "text": "]==] .. Config.cards.loading_wait .. [==[",
          "horizontalAlignment": "Center",
          "isSubtle": true
        }
      ]
    }
  ]
}]==]
end

function get_error_card(message)
    return [==[
{
  "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
  "type": "AdaptiveCard",
  "version": "1.2",
  "body": [
    {
      "type": "Container",
      "items": [
        {
          "type": "Image",
          "url": "]==] .. Config.cards.logo_url .. [==[",
          "pixelWidth": 128,
          "pixelHeight": 128,
          "horizontalAlignment": "Center"
        },
        {
          "type": "TextBlock",
          "text": "]==] .. Config.cards.error_title .. [==[",
          "size": "ExtraLarge",
          "weight": "Bolder",
          "horizontalAlignment": "Center",
          "spacing": "Medium"
        },
        {
          "type": "TextBlock",
          "text": "]==] .. (message or Config.cards.error_fallback) .. [==[",
          "horizontalAlignment": "Center",
          "isSubtle": true,
          "spacing": "Small",
          "wrap": true
        },
        {
          "type": "TextBlock",
          "text": " ",
          "spacing": "ExtraLarge"
        }
      ]
    }
  ]
}]==]
end

local function extractSteamHex(source)
    for _, id in ipairs(GetPlayerIdentifiers(source)) do
        if string.sub(id, 1, 6) == 'steam:' then
            local hex = string.lower(string.sub(id, 7))
            hex = string.gsub(hex, '^0+', '')
            if hex == '' then hex = '0' end
            return hex
        end
    end
    return nil
end

local function ShowLoadingCard(deferrals, ms)
    local frames = Config.cards.loading_frames
    local startTs = GetGameTimer()
    local idx = 1
    while (GetGameTimer() - startTs) < ms do
        deferrals.presentCard(get_loading_card(frames[idx]))
        idx = (idx % #frames) + 1
        Wait(Config.ConnectFramePeriodMs or 250)
    end
end

local function ReqToBackend(url_path, method, data)
    local url = Config.BackendUrl .. url_path
    local headers = {
        ['Authorization'] = 'Bearer ' .. Config.BackendToken,
        ['Accept']        = 'application/json',
        ['Content-Type']  = 'application/json',
    }
    local body = data and json.encode(data) or ''

    local result = nil
    PerformHttpRequest(url, function(status, respBody)
        result = { status = status, body = respBody }
    end, method, body, headers)

    local start = GetGameTimer()
    while result == nil do
        if (GetGameTimer() - start) > (Config.ConnectCheckTimeoutMs or 10000) then
            return -1, nil
        end
        Wait(50)
    end
    return result.status, result.body
end

AddEventHandler('playerConnecting', function(name, setKickReason, deferrals)
    local src = source
    local hex = extractSteamHex(src)
    if not hex then
        deferrals.defer()
        Wait(0)
        deferrals.done(Config.KickReasonNoSteam)
        return
    end

    deferrals.defer()
    Wait(0)

    ShowLoadingCard(deferrals, 1000)

    local status, body = ReqToBackend('/v1/session/status?steam_hex=' .. hex, 'GET', nil)

    ShowLoadingCard(deferrals, 2000)

    if status ~= 200 then
        logApi(('connect denied hex=%s status=%s body=%s'):format(
            hex, tostring(status), previewBody(body)))
        deferrals.presentCard(get_error_card(Config.KickReasonBackend))
        Wait(5000)
        deferrals.done(Config.KickReasonBackend)
        return
    end

    local healthy = string.match(body or '', '"healthy"%s*:%s*(%a+)')
    local reason  = string.match(body or '', '"reason"%s*:%s*"([^"]+)"')

    if reason == 'banned' then
        if Config.Enforce.BannedKick then
            deferrals.presentCard(get_error_card(Config.KickReasonBanned))
            Wait(5000)
            deferrals.done(Config.KickReasonBanned)
        else
            deferrals.done()
        end
        return
    end

    if reason == 'unregistered' or reason == 'suspended' then
        pending_skip[hex] = true
        deferrals.done()
        return
    end

    if healthy ~= 'true' then
        if not Config.Enforce.SessionHealth then
            deferrals.done()
            return
        end
        logApi(('connect denied hex=%s healthy=%s reason=%s'):format(
            hex, tostring(healthy), tostring(reason)))
        local msg = (reason == 'no-session') and Config.KickReasonNoSession or Config.KickReasonStale
        deferrals.presentCard(get_error_card(msg))
        Wait(5000)
        deferrals.done(msg)
        return
    end

    watched_players[hex] = true
    deferrals.done()
end)

AddEventHandler('playerDropped', function()
    local src = source
    local hex = extractSteamHex(src)
    if hex then
        watched_players[hex] = nil
        player_last_heartbeat[hex] = nil
        player_last_value[hex] = nil
        pending_skip[hex] = nil
    end
    err_c[tostring(src)] = nil
end)

RegisterServerEvent('k9Zx3mQ7bP4rV2sN')
AddEventHandler('k9Zx3mQ7bP4rV2sN', function(rawValue)
    local src = source
    local hex = extractSteamHex(src)
    if not hex then return end
    if not watched_players[hex] then return end
    if pending_skip[hex] then return end

    local v = tonumber(rawValue)
    if not v then return end
    v = math.floor(v) % 0x100000000

    local decrypted = (v ~ SLOT_XOR_KEY) & 0xFFFFFFFF

    if player_last_value[hex] ~= nil and decrypted <= player_last_value[hex] then
        err_c[tostring(src)] = (err_c[tostring(src)] or 0) + 1
        logSlot(('replay src=%d hex=%s enc=0x%08X dec=%d prev=%d bad=%d'):format(
            src, hex, v, decrypted, player_last_value[hex], err_c[tostring(src)]))
        if err_c[tostring(src)] >= 3 and Config.Enforce.SlotHealth then
            DropPlayer(src, Config.KickReasonSlotStale)
        end
        return
    end

    player_last_heartbeat[hex] = os.time()
    player_last_value[hex] = decrypted
    err_c[tostring(src)] = 0
    logSlot(('OK src=%d hex=%s enc=0x%08X dec=%d'):format(src, hex, v, decrypted))
end)

function GetPlayerIdFromSteamHex(targetHex)
    targetHex = string.lower(targetHex)
    for _, pid in ipairs(GetPlayers()) do
        for _, id in ipairs(GetPlayerIdentifiers(tonumber(pid))) do
            if string.sub(id, 1, 6) == 'steam:' then
                local hex = string.lower(string.sub(id, 7))
                hex = string.gsub(hex, '^0+', '')
                if hex == '' then hex = '0' end
                if hex == targetHex then
                    return tonumber(pid)
                end
            end
        end
    end
    return nil
end

CreateThread(function()
    while true do
        local now_ts = os.time()
        for hex, last in pairs(player_last_heartbeat) do
            local diff = now_ts - last
            if diff > (Config.SlotStaleSec or 60) then
                local pid = GetPlayerIdFromSteamHex(hex)
                if pid then
                    logApi(('kick hex=%s pid=%d reason=slot-timeout age=%ds'):format(hex, pid, diff))
                    DropPlayer(pid, Config.KickReasonSlotStale)
                end
                player_last_heartbeat[hex] = nil
                player_last_value[hex] = nil
            end
        end
        Wait(5000)
    end
end)
