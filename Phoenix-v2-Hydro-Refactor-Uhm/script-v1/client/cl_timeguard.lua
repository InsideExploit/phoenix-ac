CreateThread(function()
    Wait(15000)

    TriggerServerEvent('phoenixac:timeguardReady')

    while true do
        local token = Citizen.InvokeNative(0x393BD2275CEB7793, Citizen.ResultAsInteger())
        TriggerServerEvent('phoenixac:timeguard', token)
        Wait(10000)
    end
end)
