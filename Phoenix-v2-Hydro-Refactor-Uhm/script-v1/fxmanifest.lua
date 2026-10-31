fx_version 'cerulean'
game 'gta5'
lua54 'yes'

name 'PhoenixAC'
author 'PhoenixAC'

shared_scripts {
    'config.lua',
}

client_scripts {
    'client/cl_kills.lua',
    'client/cl_timeguard.lua',
}

server_scripts {
    'server/sv_config.lua',
    'server/sv_lib.lua',
    'server/sv_cards.lua',
    'server/sv_main.lua',
    'server/sv_evasion.lua',
    'server/sv_kills.lua',
    'server/sv_timeguard.lua',
}
