Config = Config or {}

Config.api = {
    base_url = 'http://localhost:3000',
    server_key = 'REDACTED',
    endpoints = {
        server_check = '/api/phoenixac/server-check',
        fingerprint  = '/api/phoenixac/fingerprint',
        kill_event   = '/api/phoenixac/kill-event',
    },
}

Config.webhook = {
    enabled          = true,
    kick_url         = 'REDACTED',
    username         = 'Phoenix',
    kick_title       = 'Player kickato in-game',
    kick_description = 'Ha chiuso Phoenix mentre era in partita.',
    kick_color       = 0xe74c3c,
}

Config.connection = {
    watchdog_interval_ms     = 2000,
    watchdog_timeout_ms      = 5000,
    connect_timeout_ms       = 10000,
    connect_retry_attempts   = 6,
    connect_retry_delay_ms   = 2000,
    kick_fail_threshold      = 3,
    fail_open_on_api_error   = true,
    loading_card_ms          = 800,
    loading_frame_ms         = 250,
    card_dismiss_ms          = 4000,
    steam_resolve_attempts   = 10,
    steam_resolve_delay_ms   = 200,
    steam_missing_dismiss_ms = 3000,
    login_card_enabled       = true,
    timeguard_warmup_ms      = 20000,
    timeguard_timeout_ms     = 15000,
}

Config.evasion = {
    enabled    = true,
    delay_ms   = 1000,
    max_tokens = 12,
}

Config.cards = {
    logo_url         = 'REDACTED',
    brand            = 'Phoenix',
    loading_subtitle = 'Verifica di sicurezza in corso',
    loading_wait     = 'Attendere prego…',
    error_title      = 'Accesso negato',
    error_fallback   = 'Verifica fallita.',
    loading_frames   = { '◐ ', '◓ ', '◑ ', '◒ ' },
}

Config.events = {
    player_allowed = 'phoenixac:playerAllowed',
}

Config.messages = {
    prefix               = '[Phoenix]',
    steam_missing_card   = 'Steam non rilevato. Avvia Steam e riprova.',
    steam_missing_done   = 'Steam non rilevato.',
    api_error_card       = 'Servizio non disponibile. Riprova tra poco.',
    api_error_done       = 'Servizio non disponibile.',
    banned_card          = 'Sei bannato da questo server.',
    banned_done          = 'Bannato.',
    launcher_closed_card = 'Apri Phoenix prima di connetterti.',
    launcher_closed_done = 'Phoenix non attivo.',
    banned_kick          = 'Sei bannato da questo server.',
    launcher_kick        = 'Phoenix chiuso durante la partita. Riaprilo e rientra.',
}

Config.kills.ingest_cooldown_ms = 1500
