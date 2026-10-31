Config = Config or {}

Config.kills = {
    enabled = true,
    poll_interval_ms = 500,
    death_resolve_attempts = 20,
    death_resolve_delay_ms = 100,
    post_death_delay_ms = 200,
    event_name = 'phoenixac:reportKill',
}
