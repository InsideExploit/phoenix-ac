const env = (name: string, fallback = ""): string =>
  (process.env[name] ?? "").trim() || fallback;

const num = (name: string, fallback: number): number => {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const n = Number(raw);
  return Number.isFinite(n) ? n : fallback;
};

const bool = (name: string, fallback: boolean): boolean => {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  return raw.toLowerCase() !== "false" && raw !== "0";
};

export const config = {
  site_url: env(
    "SITE_URL",
    process.platform === "linux" ? "https://phoenix-ac.org" : "http://localhost:3000",
  ),
  bind_host: env("BIND_HOST", "127.0.0.1"),

  discord_client_id: env("DISCORD_CLIENT_ID", ""),
  discord_client_secret: env("DISCORD_CLIENT_SECRET", "REDACTED"),
  discord_bot_token: env("DISCORD_BOT_TOKEN", "REDACTED"),

  session_secret: env("SESSION_SECRET", "REDACTED"),

  db_host: env("MYSQL_HOST", "127.0.0.1"),
  db_port: num("MYSQL_PORT", process.platform === "linux" ? 43061 : 3306),
  db_user: env("MYSQL_USER", "root"),
  db_password: env(
    "MYSQL_PASSWORD",
    process.platform === "linux" ? "REDACTED" : "",
  ),
  db_name: env("MYSQL_DATABASE", "phoenix"),

  download_file: env(
    "PAC_DOWNLOAD_FILE",
    process.platform === "linux"
      ? "/srv/PhoenixAC/backend/artifacts/PhoenixAC.msi"
      : "../backend/artifacts/PhoenixAC.msi",
  ),
  download_name: env("PAC_DOWNLOAD_NAME", "PhoenixAC.msi"),
  app_version: env("PAC_APP_VERSION", "1.1.0"),
  update_file: env("PAC_UPDATE_FILE", "private/AutoUpdate.exe"),

  phoenix_api_key: env("PHOENIX_API_KEY", "REDACTED"),
  phoenix_hmac_key: env("PHOENIX_HMAC_KEY", "REDACTED"),
  phoenix_crypto_key: env("PHOENIX_CRYPTO_KEY", "REDACTED"),
  phoenix_dashboard_key: env("PHOENIX_DASHBOARD_KEY", "REDACTED"),
  phoenix_server_key: env("PHOENIX_SERVER_KEY", "REDACTED"),

  discord_login_webhook: env("PAC_WH_LOGIN", "REDACTED"),
  discord_admin_webhook: env("PAC_WH_ADMIN", "REDACTED"),
  discord_detection_webhook: env("PAC_WH_DETECTION", "REDACTED"),
  discord_security_webhook: env("PAC_WH_SECURITY", "REDACTED"),
  discord_antibanevading_webhook: env("PAC_WH_ANTIBANEVADING", "REDACTED"),

  launcher_file: env("PAC_LAUNCHER_FILE", "private/AnticheatFinito.exe"),
  launcher_runtime_file: env("PAC_LAUNCHER_RUNTIME_FILE", "private/vxlib64.dll"),
  phoenix_launcher_sha_enforce: bool("PAC_LAUNCHER_SHA_ENFORCE", true),
  phoenix_check_debug: bool("PAC_CHECK_DEBUG", false),

  phoenix_tcp_port: num("PAC_TCP_PORT", 37241),
  phoenix_heartbeat_seconds: num("PAC_HEARTBEAT_SECONDS", 5),
  phoenix_online_window_seconds: num("PAC_ONLINE_WINDOW_SECONDS", 20),

  steam_api_key: env("STEAM_API_KEY", "REDACTED"),

  steam_openid_realm: env("STEAM_OPENID_REALM", ""),
} as const;
