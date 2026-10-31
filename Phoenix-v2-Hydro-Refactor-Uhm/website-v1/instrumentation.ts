export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    const { ensure_database } = await import("@/lib/database/migrate");
    await ensure_database();
    const { startTcpGateway } = await import("@/lib/net/tcp_gateway");
    startTcpGateway();
  }
}