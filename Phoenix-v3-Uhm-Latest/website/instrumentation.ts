export async function register() {
  if (process.env.NEXT_RUNTIME === 'nodejs') {
    const { startTcpGateway } = await import('@/lib/net/tcp_gateway');
    startTcpGateway();
  }
}
