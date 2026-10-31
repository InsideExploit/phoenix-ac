const phoenixEnv = (process.env.PHOENIX_ENV ?? '').toLowerCase();

export const isLocal =
  phoenixEnv === 'local' || phoenixEnv === 'dev' || phoenixEnv === 'development';

export const backendUrl: string = (() => {
  const explicit = process.env.PHOENIX_BACKEND_HTTP?.trim();
  if (explicit) return explicit;
  return isLocal ? 'http://127.0.0.1:27016' : 'http://127.0.0.1:27016';
})();

export const phoenixMode = isLocal ? 'local' : 'remote';
