/**
 * Bearer token for `raf serve` deployments bound to a non-loopback address: the API then requires
 * `Authorization: Bearer <token>` on every request (401 `raf.unauthorized` otherwise).
 *
 * - The token is kept in `sessionStorage` (this browser tab only, cleared when the tab closes), never
 *   in `localStorage`. When session storage is unavailable it lives in memory for the page lifetime.
 * - It is never rendered, logged or put into URLs; `api/client.ts` adds it as a header.
 * - Listeners let the UI react to token changes and to 401 `raf.unauthorized` answers (token prompt).
 */

const TOKEN_KEY = 'raf.api.token';
const MAX_TOKEN_LENGTH = 4096;
/** Visible ASCII without spaces: anything else cannot travel in an HTTP header value. */
const TOKEN_PATTERN = /^[\x21-\x7e]+$/;

let memoryToken: string | null = null;
const tokenListeners = new Set<() => void>();
/** Receives the token the rejected request was sent with (null = none). */
type UnauthorizedListener = (usedToken: string | null) => void;
const unauthorizedListeners = new Set<UnauthorizedListener>();

function storage(): Storage | null {
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

/** The token for this tab, or null. */
export function getApiToken(): string | null {
  try {
    const stored = storage()?.getItem(TOKEN_KEY);
    if (stored) return stored;
  } catch {
    // Storage blocked: fall back to the in-memory copy.
  }
  return memoryToken;
}

export function hasApiToken(): boolean {
  return getApiToken() !== null;
}

/** Whether `value` (already trimmed) can be used as a bearer token. */
export function isValidApiToken(value: string): boolean {
  return value.length > 0 && value.length <= MAX_TOKEN_LENGTH && TOKEN_PATTERN.test(value);
}

function emitTokenChange(): void {
  for (const listener of [...tokenListeners]) listener();
}

/** Stores the token for this tab (sessionStorage; memory when storage is unavailable). */
export function setApiToken(token: string): void {
  const value = token.trim();
  if (!isValidApiToken(value)) throw new Error('The token must be visible ASCII characters without spaces.');
  memoryToken = null;
  try {
    const target = storage();
    if (!target) throw new Error('unavailable');
    target.setItem(TOKEN_KEY, value);
  } catch {
    memoryToken = value;
  }
  emitTokenChange();
}

/** Removes the token from this tab (storage and memory). */
export function clearApiToken(): void {
  memoryToken = null;
  try {
    storage()?.removeItem(TOKEN_KEY);
  } catch {
    // Nothing stored.
  }
  emitTokenChange();
}

/** Subscribes to token changes (React `useSyncExternalStore`). */
export function subscribeApiToken(listener: () => void): () => void {
  tokenListeners.add(listener);
  return () => tokenListeners.delete(listener);
}

/**
 * Called by the API client whenever the server answers 401 `raf.unauthorized`, with the token the
 * request carried. Listeners can ignore stale answers (a request sent before a new token was set).
 */
export function notifyUnauthorized(usedToken: string | null): void {
  for (const listener of [...unauthorizedListeners]) listener(usedToken);
}

export function onUnauthorized(listener: UnauthorizedListener): () => void {
  unauthorizedListeners.add(listener);
  return () => unauthorizedListeners.delete(listener);
}

/** `Authorization` header for `token` (empty when there is none). */
export function authorizationHeaders(token: string | null = getApiToken()): Record<string, string> {
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export const API_TOKEN_STORAGE_KEY = TOKEN_KEY;
