/**
 * Per-browser conveniences only (theme, layout choices). Storage can be unavailable (private
 * windows, blocked site data), so every access is guarded and callers always get a fallback.
 */

export function readStorage(key: string): string | null {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

export function writeStorage(key: string, value: string): void {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    // Ignore: the preference simply will not persist.
  }
}

export const STORAGE_KEYS = {
  theme: 'raf.theme',
  navCollapsed: 'raf.nav.collapsed',
} as const;
