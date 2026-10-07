import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react';
import { readStorage, STORAGE_KEYS, writeStorage } from '../lib/storage';

export type Theme = 'dark' | 'light';

interface ThemeContextValue {
  theme: Theme;
  setTheme: (theme: Theme) => void;
  toggle: () => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

function initialTheme(): Theme {
  return readStorage(STORAGE_KEYS.theme) === 'light' ? 'light' : 'dark';
}

function applyTheme(theme: Theme): void {
  document.documentElement.setAttribute('data-theme', theme);
}

/**
 * Dark is the default; the choice persists per browser (public/theme-init.js applies it before the
 * first paint). The attribute is updated synchronously in the handler so canvas consumers (graph)
 * read the new design tokens in their own effects.
 */
export function ThemeProvider({ children }: { children: ReactNode }) {
  // public/theme-init.js has already applied the stored theme to <html> before the first paint.
  const [theme, setThemeState] = useState<Theme>(initialTheme);

  const setTheme = useCallback((next: Theme) => {
    applyTheme(next);
    writeStorage(STORAGE_KEYS.theme, next);
    setThemeState(next);
  }, []);

  const toggle = useCallback(() => setTheme(theme === 'dark' ? 'light' : 'dark'), [setTheme, theme]);

  const value = useMemo(() => ({ theme, setTheme, toggle }), [theme, setTheme, toggle]);
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  const value = useContext(ThemeContext);
  if (!value) throw new Error('useTheme must be used inside <ThemeProvider>');
  return value;
}
