import { Link } from 'react-router-dom';
import { IconButton } from '../components/Button';
import { Kbd } from '../components/Data';
import { Icon } from '../components/Icon';
import { GlobalSearch } from '../features/search/GlobalSearch';
import { AuthIndicator } from './auth';
import { JobIndicator } from './JobIndicator';
import { useOracle, usePalette } from './shellState';
import { useTheme } from './theme';
import { WorkspaceSwitcher } from './WorkspaceSwitcher';

const IS_MAC = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.userAgent);
export const PALETTE_SHORTCUT = IS_MAC ? '⌘K' : 'Ctrl K';

export function TopBar({ navCollapsed, onToggleNav }: { navCollapsed: boolean; onToggleNav: () => void }) {
  const palette = usePalette();
  const oracle = useOracle();
  const { theme, toggle } = useTheme();
  return (
    <header className="topbar">
      <IconButton
        icon="menu"
        label={navCollapsed ? 'Expand navigation' : 'Collapse navigation'}
        onClick={onToggleNav}
        className="topbar__menu"
      />
      <Link to="/" className="brand" aria-label="R$F overview">
        <span className="brand__mark">R$F</span>
      </Link>
      <WorkspaceSwitcher />
      <GlobalSearch />
      <div className="topbar__actions">
        <AuthIndicator />
        <JobIndicator />
        <button
          type="button"
          className="topbar__cmd"
          onClick={palette.open}
          aria-label={`Open command palette (${PALETTE_SHORTCUT})`}
          title="Command palette"
        >
          <Icon name="command" />
          <span className="topbar__cmd-label">Commands</span>
          <Kbd>{PALETTE_SHORTCUT}</Kbd>
        </button>
        <IconButton
          icon="oracle"
          label="Open Oracle (AI assistant)"
          active={oracle.isOpen}
          onClick={() => oracle.open()}
        />
        <IconButton
          icon={theme === 'dark' ? 'sun' : 'moon'}
          label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
          onClick={toggle}
        />
      </div>
    </header>
  );
}
