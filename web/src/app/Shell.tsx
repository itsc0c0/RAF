import { Suspense, useState, type ReactNode } from 'react';
import { Outlet } from 'react-router-dom';
import { isApiError } from '../api/client';
import { LoadingState } from '../components/Spinner';
import { ErrorState } from '../components/States';
import { InspectorHost } from '../features/inspector/InspectorHost';
import { OracleHost } from '../features/oracle/OraclePanel';
import { CommandPaletteHost } from '../features/palette/CommandPalette';
import { readStorage, STORAGE_KEYS, writeStorage } from '../lib/storage';
import { AnalyzeProvider } from './analyze';
import { AuthRequiredState } from './auth';
import { LeftNav } from './LeftNav';
import { InspectorProvider, OracleProvider, PaletteProvider } from './shellState';
import { TopBar } from './TopBar';
import { useWorkspace } from './workspace';

/** Shell-level UI state shared by every page (also used by tests). Requires a router above it. */
export function ShellProviders({ children }: { children: ReactNode }) {
  return (
    <InspectorProvider>
      <OracleProvider>
        <PaletteProvider>
          <AnalyzeProvider>{children}</AnalyzeProvider>
        </PaletteProvider>
      </OracleProvider>
    </InspectorProvider>
  );
}

/** Pages render only once the workspace is known (every request is workspace scoped). */
function WorkspaceGate({ children }: { children: ReactNode }) {
  const { workspace, isLoading, error, retry } = useWorkspace();
  if (error && !workspace && isApiError(error) && error.isUnauthorized) {
    return (
      <div className="page">
        <AuthRequiredState />
      </div>
    );
  }
  if (error && !workspace) {
    return (
      <div className="page">
        <ErrorState title="R$F is not reachable" error={error} onRetry={retry} />
      </div>
    );
  }
  if (isLoading || !workspace) return <LoadingState label="Connecting to R$F…" />;
  return <>{children}</>;
}

export function Shell() {
  const [navCollapsed, setNavCollapsed] = useState(() => readStorage(STORAGE_KEYS.navCollapsed) === '1');
  const toggleNav = () => {
    setNavCollapsed((value) => {
      writeStorage(STORAGE_KEYS.navCollapsed, value ? '0' : '1');
      return !value;
    });
  };
  return (
    <ShellProviders>
      <button type="button" className="skip-link" onClick={() => document.getElementById('main')?.focus()}>
        Skip to content
      </button>
      <div className={navCollapsed ? 'shell shell--nav-collapsed' : 'shell'}>
        <TopBar navCollapsed={navCollapsed} onToggleNav={toggleNav} />
        <LeftNav collapsed={navCollapsed} />
        <main id="main" className="main" tabIndex={-1}>
          <WorkspaceGate>
            <Suspense fallback={<LoadingState label="Loading view…" />}>
              <Outlet />
            </Suspense>
          </WorkspaceGate>
        </main>
      </div>
      <OracleHost />
      <InspectorHost />
      <CommandPaletteHost />
    </ShellProviders>
  );
}
