import { useQuery, useQueryClient } from '@tanstack/react-query';
import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react';
import { api, encodeRef } from '../api/client';
import type { WorkspaceInfo, WorkspacesResponse } from '../api/types';

/**
 * The selected workspace. Every API request carries it explicitly (`X-RAF-Workspace`) and every
 * query key includes it, so switching workspaces never mixes cached data between workspaces.
 */
export interface WorkspaceContextValue {
  workspace: string | null;
  workspaces: WorkspaceInfo[];
  /** The workspace the server (and CLI) currently consider current. */
  serverCurrent: string | null;
  isLoading: boolean;
  error: unknown;
  retry: () => void;
  switchTo: (name: string) => Promise<void>;
  create: (name: string, description: string) => Promise<void>;
}

const WorkspaceContext = createContext<WorkspaceContextValue | null>(null);

export const WORKSPACES_KEY = ['raf-workspaces'] as const;

export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [selected, setSelected] = useState<string | null>(null);
  const query = useQuery({
    queryKey: WORKSPACES_KEY,
    queryFn: ({ signal }) => api.get<WorkspacesResponse>('/workspaces', { signal }),
    staleTime: 60_000,
  });
  const items = useMemo(() => query.data?.items ?? [], [query.data]);
  const serverCurrent = query.data?.current ?? null;
  const workspace =
    selected && items.some((item) => item.name === selected) ? selected : (serverCurrent ?? null);

  const switchTo = useCallback(
    async (name: string) => {
      // Makes the workspace current for the CLI too, then scopes every request to it.
      await api.post(`/workspaces/${encodeRef(name)}/use`);
      setSelected(name);
      await queryClient.invalidateQueries({ queryKey: WORKSPACES_KEY });
    },
    [queryClient],
  );

  const create = useCallback(
    async (name: string, description: string) => {
      await api.post('/workspaces', { body: { name, description } });
      await queryClient.invalidateQueries({ queryKey: WORKSPACES_KEY });
    },
    [queryClient],
  );

  const { refetch } = query;
  const value = useMemo<WorkspaceContextValue>(
    () => ({
      workspace,
      workspaces: items,
      serverCurrent,
      isLoading: query.isPending,
      error: query.error,
      retry: () => void refetch(),
      switchTo,
      create,
    }),
    [workspace, items, serverCurrent, query.isPending, query.error, refetch, switchTo, create],
  );
  return <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>;
}

export function useWorkspace(): WorkspaceContextValue {
  const value = useContext(WorkspaceContext);
  if (!value) throw new Error('useWorkspace must be used inside <WorkspaceProvider>');
  return value;
}

/** The workspace every request should be scoped to (null until known). */
export function useWorkspaceName(): string | null {
  return useWorkspace().workspace;
}
