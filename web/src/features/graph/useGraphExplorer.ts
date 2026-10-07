import { useQueryClient } from '@tanstack/react-query';
import { useCallback, useMemo, useState } from 'react';
import { isApiError } from '../../api/client';
import { apiKey, fetchNeighbors, fetchPath, useGraphView } from '../../api/hooks';
import type { PathResult } from '../../api/types';
import { useWorkspaceName } from '../../app/workspace';
import { useToast } from '../../components/Toast';
import { formatNumber } from '../../lib/format';
import {
  collapseBranch,
  mergePath,
  mergeSubgraph,
  modelFromSubgraph,
  pathHighlight,
  type GraphModel,
} from './graphModel';

const NEIGHBOR_LIMIT = 150;

export interface GraphViewParams {
  focus: string | null;
  depth: number;
  at: string | null;
}

interface Overlay {
  key: string;
  model: GraphModel;
  /** Incremented whenever nodes are added, to re-run the layout. */
  nonce: number;
  path: PathResult | null;
}

/**
 * Graph view state: the server view plus local expansions/collapses and the highlighted path.
 * Local changes are keyed to the loaded view, so loading another view starts fresh.
 */
export function useGraphExplorer({ focus, depth, at }: GraphViewParams) {
  const workspace = useWorkspaceName();
  const queryClient = useQueryClient();
  const { notify } = useToast();
  const view = useGraphView({ ref: focus, depth, at });
  const viewKey = `${focus ?? ''}|${depth}|${at ?? ''}|${view.dataUpdatedAt}`;
  const baseModel = useMemo(() => (view.data ? modelFromSubgraph(view.data) : null), [view.data]);
  const [overlay, setOverlay] = useState<Overlay | null>(null);
  const [expanding, setExpanding] = useState<string | null>(null);
  const [pathBusy, setPathBusy] = useState(false);

  const current = overlay && overlay.key === viewKey ? overlay : null;
  const model = current?.model ?? baseModel;
  const path = current?.path ?? null;
  const highlight = useMemo(() => (path ? pathHighlight(path) : null), [path]);

  const update = useCallback(
    (change: (state: Overlay) => Overlay) => {
      setOverlay((previous) => {
        if (!baseModel) return previous;
        const state =
          previous && previous.key === viewKey
            ? previous
            : { key: viewKey, model: baseModel, nonce: 0, path: null };
        return change(state);
      });
    },
    [baseModel, viewKey],
  );

  const expand = useCallback(
    async (id: string) => {
      if (!model || expanding) return;
      setExpanding(id);
      try {
        const query = { ref: id, at: at ?? undefined, limit: NEIGHBOR_LIMIT };
        const subgraph = await queryClient.fetchQuery({
          queryKey: apiKey(workspace, '/graph/neighbors', query),
          queryFn: () => fetchNeighbors(workspace, id, at, NEIGHBOR_LIMIT),
          staleTime: 60_000,
        });
        const preview = mergeSubgraph(model, subgraph, id);
        update((state) => {
          const merged = mergeSubgraph(state.model, subgraph, id);
          return {
            ...state,
            model: merged.model,
            nonce: state.nonce + (merged.addedNodes.length > 0 ? 1 : 0),
          };
        });
        if (subgraph.truncated) {
          notify({
            tone: 'warn',
            title: 'Expansion truncated',
            description: `The server returned at most ${formatNumber(NEIGHBOR_LIMIT)} neighbors; some are not shown.`,
          });
        } else if (preview.addedNodes.length === 0) {
          notify({
            tone: 'info',
            title: 'No new neighbors',
            description: 'Every neighbor is already in the view.',
          });
        }
      } catch (error) {
        notify({
          tone: 'bad',
          title: 'Could not expand neighbors',
          description: isApiError(error) ? error.message : undefined,
        });
      } finally {
        setExpanding(null);
      }
    },
    [model, expanding, at, queryClient, workspace, update, notify],
  );

  const collapse = useCallback(
    (id: string) => {
      if (!model) return;
      const { removed } = collapseBranch(model, id);
      if (removed.length === 0) {
        notify({
          tone: 'info',
          title: 'Nothing to collapse',
          description: 'No nodes are reachable only through this node.',
        });
        return;
      }
      update((state) => ({ ...state, model: collapseBranch(state.model, id).model }));
      notify({ tone: 'info', title: `Collapsed ${removed.length} node${removed.length === 1 ? '' : 's'}` });
    },
    [model, update, notify],
  );

  const findPath = useCallback(
    async (source: string, target: string) => {
      setPathBusy(true);
      try {
        const result = await fetchPath(workspace, source, target, at);
        if (!result.found) {
          update((state) => ({ ...state, path: null }));
          notify({
            tone: 'info',
            title: 'No path found',
            description: `${source} and ${target} are not connected within the search depth.`,
          });
          return;
        }
        update((state) => {
          const merged = mergePath(state.model, result);
          return {
            ...state,
            model: merged.model,
            nonce: state.nonce + (merged.addedNodes.length > 0 ? 1 : 0),
            path: result,
          };
        });
      } catch (error) {
        notify({
          tone: 'bad',
          title: 'Path search failed',
          description: isApiError(error) ? error.message : undefined,
        });
      } finally {
        setPathBusy(false);
      }
    },
    [workspace, at, update, notify],
  );

  const clearPath = useCallback(() => update((state) => ({ ...state, path: null })), [update]);

  const reset = useCallback(() => setOverlay(null), []);

  return {
    view,
    model,
    viewKey,
    layoutNonce: current?.nonce ?? 0,
    modified: current !== null,
    path,
    highlight,
    expanding,
    pathBusy,
    expand,
    collapse,
    findPath,
    clearPath,
    reset,
  };
}
