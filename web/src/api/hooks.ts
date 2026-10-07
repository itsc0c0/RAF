/**
 * React Query hooks for the R$F API. Query keys are `['raf', workspace, path, query]`, so cached data
 * is always attributed to the workspace it was fetched from.
 */

import {
  keepPreviousData,
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
  type QueryClient,
} from '@tanstack/react-query';
import { useWorkspaceName } from '../app/workspace';
import { api, encodeRef, type QueryParams } from './client';
import type {
  AnalyzeResponse,
  BlastResult,
  ConfigEntry,
  EvidenceCase,
  EvidenceItem,
  EvidenceVerifyResult,
  ExposureItem,
  ExposureResponse,
  Finding,
  FindingStatus,
  IamPathResponse,
  Incident,
  Job,
  LabInfo,
  LabStatus,
  LensResponse,
  ObjectDetail,
  ObjectProvenance,
  ObjectRelationships,
  ObjectTypeCounts,
  OracleAnswer,
  OracleStatus,
  Page,
  PathResult,
  ProductInfo,
  RafEvent,
  RangeInfo,
  ReplayTimeline,
  SearchResponse,
  SecurityObject,
  Snapshot,
  StatusResponse,
  Subgraph,
  TimelineResponse,
  TraceResult,
  VersionInfo,
} from './types';

export function apiKey(workspace: string | null, path: string, query?: QueryParams) {
  return ['raf', workspace ?? '', path, query ?? {}] as const;
}

export interface ApiQueryOptions {
  enabled?: boolean;
  staleTime?: number;
  refetchInterval?: number | false;
  keepPrevious?: boolean;
}

/** Generic GET query scoped to the selected workspace. `path === null` disables the query. */
export function useApiQuery<T>(path: string | null, query?: QueryParams, options: ApiQueryOptions = {}) {
  const workspace = useWorkspaceName();
  return useQuery({
    queryKey: apiKey(workspace, path ?? '', query),
    queryFn: ({ signal }) => api.get<T>(path ?? '/', { workspace, query, signal }),
    enabled: path !== null && workspace !== null && (options.enabled ?? true),
    staleTime: options.staleTime,
    refetchInterval: options.refetchInterval,
    placeholderData: options.keepPrevious ? keepPreviousData : undefined,
  });
}

/** Invalidates every cached query whose path starts with one of `prefixes` ('*' = everything). */
export function invalidatePaths(client: QueryClient, prefixes: readonly string[]): Promise<void> {
  return client.invalidateQueries({
    predicate: (query) => {
      if (prefixes.includes('*')) return true;
      const path = query.queryKey[2];
      return typeof path === 'string' && prefixes.some((prefix) => path.startsWith(prefix));
    },
  });
}

/** Mutation helper: runs `fn` with the selected workspace and invalidates affected paths. */
export function useApiMutation<TVars, TResult>(
  fn: (vars: TVars, workspace: string | null) => Promise<TResult>,
  invalidate: readonly string[],
) {
  const workspace = useWorkspaceName();
  const client = useQueryClient();
  return useMutation({
    mutationFn: (vars: TVars) => fn(vars, workspace),
    onSuccess: () => invalidatePaths(client, invalidate),
  });
}

// ------------------------------------------------------------------ platform

export const useStatus = () => useApiQuery<StatusResponse>('/status', undefined, { staleTime: 10_000 });
export const useVersion = () => useApiQuery<VersionInfo>('/version', undefined, { staleTime: Infinity });
export const useConfig = () => useApiQuery<{ items: ConfigEntry[] }>('/config');
export const useProducts = () =>
  useApiQuery<{ items: ProductInfo[] }>('/products', undefined, { staleTime: 60_000 });

export function useToggleProduct() {
  return useApiMutation(
    ({ name, enable }: { name: string; enable: boolean }, workspace) =>
      api.post<ProductInfo>(`/products/${encodeRef(name)}/${enable ? 'enable' : 'disable'}`, { workspace }),
    ['/products', '/status', '/objects'],
  );
}

// ------------------------------------------------------------------ objects & search

export const useObject = (ref: string | null) =>
  useApiQuery<ObjectDetail>(ref ? `/objects/${encodeRef(ref)}` : null);

export const useObjectRelationships = (ref: string | null, limit = 200) =>
  useApiQuery<ObjectRelationships>(ref ? `/objects/${encodeRef(ref)}/relationships` : null, { limit });

export const useObjectProvenance = (ref: string | null, limit = 50) =>
  useApiQuery<ObjectProvenance>(ref ? `/objects/${encodeRef(ref)}/provenance` : null, { limit });

export const useObjectTypes = () =>
  useApiQuery<ObjectTypeCounts>('/objects/types', undefined, { staleTime: 30_000 });

export const useObjects = (query: QueryParams, enabled = true) =>
  useApiQuery<Page<SecurityObject>>('/objects', query, { enabled, keepPrevious: true });

export const useSearch = (q: string) => {
  const text = q.trim();
  return useApiQuery<SearchResponse>(
    text ? '/search' : null,
    { q: text.slice(0, 200), limit: 12 },
    { staleTime: 30_000, keepPrevious: true },
  );
};

export const useEvent = (id: string | null) => useApiQuery<RafEvent>(id ? `/events/${encodeRef(id)}` : null);

// ------------------------------------------------------------------ findings / incidents / jobs

export const useFindings = (query: QueryParams) =>
  useApiQuery<Page<Finding>>('/findings', query, { keepPrevious: true });

export const useFinding = (id: string | null) =>
  useApiQuery<Finding>(id ? `/findings/${encodeRef(id)}` : null);

export function useUpdateFinding() {
  return useApiMutation(
    ({ id, status, note }: { id: string; status: FindingStatus; note: string | null }, workspace) =>
      api.patch<Finding>(`/findings/${encodeRef(id)}`, { workspace, body: { status, note } }),
    ['/findings', '/status', '/objects'],
  );
}

export const useIncidents = () =>
  useApiQuery<{ items: Incident[] }>('/incidents', undefined, { staleTime: 30_000 });

export const useJobs = (query: QueryParams = { limit: 10 }, refetchInterval: number | false = false) =>
  useApiQuery<{ items: Job[] }>('/jobs', query, { refetchInterval });

export const useSnapshots = () => useApiQuery<{ items: Snapshot[] }>('/snapshots');

export function useCreateSnapshot() {
  return useApiMutation(
    (body: { name: string; source?: string; description?: string }, workspace) =>
      api.post<Snapshot>('/snapshots', { workspace, body: { source: 'current', description: '', ...body } }),
    ['/snapshots', '/status'],
  );
}

export function useAnalyzeUpload() {
  return useApiMutation(
    (file: File, workspace) => {
      const form = new FormData();
      form.append('file', file, file.name);
      return api.post<AnalyzeResponse>('/analyze', { workspace, form });
    },
    ['/jobs', '/analyses'],
  );
}

// ------------------------------------------------------------------ investigation

export interface GraphViewParams {
  ref?: string | null;
  depth?: number | null;
  at?: string | null;
  maxNodes?: number | null;
}

export const useGraphView = (params: GraphViewParams) =>
  useApiQuery<Subgraph>('/graph/view', {
    ref: params.ref || undefined,
    depth: params.ref ? (params.depth ?? undefined) : undefined,
    at: params.at ?? undefined,
    max_nodes: params.maxNodes ?? undefined,
  });

export function fetchNeighbors(workspace: string | null, ref: string, at: string | null, limit = 200) {
  return api.get<Subgraph>('/graph/neighbors', { workspace, query: { ref, at: at ?? undefined, limit } });
}

export function fetchPath(workspace: string | null, source: string, target: string, at: string | null) {
  return api.get<PathResult>('/graph/path', { workspace, query: { source, target, at: at ?? undefined } });
}

export interface TimelineParams {
  ref?: string | null;
  start?: string | null;
  end?: string | null;
  type?: readonly string[];
  category?: readonly string[];
  severity?: string | null;
  q?: string | null;
  filter?: string | null;
  groupBy?: string | null;
  buckets?: number;
  limit?: number;
}

export function timelineQuery(params: TimelineParams): QueryParams {
  return {
    ref: params.ref || undefined,
    start: params.start ?? undefined,
    end: params.end ?? undefined,
    type: params.type ?? [],
    category: params.category ?? [],
    severity: params.severity ?? undefined,
    q: params.q ?? undefined,
    filter: params.filter ?? undefined,
    group_by: params.groupBy ?? 'category',
    buckets: params.buckets ?? 60,
    limit: params.limit ?? 200,
  };
}

/** Timeline with keyset ("load more") pagination. Groups and histogram come with the first page. */
export function useTimeline(params: TimelineParams, enabled = true) {
  const workspace = useWorkspaceName();
  const query = timelineQuery(params);
  return useInfiniteQuery({
    queryKey: apiKey(workspace, '/timeline', query),
    queryFn: ({ pageParam, signal }) =>
      api.get<TimelineResponse>('/timeline', {
        workspace,
        signal,
        query: pageParam ? { ...query, cursor: pageParam } : query,
      }),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor ?? undefined,
    enabled: enabled && workspace !== null,
    placeholderData: keepPreviousData,
  });
}

export const useTrace = (ref: string | null, direction = 'both', depth = 3) =>
  useApiQuery<TraceResult>(ref ? `/trace/${encodeRef(ref)}` : null, { direction, depth });

export const useReplay = (ref: string | null) =>
  useApiQuery<ReplayTimeline>(ref ? `/replay/${encodeRef(ref)}` : null, undefined, { staleTime: 5 * 60_000 });

export const useLens = (query: QueryParams, enabled = true) =>
  useApiQuery<LensResponse>('/lens/query', query, { enabled, keepPrevious: true });

// ------------------------------------------------------------------ exposure

export const useExposureList = (minLevel?: string | null) =>
  useApiQuery<ExposureResponse>('/exposure', { limit: 100, min_level: minLevel ?? undefined });

export const useExposureDetail = (ref: string | null) =>
  useApiQuery<ExposureItem>(ref ? `/exposure/${encodeRef(ref)}` : null);

export const useBlast = (ref: string | null, maxDepth?: number, minConfidence?: number) =>
  useApiQuery<BlastResult>(ref ? `/blast/${encodeRef(ref)}` : null, {
    max_depth: maxDepth,
    min_confidence: minConfidence,
  });

export const useIamPath = (source: string | null, target: string | null) =>
  useApiQuery<IamPathResponse>(source && target ? '/iam/path' : null, {
    source: source ?? undefined,
    target: target ?? undefined,
  });

// ------------------------------------------------------------------ evidence

export const useEvidenceCases = () => useApiQuery<Page<EvidenceCase>>('/evidence/cases');

export const useEvidenceCase = (name: string | null) =>
  useApiQuery<EvidenceCase>(name ? `/evidence/cases/${encodeRef(name)}` : null);

export const useEvidenceItem = (id: string | null) =>
  useApiQuery<EvidenceItem>(id ? `/evidence/items/${encodeRef(id)}` : null);

export function useCreateCase() {
  return useApiMutation(
    (body: { name: string; title?: string }, workspace) =>
      api.post<EvidenceCase>('/evidence/cases', { workspace, body }),
    ['/evidence'],
  );
}

export function useVerifyCase() {
  return useApiMutation(
    (name: string, workspace) =>
      api.post<EvidenceVerifyResult>(`/evidence/cases/${encodeRef(name)}/verify`, { workspace }),
    [],
  );
}

// ------------------------------------------------------------------ ranges & labs

export const useRanges = () => useApiQuery<Page<RangeInfo>>('/range/ranges');

export function useCreateRange() {
  return useApiMutation(
    (body: { name: string; preset?: string; seed?: number }, workspace) =>
      api.post<RangeInfo>('/range/ranges', { workspace, body }),
    ['/range'],
  );
}

export type LifecycleAction = 'start' | 'stop' | 'reset' | 'destroy';

export function useRangeAction() {
  return useApiMutation(
    ({ name, action }: { name: string; action: LifecycleAction }, workspace) => {
      const path = `/range/ranges/${encodeRef(name)}`;
      return action === 'destroy'
        ? api.delete<unknown>(path, { workspace })
        : api.post<unknown>(`${path}/${action}`, { workspace });
    },
    ['/range', '/status'],
  );
}

export const useLabStatus = () => useApiQuery<LabStatus>('/lab/status', undefined, { staleTime: 30_000 });
export const useLabs = () => useApiQuery<Page<LabInfo>>('/lab/labs');

export function useCreateLab() {
  return useApiMutation(
    (body: { name: string; template?: string }, workspace) =>
      api.post<LabInfo>('/lab/labs', { workspace, body }),
    ['/lab'],
  );
}

export function useLabAction() {
  return useApiMutation(
    ({ name, action }: { name: string; action: LifecycleAction }, workspace) => {
      const path = `/lab/labs/${encodeRef(name)}`;
      return action === 'destroy'
        ? api.delete<unknown>(path, { workspace })
        : api.post<unknown>(`${path}/${action}`, { workspace });
    },
    ['/lab'],
  );
}

// ------------------------------------------------------------------ oracle

export const useOracleStatus = () =>
  useApiQuery<OracleStatus>('/oracle/status', undefined, { staleTime: 60_000 });

export function useOracleAsk() {
  const workspace = useWorkspaceName();
  return useMutation({
    mutationFn: (question: string) =>
      api.post<OracleAnswer>('/oracle/ask', { workspace, body: { question } }),
  });
}
