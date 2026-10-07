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
  Advisory,
  AnalysisList,
  AnalysisRecord,
  BlastResult,
  CaptureFlows,
  CaptureSummary,
  ConfigEntry,
  DependencyGraph,
  DependencyProject,
  DiffResult,
  EvidenceCase,
  EvidenceItem,
  EvidenceVerifyResult,
  ExposureItem,
  ExposureResponse,
  Finding,
  FindingStatus,
  GhostComparison,
  GhostModel,
  GhostModelSummary,
  GhostOperationInfo,
  GhostOpResult,
  GhostSimulation,
  GhostUndoResult,
  IamPathResponse,
  Incident,
  Job,
  Lab,
  LabCreateRequest,
  LabDestroyResult,
  LabList,
  LabStatus,
  LensResponse,
  ObjectDetail,
  ObjectProvenance,
  ObjectRelationships,
  ObjectTypeCounts,
  OracleAnswer,
  OracleStatus,
  PacketDetail,
  Page,
  PathResult,
  Policy,
  PolicyAnalysis,
  PolicyCheckRequest,
  PolicyCheckResult,
  PolicyDiff,
  PolicyEvaluateRequest,
  PolicyEvaluation,
  ProductInfo,
  ProtocolUploadList,
  RafEvent,
  RangeInfo,
  ReplayTimeline,
  SearchResponse,
  SecurityObject,
  Snapshot,
  StatusResponse,
  Subgraph,
  SurfaceAnalysis,
  SurfaceAsset,
  SurfaceImportResult,
  SurfaceScopeEntry,
  SurfaceScopeResult,
  SurfaceSummary,
  TimelineResponse,
  TraceResult,
  VaultRule,
  VaultSecret,
  VersionInfo,
  VulnerablePackage,
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
    ['/snapshots', '/status', '/diff'],
  );
}

// ------------------------------------------------------------------ analyses

export interface AnalyzeUploadInput {
  file: File;
  /** Optional incident name to link the imported events to. */
  incident?: string;
  /** Correlation re-runs the workspace-wide IAM and exposure analyses (server default: true). */
  correlate?: boolean;
  /** Mark what the file creates as synthetic (demo, Range or Forge data; server default: false). */
  synthetic?: boolean;
}

/**
 * `POST /analyze` (multipart `file`, form fields `incident`, `correlate`, `synthetic`). The analysis runs during
 * the request and the response is the complete record; the import changes data everywhere, so every
 * cached query is invalidated.
 */
export function useAnalyzeUpload() {
  return useApiMutation(
    ({ file, incident, correlate, synthetic }: AnalyzeUploadInput, workspace) => {
      const form = new FormData();
      form.append('file', file, file.name);
      if (incident?.trim()) form.append('incident', incident.trim());
      if (correlate !== undefined) form.append('correlate', correlate ? 'true' : 'false');
      if (synthetic) form.append('synthetic', 'true');
      return api.post<AnalysisRecord>('/analyze', { workspace, form });
    },
    ['*'],
  );
}

export const useAnalyses = (limit = 100) =>
  useApiQuery<AnalysisList>('/analyses', { limit }, { keepPrevious: true });

export const useAnalysis = (id: string | null) =>
  useApiQuery<AnalysisRecord>(id ? `/analyses/${encodeRef(id)}` : null);

// ------------------------------------------------------------------ diff

export interface DiffParams {
  a: string | null;
  b: string | null;
  category?: string | null;
  limit?: number;
}

export const useDiff = ({ a, b, category, limit }: DiffParams) =>
  useApiQuery<DiffResult>(
    a && b ? '/diff' : null,
    { a: a ?? undefined, b: b ?? undefined, category: category || undefined, limit },
    { keepPrevious: true },
  );

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
export const useLabs = () => useApiQuery<LabList>('/lab/labs');
export const useLab = (name: string | null) => useApiQuery<Lab>(name ? `/lab/labs/${encodeRef(name)}` : null);

/** `POST /lab/labs`: only the fields the API accepts (unknown fields are rejected with 422). */
export function useCreateLab() {
  return useApiMutation(
    (body: LabCreateRequest, workspace) => api.post<Lab>('/lab/labs', { workspace, body }),
    ['/lab'],
  );
}

export type LabAction = 'start' | 'stop' | 'destroy';

/**
 * Lab lifecycle. There is deliberately no exec/shell route: commands run in a lab only through the
 * local CLI (`raf lab exec`, `raf lab shell`).
 */
export function useLabAction() {
  const workspace = useWorkspaceName();
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({
      name,
      action,
      forget = false,
    }: {
      name: string;
      action: LabAction;
      forget?: boolean;
    }): Promise<Lab | LabDestroyResult> => {
      const path = `/lab/labs/${encodeRef(name)}`;
      return action === 'destroy'
        ? api.delete<LabDestroyResult>(path, { workspace, query: { forget: forget ? 'true' : undefined } })
        : api.post<Lab>(`${path}/${action}`, { workspace });
    },
    onSuccess: (_result, { name, action }) => {
      // A destroyed lab no longer exists: refetching its detail (still open in the drawer until the
      // caller closes it) would only answer 404. Everything else under /lab is refreshed.
      const gone = action === 'destroy' ? `/lab/labs/${encodeRef(name)}` : null;
      return client.invalidateQueries({
        predicate: (query) => {
          const path = query.queryKey[2];
          return typeof path === 'string' && path.startsWith('/lab') && path !== gone;
        },
      });
    },
  });
}

// ------------------------------------------------------------------ ghost

export const useGhostModels = () => useApiQuery<{ items: GhostModelSummary[] }>('/ghost/models');

export const useGhostModel = (name: string | null) =>
  useApiQuery<GhostModel>(name ? `/ghost/models/${encodeRef(name)}` : null);

export const useGhostOperations = () =>
  useApiQuery<{ items: GhostOperationInfo[] }>('/ghost/operations', undefined, { staleTime: Infinity });

export const useGhostSimulation = (name: string | null, limit = 20) =>
  useApiQuery<GhostSimulation>(name ? `/ghost/models/${encodeRef(name)}/simulate` : null, { limit });

export const useGhostCompare = (a: string | null, b: string | null) =>
  useApiQuery<GhostComparison>(a && b ? '/ghost/compare' : null, { a: a ?? undefined, b: b ?? undefined });

// Creating or deleting a model also creates/removes its frozen base snapshot.
const GHOST_PATHS = ['/ghost', '/snapshots', '/diff'];

export function useCreateGhostModel() {
  return useApiMutation(
    (body: { name: string; base: string; description?: string }, workspace) =>
      api.post<GhostModel>('/ghost/models', { workspace, body }),
    GHOST_PATHS,
  );
}

export function useCloneGhostModel() {
  return useApiMutation(
    ({ source, name }: { source: string; name: string }, workspace) =>
      api.post<GhostModel>(`/ghost/models/${encodeRef(source)}/clone`, { workspace, body: { name } }),
    GHOST_PATHS,
  );
}

export function useDeleteGhostModel() {
  return useApiMutation(
    (name: string, workspace) =>
      api.delete<{ model: string; base_snapshot_removed: string | null }>(
        `/ghost/models/${encodeRef(name)}`,
        {
          workspace,
        },
      ),
    GHOST_PATHS,
  );
}

export function useApplyGhostOp() {
  return useApiMutation(
    ({ model, op, arg }: { model: string; op: string; arg: string }, workspace) =>
      api.post<GhostOpResult>(`/ghost/models/${encodeRef(model)}/ops`, { workspace, body: { op, arg } }),
    ['/ghost', '/diff'],
  );
}

export function useUndoGhostOp() {
  return useApiMutation(
    (model: string, workspace) =>
      api.post<GhostUndoResult>(`/ghost/models/${encodeRef(model)}/undo`, { workspace }),
    ['/ghost', '/diff'],
  );
}

// ------------------------------------------------------------------ policy

export const usePolicies = () => useApiQuery<{ items: Policy[] }>('/policy/policies');

/** `POST /policy/analyze?persist=false` is a dry run; `persist=true` records (and resolves) findings. */
export function usePolicyAnalyze() {
  return useApiMutation(
    (persist: boolean, workspace) =>
      api.post<PolicyAnalysis>('/policy/analyze', {
        workspace,
        query: { persist: persist ? 'true' : 'false' },
      }),
    ['/findings', '/status', '/objects'],
  );
}

export function usePolicyEvaluate() {
  const workspace = useWorkspaceName();
  return useMutation({
    mutationFn: (body: PolicyEvaluateRequest) =>
      api.post<PolicyEvaluation>('/policy/evaluate', { workspace, body }),
  });
}

/** `POST /policy/check`: normalizes and analyzes a document; nothing is stored, so nothing is invalidated. */
export function usePolicyCheck() {
  const workspace = useWorkspaceName();
  return useMutation({
    mutationFn: (body: PolicyCheckRequest) =>
      api.post<PolicyCheckResult>('/policy/check', { workspace, body }),
  });
}

/** `GET /policy/diff`: compares the policies of two stored states (`current` or snapshot names). */
export const usePolicyDiff = (before: string | null, after: string | null) =>
  useApiQuery<PolicyDiff>(before && after ? '/policy/diff' : null, {
    before: before ?? undefined,
    after: after ?? undefined,
  });

// ------------------------------------------------------------------ protocol

export interface CaptureFilterParams {
  protocol?: string | null;
  host?: string | null;
  port?: number | null;
  flow?: number | null;
  limit?: number;
}

function captureQuery(filters: CaptureFilterParams): QueryParams {
  return {
    protocol: filters.protocol || undefined,
    host: filters.host || undefined,
    port: filters.port ?? undefined,
    flow: filters.flow ?? undefined,
    limit: filters.limit,
  };
}

/** `POST /protocol/inspect` (multipart `file`): stores the capture and returns its summary + upload ID. */
export function useInspectCapture() {
  return useApiMutation(
    ({ file }: { file: File }, workspace) => {
      const form = new FormData();
      form.append('file', file, file.name);
      return api.post<CaptureSummary>('/protocol/inspect', { workspace, form, query: { limit: 50 } });
    },
    ['/protocol/uploads'],
  );
}

/** `GET /protocol/uploads`: earlier uploads of the workspace, newest first (IDs and names, never paths). */
export const useProtocolUploads = (limit = 100) =>
  useApiQuery<ProtocolUploadList>('/protocol/uploads', { limit });

export const useCaptureSummary = (upload: string | null, filters: CaptureFilterParams) =>
  useApiQuery<CaptureSummary>(
    upload ? '/protocol/inspect' : null,
    { upload: upload ?? undefined, ...captureQuery(filters) },
    { staleTime: Infinity, keepPrevious: true },
  );

export const useCaptureFlows = (upload: string | null, sort: string, limit = 200) =>
  useApiQuery<CaptureFlows>(
    upload ? '/protocol/flows' : null,
    { upload: upload ?? undefined, sort, limit },
    { staleTime: Infinity, keepPrevious: true },
  );

export const useCapturePacket = (upload: string | null, n: number | null) =>
  useApiQuery<PacketDetail>(
    upload && n ? '/protocol/packet' : null,
    { upload: upload ?? undefined, n: n ?? undefined },
    { staleTime: Infinity, keepPrevious: true },
  );

// ------------------------------------------------------------------ vault (values are always redacted)

export const useVaultFindings = (query: QueryParams) =>
  useApiQuery<Page<Finding>>('/vault/findings', query, { keepPrevious: true });

export const useVaultSecrets = (includeRemoved: boolean) =>
  useApiQuery<Page<VaultSecret>>(
    '/vault/secrets',
    { include_removed: includeRemoved ? 'true' : undefined, limit: 500 },
    { keepPrevious: true },
  );

export const useVaultRules = () =>
  useApiQuery<{ items: VaultRule[] }>('/vault/rules', undefined, { staleTime: 5 * 60_000 });

// ------------------------------------------------------------------ surface (never scans: imported inventories only)

export const useSurfaceSummary = (expiringDays?: number) =>
  useApiQuery<SurfaceSummary>('/surface/summary', { expiring_days: expiringDays }, { keepPrevious: true });

export interface SurfaceAssetQuery {
  kind?: string | null;
  scope?: 'in' | 'out' | 'all';
  references?: boolean;
  limit?: number;
  offset?: number;
}

export const useSurfaceAssets = ({
  kind,
  scope = 'all',
  references = false,
  limit = 100,
  offset = 0,
}: SurfaceAssetQuery) =>
  useApiQuery<Page<SurfaceAsset>>(
    '/surface/assets',
    { kind: kind || undefined, scope, references: references ? 'true' : undefined, limit, offset },
    { keepPrevious: true },
  );

export const useSurfaceScope = () =>
  useApiQuery<{ items: SurfaceScopeEntry[]; total: number }>('/surface/scope');

export const useSurfaceFindings = (query: QueryParams) =>
  useApiQuery<Page<Finding>>('/surface/findings', query, { keepPrevious: true });

// Scope, imports and analyses change what is judged: summary, assets, findings everywhere.
const SURFACE_PATHS = ['/surface', '/findings', '/status', '/objects', '/graph', '/search'];

export interface SurfaceScopeInput {
  target: string;
  kind?: string;
  owner?: string;
  authorization?: string;
  replace?: boolean;
}

export function useAddSurfaceScope() {
  return useApiMutation(
    (body: SurfaceScopeInput, workspace) =>
      api.post<SurfaceScopeResult>('/surface/scope', { workspace, body }),
    SURFACE_PATHS,
  );
}

/** CIDR targets contain `/`: the reference is encoded, the API's path converter accepts it. */
export function useRemoveSurfaceScope() {
  return useApiMutation(
    (target: string, workspace) =>
      api.delete<SurfaceScopeResult>(`/surface/scope/${encodeRef(target)}`, { workspace }),
    SURFACE_PATHS,
  );
}

export function useAnalyzeSurface() {
  return useApiMutation(
    (persist: boolean, workspace) =>
      api.post<SurfaceAnalysis>('/surface/analyze', {
        workspace,
        query: { persist: persist ? 'true' : 'false' },
      }),
    SURFACE_PATHS,
  );
}

export type SurfaceFormat = 'json' | 'jsonl' | 'yaml' | 'csv';

export const SURFACE_CONTENT_TYPES: Record<SurfaceFormat, string> = {
  json: 'application/json',
  jsonl: 'application/x-ndjson',
  yaml: 'application/yaml',
  csv: 'text/csv',
};

export interface SurfaceImportInput {
  file: Blob;
  format: SurfaceFormat;
  sourceName: string;
  /** Adds the document's `scope` section to the authorized scope (explicit operator choice). */
  applyScope: boolean;
}

/** `POST /surface/import`: the inventory travels as the request body (the API never takes a path). */
export function useImportSurface() {
  return useApiMutation(
    ({ file, format, sourceName, applyScope }: SurfaceImportInput, workspace) =>
      api.post<SurfaceImportResult>('/surface/import', {
        workspace,
        query: {
          format,
          source_name: sourceName.slice(0, 200) || undefined,
          apply_scope: applyScope ? 'true' : undefined,
        },
        raw: { body: file, contentType: SURFACE_CONTENT_TYPES[format] },
      }),
    SURFACE_PATHS,
  );
}

// ------------------------------------------------------------------ dependency

export const useDependencyProjects = () =>
  useApiQuery<{ items: DependencyProject[]; total: number }>('/dependency/projects');

export const useDependencyGraph = (ref: string | null) =>
  useApiQuery<DependencyGraph>(ref ? `/dependency/projects/${encodeRef(ref)}/graph` : null);

export const useVulnerablePackages = (includeUnused: boolean) =>
  useApiQuery<{ items: VulnerablePackage[]; total: number }>(
    '/dependency/vulnerable',
    { include_unused: includeUnused ? 'true' : undefined },
    { keepPrevious: true },
  );

export const useAdvisories = () =>
  useApiQuery<{ items: Advisory[]; total: number }>('/dependency/advisories', undefined, {
    staleTime: 60_000,
  });

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
