/**
 * Types for the R$F HTTP API (`/api/v1`), following docs/api.md.
 *
 * Every string in these payloads is untrusted data (imported logs, file names, user-controlled
 * metadata): it is rendered as text only. Shapes for products that are still being implemented
 * (blast, exposure, iam, evidence, ranges, labs, lens, oracle, analyze) mark undocumented fields
 * optional and the UI reads them defensively.
 */

export type IsoTime = string;
export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type ConfidenceLevel = 'LOW' | 'MEDIUM' | 'HIGH';
export type Metadata = Record<string, unknown>;

export const SEVERITIES: readonly Severity[] = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

// ------------------------------------------------------------------ errors

export interface ApiErrorBody {
  code: string;
  message: string;
  reason?: string;
  hint?: string;
  suggestions?: string[];
  details?: unknown;
}

// ------------------------------------------------------------------ core model

export interface SecurityObject {
  id: string;
  type: string;
  name: string;
  created_at: IsoTime;
  updated_at: IsoTime;
  first_seen: IsoTime | null;
  last_seen: IsoTime | null;
  valid_from: IsoTime | null;
  valid_to: IsoTime | null;
  source: string;
  confidence: number;
  confidence_level: ConfidenceLevel;
  tags: string[];
  metadata: Metadata;
  observations: number;
  synthetic: boolean;
}

export interface Relationship {
  id: string;
  relationship_type: string;
  source_object: string;
  target_object: string;
  timestamp: IsoTime | null;
  first_seen: IsoTime | null;
  last_seen: IsoTime | null;
  valid_from: IsoTime | null;
  valid_to: IsoTime | null;
  confidence: number;
  confidence_level: ConfidenceLevel;
  source: string;
  metadata: Metadata;
  observations: number;
  created_at: IsoTime;
  updated_at: IsoTime;
  synthetic: boolean;
}

export interface EventObjectRef {
  object_id: string;
  role: string;
}

export interface RafEvent {
  id: string;
  timestamp: IsoTime;
  event_type: string;
  category: string;
  action: string;
  outcome: string | null;
  actor: string | null;
  target: string | null;
  objects: EventObjectRef[];
  source: string;
  parser: string;
  record: string | null;
  raw_reference: string | null;
  raw: string | null;
  severity: Severity;
  confidence: number;
  attributes: Metadata;
  relationships: string[];
  message: string | null;
  synthetic: boolean;
  job_id?: string | null;
  incidents: string[];
  ingested_at?: IsoTime | null;
}

export interface EvidenceRef {
  kind: string;
  id: string;
  note?: string | null;
}

/**
 * Explainable scoring factor (findings, exposure, blast risk). Exposure/blast factors carry points;
 * some finding explanations only state the direction (sign) of a factor.
 */
export interface ScoreFactor {
  label: string;
  sign: string;
  points?: number | null;
  evidence?: string[];
  rule?: string;
  factor?: string;
}

export type FindingStatus = 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED' | 'FALSE_POSITIVE' | 'SUPPRESSED';
export const FINDING_STATUSES: readonly FindingStatus[] = [
  'OPEN',
  'ACKNOWLEDGED',
  'RESOLVED',
  'FALSE_POSITIVE',
  'SUPPRESSED',
];

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: number;
  confidence_level: ConfidenceLevel;
  product: string;
  rule_id: string;
  status: FindingStatus;
  affected_objects: string[];
  evidence: EvidenceRef[];
  recommendation: string;
  explanation: ScoreFactor[];
  created_at: IsoTime;
  updated_at: IsoTime;
  tags: string[];
  metadata: Metadata;
}

export interface Incident {
  id: string;
  name: string;
  title: string;
  status: string;
  severity: Severity;
  start: IsoTime | null;
  end: IsoTime | null;
  description: string;
  source: string;
  event_count: number;
  created_at: IsoTime;
  updated_at: IsoTime;
  tags?: string[];
  metadata?: Metadata;
}

export interface Pivot {
  key: string;
  product: string;
  label: string;
  command: string;
  view: string;
}

export interface ObjectActivity {
  first_event: IsoTime | null;
  last_event: IsoTime | null;
  events: number;
}

export interface ObjectDetail {
  object: SecurityObject;
  notes: string[];
  activity: ObjectActivity | null;
  relationship_count: number;
  findings: Finding[];
  pivots: Pivot[];
}

export interface ProvenanceRecord {
  subject_id: string;
  subject_kind: string;
  source: string;
  parser: string | null;
  record: string | null;
  event_id: string | null;
  observed_at: IsoTime | null;
  evidence_id: string | null;
  source_sha256: string | null;
  job_id?: string | null;
  note: string | null;
  recorded_at?: IsoTime | null;
}

export interface ObjectRelationships {
  object_id: string;
  items: Relationship[];
  total: number;
}

export interface ObjectProvenance {
  object_id: string;
  items: ProvenanceRecord[];
  total: number;
}

export interface Page<T> {
  items: T[];
  total?: number | null;
  limit?: number;
  offset?: number;
}

export interface SearchResponse {
  query: string;
  objects: SecurityObject[];
  incidents: SecurityObject[];
  findings: Finding[];
}

export interface ObjectTypeCounts {
  objects: Record<string, number>;
  relationships: Record<string, number>;
}

// ------------------------------------------------------------------ platform

export interface StatusResponse {
  raf_version: string;
  core: string;
  database: string;
  workspace: string;
  products: { total: number; available: number };
  data: Record<string, number>;
  findings_by_severity: Partial<Record<Severity, number>>;
  oracle_provider: string | null;
}

export type ProductStatus = 'STABLE' | 'BETA' | 'ALPHA' | 'EXPERIMENTAL' | 'DISABLED' | 'UNAVAILABLE';

export interface ProductInfo {
  name: string;
  display_name: string;
  version: string;
  /** One of {@link ProductStatus}; typed as string because plugins may report others. */
  status: string;
  maturity: string;
  description: string;
  category: string;
  depends_on: string[];
  commands: string[];
  optional: boolean;
  enabled: boolean;
  available: boolean;
  source: string;
  trusted: boolean;
  unavailable_reason: string | null;
  permissions: string[];
  docs: string | null;
  ui: { route?: string; nav?: string | null } & Metadata;
  dependents?: string[];
}

export interface ConfigEntry {
  key: string;
  value: unknown;
  origin: string;
  secret: boolean;
  description: string;
}

export interface WorkspaceInfo {
  name: string;
  path: string;
  description: string;
  created_at: IsoTime | null;
  current: boolean;
}

export interface WorkspacesResponse {
  items: WorkspaceInfo[];
  current: string;
}

export type VersionInfo = Record<string, string>;

export type JobStatus = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';

export interface Job {
  id: string;
  kind: string;
  title: string;
  status: JobStatus;
  progress: number;
  message: string | null;
  params: Metadata;
  result: Metadata | null;
  error: Metadata | null;
  actor: string;
  cancel_requested: boolean;
  created_at: IsoTime;
  started_at: IsoTime | null;
  finished_at: IsoTime | null;
  duration_ms: number | null;
}

export interface Snapshot {
  id: string;
  name: string;
  source: string;
  description: string;
  created_at: IsoTime;
  stats: Metadata;
  content_hash: string;
}

export interface AuditEntry {
  id: number;
  ts: IsoTime;
  actor: string;
  interface: string;
  command: string;
  workspace: string;
  operation: string;
  affected: string[];
  result: string;
  details: Metadata;
  entry_hash: string;
}

/** `POST /analyze` (multipart). The analysis record shape is product-defined. */
export interface AnalyzeResponse {
  analysis?: Metadata & { id?: string; detected_type?: string; suggestions?: string[] };
  job?: Partial<Job> & Metadata;
}

// ------------------------------------------------------------------ graph

export interface Scope {
  kind: string;
  id: string;
  label: string;
  job_ids?: string[];
}

export interface GraphNode {
  id: string;
  type: string;
  name: string;
  depth: number;
  criticality: string | null;
  tags: string[];
  synthetic: boolean;
  first_seen: IsoTime | null;
  last_seen: IsoTime | null;
  metadata: Metadata;
  missing: boolean;
}

export interface GraphEdge {
  id: string;
  type: string;
  source: string;
  target: string;
  confidence: number;
  first_seen: IsoTime | null;
  last_seen: IsoTime | null;
  valid_to: IsoTime | null;
  observations: number;
  metadata: Metadata;
}

export interface Subgraph {
  roots: string[];
  nodes: GraphNode[];
  edges: GraphEdge[];
  truncated: boolean;
  at: IsoTime | null;
  depth: number;
  scope?: Scope;
}

export interface PathHop {
  source: string;
  source_name: string;
  target: string;
  target_name: string;
  relationship: GraphEdge;
  forward: boolean;
}

export interface PathResult {
  source: string;
  target: string;
  found: boolean;
  directed: boolean;
  hops: PathHop[];
  at: IsoTime | null;
  length: number;
}

// ------------------------------------------------------------------ timeline

export interface CountGroup {
  key: string | null;
  count: number;
}

export interface HistogramBucket {
  start: IsoTime;
  count: number;
}

export interface TimelineResponse {
  scope: Scope;
  filters: string[];
  total: number;
  first: IsoTime | null;
  last: IsoTime | null;
  items: RafEvent[];
  names: Record<string, string>;
  next_cursor: string | null;
  group_by: string | null;
  groups: CountGroup[];
  histogram: HistogramBucket[];
}

export interface EventsResponse {
  items: RafEvent[];
  next_cursor: string | null;
  total: number | null;
}

// ------------------------------------------------------------------ trace

export interface TraceProvenance {
  source?: string | null;
  record?: string | null;
  parser?: string | null;
  raw_reference?: string | null;
  event_id?: string | null;
}

export type TraceKind = 'observed' | 'correlated';

export interface TraceLink {
  cause: string;
  effect: string;
  relation: string;
  /** {@link TraceKind}: `observed` or `correlated`. */
  kind: string;
  confidence: number;
  timestamp: IsoTime;
  event_id: string | null;
  explanation: string;
  provenance: TraceProvenance;
  /** `backward` or `forward`. */
  direction: string;
  step: number;
  parent_step: number | null;
  corroborated_by: TraceProvenance[];
}

export interface TraceNode {
  id: string;
  name: string;
  type: string;
  depth: number;
  direction: string;
}

export interface TraceResult {
  subject: TraceNode;
  nodes: TraceNode[];
  backward: TraceLink[];
  forward: TraceLink[];
  chain: TraceLink[];
  notes: string[];
}

// ------------------------------------------------------------------ replay

export interface ReplaySession {
  user: string;
  host: string;
  since?: IsoTime;
  source?: string | null;
  method?: string | null;
}

export interface ReplaySessionRef {
  user: string;
  host: string;
}

export interface ReplayProcess {
  process: string;
  host?: string | null;
  user?: string | null;
  since?: IsoTime;
  command_line?: string | null;
}

export interface ReplayFlow {
  at: IsoTime;
  source: string | null;
  destination: string | null;
  port?: number | string | null;
  bytes_out?: number | string | null;
  protocol?: string | null;
}

export interface ReplayFileActivity {
  at: IsoTime;
  operation: string;
  file: string | null;
  actor: string | null;
}

export interface ReplayIdentityChange {
  at: IsoTime;
  change: string;
  actor: string | null;
  target: string | null;
  detail: Metadata;
}

export interface ReplayAlert {
  at: IsoTime;
  event_id?: string;
  /** A {@link Severity} value. */
  severity: string;
  message: string;
  target: string | null;
}

export interface ReplayStep {
  index: number;
  timestamp: IsoTime;
  event_id: string;
  event_type: string;
  severity: Severity;
  summary: string;
  actor: string | null;
  target: string | null;
  added_objects: string[];
  added_relationships: string[];
  removed_relationships: string[];
  sessions_opened: ReplaySession[];
  sessions_closed: ReplaySessionRef[];
  processes_started: ReplayProcess[];
  processes_ended: string[];
  flows: ReplayFlow[];
  files: ReplayFileActivity[];
  identity_changes: ReplayIdentityChange[];
  alerts: ReplayAlert[];
}

export interface ReplayObjectInfo {
  name: string;
  type: string;
  criticality: string | null;
}

export interface ReplayRelationshipInfo {
  type: string;
  source: string;
  target: string;
}

export interface ReplayTimeline {
  scope: Scope;
  title: string;
  start: IsoTime;
  end: IsoTime;
  objects: Record<string, ReplayObjectInfo>;
  relationships: Record<string, ReplayRelationshipInfo>;
  initial_objects: string[];
  initial_relationships: string[];
  steps: ReplayStep[];
  checkpoints: Array<{ index: number; state_hash: string }>;
  final_state_hash: string;
  excluded_events?: number;
  notes: string[];
}

// ------------------------------------------------------------------ exposure

export interface RiskAssessment {
  level: string;
  score: number;
  factors: ScoreFactor[];
}

export interface Reach {
  id: string;
  name: string;
  type: string;
  depth: number;
  confidence: number;
  mode: string;
  criticality: string | null;
}

export interface BlastHop {
  source: string;
  source_name?: string;
  target: string;
  target_name?: string;
  relationship_type: string;
  relationship_id?: string | null;
  why: string;
  confidence: number;
}

export interface BlastResult {
  target: { id: string; name: string; type: string };
  reachable_assets: number;
  critical_assets: number;
  privileged_paths: number;
  max_depth: number;
  direct: Reach[];
  indirect: Reach[];
  identity_propagation: string[];
  network_propagation: string[];
  trust_propagation: string[];
  risk: RiskAssessment;
  primary_path: BlastHop[];
}

export interface ExposureObjectRef {
  id: string;
  name: string;
  type: string;
  criticality: string | null;
}

export interface ExposureItem {
  object: ExposureObjectRef;
  score: number;
  level: string;
  factors: ScoreFactor[];
  entry_points: unknown[];
  vulnerabilities: Array<{ id: string; cvss?: number | null }>;
}

export interface ExposureResponse {
  items: ExposureItem[];
}

/** `GET /iam/path`: privilege paths with per-hop explanations (shape partially documented). */
export interface IamPathResponse {
  source?: string;
  target?: string;
  found?: boolean;
  paths?: Array<{ hops?: BlastHop[]; length?: number; privileged?: boolean; score?: number } & Metadata>;
  hops?: BlastHop[];
}

// ------------------------------------------------------------------ evidence

export interface CustodyEntry {
  at?: IsoTime;
  timestamp?: IsoTime;
  actor?: string;
  action?: string;
  note?: string | null;
  sha256?: string | null;
}

export interface EvidenceItem {
  id: string;
  name?: string;
  path?: string;
  filename?: string;
  sha256?: string;
  size?: number;
  media_type?: string;
  acquired_at?: IsoTime;
  added_at?: IsoTime;
  case?: string;
  objects?: string[];
  custody?: CustodyEntry[];
  chain?: CustodyEntry[];
  metadata?: Metadata;
}

export interface EvidenceCase {
  name: string;
  title?: string | null;
  created_at?: IsoTime;
  status?: string;
  item_count?: number;
  items?: EvidenceItem[];
  description?: string;
}

export interface EvidenceVerifyResult {
  verified: boolean;
  items: Array<{ id: string; ok: boolean; expected?: string | null; actual?: string | null }>;
}

// ------------------------------------------------------------------ ranges / labs

export interface RangeInfo {
  name: string;
  preset?: string | null;
  seed?: number | null;
  status?: string;
  state?: string;
  created_at?: IsoTime;
  description?: string;
  stats?: Metadata;
}

export interface LabStatus {
  backend: string;
  available: boolean;
  reason: string | null;
}

export interface LabInfo {
  name: string;
  status?: string;
  state?: string;
  backend?: string;
  template?: string;
  created_at?: IsoTime;
  description?: string;
}

// ------------------------------------------------------------------ lens / oracle

export interface LensResponse {
  scope?: Scope;
  total: number;
  items: RafEvent[];
  groups?: CountGroup[];
  histogram?: HistogramBucket[];
  involved?: Array<{ type: string; count: number }>;
  top_objects?: Array<{ id: string; name?: string; type?: string; count?: number }>;
  names?: Record<string, string>;
}

export interface OracleCitation {
  id: string;
  label: string;
}

export interface OracleAnswer {
  answer: string;
  provider: string;
  mode: string;
  citations: OracleCitation[];
  invalid_references: string[];
  facts: Array<{ key: string; text: string; refs: string[] }>;
  suggestions: string[];
}

export type OracleStatus = Metadata;
