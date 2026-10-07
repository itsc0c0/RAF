/**
 * Types for the R$F HTTP API (`/api/v1`), following docs/api.md and the JSON observed from a running
 * `raf serve` (demo workspace).
 *
 * Every string in these payloads is untrusted data (imported logs, file names, user-controlled
 * metadata): it is rendered as text only. Shapes for products that are still being implemented
 * (blast, exposure, iam, evidence, ranges, lens) mark undocumented fields optional and the UI reads
 * them defensively.
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

// ------------------------------------------------------------------ analyses

/** `ok`, `skipped` or `failed` (typed as string: future pipelines may report others). */
export type AnalysisStepStatus = 'ok' | 'skipped' | 'failed';

export interface AnalysisStep {
  name: string;
  /** Product that ran the step (`timeline`, `graph`, `iam`...); null for core steps. */
  product: string | null;
  status: string;
  detail: string;
  duration_ms: number | null;
  stats: Metadata;
}

/**
 * `POST /analyze` (multipart) and `GET /analyses[/{id}]`. The upload response carries every field;
 * stored records omit `detected_label` / `detection` / `incidents` (the label lives in
 * `stats.detected_label`) and only the detail route adds `job_ids`.
 */
export interface AnalysisRecord {
  id: string;
  /** Sanitized upload name (never a server path). */
  input: string;
  input_name?: string;
  input_sha256: string;
  detected_type: string;
  detected_label?: string | null;
  detection?: string[] | null;
  /** `completed`, `partial` or `failed`. */
  status: string;
  steps: AnalysisStep[];
  stats: Metadata;
  suggestions: string[];
  job_id: string | null;
  job_ids?: string[];
  incidents?: string[];
  created_at: IsoTime;
  duration_ms?: number | null;
}

export interface AnalysisList {
  items: AnalysisRecord[];
  total: number;
}

// ------------------------------------------------------------------ diff

export interface DiffChange {
  category: string;
  /** `added`, `removed` or `changed`. */
  change: string;
  /** `object`, `relationship` or `finding`. */
  item_kind: string;
  item_id: string;
  label: string;
  /** `HIGH`, `MEDIUM` or `LOW`. */
  importance: string;
  reason: string;
  details: Metadata;
}

export interface DiffCounts {
  added: number;
  removed: number;
  changed: number;
}

/** `GET /diff?a=&b=&category=&limit=`: `summary`/`importance` always cover every change. */
export interface DiffResult {
  a: string;
  b: string;
  generated_at: IsoTime;
  summary: Record<string, DiffCounts>;
  importance: Record<string, number>;
  totals: Record<string, number>;
  changes: DiffChange[];
  truncated?: boolean;
}

// ------------------------------------------------------------------ ghost

/** `GET /ghost/models` items: a model without its operations log (`ops_count` instead of `ops`). */
export interface GhostModelSummary {
  name: string;
  base_snapshot: string;
  base_label: string;
  parent: string | null;
  ops_count: number;
  created_at: IsoTime;
  updated_at: IsoTime;
  description: string;
}

export interface GhostAddedRelationship {
  source: string;
  type: string;
  target: string;
  metadata: Metadata;
}

export interface GhostAddedObject {
  id: string;
  type: string;
  name: string;
  metadata: Metadata;
  tags: string[];
}

export interface GhostOpEffects {
  removed_relationships: string[];
  added_relationships: GhostAddedRelationship[];
  added_objects: GhostAddedObject[];
  /** Object ID -> replaced top-level metadata. */
  patched_objects: Record<string, Metadata>;
}

export interface GhostOp {
  op: string;
  arg: string;
  summary: string;
  explanation: string[];
  effects: GhostOpEffects;
  applied_at: IsoTime;
}

/** `GET /ghost/models/{name}` (full model: `base_label`, operations log). */
export interface GhostModel {
  name: string;
  base_snapshot: string;
  base_label: string;
  parent: string | null;
  description: string;
  created_at: IsoTime;
  updated_at: IsoTime;
  ops: GhostOp[];
}

export interface GhostOperationInfo {
  op: string;
  /** Argument format, e.g. `A:B`. */
  argument: string;
  effect: string;
}

/** `attack_paths`, `critical_paths`, `reachable_assets`, `entry_points`, `exposed_critical_assets`. */
export type ExposureMetrics = Record<string, number>;

export interface GhostStateSummary {
  label: string;
  metrics: ExposureMetrics;
  levels: Record<string, number>;
  /** User ID -> number of high/critical assets the user can control. */
  user_control: Record<string, number>;
}

export interface AssetEntryPoint {
  id: string;
  name: string;
  kind: string;
  hops: number;
  path: string[];
}

/** One asset assessment of `GET /ghost/models/{name}/simulate` (exposure model `raf-risk/1.0`). */
export interface AssetExposure {
  object: ExposureObjectRef;
  score: number;
  level: string;
  factors: ScoreFactor[];
  methodology?: string;
  internet?: string | null;
  entry_points?: AssetEntryPoint[];
  vulnerabilities?: Array<{ id: string; name?: string; cvss?: number | null; summary?: string } & Metadata>;
  controllers?: Array<{ id: string; name?: string; type?: string; confidence?: number } & Metadata>;
  stepping_stone_to?: Array<{ id: string; name?: string; confidence?: number; why?: string[] } & Metadata>;
}

export interface GhostSimulation {
  summary: GhostStateSummary;
  items: AssetExposure[];
}

export interface GhostAssetChange {
  id: string;
  name: string;
  before: { score: number; level: string } | null;
  after: { score: number; level: string } | null;
}

export interface GhostUserChange {
  id: string;
  name: string;
  before: number;
  after: number;
  lost: string[];
  gained: string[];
}

export interface GhostComparison {
  a: GhostStateSummary;
  b: GhostStateSummary;
  delta: ExposureMetrics;
  assets: GhostAssetChange[];
  users: GhostUserChange[];
  relationships_removed?: number;
  relationships_added?: number;
  a_metrics?: ExposureMetrics;
  b_metrics?: ExposureMetrics;
}

export interface GhostOpResult {
  model: GhostModel;
  applied: GhostOp[];
}

export interface GhostUndoResult {
  model: GhostModel;
  removed: GhostOp;
}

// ------------------------------------------------------------------ policy

export interface PolicyRule {
  id: string;
  policy: string;
  order: number;
  /** `allow` or `deny`. */
  effect: string;
  sources: string[];
  destinations: string[];
  ports: string[];
  actions: string[];
  description: string;
  enabled: boolean;
  metadata: Metadata;
}

export interface Policy {
  id: string;
  name: string;
  /** `network` or `identity`. */
  domain: string;
  /** `first-match` or `deny-overrides`. */
  evaluation: string;
  default: string;
  revision: string | null;
  description: string;
  source: string | null;
  scope: string[];
  rules: PolicyRule[];
  object_id?: string;
  rule_count?: number;
  digest?: string;
}

export interface PolicyAnalysisEntry {
  id: string;
  object_id: string;
  name: string;
  domain: string;
  evaluation: string;
  default: string;
  revision: string | null;
  rules: number;
  active_rules: number;
  findings: number;
  digest: string;
  source: string | null;
}

/** `POST /policy/analyze?persist=` */
export interface PolicyAnalysis {
  policies: PolicyAnalysisEntry[];
  findings: Finding[];
  by_rule: Record<string, number>;
  warnings: string[];
  workspace_aware?: boolean;
}

export interface PolicyEndpoint {
  id: string;
  name: string;
  type: string;
  known: boolean;
}

export interface PolicyRuleDecision {
  policy: string;
  /** null = the policy default. */
  rule: string | null;
  effect: string;
  ports: string[];
  actions: string[];
  summary: string;
  description: string;
}

export interface PolicyPartVerdict {
  /** `network` or `identity`. */
  part: string;
  policy: string;
  decision: string;
  source?: string | null;
  target?: string | null;
  allowed_ports: string[];
  decisions: PolicyRuleDecision[];
  preempted: PolicyRuleDecision[];
  explanation: string[];
}

export interface PolicyIndirectPath {
  pivot: string;
  pivot_name: string;
  legs: Array<{ source: string; target: string; ports: string[]; rules: string[] }>;
  summary: string;
}

/** `POST /policy/evaluate`: the decision with the policy chain that caused it. */
export interface PolicyEvaluation {
  subject: PolicyEndpoint;
  target: PolicyEndpoint;
  verb: string;
  action: string | null;
  requested_ports: string[];
  /** `allow`, `deny` or `not-evaluated`. */
  decision: string;
  reason: string;
  parts: PolicyPartVerdict[];
  network_sources: string[];
  indirect: PolicyIndirectPath[];
  notes: string[];
}

export interface PolicyEvaluateRequest {
  subject?: string;
  source?: string;
  target: string;
  action?: string;
  port?: string;
}

/** Format of a policy document sent to `POST /policy/check` (raf-policy/1 and AWS-style JSON are `json`). */
export type PolicyFormat = 'json' | 'yaml' | 'csv' | 'iptables' | 'nftables';

export interface PolicyCheckRequest {
  document: string;
  format: PolicyFormat;
  /** Principal for AWS-style statements that name none. */
  principal?: string;
  /** iptables-save or nftables: the host the rules belong to (names the policies and their `host:` scope). */
  host?: string;
}

/** A normalized policy document: one file or revision. */
export interface PolicySet {
  /** The document's own name; otherwise derived from `source`. */
  name: string;
  /** Detected format: `raf-policy/1`, `aws-iam` or `csv-firewall`. */
  format: string;
  revision: string | null;
  /** `request` for documents sent to the API. */
  source: string | null;
  policies: Policy[];
  warnings: string[];
}

/** `POST /policy/check`: the normalized document and its analysis. Nothing is stored. */
export interface PolicyCheckResult {
  set: PolicySet;
  /** `warnings` already include the document's own warnings (`set.warnings`). */
  analysis: PolicyAnalysis;
}

export interface PolicyRuleChange {
  policy: string;
  rule: string;
  /** `added`, `removed`, `modified` or `moved`. */
  change: string;
  /** `access-expanded`, `access-reduced` or `changed`. */
  impact: string;
  /** Changed rule fields (`effect`, `sources`, `destinations`, `ports`, `actions`, `enabled`, `position`). */
  fields: Record<string, { before: unknown; after: unknown }>;
  /** The rule's summary in each revision (null where the rule does not exist). */
  before: string | null;
  after: string | null;
}

export interface PolicyDefaultChange {
  policy: string;
  before: string;
  after: string;
}

/** `GET /policy/diff?before=&after=`: two stored revisions (`current` or snapshot names; files are CLI-only). */
export interface PolicyDiff {
  before: string;
  after: string;
  policies_added: string[];
  policies_removed: string[];
  defaults_changed: PolicyDefaultChange[];
  changes: PolicyRuleChange[];
  /** Analysis findings of `after` that `before` does not have, and the reverse (computed, not stored). */
  findings_introduced: Finding[];
  findings_resolved: Finding[];
  /** How many rule changes grant more access (`impact: access-expanded`). */
  access_expanded: number;
}

// ------------------------------------------------------------------ protocol

export interface ProtocolUpload {
  /** 32 hex characters (first half of the SHA-256). */
  id: string;
  name: string;
  size: number;
  sha256: string;
}

/** `GET /protocol/uploads` item: the upload's record and when it was stored (never a server path). */
export interface StoredUpload extends ProtocolUpload {
  uploaded_at: IsoTime;
}

/** `GET /protocol/uploads?limit=`: newest first; `total` counts every complete upload of the workspace. */
export interface ProtocolUploadList {
  items: StoredUpload[];
  total: number;
}

export interface CaptureFile {
  name: string;
  path: string | null;
  size: number;
  sha256: string | null;
  format: string;
  version: string | null;
  byte_order?: string | null;
  snaplen?: number | null;
  link_types: string[];
  interfaces?: Array<{ index: number; link_type_name: string; timestamp_resolution?: string } & Metadata>;
}

export interface CapturePackets {
  total: number;
  matched: number;
  bytes: number;
  first: IsoTime | null;
  last: IsoTime | null;
  duration_s: number | null;
  malformed: number;
}

export interface CaptureFlow {
  id: number;
  protocol: string;
  client: string;
  client_port: number | null;
  server: string;
  server_port: number | null;
  server_reason: string;
  app: string;
  app_evidence: string;
  packets: number;
  packets_out: number;
  packets_in: number;
  bytes_out: number;
  bytes_in: number;
  payload_out: number;
  payload_in: number;
  first: IsoTime | null;
  last: IsoTime | null;
  duration_s: number | null;
  tcp_flags: string[];
  community_id: string | null;
}

export interface CaptureDns {
  name: string;
  type: string;
  answers: string[];
  rcodes: string[];
  queries: number;
  responses: number;
  clients: string[];
  servers: string[];
}

export interface CaptureTls {
  sni: string | null;
  servers: string[];
  alpn: string[];
  versions: string[];
  ciphers: string[];
  handshakes: number;
  clients: string[];
  flows: number[];
  encrypted_client_hello: boolean;
}

export interface CaptureHttp {
  host: string | null;
  servers: string[];
  requests: number;
  methods: string[];
  paths: string[];
  user_agents: string[];
  statuses: number[];
  clients: string[];
  flows: number[];
}

export interface CaptureFilters {
  protocol: string | null;
  host: string | null;
  port: number | null;
  flow: number | null;
  from: IsoTime | null;
  to: IsoTime | null;
}

/** `POST /protocol/inspect` (upload) and `GET /protocol/inspect?upload=`. */
export interface CaptureSummary {
  upload: ProtocolUpload;
  file: CaptureFile;
  filters: CaptureFilters;
  packets: CapturePackets;
  protocols: Array<{ protocol: string; packets: number; bytes: number }>;
  flows: CaptureFlow[];
  flows_total: number;
  dns: CaptureDns[];
  dns_total: number;
  tls: CaptureTls[];
  tls_total: number;
  http: CaptureHttp[];
  http_total: number;
  warnings: string[];
  truncated: boolean;
  limit_reached: boolean;
}

export interface CaptureFlows {
  upload: ProtocolUpload;
  file: CaptureFile;
  packets: CapturePackets;
  flows: CaptureFlow[];
  flows_total: number;
  sort: string;
  warnings: string[];
  truncated: boolean;
  limit_reached: boolean;
}

export interface PacketField {
  name: string;
  /** String, number, list or object, as decoded. */
  value: unknown;
  explanation: string;
}

export interface PacketLayer {
  name: string;
  summary: string;
  /** Why the layer could not be decoded completely (fields decoded before the problem are kept). */
  malformed: string | null;
  fields: PacketField[];
  children: PacketLayer[];
}

/** `GET /protocol/packet?upload=&n=` */
export interface PacketDetail {
  upload: ProtocolUpload;
  file: CaptureFile;
  number: number;
  timestamp: IsoTime | null;
  captured_length: number;
  original_length: number;
  interface: number | null;
  link_type: string | null;
  flow_id: number | null;
  flow: string | null;
  protocols: string[];
  info: string;
  tree: string[];
  /** Root layer (link layer); decoded layers nest in `children`. */
  layers: PacketLayer | null;
  malformed: string[];
}

// ------------------------------------------------------------------ vault

/** `GET /vault/secrets`: secret objects, always redacted and fingerprinted. */
export interface VaultSecret {
  id: string;
  name: string;
  rule: string;
  kind: string;
  severity: string;
  /** Redacted by the API (`ghp****OL8d`); the value itself is never stored or returned. */
  redacted: string;
  fingerprint: string;
  host: string | null;
  path: string | null;
  relative_path: string | null;
  line: number | null;
  confidence: number;
  first_seen: IsoTime | null;
  last_seen: IsoTime | null;
  removed: boolean;
}

export interface VaultRule {
  id: string;
  title: string;
  severity: string;
  confidence: number;
  /** Documented precision of the detector (`high`, `medium`, `low`). */
  precision: string;
  description: string;
  recommendation: string;
}

// ------------------------------------------------------------------ surface (imported inventories only)

/** An authorized scope entry: explicit authorization to treat matching assets as the organization's. */
export interface SurfaceScopeEntry {
  target: string;
  /** `domain`, `cidr`, `ip` or `cloud_account`. */
  kind: string;
  owner: string | null;
  /** Authorization reference (free text, e.g. a ticket). */
  authorization: string | null;
  added_at: IsoTime;
}

/** Certificate state at the summary's reference time. */
export type CertificateState = 'valid' | 'expiring' | 'expired' | 'unknown';

export interface SurfaceTreeService {
  id: string;
  name: string;
  endpoint: string;
  port: number | null;
  transport: string;
  product: string | null;
  internet_facing: boolean;
  status: string;
}

export interface SurfaceTreeCertificate {
  id: string;
  name: string;
  endpoint: string;
  not_after: IsoTime | null;
  /** A {@link CertificateState}. */
  state: string;
  /** Whole days left (negative when expired); null when unknown. */
  days_remaining: number | null;
}

export interface SurfaceTreeCloud {
  id: string;
  name: string;
  kind: string | null;
  provider: string | null;
  public: boolean;
}

/** A DNS record of a tree node (A/AAAA records add hosts and scope, CNAMEs add status and cloud assets). */
export interface SurfaceTreeRecord {
  type: string;
  value: string;
  /** `external` or `internal`. */
  view: string;
  target: string;
  hosts?: string[];
  scope?: string;
  internal?: boolean;
  status?: string;
  services?: SurfaceTreeService[];
  certificates?: SurfaceTreeCertificate[];
  cloud?: SurfaceTreeCloud[];
}

export interface SurfaceTreeNode {
  id: string;
  name: string;
  /** `in`, `out` or `unknown` (no scope configured). */
  scope: string;
  scope_entry: string | null;
  owners: string[];
  /** Owners recorded for out-of-scope names: shown as claims, never accepted. */
  claimed_owners: string[];
  status: string;
  inventoried: boolean;
  records: SurfaceTreeRecord[];
  txt: string[];
  children: SurfaceTreeNode[];
  findings: number;
}

export interface SurfaceAsset {
  id: string;
  /** `domain`, `ip`, `service`, `certificate` or `cloud_asset`. */
  kind: string;
  name: string;
  /** False: a reference (seen only as a DNS answer or in a certificate), never judged on its own. */
  asset: boolean;
  scope: string;
  scope_entry: string | null;
  scope_via: string | null;
  owners: string[];
  owner_via: string | null;
  claimed_owners: string[];
  status: string;
  sources: string[];
  internet_facing: boolean;
  criticality: string | null;
  summary: string;
  details: Metadata;
  findings: number;
}

/** `GET /surface/summary` (same document as `raf surface show --json`). */
export interface SurfaceSummary {
  workspace: string;
  scope_configured: boolean;
  scope: SurfaceScopeEntry[];
  assets: number;
  references: number;
  by_kind: Record<string, number>;
  in_scope: number;
  out_of_scope: number;
  unscoped: number;
  internet_facing: number;
  owners: string[];
  reference_time: IsoTime;
  reference_source: string;
  findings_open: number;
  findings_by_severity: Partial<Record<Severity, number>>;
  findings_by_rule: Record<string, number>;
  top_findings: Array<{ id: string; title: string; severity: string; rule: string }>;
  tree: SurfaceTreeNode[];
  /** In-scope addresses no name in the tree reaches. */
  addresses: SurfaceAsset[];
  cloud: SurfaceAsset[];
  /** Out-of-scope addresses, services and cloud assets. */
  outside: SurfaceAsset[];
  truncated: boolean;
  notes: string[];
}

/** `POST /surface/analyze?persist=` */
export interface SurfaceAnalysis {
  generated_at: IsoTime;
  reference_time: IsoTime;
  reference_source: string;
  expiring_days: number;
  scope_entries: number;
  assets: number;
  in_scope: number;
  out_of_scope: number;
  findings: Finding[];
  by_rule: Record<string, number>;
  by_severity: Partial<Record<Severity, number>>;
  created: number;
  updated: number;
  resolved: number;
  persisted: boolean;
  notes: string[];
}

/** `POST /surface/import` (inventory sent as the request body). */
export interface SurfaceImportResult {
  source: string;
  path: string | null;
  sha256: string;
  size: number;
  format: string;
  organization: string | null;
  as_of: IsoTime | null;
  records: number;
  accepted: number;
  rejected: number;
  by_kind: Record<string, number>;
  rejections: Array<{ record: string; reason: string; hint: string | null; source?: string | null }>;
  warnings: string[];
  scope_declared: number;
  scope_applied: boolean;
  scope_changes: Array<{ target: string; kind: string; result: string; detail: string | null }>;
  job_id: string | null;
  native_records?: number;
  objects_created?: number;
  objects_updated?: number;
  relationships_created?: number;
  relationships_updated?: number;
}

export interface SurfaceScopeResult {
  entry: SurfaceScopeEntry;
  /** `added`, `replaced`, `unchanged` or `removed`. */
  result: string;
}

// ------------------------------------------------------------------ dependency

export interface DependencyProject {
  id: string;
  name: string;
  path?: string | null;
  source: string;
  ecosystems: string[];
  dependencies: number;
  packages: number;
  direct: number;
  open_findings: number;
  last_scan: IsoTime | null;
}

export interface DependencyPackage {
  id: string;
  ecosystem: string;
  name: string;
  version: string | null;
  direct?: boolean;
  scope?: string;
  /** Vulnerability object IDs (`vulnerability:<advisory>`). */
  vulnerabilities?: string[];
  purl?: string;
}

/** `GET /dependency/projects/{ref}/graph` */
export interface DependencyGraph {
  project: { id: string; name: string; path?: string | null };
  packages: DependencyPackage[];
  edges: Array<{ source: string; target: string; type: string }>;
}

export interface VulnerableAdvisory {
  id: string;
  object_id: string;
  summary: string;
  severity: string;
  severity_rank: number;
  cvss: number | null;
  aliases: string[];
  fixed: string[];
  /** Why the version matches, e.g. `2.2.0 is in the affected range >=2.0.0, <2.3.1`. */
  reason: string;
  /** `exact`: an installed version is affected; `constraint`: only a declared range admits affected versions. */
  basis?: 'exact' | 'constraint';
  constraint?: string | null;
  confidence?: number;
  since: IsoTime | null;
}

export interface VulnerablePackage {
  /** For `constraint` matches this is the declared dependency (`version` is null). */
  package: DependencyPackage & Metadata;
  basis?: 'exact' | 'constraint';
  confidence?: number;
  advisories: VulnerableAdvisory[];
  projects: string[];
}

export interface Advisory {
  id: string;
  summary: string;
  severity: string;
  severity_source: string | null;
  cvss: number | null;
  aliases: string[];
  withdrawn: IsoTime | null;
  affected: Array<{ ecosystem: string; name: string; ranges: string; fixed: string[] }>;
  object_id?: string;
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

/** `GET /lab/status?backend=` */
export interface LabStatus {
  backend: string;
  available: boolean;
  reason: string | null;
  version?: string | null;
}

export interface LabMount {
  /** Resolved host path (validated on the server, mounted read-only). */
  source: string;
  /** Always `/lab/input/<basename>`. */
  target: string;
  read_only: boolean;
}

/** A lab definition with its last recorded (or live) container state. */
export interface Lab {
  name: string;
  /** `defined` (no container), the runtime state (`created`, `running`, `exited`...) or `conflict`. */
  state: string;
  /** True when `state` was just observed from the backend; false = last recorded state. */
  live: boolean;
  image: string;
  /** `none` (isolated, default) or `bridge` (outbound access). */
  network: string;
  allow_outbound: boolean;
  mounts: LabMount[];
  memory: string;
  cpus: string;
  pids_limit: number;
  /** `1000:1000`, or `0:0` for root labs. */
  user: string;
  root: boolean;
  /** `auto`, `docker` or `podman`. */
  backend: string;
  container: string;
  container_id: string | null;
  description: string;
  created_at: IsoTime | null;
  updated_at: IsoTime | null;
  state_at: IsoTime | null;
  note?: string | null;
  /** Detail and create responses: the exact container command (`docker create ...`). */
  container_args?: string[];
  /** Lifecycle (start/stop) responses. */
  changed?: boolean;
  created?: boolean;
}

export interface LabList {
  items: Lab[];
  total: number;
  /** Stored definitions that failed validation (they can only be removed with `forget`). */
  invalid?: string[];
}

/** `POST /lab/labs`: unknown fields are rejected (422); flags must be JSON booleans. */
export interface LabCreateRequest {
  name: string;
  image?: string;
  mounts?: string[];
  allow_outbound?: boolean;
  memory?: string;
  cpus?: string;
  root?: boolean;
  description?: string;
  backend?: string;
}

export interface LabDestroyResult {
  name: string;
  destroyed: boolean;
  container: string;
  container_removed: boolean;
  note?: string | null;
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
  /** Object type, or `event` / `finding` / `relationship`. */
  type?: string;
}

/** A fact Oracle retrieved from R$F data. `untrusted` holds verbatim imported text (data, not R$F wording). */
export interface OracleFact {
  key: string;
  kind?: string;
  text: string;
  refs: string[];
  source?: string;
  untrusted?: string[];
}

/** `POST /oracle/ask` */
export interface OracleAnswer {
  question?: string;
  answer: string;
  provider: string;
  /** `builtin`, `model` or `builtin-fallback`. */
  mode: string;
  model?: string | null;
  intent?: string;
  entities?: Array<{ id: string; name: string; type: string }>;
  citations: OracleCitation[];
  /** IDs the answer mentioned that are not in the retrieved R$F data. */
  invalid_references: string[];
  facts: OracleFact[];
  suggestions: string[];
  warnings?: string[];
  generated_at?: IsoTime;
  notice?: string;
}

/** `GET /oracle/status`: provider configuration and readiness (never the API key). */
export interface OracleStatus extends Metadata {
  provider?: string;
  enabled?: boolean;
  ready?: boolean;
  mode?: string;
  detail?: string;
  max_facts?: number;
  tools?: string;
  stores_answers?: boolean;
  base_url?: string;
  model?: string | null;
  loopback?: boolean;
  api_key_configured?: boolean;
  timeout_seconds?: number;
  warning?: string;
  data_leaves_host?: boolean;
}
