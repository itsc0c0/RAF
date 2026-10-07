import { useId, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  useFindings,
  usePolicies,
  usePolicyAnalyze,
  usePolicyCheck,
  usePolicyDiff,
  usePolicyEvaluate,
  useSnapshots,
} from '../../api/hooks';
import type {
  Finding,
  Policy,
  PolicyAnalysis,
  PolicyCheckResult,
  PolicyDiff,
  PolicyEvaluation,
  PolicyFormat,
  PolicyPartVerdict,
  PolicyRule,
  PolicyRuleChange,
  PolicyRuleDecision,
  Snapshot,
} from '../../api/types';
import { Badge, type Tone } from '../../components/Badge';
import { Button } from '../../components/Button';
import { Chain } from '../../components/Chain';
import { KeyValueList, Mono } from '../../components/Data';
import { Field, Select, TextArea, TextInput } from '../../components/Form';
import { ConfirmDialog } from '../../components/Modal';
import { ObjectChip } from '../../components/ObjectChip';
import { Callout, Panel } from '../../components/Panel';
import { EmptyState, ErrorState, QueryView } from '../../components/States';
import { Table } from '../../components/Table';
import { useToast } from '../../components/Toast';
import { formatBytes, formatNumber, formatTimestamp, pluralize } from '../../lib/format';
import { routeTo } from '../../lib/routes';
import { ComputedFindingDrawer } from '../findings/FindingDetail';
import { FindingsTable } from '../findings/FindingsTable';
import {
  hostFromFileName,
  inferPolicyFormat,
  IPTABLES_SUFFIXES,
  isEmptyPolicyDiff,
  MAX_POLICY_DOCUMENT_BYTES,
  POLICY_FORMATS,
  ruleFieldText,
} from './policyModel';

const DECISION_TONES: Record<string, Tone> = { allow: 'good', deny: 'bad' };

/** Policy decision (`allow` / `deny` / `not-evaluated`) or rule effect, always labelled. */
export function DecisionBadge({ decision }: { decision: string }) {
  const value = decision.toLowerCase();
  return (
    <Badge tone={DECISION_TONES[value] ?? 'neutral'} outline={!(value in DECISION_TONES)}>
      {decision.toUpperCase()}
    </Badge>
  );
}

function List({ values }: { values: readonly string[] }) {
  return <span className="mono small break">{values.join(', ') || '—'}</span>;
}

function RulesTable({ policy }: { policy: Policy }) {
  const network = policy.domain === 'network';
  const rules = [...policy.rules].sort((a, b) => a.order - b.order);
  return (
    <Table<PolicyRule>
      caption={`Rules of ${policy.name}`}
      dense
      rows={rules}
      rowKey={(rule) => rule.id}
      empty={<span className="muted">No rules.</span>}
      columns={[
        { key: 'order', header: '#', align: 'right', width: '40px', render: (r) => r.order + 1 },
        {
          key: 'rule',
          header: 'Rule',
          render: (r) => (
            <span className="stack stack--tight">
              <Mono>{r.id}</Mono>
              {r.description ? <span className="small muted break">{r.description}</span> : null}
            </span>
          ),
        },
        {
          key: 'effect',
          header: 'Effect',
          render: (r) => (
            <span className="row">
              <DecisionBadge decision={r.effect} />
              {!r.enabled ? (
                <Badge tone="neutral" outline>
                  DISABLED
                </Badge>
              ) : null}
            </span>
          ),
        },
        {
          key: 'sources',
          header: network ? 'Sources' : 'Principals',
          render: (r) => <List values={r.sources} />,
        },
        {
          key: 'destinations',
          header: network ? 'Destinations' : 'Resources',
          render: (r) => <List values={r.destinations} />,
        },
        network
          ? { key: 'ports', header: 'Ports', render: (r: PolicyRule) => <List values={r.ports} /> }
          : { key: 'actions', header: 'Actions', render: (r: PolicyRule) => <List values={r.actions} /> },
      ]}
    />
  );
}

/** Policies (stored or from a checked document); a row selects the policy whose rules are shown. */
function PoliciesTable({
  policies,
  selected,
  onSelect,
  caption,
  findings,
}: {
  policies: readonly Policy[];
  selected: string;
  onSelect: (id: string) => void;
  caption: string;
  /** Analysis findings per policy ID (a checked document): shown instead of the Source column. */
  findings?: Readonly<Record<string, number>>;
}) {
  return (
    <Table<Policy>
      caption={caption}
      dense
      rows={policies}
      rowKey={(policy) => policy.id}
      selectedKey={selected}
      onRowClick={(policy) => onSelect(policy.id)}
      rowLabel={(policy) => `Show rules of ${policy.name}`}
      columns={[
        {
          key: 'name',
          header: 'Policy',
          render: (p) => (
            <span className="stack stack--tight">
              <strong className="break">{p.name}</strong>
              <Mono className="small muted">{p.id}</Mono>
            </span>
          ),
        },
        { key: 'domain', header: 'Domain', render: (p) => <span className="tag">{p.domain}</span> },
        {
          key: 'evaluation',
          header: 'Evaluation',
          render: (p) => <span className="small">{p.evaluation}</span>,
        },
        {
          key: 'default',
          header: 'Default',
          render: (p) => <DecisionBadge decision={p.default} />,
        },
        {
          key: 'revision',
          header: 'Revision',
          render: (p) => <Mono className="small">{p.revision ?? '—'}</Mono>,
        },
        {
          key: 'rules',
          header: 'Rules',
          align: 'right',
          render: (p) => formatNumber(p.rule_count ?? p.rules.length),
        },
        findings
          ? {
              key: 'findings',
              header: 'Findings',
              align: 'right',
              render: (p: Policy) => formatNumber(findings[p.id] ?? 0),
            }
          : {
              key: 'source',
              header: 'Source',
              render: (p: Policy) => <span className="small break">{p.source ?? '—'}</span>,
            },
      ]}
    />
  );
}

/** One policy's rules and how its evaluation strategy decides. */
function PolicyRulesPanel({ policy }: { policy: Policy }) {
  return (
    <Panel
      title={
        <span className="row row--wrap">
          <span className="break">{policy.name}</span>
          <span className="small muted">
            {policy.domain} · {policy.evaluation} · default {policy.default}
          </span>
        </span>
      }
      flush
      actions={policy.object_id ? <ObjectChip id={policy.object_id} /> : null}
    >
      {policy.description ? <p className="panel__pad small break">{policy.description}</p> : null}
      <RulesTable policy={policy} />
      <p className="panel__pad small muted">
        {policy.domain === 'network'
          ? 'Network policies: the first matching rule decides the still-undecided ports (first match wins).'
          : 'Access policies: an explicit deny overrides any allow; nothing granted means deny.'}
      </p>
    </Panel>
  );
}

export function PolicyList({
  selected,
  onSelect,
}: {
  selected: string | null;
  onSelect: (id: string) => void;
}) {
  const policies = usePolicies();
  return (
    <QueryView query={policies} feature="Policy">
      {(data) => {
        if (data.items.length === 0) {
          return (
            <Panel>
              <EmptyState title="No policies stored">
                <p>
                  Import network or access policies with <code>raf policy import FILE</code> or{' '}
                  <code>raf analyze FILE</code> (raf-policy/1, AWS-style JSON, CSV firewall exports).
                </p>
              </EmptyState>
            </Panel>
          );
        }
        const current = data.items.find((policy) => policy.id === selected) ?? data.items[0]!;
        return (
          <div className="stack">
            <Panel title="Policies" flush>
              <PoliciesTable
                caption="Stored policies"
                policies={data.items}
                selected={current.id}
                onSelect={onSelect}
              />
            </Panel>
            <PolicyRulesPanel policy={current} />
          </div>
        );
      }}
    </QueryView>
  );
}

/**
 * Findings of a policy analysis by rule, with its warnings. Findings of stored policies open the
 * findings drawer; computed ones (`recorded={false}`, e.g. a checked document) go to `onOpenFinding`.
 */
function AnalysisResult({
  analysis,
  recorded = true,
  selectedId = null,
  onOpenFinding,
}: {
  analysis: PolicyAnalysis;
  recorded?: boolean;
  selectedId?: string | null;
  onOpenFinding?: (finding: Finding) => void;
}) {
  const navigate = useNavigate();
  const rules = Object.entries(analysis.by_rule);
  return (
    <div className="stack">
      <div className="row row--wrap">
        {rules.length === 0 ? <span className="small muted">No problems found.</span> : null}
        {rules.map(([rule, count]) => (
          <span key={rule} className="tag">
            {rule} {count}
          </span>
        ))}
      </div>
      {analysis.warnings.length > 0 ? (
        <Callout tone="warn" title="Warnings">
          <ul className="stack stack--tight">
            {analysis.warnings.map((warning, index) => (
              <li key={index} className="break">
                {warning}
              </li>
            ))}
          </ul>
        </Callout>
      ) : null}
      <FindingsTable
        rows={analysis.findings}
        selectedId={selectedId}
        showProduct={false}
        recorded={recorded}
        empty="The analysis found no conflicting, shadowed, redundant or overly broad rules."
        onOpen={onOpenFinding ?? ((finding) => void navigate(routeTo.finding(finding.id)))}
      />
    </div>
  );
}

/** Recorded policy findings, plus a dry-run re-analysis (`persist=false`) and "record findings". */
export function PolicyAnalysisPanel() {
  const navigate = useNavigate();
  const recorded = useFindings({ product: 'policy', status: ['OPEN', 'ACKNOWLEDGED'], limit: 100 });
  const analyze = usePolicyAnalyze();
  const { notify } = useToast();
  const [confirming, setConfirming] = useState(false);
  const dryRun = analyze.data && analyze.variables === false ? analyze.data : null;
  return (
    <Panel
      title="Analysis findings"
      actions={
        <span className="row">
          <Button
            size="sm"
            icon="refresh"
            loading={analyze.isPending && analyze.variables === false}
            onClick={() => analyze.mutate(false)}
          >
            Analyze (dry run)
          </Button>
          <Button size="sm" variant="primary" icon="check" onClick={() => setConfirming(true)}>
            Analyze and record
          </Button>
        </span>
      }
    >
      <div className="stack">
        <p className="small muted">
          Overly broad, shadowed, redundant and conflicting rules, stale references and default-allow
          policies. A dry run changes nothing; recording upserts the findings and resolves those that no
          longer apply.
        </p>
        {analyze.isError ? <ErrorState title="Analysis failed" error={analyze.error} compact /> : null}
        {dryRun ? (
          <section className="stack stack--tight" aria-label="Dry-run analysis">
            <h4>Dry run · {pluralize(dryRun.findings.length, 'finding')}</h4>
            <AnalysisResult analysis={dryRun} />
          </section>
        ) : null}
        <section className="stack stack--tight" aria-label="Recorded policy findings">
          <h4>Recorded (open and acknowledged)</h4>
          <QueryView query={recorded} feature="Findings" compact>
            {(page) => (
              <FindingsTable
                rows={page.items}
                selectedId={null}
                showProduct={false}
                empty="No open policy findings are recorded."
                onOpen={(finding) => void navigate(routeTo.finding(finding.id))}
              />
            )}
          </QueryView>
        </section>
      </div>
      {confirming ? (
        <ConfirmDialog
          title="Analyze and record policy findings?"
          confirmLabel="Analyze and record"
          busy={analyze.isPending}
          onCancel={() => setConfirming(false)}
          onConfirm={() =>
            analyze.mutate(true, {
              onSuccess: (result) => {
                notify({
                  tone: 'good',
                  title: `Policy analysis recorded ${pluralize(result.findings.length, 'finding')}`,
                  description: result.warnings.join(' ') || undefined,
                });
                setConfirming(false);
              },
              onError: () => setConfirming(false),
            })
          }
        >
          <p>
            Findings are written to the workspace (audited as <code>policy.analyze</code>); earlier policy
            findings that no longer apply are resolved.
          </p>
        </ConfirmDialog>
      ) : null}
    </Panel>
  );
}

function DecisionLine({
  decision,
  preempted = false,
}: {
  decision: PolicyRuleDecision;
  preempted?: boolean;
}) {
  return (
    <li className="policy-decision">
      <span className="row row--wrap">
        <DecisionBadge decision={decision.effect} />
        <Mono>
          {decision.policy}
          {decision.rule ? `:${decision.rule}` : ' (default)'}
        </Mono>
        {decision.ports.length > 0 ? (
          <span className="small muted">ports {decision.ports.join(', ')}</span>
        ) : null}
        {decision.actions.length > 0 ? (
          <span className="small muted">actions {decision.actions.join(', ')}</span>
        ) : null}
        {preempted ? (
          <Badge tone="warn" outline title="Would have matched, but an earlier rule already decided">
            PRE-EMPTED
          </Badge>
        ) : null}
      </span>
      <span className="small break">{decision.summary}</span>
      {decision.description ? <span className="small muted break">{decision.description}</span> : null}
    </li>
  );
}

function PartView({ part }: { part: PolicyPartVerdict }) {
  return (
    <section className="policy-part" aria-label={`${part.part} decision`}>
      <div className="row row--wrap">
        <span className="tag">{part.part}</span>
        <Mono>{part.policy}</Mono>
        <DecisionBadge decision={part.decision} />
        {part.allowed_ports.length > 0 ? (
          <span className="small muted">allowed ports {part.allowed_ports.join(', ')}</span>
        ) : null}
      </div>
      {part.explanation.length > 0 ? (
        <ol className="policy-explanation">
          {part.explanation.map((line, index) => (
            <li key={index} className="break">
              {line}
            </li>
          ))}
        </ol>
      ) : null}
      {part.decisions.length > 0 ? (
        <ul className="stack stack--tight" aria-label="Deciding rules">
          {part.decisions.map((decision, index) => (
            <DecisionLine key={`d${index}`} decision={decision} />
          ))}
        </ul>
      ) : null}
      {part.preempted.length > 0 ? (
        <ul className="stack stack--tight" aria-label="Pre-empted rules">
          {part.preempted.map((decision, index) => (
            <DecisionLine key={`p${index}`} decision={decision} preempted />
          ))}
        </ul>
      ) : null}
    </section>
  );
}

export function EvaluationResult({ result }: { result: PolicyEvaluation }) {
  return (
    <div className="stack">
      <div className="row row--wrap policy-verdict">
        <DecisionBadge decision={result.decision} />
        <ObjectChip id={result.subject.id} name={result.subject.name} type={result.subject.type} />
        <span className="mono small">{result.verb}</span>
        <ObjectChip id={result.target.id} name={result.target.name} type={result.target.type} />
        {result.requested_ports.length > 0 ? (
          <span className="small muted">ports {result.requested_ports.join(', ')}</span>
        ) : null}
      </div>
      <p className="break">{result.reason}</p>
      {result.parts.map((part, index) => (
        <PartView key={`${part.part}:${part.policy}:${index}`} part={part} />
      ))}
      {result.indirect.length > 0 ? (
        <Callout tone="warn" title="Indirect paths">
          <div className="stack">
            {result.indirect.map((path, index) => (
              <div key={index} className="stack stack--tight">
                <span className="small break">{path.summary}</span>
                <Chain
                  label={`Indirect path through ${path.pivot_name}`}
                  items={[
                    ...path.legs.map((leg, legIndex) => ({
                      key: `${legIndex}:${leg.source}`,
                      node: <ObjectChip id={leg.source} />,
                      link: (
                        <span className="small">
                          ports {leg.ports.join(', ')} via{' '}
                          <span className="mono">{leg.rules.join(', ')}</span>
                        </span>
                      ),
                    })),
                    ...(path.legs.length > 0
                      ? [{ key: 'end', node: <ObjectChip id={path.legs[path.legs.length - 1]!.target} /> }]
                      : []),
                  ]}
                />
              </div>
            ))}
          </div>
        </Callout>
      ) : null}
      {result.notes.length > 0 ? (
        <ul className="stack stack--tight small muted">
          {result.notes.map((note, index) => (
            <li key={index} className="break">
              {note}
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

/** `POST /policy/evaluate`: a hypothetical flow or access request and the chain that decides it. */
export function EvaluatePanel() {
  const evaluate = usePolicyEvaluate();
  const [subject, setSubject] = useState('');
  const [target, setTarget] = useState('');
  const [action, setAction] = useState('');
  const [port, setPort] = useState('');
  const [source, setSource] = useState('');
  return (
    <Panel title="Evaluate a request">
      <div className="stack">
        <form
          className="filters"
          aria-label="Evaluate a flow or access request"
          onSubmit={(event) => {
            event.preventDefault();
            evaluate.mutate({
              subject: subject.trim(),
              target: target.trim(),
              action: action.trim() || undefined,
              port: port.trim() || undefined,
              source: source.trim() || undefined,
            });
          }}
        >
          <Field label="Subject" hint="A user, identity, host or IP">
            {(id) => (
              <TextInput
                id={id}
                value={subject}
                placeholder="alice, DEV-01"
                onChange={(e) => setSubject(e.target.value)}
              />
            )}
          </Field>
          <Field label="Action (optional)" hint="access, reach, ssh, https, admin, deploy:release…">
            {(id) => (
              <TextInput
                id={id}
                value={action}
                placeholder="access"
                onChange={(e) => setAction(e.target.value)}
              />
            )}
          </Field>
          <Field label="Target">
            {(id) => (
              <TextInput
                id={id}
                value={target}
                placeholder="DB-01"
                onChange={(e) => setTarget(e.target.value)}
              />
            )}
          </Field>
          <Field label="Port (optional)" hint="tcp/5432, 443, udp/53">
            {(id) => <TextInput id={id} value={port} onChange={(e) => setPort(e.target.value)} />}
          </Field>
          <Field label="From host (optional)" hint="Origin host for a user">
            {(id) => <TextInput id={id} value={source} onChange={(e) => setSource(e.target.value)} />}
          </Field>
          <div className="filters__actions">
            <Button
              type="submit"
              variant="primary"
              icon="route"
              loading={evaluate.isPending}
              disabled={!subject.trim() || !target.trim()}
            >
              Evaluate
            </Button>
          </div>
        </form>
        {evaluate.isError ? <ErrorState title="Evaluation failed" error={evaluate.error} compact /> : null}
        {evaluate.data ? <EvaluationResult result={evaluate.data} /> : null}
        <p className="small muted">
          Evaluation reads the stored policies only (audited as <code>policy.evaluate</code>); nothing is
          changed.
        </p>
      </div>
    </Panel>
  );
}

// ------------------------------------------------------------------ check a document (nothing is stored)

export const CHECK_NOTICE =
  'The document is normalized and analyzed against this workspace’s objects, then shown here only: no policy, finding, job or audit entry is written.';

const FORMAT_LABELS: Record<PolicyFormat, string> = {
  json: 'JSON (raf-policy/1, AWS-style)',
  yaml: 'YAML (raf-policy/1)',
  csv: 'CSV (firewall export)',
  iptables: 'iptables-save (filter table)',
};

function PolicyCheckResultView({ result }: { result: PolicyCheckResult }) {
  const { set, analysis } = result;
  const [selected, setSelected] = useState<string | null>(null);
  const [open, setOpen] = useState<Finding | null>(null);
  const current = set.policies.find((policy) => policy.id === selected) ?? set.policies[0];
  const rules = set.policies.reduce((total, policy) => total + policy.rules.length, 0);
  const findings = Object.fromEntries(analysis.policies.map((entry) => [entry.id, entry.findings]));
  // Without a name of its own, a document is named after its source (`request` for the API).
  const summary = [
    set.format,
    set.name !== set.source ? set.name : null,
    set.revision ? `revision ${set.revision}` : null,
    pluralize(set.policies.length, 'policy', 'policies'),
    pluralize(rules, 'rule'),
    pluralize(analysis.findings.length, 'finding'),
  ];
  return (
    <section className="stack" aria-label="Check result">
      <div className="row row--wrap policy-result-head">
        <strong>Checked</strong>
        <span className="small break">{summary.filter(Boolean).join(' · ')}</span>
        <Badge tone="neutral" outline title="Nothing from this check is stored in the workspace">
          NOT STORED
        </Badge>
      </div>
      {current ? (
        <>
          <Panel title="Normalized policies" flush>
            <PoliciesTable
              caption="Normalized policies of the checked document"
              policies={set.policies}
              selected={current.id}
              onSelect={setSelected}
              findings={findings}
            />
          </Panel>
          <PolicyRulesPanel policy={current} />
        </>
      ) : (
        <Panel>
          <EmptyState title="The document holds no policies">
            <p>
              It was read, but no policy or rule came out of it (for example a CSV export with a header only).
            </p>
          </EmptyState>
        </Panel>
      )}
      <Panel title={`Analysis · ${pluralize(analysis.findings.length, 'finding')}`}>
        <div className="stack">
          <p className="small muted">
            {analysis.workspace_aware === false
              ? 'This workspace has no objects yet: destination criticality and references to unknown objects were not judged.'
              : 'Judged against this workspace’s objects: destination criticality and references to objects the workspace does not know.'}
          </p>
          <AnalysisResult
            analysis={analysis}
            recorded={false}
            selectedId={open?.id ?? null}
            onOpenFinding={setOpen}
          />
        </div>
      </Panel>
      {open ? <ComputedFindingDrawer key={open.id} finding={open} onClose={() => setOpen(null)} /> : null}
    </section>
  );
}

/** `POST /policy/check`: paste a document or pick a file; nothing is stored. */
export function PolicyCheckView() {
  const check = usePolicyCheck();
  const [text, setText] = useState('');
  const [fileName, setFileName] = useState<string | null>(null);
  const [format, setFormat] = useState<PolicyFormat>('json');
  const [principal, setPrincipal] = useState('');
  const [host, setHost] = useState('');
  const [problem, setProblem] = useState<string | null>(null);
  const fileId = useId();

  const pick = (file: File | undefined) => {
    setProblem(null);
    if (!file) return;
    if (file.size > MAX_POLICY_DOCUMENT_BYTES) {
      setProblem(`${file.name} is ${formatBytes(file.size)}; policy documents are limited to 5 MB.`);
      return;
    }
    // The browser reads the file; only its text reaches the API (the server never reads a path).
    void file.text().then(
      (content) => {
        const inferred = inferPolicyFormat(file.name);
        setText(content);
        setFileName(file.name);
        setFormat(inferred);
        if (inferred === 'iptables') setHost(hostFromFileName(file.name));
      },
      () => setProblem(`${file.name} could not be read.`),
    );
  };

  return (
    <div className="stack">
      <Panel title="Check a policy document">
        <form
          className="stack"
          aria-label="Check a policy document"
          onSubmit={(event) => {
            event.preventDefault();
            if (!text.trim()) return;
            if (new TextEncoder().encode(text).length > MAX_POLICY_DOCUMENT_BYTES) {
              setProblem('Policy documents are limited to 5 MB.');
              return;
            }
            setProblem(null);
            check.mutate({
              document: text,
              format,
              principal: principal.trim() || undefined,
              host: format === 'iptables' ? host.trim() || undefined : undefined,
            });
          }}
        >
          <Callout title="Nothing is stored">
            {CHECK_NOTICE} To store policies, import them with <code>raf policy import FILE</code>.
          </Callout>
          <div className="field">
            <label className="field__label" htmlFor={fileId}>
              Policy file (optional)
            </label>
            <input
              id={fileId}
              type="file"
              className="input input--file"
              accept={['.json', '.yaml', '.yml', '.csv', ...IPTABLES_SUFFIXES].join(',')}
              onChange={(event) => pick(event.target.files?.[0])}
            />
            <p className="field__hint">
              raf-policy/1 JSON or YAML, AWS-style JSON, a CSV firewall export or iptables-save output; at
              most 5 MB. The file is loaded into the document below.
            </p>
            {fileName ? <p className="small muted break">Loaded {fileName}.</p> : null}
          </div>
          <Field label="Policy document" hint="Paste the document here, or pick a file above.">
            {(id) => (
              <TextArea
                id={id}
                className="mono policy-document"
                rows={12}
                spellCheck={false}
                value={text}
                placeholder='{"format": "raf-policy/1", "policies": [...]}'
                onChange={(event) => setText(event.target.value)}
              />
            )}
          </Field>
          <div className="row row--wrap row--top">
            <Field label="Format" hint="Set from the file extension when a file is picked">
              {(id) => (
                <Select
                  id={id}
                  value={format}
                  options={POLICY_FORMATS.map((value) => ({ value, label: FORMAT_LABELS[value] }))}
                  onChange={(event) => setFormat(event.target.value as PolicyFormat)}
                />
              )}
            </Field>
            <Field
              label="Principal (optional)"
              className="grow"
              hint="For AWS-style statements without a Principal, e.g. identity:svc-deploy or role:developer"
            >
              {(id) => (
                <TextInput
                  id={id}
                  value={principal}
                  maxLength={300}
                  onChange={(event) => setPrincipal(event.target.value)}
                />
              )}
            </Field>
            {format === 'iptables' ? (
              <Field
                label="Host (optional)"
                className="grow"
                hint="The host whose rules these are, e.g. VPN-01: its INPUT and OUTPUT rules apply to host:NAME"
              >
                {(id) => (
                  <TextInput
                    id={id}
                    value={host}
                    maxLength={200}
                    onChange={(event) => setHost(event.target.value)}
                  />
                )}
              </Field>
            ) : null}
          </div>
          {problem ? (
            <p className="field__error" role="alert">
              {problem}
            </p>
          ) : null}
          {check.isError ? (
            <ErrorState title="The document was not checked" error={check.error} compact />
          ) : null}
          <div>
            <Button
              type="submit"
              variant="primary"
              icon="check"
              loading={check.isPending}
              disabled={!text.trim()}
            >
              Check
            </Button>
          </div>
        </form>
      </Panel>
      {check.data ? (
        <PolicyCheckResultView key={check.submittedAt} result={check.data} />
      ) : (
        <EmptyState icon="file" title="Policy documents are untrusted input">
          <p>
            The server parses them with safe loaders (no YAML aliases), within size and rule limits, and
            normalizes every selector; everything is shown here as text.
          </p>
        </EmptyState>
      )}
    </div>
  );
}

// ------------------------------------------------------------------ compare stored revisions

const IMPACTS: Record<string, { label: string; tone: Tone }> = {
  'access-expanded': { label: 'ACCESS EXPANDED', tone: 'bad' },
  'access-reduced': { label: 'ACCESS REDUCED', tone: 'good' },
};

/** `access-expanded`, `access-reduced` or `changed`, always as words (never colour alone). */
export function ImpactBadge({ impact }: { impact: string }) {
  const known = IMPACTS[impact];
  return (
    <Badge tone={known?.tone ?? 'neutral'} outline={!known} title={`Impact: ${impact}`}>
      {known?.label ?? impact.toUpperCase()}
    </Badge>
  );
}

/** States whose policies can be compared: the live workspace and every snapshot (plus refs from the URL). */
function revisionOptions(snapshots: readonly Snapshot[], extra: ReadonlyArray<string | null>) {
  const options = [{ value: 'current', label: 'current (live workspace)' }];
  for (const snapshot of snapshots) {
    options.push({
      value: snapshot.name,
      label: `${snapshot.name} (snapshot ${formatTimestamp(snapshot.created_at)})`,
    });
  }
  for (const ref of extra) {
    if (ref && !options.some((option) => option.value === ref)) options.push({ value: ref, label: ref });
  }
  return options;
}

function PolicyCompareForm({
  snapshots,
  before,
  after,
  onCompare,
}: {
  snapshots: readonly Snapshot[];
  before: string | null;
  after: string | null;
  onCompare: (before: string, after: string) => void;
}) {
  const latest = snapshots.length > 0 ? snapshots[snapshots.length - 1]!.name : null;
  const [from, setFrom] = useState(before ?? latest ?? 'current');
  const [to, setTo] = useState(after ?? 'current');
  const options = revisionOptions(snapshots, [before, after]);
  return (
    <form
      className="filters filters--inline"
      aria-label="Compare policy revisions"
      onSubmit={(event) => {
        event.preventDefault();
        onCompare(from, to);
      }}
    >
      <Field label="Before">
        {(id) => <Select id={id} value={from} options={options} onChange={(e) => setFrom(e.target.value)} />}
      </Field>
      <Field label="After">
        {(id) => <Select id={id} value={to} options={options} onChange={(e) => setTo(e.target.value)} />}
      </Field>
      <div className="filters__actions">
        <Button
          variant="ghost"
          icon="diff"
          onClick={() => {
            setFrom(to);
            setTo(from);
          }}
        >
          Swap
        </Button>
        <Button type="submit" variant="primary" disabled={from === to}>
          Compare
        </Button>
      </div>
    </form>
  );
}

/** Whether access expanded: rule changes the API classifies so, and default actions that became allow. */
function AccessCallout({ diff }: { diff: PolicyDiff }) {
  const opened = diff.defaults_changed.filter(
    (change) => change.after === 'allow' && change.before !== 'allow',
  );
  if (diff.access_expanded === 0 && opened.length === 0) {
    return (
      <Callout title="Access did not expand">
        No rule change grants more access, and no default action became allow.
      </Callout>
    );
  }
  return (
    <Callout tone="bad" title="Access expanded">
      <ul className="stack stack--tight">
        {diff.access_expanded > 0 ? (
          <li>
            {pluralize(diff.access_expanded, 'rule change grants', 'rule changes grant')} more access (marked
            ACCESS EXPANDED below).
          </li>
        ) : null}
        {opened.map((change) => (
          <li key={change.policy} className="break">
            The default action of <span className="mono">{change.policy}</span> changed from {change.before}{' '}
            to allow.
          </li>
        ))}
      </ul>
    </Callout>
  );
}

function PolicyIds({ ids }: { ids: readonly string[] }) {
  if (ids.length === 0) return <span className="muted">—</span>;
  return (
    <span className="row row--wrap">
      {ids.map((id) => (
        <Mono key={id} className="small">
          {id}
        </Mono>
      ))}
    </span>
  );
}

function PolicyLevelChanges({ diff }: { diff: PolicyDiff }) {
  if (diff.policies_added.length + diff.policies_removed.length + diff.defaults_changed.length === 0)
    return null;
  return (
    <Panel title="Policies">
      <div className="stack">
        <KeyValueList
          entries={[
            ['Added', <PolicyIds ids={diff.policies_added} />],
            ['Removed', <PolicyIds ids={diff.policies_removed} />],
            [
              'Default action',
              diff.defaults_changed.length === 0 ? (
                <span className="muted">unchanged</span>
              ) : (
                <ul className="stack stack--tight">
                  {diff.defaults_changed.map((change) => (
                    <li key={change.policy} className="row row--wrap">
                      <Mono className="small">{change.policy}</Mono>
                      <DecisionBadge decision={change.before} />
                      <span aria-hidden="true">→</span>
                      <span className="sr-only">changed to</span>
                      <DecisionBadge decision={change.after} />
                    </li>
                  ))}
                </ul>
              ),
            ],
          ]}
        />
        {diff.policies_added.length + diff.policies_removed.length > 0 ? (
          <p className="small muted">
            Added and removed policies are listed as a whole: their rules are not compared one by one.
          </p>
        ) : null}
      </div>
    </Panel>
  );
}

function ChangedFields({ change }: { change: PolicyRuleChange }) {
  const entries = Object.entries(change.fields ?? {});
  if (entries.length === 0) return <span className="muted">—</span>;
  const text = (field: string, value: unknown) =>
    field === 'position' && typeof value === 'number' ? `#${value + 1}` : ruleFieldText(value);
  return (
    <ul className="policy-fields">
      {entries.map(([field, raw]) => {
        const value: { before?: unknown; after?: unknown } = raw && typeof raw === 'object' ? raw : {};
        return (
          <li key={field} className="mono small break">
            {field}: {text(field, value.before)} → {text(field, value.after)}
          </li>
        );
      })}
    </ul>
  );
}

function RuleChangesTable({ changes }: { changes: readonly PolicyRuleChange[] }) {
  const rows = changes.map((change, index) => ({ change, key: `${index}:${change.policy}:${change.rule}` }));
  return (
    <Table<(typeof rows)[number]>
      caption="Rule changes"
      rows={rows}
      rowKey={(row) => row.key}
      empty={<span className="muted">No rule of a policy present in both revisions changed.</span>}
      columns={[
        { key: 'impact', header: 'Impact', render: (r) => <ImpactBadge impact={r.change.impact} /> },
        { key: 'change', header: 'Change', render: (r) => <span className="tag">{r.change.change}</span> },
        {
          key: 'rule',
          header: 'Rule',
          render: (r) => (
            <span className="stack stack--tight">
              <Mono>{r.change.rule}</Mono>
              <Mono className="small muted">{r.change.policy}</Mono>
            </span>
          ),
        },
        {
          key: 'summary',
          header: 'Before → after',
          render: (r) =>
            r.change.before || r.change.after ? (
              <span className="stack stack--tight">
                {r.change.before ? (
                  <span className="small break">
                    <span className="muted">before </span>
                    {r.change.before}
                  </span>
                ) : null}
                {r.change.after ? (
                  <span className="small break">
                    <span className="muted">after </span>
                    {r.change.after}
                  </span>
                ) : null}
              </span>
            ) : (
              <span className="muted">—</span>
            ),
        },
        { key: 'fields', header: 'Changed fields', render: (r) => <ChangedFields change={r.change} /> },
      ]}
    />
  );
}

function PolicyDiffResult({ before, after }: { before: string; after: string }) {
  const query = usePolicyDiff(before, after);
  const [open, setOpen] = useState<Finding | null>(null);
  return (
    <QueryView query={query} feature="Policy diff" loadingLabel="Comparing policy revisions…">
      {(diff) => (
        <section className="stack" aria-label="Policy differences">
          <div className="row row--wrap policy-result-head">
            <Mono>{diff.before}</Mono>
            <span aria-hidden="true">→</span>
            <Mono>{diff.after}</Mono>
            <span className="small muted">
              {pluralize(diff.changes.length, 'rule change')} ·{' '}
              {pluralize(diff.policies_added.length, 'policy', 'policies')} added ·{' '}
              {formatNumber(diff.policies_removed.length)} removed ·{' '}
              {pluralize(diff.findings_introduced.length, 'finding')} introduced ·{' '}
              {formatNumber(diff.findings_resolved.length)} resolved
            </span>
            {query.isFetching ? <span className="small muted">Updating…</span> : null}
          </div>
          {isEmptyPolicyDiff(diff) ? (
            <Panel>
              <EmptyState icon="check" title="No policy differences">
                <p>
                  The policies of <span className="mono">{diff.before}</span> and{' '}
                  <span className="mono">{diff.after}</span> match: no policy, default action, rule or
                  analysis finding differs.
                </p>
              </EmptyState>
            </Panel>
          ) : (
            <>
              <AccessCallout diff={diff} />
              <PolicyLevelChanges diff={diff} />
              <Panel title={`Rule changes (${formatNumber(diff.changes.length)})`} flush>
                <RuleChangesTable changes={diff.changes} />
              </Panel>
              <p className="small muted">
                Findings below come from analyzing both revisions for this comparison: they are computed, not
                stored.
              </p>
              <Panel title={`Findings introduced (${formatNumber(diff.findings_introduced.length)})`} flush>
                <FindingsTable
                  rows={diff.findings_introduced}
                  selectedId={open?.id ?? null}
                  showProduct={false}
                  recorded={false}
                  empty="The later revision introduces no finding."
                  onOpen={setOpen}
                />
              </Panel>
              <Panel title={`Findings resolved (${formatNumber(diff.findings_resolved.length)})`} flush>
                <FindingsTable
                  rows={diff.findings_resolved}
                  selectedId={open?.id ?? null}
                  showProduct={false}
                  recorded={false}
                  empty="The later revision resolves no finding."
                  onOpen={setOpen}
                />
              </Panel>
            </>
          )}
          {open ? <ComputedFindingDrawer key={open.id} finding={open} onClose={() => setOpen(null)} /> : null}
        </section>
      )}
    </QueryView>
  );
}

/** `GET /policy/diff`: the policies of two stored states. Policy files are compared from the CLI only. */
export function PolicyDiffView({
  before,
  after,
  onCompare,
}: {
  before: string | null;
  after: string | null;
  onCompare: (before: string, after: string) => void;
}) {
  const snapshots = useSnapshots();
  const items = snapshots.data?.items ?? [];
  return (
    <div className="stack">
      <Panel title="Compare policy revisions" flush>
        <PolicyCompareForm
          key={`${before ?? ''}|${after ?? ''}|${snapshots.data ? items.length : -1}`}
          snapshots={items}
          before={before}
          after={after}
          onCompare={onCompare}
        />
        <p className="panel__pad small muted">
          Compares the policies stored in two workspace states (<code>current</code> or a snapshot); each rule
          change is classified as access-expanded, access-reduced or changed by comparing what the rules
          cover. Policy files are compared from the CLI only (<code>raf policy diff FILE current</code>).
        </p>
      </Panel>
      {before && after ? (
        <PolicyDiffResult key={`${before}|${after}`} before={before} after={after} />
      ) : (
        <Panel>
          {snapshots.data && items.length === 0 ? (
            <EmptyState icon="database" title="No snapshots to compare yet">
              <p>
                Policy revisions are kept in snapshots. Create one before changing policies (Snapshots &amp;
                Diff, or <code>raf snapshot create NAME</code>), then compare it with <code>current</code>.
              </p>
            </EmptyState>
          ) : (
            <EmptyState icon="diff" title="Choose two states to compare">
              <p>
                A snapshot as “Before” and <code>current</code> as “After” shows what changed since the
                snapshot.
              </p>
            </EmptyState>
          )}
        </Panel>
      )}
    </div>
  );
}
