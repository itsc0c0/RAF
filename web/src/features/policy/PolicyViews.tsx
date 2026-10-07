import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useFindings, usePolicies, usePolicyAnalyze, usePolicyEvaluate } from '../../api/hooks';
import type {
  Policy,
  PolicyAnalysis,
  PolicyEvaluation,
  PolicyPartVerdict,
  PolicyRule,
  PolicyRuleDecision,
} from '../../api/types';
import { Badge, type Tone } from '../../components/Badge';
import { Button } from '../../components/Button';
import { Chain } from '../../components/Chain';
import { Mono } from '../../components/Data';
import { Field, TextInput } from '../../components/Form';
import { ConfirmDialog } from '../../components/Modal';
import { ObjectChip } from '../../components/ObjectChip';
import { Callout, Panel } from '../../components/Panel';
import { EmptyState, ErrorState, QueryView } from '../../components/States';
import { Table } from '../../components/Table';
import { useToast } from '../../components/Toast';
import { formatNumber, pluralize } from '../../lib/format';
import { routeTo } from '../../lib/routes';
import { FindingsTable } from '../findings/FindingsTable';

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
              <Table<Policy>
                caption="Stored policies"
                dense
                rows={data.items}
                rowKey={(policy) => policy.id}
                selectedKey={current.id}
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
                  {
                    key: 'source',
                    header: 'Source',
                    render: (p) => <span className="small break">{p.source ?? '—'}</span>,
                  },
                ]}
              />
            </Panel>
            <Panel
              title={
                <span className="row row--wrap">
                  <span className="break">{current.name}</span>
                  <span className="small muted">
                    {current.domain} · {current.evaluation} · default {current.default}
                  </span>
                </span>
              }
              flush
              actions={current.object_id ? <ObjectChip id={current.object_id} /> : null}
            >
              {current.description ? <p className="panel__pad small break">{current.description}</p> : null}
              <RulesTable policy={current} />
              <p className="panel__pad small muted">
                {current.domain === 'network'
                  ? 'Network policies: the first matching rule decides the still-undecided ports (first match wins).'
                  : 'Access policies: an explicit deny overrides any allow; nothing granted means deny.'}
              </p>
            </Panel>
          </div>
        );
      }}
    </QueryView>
  );
}

function AnalysisResult({ analysis }: { analysis: PolicyAnalysis }) {
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
        selectedId={null}
        showProduct={false}
        empty="The analysis found no conflicting, shadowed, redundant or overly broad rules."
        onOpen={(finding) => void navigate(routeTo.finding(finding.id))}
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
