import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { isApiError } from '../../api/client';
import { useFinding, useUpdateFinding } from '../../api/hooks';
import { FINDING_STATUSES, type EvidenceRef, type Finding, type FindingStatus } from '../../api/types';
import { useInspector } from '../../app/shellState';
import { Badge, ConfidenceBadge, SeverityBadge } from '../../components/Badge';
import { Button } from '../../components/Button';
import { FactorList, KeyValueList, MetadataList, Mono, TagList, Time } from '../../components/Data';
import { Drawer } from '../../components/Drawer';
import { Field, Select, TextArea } from '../../components/Form';
import { ObjectChip } from '../../components/ObjectChip';
import { QueryView } from '../../components/States';
import { useToast } from '../../components/Toast';
import { routeTo } from '../../lib/routes';

export const STATUS_TONES: Record<string, 'neutral' | 'accent' | 'good' | 'warn' | 'bad'> = {
  OPEN: 'bad',
  ACKNOWLEDGED: 'warn',
  RESOLVED: 'good',
  FALSE_POSITIVE: 'neutral',
  SUPPRESSED: 'neutral',
};

export function FindingStatusBadge({ status }: { status: string }) {
  return (
    <Badge tone={STATUS_TONES[status] ?? 'neutral'} outline>
      {status.replace('_', ' ')}
    </Badge>
  );
}

function EvidenceItem({ evidence }: { evidence: EvidenceRef }) {
  const { openEvent } = useInspector();
  const navigate = useNavigate();
  let content;
  if (evidence.kind === 'object') content = <ObjectChip id={evidence.id} />;
  else if (evidence.kind === 'event')
    content = (
      <button type="button" className="link-btn mono" onClick={() => openEvent(evidence.id)}>
        {evidence.id}
      </button>
    );
  else if (evidence.kind === 'finding')
    content = (
      <button type="button" className="link-btn mono" onClick={() => navigate(routeTo.finding(evidence.id))}>
        {evidence.id}
      </button>
    );
  else if (evidence.kind === 'evidence')
    content = (
      <button type="button" className="link-btn mono" onClick={() => navigate(routeTo.evidence(evidence.id))}>
        {evidence.id}
      </button>
    );
  else content = <Mono>{evidence.id}</Mono>;
  return (
    <li className="evidence-ref">
      <span className="tag">{evidence.kind}</span>
      {content}
      {evidence.note ? <span className="small muted break">{evidence.note}</span> : null}
    </li>
  );
}

function TriageForm({ finding }: { finding: Finding }) {
  const [status, setStatus] = useState<FindingStatus>(finding.status);
  const [note, setNote] = useState('');
  const update = useUpdateFinding();
  const { notify } = useToast();
  return (
    <form
      className="stack triage"
      onSubmit={(event) => {
        event.preventDefault();
        update.mutate(
          { id: finding.id, status, note: note.trim() || null },
          {
            onSuccess: () => {
              notify({ tone: 'good', title: `Finding marked ${status.replace('_', ' ')}` });
              setNote('');
            },
            onError: (error) =>
              notify({
                tone: 'bad',
                title: 'Triage failed',
                description: isApiError(error) ? error.message : undefined,
              }),
          },
        );
      }}
    >
      <h3>Triage</h3>
      <Field label="Status">
        {(id) => (
          <Select
            id={id}
            value={status}
            options={FINDING_STATUSES.map((value) => ({ value, label: value.replace('_', ' ') }))}
            onChange={(event) => setStatus(event.target.value as FindingStatus)}
          />
        )}
      </Field>
      <Field label="Note (recorded in the audit log)">
        {(id) => (
          <TextArea
            id={id}
            rows={3}
            maxLength={2000}
            value={note}
            onChange={(event) => setNote(event.target.value)}
          />
        )}
      </Field>
      <div>
        <Button
          type="submit"
          variant="primary"
          loading={update.isPending}
          disabled={status === finding.status && !note.trim()}
        >
          Save
        </Button>
      </div>
    </form>
  );
}

export function FindingBody({ finding }: { finding: Finding }) {
  return (
    <div className="stack">
      <div className="row row--wrap">
        <SeverityBadge severity={finding.severity} showLabel />
        <ConfidenceBadge confidence={finding.confidence} level={finding.confidence_level} showLabel />
        <FindingStatusBadge status={finding.status} />
      </div>
      <p className="break">{finding.description}</p>
      {finding.recommendation ? (
        <section className="stack stack--tight">
          <h4>Recommendation</h4>
          <p className="break">{finding.recommendation}</p>
        </section>
      ) : null}
      <section className="stack stack--tight">
        <h4>Explanation</h4>
        <FactorList factors={finding.explanation ?? []} />
      </section>
      <section className="stack stack--tight">
        <h4>Affected objects</h4>
        {finding.affected_objects.length === 0 ? (
          <span className="muted small">None.</span>
        ) : (
          <div className="row row--wrap">
            {finding.affected_objects.map((id) => (
              <ObjectChip key={id} id={id} />
            ))}
          </div>
        )}
      </section>
      <section className="stack stack--tight">
        <h4>Evidence</h4>
        {finding.evidence.length === 0 ? (
          <span className="muted small">No evidence references.</span>
        ) : (
          <ul className="stack stack--tight">
            {finding.evidence.map((evidence, index) => (
              <EvidenceItem key={`${evidence.kind}:${evidence.id}:${index}`} evidence={evidence} />
            ))}
          </ul>
        )}
      </section>
      <KeyValueList
        entries={[
          ['Product', <Mono>{finding.product}</Mono>],
          ['Rule', <Mono>{finding.rule_id}</Mono>],
          ['Created', <Time value={finding.created_at} />],
          ['Updated', <Time value={finding.updated_at} />],
          ['Tags', <TagList tags={finding.tags} />],
          ['ID', <Mono>{finding.id}</Mono>],
        ]}
      />
      {Object.keys(finding.metadata ?? {}).length > 0 ? (
        <section className="stack stack--tight">
          <h4>Metadata</h4>
          <MetadataList metadata={finding.metadata} />
        </section>
      ) : null}
      <TriageForm key={`${finding.id}:${finding.status}:${finding.updated_at}`} finding={finding} />
    </div>
  );
}

export function FindingDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const query = useFinding(id);
  return (
    <Drawer
      title={<span className="break">{query.data?.title ?? 'Finding'}</span>}
      subtitle="Finding"
      onClose={onClose}
      closeLabel="Close finding"
    >
      <QueryView query={query} feature="Finding" loadingLabel="Loading finding…">
        {(finding) => <FindingBody finding={finding} />}
      </QueryView>
    </Drawer>
  );
}
