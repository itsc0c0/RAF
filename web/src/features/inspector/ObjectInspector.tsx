import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useObject, useObjectProvenance, useObjectRelationships } from '../../api/hooks';
import type { ObjectDetail, ProvenanceRecord, Relationship } from '../../api/types';
import { useInspector } from '../../app/shellState';
import { ConfidenceBadge, CriticalityTag, SeverityBadge } from '../../components/Badge';
import { Button } from '../../components/Button';
import { CopyButton, KeyValueList, MetadataList, Mono, TagList, Time } from '../../components/Data';
import { ObjectChip, TypeTag } from '../../components/ObjectChip';
import { QueryView } from '../../components/States';
import { formatNumber } from '../../lib/format';
import { routeTo } from '../../lib/routes';
import { PivotMenu } from './PivotMenu';

const RELATIONSHIP_PREVIEW = 25;

export function ObjectInspectorHeader({ detail }: { detail: ObjectDetail }) {
  const object = detail.object;
  return (
    <div className="inspector-head">
      <div className="row row--wrap">
        <TypeTag type={object.type} />
        <CriticalityTag
          value={typeof object.metadata.criticality === 'string' ? object.metadata.criticality : null}
        />
      </div>
      <div className="row">
        <Mono className="small muted">{object.id}</Mono>
        <CopyButton value={object.id} label="Copy object ID" />
      </div>
    </div>
  );
}

function RelationshipRow({ rel, subject }: { rel: Relationship; subject: string }) {
  const outgoing = rel.source_object === subject;
  const other = outgoing ? rel.target_object : rel.source_object;
  return (
    <li className="rel-row">
      <span
        className="rel-row__dir"
        aria-label={outgoing ? 'outgoing' : 'incoming'}
        title={outgoing ? 'outgoing' : 'incoming'}
      >
        {outgoing ? '→' : '←'}
      </span>
      <span className="rel-row__type mono">{rel.relationship_type}</span>
      <ObjectChip id={other} />
      <span className="rel-row__meta">
        <ConfidenceBadge confidence={rel.confidence} level={rel.confidence_level} showValue={false} />
        {rel.valid_to ? (
          <span className="tag" title={`Ended ${rel.valid_to}`}>
            ended
          </span>
        ) : null}
      </span>
    </li>
  );
}

function RelationshipsSection({ objectId, total }: { objectId: string; total: number }) {
  const query = useObjectRelationships(objectId);
  const [showAll, setShowAll] = useState(false);
  return (
    <section className="inspector-section" aria-label="Relationships">
      <h3>
        Relationships <span className="muted tabular">{formatNumber(total)}</span>
      </h3>
      <QueryView query={query} feature="Relationships" compact>
        {(data) => {
          if (data.items.length === 0) return <p className="muted small">No relationships.</p>;
          const items = showAll ? data.items : data.items.slice(0, RELATIONSHIP_PREVIEW);
          return (
            <>
              <ul className="rel-list">
                {items.map((rel) => (
                  <RelationshipRow key={rel.id} rel={rel} subject={data.object_id} />
                ))}
              </ul>
              {data.items.length > RELATIONSHIP_PREVIEW ? (
                <Button size="sm" variant="ghost" onClick={() => setShowAll((value) => !value)}>
                  {showAll ? 'Show fewer' : `Show all ${data.items.length}`}
                </Button>
              ) : null}
              {data.total > data.items.length ? (
                <p className="muted small">
                  Showing {data.items.length} of {formatNumber(data.total)} — open the Graph for the full
                  neighborhood.
                </p>
              ) : null}
            </>
          );
        }}
      </QueryView>
    </section>
  );
}

function ProvenanceRow({ record }: { record: ProvenanceRecord }) {
  const { openEvent } = useInspector();
  return (
    <li className="prov-row">
      <div className="row row--wrap">
        <span className="mono">{record.source}</span>
        {record.record ? <span className="mono muted">#{record.record}</span> : null}
      </div>
      <div className="prov-row__meta small muted">
        {record.parser ? <span className="mono">{record.parser}</span> : null}
        {record.observed_at ? (
          <span>
            observed <Time value={record.observed_at} />
          </span>
        ) : null}
        {record.job_id ? <span className="mono">{record.job_id}</span> : null}
        {record.evidence_id ? <span className="mono">evidence {record.evidence_id}</span> : null}
        {record.event_id ? (
          <button type="button" className="link-btn" onClick={() => openEvent(record.event_id!)}>
            event
          </button>
        ) : null}
      </div>
      {record.note ? <p className="small break">{record.note}</p> : null}
    </li>
  );
}

function ProvenanceSection({ objectId }: { objectId: string }) {
  const query = useObjectProvenance(objectId);
  return (
    <section className="inspector-section" aria-label="Provenance">
      <h3>
        Provenance{' '}
        {query.data ? <span className="muted tabular">{formatNumber(query.data.total)}</span> : null}
      </h3>
      <QueryView query={query} feature="Provenance" compact>
        {(data) =>
          data.items.length === 0 ? (
            <p className="muted small">No provenance records.</p>
          ) : (
            <>
              <ul className="prov-list">
                {data.items.map((record, index) => (
                  <ProvenanceRow key={`${record.source}-${record.record ?? ''}-${index}`} record={record} />
                ))}
              </ul>
              {data.total > data.items.length ? (
                <p className="muted small">
                  Showing {data.items.length} of {formatNumber(data.total)} records.
                </p>
              ) : null}
            </>
          )
        }
      </QueryView>
    </section>
  );
}

export function ObjectInspectorBody({ detail }: { detail: ObjectDetail }) {
  const navigate = useNavigate();
  const object = detail.object;
  return (
    <div className="inspector">
      <ObjectInspectorHeader detail={detail} />
      <PivotMenu pivots={detail.pivots} />
      <div className="row row--wrap">
        <ConfidenceBadge confidence={object.confidence} level={object.confidence_level} showLabel />
        {object.synthetic ? (
          <span className="tag" title="Generated by the synthetic demo or a range">
            synthetic
          </span>
        ) : null}
      </div>
      {detail.notes.length > 0 ? (
        <ul className="notes">
          {detail.notes.map((note) => (
            <li key={note} className="small muted">
              {note}
            </li>
          ))}
        </ul>
      ) : null}
      <section className="inspector-section" aria-label="Details">
        <h3>Details</h3>
        <KeyValueList
          entries={[
            ['Name', <span className="break">{object.name}</span>],
            ['First seen', <Time value={object.first_seen} />],
            ['Last seen', <Time value={object.last_seen} />],
            ...(object.valid_from || object.valid_to
              ? ([
                  [
                    'Valid',
                    <span>
                      <Time value={object.valid_from} /> → <Time value={object.valid_to} />
                    </span>,
                  ],
                ] as const)
              : []),
            ['Source', <Mono>{object.source}</Mono>],
            ['Observations', formatNumber(object.observations)],
            ['Tags', <TagList tags={object.tags} />],
          ]}
        />
      </section>
      {detail.activity ? (
        <section className="inspector-section" aria-label="Activity">
          <h3>Activity</h3>
          <KeyValueList
            entries={[
              ['Events', formatNumber(detail.activity.events)],
              ['First event', <Time value={detail.activity.first_event} />],
              ['Last event', <Time value={detail.activity.last_event} />],
            ]}
          />
        </section>
      ) : null}
      <section className="inspector-section" aria-label="Findings">
        <h3>
          Findings <span className="muted tabular">{detail.findings.length}</span>
        </h3>
        {detail.findings.length === 0 ? (
          <p className="muted small">No findings reference this object.</p>
        ) : (
          <ul className="finding-mini-list">
            {detail.findings.map((finding) => (
              <li key={finding.id}>
                <button
                  type="button"
                  className="finding-mini"
                  onClick={() => navigate(routeTo.finding(finding.id))}
                >
                  <span className="row row--wrap">
                    <SeverityBadge severity={finding.severity} />
                    <ConfidenceBadge confidence={finding.confidence} level={finding.confidence_level} />
                  </span>
                  <span className="finding-mini__title">{finding.title}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>
      <section className="inspector-section" aria-label="Metadata">
        <h3>Metadata</h3>
        <MetadataList metadata={object.metadata} />
      </section>
      <RelationshipsSection objectId={object.id} total={detail.relationship_count} />
      <ProvenanceSection objectId={object.id} />
    </div>
  );
}

/** Loads `GET /objects/{ref}` and renders the inspector body. */
export function ObjectInspector({ objectRef }: { objectRef: string }) {
  const query = useObject(objectRef);
  return (
    <QueryView query={query} feature="Object details" loadingLabel="Loading object…">
      {(detail) => <ObjectInspectorBody detail={detail} />}
    </QueryView>
  );
}
