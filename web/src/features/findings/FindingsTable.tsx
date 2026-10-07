import type { Finding } from '../../api/types';
import { ConfidenceBadge, SeverityBadge } from '../../components/Badge';
import { Time } from '../../components/Data';
import { ObjectChip } from '../../components/ObjectChip';
import { Table } from '../../components/Table';
import { FindingStatusBadge } from './FindingDetail';

/** Findings with separate severity and confidence badges; rows open the finding drawer. */
export function FindingsTable({
  rows,
  selectedId,
  onOpen,
  empty,
  showProduct = true,
}: {
  rows: readonly Finding[];
  selectedId: string | null;
  onOpen: (finding: Finding) => void;
  empty?: string;
  showProduct?: boolean;
}) {
  return (
    <Table<Finding>
      caption="Findings"
      rows={rows}
      rowKey={(finding) => finding.id}
      selectedKey={selectedId}
      onRowClick={onOpen}
      rowLabel={(finding) => `Open finding ${finding.title}`}
      empty={<span className="muted">{empty ?? 'No findings match these filters.'}</span>}
      columns={[
        {
          key: 'severity',
          header: 'Severity',
          width: '96px',
          render: (f) => <SeverityBadge severity={f.severity} />,
        },
        {
          key: 'confidence',
          header: 'Confidence',
          width: '128px',
          render: (f) => <ConfidenceBadge confidence={f.confidence} level={f.confidence_level} />,
        },
        {
          key: 'title',
          header: 'Finding',
          render: (f) => (
            <span className="stack stack--tight">
              <span className="break">{f.title}</span>
              <span className="mono small muted">{f.rule_id}</span>
            </span>
          ),
        },
        ...(showProduct
          ? [
              {
                key: 'product',
                header: 'Product',
                render: (f: Finding) => <span className="mono small">{f.product}</span>,
              },
            ]
          : []),
        { key: 'status', header: 'Status', render: (f) => <FindingStatusBadge status={f.status} /> },
        {
          key: 'affected',
          header: 'Affected',
          render: (f) => (
            <span className="row row--wrap">
              {f.affected_objects.slice(0, 2).map((id) => (
                <ObjectChip key={id} id={id} showType={false} />
              ))}
              {f.affected_objects.length > 2 ? (
                <span className="small muted">+{f.affected_objects.length - 2}</span>
              ) : null}
            </span>
          ),
        },
        { key: 'updated', header: 'Updated', render: (f) => <Time value={f.updated_at} className="small" /> },
      ]}
    />
  );
}
