import { useSearchParams } from 'react-router-dom';
import { useSnapshots } from '../api/hooks';
import { PageHeader, Panel } from '../components/Panel';
import { EmptyState } from '../components/States';
import {
  CompareForm,
  DIFF_LIMITS,
  DiffResultView,
  SnapshotsPanel,
  type CompareParams,
} from '../features/diff/DiffViews';
import '../styles/diff.css';

function readLimit(value: string | null): number {
  const limit = Number(value);
  return DIFF_LIMITS.includes(limit) ? limit : 500;
}

export default function DiffPage() {
  const [params, setParams] = useSearchParams();
  const snapshots = useSnapshots();
  const current: CompareParams = {
    a: params.get('a'),
    b: params.get('b'),
    category: params.get('category'),
    limit: readLimit(params.get('limit')),
  };

  const apply = (next: CompareParams) => {
    const search = new URLSearchParams();
    if (next.a) search.set('a', next.a);
    if (next.b) search.set('b', next.b);
    if (next.category) search.set('category', next.category);
    if (next.limit !== 500) search.set('limit', String(next.limit));
    setParams(search);
  };

  const ready = Boolean(current.a && current.b);
  return (
    <div className="page">
      <PageHeader
        title="Snapshots & Diff"
        subtitle="Freeze security states and see what changed between them, with the importance of every change and why"
      />
      <Panel title="Compare" flush>
        <CompareForm
          key={`${current.a ?? ''}|${current.b ?? ''}|${current.category ?? ''}|${current.limit}|${snapshots.data ? snapshots.data.items.length : -1}`}
          value={current}
          onCompare={apply}
        />
      </Panel>
      {ready ? (
        <DiffResultView params={current} onCategory={(category) => apply({ ...current, category })} />
      ) : (
        <Panel>
          <EmptyState icon="diff" title="Choose two states to compare">
            <p>
              Compare a snapshot with the live workspace (<code>current</code>) or two snapshots. Ghost models
              become comparable once saved as a snapshot (source “Ghost model” below, or{' '}
              <code>raf snapshot create NAME --source ghost:MODEL</code>).
            </p>
          </EmptyState>
        </Panel>
      )}
      <SnapshotsPanel onCompare={(a, b) => apply({ a, b, category: null, limit: current.limit })} />
    </div>
  );
}
