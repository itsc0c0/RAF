import { useSearchParams } from 'react-router-dom';
import { PageHeader, Panel } from '../components/Panel';
import { EmptyState } from '../components/States';
import { AnalysisDetail, AnalysisList, AnalyzeForm } from '../features/analyses/AnalysisViews';
import '../styles/analyses.css';

export default function AnalysesPage() {
  const [params, setParams] = useSearchParams();
  const selected = params.get('analysis');
  return (
    <div className="page">
      <PageHeader
        title="Analyses"
        subtitle="Every analyzed file: what it was detected as, which modules ran (or were skipped, and why), and what they found"
      />
      <div className="split split--narrow-left">
        <div className="stack">
          <Panel title="Analyze a file">
            <AnalyzeForm />
          </Panel>
          <Panel title="Analyses" flush>
            <AnalysisList selected={selected} onOpen={(id) => setParams({ analysis: id })} />
          </Panel>
        </div>
        <div>
          {selected ? (
            <AnalysisDetail key={selected} id={selected} />
          ) : (
            <Panel>
              <EmptyState icon="analyses" title="Select an analysis">
                <p>
                  Each analysis lists every step with its status, detail, duration and numbers, and pivots to
                  Lens, Graph and Timeline scoped to exactly its data.
                </p>
              </EmptyState>
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}
