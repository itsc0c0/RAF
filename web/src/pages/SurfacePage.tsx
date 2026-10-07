import { useSearchParams } from 'react-router-dom';
import { useSurfaceScope } from '../api/hooks';
import { PageHeader } from '../components/Panel';
import { isUnavailableError, UnavailableState } from '../components/States';
import { TabPanel, Tabs } from '../components/Tabs';
import { FindingDrawer } from '../features/findings/FindingDetail';
import {
  NoScanningNotice,
  SurfaceAssetsView,
  SurfaceFindingsView,
  SurfaceImportView,
  SurfaceOverview,
  SurfaceScopeView,
} from '../features/surface/SurfaceViews';
import '../styles/surface.css';

type View = 'overview' | 'assets' | 'scope' | 'findings' | 'import';

const VIEWS: readonly View[] = ['overview', 'assets', 'scope', 'findings', 'import'];

function readView(value: string | null): View {
  return VIEWS.find((view) => view === value) ?? 'overview';
}

export default function SurfacePage() {
  const [params, setParams] = useSearchParams();
  const view = readView(params.get('view'));
  const finding = params.get('finding');
  const scope = useSurfaceScope();

  const update = (changes: Record<string, string | null>) => {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(changes)) {
      if (value) next.set(key, value);
      else next.delete(key);
    }
    setParams(next);
  };

  const header = (
    <PageHeader
      title="Surface"
      subtitle="The authorized external attack surface: domains, DNS, addresses, services, certificates and cloud assets from imported inventories"
    />
  );
  if (isUnavailableError(scope.error)) {
    return (
      <div className="page">
        {header}
        <UnavailableState feature="Surface" error={scope.error} />
      </div>
    );
  }
  return (
    <div className="page">
      {header}
      <NoScanningNotice />
      <Tabs<View>
        label="Surface views"
        idPrefix="surface"
        value={view}
        onChange={(next) => update({ view: next === 'overview' ? null : next })}
        items={[
          { key: 'overview', label: 'Overview' },
          { key: 'assets', label: 'Assets' },
          {
            key: 'scope',
            label: 'Authorized scope',
            badge: scope.data ? String(scope.data.total) : undefined,
          },
          { key: 'findings', label: 'Findings' },
          { key: 'import', label: 'Import' },
        ]}
      />
      <TabPanel idPrefix="surface" activeKey={view}>
        {view === 'overview' ? <SurfaceOverview onOpenFinding={(id) => update({ finding: id })} /> : null}
        {view === 'assets' ? <SurfaceAssetsView /> : null}
        {view === 'scope' ? <SurfaceScopeView /> : null}
        {view === 'findings' ? (
          <SurfaceFindingsView selectedId={finding} onOpen={(id) => update({ finding: id })} />
        ) : null}
        {view === 'import' ? <SurfaceImportView /> : null}
      </TabPanel>
      {finding ? (
        <FindingDrawer key={finding} id={finding} onClose={() => update({ finding: null })} />
      ) : null}
    </div>
  );
}
