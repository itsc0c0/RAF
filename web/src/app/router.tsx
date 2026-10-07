import { lazy } from 'react';
import {
  isRouteErrorResponse,
  Navigate,
  useLocation,
  useRouteError,
  type RouteObject,
} from 'react-router-dom';
import { Button } from '../components/Button';
import { EmptyState, ErrorState } from '../components/States';
import { Shell } from './Shell';

// Pages are code-split: Cytoscape (Graph, Replay) only loads when those views open.
const OverviewPage = lazy(() => import('../pages/OverviewPage'));
const InvestigatePage = lazy(() => import('../pages/InvestigatePage'));
const GraphPage = lazy(() => import('../pages/GraphPage'));
const ReplayPage = lazy(() => import('../pages/ReplayPage'));
const TimelinePage = lazy(() => import('../pages/TimelinePage'));
const AnalysesPage = lazy(() => import('../pages/AnalysesPage'));
const DiffPage = lazy(() => import('../pages/DiffPage'));
const ExposurePage = lazy(() => import('../pages/ExposurePage'));
const SurfacePage = lazy(() => import('../pages/SurfacePage'));
const GhostPage = lazy(() => import('../pages/GhostPage'));
const RangesPage = lazy(() => import('../pages/RangesPage'));
const LabPage = lazy(() => import('../pages/LabPage'));
const ProtocolPage = lazy(() => import('../pages/ProtocolPage'));
const EvidencePage = lazy(() => import('../pages/EvidencePage'));
const FindingsPage = lazy(() => import('../pages/FindingsPage'));
const OraclePage = lazy(() => import('../pages/OraclePage'));
const ProductsPage = lazy(() => import('../pages/ProductsPage'));
const SettingsPage = lazy(() => import('../pages/SettingsPage'));

/** Redirect that keeps the query string (old or manifest-declared routes). */
export function RedirectTo({ to }: { to: string }) {
  const location = useLocation();
  return <Navigate to={`${to}${location.search}`} replace />;
}

function RouteError() {
  const error = useRouteError();
  if (isRouteErrorResponse(error) && error.status === 404) {
    return (
      <div className="page">
        <NotFound />
      </div>
    );
  }
  return (
    <div className="page">
      <ErrorState
        title="This view failed to load"
        error={error instanceof Error ? error : new Error('Unexpected error.')}
        onRetry={() => window.location.reload()}
      />
    </div>
  );
}

function NotFound() {
  return (
    <EmptyState icon="warning" title="No such view">
      <p>The address does not match any R$F view.</p>
      <p>
        <Button size="sm" onClick={() => window.history.back()}>
          Go back
        </Button>
      </p>
    </EmptyState>
  );
}

export const routes: RouteObject[] = [
  {
    path: '/',
    element: <Shell />,
    errorElement: <RouteError />,
    children: [
      { index: true, element: <OverviewPage /> },
      { path: 'investigate', element: <InvestigatePage /> },
      { path: 'graph', element: <GraphPage /> },
      { path: 'replay', element: <ReplayPage /> },
      { path: 'timeline', element: <TimelinePage /> },
      { path: 'analyses', element: <AnalysesPage /> },
      { path: 'diff', element: <DiffPage /> },
      { path: 'exposure', element: <ExposurePage /> },
      { path: 'surface', element: <SurfacePage /> },
      { path: 'ghost', element: <GhostPage /> },
      { path: 'ranges', element: <RangesPage /> },
      { path: 'lab', element: <LabPage /> },
      { path: 'protocol', element: <ProtocolPage /> },
      { path: 'evidence', element: <EvidencePage /> },
      { path: 'findings', element: <FindingsPage /> },
      { path: 'oracle', element: <OraclePage /> },
      { path: 'products', element: <ProductsPage /> },
      { path: 'settings', element: <SettingsPage /> },
      // `ui.route` of the range/forge manifests, and the previous Lab route.
      { path: 'range', element: <RedirectTo to="/ranges" /> },
      { path: 'labs', element: <RedirectTo to="/lab" /> },
      {
        path: '*',
        element: (
          <div className="page">
            <NotFound />
          </div>
        ),
      },
    ],
  },
];
