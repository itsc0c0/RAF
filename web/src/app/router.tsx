import { lazy } from 'react';
import { isRouteErrorResponse, useRouteError, type RouteObject } from 'react-router-dom';
import { Button } from '../components/Button';
import { EmptyState, ErrorState } from '../components/States';
import { Shell } from './Shell';

// Pages are code-split: Cytoscape (Graph, Replay) only loads when those views open.
const OverviewPage = lazy(() => import('../pages/OverviewPage'));
const InvestigatePage = lazy(() => import('../pages/InvestigatePage'));
const GraphPage = lazy(() => import('../pages/GraphPage'));
const ReplayPage = lazy(() => import('../pages/ReplayPage'));
const TimelinePage = lazy(() => import('../pages/TimelinePage'));
const ExposurePage = lazy(() => import('../pages/ExposurePage'));
const RangesPage = lazy(() => import('../pages/RangesPage'));
const LabsPage = lazy(() => import('../pages/LabsPage'));
const EvidencePage = lazy(() => import('../pages/EvidencePage'));
const FindingsPage = lazy(() => import('../pages/FindingsPage'));
const ProductsPage = lazy(() => import('../pages/ProductsPage'));
const SettingsPage = lazy(() => import('../pages/SettingsPage'));

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
      { path: 'exposure', element: <ExposurePage /> },
      { path: 'ranges', element: <RangesPage /> },
      { path: 'labs', element: <LabsPage /> },
      { path: 'evidence', element: <EvidencePage /> },
      { path: 'findings', element: <FindingsPage /> },
      { path: 'products', element: <ProductsPage /> },
      { path: 'settings', element: <SettingsPage /> },
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
