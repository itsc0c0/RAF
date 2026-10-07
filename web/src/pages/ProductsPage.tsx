import { useNavigate } from 'react-router-dom';
import { isApiError } from '../api/client';
import { useProducts, useToggleProduct } from '../api/hooks';
import type { ProductInfo } from '../api/types';
import { ProductStatusBadge } from '../components/Badge';
import { Button } from '../components/Button';
import { Switch } from '../components/Form';
import { PageHeader, Panel } from '../components/Panel';
import { QueryView } from '../components/States';
import { Table } from '../components/Table';
import { useToast } from '../components/Toast';
import { toInternalRoute } from '../lib/routes';

export default function ProductsPage() {
  const products = useProducts();
  const toggle = useToggleProduct();
  const { notify } = useToast();
  const navigate = useNavigate();
  return (
    <div className="page">
      <PageHeader
        title="Products"
        subtitle="Every product is a view into the same security graph; disabling one removes its commands and views"
      />
      <Panel flush>
        <QueryView query={products} feature="Product registry">
          {(data) => (
            <Table<ProductInfo>
              caption="Product registry"
              rows={data.items}
              rowKey={(product) => product.name}
              columns={[
                {
                  key: 'name',
                  header: 'Product',
                  render: (p) => (
                    <span className="stack stack--tight">
                      <strong>{p.display_name}</strong>
                      <span className="mono small muted">{p.name}</span>
                    </span>
                  ),
                },
                { key: 'status', header: 'Status', render: (p) => <ProductStatusBadge status={p.status} /> },
                {
                  key: 'category',
                  header: 'Category',
                  render: (p) => <span className="small">{p.category}</span>,
                },
                {
                  key: 'description',
                  header: 'Description',
                  render: (p) => (
                    <span className="stack stack--tight">
                      <span className="break">{p.description}</span>
                      {!p.available && p.unavailable_reason ? (
                        <span className="small muted break">{p.unavailable_reason}</span>
                      ) : null}
                      {p.depends_on.length > 0 ? (
                        <span className="small muted">depends on {p.depends_on.join(', ')}</span>
                      ) : null}
                    </span>
                  ),
                },
                {
                  key: 'commands',
                  header: 'CLI',
                  render: (p) => (
                    <span className="mono small">{p.commands.map((c) => `raf ${c}`).join(', ') || '—'}</span>
                  ),
                },
                {
                  key: 'version',
                  header: 'Version',
                  render: (p) => <span className="mono small">{p.version}</span>,
                },
                {
                  key: 'open',
                  header: 'View',
                  render: (p) => {
                    const route = toInternalRoute(p.ui?.route);
                    return route && p.available && p.enabled ? (
                      <Button size="sm" variant="ghost" icon="pivot" onClick={() => navigate(route)}>
                        Open
                      </Button>
                    ) : (
                      <span className="muted">—</span>
                    );
                  },
                },
                {
                  key: 'enabled',
                  header: 'Enabled',
                  render: (p) => (
                    <Switch
                      checked={p.enabled}
                      label={`${p.enabled ? 'Disable' : 'Enable'} ${p.display_name}`}
                      disabled={toggle.isPending}
                      onChange={(enable) =>
                        toggle.mutate(
                          { name: p.name, enable },
                          {
                            onSuccess: () =>
                              notify({
                                tone: 'good',
                                title: `${p.display_name} ${enable ? 'enabled' : 'disabled'}`,
                                description:
                                  'API routes of newly enabled products are mounted when raf serve restarts.',
                              }),
                            onError: (error) =>
                              notify({
                                tone: 'bad',
                                title: `Could not ${enable ? 'enable' : 'disable'} ${p.display_name}`,
                                description: isApiError(error)
                                  ? [error.message, error.hint].filter(Boolean).join(' ')
                                  : undefined,
                              }),
                          },
                        )
                      }
                    />
                  ),
                },
              ]}
            />
          )}
        </QueryView>
      </Panel>
    </div>
  );
}
