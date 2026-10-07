import { useSearchParams } from 'react-router-dom';
import { Callout, PageHeader, Panel } from '../components/Panel';
import { EmptyState } from '../components/States';
import { GhostModelList, GhostModelView } from '../features/ghost/GhostViews';
import '../styles/ghost.css';

type ModelTab = 'ops' | 'simulate' | 'compare';

function readTab(value: string | null): ModelTab {
  return value === 'simulate' || value === 'compare' ? value : 'ops';
}

export default function GhostPage() {
  const [params, setParams] = useSearchParams();
  const model = params.get('model');
  const tab = readTab(params.get('view'));

  const select = (name: string | null, nextTab: ModelTab = 'ops') => {
    if (!name) setParams({});
    else setParams(nextTab === 'ops' ? { model: name } : { model: name, view: nextTab });
  };

  return (
    <div className="page">
      <PageHeader
        title="Ghost"
        subtitle="Security digital twins: model a change, simulate exposure, compare with the real state"
      />
      <Callout tone="info">
        Models are in-memory copies of a frozen state. Operations never touch the workspace or any real
        system; there are no connectors that apply changes.
      </Callout>
      <div className="split split--narrow-left">
        <GhostModelList selected={model} onSelect={(name) => select(name)} />
        <div>
          {model ? (
            <GhostModelView
              key={model}
              name={model}
              tab={tab}
              onTab={(next) => select(model, next)}
              onSelect={(name) => select(name)}
            />
          ) : (
            <Panel>
              <EmptyState icon="ghost" title="Select or create a model">
                <p>
                  Apply what-if operations (remove an access path, add segmentation, disable an identity,
                  patch a vulnerability…), then simulate exposure and compare with <code>current</code>.
                </p>
              </EmptyState>
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}
