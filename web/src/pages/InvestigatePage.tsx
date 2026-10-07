import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Button } from '../components/Button';
import { Field, TextInput } from '../components/Form';
import { PageHeader, Panel } from '../components/Panel';
import { TabPanel, Tabs } from '../components/Tabs';
import { LensWorkbench } from '../features/investigate/LensWorkbench';
import { TraceView } from '../features/trace/TraceView';
import '../styles/investigate.css';

type Mode = 'lens' | 'trace';

function TraceStart({ onTrace }: { onTrace: (ref: string) => void }) {
  const [value, setValue] = useState('');
  return (
    <Panel title="Trace an object">
      <form
        className="row row--wrap"
        onSubmit={(event) => {
          event.preventDefault();
          if (value.trim()) onTrace(value.trim());
        }}
      >
        <Field label="Object (ID, name or alias)" inline>
          {(id) => (
            <TextInput
              id={id}
              value={value}
              placeholder="e.g. svc-deploy"
              onChange={(e) => setValue(e.target.value)}
            />
          )}
        </Field>
        <Button type="submit" variant="primary" icon="route" disabled={!value.trim()}>
          Trace
        </Button>
      </form>
      <p className="small muted">
        Trace answers “how did this become involved, and what did it do next?” from events, separating
        observed links from correlations.
      </p>
    </Panel>
  );
}

export default function InvestigatePage() {
  const [params, setParams] = useSearchParams();
  const trace = params.get('trace');
  const object = params.get('object');
  const [mode, setMode] = useState<Mode>(trace ? 'trace' : 'lens');
  const active: Mode = trace ? 'trace' : mode;

  return (
    <div className="page">
      <PageHeader title="Investigate" subtitle="Search, filter, group, trace and pivot across every product">
        <Tabs<Mode>
          label="Investigate mode"
          idPrefix="investigate"
          value={active}
          onChange={(next) => {
            setMode(next);
            if (next === 'lens' && trace) setParams(object ? { object } : {});
          }}
          items={[
            { key: 'lens', label: 'Lens' },
            { key: 'trace', label: 'Trace' },
          ]}
        />
      </PageHeader>
      <TabPanel idPrefix="investigate" activeKey={active}>
        {active === 'trace' ? (
          trace ? (
            <TraceView key={trace} subject={trace} onClose={() => setParams(object ? { object } : {})} />
          ) : (
            <TraceStart onTrace={(ref) => setParams({ trace: ref })} />
          )
        ) : (
          <LensWorkbench key={object ?? ''} initialScope={object ?? ''} />
        )}
      </TabPanel>
    </div>
  );
}
