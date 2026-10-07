import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Button } from '../components/Button';
import { Field, TextInput } from '../components/Form';
import { PageHeader, Panel } from '../components/Panel';
import { TabPanel, Tabs } from '../components/Tabs';
import {
  BlastView,
  ExposureDetailView,
  ExposureRanking,
  IamPathsView,
} from '../features/exposure/ExposureViews';
import { EvaluatePanel, PolicyAnalysisPanel, PolicyList } from '../features/policy/PolicyViews';
import '../styles/exposure.css';

type Mode = 'ranking' | 'asset' | 'blast' | 'iam' | 'policies';

function RefPrompt({
  label,
  button,
  onSubmit,
}: {
  label: string;
  button: string;
  onSubmit: (ref: string) => void;
}) {
  const [value, setValue] = useState('');
  return (
    <Panel>
      <form
        className="row row--wrap"
        onSubmit={(event) => {
          event.preventDefault();
          if (value.trim()) onSubmit(value.trim());
        }}
      >
        <Field label={label} inline>
          {(id) => (
            <TextInput
              id={id}
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder="ID, name or alias"
            />
          )}
        </Field>
        <Button type="submit" variant="primary" disabled={!value.trim()}>
          {button}
        </Button>
      </form>
    </Panel>
  );
}

export default function ExposurePage() {
  const [params, setParams] = useSearchParams();
  const blast = params.get('blast');
  const object = params.get('object');
  const iam = params.get('iam');
  const policy = params.get('policy');
  const policiesView = params.get('view') === 'policies';
  // A pivot (?blast=, ?iam=, ?object=, ?policy=) decides the view; otherwise the user's tab choice does.
  const fromParams: Mode | null = blast
    ? 'blast'
    : iam
      ? 'iam'
      : object
        ? 'asset'
        : policy || policiesView
          ? 'policies'
          : null;
  const [chosen, setChosen] = useState<Mode>('ranking');
  const mode = fromParams ?? chosen;

  const select = (next: Mode) => {
    if (next === mode) return;
    setChosen(next);
    // Policies are deep-linkable (`?view=policies`, `?policy=<id>`); the other tabs clear pivots.
    if (next === 'policies') setParams({ view: 'policies' });
    else if (fromParams) setParams({});
  };

  return (
    <div className="page">
      <PageHeader
        title="Exposure"
        subtitle="Explainable exposure ranking, blast radius, privilege paths and the policies that decide flows"
      >
        <Tabs<Mode>
          label="Exposure views"
          idPrefix="exposure"
          value={mode}
          onChange={select}
          items={[
            { key: 'ranking', label: 'Ranked assets' },
            { key: 'asset', label: 'Asset' },
            { key: 'blast', label: 'Blast radius' },
            { key: 'iam', label: 'IAM paths' },
            { key: 'policies', label: 'Policies' },
          ]}
        />
      </PageHeader>
      <TabPanel idPrefix="exposure" activeKey={mode}>
        {mode === 'ranking' ? <ExposureRanking /> : null}
        {mode === 'asset' ? (
          object ? (
            <ExposureDetailView key={object} reference={object} />
          ) : (
            <RefPrompt
              label="Asset"
              button="Explain exposure"
              onSubmit={(ref) => setParams({ object: ref })}
            />
          )
        ) : null}
        {mode === 'blast' ? (
          blast ? (
            <BlastView key={blast} reference={blast} />
          ) : (
            <RefPrompt
              label="Principal or asset"
              button="Compute blast radius"
              onSubmit={(ref) => setParams({ blast: ref })}
            />
          )
        ) : null}
        {mode === 'iam' ? (
          iam ? (
            <IamPathsView key={iam} source={iam} />
          ) : (
            <RefPrompt
              label="Principal"
              button="Explore privilege paths"
              onSubmit={(ref) => setParams({ iam: ref })}
            />
          )
        ) : null}
        {mode === 'policies' ? (
          <div className="stack">
            <PolicyList selected={policy} onSelect={(id) => setParams({ policy: id })} />
            <PolicyAnalysisPanel />
            <EvaluatePanel />
          </div>
        ) : null}
      </TabPanel>
    </div>
  );
}
