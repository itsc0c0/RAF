import { useSearchParams } from 'react-router-dom';
import { useLabs, useLabStatus } from '../api/hooks';
import { PageHeader, Panel } from '../components/Panel';
import { isUnavailableError, UnavailableState } from '../components/States';
import { BackendStatus, CreateLabForm, LabDrawer, LabTable, NoExecNotice } from '../features/lab/LabViews';
import '../styles/lab.css';

export default function LabPage() {
  const [params, setParams] = useSearchParams();
  const selected = params.get('lab');
  const status = useLabStatus();
  const labs = useLabs();
  const header = (
    <PageHeader
      title="Lab"
      subtitle="Isolated container labs for experiments: no network, no capabilities and a read-only root filesystem by default; host files enter only as read-only mounts"
    />
  );
  if (isUnavailableError(labs.error) && (status.isError || !status.data)) {
    return (
      <div className="page">
        {header}
        <UnavailableState feature="Lab" error={labs.error} />
      </div>
    );
  }
  return (
    <div className="page">
      {header}
      <div className="grid-2">
        <BackendStatus />
        <Panel title="Running commands">
          <NoExecNotice />
        </Panel>
      </div>
      <Panel title="New lab">
        <CreateLabForm onCreated={(lab) => setParams({ lab: lab.name })} />
      </Panel>
      <Panel title="Labs" flush>
        <LabTable selected={selected} onOpen={(name) => setParams({ lab: name })} />
      </Panel>
      {selected ? <LabDrawer key={selected} name={selected} onClose={() => setParams({})} /> : null}
    </div>
  );
}
