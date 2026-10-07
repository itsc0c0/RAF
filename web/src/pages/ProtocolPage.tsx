import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useCaptureSummary } from '../api/hooks';
import { Callout, PageHeader, Panel } from '../components/Panel';
import { TabPanel, Tabs } from '../components/Tabs';
import {
  CaptureSummaryView,
  CaptureUploadForm,
  FlowsView,
  NO_FILTERS,
  NoCapture,
  OpenUploadForm,
  PacketView,
  UPLOAD_ID_RE,
  type CaptureFilterState,
} from '../features/protocol/ProtocolViews';
import '../styles/protocol.css';

type View = 'summary' | 'flows' | 'packet';

function readView(value: string | null): View {
  return value === 'flows' || value === 'packet' ? value : 'summary';
}

function readPacket(value: string | null): number {
  const n = Number(value);
  return Number.isInteger(n) && n >= 1 ? n : 1;
}

/** Total packet count of the capture (from the cached unfiltered summary) for the packet navigator. */
function usePacketTotal(upload: string | null): number | null {
  const summary = useCaptureSummary(upload, { limit: 50 });
  return summary.data?.packets.total ?? null;
}

export default function ProtocolPage() {
  const [params, setParams] = useSearchParams();
  const rawUpload = params.get('upload');
  const upload = rawUpload && UPLOAD_ID_RE.test(rawUpload) ? rawUpload : null;
  const view = readView(params.get('view'));
  const packet = readPacket(params.get('packet'));
  const [filters, setFilters] = useState<CaptureFilterState>(NO_FILTERS);
  const total = usePacketTotal(upload);

  const go = (next: { upload?: string | null; view?: View; packet?: number }) => {
    const search = new URLSearchParams();
    const target = next.upload === undefined ? upload : next.upload;
    if (target) search.set('upload', target);
    const nextView = next.view ?? view;
    if (target && nextView !== 'summary') search.set('view', nextView);
    if (target && nextView === 'packet') search.set('packet', String(next.packet ?? packet));
    setParams(search);
  };

  return (
    <div className="page">
      <PageHeader
        title="Protocol"
        subtitle="Saved packet captures explained: protocols, flows with client/server inference, DNS/HTTP/TLS metadata and every decoded field"
      />
      <div className="grid-2">
        <Panel title="Upload a capture">
          <CaptureUploadForm
            onUploaded={(summary) => {
              setFilters(NO_FILTERS);
              go({ upload: summary.upload.id, view: 'summary' });
            }}
          />
        </Panel>
        <Panel title="Open an earlier upload">
          <OpenUploadForm
            onOpen={(id) => {
              setFilters(NO_FILTERS);
              go({ upload: id, view: 'summary' });
            }}
          />
        </Panel>
      </div>
      {rawUpload && !upload ? (
        <Callout tone="bad" title="Invalid upload ID">
          Upload IDs are 32 hexadecimal characters.
        </Callout>
      ) : null}
      {upload ? (
        <>
          <Tabs<View>
            label="Capture views"
            idPrefix="protocol"
            value={view}
            onChange={(next) => go({ view: next })}
            items={[
              { key: 'summary', label: 'Summary' },
              { key: 'flows', label: 'Flows' },
              { key: 'packet', label: 'Packet' },
            ]}
          />
          <TabPanel idPrefix="protocol" activeKey={view}>
            {view === 'summary' ? (
              <CaptureSummaryView key={upload} upload={upload} filters={filters} onFilters={setFilters} />
            ) : null}
            {view === 'flows' ? <FlowsView key={upload} upload={upload} /> : null}
            {view === 'packet' ? (
              <PacketView
                key={`${upload}:${packet}`}
                upload={upload}
                packet={packet}
                total={total}
                onPacket={(n) => go({ view: 'packet', packet: n })}
              />
            ) : null}
          </TabPanel>
        </>
      ) : (
        <Panel>
          <NoCapture />
        </Panel>
      )}
    </div>
  );
}
