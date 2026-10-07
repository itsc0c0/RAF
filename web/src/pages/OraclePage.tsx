import { useOracleStatus } from '../api/hooks';
import type { OracleStatus } from '../api/types';
import { Badge } from '../components/Badge';
import { KeyValueList, Mono } from '../components/Data';
import { Callout, PageHeader, Panel } from '../components/Panel';
import { QueryView } from '../components/States';
import { ORACLE_DISCLAIMER, OracleConversation } from '../features/oracle/OraclePanel';
import { displayValue } from '../lib/format';
import '../styles/oracle.css';

function yesNo(value: unknown): string {
  return value === true ? 'yes' : value === false ? 'no' : '—';
}

function StatusPanel() {
  const status = useOracleStatus();
  return (
    <Panel title="Provider">
      <QueryView query={status} feature="Oracle" compact>
        {(data: OracleStatus) => (
          <div className="stack">
            <div className="row row--wrap">
              <Badge tone={data.ready ? 'good' : 'warn'}>{data.ready ? 'READY' : 'NOT READY'}</Badge>
              <Mono>{displayValue(data.provider ?? 'unknown')}</Mono>
              {data.mode ? <span className="tag">{displayValue(data.mode)}</span> : null}
            </div>
            {data.detail ? <p className="small break">{displayValue(data.detail)}</p> : null}
            {data.warning ? (
              <Callout tone="warn" title="Transport">
                <span className="break">{displayValue(data.warning)}</span>
              </Callout>
            ) : null}
            {data.data_leaves_host ? (
              <Callout tone="warn" title="Data leaves this host">
                Retrieved facts are sent to the configured model server.
              </Callout>
            ) : null}
            <KeyValueList
              entries={[
                ['Enabled', yesNo(data.enabled)],
                ...(data.model !== undefined
                  ? ([['Model', <Mono>{displayValue(data.model ?? '—')}</Mono>]] as const)
                  : []),
                ...(data.base_url !== undefined
                  ? ([['Server', <Mono className="break">{displayValue(data.base_url)}</Mono>]] as const)
                  : []),
                ...(data.loopback !== undefined
                  ? ([['Loopback server', yesNo(data.loopback)]] as const)
                  : []),
                ...(data.api_key_configured !== undefined
                  ? ([['API key', data.api_key_configured ? 'set (never shown)' : 'not set']] as const)
                  : []),
                ['Facts per answer', displayValue(data.max_facts ?? '—')],
                ['Tools', <span className="break">{displayValue(data.tools ?? '—')}</span>],
                ['Stores answers', yesNo(data.stores_answers)],
              ]}
            />
          </div>
        )}
      </QueryView>
    </Panel>
  );
}

export default function OraclePage() {
  return (
    <div className="page oracle-page">
      <PageHeader
        title="Oracle"
        subtitle="Grounded answers about this workspace: every claim cites R$F data you can inspect"
      />
      <Callout tone="warn">
        <strong>{ORACLE_DISCLAIMER}</strong> Answers are built only from facts retrieved from this workspace.
        Imported text quoted in facts is untrusted data, labelled as such. References the answer makes that
        are not in R$F data are flagged and are not citations. Oracle changes nothing and stores no answers.
      </Callout>
      <div className="split split--wide-left">
        <Panel title="Ask">
          <OracleConversation examples wide />
        </Panel>
        <StatusPanel />
      </div>
    </div>
  );
}
