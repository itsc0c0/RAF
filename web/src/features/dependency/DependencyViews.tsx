import { useMemo, useState } from 'react';
import {
  useAdvisories,
  useDependencyGraph,
  useDependencyProjects,
  useFindings,
  useVulnerablePackages,
} from '../../api/hooks';
import type { Advisory, DependencyProject, Finding, VulnerableAdvisory } from '../../api/types';
import { Badge, ConfidenceBadge, SeverityBadge } from '../../components/Badge';
import { Mono, Time } from '../../components/Data';
import { Checkbox } from '../../components/Form';
import { ObjectChip } from '../../components/ObjectChip';
import { Callout, Panel } from '../../components/Panel';
import { EmptyState, QueryView } from '../../components/States';
import { Table } from '../../components/Table';
import { displayValue, formatNumber, pluralize } from '../../lib/format';
import {
  buildDependencyTree,
  constraintFindings,
  countVulnerable,
  findingFor,
  type DependencyTreeNode,
} from './dependencyModel';

export const DEPENDENCY_CLI_NOTE =
  'Scans, SBOM imports and advisory imports read local paths, so they run from the CLI only (raf dependency scan, raf dependency sbom import, raf dependency advisories import); the API is read-only.';

export function ProjectsTable({
  selected,
  onSelect,
}: {
  selected: string | null;
  onSelect: (id: string) => void;
}) {
  const projects = useDependencyProjects();
  return (
    <QueryView query={projects} feature="Dependency">
      {(data) =>
        data.items.length === 0 ? (
          <div className="panel__pad">
            <EmptyState title="No projects scanned">
              <p>
                Scan a repository with <code>raf dependency scan PATH</code> or import an SBOM with{' '}
                <code>raf dependency sbom import FILE</code>.
              </p>
            </EmptyState>
          </div>
        ) : (
          <Table<DependencyProject>
            caption="Projects with dependency data"
            dense
            rows={data.items}
            rowKey={(project) => project.id}
            selectedKey={selected}
            onRowClick={(project) => onSelect(project.id)}
            rowLabel={(project) => `Show the dependency tree of ${project.name}`}
            columns={[
              {
                key: 'name',
                header: 'Project',
                render: (p) => (
                  <span className="stack stack--tight">
                    <strong className="dep-project__name">{p.name}</strong>
                    <span className="small muted">
                      {[p.ecosystems.join(', '), p.source].filter(Boolean).join(' · ')}
                    </span>
                    <Time value={p.last_scan} className="small muted" />
                  </span>
                ),
              },
              {
                key: 'packages',
                header: 'Packages',
                align: 'right',
                render: (p) => (
                  <span className="stack stack--tight">
                    <span className="tabular">{formatNumber(p.packages)}</span>
                    <span className="small muted tabular">
                      {formatNumber(p.direct)} direct · {formatNumber(p.dependencies)} declared
                    </span>
                  </span>
                ),
              },
              {
                key: 'findings',
                header: 'Findings',
                align: 'right',
                render: (p) =>
                  p.open_findings > 0 ? (
                    <Badge tone="bad" title={`${p.open_findings} open findings`}>
                      {formatNumber(p.open_findings)}
                    </Badge>
                  ) : (
                    <span className="muted" title="No open findings">
                      0
                    </span>
                  ),
              },
            ]}
          />
        )
      }
    </QueryView>
  );
}

function TreeNodeView({ node }: { node: DependencyTreeNode }) {
  const pkg = node.package;
  const vulnerabilities = pkg?.vulnerabilities ?? [];
  return (
    <li className="dep-tree__item">
      <div className="dep-tree__row row row--wrap">
        {pkg ? (
          <>
            <span className="tag">{pkg.ecosystem}</span>
            <ObjectChip id={pkg.id} name={`${pkg.name} ${pkg.version ?? '(unresolved)'}`} showType={false} />
            {pkg.direct === false ? <span className="small muted">transitive</span> : null}
            {pkg.scope && pkg.scope !== 'runtime' ? <span className="small muted">{pkg.scope}</span> : null}
          </>
        ) : (
          <Mono className="small">{node.id}</Mono>
        )}
        {vulnerabilities.map((id) => (
          <ObjectChip key={id} id={id} className="chip--bad" />
        ))}
        {node.cycle ? (
          <Badge tone="warn" outline title="Already above in this branch">
            CYCLE
          </Badge>
        ) : null}
        {node.repeated ? (
          <span className="small muted" title="Its dependencies are listed where it first appears">
            (dependencies listed above)
          </span>
        ) : null}
      </div>
      {node.children.length > 0 ? (
        <ul className="dep-tree">
          {node.children.map((child, index) => (
            <TreeNodeView key={`${index}:${child.id}`} node={child} />
          ))}
        </ul>
      ) : null}
    </li>
  );
}

/** `GET /dependency/projects/{ref}/graph` as a tree (direct → transitive), advisories marked. */
export function ProjectTree({ projectRef }: { projectRef: string }) {
  const query = useDependencyGraph(projectRef);
  return (
    <QueryView query={query} feature="Dependency graph" loadingLabel="Loading dependency tree…">
      {(graph) => {
        const tree = buildDependencyTree(graph);
        const vulnerable = countVulnerable(tree);
        return (
          <Panel
            title={
              <span className="row row--wrap">
                <span className="break">{graph.project.name}</span>
                <span className="small muted">
                  {pluralize(graph.packages.length, 'package')} ·{' '}
                  {vulnerable > 0 ? `${vulnerable} with advisories` : 'no advisories matched'}
                </span>
              </span>
            }
            actions={<ObjectChip id={graph.project.id} name={graph.project.name} />}
          >
            {tree.length === 0 ? (
              <p className="muted small">The project has no resolved dependencies.</p>
            ) : (
              <ul className="dep-tree dep-tree--root" aria-label={`Dependency tree of ${graph.project.name}`}>
                {tree.map((node, index) => (
                  <TreeNodeView key={`${index}:${node.id}`} node={node} />
                ))}
              </ul>
            )}
            <p className="small muted">
              Declared dependencies without a resolved version are not packages yet; constraint matches for
              them are listed under “Vulnerable packages”.
            </p>
          </Panel>
        );
      }}
    </QueryView>
  );
}

interface VulnerableRow {
  key: string;
  packageId: string;
  ecosystem: string;
  name: string;
  version: string | null;
  advisory: VulnerableAdvisory;
  projects: string[];
  finding: Finding | null;
}

function ConfidenceCell({ finding }: { finding: Finding | null }) {
  if (!finding) {
    return (
      <span className="small muted" title="No finding records this match (run raf dependency check)">
        —
      </span>
    );
  }
  return <ConfidenceBadge confidence={finding.confidence} level={finding.confidence_level} />;
}

export function VulnerablePackagesView({ onOpenFinding }: { onOpenFinding: (id: string) => void }) {
  const [includeUnused, setIncludeUnused] = useState(false);
  const vulnerable = useVulnerablePackages(includeUnused);
  const findings = useFindings({ product: 'dependency', status: ['OPEN', 'ACKNOWLEDGED'], limit: 500 });
  const findingItems = useMemo(() => findings.data?.items ?? [], [findings.data]);
  return (
    <Panel
      title="Vulnerable packages"
      flush
      actions={
        <Checkbox
          label="Include packages no project uses any more"
          checked={includeUnused}
          onChange={setIncludeUnused}
        />
      }
    >
      <QueryView query={vulnerable} feature="Dependency">
        {(data) => {
          // constraint-only matches are listed below with their findings
          const exact = data.items.filter((item) => item.basis !== 'constraint');
          const rows: VulnerableRow[] = exact.flatMap((item) =>
            item.advisories.map((advisory) => ({
              key: `${item.package.id}|${advisory.id}`,
              packageId: item.package.id,
              ecosystem: item.package.ecosystem,
              name: item.package.name,
              version: item.package.version,
              advisory,
              projects: item.projects,
              finding: findingFor(findingItems, item.package.id, advisory.id),
            })),
          );
          const constraints = constraintFindings(findingItems);
          return (
            <div className="stack">
              <Table<VulnerableRow>
                caption="Packages matched by advisories"
                rows={rows}
                rowKey={(row) => row.key}
                empty={<span className="muted">No package matches an imported advisory.</span>}
                columns={[
                  {
                    key: 'severity',
                    header: 'Severity',
                    render: (r) => <SeverityBadge severity={r.finding?.severity ?? r.advisory.severity} />,
                  },
                  {
                    key: 'confidence',
                    header: 'Confidence',
                    render: (r) => <ConfidenceCell finding={r.finding} />,
                  },
                  {
                    key: 'advisory',
                    header: 'Advisory',
                    render: (r) => (
                      <span className="stack stack--tight">
                        <span className="row row--wrap">
                          <Mono>{r.advisory.id}</Mono>
                          {r.advisory.cvss !== null ? (
                            <span className="small muted">CVSS {r.advisory.cvss}</span>
                          ) : null}
                        </span>
                        <span className="small break">{r.advisory.summary}</span>
                      </span>
                    ),
                  },
                  {
                    key: 'package',
                    header: 'Package',
                    render: (r) => (
                      <span className="row row--wrap">
                        <span className="tag">{r.ecosystem}</span>
                        <ObjectChip
                          id={r.packageId}
                          name={`${r.name} ${r.version ?? ''}`.trim()}
                          showType={false}
                        />
                      </span>
                    ),
                  },
                  {
                    key: 'fixed',
                    header: 'Fixed in',
                    render: (r) => <Mono className="small">{r.advisory.fixed.join(', ') || '—'}</Mono>,
                  },
                  {
                    key: 'why',
                    header: 'Why it matches',
                    render: (r) => <span className="small break">{r.advisory.reason}</span>,
                  },
                  {
                    key: 'projects',
                    header: 'Projects',
                    render: (r) => (
                      <span className="row row--wrap">
                        {r.projects.map((id) => (
                          <ObjectChip key={id} id={id} showType={false} />
                        ))}
                      </span>
                    ),
                  },
                  {
                    key: 'finding',
                    header: 'Finding',
                    render: (r) =>
                      r.finding ? (
                        <button
                          type="button"
                          className="link-btn"
                          onClick={() => onOpenFinding(r.finding!.id)}
                          title={r.finding.title}
                        >
                          Open
                        </button>
                      ) : (
                        <span className="muted">—</span>
                      ),
                  },
                ]}
              />
              {constraints.length > 0 ? (
                <div className="panel__pad stack stack--tight">
                  <h4>Declared constraints that may match (no resolved version)</h4>
                  <Table<Finding>
                    caption="Constraint matches"
                    dense
                    rows={constraints}
                    rowKey={(finding) => finding.id}
                    onRowClick={(finding) => onOpenFinding(finding.id)}
                    rowLabel={(finding) => `Open finding ${finding.title}`}
                    columns={[
                      {
                        key: 'severity',
                        header: 'Severity',
                        render: (f) => <SeverityBadge severity={f.severity} />,
                      },
                      {
                        key: 'confidence',
                        header: 'Confidence',
                        render: (f) => (
                          <ConfidenceBadge confidence={f.confidence} level={f.confidence_level} />
                        ),
                      },
                      {
                        key: 'title',
                        header: 'Finding',
                        render: (f) => <span className="break">{f.title}</span>,
                      },
                      {
                        key: 'constraint',
                        header: 'Constraint',
                        render: (f) => (
                          <Mono className="small">{displayValue(f.metadata.constraint ?? '—')}</Mono>
                        ),
                      },
                    ]}
                  />
                </div>
              ) : null}
              <p className="small muted panel__pad">
                Severity and confidence come from the recorded findings (the match basis decides confidence:
                an exact version is likelier than a declared range). Advisories are imported OSV data, matched
                offline.
              </p>
            </div>
          );
        }}
      </QueryView>
    </Panel>
  );
}

export function AdvisoriesTable() {
  const advisories = useAdvisories();
  return (
    <Panel title="Advisories" flush>
      <QueryView query={advisories} feature="Dependency advisories">
        {(data) => (
          <Table<Advisory>
            caption="Imported advisories"
            dense
            rows={data.items}
            rowKey={(advisory) => advisory.id}
            empty={
              <span className="muted">
                No advisories imported (<code>raf dependency advisories import FILE</code>).
              </span>
            }
            columns={[
              { key: 'severity', header: 'Severity', render: (a) => <SeverityBadge severity={a.severity} /> },
              {
                key: 'id',
                header: 'Advisory',
                render: (a) => (
                  <span className="stack stack--tight">
                    <Mono>{a.id}</Mono>
                    {a.aliases.length > 0 ? (
                      <span className="small muted">{a.aliases.join(', ')}</span>
                    ) : null}
                  </span>
                ),
              },
              {
                key: 'summary',
                header: 'Summary',
                render: (a) => <span className="break">{a.summary}</span>,
              },
              {
                key: 'affected',
                header: 'Affected',
                render: (a) => (
                  <ul className="stack stack--tight">
                    {a.affected.map((entry, index) => (
                      <li key={index} className="small">
                        <span className="mono">
                          {entry.ecosystem}/{entry.name}
                        </span>{' '}
                        <span className="muted">{entry.ranges}</span>
                        {entry.fixed.length > 0 ? (
                          <span className="muted"> · fixed {entry.fixed.join(', ')}</span>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                ),
              },
              {
                key: 'cvss',
                header: 'CVSS',
                align: 'right',
                render: (a) => (a.cvss !== null ? a.cvss : <span className="muted">—</span>),
              },
              {
                key: 'withdrawn',
                header: 'Withdrawn',
                render: (a) =>
                  a.withdrawn ? (
                    <Time value={a.withdrawn} className="small" />
                  ) : (
                    <span className="muted">—</span>
                  ),
              },
            ]}
          />
        )}
      </QueryView>
    </Panel>
  );
}

export function DependencyView({
  project,
  onProject,
  onOpenFinding,
}: {
  project: string | null;
  onProject: (id: string) => void;
  onOpenFinding: (id: string) => void;
}) {
  return (
    <div className="stack">
      <Callout tone="info">{DEPENDENCY_CLI_NOTE}</Callout>
      <div className="split split--narrow-left">
        <Panel title="Projects" flush>
          <ProjectsTable selected={project} onSelect={onProject} />
        </Panel>
        <div>
          {project ? (
            <ProjectTree key={project} projectRef={project} />
          ) : (
            <Panel>
              <EmptyState title="Select a project">
                <p>The tree shows direct and transitive dependencies with the advisories that match them.</p>
              </EmptyState>
            </Panel>
          )}
        </div>
      </div>
      <VulnerablePackagesView onOpenFinding={onOpenFinding} />
      <AdvisoriesTable />
    </div>
  );
}
