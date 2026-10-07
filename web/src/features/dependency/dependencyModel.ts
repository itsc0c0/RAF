/** Pure helpers for Dependency views: the project tree and advisory ↔ finding matching. */
import type { DependencyGraph, DependencyPackage, Finding } from '../../api/types';

export interface DependencyTreeNode {
  id: string;
  package: DependencyPackage | null;
  children: DependencyTreeNode[];
  /** The package already appears above in this branch (a dependency cycle): not expanded again. */
  cycle: boolean;
  /** The package was expanded elsewhere in the tree: listed, not expanded again. */
  repeated: boolean;
}

function byName(packages: Map<string, DependencyPackage>) {
  return (a: string, b: string) => {
    const pa = packages.get(a);
    const pb = packages.get(b);
    const ka = pa ? `${pa.ecosystem}/${pa.name}@${pa.version ?? ''}` : a;
    const kb = pb ? `${pb.ecosystem}/${pb.name}@${pb.version ?? ''}` : b;
    return ka.localeCompare(kb);
  };
}

/**
 * The dependency tree of a project from `{project, packages, edges}`: direct dependencies under the
 * project, transitive ones under the package that requires them. Cycles and repeated subtrees are
 * marked instead of expanded, so the tree stays finite and small.
 */
export function buildDependencyTree(graph: DependencyGraph, maxNodes = 2000): DependencyTreeNode[] {
  const packages = new Map(graph.packages.map((pkg) => [pkg.id, pkg]));
  const children = new Map<string, string[]>();
  for (const edge of graph.edges) {
    if (edge.type !== 'DEPENDS_ON') continue;
    const list = children.get(edge.source) ?? [];
    if (!list.includes(edge.target)) list.push(edge.target);
    children.set(edge.source, list);
  }
  const compare = byName(packages);
  const expanded = new Set<string>();
  let budget = maxNodes;

  const visit = (id: string, path: ReadonlySet<string>): DependencyTreeNode => {
    budget -= 1;
    const node: DependencyTreeNode = {
      id,
      package: packages.get(id) ?? null,
      children: [],
      cycle: path.has(id),
      repeated: false,
    };
    if (node.cycle) return node;
    if (expanded.has(id)) {
      node.repeated = (children.get(id) ?? []).length > 0;
      return node;
    }
    expanded.add(id);
    const next = new Set(path).add(id);
    for (const child of [...(children.get(id) ?? [])].sort(compare)) {
      if (budget <= 0) break;
      node.children.push(visit(child, next));
    }
    return node;
  };

  const tree: DependencyTreeNode[] = [];
  for (const id of [...(children.get(graph.project.id) ?? [])].sort(compare)) {
    if (budget <= 0) break;
    tree.push(visit(id, new Set([graph.project.id])));
  }
  return tree;
}

export function countVulnerable(nodes: readonly DependencyTreeNode[]): number {
  let total = 0;
  for (const node of nodes) {
    if ((node.package?.vulnerabilities ?? []).length > 0) total += 1;
    total += countVulnerable(node.children);
  }
  return total;
}

/**
 * The recorded finding of a vulnerable package match: `GET /dependency/vulnerable` carries no
 * confidence, the dependency findings do (`metadata.advisory` + the package in `affected_objects`).
 */
export function findingFor(
  findings: readonly Finding[],
  packageId: string,
  advisory: string,
): Finding | null {
  return (
    findings.find(
      (finding) => finding.metadata.advisory === advisory && finding.affected_objects.includes(packageId),
    ) ?? null
  );
}

/** Findings for declared constraints that may match an advisory (no resolved version). */
export function constraintFindings(findings: readonly Finding[]): Finding[] {
  return findings.filter((finding) => finding.metadata.basis === 'constraint');
}
