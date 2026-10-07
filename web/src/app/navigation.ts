import type { IconName } from '../components/Icon';
import type { AppRoute } from '../lib/routes';

export interface NavItem {
  path: AppRoute;
  label: string;
  icon: IconName;
  description: string;
  /** Backing product(s); the nav marks the item when none of them is available. */
  products?: readonly string[];
  /** Section heading in the left navigation (follows the product categories). */
  group: NavGroup;
}

export type NavGroup = 'Workspace' | 'Investigation' | 'Exposure' | 'Synthetic' | 'Analysis' | 'Platform';

export const NAV_GROUPS: readonly NavGroup[] = [
  'Workspace',
  'Investigation',
  'Exposure',
  'Synthetic',
  'Analysis',
  'Platform',
];

export const NAV_ITEMS: readonly NavItem[] = [
  {
    path: '/',
    label: 'Overview',
    icon: 'overview',
    description: 'Workspace status, incidents, jobs, snapshots',
    group: 'Workspace',
  },
  {
    path: '/findings',
    label: 'Findings',
    icon: 'findings',
    description: 'Triage findings across products, secrets (Vault) and dependencies',
    group: 'Workspace',
  },
  {
    path: '/investigate',
    label: 'Investigate',
    icon: 'investigate',
    description: 'Search, filter, group and trace (Lens, Trace)',
    products: ['trace', 'lens', 'timeline'],
    group: 'Investigation',
  },
  {
    path: '/graph',
    label: 'Graph',
    icon: 'graph',
    description: 'Security relationship graph',
    products: ['graph'],
    group: 'Investigation',
  },
  {
    path: '/replay',
    label: 'Replay',
    icon: 'replay',
    description: 'Replay incidents step by step',
    products: ['replay'],
    group: 'Investigation',
  },
  {
    path: '/timeline',
    label: 'Timeline',
    icon: 'timeline',
    description: 'Unified event timelines',
    products: ['timeline'],
    group: 'Investigation',
  },
  {
    path: '/analyses',
    label: 'Analyses',
    icon: 'analyses',
    description: 'Analyze files (upload) and review every analysis step',
    group: 'Investigation',
  },
  {
    path: '/diff',
    label: 'Diff',
    icon: 'diff',
    description: 'Snapshots and what changed between security states',
    products: ['diff'],
    group: 'Investigation',
  },
  {
    path: '/exposure',
    label: 'Exposure',
    icon: 'exposure',
    description: 'Exposure ranking, blast radius, IAM paths, policies',
    products: ['exposure', 'blast', 'iam', 'policy'],
    group: 'Exposure',
  },
  {
    path: '/surface',
    label: 'Surface',
    icon: 'surface',
    description: 'Authorized external attack surface from imported inventories (no scanning)',
    products: ['surface'],
    group: 'Exposure',
  },
  {
    path: '/ghost',
    label: 'Ghost',
    icon: 'ghost',
    description: 'What-if models: simulate and compare changes',
    products: ['ghost'],
    group: 'Synthetic',
  },
  {
    path: '/ranges',
    label: 'Ranges',
    icon: 'ranges',
    description: 'Synthetic organizations',
    products: ['range'],
    group: 'Synthetic',
  },
  {
    path: '/lab',
    label: 'Lab',
    icon: 'labs',
    description: 'Isolated container labs',
    products: ['lab'],
    group: 'Synthetic',
  },
  {
    path: '/protocol',
    label: 'Protocol',
    icon: 'protocol',
    description: 'Packet captures: summary, flows, explained packets',
    products: ['protocol'],
    group: 'Analysis',
  },
  {
    path: '/evidence',
    label: 'Evidence',
    icon: 'evidence',
    description: 'Cases, items, custody',
    products: ['evidence'],
    group: 'Analysis',
  },
  {
    path: '/oracle',
    label: 'Oracle',
    icon: 'oracle',
    description: 'Grounded answers about this workspace, with citations',
    products: ['oracle'],
    group: 'Analysis',
  },
  {
    path: '/products',
    label: 'Products',
    icon: 'products',
    description: 'Product registry',
    group: 'Platform',
  },
  {
    path: '/settings',
    label: 'Settings',
    icon: 'settings',
    description: 'Configuration, workspaces, access token, Oracle',
    group: 'Platform',
  },
];
