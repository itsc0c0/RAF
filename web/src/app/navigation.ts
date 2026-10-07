import type { IconName } from '../components/Icon';
import type { AppRoute } from '../lib/routes';

export interface NavItem {
  path: AppRoute;
  label: string;
  icon: IconName;
  description: string;
  /** Backing product(s); the nav marks the item when none of them is available. */
  products?: readonly string[];
}

export const NAV_ITEMS: readonly NavItem[] = [
  {
    path: '/',
    label: 'Overview',
    icon: 'overview',
    description: 'Workspace status, incidents, jobs, snapshots',
  },
  {
    path: '/investigate',
    label: 'Investigate',
    icon: 'investigate',
    description: 'Search, filter, group and trace (Lens, Trace)',
    products: ['trace', 'lens', 'timeline'],
  },
  {
    path: '/graph',
    label: 'Graph',
    icon: 'graph',
    description: 'Security relationship graph',
    products: ['graph'],
  },
  {
    path: '/replay',
    label: 'Replay',
    icon: 'replay',
    description: 'Replay incidents step by step',
    products: ['replay'],
  },
  {
    path: '/timeline',
    label: 'Timeline',
    icon: 'timeline',
    description: 'Unified event timelines',
    products: ['timeline'],
  },
  {
    path: '/exposure',
    label: 'Exposure',
    icon: 'exposure',
    description: 'Exposure ranking, blast radius, IAM paths',
    products: ['exposure', 'blast', 'iam'],
  },
  {
    path: '/ranges',
    label: 'Ranges',
    icon: 'ranges',
    description: 'Synthetic organizations',
    products: ['range'],
  },
  { path: '/labs', label: 'Labs', icon: 'labs', description: 'Isolated labs', products: ['lab'] },
  {
    path: '/evidence',
    label: 'Evidence',
    icon: 'evidence',
    description: 'Cases, items, custody',
    products: ['evidence'],
  },
  { path: '/findings', label: 'Findings', icon: 'findings', description: 'Triage findings across products' },
  { path: '/products', label: 'Products', icon: 'products', description: 'Product registry' },
  {
    path: '/settings',
    label: 'Settings',
    icon: 'settings',
    description: 'Configuration, workspaces, Oracle',
  },
];
