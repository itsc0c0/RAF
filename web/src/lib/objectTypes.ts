/**
 * Visual encoding of object types.
 *
 * Graph views scatter many types on one canvas (an "all pairs" form), so hue carries only three
 * validated families (assets, principals, activity) plus neutral; the exact type is carried by node
 * shape and by labels. See docs/web-ui.md, "Visual language".
 */

export type NodeFamily = 'asset' | 'principal' | 'activity' | 'neutral' | 'incident';

const FAMILY: Record<string, NodeFamily> = {
  host: 'asset',
  service: 'asset',
  cloud_resource: 'asset',
  container: 'asset',
  network: 'asset',
  project: 'asset',
  user: 'principal',
  identity: 'principal',
  group: 'principal',
  role: 'principal',
  permission: 'principal',
  organization: 'principal',
  process: 'activity',
  file: 'activity',
  directory: 'activity',
  session: 'activity',
  connection: 'activity',
  incident: 'incident',
};

export const FAMILY_LABELS: Record<NodeFamily, string> = {
  asset: 'Assets',
  principal: 'Principals',
  activity: 'Activity',
  neutral: 'Indicators & other',
  incident: 'Incident',
};

export function familyOf(type: string): NodeFamily {
  return FAMILY[type] ?? 'neutral';
}

/** Cytoscape node shapes (secondary encoding of the exact type). */
const SHAPES: Record<string, string> = {
  host: 'round-rectangle',
  service: 'cut-rectangle',
  cloud_resource: 'barrel',
  container: 'rhomboid',
  network: 'octagon',
  project: 'tag',
  user: 'ellipse',
  identity: 'round-diamond',
  group: 'hexagon',
  role: 'diamond',
  permission: 'vee',
  organization: 'round-pentagon',
  process: 'round-triangle',
  file: 'rectangle',
  directory: 'bottom-round-rectangle',
  session: 'round-octagon',
  connection: 'right-rhomboid',
  ip: 'round-hexagon',
  domain: 'pentagon',
  url: 'round-tag',
  port: 'heptagon',
  certificate: 'concave-hexagon',
  secret: 'star',
  vulnerability: 'triangle',
  package: 'round-heptagon',
  dependency: 'round-heptagon',
  policy: 'round-rectangle',
  alert: 'triangle',
  incident: 'ellipse',
};

export function shapeOf(type: string): string {
  return SHAPES[type] ?? 'ellipse';
}

/** Short human label for a type (`cloud_resource` -> `cloud resource`). */
export function typeLabel(type: string): string {
  return type.replace(/_/g, ' ');
}
