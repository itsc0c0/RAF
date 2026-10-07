import { describe, expect, it } from 'vitest';
import { routeTo, toInternalRoute } from './routes';

describe('toInternalRoute (pivot views are data)', () => {
  it('accepts every pivot the backend produces and encodes raw object IDs', () => {
    expect(toInternalRoute('/graph?focus=host:ws-04')).toBe('/graph?focus=host%3Aws-04');
    expect(toInternalRoute('/timeline?object=incident:inc-001')).toBe('/timeline?object=incident%3Ainc-001');
    expect(toInternalRoute('/replay?incident=incident:inc-001')).toBe('/replay?incident=incident%3Ainc-001');
    expect(toInternalRoute('/investigate?trace=file:app-01|/usr/bin/curl')).toBe(
      '/investigate?trace=file%3Aapp-01%7C%2Fusr%2Fbin%2Fcurl',
    );
    expect(toInternalRoute('/exposure?blast=user:alice')).toBe('/exposure?blast=user%3Aalice');
    expect(toInternalRoute('/evidence?object=host:db-01')).toBe('/evidence?object=host%3Adb-01');
  });

  it('keeps IDs containing &, +, # and = intact', () => {
    const route = toInternalRoute('/graph?focus=url:https://x.example/?a=1&b=2+3#frag');
    expect(route).toBe(`/graph?focus=${encodeURIComponent('url:https://x.example/?a=1&b=2+3#frag')}`);
    const params = new URLSearchParams(route!.split('?')[1]);
    expect(params.get('focus')).toBe('url:https://x.example/?a=1&b=2+3#frag');
  });

  it('rejects anything that is not an internal route', () => {
    for (const view of [
      'javascript:alert(1)',
      'JAVASCRIPT:alert(1)',
      'https://evil.example/graph',
      '//evil.example/graph',
      '/\\evil.example',
      '\\\\evil',
      '/admin',
      '/graph/../../etc',
      'graph?focus=x',
      '/graph\n?focus=x',
      '',
      null,
      42,
    ]) {
      expect(toInternalRoute(view)).toBeNull();
    }
  });

  it('normalizes trailing slashes and other query strings', () => {
    expect(toInternalRoute('/findings/')).toBe('/findings');
    expect(toInternalRoute('/')).toBe('/');
    expect(toInternalRoute('/timeline?start=2026-10-06T22:00:00Z&type=auth.login')).toBe(
      '/timeline?start=2026-10-06T22%3A00%3A00Z&type=auth.login',
    );
  });

  it('builds encoded routes for UI pivots', () => {
    expect(routeTo.graph('host:ws-04')).toBe('/graph?focus=host%3Aws-04');
    expect(routeTo.graph()).toBe('/graph');
    expect(routeTo.trace('a&b')).toBe('/investigate?trace=a%26b');
    expect(new URLSearchParams(routeTo.timeline('user:a+b').split('?')[1]).get('object')).toBe('user:a+b');
  });

  it('knows the new views and the manifest routes (/lab, /surface, /range, /oracle...)', () => {
    for (const route of [
      '/lab',
      '/analyses',
      '/diff',
      '/ghost',
      '/protocol',
      '/oracle',
      '/surface',
      '/range',
      '/labs',
    ]) {
      expect(toInternalRoute(route)).toBe(route);
    }
    expect(toInternalRoute('/surface?view=scope')).toBe('/surface?view=scope');
    expect(routeTo.analysis('analysis-3')).toBe('/analyses?analysis=analysis-3');
    expect(routeTo.diff('a', 'ghost:exp')).toBe('/diff?a=a&b=ghost%3Aexp');
    expect(routeTo.ghost('exp', 'compare')).toBe('/ghost?model=exp&view=compare');
    expect(routeTo.policy('raven-fw')).toBe('/exposure?policy=raven-fw');
    expect(
      new URLSearchParams(routeTo.dependencyProject('project:/srv/a&b').split('?')[1]).get('project'),
    ).toBe('project:/srv/a&b');
  });
});
