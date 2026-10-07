import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import ProtocolPage from '../../pages/ProtocolPage';
import { mockFetch, renderWithApp } from '../../test/utils';
import { fieldValue } from './ProtocolViews';

const UPLOAD = '6ff14b609e7cbb28010e696a45c1da5b';
const UPLOAD_INFO = {
  id: UPLOAD,
  name: 'raven-inc001.pcap',
  size: 23961,
  sha256: '6ff14b609e7cbb28010e696a45c1da5bac10dc2785b4f527ecbd898517f1216c',
};
const FILE = {
  name: 'raven-inc001.pcap',
  path: null,
  size: 23961,
  sha256: null,
  format: 'pcap',
  version: '2.4',
  link_types: ['Ethernet'],
};

/** Shape of GET /protocol/packet observed from `raf serve` (packet 20 of the malformed scenario). */
const PACKET = {
  upload: UPLOAD_INFO,
  file: FILE,
  number: 20,
  timestamp: '2026-10-07T12:00:00.209305Z',
  captured_length: 76,
  original_length: 76,
  interface: 0,
  link_type: 'Ethernet',
  flow_id: 7,
  flow: 'udp 10.10.1.21:53000 ↔ 10.10.0.5:53',
  protocols: ['eth', 'ip', 'udp', 'dns'],
  info: 'DNS response 0x1234 NOERROR [malformed]',
  tree: ['Ethernet  02:00:0a:0a:01:15 → 02:00:00:00:00:01', '└── IPv4  10.10.1.21 → 10.10.0.5 ttl=64 UDP'],
  layers: {
    name: 'Ethernet',
    summary: '02:00:0a:0a:01:15 → 02:00:00:00:00:01',
    malformed: null,
    fields: [
      {
        name: 'ethertype',
        value: 'IPv4 (0x0800)',
        explanation: 'EtherType: protocol carried (0x0800 IPv4, 0x86dd IPv6)',
      },
    ],
    children: [
      {
        name: 'IPv4',
        summary: '10.10.1.21 → 10.10.0.5 ttl=64 UDP',
        malformed: null,
        fields: [
          {
            name: 'ttl',
            value: 64,
            explanation: 'TTL: hop limit, decremented by each router; the packet is dropped at 0',
          },
          { name: 'flags', value: ['DF'], explanation: 'Flags: DF = do not fragment' },
        ],
        children: [
          {
            name: 'DNS',
            summary: 'response 0x1234 NOERROR',
            malformed: 'compression pointer loop',
            fields: [{ name: 'qname', value: '<b>evil</b>.example', explanation: 'Queried name' }],
            children: [],
          },
        ],
      },
    ],
  },
  malformed: ['DNS: compression pointer loop'],
};

describe('Protocol', () => {
  it('shows a packet with every decoded layer, explained fields and malformed markers', async () => {
    const user = userEvent.setup();
    const { calls } = mockFetch([
      {
        path: '/protocol/packet',
        body: (url: URL) => ({ ...PACKET, number: Number(url.searchParams.get('n')) }),
      },
      { path: '/protocol/inspect', body: { packets: { total: 74 } } },
    ]);
    const { router } = renderWithApp(<></>, {
      route: `/protocol?upload=${UPLOAD}&view=packet&packet=20`,
      extraRoutes: [{ path: 'protocol', element: <ProtocolPage /> }],
    });

    const ipv4 = await screen.findByRole('region', { name: 'IPv4 layer' });
    expect(within(ipv4).getByText('ttl')).toBeInTheDocument();
    expect(
      within(ipv4).getByText('TTL: hop limit, decremented by each router; the packet is dropped at 0'),
    ).toBeInTheDocument();
    expect(within(ipv4).getByText('DF')).toBeInTheDocument();
    const dns = screen.getByRole('region', { name: 'DNS layer' });
    expect(within(dns).getByText('MALFORMED')).toBeInTheDocument();
    expect(within(dns).getByText('<b>evil</b>.example')).toBeInTheDocument();
    expect(document.querySelector('.packet-layer b')).toBeNull();
    expect(screen.getByText('DNS: compression pointer loop')).toBeInTheDocument();

    const packetCall = calls.find((call) => call.path === '/protocol/packet')!;
    expect(packetCall.url.searchParams.get('upload')).toBe(UPLOAD);
    expect(packetCall.url.searchParams.get('n')).toBe('20');

    await user.click(screen.getByRole('button', { name: 'Next packet' }));
    await waitFor(() => expect(new URLSearchParams(router.state.location.search).get('packet')).toBe('21'));
  });

  it('formats decoded values as text', () => {
    expect(fieldValue(['PSH', 'ACK'])).toBe('PSH, ACK');
    expect(fieldValue(64)).toBe('64');
    expect(fieldValue(true)).toBe('yes');
    expect(fieldValue({ a: 1 })).toBe('{"a":1}');
  });
});
