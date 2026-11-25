import { describe, expect, it } from 'vitest';

import { assignTemplateHref, assignedSessionId } from './provisioning-assign';

// #2046 (Codex P1 on #2367): the sessions list's Assign Template link carries
// identifiers a device reported. Built by hand, an EK serial such as
// `EK&sessionId=other-session` added its own sessionId key, and the create page
// fulfilled that other session. The link is encoded, and the reader refuses a
// link that names more than one session.

function parse(href: string) {
  return new URL(href, 'http://x');
}

describe('assignTemplateHref', () => {
  it('encodes reserved characters so a reported identifier cannot add a query key', () => {
    const url = parse(
      assignTemplateHref('42', {
        id: 'sess-1',
        ek_serial: 'EK&sessionId=other-session',
        mac_address: '02:00:00:00:00:01',
      })
    );

    expect(url.pathname).toBe('/devices/templates/42/create-profile');
    expect(url.searchParams.getAll('sessionId')).toEqual(['sess-1']);
    expect(url.searchParams.get('ekSerial')).toBe('EK&sessionId=other-session');
    expect(url.searchParams.get('macAddress')).toBe('02:00:00:00:00:01');
  });

  it('encodes the template id path segment', () => {
    const url = parse(assignTemplateHref('a/b?c', { id: 'sess-1' }));

    expect(url.pathname).toBe('/devices/templates/a%2Fb%3Fc/create-profile');
    expect(url.searchParams.getAll('sessionId')).toEqual(['sess-1']);
  });

  it('leaves out identifiers the session did not report', () => {
    const url = parse(assignTemplateHref('42', { id: 'sess-1', ek_serial: null }));

    expect(url.searchParams.has('ekSerial')).toBe(false);
    expect(url.searchParams.has('macAddress')).toBe(false);
    expect(url.searchParams.get('sessionId')).toBe('sess-1');
  });
});

describe('assignedSessionId', () => {
  it('reads the one session the link names', () => {
    expect(assignedSessionId(new URLSearchParams('sessionId=sess-1'))).toEqual({
      sessionId: 'sess-1',
      ambiguous: false,
    });
  });

  it('reads no session when the link names none', () => {
    expect(assignedSessionId(new URLSearchParams(''))).toEqual({ sessionId: '', ambiguous: false });
    expect(assignedSessionId(null)).toEqual({ sessionId: '', ambiguous: false });
  });

  it('refuses a link that names more than one session', () => {
    expect(assignedSessionId(new URLSearchParams('sessionId=other-session&sessionId=sess-1'))).toEqual({
      sessionId: '',
      ambiguous: true,
    });
  });

  it('reads an empty sessionId as no session', () => {
    expect(assignedSessionId(new URLSearchParams('sessionId='))).toEqual({ sessionId: '', ambiguous: false });
  });
});
