import { describe, expect, it } from 'vitest';
import { eventLogBytes, eventLogFileName, summarizeEventLog } from './use-tpm-eventlog';
import { base64ToHex, textToBase64 } from './use-tpm-ops';

describe('eventLogBytes', () => {
  it('decodes the base64 log the server returns', () => {
    expect(Array.from(eventLogBytes('AAECAw=='))).toEqual([0, 1, 2, 3]);
  });

  it('is empty for an absent or invalid log', () => {
    expect(eventLogBytes(undefined)).toHaveLength(0);
    expect(eventLogBytes('')).toHaveLength(0);
    expect(eventLogBytes('%%%not base64%%%')).toHaveLength(0);
  });
});

describe('eventLogFileName', () => {
  it('names the download after the format, tcg2 by default', () => {
    expect(eventLogFileName('tcg1')).toBe('tpm-eventlog-tcg1.bin');
    expect(eventLogFileName('')).toBe('tpm-eventlog-tcg2.bin');
    expect(eventLogFileName(undefined)).toBe('tpm-eventlog-tcg2.bin');
  });
});

describe('summarizeEventLog', () => {
  it('uses the server event count when entries are not parsed', () => {
    expect(summarizeEventLog({ eventLog: 'AA==', format: 'tcg2', eventCount: 42 })).toEqual({
      total: 42,
      format: 'tcg2',
      pcrsTouched: 0,
      mostMeasured: undefined,
    });
  });

  it('counts entries per PCR when the server parses them', () => {
    const summary = summarizeEventLog({
      eventLog: '',
      format: '',
      eventCount: 0,
      entries: [
        { pcrIndex: 0 },
        { pcrIndex: 7 },
        { pcrIndex: 7 },
      ] as never,
    });
    expect(summary.total).toBe(3);
    expect(summary.format).toBe('tcg2');
    expect(summary.pcrsTouched).toBe(2);
    expect(summary.mostMeasured).toEqual([7, 2]);
  });

  it('is empty before the log loads', () => {
    expect(summarizeEventLog(null)).toEqual({
      total: 0,
      format: 'tcg2',
      pcrsTouched: 0,
      mostMeasured: undefined,
    });
  });
});

describe('use-tpm-ops helpers', () => {
  it('round-trips text to hex', () => {
    expect(base64ToHex(textToBase64('AB'))).toBe('4142');
    expect(base64ToHex('%%%')).toBe('');
  });
});
