import { describe, expect, it } from 'vitest';
import { coerceSearchRequestNumbers } from '../src/graph-tools.js';

describe('coerceSearchRequestNumbers', () => {
  it('converts numeric-string size and from to numbers', () => {
    const out = coerceSearchRequestNumbers({
      requests: [{ entityTypes: ['chatMessage'], size: '25', from: '10' }],
    }) as { requests: Array<Record<string, unknown>> };

    expect(out.requests[0].size).toBe(25);
    expect(out.requests[0].from).toBe(10);
  });

  it('leaves real numbers untouched', () => {
    const out = coerceSearchRequestNumbers({ requests: [{ size: 25, from: 0 }] }) as {
      requests: Array<Record<string, unknown>>;
    };

    expect(out.requests[0].size).toBe(25);
    expect(out.requests[0].from).toBe(0);
  });

  it('does not invent fields that were not sent', () => {
    const out = coerceSearchRequestNumbers({
      requests: [{ query: { queryString: 'giri' } }],
    }) as { requests: Array<Record<string, unknown>> };

    expect(out.requests[0].size).toBeUndefined();
    expect(out.requests[0].from).toBeUndefined();
    expect(out.requests[0].query).toEqual({ queryString: 'giri' });
  });

  it('passes non-numeric strings through so validation still fails loudly', () => {
    const out = coerceSearchRequestNumbers({
      requests: [{ size: 'twenty five' }, { size: '25abc' }, { size: '' }, { size: '1.5' }],
    }) as { requests: Array<Record<string, unknown>> };

    expect(out.requests[0].size).toBe('twenty five');
    expect(out.requests[1].size).toBe('25abc');
    expect(out.requests[2].size).toBe('');
    expect(out.requests[3].size).toBe('1.5');
  });

  it('rejects integers beyond safe range rather than silently mangling them', () => {
    const out = coerceSearchRequestNumbers({ requests: [{ size: '99999999999999999999' }] }) as {
      requests: Array<Record<string, unknown>>;
    };

    expect(out.requests[0].size).toBe('99999999999999999999');
  });

  it('preserves sibling fields and other requests', () => {
    const out = coerceSearchRequestNumbers({
      extra: 'kept',
      requests: [
        { size: '5', query: { queryString: 'a' } },
        { size: 7, entityTypes: ['message'] },
      ],
    }) as { extra: string; requests: Array<Record<string, unknown>> };

    expect(out.extra).toBe('kept');
    expect(out.requests[0]).toEqual({ size: 5, from: undefined, query: { queryString: 'a' } });
    expect(out.requests[1].size).toBe(7);
    expect(out.requests[1].entityTypes).toEqual(['message']);
  });

  it('returns non-conforming shapes unchanged', () => {
    expect(coerceSearchRequestNumbers(undefined)).toBeUndefined();
    expect(coerceSearchRequestNumbers('nope')).toBe('nope');
    expect(coerceSearchRequestNumbers({ requests: 'not-an-array' })).toEqual({
      requests: 'not-an-array',
    });
    expect(coerceSearchRequestNumbers({ requests: ['scalar'] })).toEqual({ requests: ['scalar'] });
  });
});
