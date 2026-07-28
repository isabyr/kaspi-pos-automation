import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

const { runPool } = await import('../src/util/pool.js');

const tick = (ms = 5) => new Promise((r) => setTimeout(r, ms));

describe('runPool', () => {
  it('should process every item', async () => {
    const seen = [];
    await runPool([1, 2, 3, 4, 5], 2, async (n) => {
      await tick();
      seen.push(n);
    });
    assert.deepEqual(seen.sort(), [1, 2, 3, 4, 5]);
  });

  it('should never exceed the concurrency limit', async () => {
    let active = 0;
    let peak = 0;
    await runPool([1, 2, 3, 4, 5, 6, 7], 3, async () => {
      active++;
      peak = Math.max(peak, active);
      await tick();
      active--;
    });
    assert.equal(peak, 3);
  });

  it('should keep going when a worker throws', async () => {
    const done = [];
    await runPool([1, 2, 3, 4, 5], 2, async (n) => {
      await tick();
      if (n === 3) throw new Error('boom');
      done.push(n);
    });
    assert.deepEqual(done.sort(), [1, 2, 4, 5]);
  });

  it('should handle an empty list', async () => {
    let calls = 0;
    await runPool([], 5, async () => {
      calls++;
    });
    assert.equal(calls, 0);
  });

  it('should run serially when limit is 1', async () => {
    let active = 0;
    let peak = 0;
    await runPool([1, 2, 3], 1, async () => {
      active++;
      peak = Math.max(peak, active);
      await tick();
      active--;
    });
    assert.equal(peak, 1);
  });
});
