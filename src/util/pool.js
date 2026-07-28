import { logger } from '../logger.js';

/**
 * Выполняет worker(item) для каждого элемента, но не более `limit` одновременно.
 * Ошибка одного элемента не останавливает остальные — она логируется и пропускается.
 */
export const runPool = async (items, limit, worker) => {
  const queue = [...items];
  const workers = Math.max(1, Math.min(limit, queue.length));

  await Promise.all(
    Array.from({ length: workers }, async () => {
      while (queue.length) {
        const item = queue.shift();
        try {
          await worker(item);
        } catch (err) {
          logger.error('POOL', 'Worker failed', err.message);
        }
      }
    }),
  );
};
