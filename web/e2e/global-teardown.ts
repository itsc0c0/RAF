/**
 * Stops the shared server by its PID (and any server a crashed test worker left running), then
 * removes the temporary directory of the run with every R$F home in it. Playwright also runs this
 * when the global setup failed halfway or the run was interrupted.
 */
import { ENV, stopServersUnder } from './support/server';

export default async function globalTeardown(): Promise<void> {
  const root = process.env[ENV.root];
  if (root) await stopServersUnder(root);
}
