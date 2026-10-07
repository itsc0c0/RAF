/**
 * Starts the shared R$F server for the tests that change nothing: a private temporary R$F home with
 * the demo workspace (`raf demo load --yes`) and `raf serve` on 127.0.0.1 and a free port, serving
 * the built workbench. Tests that change data start their own server (support/fixtures.ts).
 */
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { checkPrerequisites, ENV, startServer } from './support/server';

export default async function globalSetup(): Promise<void> {
  checkPrerequisites();
  // Every server of the run gets a directory in here; the global teardown removes it.
  const root = mkdtempSync(path.join(tmpdir(), 'raf-e2e-'));
  process.env[ENV.root] = root;
  const server = await startServer({ parent: root, name: 'shared' });
  process.env[ENV.baseURL] = server.baseURL;
}
