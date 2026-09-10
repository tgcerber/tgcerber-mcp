#!/usr/bin/env node
/**
 * tgcerber-mcp — the local bridge.
 *
 * Runs as an MCP server over stdio for Claude Desktop or Claude Code. stdout is the protocol, so
 * every diagnostic goes to stderr.
 *
 * Configuration is environment-only, because MCP clients launch this process with no terminal:
 *   TGCERBER_ARCHIVE_URL          the archive endpoint from the console (required)
 *   TGCERBER_TOKEN                the connection token from the console (required)
 *   TGCERBER_VAULT_PASSWORD       the organization archive password (this, or the next)
 *   TGCERBER_VAULT_PASSWORD_FILE  a file whose first line is that password
 *   TGCERBER_REFRESH_SECONDS      how often to re-fetch the archive list while serving (default 30)
 *
 * `--check` fetches the bundle, unwraps the key, prints what is readable, and exits — a way to
 * verify the setup before involving an MCP client.
 */
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createServer } from './server.js';
import { Vault, WrongPasswordError, fetchBundle } from './vault.js';

const VERSION: string = (createRequire(import.meta.url)('../package.json') as { version: string }).version;

function fail(message: string): never {
  process.stderr.write(`tgcerber-mcp: ${message}\n`);
  process.exit(1);
}

function config(): { archiveUrl: string; token: string; password: string; refreshMs: number } {
  const archiveUrl = process.env['TGCERBER_ARCHIVE_URL']?.trim();
  const token = process.env['TGCERBER_TOKEN']?.trim();
  let password = process.env['TGCERBER_VAULT_PASSWORD'];
  const passwordFile = process.env['TGCERBER_VAULT_PASSWORD_FILE']?.trim();
  if (!password && passwordFile) {
    try {
      password = readFileSync(passwordFile, 'utf8').split(/\r?\n/)[0];
    } catch {
      fail(`cannot read TGCERBER_VAULT_PASSWORD_FILE (${passwordFile})`);
    }
  }
  if (!archiveUrl) fail('TGCERBER_ARCHIVE_URL is not set');
  if (!token) fail('TGCERBER_TOKEN is not set');
  if (!password) fail('set TGCERBER_VAULT_PASSWORD or TGCERBER_VAULT_PASSWORD_FILE');
  const refreshSeconds = Number(process.env['TGCERBER_REFRESH_SECONDS'] ?? '30');
  const refreshMs = Number.isFinite(refreshSeconds) && refreshSeconds >= 5 ? refreshSeconds * 1000 : 30_000;
  return { archiveUrl, token, password, refreshMs };
}

async function open(): Promise<Vault> {
  const { archiveUrl, token, password, refreshMs } = config();
  const bundle = await fetchBundle(archiveUrl, token);
  try {
    // The bundle is fetched again while serving, so an archive that grows after the bridge started
    // — the live tap seals messages every few seconds — is read as it is now, not as it was.
    return await Vault.open(bundle, password, { refetch: () => fetchBundle(archiveUrl, token), refreshMs });
  } catch (error) {
    if (error instanceof WrongPasswordError) fail('wrong archive password');
    throw error;
  }
}

function describeArchive(a: { archive: import('./vault.js').ArchiveStatus | null; objects: number }): string {
  const s = a.archive;
  if (!s) return `${a.objects} objects`;
  const parts = [`${s.messages} messages`, `${s.media} media`, `${Math.round(s.bytes / 1024 / 1024)} MB`];
  if (s.running) {
    parts.push(`READING HISTORY ${s.running.dialogsDone}${s.running.dialogsTotal ? `/${s.running.dialogsTotal}` : ''} chats`);
  } else if (s.updatedAt) {
    parts.push(`last message ${s.updatedAt}`);
  }
  if (s.liveArchive) parts.push('live');
  return parts.join(' · ');
}

async function main(): Promise<void> {
  const args = new Set(process.argv.slice(2));
  if (args.has('--version') || args.has('-v')) {
    process.stdout.write(`${VERSION}\n`);
    return;
  }
  if (args.has('--help') || args.has('-h')) {
    process.stdout.write(
      [
        `tgcerber-mcp ${VERSION}`,
        'Local MCP bridge for TG Cerber for Business archives.',
        '',
        'Environment:',
        '  TGCERBER_ARCHIVE_URL           archive endpoint from the console',
        '  TGCERBER_TOKEN                 connection token from the console',
        '  TGCERBER_VAULT_PASSWORD        organization archive password',
        '  TGCERBER_VAULT_PASSWORD_FILE   or a file whose first line is the password',
        '  TGCERBER_REFRESH_SECONDS       re-fetch the archive list this often while serving (default 30)',
        '',
        'Flags:',
        '  --check     verify the connection and password, print readable accounts, exit',
        '  --version   print the version',
        '',
        'Tools served: list_accounts, list_folders, list_chats, get_chat_messages, search_messages,',
        '              get_message_history, get_media',
        '',
      ].join('\n'),
    );
    return;
  }

  const vault = await open();

  if (args.has('--check')) {
    const accounts = await vault.listAccounts();
    process.stderr.write(`tgcerber-mcp: ${vault.organization.name} (${vault.organization.orgId}) — ${accounts.length} readable account(s)\n`);
    for (const a of accounts) process.stderr.write(`  ${a.name}  ${a.phoneNumber}  ${a.account}  ${describeArchive(a)}\n`);
    return;
  }

  const server = createServer(vault, VERSION);
  await server.connect(new StdioServerTransport());
  process.stderr.write(`tgcerber-mcp: serving ${vault.accounts.length} account(s) of ${vault.organization.name} over stdio\n`);
}

main().catch(error => fail(error instanceof Error ? error.message : String(error)));
