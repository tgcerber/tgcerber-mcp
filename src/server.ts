import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { Vault } from './vault.js';

const text = (value: unknown) => ({ content: [{ type: 'text' as const, text: JSON.stringify(value, null, 2) }] });
const failure = (error: unknown) => ({
  content: [{ type: 'text' as const, text: error instanceof Error ? error.message : String(error) }],
  isError: true,
});

/** The four tools Claude gets. Same names and shapes as TG Cerber's cloud mode, so prompts port. */
export function createServer(vault: Vault, version: string): McpServer {
  const server = new McpServer({ name: 'tgcerber-archive', version });

  server.registerTool(
    'list_accounts',
    {
      description: 'The Telegram accounts this bridge can read, with how much each archive holds.',
      inputSchema: {},
    },
    async () => text(vault.listAccounts()),
  );

  server.registerTool(
    'list_chats',
    {
      description: 'Chats in the archive, newest first. Optionally limited to one account.',
      inputSchema: { account: z.string().optional().describe('Account id, name, or phone number.') },
    },
    async ({ account }) => {
      try {
        return text(await vault.listChats(account));
      } catch (error) {
        return failure(error);
      }
    },
  );

  server.registerTool(
    'get_chat_messages',
    {
      description: 'The most recent messages of one chat, in chronological order.',
      inputSchema: {
        account: z.string().describe('Account id, name, or phone number.'),
        chat: z.string().describe('Chat id or title (substring match).'),
        limit: z.number().int().min(1).max(500).default(50),
        before: z.string().optional().describe('ISO timestamp; only messages before it.'),
      },
    },
    async ({ account, chat, limit, before }) => {
      try {
        return text(await vault.getMessages(account, chat, { limit, before }));
      } catch (error) {
        return failure(error);
      }
    },
  );

  server.registerTool(
    'search_messages',
    {
      description: 'Full-text search across the archive (case-insensitive substring), newest first.',
      inputSchema: {
        query: z.string().min(1),
        account: z.string().optional(),
        chat: z.string().optional(),
        limit: z.number().int().min(1).max(200).default(30),
      },
    },
    async ({ query, account, chat, limit }) => {
      try {
        return text(await vault.search(query, { account, chat, limit }));
      } catch (error) {
        return failure(error);
      }
    },
  );

  return server;
}
