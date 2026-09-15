import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { AmbiguousError, NotFoundError, type MediaContent, type Vault } from './vault.js';

const text = (value: unknown) => ({ content: [{ type: 'text' as const, text: JSON.stringify(value, null, 2) }] });
const failure = (error: unknown) => ({
  content: [{ type: 'text' as const, text: error instanceof Error ? error.message : String(error) }],
  isError: true,
});

/** Same names, arguments and answers as TG Cerber's cloud mode, so a prompt written against one works against the other. */
export function createServer(vault: Vault, version: string): McpServer {
  const server = new McpServer(
    { name: 'tgcerber-archive', version },
    {
      instructions: [
        'TG Cerber archive: read-only access to archived Telegram messages and files, decrypted on this machine.',
        'Two error channels, by MCP convention: a malformed call is a protocol error and nothing ran; an answer about the archive ("no such chat", "several chats match", "no such message") is a tool result with isError=true and a message you can act on.',
        'Limits differ on purpose: get_chat_messages accepts limit 1–500, search_messages 1–200.',
        'A photo never has a fileName. media.facts="basic" means the message was archived before file facts were kept, so a missing name, transcript or text says nothing about the file.',
        'A deleted message is still returned, with deletedAt; an edited one carries edits and editedAt, and get_message_history returns the earlier wordings captured since 2026-09-10.',
        'Group membership: list_chat_members returns everyone in a group (silent members included) with role, join date and inviter as of the last full check (capturedAt), plus former members and the joins/leaves seen since. Service rows (includeService=true) say what happened in `text` and structured in `event` (kind member_added / member_left / member_removed / chat_renamed / photo_changed / message_pinned / …); rows archived before 2026-09-15 have an empty text.',
      ].join('\n'),
    },
  );

  const account = z
    .string()
    .min(1)
    .describe('Account id, exact name, or phone number — see list_accounts. No partial matches. Where optional, omitting it means every account this bridge can read.');
  const includeDocumentText = z
    .boolean()
    .default(false)
    .describe('Put the full extracted text of each document into media.documentText.text, so a batch of files needs no get_media per file.');
  const chat = z.string().min(1).describe('Chat id (preferred) or title. A title that matches several chats is refused with the candidates listed.');
  const folder = z.string().min(1).describe('Only chats in this Telegram folder of the account (exact folder name, see list_folders).');
  const includeService = z
    .boolean()
    .default(false)
    .describe(
      'Include service rows: members added, joined, left or removed, renames, photo changes, pins, calls. Each carries a readable `text` ("Fazil Suleymanov added Fedor Erashev") and a structured `event` {kind, by, byId, members[{id,name,username}], title, pinnedMsgId}. Off by default.',
    );
  const msgId = z.number().int().min(1).describe('The Telegram message id.');
  const dateTime = z.string().datetime({ offset: true });

  const guarded = async (fn: () => Promise<unknown>) => {
    try {
      return text(await fn());
    } catch (error) {
      // Ambiguity and absence are answers about the archive; the model reads them and acts.
      if (error instanceof AmbiguousError || error instanceof NotFoundError) return failure(error);
      return failure(error);
    }
  };

  server.registerTool(
    'list_accounts',
    {
      description:
        "The Telegram accounts this bridge can read, with each archive's state: message count, size, when it last " +
        'received a message, and — while a sweep is filling it — how many chats of how many have been read.',
      inputSchema: {},
    },
    async () => guarded(() => vault.listAccounts()),
  );

  server.registerTool(
    'list_folders',
    {
      description: 'The Telegram folders the account owner keeps, with how many archived chats each holds. Folder names are accepted by list_chats and search_messages.',
      inputSchema: { account: account.optional() },
    },
    async ({ account }) => guarded(() => vault.listFolders(account)),
  );

  server.registerTool(
    'list_chats',
    {
      description:
        'Chats in the archive, newest first, with their Telegram folders, message/media/deleted/edited counts, the oldest ' +
        'archived message, whether the history is complete back to the first message (historyComplete=false means the ' +
        'archive is still being filled for that chat) and, for groups, the member count of the last recorded member list ' +
        '(`members`, null when none is recorded yet). Optionally limited to one account or one folder.',
      inputSchema: { account: account.optional(), folder: folder.optional() },
    },
    async ({ account, folder }) => guarded(() => vault.listChats(account, folder)),
  );

  server.registerTool(
    'list_chat_members',
    {
      description:
        'Who is in a group chat — every member, the silent ones included — with name, username, id, role (owner / admin / ' +
        "member / restricted), when they joined and who invited them, as Telegram listed them at the account's last full " +
        'check (`capturedAt`; a check runs every 24 h). Also `former`: people who were in an earlier list or whose leaving / ' +
        'removal the archive saw (with when and how), and `changesSince`: the joins and leaves witnessed after the snapshot, ' +
        'already applied to `members`. Groups and supergroups only; a private chat or a broadcast channel → tool result with ' +
        'isError. `note` explains a partial answer (no list recorded yet, or Telegram hides the members).',
      inputSchema: { account, chat },
    },
    async ({ account, chat }) => guarded(() => vault.listChatMembers(account, chat)),
  );

  server.registerTool(
    'get_chat_messages',
    {
      description:
        'Messages of one chat in chronological order, newest `limit` (1–500, default 50) by default; page back with `before`. Each ' +
        'message carries its media facts (file name — never for photos —, MIME type, size, whether the file was saved, a voice ' +
        'transcript, a document\'s text length), `deletedAt` when Telegram deleted it (the archive keeps it), and `edits` when ' +
        'earlier versions exist (see get_message_history).',
      inputSchema: {
        account,
        chat,
        limit: z.number().int().min(1).max(500).default(50).describe('1–500.'),
        before: dateTime.optional().describe('ISO timestamp; only messages before it.'),
        after: dateTime.optional().describe('ISO timestamp; only messages after it.'),
        includeService,
        includeDocumentText,
      },
    },
    async ({ account, chat, limit, before, after, includeService, includeDocumentText }) =>
      guarded(() => vault.getMessages(account, chat, { limit, before, after, includeService, includeDocumentText })),
  );

  server.registerTool(
    'search_messages',
    {
      description:
        'Case-insensitive substring search over message text and captions, sender names, file names, the extracted text of ' +
        'documents (PDF, Word, Excel, plain text) and voice transcripts; newest first, at most `limit` (1–200, default 30) hits. ' +
        'Each hit says where it matched (matchedIn) and shows a snippet. The result reports how many messages were examined and ' +
        '`partial: true` if the time budget ran out before all of them were — narrow by account, chat, folder, sender or dates, ' +
        'or repeat the query.',
      inputSchema: {
        query: z.string().trim().min(1),
        account: account.optional(),
        chat: chat.optional(),
        folder: folder.optional(),
        sender: z.string().min(1).optional().describe('Only messages whose sender name contains this.'),
        before: dateTime.optional(),
        after: dateTime.optional(),
        includeService,
        includeDocumentText,
        limit: z.number().int().min(1).max(200).default(30).describe('1–200.'),
      },
    },
    async ({ query, account, chat, folder, sender, before, after, includeService, includeDocumentText, limit }) =>
      guarded(() => vault.search(query, { account, chat, folder, sender, before, after, includeService, includeDocumentText, limit })),
  );

  server.registerTool(
    'get_message_history',
    {
      description:
        'Every archived version of one message, oldest first, with when each was captured — what the text said before it was ' +
        'edited — plus the current version and its deletion time if Telegram deleted it. Versions exist only for edits the ' +
        'archive witnessed since 2026-09-10; an edited message with none says so in `note`.',
      inputSchema: { account, chat, msgId },
    },
    async ({ account, chat, msgId }) => guarded(() => vault.getMessageHistory(account, chat, msgId)),
  );

  server.registerTool(
    'get_media',
    {
      description:
        'The file attached to one message. Always returns its facts (name, MIME type, size, saved or not). Returns a photo or ' +
        'sticker as an image, a voice message as audio plus its transcript, and a document as its extracted text (PDF, Word, ' +
        'Excel, plain text); other files come back as a binary resource when under the size limit.',
      inputSchema: { account, chat, msgId },
    },
    async ({ account, chat, msgId }) => {
      try {
        return mediaContent(await vault.getMedia(account, chat, msgId));
      } catch (error) {
        return failure(error);
      }
    },
  );

  return server;
}

/** The facts as text; then an image, audio or binary block for the bytes; then a document's text. */
function mediaContent(out: MediaContent) {
  const content: Array<
    | { type: 'text'; text: string }
    | { type: 'image'; data: string; mimeType: string }
    | { type: 'audio'; data: string; mimeType: string }
    | { type: 'resource'; resource: { uri: string; mimeType: string; blob: string } }
  > = [{ type: 'text', text: JSON.stringify({ media: out.info, message: out.message, ...(out.reason ? { reason: out.reason } : {}) }, null, 2) }];
  if (out.data) {
    const mime = out.data.mimeType;
    if (mime.startsWith('image/')) content.push({ type: 'image', data: out.data.base64, mimeType: mime });
    else if (mime.startsWith('audio/')) content.push({ type: 'audio', data: out.data.base64, mimeType: mime });
    else if (!out.text) {
      content.push({
        type: 'resource',
        resource: { uri: `tgcerber://archive/${out.message.account}/${out.message.chat}/${out.message.msgId}`, mimeType: mime, blob: out.data.base64 },
      });
    }
  }
  if (out.text) content.push({ type: 'text', text: out.text });
  return { content };
}
