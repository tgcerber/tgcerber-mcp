/**
 * Reads a TG Cerber for Business archive on this machine.
 *
 * Everything the server hands out is ciphertext: sealed boxes to the organization's X25519 public
 * key, plus that key's private half wrapped under Argon2id(password). This module unwraps the key
 * with the password you supply and opens objects in memory. Nothing decrypted is written to disk,
 * and the password never leaves this process.
 *
 * Wire format (from the server):
 *   - bundle           `{ v, organization, key: { publicKeyB64, wrappedPrivateKey }, accounts[] }`
 *   - every object     `{ sealedB64 }` → libsodium `crypto_box_seal` of a JSON document
 *   - manifest shard   opens to `{ objects: ManifestEntry[], chats?: Record<chatId, ChatMeta> }`
 *   - message object   opens to `MessageRecord`
 *   - media object     `{ envelope }` → a chunked XChaCha20-Poly1305 secretstream, file key sealed
 *
 * This mirrors the server's cloud reader tool for tool (`b2b/backend/src/mcp/vault-reader.ts` in the
 * TG Cerber repository), so a prompt written against one mode works against the other.
 */
import { createRequire } from 'node:module';

// The package's ESM entry references a file it does not ship; its CommonJS build is complete.
const require = createRequire(import.meta.url);
const sodium = require('libsodium-wrappers-sumo') as typeof import('libsodium-wrappers-sumo');

export interface WrappedPrivateKey {
  v: 1;
  salt: string;
  ops: number;
  mem: number;
  alg: number;
  nonce: string;
  ct: string;
}

export interface ArchiveStatus {
  status: string;
  messages: number;
  media: number;
  bytes: number;
  lastBackupAt: string | null;
  updatedAt: string | null;
  liveArchive: boolean;
  running?: { phase: string; startedAt: string | null; dialogsDone: number; dialogsTotal: number | null; currentChat: string | null };
}

export interface Account {
  employeeId: string;
  name: string;
  phoneNumber: string;
  manifests: string[];
  objects: Record<string, string>;
  /** Per chat, whether a sweep has read the history down to the first message. Bundle v2. */
  coverage?: Record<string, { complete: boolean }>;
  archive?: ArchiveStatus;
}

export interface Bundle {
  v: 1 | 2;
  organization: { orgId: string; name: string };
  key: { publicKeyB64: string; wrappedPrivateKey: WrappedPrivateKey };
  accounts: Account[];
}

export interface ManifestEntry {
  msgKey: string;
  mediaKey: string | null;
  type: string;
  chatTitle: string;
  chatId?: string | number | null;
  chatType?: string | null;
  date?: string | null;
  msgId?: number | null;
  /** Text and sender on the manifest (since 2026-09-10); absent means "open the record". */
  text?: string;
  sender?: string | null;
  mediaType?: string | null;
  fileName?: string | null;
  editDate?: string | null;
  /** The record holds more searchable text: a transcript or a document's contents. */
  more?: boolean;
  /** On a `type: 'members'` entry: how many members the snapshot holds. The object is a `MembersSnapshot`. */
  members?: number;
  deletedAt?: string | null;
  versions?: ManifestEntry[];
}

export interface NamedUser {
  id: number;
  name: string | null;
  username: string | null;
}

/** What a service row says happened (records sealed since 2026-09-15). */
export interface ServiceEvent {
  kind: string;
  action: string;
  by: string | null;
  byId: number | null;
  members?: NamedUser[];
  title?: string;
  pinnedMsgId?: number;
  inviter?: NamedUser;
  [extra: string]: unknown;
}

export type MemberRole = 'owner' | 'admin' | 'member' | 'restricted';

export interface MemberRecord extends NamedUser {
  role: MemberRole;
  title?: string;
  joinedAt: string | null;
  invitedBy?: NamedUser;
  promotedBy?: NamedUser;
  bot?: true;
  deleted?: true;
  premium?: true;
  phone?: string;
}

/** A group's member list as the sweep sealed it. */
export interface MembersSnapshot {
  type: 'members';
  chatId?: string | number | null;
  chatTitle: string;
  chatType?: string | null;
  capturedAt: string;
  total: number | null;
  truncated: boolean;
  unavailable?: string;
  members: MemberRecord[];
}

export interface MemberView extends MemberRecord {
  status: 'current' | 'left';
  source: 'snapshot' | 'event';
  leftAt?: string;
  how?: 'left' | 'removed';
  removedBy?: string | null;
}

export interface MembershipChange {
  date: string | null;
  msgId: number | null;
  kind: string;
  by: string | null;
  byId: number | null;
  members: NamedUser[];
  text: string;
}

export interface ChatMembers {
  account: string;
  accountName: string;
  chat: string;
  title: string;
  type: string | null;
  capturedAt: string | null;
  total: number | null;
  truncated: boolean;
  unavailable?: string;
  members: MemberView[];
  former: MemberView[];
  changesSince: MembershipChange[];
  note?: string;
}

export interface ChatMeta {
  title: string;
  type: string | null;
  folders: string[];
  archived: boolean;
  at: string;
}

interface ManifestShard {
  objects?: ManifestEntry[];
  chats?: Record<string, ChatMeta>;
}

interface DeletionRecord {
  type: 'deletion';
  msgIds?: number[];
  chatId?: string | number | null;
  deletedAt: string;
}

export interface MessageRecord {
  chatId?: string | number | null;
  chatTitle: string;
  chatType?: string | null;
  msgId: number | null;
  date: string | null;
  type: string;
  text: string;
  sender: string | null;
  senderId?: number | null;
  replyToId?: number | null;
  editDate?: string | null;
  capturedAt?: string | null;
  mediaKey?: string;
  mediaType?: string;
  mediaBytes?: number;
  mediaSaved?: boolean;
  mediaError?: boolean;
  fileName?: string | null;
  mimeType?: string | null;
  fileSize?: number | null;
  duration?: number;
  width?: number;
  height?: number;
  isRound?: boolean;
  emoji?: string;
  documentText?: string;
  documentTextKind?: string;
  documentTextTruncated?: boolean;
  documentPages?: number;
  transcript?: string;
  transcriptPartial?: boolean;
  transcriptUnavailable?: string;
  event?: ServiceEvent;
}

export interface ChatSummary {
  account: string;
  accountName: string;
  chat: string;
  title: string;
  type: string | null;
  folders: string[];
  archived: boolean;
  messages: number;
  media: number;
  deleted: number;
  edited: number;
  historyFrom: string | null;
  lastAt: string | null;
  historyComplete: boolean | null;
  /** Members in the last recorded member list of a group; null when none is recorded. */
  members: number | null;
}

export interface MediaInfo {
  mediaType: string;
  /** `full` since 2026-09-10; `basic` for a record archived before facts were kept (no name, transcript or text — that says nothing about the file). */
  facts: 'full' | 'basic';
  /** Always null for a `photo`. */
  fileName: string | null;
  mimeType: string | null;
  bytes: number | null;
  declaredBytes: number | null;
  saved: boolean;
  duration?: number;
  width?: number;
  height?: number;
  isRound?: boolean;
  emoji?: string;
  documentText?: { kind: string; chars: number; truncated: boolean; pages?: number; text?: string };
  transcript?: string;
  transcriptPartial?: boolean;
  transcriptUnavailable?: string;
}

export interface Message {
  account: string;
  accountName: string;
  chat: string;
  chatTitle: string;
  folders?: string[];
  msgId: number | null;
  date: string | null;
  sender: string | null;
  senderId?: number | null;
  type: string;
  text: string;
  replyToId?: number | null;
  media?: MediaInfo;
  mediaType?: string;
  /** On a service row: what happened, structured; `text` is the sentence. */
  event?: ServiceEvent;
  deletedAt?: string;
  edits?: number;
  editedAt?: string;
}

export interface SearchHit extends Message {
  matchedIn: 'text' | 'sender' | 'fileName' | 'document' | 'transcript';
  snippet?: string;
}

export interface SearchResult {
  query: string;
  hits: SearchHit[];
  scanned: number;
  total: number;
  partial: boolean;
  accounts: number;
}

export interface MessageHistory {
  current: Message;
  versions: Array<{ text: string; capturedAt: string | null; editDate: string | null; media?: MediaInfo }>;
  versionsKeptSince: string;
  note?: string;
}

export interface MediaContent {
  info: MediaInfo;
  message: Message;
  data?: { base64: string; mimeType: string; bytes: number };
  text?: string;
  reason?: 'not_saved' | 'too_large' | 'no_media';
}

export class WrongPasswordError extends Error {
  constructor() {
    super('Wrong archive password.');
  }
}
export class AmbiguousError extends Error {}
export class NotFoundError extends Error {}

const FETCH_CONCURRENCY = 32;
export const VERSIONS_KEPT_SINCE = '2026-09-10';
const SEARCH_BUDGET_MS = 20_000;
const DEFAULT_REFRESH_MS = 30_000;
const MAX_MEDIA_BYTES = 20 * 1024 * 1024;

export async function fetchBundle(archiveUrl: string, token: string): Promise<Bundle> {
  const res = await fetch(archiveUrl, { headers: { authorization: `Bearer ${token}` } });
  if (!res.ok) {
    throw new Error(`Archive request failed: HTTP ${res.status} ${await res.text().catch(() => '')}`.trim());
  }
  const bundle = (await res.json()) as Bundle;
  if ((bundle?.v !== 1 && bundle?.v !== 2) || !bundle.key?.publicKeyB64 || !Array.isArray(bundle.accounts)) {
    throw new Error('The archive endpoint returned something that is not a TG Cerber bundle.');
  }
  return bundle;
}

interface AccountState {
  account: Account;
  shards: Map<string, ManifestShard>;
  entries: ManifestEntry[] | null;
  /** The bundle moved; the entries already built keep serving until the rebuild lands. */
  stale: boolean;
  chats: Record<string, ChatMeta>;
  building: Promise<ManifestEntry[]> | null;
}

export class Vault {
  private readonly states = new Map<string, AccountState>();
  private readonly records = new Map<string, Promise<MessageRecord | null>>();
  private fetchedAt = Date.now();
  private refreshing: Promise<void> | null = null;

  private constructor(
    private readonly pub: Uint8Array,
    private readonly priv: Uint8Array,
    readonly organization: Bundle['organization'],
    accounts: Account[],
    private readonly refetch: (() => Promise<Bundle>) | null,
    private readonly refreshMs: number,
  ) {
    for (const account of accounts) this.states.set(account.employeeId, { account, shards: new Map(), entries: null, stale: false, chats: {}, building: null });
  }

  /**
   * Unwraps the key with the password. With `refetch`, the bundle is fetched again every
   * `refreshMs` on use, so messages the archive sealed since the bridge started show up.
   */
  static async open(bundle: Bundle, password: string, opts: { refetch?: () => Promise<Bundle>; refreshMs?: number } = {}): Promise<Vault> {
    await sodium.ready;
    const priv = unwrap(bundle.key.wrappedPrivateKey, password);
    const pub = sodium.from_base64(bundle.key.publicKeyB64, sodium.base64_variants.ORIGINAL);
    return new Vault(pub, priv, bundle.organization, bundle.accounts, opts.refetch ?? null, opts.refreshMs ?? DEFAULT_REFRESH_MS);
  }

  get accounts(): Account[] {
    return [...this.states.values()].map(s => s.account);
  }

  async listAccounts(): Promise<Array<{ account: string; name: string; phoneNumber: string; objects: number; archive: ArchiveStatus | null }>> {
    await this.maybeRefresh();
    return this.accounts.map(a => ({
      account: a.employeeId,
      name: a.name,
      phoneNumber: a.phoneNumber,
      objects: Object.keys(a.objects).length,
      archive: a.archive ?? null,
    }));
  }

  async listFolders(account?: string): Promise<Array<{ account: string; accountName: string; folder: string; chats: number }>> {
    await this.maybeRefresh();
    const out: Array<{ account: string; accountName: string; folder: string; chats: number }> = [];
    for (const acc of account ? [this.resolveAccount(account)] : this.accounts) {
      await this.entriesFor(acc);
      const counts = new Map<string, number>();
      for (const meta of Object.values(this.state(acc).chats)) {
        for (const folder of meta.folders) counts.set(folder, (counts.get(folder) ?? 0) + 1);
      }
      for (const [folder, chats] of counts) out.push({ account: acc.employeeId, accountName: acc.name, folder, chats });
    }
    return out.sort((a, b) => a.accountName.localeCompare(b.accountName) || a.folder.localeCompare(b.folder));
  }

  async listChats(account?: string, folder?: string): Promise<ChatSummary[]> {
    await this.maybeRefresh();
    const selected = account ? [this.resolveAccount(account)] : this.accounts;
    const out: ChatSummary[] = [];
    for (const acc of selected) {
      const entries = await this.entriesFor(acc);
      const chats = new Map<string, ChatSummary & { lastMs: number; firstMs: number; membersMs: number }>();
      for (const e of entries) {
        const key = chatKey(e);
        let chat = chats.get(key);
        if (!chat) {
          const meta = this.state(acc).chats[key];
          chat = {
            account: acc.employeeId,
            accountName: acc.name,
            chat: key,
            title: meta?.title || e.chatTitle || 'Chat',
            type: meta?.type ?? e.chatType ?? null,
            folders: meta?.folders ?? [],
            archived: meta?.archived ?? false,
            messages: 0,
            media: 0,
            deleted: 0,
            edited: 0,
            historyFrom: null,
            lastAt: null,
            historyComplete: acc.coverage ? (acc.coverage[key]?.complete ?? false) : null,
            members: null,
            lastMs: 0,
            firstMs: Number.MAX_SAFE_INTEGER,
            membersMs: -1,
          };
          chats.set(key, chat);
        }
        if (e.type === 'members') {
          const ms = e.date ? Date.parse(e.date) || 0 : 0;
          if (ms >= chat.membersMs) {
            chat.membersMs = ms;
            chat.members = typeof e.members === 'number' ? e.members : chat.members;
          }
          continue;
        }
        if (e.type !== 'service') chat.messages += 1;
        if (e.mediaKey) chat.media += 1;
        if (e.deletedAt) chat.deleted += 1;
        if (e.versions?.length) chat.edited += 1;
        const ms = e.date ? Date.parse(e.date) || 0 : 0;
        if (ms > chat.lastMs) {
          chat.lastMs = ms;
          chat.lastAt = e.date ?? null;
        }
        if (ms && ms < chat.firstMs) {
          chat.firstMs = ms;
          chat.historyFrom = e.date ?? null;
        }
      }
      for (const { lastMs: _l, firstMs: _f, membersMs: _m, ...chat } of chats.values()) {
        if (folder && !chat.folders.some(f => f.toLowerCase() === folder.trim().toLowerCase())) continue;
        out.push(chat);
      }
    }
    return out.sort((a, b) => Date.parse(b.lastAt ?? '') - Date.parse(a.lastAt ?? '') || a.title.localeCompare(b.title));
  }

  async getMessages(
    account: string,
    chat: string,
    opts: { limit: number; before?: string; after?: string; includeService?: boolean; includeDocumentText?: boolean },
  ): Promise<Message[]> {
    await this.maybeRefresh();
    const acc = this.resolveAccount(account);
    const { entries } = await this.resolveChat(acc, chat);
    const beforeMs = opts.before ? Date.parse(opts.before) : Number.NaN;
    const afterMs = opts.after ? Date.parse(opts.after) : Number.NaN;
    let scoped = entries.filter(e => isMessage(e) || (opts.includeService && e.type === 'service'));
    if (!Number.isNaN(beforeMs)) scoped = scoped.filter(e => (e.date ? Date.parse(e.date) : 0) < beforeMs);
    if (!Number.isNaN(afterMs)) scoped = scoped.filter(e => (e.date ? Date.parse(e.date) : 0) > afterMs);
    const tail = scoped.sort(byTime).slice(-clamp(opts.limit, 1, 500));
    const records = await mapLimit(tail, e => this.recordFor(acc, e.msgKey));
    return records.flatMap((r, i) => (r ? [this.toMessage(acc, tail[i]!, r, opts.includeDocumentText)] : []));
  }

  async search(
    query: string,
    opts: { account?: string; chat?: string; folder?: string; sender?: string; before?: string; after?: string; includeService?: boolean; includeDocumentText?: boolean; limit: number },
  ): Promise<SearchResult> {
    await this.maybeRefresh();
    const needle = query.trim().toLowerCase();
    if (!needle) throw new NotFoundError('search_messages: "query" must not be empty');
    const selected = opts.account ? [this.resolveAccount(opts.account)] : this.accounts;
    const senderNeedle = opts.sender?.trim().toLowerCase();
    const folderNeedle = opts.folder?.trim().toLowerCase();
    const beforeMs = opts.before ? Date.parse(opts.before) : Number.NaN;
    const afterMs = opts.after ? Date.parse(opts.after) : Number.NaN;
    const deadline = Date.now() + SEARCH_BUDGET_MS;
    const hits: SearchHit[] = [];
    let scanned = 0;
    let total = 0;
    let partial = false;

    for (const acc of selected) {
      let entries = opts.chat ? (await this.resolveChat(acc, opts.chat)).entries : await this.entriesFor(acc);
      entries = entries.filter(e => isMessage(e) || (opts.includeService && e.type === 'service'));
      if (folderNeedle) {
        const chats = this.state(acc).chats;
        entries = entries.filter(e => chats[chatKey(e)]?.folders.some(f => f.toLowerCase() === folderNeedle));
      }
      if (!Number.isNaN(beforeMs)) entries = entries.filter(e => (e.date ? Date.parse(e.date) : 0) < beforeMs);
      if (!Number.isNaN(afterMs)) entries = entries.filter(e => (e.date ? Date.parse(e.date) : 0) > afterMs);
      if (senderNeedle) entries = entries.filter(e => e.sender === undefined || (e.sender ?? '').toLowerCase().includes(senderNeedle));
      total += entries.length;

      const needRecord: ManifestEntry[] = [];
      for (const e of entries) {
        if (e.text === undefined) {
          needRecord.push(e);
          continue;
        }
        scanned += 1;
        const where = matchManifest(e, needle);
        if (where) {
          const record = await this.recordFor(acc, e.msgKey);
          if (record) hits.push({ ...this.toMessage(acc, e, record, opts.includeDocumentText), matchedIn: where.in, snippet: where.snippet });
          continue;
        }
        if (e.more) needRecord.push(e);
      }

      needRecord.sort(byTime).reverse();
      let index = 0;
      const worker = async (): Promise<void> => {
        while (index < needRecord.length) {
          if (Date.now() > deadline) {
            partial = true;
            return;
          }
          const e = needRecord[index++]!;
          const record = await this.recordFor(acc, e.msgKey);
          if (e.text === undefined) scanned += 1;
          if (!record) continue;
          if (senderNeedle && !(record.sender ?? '').toLowerCase().includes(senderNeedle)) continue;
          const where = matchRecord(record, needle);
          if (where) hits.push({ ...this.toMessage(acc, e, record, opts.includeDocumentText), matchedIn: where.in, snippet: where.snippet });
        }
      };
      await Promise.all(Array.from({ length: Math.min(FETCH_CONCURRENCY, needRecord.length) }, worker));
      if (partial) break;
    }
    hits.sort((a, b) => Date.parse(b.date ?? '') - Date.parse(a.date ?? ''));
    return { query, hits: hits.slice(0, clamp(opts.limit, 1, 200)), scanned, total, partial, accounts: selected.length };
  }

  /** Manifests written before 2026-09-10 carry no `msgId`; for those the chat's records are opened and compared. */
  private async entryByMsgId(acc: Account, entries: ManifestEntry[], msgId: number): Promise<ManifestEntry> {
    const direct = entries.find(e => e.msgId === msgId);
    if (direct) return direct;
    const legacy = entries.filter(e => e.msgId == null && e.type !== 'members');
    const records = await mapLimit(legacy, e => this.recordFor(acc, e.msgKey));
    const at = records.findIndex(r => r?.msgId === msgId);
    if (at >= 0) return legacy[at]!;
    throw new NotFoundError(`No message ${msgId} in that chat of ${acc.name}'s archive.`);
  }

  async getMessageHistory(account: string, chat: string, msgId: number): Promise<MessageHistory> {
    await this.maybeRefresh();
    const acc = this.resolveAccount(account);
    const { entries } = await this.resolveChat(acc, chat);
    const entry = await this.entryByMsgId(acc, entries, msgId);
    const current = await this.recordFor(acc, entry.msgKey);
    if (!current) throw new NotFoundError(`Message ${msgId} could not be opened.`);
    const olders = await mapLimit(entry.versions ?? [], v => this.recordFor(acc, v.msgKey));
    const versions = olders.flatMap(r =>
      r ? [{ text: r.text ?? '', capturedAt: r.capturedAt ?? null, editDate: r.editDate ?? null, ...(r.mediaType ? { media: mediaInfo(r) } : {}) }] : [],
    );
    const message = this.toMessage(acc, entry, current);
    return {
      current: message,
      versions,
      versionsKeptSince: VERSIONS_KEPT_SINCE,
      ...(!versions.length && message.editedAt
        ? { note: `Telegram says this message was edited, but its earlier wording was not captured: versions are kept only for edits the archive witnessed after ${VERSIONS_KEPT_SINCE}.` }
        : {}),
    };
  }

  /**
   * Who is in a group — silent members included — and who used to be. Same rules as the server's
   * cloud reader: the newest `members` snapshot is the list, the service rows after it are applied
   * to it, earlier snapshots and leave/removal rows give `former`.
   */
  async listChatMembers(account: string, chat: string): Promise<ChatMembers> {
    await this.maybeRefresh();
    const acc = this.resolveAccount(account);
    const { key, entries } = await this.resolveChat(acc, chat);
    const meta = this.state(acc).chats[key];
    const type = meta?.type ?? entries.find(e => e.chatType)?.chatType ?? null;
    const title = meta?.title || entries[entries.length - 1]?.chatTitle || key;
    if (type === 'user' || type === 'bot') throw new NotFoundError(`"${title}" is a private chat; list_chat_members is for groups and supergroups.`);
    if (type === 'channel') throw new NotFoundError(`"${title}" is a broadcast channel; subscriber lists are not archived (Telegram shows them to admins only).`);

    const snapshotEntries = entries.filter(e => e.type === 'members').sort(byTime);
    const snapshots = (await mapLimit(snapshotEntries.slice(-30), e => this.recordFor(acc, e.msgKey) as Promise<MembersSnapshot | null>)).filter(
      (s): s is MembersSnapshot => Boolean(s && Array.isArray(s.members)),
    );
    const latest = snapshots[snapshots.length - 1] ?? null;
    const capturedAt = latest?.capturedAt ?? null;
    const capturedMs = capturedAt ? Date.parse(capturedAt) : Number.NEGATIVE_INFINITY;

    const serviceEntries = entries.filter(e => e.type === 'service').sort(byTime);
    const serviceRecords = await mapLimit(serviceEntries, e => this.recordFor(acc, e.msgKey));
    const events: Array<{ record: MessageRecord; event: ServiceEvent; ms: number }> = [];
    serviceRecords.forEach((r, i) => {
      if (!r?.event || !MEMBERSHIP_KINDS.has(r.event.kind)) return;
      const date = r.date ?? serviceEntries[i]!.date ?? null;
      events.push({ record: r, event: r.event, ms: date ? Date.parse(date) || 0 : 0 });
    });

    const current = new Map<number, MemberView>();
    const former = new Map<number, MemberView>();
    for (const m of latest?.members ?? []) current.set(m.id, { ...m, status: 'current', source: 'snapshot' });
    for (const s of snapshots.slice(0, -1)) {
      for (const m of s.members) if (!current.has(m.id) && !former.has(m.id)) former.set(m.id, { ...m, status: 'left', source: 'snapshot' });
    }
    const changesSince: MembershipChange[] = [];
    for (const { record, event, ms } of events) {
      const people = event.members ?? [];
      const after = ms > capturedMs;
      if (after) changesSince.push({ date: record.date ?? null, msgId: record.msgId, kind: event.kind, by: event.by, byId: event.byId, members: people, text: record.text ?? '' });
      if (event.kind === 'chat_created' && after && event.byId !== null && !current.has(event.byId)) {
        current.set(event.byId, { id: event.byId, name: event.by, username: null, role: 'owner', joinedAt: record.date ?? null, status: 'current', source: 'event' });
      }
      for (const p of people) {
        if (event.kind === 'member_added' || event.kind === 'member_joined' || event.kind === 'chat_created') {
          if (!after) continue;
          former.delete(p.id);
          if (!current.has(p.id)) {
            current.set(p.id, { ...p, role: 'member', joinedAt: record.date ?? null, status: 'current', source: 'event', ...((event.kind === 'member_added' || event.kind === 'chat_created') && event.by ? { invitedBy: { id: event.byId ?? 0, name: event.by, username: null } } : {}) });
          }
        } else if (event.kind === 'member_left' || event.kind === 'member_removed') {
          const how = event.kind === 'member_left' ? 'left' : 'removed';
          const known = current.get(p.id);
          if (after && known) {
            current.delete(p.id);
            former.set(p.id, { ...known, status: 'left', leftAt: record.date ?? undefined, how, ...(how === 'removed' ? { removedBy: event.by } : {}) });
          } else if (!current.has(p.id)) {
            const prior = former.get(p.id);
            former.set(p.id, {
              ...(prior ?? { ...p, role: 'member' as const, joinedAt: null, source: 'event' as const }),
              status: 'left',
              ...(prior?.leftAt && Date.parse(prior.leftAt) > ms ? {} : { leftAt: record.date ?? undefined, how, ...(how === 'removed' ? { removedBy: event.by } : {}) }),
            });
          }
        }
      }
    }
    const byRole = (a: MemberView, b: MemberView): number => ROLE_ORDER[a.role] - ROLE_ORDER[b.role] || (a.name ?? '').localeCompare(b.name ?? '');
    const out: ChatMembers = {
      account: acc.employeeId,
      accountName: acc.name,
      chat: key,
      title,
      type,
      capturedAt,
      total: latest?.total ?? null,
      truncated: latest?.truncated ?? false,
      ...(latest?.unavailable ? { unavailable: latest.unavailable } : {}),
      members: [...current.values()].sort(byRole),
      former: [...former.values()].sort((a, b) => leftMs(b) - leftMs(a) || (a.name ?? '').localeCompare(b.name ?? '')),
      changesSince,
    };
    if (!latest) {
      out.note =
        "No member list has been recorded for this chat yet: lists are captured by the account's full check (every 24 h, since 2026-09-15). " +
        'What is shown comes from the joins and leaves the archive witnessed and is not the whole membership.';
    } else if (latest.unavailable) {
      out.note = `Telegram refused the member list at the last check (${latest.unavailable}): the group hides its members from non-admins, or the account is no longer in it. Only changes seen in service messages are listed.`;
    }
    return out;
  }

  async getMedia(account: string, chat: string, msgId: number): Promise<MediaContent> {
    await this.maybeRefresh();
    const acc = this.resolveAccount(account);
    const { entries } = await this.resolveChat(acc, chat);
    const entry = await this.entryByMsgId(acc, entries, msgId);
    const record = await this.recordFor(acc, entry.msgKey);
    if (!record) throw new NotFoundError(`Message ${msgId} could not be opened.`);
    const message = this.toMessage(acc, entry, record);
    if (!record.mediaType) throw new NotFoundError(`Message ${msgId} carries no file.`);
    const info = mediaInfo(record);
    const mediaKey = record.mediaKey ?? entry.mediaKey;
    if (!mediaKey || record.mediaSaved === false || record.mediaError) {
      return { info, message, reason: 'not_saved', ...(record.documentText ? { text: record.documentText } : {}) };
    }
    if ((record.mediaBytes ?? 0) > MAX_MEDIA_BYTES) {
      return { info, message, reason: 'too_large', ...(record.documentText ? { text: record.documentText } : {}) };
    }
    const url = acc.objects[mediaKey];
    if (!url) throw new NotFoundError(`The file of message ${msgId} is not in this bundle; restart the bridge to fetch a fresh one.`);
    const res = await fetch(url);
    if (!res.ok) throw new Error(`Archive object fetch failed: HTTP ${res.status}`);
    const body = (await res.json()) as { envelope?: MediaEnvelope };
    if (!body?.envelope) throw new Error('Archive object is not a sealed file.');
    const bytes = openMedia(body.envelope, this.pub, this.priv, mediaKey);
    const mimeType = record.mimeType ?? sniffMime(bytes) ?? 'application/octet-stream';
    let text = record.documentText;
    if (!text && record.mediaType === 'document') {
      const doc = await extractDocumentText(bytes, record.fileName ?? null, mimeType);
      if (doc) text = doc;
    }
    return { info, message, data: { base64: Buffer.from(bytes).toString('base64'), mimeType, bytes: bytes.length }, ...(text ? { text } : {}) };
  }

  // ---- resolution ----

  resolveAccount(selector: string): Account {
    const s = selector.trim();
    const byId = this.states.get(s)?.account;
    if (byId) return byId;
    const lower = s.toLowerCase();
    const digits = s.replace(/[^\d]/g, '');
    const matches = this.accounts.filter(a => a.name.toLowerCase() === lower || (digits.length >= 7 && a.phoneNumber.replace(/[^\d]/g, '') === digits));
    if (matches.length === 1) return matches[0]!;
    if (matches.length > 1) {
      throw new AmbiguousError(`Several accounts are called "${s}": ${matches.map(a => `${a.employeeId} (${a.phoneNumber})`).join(', ')}. Pass the account id.`);
    }
    const available = this.accounts.slice(0, 20).map(a => `${a.name} (${a.employeeId})`).join(', ');
    throw new NotFoundError(`No account matching "${s}". This connection can read: ${available || 'no accounts'}.`);
  }

  private async resolveChat(acc: Account, selector: string): Promise<{ key: string; entries: ManifestEntry[] }> {
    const s = selector.trim();
    const lower = s.toLowerCase();
    const entries = await this.entriesFor(acc);
    const byKey = new Map<string, ManifestEntry[]>();
    for (const e of entries) {
      const key = chatKey(e);
      const list = byKey.get(key);
      if (list) list.push(e);
      else byKey.set(key, [e]);
    }
    const exact = byKey.get(s);
    if (exact) return { key: s, entries: exact };
    const titleOf = (key: string, list: ManifestEntry[]): string => this.state(acc).chats[key]?.title || list[list.length - 1]!.chatTitle || '';
    const pick = (test: (title: string) => boolean): string[] => [...byKey.entries()].filter(([k, l]) => test(titleOf(k, l).toLowerCase())).map(([k]) => k);
    let keys = pick(t => t === lower);
    if (!keys.length) keys = pick(t => t.includes(lower));
    if (keys.length === 1) return { key: keys[0]!, entries: byKey.get(keys[0]!)! };
    if (keys.length > 1) {
      const listed = keys
        .slice(0, 12)
        .map(k => `${k} — "${titleOf(k, byKey.get(k)!)}" (${byKey.get(k)!.filter(e => e.type !== 'service').length} messages)`)
        .join('; ');
      throw new AmbiguousError(`"${s}" matches ${keys.length} chats in ${acc.name}'s archive: ${listed}${keys.length > 12 ? '; …' : ''}. Pass the chat id.`);
    }
    throw new NotFoundError(`No chat matching "${s}" in ${acc.name}'s archive. Use list_chats to see what is there.`);
  }

  // ---- manifests ----

  private state(acc: Account): AccountState {
    const state = this.states.get(acc.employeeId);
    if (!state) throw new NotFoundError(`Account ${acc.employeeId} is not readable by this connection.`);
    return state;
  }

  /** Fetches the bundle again when the last one is older than `refreshMs`; one fetch at a time. */
  private async maybeRefresh(): Promise<void> {
    if (!this.refetch || Date.now() - this.fetchedAt < this.refreshMs) return;
    if (!this.refreshing) {
      this.refreshing = (async () => {
        try {
          const bundle = await this.refetch!();
          for (const account of bundle.accounts) {
            const state = this.states.get(account.employeeId);
            if (state) {
              state.account = account;
              state.stale = true; // the open shard may have grown; rebuilt from cached shards plus one fetch
            } else {
              this.states.set(account.employeeId, { account, shards: new Map(), entries: null, stale: false, chats: {}, building: null });
            }
          }
          for (const id of [...this.states.keys()]) {
            if (!bundle.accounts.some(a => a.employeeId === id)) this.states.delete(id);
          }
        } catch (e) {
          process.stderr.write(`tgcerber-mcp: refresh failed, serving the previous view: ${e instanceof Error ? e.message : String(e)}\n`);
        } finally {
          this.fetchedAt = Date.now();
          this.refreshing = null;
        }
      })();
    }
    await this.refreshing;
  }

  private async entriesFor(acc: Account): Promise<ManifestEntry[]> {
    const state = this.state(acc);
    if (state.entries && !state.stale) return state.entries;
    if (!state.building) {
      state.building = this.buildEntries(state).finally(() => {
        state.building = null;
      });
    }
    return state.building;
  }

  private async buildEntries(state: AccountState): Promise<ManifestEntry[]> {
    const acc = state.account;
    const urls = acc.manifests;
    const shards = await mapLimit(urls, async (url, i) => {
      const key = keyOf(url);
      const cached = i !== urls.length - 1 ? state.shards.get(key) : undefined;
      if (cached) return cached;
      const shard = await this.openJson<ManifestShard>(url);
      state.shards.set(key, shard);
      return shard;
    });
    const all = shards.flatMap(s => s?.objects ?? []);
    const chats: Record<string, ChatMeta> = {};
    for (const s of shards) {
      for (const [id, meta] of Object.entries(s?.chats ?? {})) {
        if (!chats[id] || meta.at >= chats[id]!.at) chats[id] = meta;
      }
    }
    state.chats = chats;

    const tombstones = all.filter(e => e.type === 'deletion');
    const deletedAnywhere = new Map<number, string>();
    const deletedInChat = new Map<string, string>();
    if (tombstones.length) {
      const records = await mapLimit(tombstones, e => this.recordFor(acc, e.msgKey) as Promise<DeletionRecord | null>);
      for (const rec of records) {
        if (!rec?.deletedAt) continue;
        for (const id of rec.msgIds ?? []) {
          if (rec.chatId == null || rec.chatId === '') {
            if (!deletedAnywhere.has(id)) deletedAnywhere.set(id, rec.deletedAt);
          } else if (!deletedInChat.has(`${rec.chatId}:${id}`)) {
            deletedInChat.set(`${rec.chatId}:${id}`, rec.deletedAt);
          }
        }
      }
    }
    await this.learnLegacyIds(acc, all);
    state.entries = foldVersions(all, e => deletedInChat.get(`${e.chatId}:${e.msgId}`) ?? (e.msgId != null ? deletedAnywhere.get(e.msgId) : undefined) ?? null);
    state.stale = false;
    return state.entries;
  }

  /** Legacy entries (no `msgId` on the manifest) in a chat the sweep has re-sealed: learn their ids from the records so they fold. */
  private async learnLegacyIds(acc: Account, all: ManifestEntry[]): Promise<void> {
    const withIds = new Set<string>();
    for (const e of all) if (e.msgId != null) withIds.add(chatKey(e));
    const legacy = all.filter(e => e.msgId == null && e.type !== 'deletion' && e.type !== 'members' && withIds.has(chatKey(e)));
    if (!legacy.length) return;
    const records = await mapLimit(legacy, e => this.recordFor(acc, e.msgKey));
    records.forEach((r, i) => {
      if (!r || typeof r.msgId !== 'number') return;
      legacy[i]!.msgId = r.msgId;
      if (r.editDate !== undefined) legacy[i]!.editDate = r.editDate;
    });
  }

  private recordFor(acc: Account, msgKey: string): Promise<MessageRecord | null> {
    let pending = this.records.get(msgKey);
    if (!pending) {
      const url = this.state(acc).account.objects[msgKey];
      pending = url ? this.openJson<MessageRecord>(url).catch(() => null) : Promise.resolve(null);
      this.records.set(msgKey, pending);
    }
    return pending;
  }

  private async openJson<T>(url: string): Promise<T> {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`Archive object fetch failed: HTTP ${res.status}`);
    const body = (await res.json()) as { sealedB64?: string };
    if (!body?.sealedB64) throw new Error('Archive object is not a sealed message.');
    const sealed = sodium.from_base64(body.sealedB64, sodium.base64_variants.ORIGINAL);
    const opened = sodium.crypto_box_seal_open(sealed, this.pub, this.priv);
    return JSON.parse(sodium.to_string(opened)) as T;
  }

  private toMessage(acc: Account, e: ManifestEntry, r: MessageRecord, includeDocumentText = false): Message {
    const key = chatKey(e);
    const meta = this.state(acc).chats[key];
    return {
      account: acc.employeeId,
      accountName: acc.name,
      chat: key,
      chatTitle: meta?.title || r.chatTitle || e.chatTitle,
      ...(meta?.folders.length ? { folders: meta.folders } : {}),
      msgId: r.msgId,
      date: r.date ?? e.date ?? null,
      sender: r.sender,
      ...(typeof r.senderId === 'number' ? { senderId: r.senderId } : {}),
      type: r.type,
      text: r.text ?? '',
      ...(typeof r.replyToId === 'number' ? { replyToId: r.replyToId } : {}),
      ...(r.mediaType ? { mediaType: r.mediaType, media: mediaInfo(r, includeDocumentText) } : {}),
      ...(r.event ? { event: r.event } : {}),
      ...(e.deletedAt ? { deletedAt: e.deletedAt } : {}),
      ...(e.versions?.length ? { edits: e.versions.length } : {}),
      ...(r.editDate ? { editedAt: r.editDate } : {}),
    };
  }
}

// ---- crypto ----

function unwrap(wrapped: WrappedPrivateKey, password: string): Uint8Array {
  const b64 = (s: string): Uint8Array => sodium.from_base64(s, sodium.base64_variants.ORIGINAL);
  const key = sodium.crypto_pwhash(sodium.crypto_secretbox_KEYBYTES, password, b64(wrapped.salt), wrapped.ops, wrapped.mem, wrapped.alg);
  try {
    return sodium.crypto_secretbox_open_easy(b64(wrapped.ct), b64(wrapped.nonce), key);
  } catch {
    throw new WrongPasswordError();
  }
}

export interface MediaEnvelope {
  v: 1;
  sealedFileKey: string;
  header: string;
  chunks: string[];
}

/** Opens a media envelope: the file key is a sealed box, the body a secretstream bound to the object key. */
export function openMedia(envelope: MediaEnvelope, pub: Uint8Array, priv: Uint8Array, objectId: string): Uint8Array {
  const b64 = (s: string): Uint8Array => sodium.from_base64(s, sodium.base64_variants.ORIGINAL);
  const fileKey = sodium.crypto_box_seal_open(b64(envelope.sealedFileKey), pub, priv);
  const state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(b64(envelope.header), fileKey);
  const ad = sodium.from_string(objectId);
  const parts: Uint8Array[] = [];
  envelope.chunks.forEach((chunk, i) => {
    const res = sodium.crypto_secretstream_xchacha20poly1305_pull(state, b64(chunk), ad) as unknown as false | { message: Uint8Array; tag: number };
    if (!res) throw new Error(`media chunk ${i} failed to open`);
    parts.push(res.message);
  });
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// ---- helpers ----

const MEMBERSHIP_KINDS = new Set(['member_added', 'member_joined', 'member_left', 'member_removed', 'chat_created']);
const ROLE_ORDER: Record<MemberRole, number> = { owner: 0, admin: 1, member: 2, restricted: 3 };
const leftMs = (m: { leftAt?: string }): number => (m.leftAt ? Date.parse(m.leftAt) || 0 : 0);

/** A conversation row: not a service line, not a member-list snapshot. */
export function isMessage(e: { type: string }): boolean {
  return e.type !== 'service' && e.type !== 'members' && e.type !== 'deletion';
}

export function chatKey(e: { chatId?: string | number | null; chatTitle: string }): string {
  return e.chatId != null && e.chatId !== '' ? String(e.chatId) : `title:${e.chatTitle}`;
}

export function keyOf(url: string): string {
  try {
    const path = new URL(url).pathname;
    const local = path.indexOf('/local-object/');
    if (local >= 0) return decodeURIComponent(path.slice(local + '/local-object/'.length));
    return decodeURIComponent(path.replace(/^\/+/, ''));
  } catch {
    return url;
  }
}

function byTime(a: ManifestEntry, b: ManifestEntry): number {
  const at = (e: ManifestEntry): number => (e.date ? Date.parse(e.date) || Number.MAX_SAFE_INTEGER : Number.MAX_SAFE_INTEGER);
  return at(a) - at(b) || a.msgKey.localeCompare(b.msgKey);
}

/** Same rule as the server's reader: an original never supersedes; equal known edit times are one version. */
export function sameVersion(current: ManifestEntry, next: ManifestEntry): boolean {
  if (next.editDate === null) return current.editDate === null || current.editDate === undefined;
  return typeof next.editDate === 'string' && next.editDate === current.editDate;
}

export function foldVersions(all: ManifestEntry[], deletedAt: (e: ManifestEntry) => string | null): ManifestEntry[] {
  const at = new Map<string, number>();
  const out: ManifestEntry[] = [];
  for (const entry of all) {
    if (entry.type === 'deletion') continue;
    if (entry.msgId == null) {
      out.push({ ...entry, deletedAt: null });
      continue;
    }
    const key = `${chatKey(entry)}:${entry.msgId}`;
    const index = at.get(key);
    if (index === undefined) {
      at.set(key, out.length);
      out.push({ ...entry, deletedAt: deletedAt(entry), versions: [] });
      continue;
    }
    const current = out[index]!;
    if (sameVersion(current, entry)) {
      out[index] = { ...entry, deletedAt: current.deletedAt, versions: current.versions };
    } else {
      const { versions, ...older } = current;
      out[index] = { ...entry, deletedAt: current.deletedAt, versions: [...(versions ?? []), older] };
    }
  }
  return out;
}

export function mediaInfo(r: MessageRecord, includeDocumentText = false): MediaInfo {
  const saved = r.mediaSaved ?? (Boolean(r.mediaKey) && !r.mediaError);
  const facts: MediaInfo['facts'] = r.mediaSaved === undefined && r.fileName === undefined ? 'basic' : 'full';
  return {
    mediaType: r.mediaType ?? 'document',
    facts,
    fileName: r.fileName ?? null,
    mimeType: r.mimeType ?? null,
    bytes: saved ? (r.mediaBytes ?? null) : null,
    declaredBytes: r.fileSize ?? null,
    saved,
    ...(r.duration !== undefined ? { duration: r.duration } : {}),
    ...(r.width !== undefined && r.height !== undefined ? { width: r.width, height: r.height } : {}),
    ...(r.isRound ? { isRound: true } : {}),
    ...(r.emoji ? { emoji: r.emoji } : {}),
    ...(r.documentText
      ? { documentText: { kind: r.documentTextKind ?? 'text', chars: r.documentText.length, truncated: Boolean(r.documentTextTruncated), ...(r.documentPages ? { pages: r.documentPages } : {}), ...(includeDocumentText ? { text: r.documentText } : {}) } }
      : {}),
    ...(r.transcript ? { transcript: r.transcript } : {}),
    ...(r.transcriptPartial ? { transcriptPartial: true } : {}),
    ...(r.transcriptUnavailable
      ? { transcriptUnavailable: r.transcriptUnavailable }
      : facts === 'basic' && (r.mediaType === 'voice' || r.mediaType === 'audio')
        ? { transcriptUnavailable: 'archived_before_transcription' }
        : {}),
  };
}

type Where = { in: SearchHit['matchedIn']; snippet?: string };

function matchManifest(e: ManifestEntry, needle: string): Where | null {
  if ((e.text ?? '').toLowerCase().includes(needle)) return { in: 'text', snippet: snippet(e.text ?? '', needle) };
  if ((e.sender ?? '').toLowerCase().includes(needle)) return { in: 'sender', snippet: e.sender ?? undefined };
  if ((e.fileName ?? '').toLowerCase().includes(needle)) return { in: 'fileName', snippet: e.fileName ?? undefined };
  return null;
}

function matchRecord(r: MessageRecord, needle: string): Where | null {
  if ((r.text ?? '').toLowerCase().includes(needle)) return { in: 'text', snippet: snippet(r.text ?? '', needle) };
  if ((r.sender ?? '').toLowerCase().includes(needle)) return { in: 'sender', snippet: r.sender ?? undefined };
  if ((r.fileName ?? '').toLowerCase().includes(needle)) return { in: 'fileName', snippet: r.fileName ?? undefined };
  if ((r.documentText ?? '').toLowerCase().includes(needle)) return { in: 'document', snippet: snippet(r.documentText ?? '', needle) };
  if ((r.transcript ?? '').toLowerCase().includes(needle)) return { in: 'transcript', snippet: snippet(r.transcript ?? '', needle) };
  return null;
}

export function snippet(haystack: string, needle: string, radius = 80): string {
  const at = haystack.toLowerCase().indexOf(needle);
  if (at < 0) return haystack.slice(0, radius * 2);
  let start = Math.max(0, at - radius);
  let end = Math.min(haystack.length, at + needle.length + radius);
  if (start > 0) {
    const space = haystack.indexOf(' ', start);
    if (space >= 0 && space < at) start = space + 1;
  }
  if (end < haystack.length) {
    const space = haystack.lastIndexOf(' ', end);
    if (space > at + needle.length) end = space;
  }
  return `${start > 0 ? '…' : ''}${haystack.slice(start, end).replace(/\s+/g, ' ').trim()}${end < haystack.length ? '…' : ''}`;
}

function sniffMime(bytes: Uint8Array): string | null {
  const h = Array.from(bytes.slice(0, 4)).map(b => b.toString(16).padStart(2, '0')).join('');
  if (h.startsWith('ffd8ff')) return 'image/jpeg';
  if (h.startsWith('89504e47')) return 'image/png';
  if (h.startsWith('52494646')) return 'image/webp';
  if (h.startsWith('25504446')) return 'application/pdf';
  if (h.startsWith('4f676753')) return 'audio/ogg';
  if (Buffer.from(bytes.slice(4, 8)).toString() === 'ftyp') return 'video/mp4';
  return null;
}

/** Text out of a PDF, Word or Excel document, or plain text; null for anything else or on failure. */
async function extractDocumentText(bytes: Uint8Array, fileName: string | null, mimeType: string): Promise<string | null> {
  const ext = (fileName ?? '').toLowerCase().split('.').pop() ?? '';
  const mime = mimeType.toLowerCase();
  const buf = Buffer.from(bytes);
  try {
    if (ext === 'pdf' || mime === 'application/pdf') {
      const pdfParse = require('pdf-parse') as (data: Buffer) => Promise<{ text: string }>;
      return tidy((await pdfParse(buf)).text);
    }
    if (ext === 'docx' || mime.includes('wordprocessingml')) {
      const mammoth = require('mammoth') as { extractRawText(input: { buffer: Buffer }): Promise<{ value: string }> };
      return tidy((await mammoth.extractRawText({ buffer: buf })).value);
    }
    if (['xlsx', 'xlsm', 'xls', 'ods'].includes(ext) || mime.includes('spreadsheetml') || mime === 'application/vnd.ms-excel') {
      const xlsx = require('xlsx') as typeof import('xlsx');
      const book = xlsx.read(buf, { type: 'buffer' });
      return tidy(book.SheetNames.map(n => `# ${n}\n${xlsx.utils.sheet_to_csv(book.Sheets[n]!, { blankrows: false })}`).join('\n\n'));
    }
    if (mime.startsWith('text/') || mime === 'application/json' || ['txt', 'md', 'csv', 'json', 'log', 'xml', 'html'].includes(ext)) {
      return tidy(buf.toString('utf8'));
    }
  } catch {
    return null;
  }
  return null;
}

function tidy(text: string): string | null {
  const out = text.replace(/\r\n?/g, '\n').replace(/[ \t\f\v]+/g, ' ').replace(/ ?\n ?/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
  return out || null;
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, Number.isFinite(n) ? Math.trunc(n) : lo));
}

async function mapLimit<T, R>(items: T[], fn: (item: T, index: number) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]!, i);
    }
  };
  await Promise.all(Array.from({ length: Math.min(FETCH_CONCURRENCY, items.length) }, worker));
  return out;
}
