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
 *   - manifest shard   opens to `{ objects: ManifestEntry[] }`
 *   - message object   opens to `MessageRecord`
 */
import { createRequire } from 'node:module';

// The package's ESM entry references a file it does not ship; its CommonJS build is complete.
const sodium = createRequire(import.meta.url)('libsodium-wrappers-sumo') as typeof import('libsodium-wrappers-sumo');

export interface WrappedPrivateKey {
  v: 1;
  salt: string;
  ops: number;
  mem: number;
  alg: number;
  nonce: string;
  ct: string;
}

export interface Account {
  employeeId: string;
  name: string;
  phoneNumber: string;
  manifests: string[];
  objects: Record<string, string>;
}

export interface Bundle {
  v: 1;
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
  mediaType?: string;
  replyToId?: number | null;
}

export interface ChatSummary {
  account: string;
  accountName: string;
  chat: string;
  title: string;
  type: string | null;
  messages: number;
  media: number;
  lastAt: string | null;
}

export interface Message {
  account: string;
  accountName: string;
  chat: string;
  chatTitle: string;
  msgId: number | null;
  date: string | null;
  sender: string | null;
  type: string;
  text: string;
  mediaType?: string;
}

export class WrongPasswordError extends Error {
  constructor() {
    super('Wrong archive password.');
  }
}

const FETCH_CONCURRENCY = 8;
const MAX_SEARCH_SCAN = 5000;

export async function fetchBundle(archiveUrl: string, token: string): Promise<Bundle> {
  const res = await fetch(archiveUrl, { headers: { authorization: `Bearer ${token}` } });
  if (!res.ok) {
    throw new Error(`Archive request failed: HTTP ${res.status} ${await res.text().catch(() => '')}`.trim());
  }
  const bundle = (await res.json()) as Bundle;
  if (bundle?.v !== 1 || !bundle.key?.publicKeyB64 || !Array.isArray(bundle.accounts)) {
    throw new Error('The archive endpoint returned something that is not a TG Cerber bundle.');
  }
  return bundle;
}

export class Vault {
  private readonly entries = new Map<string, Promise<ManifestEntry[]>>();
  private readonly records = new Map<string, Promise<MessageRecord | null>>();

  private constructor(
    private readonly pub: Uint8Array,
    private readonly priv: Uint8Array,
    readonly organization: Bundle['organization'],
    readonly accounts: Account[],
  ) {}

  static async open(bundle: Bundle, password: string): Promise<Vault> {
    await sodium.ready;
    const priv = unwrap(bundle.key.wrappedPrivateKey, password);
    const pub = sodium.from_base64(bundle.key.publicKeyB64, sodium.base64_variants.ORIGINAL);
    return new Vault(pub, priv, bundle.organization, bundle.accounts);
  }

  listAccounts(): Array<{ account: string; name: string; phoneNumber: string; objects: number }> {
    return this.accounts.map(a => ({
      account: a.employeeId,
      name: a.name,
      phoneNumber: a.phoneNumber,
      objects: Object.keys(a.objects).length,
    }));
  }

  async listChats(account?: string): Promise<ChatSummary[]> {
    const selected = account ? [this.resolveAccount(account)] : this.accounts;
    const out: ChatSummary[] = [];
    for (const acc of selected) {
      const chats = new Map<string, ChatSummary & { lastMs: number }>();
      for (const e of await this.entriesFor(acc)) {
        const key = chatKey(e);
        let chat = chats.get(key);
        if (!chat) {
          chat = {
            account: acc.employeeId,
            accountName: acc.name,
            chat: key,
            title: e.chatTitle || 'Chat',
            type: e.chatType ?? null,
            messages: 0,
            media: 0,
            lastAt: null,
            lastMs: 0,
          };
          chats.set(key, chat);
        }
        if (e.type !== 'service') chat.messages += 1;
        if (e.mediaKey) chat.media += 1;
        const ms = e.date ? Date.parse(e.date) || 0 : 0;
        if (ms > chat.lastMs) {
          chat.lastMs = ms;
          chat.lastAt = e.date ?? null;
        }
      }
      for (const { lastMs: _ignored, ...chat } of chats.values()) out.push(chat);
    }
    return out.sort((a, b) => Date.parse(b.lastAt ?? '') - Date.parse(a.lastAt ?? '') || a.title.localeCompare(b.title));
  }

  async getMessages(account: string, chat: string, opts: { limit: number; before?: string }): Promise<Message[]> {
    const acc = this.resolveAccount(account);
    const entries = (await this.entriesFor(acc)).filter(e => matchesChat(e, chat));
    if (!entries.length) {
      throw new Error(`No chat matching "${chat}" in ${acc.name}'s archive.`);
    }
    const beforeMs = opts.before ? Date.parse(opts.before) : Number.NaN;
    const scoped = Number.isNaN(beforeMs) ? entries : entries.filter(e => (e.date ? Date.parse(e.date) : 0) < beforeMs);
    const tail = scoped.sort(byTime).slice(-clamp(opts.limit, 1, 500));
    const records = await mapLimit(tail, e => this.recordFor(acc, e.msgKey));
    return records.flatMap((r, i) => (r ? [toMessage(acc, tail[i]!, r)] : []));
  }

  async search(query: string, opts: { account?: string; chat?: string; limit: number }): Promise<Message[]> {
    const needle = query.trim().toLowerCase();
    if (!needle) return [];
    const selected = opts.account ? [this.resolveAccount(opts.account)] : this.accounts;
    const hits: Message[] = [];
    for (const acc of selected) {
      let entries = (await this.entriesFor(acc)).filter(e => e.type !== 'service');
      if (opts.chat) entries = entries.filter(e => matchesChat(e, opts.chat!));
      entries = entries.sort(byTime).slice(-MAX_SEARCH_SCAN);
      const records = await mapLimit(entries, e => this.recordFor(acc, e.msgKey));
      records.forEach((r, i) => {
        if (r && `${r.text ?? ''}\n${r.sender ?? ''}`.toLowerCase().includes(needle)) {
          hits.push(toMessage(acc, entries[i]!, r));
        }
      });
    }
    return hits.sort((a, b) => Date.parse(b.date ?? '') - Date.parse(a.date ?? '')).slice(0, clamp(opts.limit, 1, 200));
  }

  private resolveAccount(selector: string): Account {
    const s = selector.trim().toLowerCase();
    const hit =
      this.accounts.find(a => a.employeeId === selector) ??
      this.accounts.find(a => a.name.toLowerCase() === s || a.phoneNumber === selector) ??
      this.accounts.find(a => a.name.toLowerCase().includes(s));
    if (!hit) {
      throw new Error(`No account matching "${selector}". Use list_accounts to see what is available.`);
    }
    return hit;
  }

  private entriesFor(acc: Account): Promise<ManifestEntry[]> {
    let pending = this.entries.get(acc.employeeId);
    if (!pending) {
      pending = mapLimit(acc.manifests, url => this.openJson<{ objects?: ManifestEntry[] }>(url)).then(shards =>
        shards.flatMap(s => s?.objects ?? []),
      );
      this.entries.set(acc.employeeId, pending);
    }
    return pending;
  }

  private recordFor(acc: Account, msgKey: string): Promise<MessageRecord | null> {
    let pending = this.records.get(msgKey);
    if (!pending) {
      const url = acc.objects[msgKey];
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
}

function unwrap(wrapped: WrappedPrivateKey, password: string): Uint8Array {
  const b64 = (s: string): Uint8Array => sodium.from_base64(s, sodium.base64_variants.ORIGINAL);
  const key = sodium.crypto_pwhash(sodium.crypto_secretbox_KEYBYTES, password, b64(wrapped.salt), wrapped.ops, wrapped.mem, wrapped.alg);
  try {
    return sodium.crypto_secretbox_open_easy(b64(wrapped.ct), b64(wrapped.nonce), key);
  } catch {
    throw new WrongPasswordError();
  }
}

function chatKey(e: ManifestEntry): string {
  return e.chatId != null && e.chatId !== '' ? String(e.chatId) : `title:${e.chatTitle}`;
}

function matchesChat(e: ManifestEntry, selector: string): boolean {
  const s = selector.trim().toLowerCase();
  const title = (e.chatTitle ?? '').toLowerCase();
  return chatKey(e) === selector || title === s || title.includes(s);
}

function byTime(a: ManifestEntry, b: ManifestEntry): number {
  const at = (e: ManifestEntry): number => (e.date ? Date.parse(e.date) || Number.MAX_SAFE_INTEGER : Number.MAX_SAFE_INTEGER);
  return at(a) - at(b) || a.msgKey.localeCompare(b.msgKey);
}

function toMessage(acc: Account, e: ManifestEntry, r: MessageRecord): Message {
  return {
    account: acc.employeeId,
    accountName: acc.name,
    chat: chatKey(e),
    chatTitle: r.chatTitle || e.chatTitle,
    msgId: r.msgId,
    date: r.date ?? e.date ?? null,
    sender: r.sender,
    type: r.type,
    text: r.text ?? '',
    ...(r.mediaType ? { mediaType: r.mediaType } : {}),
  };
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, Number.isFinite(n) ? Math.trunc(n) : lo));
}

async function mapLimit<T, R>(items: T[], fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]!);
    }
  };
  await Promise.all(Array.from({ length: Math.min(FETCH_CONCURRENCY, items.length) }, worker));
  return out;
}
