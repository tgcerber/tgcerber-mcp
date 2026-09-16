/**
 * The read side of the server's `b2b/backend/src/vault/chat-state.ts`, kept identical on purpose.
 *
 * What Telegram says about a DIALOG rather than about its messages: the auto-delete timer, how much
 * of it the owner has read, and how much of its media the archive keeps. It arrives in the bundle as
 * plaintext bookkeeping alongside `coverage`, because a manifest entry is immutable and these change
 * by the minute.
 *
 * The rules that RESOLVE a retention policy live on the server only — it is the only thing that sees
 * Telegram — so this file carries the vocabulary and the read-side judgements, and nothing else.
 */

/** How much of a chat's media the archive keeps. `none` means the chat is not archived at all. */
export type MediaPolicy = 'all' | 'documentsOnly' | 'textOnly' | 'none';

export const MEDIA_POLICIES: readonly MediaPolicy[] = ['all', 'documentsOnly', 'textOnly', 'none'];

export function isMediaPolicy(value: unknown): value is MediaPolicy {
  return typeof value === 'string' && (MEDIA_POLICIES as readonly string[]).includes(value);
}

/**
 * One observation of a dialog's Telegram-side state.
 *
 * Every field is what Telegram answered at `at`; a field Telegram did not answer is absent rather
 * than guessed, because "0 unread" and "we have not looked" are different claims and the console and
 * MCP both make the difference visible.
 */
export interface ChatStateRecord {
  /** Auto-delete period in seconds. 0 means the timer is off. Absent means Telegram did not say. */
  ttl?: number;
  /** Unread incoming messages, as Telegram counts them. */
  unread?: number;
  /** Unread mentions of this account. */
  mentions?: number;
  /** Id of the newest incoming message the account owner has read. */
  lastReadIn?: number;
  /** Id of the newest outgoing message the other side has read. */
  lastReadOut?: number;
  /** The owner marked the chat unread by hand, whatever the count says. */
  manualUnread?: boolean;
  /**
   * Members in the last recorded member list. Only used to decide whether a group is one the owner
   * merely reads (the `auto` retention rule); the list itself is sealed, this is its length.
   */
  members?: number;
  /**
   * The media retention policy resolved for this chat, and which rule decided it.
   *
   * Stored rather than recomputed because the live tap seals messages one at a time and has neither
   * the folder rules nor the member count at hand — and because the alternative, keeping the chat's
   * folder NAMES in a plaintext column so the tap could resolve them, would put a piece of the
   * user's own labelling outside the sealed archive for no gain.
   */
  policy?: MediaPolicy;
  policyFrom?: string;
  /** When this observation was made (ISO). */
  at: string;
}

export type ChatStates = Record<string, ChatStateRecord>;

/** `list_chats.autoDelete`: the timer as the archive last saw it, or null when it never has. */
export interface AutoDeleteView {
  enabled: boolean;
  /** Seconds, when the timer is on; null when it is off. */
  seconds: number | null;
  /** When the archive last looked. */
  seenAt: string;
}

/** `list_chats.unread`: what the account owner has not read, as of `seenAt`. */
export interface UnreadView {
  count: number;
  mentions: number;
  /** Newest incoming message the owner has read; null when Telegram did not say. */
  lastReadMsgId: number | null;
  /** When that message was sent, resolved from the archive; null when it is not in the archive. */
  lastReadAt: string | null;
  /** The owner marked this chat unread by hand. */
  manuallyUnread?: boolean;
  seenAt: string;
}

export function autoDeleteView(state: ChatStateRecord | undefined): AutoDeleteView | null {
  if (!state || state.ttl === undefined) return null;
  return { enabled: state.ttl > 0, seconds: state.ttl > 0 ? state.ttl : null, seenAt: state.at };
}

/** The unread half of an observation, or null when the observation carries no read state. */
export function unreadView(state: ChatStateRecord | undefined): Omit<UnreadView, 'lastReadAt'> | null {
  if (!state || state.unread === undefined) return null;
  return {
    count: state.unread,
    mentions: state.mentions ?? 0,
    lastReadMsgId: typeof state.lastReadIn === 'number' && state.lastReadIn > 0 ? state.lastReadIn : null,
    ...(state.manualUnread ? { manuallyUnread: true } : {}),
    seenAt: state.at,
  };
}

/**
 * Why a message is no longer in Telegram: the chat's timer, or somebody's hand.
 *
 * The archive never loses the message either way — this only labels it. The judgement is made from
 * how long the message lived against the timer the chat is known to carry, because Telegram tells
 * nobody who deleted what: `updateDeleteMessages` carries ids and nothing else, and there is no
 * "expired" flag on it.
 *
 * The tolerances are asymmetric on purpose. A message deleted noticeably EARLIER than the timer
 * could have fired was deleted by a person — that is certain, so it is `manual`. A message deleted
 * noticeably LATER is not: our own observation can lag (the tap was down, the process restarted),
 * and a timer that fired during that window looks exactly like a person acting afterwards. Calling
 * that `manual` would be inventing a fact, so it is `unknown`.
 */
export function deletionReason(opts: {
  /** When the message was sent (ISO), from the archive. */
  sentAt: string | null;
  /** When the deletion was recorded (ISO). */
  deletedAt: string;
  /** The chat's timer as last observed, or null when it never was. */
  autoDelete: AutoDeleteView | null;
}): 'ttl' | 'manual' | 'unknown' {
  const { autoDelete } = opts;
  if (!autoDelete) return 'unknown';
  if (!autoDelete.enabled || !autoDelete.seconds) return 'manual';
  const sent = opts.sentAt ? Date.parse(opts.sentAt) : Number.NaN;
  const deleted = Date.parse(opts.deletedAt);
  if (!Number.isFinite(sent) || !Number.isFinite(deleted) || deleted < sent) return 'unknown';
  const ttlMs = autoDelete.seconds * 1000;
  const lived = deleted - sent;
  const early = Math.max(60_000, ttlMs * 0.05);
  const late = Math.max(10 * 60_000, ttlMs * 0.25);
  if (lived < ttlMs - early) return 'manual';
  if (lived <= ttlMs + late) return 'ttl';
  return 'unknown';
}

/**
 * Whether the account owner has read a message, from the chat's read markers.
 *
 * Two different questions share the word "read", and conflating them is how a dashboard ends up
 * lying to a sales manager: for an INCOMING message it means "I have seen it", for an OUTGOING one
 * the only interesting reading is "they have seen it". So the owner has by definition read their own
 * message, and whether the recipient did is reported separately.
 */
export function readState(
  state: ChatStateRecord | undefined,
  msg: { msgId: number | null; outgoing: boolean },
): { read: boolean; readByRecipient?: boolean } | null {
  if (!state || state.unread === undefined) return null;
  if (msg.msgId === null) return null;
  if (msg.outgoing) {
    const seen = typeof state.lastReadOut === 'number' ? msg.msgId <= state.lastReadOut : undefined;
    return { read: true, ...(seen === undefined ? {} : { readByRecipient: seen }) };
  }
  const lastRead = typeof state.lastReadIn === 'number' ? state.lastReadIn : 0;
  return { read: msg.msgId <= lastRead };
}
