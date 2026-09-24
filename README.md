# tgcerber-mcp

Local MCP bridge for **TG Cerber for Business**. It lets Claude read your organization's Telegram archive while the archive is decrypted **only on your machine** — TG Cerber's servers hand out ciphertext and never see a message.

## If you are a person

Give this repository to your AI coding agent (Claude Code, Cursor, Codex, …) with a sentence like:

> Set up the TG Cerber MCP bridge from this repo and connect it to my Claude Desktop / Claude Code. Here is my archive URL, connection token and archive password: …

Get those three values from the TG Cerber console: **Archive → Connect via MCP → Local**. Then let the agent follow the rest of this file.

---

## For AI agents

You are setting up a local MCP server that decrypts a Telegram archive on this machine and serves it to an MCP client. Follow these steps in order; each has a verification.

### 1. Inputs to obtain from the user

| Variable | Where the user gets it | Notes |
|---|---|---|
| `TGCERBER_ARCHIVE_URL` | Console → Archive → Connect via MCP → Local → *Archive URL* | Looks like `https://admin.tgcerber.com/console/mcp/local/archive` |
| `TGCERBER_TOKEN` | Same screen → *Connection token* | Shown once by the console. Opaque bearer. |
| `TGCERBER_VAULT_PASSWORD` | The organization's archive password, set by a superadmin | **Never send it anywhere except into this process's environment.** Prefer `TGCERBER_VAULT_PASSWORD_FILE` (a file whose first line is the password) so the secret does not live in a config file. |

Do not ask the user to paste the password into chat if it can be avoided; ask them to write it to a file with restrictive permissions and give you the path.

### 2. Build

Requires Node.js ≥ 20.

```sh
git clone https://github.com/oqtacore/tgcerber-mcp.git
cd tgcerber-mcp
npm install
npm run build
```

Verify: `node dist/index.js --version` prints a version.

### 3. Verify the connection before touching any MCP client

```sh
TGCERBER_ARCHIVE_URL="…" TGCERBER_TOKEN="…" TGCERBER_VAULT_PASSWORD_FILE="/path/to/pw" node dist/index.js --check
```

Expected on stderr: the organization name and a list of readable accounts with object counts.
Failure modes and what they mean:

- `TGCERBER_… is not set` — an input is missing; go back to step 1.
- `Archive request failed: HTTP 401` — the token is wrong, revoked, or the issuing admin lost access. The user must issue a new connection in the console.
- `wrong archive password` — the password is wrong. Do not retry blindly; ask the user.
- `0 readable account(s)` — the token's scope has no archives yet (no backup has run, or the admin selected accounts without archives). Nothing to fix here; wait for a backup.

### 4. Register with the MCP client

Use the **absolute path** to `dist/index.js`. Pass secrets as environment variables of the server entry, never as command-line arguments.

**Claude Code**

```sh
claude mcp add tgcerber-archive \
  -e TGCERBER_ARCHIVE_URL="…" \
  -e TGCERBER_TOKEN="…" \
  -e TGCERBER_VAULT_PASSWORD_FILE="/path/to/pw" \
  -- node /absolute/path/to/tgcerber-mcp/dist/index.js
```

**Claude Desktop** — add to `claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/`, Windows: `%APPDATA%\Claude\`):

```json
{
  "mcpServers": {
    "tgcerber-archive": {
      "command": "node",
      "args": ["/absolute/path/to/tgcerber-mcp/dist/index.js"],
      "env": {
        "TGCERBER_ARCHIVE_URL": "…",
        "TGCERBER_TOKEN": "…",
        "TGCERBER_VAULT_PASSWORD_FILE": "/path/to/pw"
      }
    }
  }
}
```

Restart the client. Verify: the client lists a server named `tgcerber-archive` with eight tools.

Optional: `TGCERBER_REFRESH_SECONDS` (default 30) is how often the bridge re-fetches the archive list while
serving, so messages archived after it started are read as they arrive.

### 5. Tools the client will see

| Tool | Arguments | Returns |
|---|---|---|
| `list_accounts` | — | accounts in scope, each with its archive state: messages, media, size, when it last received a message, and — while a sweep is filling it — chats read of total. `archive.messages` and `archive.media` are the same counts `list_chats` reports; `archive.sealedObjects` is the raw object count in the vault, larger because it counts every version of an edited message, member snapshots and service rows |
| `list_folders` | `account?` | the owner's Telegram folders and how many archived chats each holds |
| `list_chats` | `account?`, `folder?`, `unreadOnly?` | chats newest first: id, title, type, folders, message / media / deleted / edited counts, oldest archived message, `historyComplete`, for groups `members` (the count in the last recorded member list), `autoDelete` (Telegram's disappearing-message timer: `{enabled, seconds, seenAt}`, `{enabled:false}` when off, `null` when the archive has never looked), `unread` (`{count, mentions, lastReadMsgId, lastReadAt, seenAt}`) and `mediaPolicy` |
| `list_chat_members` | `account`, `chat` | everyone in a group — silent members included — with name, username, id, role (owner / admin / member / restricted), join date and inviter, as of the last full check (`capturedAt`); `former` lists people who left or were removed (when and how, from earlier lists and service rows); `changesSince` the joins and leaves seen after the snapshot; `note` when the answer is partial |
| `get_chat_messages` | `account`, `chat`, `limit?` (1–500), `before?`, `after?` (ISO), `includeService?`, `includeDocumentText?` | `{ messages, count, more, nextBefore, nextAfter }` — the newest `limit` messages by default, older with `before`, newer with `after`; `more` says whether messages remain in the paging direction, `nextBefore` / `nextAfter` are the timestamps to pass to continue (`null` when nothing remains); messages are chronological, with media facts (`media.facts` is `basic` for messages archived before 2026-09-10), `deletedAt` + `deletedReason`, `read` (and `readByRecipient` on your own messages), `edits`, `editedAt`; with `includeDocumentText` each document's full text rides in `media.documentText.text`; with `includeService` the service rows too, each with a readable `text` ("Fazil added Fedor") and a structured `event` |
| `search_messages` | `query`, `account?`, `chat?`, `folder?`, `sender?`, `before?`, `after?`, `includeService?`, `includeDocumentText?`, `limit?` (1–200) | `{ hits, scanned, total, partial }`; each hit says `matchedIn` (text, sender, fileName, document, transcript) with a `snippet` |
| `get_message_history` | `account`, `chat`, `msgId` | every archived version of one message, oldest first, plus the current one; `versionsKeptSince` and a `note` when an edited message has no captured earlier wording |
| `get_media` | `account`, `chat`, `msgId` | the file's facts (with `sha256`, the hex SHA-256 of the bytes returned, `null` when none are), then a photo as an image, a voice message as audio plus transcript, a document as its extracted text (PDF, Word, Excel, plain text) |

`account` is an id, an **exact** name, or a phone number — no partial matches, so a token scoped to some
of a hundred accounts can never answer for the wrong one. `chat` is a chat id or a title; a title that
matches several chats is refused with the candidates listed, so pass the id. Service rows (members
added, left or removed, renames, pins) are excluded unless `includeService` is set; since 2026-09-15
each says what happened, in `text` and in `event` (`kind`, `by`, `members` with names), and
`list_chat_members` gives a group's whole member list. A message Telegram deleted is still returned,
marked with `deletedAt` and `deletedReason` — `ttl` when the chat's disappearing-message timer did it,
`manual` when somebody did, `unknown` when it cannot be told apart. Nothing is ever removed from the
archive, a timer included. A message that was edited carries `edits`, and `get_message_history` returns
what it said before. `historyComplete: false` on a chat means the archive is still filling that chat's
history back to its first message; `historyFrom` is how far back it currently reaches.

Telegram renames a deleted account to "Deleted Account" everywhere, retroactively, so a person who
negotiated a deal in 2023 becomes anonymous in the archive the day they close their account. Where
that has happened, messages and member rows carry `lastKnownName`, `lastKnownUsername` and
`lastKnownAt` — the last identity that id was ever seen under anywhere this bundle reaches. All three
`null` means the archive never saw one, not that it did not look.

Read state and disappearing-message timers come from the dialog list, which the server re-reads every
couple of minutes and at every full check; each answer carries the `seenAt` it was true at, and a chat
whose state has never been observed answers `null` rather than zero. `mediaPolicy` is how much of a
chat's media the archive keeps — `all`, `documentsOnly`, `textOnly` or `none`, set by an admin in the
console. Under anything but `all` a message still carries its text and the file's name, type and
declared size, and `media.saved` is `false` with `skippedByPolicy` naming the rule: not a failed
download.

### 6. Security model, in one paragraph

The server holds the organization's X25519 public key, the private key wrapped under Argon2id(password), and message objects sealed to the public key. This bridge fetches those, unwraps the private key **in this process** with the password, and opens objects in memory. Nothing decrypted is written to disk; the password is not transmitted. Revoking the connection in the console invalidates the token immediately. The token's reach is the issuing admin's access at the moment of each request — if their access shrinks, so does the bridge's.

### 7. Things not to do

- Do not commit the token or password to any repository, dotfile in version control, or shell history you cannot clear.
- Do not run this on a shared machine where other users can read the client's config or the password file.
- Do not expose this server over the network; it is stdio-only by design. For a hosted connector the console offers a separate **Cloud** mode with a different trust model.

---

## Development

```sh
npm run check   # typecheck
npm run build   # emit dist/
```

Source layout: `src/vault.ts` (fetch, unwrap, open, query), `src/server.ts` (MCP tools), `src/index.ts` (CLI and stdio transport). No network access besides the archive endpoint and the presigned object URLs it returns. `npm test` builds and runs `test/selftest.mjs`: a throwaway archive sealed with real libsodium in the server's wire format, served locally, read through every tool over stdio.

Document text is extracted with `pdf-parse`, `mammoth` and `xlsx` when a document's record does not already carry it (the server extracts at archive time since 2026-09-10).

License: GPL-3.0-only.
