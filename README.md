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

Restart the client. Verify: the client lists a server named `tgcerber-archive` with four tools.

### 5. Tools the client will see

| Tool | Arguments | Returns |
|---|---|---|
| `list_accounts` | — | accounts in scope, with object counts |
| `list_chats` | `account?` | chats newest first: id, title, type, message and media counts |
| `get_chat_messages` | `account`, `chat`, `limit?` (≤500), `before?` (ISO) | most recent messages of one chat, chronological |
| `search_messages` | `query`, `account?`, `chat?`, `limit?` (≤200) | case-insensitive substring matches, newest first |

`account` accepts an id, an exact name or phone number, or a name substring. `chat` accepts a chat id or a title substring. All results are JSON text.

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

Source layout: `src/vault.ts` (fetch, unwrap, open, query), `src/server.ts` (MCP tools), `src/index.ts` (CLI and stdio transport). No network access besides the archive endpoint and the presigned object URLs it returns.

License: GPL-3.0-only.
