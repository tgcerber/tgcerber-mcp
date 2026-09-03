// End-to-end self-test against a throwaway archive: real libsodium sealing in the server's wire
// format, served from a local HTTP server, read back through the built bridge — once via --check
// and once as an MCP client over stdio. No network, no credentials, no TG Cerber account needed.
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const sodium = createRequire(import.meta.url)('libsodium-wrappers-sumo');
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ENTRY = path.join(ROOT, 'dist', 'index.js');
const PASSWORD = 'selftest-password-123456';
const TOKEN = 'selftest-token';

await sodium.ready;
const B64 = sodium.base64_variants.ORIGINAL;
const b64 = bytes => sodium.to_base64(bytes, B64);

const keypair = sodium.crypto_box_keypair();
const params = {
  ops: sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
  mem: sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
  alg: sodium.crypto_pwhash_ALG_ARGON2ID13,
};
const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
const wrapKey = sodium.crypto_pwhash(sodium.crypto_secretbox_KEYBYTES, PASSWORD, salt, params.ops, params.mem, params.alg);
const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
const wrapped = {
  v: 1,
  salt: b64(salt),
  ...params,
  nonce: b64(nonce),
  ct: b64(sodium.crypto_secretbox_easy(keypair.privateKey, nonce, wrapKey)),
};
const seal = value => ({ sealedB64: b64(sodium.crypto_box_seal(sodium.from_string(JSON.stringify(value)), keypair.publicKey)) });

const messages = [
  { chatId: 42, chatTitle: 'David Klein', chatType: 'user', msgId: 1, date: '2026-09-01T14:02:00Z', type: 'text', text: 'Could you send the final version of the contract by Friday?', sender: 'David Klein', senderId: 7 },
  { chatId: 42, chatTitle: 'David Klein', chatType: 'user', msgId: 2, date: '2026-09-01T14:07:00Z', type: 'text', text: 'Sending it by end of day.', sender: 'Alex Kade', senderId: 1 },
  { chatId: 99, chatTitle: 'Partners chat', chatType: 'group', msgId: 3, date: '2026-09-02T09:00:00Z', type: 'text', text: 'Quarterly numbers attached.', sender: 'Nina', senderId: 9 },
];
const objects = {};
const entries = messages.map(m => {
  const msgKey = `org/o/emp/e/msg/${m.msgId}.json`;
  objects[msgKey] = seal(m);
  return { msgKey, mediaKey: null, type: 'text', chatTitle: m.chatTitle, chatId: m.chatId, chatType: m.chatType, date: m.date };
});
const manifestKey = 'org/o/emp/e/manifests/0.json';
objects[manifestKey] = seal({ v: 1, seq: 0, objects: entries, counts: { messages: messages.length, media: 0 } });

const server = createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const json = value => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify(value));
  };
  if (url.pathname === '/archive') {
    if (req.headers.authorization !== `Bearer ${TOKEN}`) {
      res.writeHead(401, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ message: 'bad token' }));
    }
    const base = `http://127.0.0.1:${server.address().port}/obj/`;
    const urlFor = key => base + encodeURIComponent(key);
    return json({
      v: 1,
      organization: { orgId: 'selftest', name: 'Self Test' },
      key: { publicKeyB64: b64(keypair.publicKey), wrappedPrivateKey: wrapped },
      accounts: [
        {
          employeeId: 'e',
          name: 'Alex Kade',
          phoneNumber: '+10000000000',
          manifests: [urlFor(manifestKey)],
          objects: Object.fromEntries(Object.keys(objects).filter(k => k !== manifestKey).map(k => [k, urlFor(k)])),
        },
      ],
    });
  }
  if (url.pathname.startsWith('/obj/')) {
    const sealed = objects[decodeURIComponent(url.pathname.slice(5))];
    if (!sealed) {
      res.writeHead(404);
      return res.end();
    }
    return json(sealed);
  }
  res.writeHead(404);
  res.end();
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const env = {
  TGCERBER_ARCHIVE_URL: `http://127.0.0.1:${server.address().port}/archive`,
  TGCERBER_TOKEN: TOKEN,
  TGCERBER_VAULT_PASSWORD: PASSWORD,
};

function run(args, extraEnv, stdinMessages) {
  return new Promise(resolve => {
    const child = spawn(process.execPath, [ENTRY, ...args], { env: { ...process.env, ...env, ...extraEnv } });
    let out = '';
    let err = '';
    child.stdout.on('data', chunk => (out += chunk));
    child.stderr.on('data', chunk => (err += chunk));
    child.on('close', code => resolve({ code, out, err }));
    if (stdinMessages) {
      for (const message of stdinMessages) child.stdin.write(`${JSON.stringify(message)}\n`);
      setTimeout(() => child.kill(), 5000);
    }
  });
}

let failures = 0;
const check = (name, ok, detail = '') => {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${ok ? '' : ` — ${detail}`}`);
  if (!ok) failures += 1;
};

const good = await run(['--check']);
check('--check reads the archive', good.code === 0 && /1 readable account/.test(good.err), good.err.trim());

const wrongPassword = await run(['--check'], { TGCERBER_VAULT_PASSWORD: 'not-it' });
check('wrong password is refused', wrongPassword.code === 1 && /wrong archive password/.test(wrongPassword.err), wrongPassword.err.trim());

const badToken = await run(['--check'], { TGCERBER_TOKEN: 'bad' });
check('bad token is refused', badToken.code === 1 && /HTTP 401/.test(badToken.err), badToken.err.trim());

const session = await run([], {}, [
  { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'selftest', version: '0' } } },
  { jsonrpc: '2.0', method: 'notifications/initialized' },
  { jsonrpc: '2.0', id: 2, method: 'tools/list' },
  { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'search_messages', arguments: { query: 'contract' } } },
  { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'list_chats', arguments: {} } },
  { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'get_chat_messages', arguments: { account: 'alex', chat: 'david', limit: 10 } } },
]);
const replies = Object.fromEntries(
  session.out
    .split('\n')
    .filter(Boolean)
    .map(line => {
      try {
        return JSON.parse(line);
      } catch {
        return null;
      }
    })
    .filter(reply => reply && reply.id != null)
    .map(reply => [reply.id, reply]),
);
const payload = id => JSON.parse(replies[id]?.result?.content?.[0]?.text ?? 'null');

check('initialize is answered', Boolean(replies[1]?.result?.serverInfo), JSON.stringify(replies[1]));
check('four tools are listed', replies[2]?.result?.tools?.length === 4, JSON.stringify(replies[2]?.result?.tools?.map(t => t.name)));
const hits = payload(3);
check('search finds the contract message', Array.isArray(hits) && hits.length === 1 && /contract/.test(hits[0].text), JSON.stringify(hits));
const chats = payload(4);
check('chats are listed newest first', Array.isArray(chats) && chats.length === 2 && chats[0].title === 'Partners chat', JSON.stringify(chats));
const thread = payload(5);
check('a chat is read in order', Array.isArray(thread) && thread.length === 2 && thread[0].msgId === 1 && thread[1].msgId === 2, JSON.stringify(thread));

server.close();
process.exit(failures ? 1 : 0);
