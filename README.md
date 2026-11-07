# trxmix

The TRON HTTP API through the [Nym mixnet](https://nym.com): java-tron's `/wallet`, `/walletsolidity`,
`/walletpbft` and `/jsonrpc`, and TronGrid's `/v1`, for mainnet and the Nile and Shasta testnets, or any node you
add. A local gateway for TronWeb, tronpy, wallets and curl, plus a small CLI. One Go binary, no dependencies outside
the standard library, MIT.

```
trxmix nym setup                         # starts nym-socks5-client on a random active exit gateway
trxmix serve                             # local gateway: http://127.0.0.1:8090 (mainnet), /nile, /shasta
trxmix info --network nile               # latest and solidified block, genesis check
trxmix balance TKHuVq1oKVru...           # TRX, staked TRX, bandwidth, energy, USDT and USDC (TRC20)
trxmix call TR7NHq... 'balanceOf(address)' T... --returns uint256   # any constant contract call
trxmix broadcast tx.json                 # forward a signed transaction; trxmix holds no keys
trxmix probe                             # which public nodes answer Nym exit traffic, and how fast
trxmix ip                                # the IP the nodes see (a Nym exit gateway)
```

## Why

USDT on TRON is the most used stablecoin rail for remittances and P2P trading, and almost every TRON wallet and
backend talks to one API operator: TronGrid, run by TRON DAO. A wallet asks it about your addresses all the time
(`getaccount`, `getaccountresource`, `triggerconstantcontract` with your address in `balanceOf`, `/v1/accounts/<you>/
transactions/trc20`), then sends your signed transaction with `broadcasttransaction`. The operator sees all of that
next to your IP. So it learns which IP holds which addresses, and which IP sent which transfer.

TronWeb takes a `fullHost` URL but has no proxy setting, and neither do most wallets. `trxmix serve` gives you a
plain `http://127.0.0.1:8090` for that field. The node then sees a Nym exit gateway, not you.

## Use

```
export TRXMIX_NYM_SOCKS5=/path/to/nym-socks5-client    # official Nym release binary
go install github.com/apeirs/trxmix/cmd/trxmix@latest
trxmix nym setup            # SOCKS5 on 127.0.0.1:1090 (--port to change; then set TRXMIX_PROXY)
trxmix serve &
```

The gateway serves every network on one port:

| Network | Base URL | Upstreams (tried in order) |
|---|---|---|
| Mainnet (the `--default`) | `http://127.0.0.1:8090` or `/mainnet` | api.trongrid.io (+`/jsonrpc`, +`/v1`), tron-rpc.publicnode.com (+`/jsonrpc`), api.tronstack.io |
| Nile testnet | `http://127.0.0.1:8090/nile` | nile.trongrid.io |
| Shasta testnet | `http://127.0.0.1:8090/shasta` | api.shasta.trongrid.io |
| Your own node or network | `/<name>` after `--add name=https://node\|https://node2` | yours |

Under each base URL: `/wallet/*`, `/walletsolidity/*`, `/walletpbft/*`, `/jsonrpc` and `/v1/*`, GET and POST,
passed through byte for byte. `/jsonrpc` and `/v1` only go to upstreams that serve them (TronGrid's indexed `/v1`
API exists on TronGrid only). For a client that can't take a base path, `--listen-net nile=127.0.0.1:8091` serves
Nile at the root of a second port.

Put the URL into your client:

- **TronWeb** (tested with 6.5.1): `new TronWeb({ fullHost: 'http://127.0.0.1:8090/nile' })`. Block, balance,
  account resources, `contract().at()` (ABI from the node), constant calls, chain parameters, and a transfer built
  and signed locally and sent with `trx.sendRawTransaction` all went through the gateway
  (`examples/tronweb-client.mjs`). A preload hook (`examples/no-bypass-hook.cjs`) recorded every TCP connect and DNS
  lookup of the Node process: the only one was `127.0.0.1:8090`.
- **TronLink and other wallets with a custom node setting**: enter the gateway URL as the full node and solidity
  node. Requests from browser extensions are allowed without a flag. I have not tested a wallet UI yet.
- **tronpy, curl, anything that takes a node URL**: `curl -X POST http://127.0.0.1:8090/wallet/getnowblock -d '{}'`.
  curl's default form content type is sent upstream as JSON, so the usual TRON API examples work as they are.
  tronpy is not tested yet; give it the root of a `--listen-net` port if it drops the `/nile` path.

Watch the gateway log when you wire up a new app. It prints one line per request with the network, the method or
route (never the params), the upstream and the timing. Anything that doesn't show up there did not go through Nym.

trxmix forwards; it never signs anything. `trxmix broadcast` takes a signed transaction as protobuf hex or as the
JSON TronWeb and tronpy produce (a file, `-` for stdin, or inline). It parses the protobuf itself and refuses,
before anything is sent: an unsigned transaction, a signature that isn't 65 bytes, an expired one, and JSON whose
`txID` isn't sha256(`raw_data_hex`) (it was edited after it was built). Then it sends it with `broadcasthex` and
prints the txid and the node's answer, hex error messages decoded. `trxmix balance` and `trxmix call` use
`triggerconstantcontract`; the node computes the function selector, so trxmix needs no keccak.

An optional TronGrid API key (higher rate limits) goes in `TRXMIX_TRONGRID_KEY`. It is sent as `TRON-PRO-API-KEY` to
`*.trongrid.io` only, never to other upstreams, never logged, and read only from the environment so it stays out of
shell history. Read the first limit below before you use one.

## How it uses the mixnet

- It drives the official `nym-socks5-client` and does no mixing itself. `nym setup` picks a random active exit
  gateway from the Nym API (one that runs an exit-policy network requester), with reply SURBs on, so the exit
  doesn't learn your mixnet address.
- Each upstream connection is a SOCKS5 stream through the entry gateway, three mix layers and the exit, to port
  443. TLS runs end to end with the node, so the exit only relays ciphertext. Connections are kept alive, so the
  calls after the first one don't pay a new stream and TLS handshake.
- Node hostnames are resolved by DNS-over-HTTPS *through the mixnet*, then connected by IPv4. The local resolver
  never learns which node you use.
- **Genesis guard.** Before an upstream gets its first request, trxmix asks it for block 0 (`getblockbynum`) and
  compares the block id with the network's. An upstream of another chain (a testnet URL under mainnet, a typo in
  `--add`, a node that changed hands) is skipped and the next one is tried; your requests never reach it. Built-in
  networks have their genesis pinned in the code. A network you add pins the genesis of its first upstream, and
  every other upstream of it has to match.
- The gateway can only reach the configured upstreams and only the TRON API routes. The first path segment picks
  the network, the rest has to be one of the routes above. Encoded dots and anything else are 404, so a caller
  can't steer a request to another path or host.
- There is no clearnet fallback. With the mixnet client down, the gateway answers 502 in java-tron's own error shape
  (`{"Error": ..., "reason": "MixnetUnavailable"}`, which TronWeb and tronpy show), and the CLI refuses to run.
- Failover: a connection error, a timeout, a failed genesis check, HTTP 5xx, 429 or a redirect moves on to the next
  upstream. Redirects are never followed or passed back.
- Nothing from the local caller is forwarded except the method, path, query and body. Upstream sees
  `Content-Type`, `Accept` and a fixed `User-Agent`: no `Origin`, `Cookie`, `Authorization`, `Referer`, the
  wallet's own user agent or its own API key. Only `Content-Type` comes back.
- The gateway listens on loopback and rejects a foreign `Host` header (DNS-rebinding guard). It also rejects any
  web-page `Origin`, so a site you visit can't use your gateway. Browser extensions and non-browser clients are
  allowed; `--allow-origin` adds pages.
- Logs name the network, the java-tron method (`/wallet/getaccount`), the JSON-RPC method (`/jsonrpc eth_call`) or
  the `/v1` route with every parameter segment as `*` (`/v1/accounts/*/transactions/trc20`), the upstream and the
  timing. Addresses, contract arguments, txids, query strings and bodies are never logged, not even in error
  messages.

## Limits (read these)

- **It hides your IP, not your addresses.** The node still sees which addresses you query and which transactions you
  send, and everything on chain stays public. trxmix removes the IP link, not the on-chain one.
- **A TronGrid API key is an identity.** The key belongs to a TronGrid account, so with `TRXMIX_TRONGRID_KEY` set,
  TronGrid links every request to that account even though the IP is hidden. Use one only if TronGrid already knows
  that account is you, or go keyless.
- **One exit IP, one session.** All requests leave through the same exit gateway, so the node can link the
  addresses a wallet asks about to each other ("one user watches these five addresses"). For unlinkable sessions,
  run separate client identities (`trxmix nym setup --id other --port 1091`) and separate gateways.
- **Shared rate limits.** Keyless TronGrid traffic is limited per IP, and the exit IP is shared with other Nym
  users. I hit no 429 in my run. If you do, mainnet moves on to publicnode and TronStack; Nile and Shasta have only
  TronGrid.
- **Latency is seconds.** In my live run a CLI command on a fresh mixnet stream took 4.2 to 7.8 s (DoH, TLS and the
  genesis check included). Through the gateway the first request per network took 6 to 9 s, later ones 0.8 to
  1.4 s on the kept-alive stream; TronWeb's calls took 0.8 to 2.8 s. A TRON transaction expires 60 s after
  TronWeb builds it, which leaves plenty of room. Fine for a wallet; slow for an indexer.
- **Clients that ignore your URL bypass it.** trxmix only protects requests that reach it. A wallet's price feeds,
  token logos and analytics are not covered. Check with the gateway log, or with the preload hook for Node apps.
- **A rejected transaction can be linked to its retry.** Re-sending the same signed bytes from a different exit
  still has the same txid.
- Not tested yet: TronLink and other wallet UIs, tronpy, TronWeb's event API, `/walletpbft`.

## Tests

`go vet ./... && go test ./...` runs offline against a fake mixnet: a recording SOCKS5 proxy, a DoH server and fake
TLS TRON nodes. The tests check that:

- every connection goes through the proxy, and the only name lookups are DoH over it;
- GET paths and queries and POST bodies pass through byte for byte, after the upstream's genesis check;
- an upstream of another chain is skipped before it sees a request, and a custom network pins the genesis of its
  first upstream;
- `/jsonrpc` and `/v1` go only to upstreams that serve them;
- `/<network>` routes and `--listen-net` roots work, and nothing outside the TRON API routes, no encoded dots and no
  websocket upgrade get through;
- request and response headers are stripped, and the API key goes to `*.trongrid.io` only (genesis check
  included);
- the Host and Origin guards hold;
- with no proxy there is a 502 and no fallback, in both DNS modes, even when a direct connection to the upstream
  would work;
- failover covers connection errors, timeouts, 5xx, 429 and redirects (which are never followed), and only https
  upstreams are accepted;
- no address, contract argument, txid, transaction bytes, query string or API key reaches a log line or an error
  answer, on success or failure;
- base58check addresses, the transaction protobuf parser (unsigned, bad signature, expired, edited JSON, unknown
  fields), ABI encoding and decoding, and the log labels match known vectors.

I also broke each guard on purpose (42 mutations: Host and Origin guards, route allowlist, encoded dots, the
genesis check and its pinning, https-only upstreams, route-aware upstreams, a planted clearnet fallback in the
dialer and in the HTTP client, local DNS, redirects, failover, timeouts, API-key scoping, log redaction, header
stripping, body types, the websocket refusal, address checksums and every broadcast refusal) and checked that a
test fails every time.

The live run against public nodes through the real Nym mixnet is in `examples/`: `live-2026-11-07.txt` (CLI,
gateway with curl, guards, broadcast refusals, the no-fallback check), `live-tronweb.txt` (TronWeb with the
preload hook, and a transfer signed by a fresh, never-funded Nile key: the node rejected it with
`account [...] does not exist`), `live-gateway.log` and `nym-client-proxy-lines.txt`.
