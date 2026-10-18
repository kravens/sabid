# sabid

A Rust re-implementation of the Wasabi Wallet daemon. It speaks the WabiSabi coinjoin protocol
to any Wasabi coordinator, reads and writes Wasabi's own wallet files and `Config.json`, serves
Wasabi's JSON-RPC so existing tooling keeps working, drives hardware wallets through their native
coinjoin flows (Trezor, Coldcard Mk4), and exposes everything to agents over MCP.

Experimental. It has completed real mainnet rounds with a Coldcard under an HSM policy, but it is
young code around real money: use a test wallet first, keep amounts small, read `PLAN.md` for the
design notes and the progress log.

## What works

- Wallet sync from Wasabi's block-filter index (BIP 158), blocks from a local Bitcoin Core node
  over Tor, Wasabi's block cache, or P2P onion peers; Wasabi's `BlockchainAnalyzer` anonymity scores.
- Full WabiSabi round client: coin selection, amount decomposition, credential dependency graph,
  input/connection/output/signing phases, blame rounds, coin prison, round-id verification.
- Soft wallets (BIP 38 encrypted master key, password at `startcoinjoin`), Trezor (SLIP-25 coinjoin
  account over the bridge API), Coldcard Mk4 on the `coinjoin-fw-2` firmware (hidraw, HSM policy).
- Wasabi-compatible JSON-RPC, a CLI, an MCP server.

Not yet: sending from a Trezor, Passport and Krux, pure-Rust WabiSabi crypto (the vendored C
library is used through FFI). `send`, the fee bumps, mempool pickup and recovery passed the regtest smoke test;
`startcoinjoinsweep` and the device import/enable methods have not run end to end yet.

## Build

Linux, Rust 1.85 or newer, a C compiler. The C dependencies (`libwabisabi`, `secp256k1`) are
vendored and built by `cc`; no cmake, no system libraries.

```sh
cargo build --release          # target/release/sabid
cargo test --workspace
BITCOIND=/path/to/bitcoind BITCOIN_CLI=/path/to/bitcoin-cli scripts/regtest-smoke.sh
```

The smoke test starts a throwaway regtest node under `/tmp/sabid-regtest`, creates two wallets,
mines, syncs, sends, bumps and cancels with RBF, picks up a foreign payment from the mempool and
recovers a wallet from its words. It touches nothing under `~/.walletwasabi` or `~/.sabid`.

## Run

sabid reads `~/.walletwasabi/client/Config.json` (coordinator, RPC credentials and listen prefix,
Bitcoin Core RPC endpoint and credentials), Wasabi's filter index, block cache and transaction
store, all read-only. Everything it writes lives under `~/.sabid/` (`--datadir`): on the first
load of a wallet its file is copied from `~/.walletwasabi/client/Wallets/` to
`~/.sabid/Main/Wallets/` and only that copy is updated from then on (key states, labels, device
settings); the per-coordinator ban list is copied the same way. Wasabi's own files are never
written. `--wallet-dir` points both reading and writing at a directory of your choice instead.

```sh
sabid daemon --wallet MyWallet                      # RPC on the Config.json prefix, 127.0.0.1:37128 by default
sabid daemon --wallet A --wallet B --rpc-bind 127.0.0.1:37129 --wallet-dir ~/wallets --datadir ~/sabid-data
sabid daemon --wallet MyWallet --coordinator https://coinjoin.nl   # override CoordinatorUri
sabid --config ./Config.json --network regtest daemon --no-tor       # another config file, another network
```

Tor: sabid uses a SOCKS proxy on `127.0.0.1:37150` (Wasabi's) or `:9050` when one answers, else it
starts a `tor` binary (`--tor-binary`, or Wasabi's bundled one if found). `--socks host:port`
forces a proxy, `--no-tor` is for regtest only. Every coordinator identity (each input, each
output, status polling) gets its own circuit.

Bitcoin Core: `BitcoinRpcEndPoint` and `BitcoinRpcCredentialString` from `Config.json`, reached
over Tor when it is an onion address. With a node, unconfirmed transactions that pay or spend a
loaded wallet are picked up from its mempool every two minutes (transactions already in the
mempool when sabid starts are only seen once they confirm). Without a node, blocks come from the
block cache and P2P.

sabid refuses to start while a Wasabi GUI or daemon runs (`wassabee`, `wassabeed`, or `dotnet`
with their assemblies), and if Wasabi starts later it stops coinjoining, lets a round in its
critical phase finish, and exits with the same warning: both would register the same coins with
the coordinator, and Wasabi rewrites the stores sabid reads. Since sabid keeps its own wallet
copy, Wasabi does not see labels or key states sabid wrote until you run `sabid export-wallet`
(with both programs stopped; the old file is backed up next to it); without that, Wasabi
rediscovers sabid's coinjoin outputs through its gap limit.

Other commands:

```sh
sabid status [--coordinator URL]           # rounds, phases, timeouts, round-id check
sabid devices                              # Trezor bridge devices, a Coldcard on USB with its HSM state
sabid import-wasabi-txs --wallet MyWallet  # seed the tx store from Wasabi's ConfirmedTransactions, no rescan
sabid export-wallet --wallet MyWallet      # copy sabid's wallet file (labels, key states) back over Wasabi's, with a backup
sabid rpc getwalletinfo --wallet MyWallet  # any RPC method, params as a JSON array or object
sabid create-wallet --name MyWallet        # prompts for the password, prints the 12 words once
sabid recover-wallet --name MyWallet [--birth-height N]   # prompts for words and password
sabid unlock --wallet MyWallet [--ttl 3600]  # soft wallet: type the password here, the daemon keeps the key for --ttl seconds
sabid lock --wallet MyWallet
sabid rpc startcoinjoin --wallet MyWallet  # no password once unlocked (or pass '["password", true, true]')
sabid mcp [--url http://127.0.0.1:37128/]  # MCP server on stdio
```

## JSON-RPC

Same shape as Wasabi's: JSON-RPC 2.0 over HTTP, daemon-wide methods on `/`, wallet methods on
`/<wallet name>`, HTTP Basic auth when `JsonRpcUser`/`JsonRpcPassword` are set, batches accepted.

```sh
curl -s -u user:pass http://127.0.0.1:37128/MyWallet \
  -d '{"jsonrpc":"2.0","id":"1","method":"listunspentcoins"}'
```

| method | params | notes |
|---|---|---|
| `getstatus` | | Tor, best height, filters left, network |
| `listwallets` | | wallet files the daemon can see |
| `createwallet` | `[walletName, password]` | new 12-word soft wallet, birth height = current tip; returns the words (never over MCP) |
| `recoverwallet` | `[walletName, mnemonic, password, birthHeight?]` | Wasabi-format file from the words; scans from `birthHeight` (default: first segwit block) |
| `loadwallet`, `selectwallet` | `[name]` | loads and starts syncing |
| `getwalletinfo` | | balance, accounts, `coinjoinStatus`, `syncProgress`, `lastError`, device settings |
| `listunspentcoins`, `listcoins` | | amount, anonymity score, label, confirmations (`listcoins` includes spent) |
| `gethistory` | | per transaction: amount delta, height, coinjoin flag |
| `getnewaddress` | `[label]` | label required, as in Wasabi |
| `listkeys` | | |
| `excludefromcoinjoin` | `[txid, index, exclude]` | |
| `getfeerates` | | from the node's `estimatesmartfee` |
| `build` | `{payments, coins, feeTarget \| feeRate, password}` | signed transaction hex; the coins given are the inputs, change to the next internal key, RBF on. Soft wallets and Coldcards (device confirms, or its HSM policy decides) |
| `send` | same | builds, broadcasts through the node, records the transaction; returns `{txid, tx}` |
| `broadcast` | `[txHex]` | through the node; recorded in the wallets it touches |
| `canceltransaction`, `speeduptransaction` | `[txId, password]` | RBF replacement hex of an unconfirmed transaction of the wallet (cancel: everything back to a fresh key; speed up: extra fee from the change output); broadcast it with `broadcast` |
| `unlockwallet` | `[password, ttlSeconds]` | soft wallets: decrypt the key in the daemon for `ttlSeconds` (default 3600, max 86400); `getwalletinfo.unlocked` |
| `lockwallet` | | erase the decrypted key and stop a running coinjoin after its round |
| `startcoinjoin` | `[password, stopWhenAllMixed, overridePlebStop]` | empty password uses the unlocked key; device wallets need none |
| `startcoinjoinsweep` | `[password, outputWalletName]` | coinjoin every coin, private ones too, into another loaded wallet until stopped |
| `payincoinjoin` | `[address, amount, password]` | soft wallets: queue a payment to ride along as an output of a later round; returns its id |
| `listpaymentsincoinjoin` | | id, amount, destination script, address, state history (Pending, In progress, Signed, Finished) |
| `cancelpaymentincoinjoin` | `[paymentId]` | only while pending |
| `stopcoinjoin` | | takes effect after the critical phase |
| `enumeratedevices` | | HWI-shaped list: a Coldcard on USB, Trezors on the bridge |
| `importhardwarewallet` | `[walletName, enableCoinjoin, birthHeight?]` | watch-only file from the connected device (Coldcard must not be in HSM mode); Trezor with coinjoin gets its SLIP-25 account |
| `enablecoinjoin` | | device wallet: Trezor adds the SLIP-25 account and rescans, Coldcard records itself as the signer |
| `enabletaproot` | | Coldcard wallet imported segwit-only: adds the `86'` account and rescans |
| `setcoinjoinlimits` | `[maxRounds, maxFeeRate, minInputs]` | device limits, Coldcard re-approves its policy |
| `displayaddress` | `[address]` | on the device screen |
| `stop` | | |

## sabi.py (TUI)

[sabi.py](https://github.com/kravens/coinjoin.nl/tree/main/scripts) is a terminal UI for the Wasabi
daemon. It talks JSON-RPC, so it works against sabid with one difference: sabi can download and
launch `wassabeed` itself, while sabid you start by hand. Flow:

1. In `Config.json` set `"JsonRpcServerEnabled": true`, `JsonRpcUser`, `JsonRpcPassword` and (if
   sabi should see it) `CoordinatorUri`; sabi's `c` key edits `CoordinatorUri` and sabid reads it at start.
2. `sabid daemon --wallet MyWallet` (keep the default `127.0.0.1:37128` or pass sabi the port).
3. `python3 sabi.py --rpc http://127.0.0.1:37128 --wallet MyWallet`.

sabi's coinjoin dashboard, coin list, history, receive, start/stop and device limits use methods
sabid has, as do its send tab, the speed-up / cancel actions and the payments-in-coinjoin
screen; `wcli.sh` style one-liners work as is.

## MCP

`sabid mcp` is a Model Context Protocol server on stdio: newline-delimited JSON-RPC
(`initialize`, `tools/list`, `tools/call`), a thin client of a running daemon. No credentials
pass through the agent: it reads `Config.json` for the RPC URL and auth, or takes `--url`.

Register it with Claude Code:

```sh
claude mcp add sabid -- /path/to/sabid mcp --url http://127.0.0.1:37128/
```

or in any MCP client config:

```json
{"mcpServers": {"sabid": {"command": "/path/to/sabid", "args": ["mcp"]}}}
```

Tools: `getstatus`, `listwallets`, `loadwallet`, `getwalletinfo`, `listunspentcoins`,
`gethistory`, `getnewaddress` (label required), `startcoinjoin`, `stopcoinjoin`,
`enumeratedevices`, and `rpc` (any method, `{"method", "params", "wallet"}`) for the rest. Wallet
tools take `{"wallet": "<name>"}`. Amounts are satoshis.

Secrets never cross the MCP channel: no tool takes a password (`startcoinjoin` has none; a soft
wallet is unlocked on the daemon host with `sabid unlock`, which types the password into the
daemon's memory for a limited time, 24 h at most, and `getwalletinfo.unlocked` tells an agent
whether that has happened); the `rpc` passthrough only forwards an allowlist of agent-safe methods
(no `unlockwallet`, no `stop`, no method that takes a password) and blanks the password slot of
`startcoinjoin`; and both the daemon (`src/secrets.rs`, applied to every RPC answer) and the MCP
client refuse to forward an answer that contains key material (fields named like secrets, chain
codes, mnemonics, passwords or private keys, or strings shaped like `xprv`/`zprv`, WIF or BIP 38
keys). `sabid lock` erases the cached key and ends a running coinjoin after its round, since that
round holds its own copy. No RPC method reads the wallet's encrypted secret except the unlock path.
Example exchange:

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"getwalletinfo","arguments":{"wallet":"MyWallet"}}}
{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"balance\":...,\"coinjoinStatus\":\"Idle\"}"}]}}
```

An agent can therefore load a wallet, inspect coins and anonymity scores, start a coinjoin on a
hardware wallet (the device asks the human to approve the rounds or the HSM policy), and watch
`coinjoinStatus` and `gethistory` until the round is broadcast. `build`, `send` and `broadcast`
are reachable too: while a soft wallet is unlocked, an agent can spend from it. Unlock for as
long as you mean that, or keep agents on hardware wallets, where the device confirms.

## Hardware wallets

**Trezor** (T, Safe 3/5) with a coinjoin account (SLIP-25, `TaprootAccountKeyPath` under
`10025'`) over the classic bridge API on `127.0.0.1:21325` (pytrezord) or `:21328`.
`startcoinjoin` asks the device to authorize `CoinJoinDeviceMaxRounds` rounds at
`CoinJoinDeviceMaxMiningFeeRate` sat/vB (hold to confirm); ownership proofs and signatures then
come without interaction, one round per authorized round.

**Coldcard Mk4** on the `coinjoin-fw-2` firmware (6.6.1X Edge) over hidraw (`/dev/hidraw*` must be
readable by your user). `startcoinjoin` installs the HSM policy built from the wallet's
`ColdcardMaxSatsLeaving`, `ColdcardMaxTransactionsPerPeriod`, `ColdcardPeriodMinutes`,
`ColdcardMinInputs`, `CoinJoinDeviceMaxRounds` and `CoinJoinDeviceMaxMiningFeeRate`; approve it
on the device once (a device already running the wallet's recorded policy is reused). Ownership
proofs come from `slp9`; each round is signed as a PSBT under the policy, every input carrying its
witness UTXO (the firmware fails late without them). The device needs about 4.3 ms per PSBT byte,
so a round must fit the coordinator's signing phase: coinjoin.nl (100 inputs max, 129 s) does,
kruw.io (500 inputs, 57 s) does not. `cargo test -p hw --release --test coldcard_timing --
--ignored --nocapture` with `SABID_WALLET_JSON` set times a synthetic round on your device.

## Experimental directions

Ideas on the table, none implemented yet; each gets a design section in `PLAN.md` before code.

- **Hybrid liquidity, Kruw's "Four Horsemen"**: one client that mixes WabiSabi rounds, ZeroLink
  standard denominations, JoinMarket makers for on-demand liquidity and payjoin. For sabid the
  first step is a JoinMarket-compatible maker/taker side that offers WabiSabi-denominated coins
  (the standard denomination set the decomposer already produces) into JoinMarket transactions, so
  both pools' liquidity overlaps instead of fragmenting.
  [Spec discussion](https://delvingbitcoin.org/t/the-four-horsemen/2728).
- **Payjoin v2 (BIP 77)** for receiving and sending on segwit and taproot through
  [Payjoin Dev Kit](https://github.com/payjoin/rust-payjoin) (`payjoin` crate, async OHTTP relay +
  directory flow, `payjoin-mailroom` for self-hosting). sabid is Rust, so the crate plugs in
  directly; receive is the natural first step (a long-lived receiver session per wallet address),
  send follows once ordinary sending exists.
- Pure-Rust WabiSabi credentials (drop the C FFI), Passport and Krux signers, mempool scanning.

## Layout

| crate | what |
|---|---|
| `wabisabi-sys` | FFI to the vendored C `libwabisabi` (zkSNACKs/NWabiSabi) + secp256k1 |
| `wabisabi` | credential client, coordinator JSON <-> blob mapping, Strobe round-id hasher |
| `wasabi-proto` | coordinator models in Wasabi's JSON dialect, HTTP client with per-identity Tor circuits |
| `wallet` | Wasabi wallet files, BIP 158 scan, block sources (cache, bitcoind, P2P), coins, history, analyzer |
| `coinjoin` | coin selector, decomposer, dependency graph, round client, ownership proofs, soft key chain |
| `hw` | Trezor bridge transport and key chain; Coldcard hidraw link, HSM policy and key chain |
| `sabid` | daemon: Tor, sync loop, JSON-RPC, coinjoin manager, CLI, MCP |

## License

MIT. The vendored `libwabisabi` (zkSNACKs) and `secp256k1` (Bitcoin Core) keep their own MIT licenses.
