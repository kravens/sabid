# sabid — Rust re-implementation of the Wasabi Wallet daemon

Status: plan v1 (2026-10-17); progress log at the end. Target: drop-in for `wassabee` (Wasabi daemon) as seen by
`sabi.py` and by the WabiSabi coordinator, with a hardware-wallet coinjoin path like
Wasabi Preview 8, an MCP server for agents and a full CLI.

## 1. What "drop-in" means here

| Surface | Compatibility target | Source of truth |
|---|---|---|
| Coordinator wire protocol | byte/JSON identical to Wasabi 2.8.4 client (`WabiSabi` NuGet 1.3.1) | `WalletWasabi/Serialization/{Coordination,WabiSabi,Bitcoin}.cs`, `zkSNACKs/NWabiSabi` |
| JSON-RPC | same method names, param order and result keys as `WasabiJsonRpcService` (v2.8.4 + Preview 8 additions: `enumeratedevices`, `importhardwarewallet`, `enablecoinjoin`, `enabletaproot`, `setcoinjoinlimits`, `displayaddress`) | `WalletWasabi.Client/Rpc/WasabiJsonRpcService.cs` |
| RPC transport | HTTP POST, Basic auth, `/` or `/<wallet>/` path (wcli.sh shape), `text/plain` or `application/json`, positional or named params, `jsonrpc:"2.0"` | sabi.py `WasabiRpc.call` |
| Config | reads Wasabi's `~/.walletwasabi/client/Config.json` (BOM-tolerant): `CoordinatorUri`, `UseTor`, `JsonRpcUser/Password/ServerPrefixes`, `BitcoinRpcEndPoint`, `BitcoinRpcCredentialString`, `MaxCoinJoinMiningFeeRate`, `AbsoluteMinInputCount`, `CoordinatorIdentifier`, `DustThreshold` | `PersistentConfig.cs` |
| Wallet files | reads and writes Wasabi `Wallets/<name>.json` (KeyManager JSON, incl. Preview 8 fields `CoinJoinVendor`, `CoinJoinDeviceMaxRounds`, `CoinJoinDeviceMaxMiningFeeRate`, Coldcard fields) | `KeyManager.cs`, `Serialization/Client.cs` |
| Hardware wallets | Trezor via the classic bridge HTTP API (pytrezord / trezord at 127.0.0.1:21325), HWI 3.2 binary for enumerate/xpubs; Coldcard/Passport/Krux after Trezor | `Hwi/Trezor/*.cs`, `TrezorKeyChain.cs`, `HardwareWalletService.cs` |

Not a goal: GUI, Wasabi's own backend/indexer (gone since 2.6: filters come from the user's
bitcoind or P2P), Wasabi's SQLite stores (sabid keeps its own store, only wallet JSON is shared).

## 2. Architecture (one Cargo workspace)

```
sabid/
  crates/
    wabisabi-sys    FFI to libwabisabi (C, vendored from NWabiSabi) + vendored libsecp256k1 v0.7.1,
                    built by build.rs with the `cc` crate (no cmake). Ownership proofs in Rust.
    wabisabi        Safe client API: zero/real credential requests, response handling,
                    Credential type, blob <-> coordinator-JSON mapping, RoundHasher (Strobe).
    wasabi-proto    Coordinator models + serde (exact key casing), HTTP client with
                    per-identity Tor circuits (SOCKS5 username isolation), error decoding.
    wallet          Wasabi wallet JSON (KeyManager) read/write, BIP32 derivation (P2WPKH, P2TR
                    BIP86, SLIP-25 coinjoin account), key states/labels, coin + tx store
                    (SQLite), BIP158 sync over bitcoind RPC, anonymity-score analyzer.
    coinjoin        Round client: RoundStateUpdater, coin selector, AmountDecomposer,
                    DependencyGraph + scheduler, Alice/Bob/Arena, signing, blame rounds,
                    coin prison (bans), Poisson request scheduling, LiquidityClue.
    hw              Trezor bridge transport + minimal protobuf codec + coinjoin flows
                    (UnlockPath, AuthorizeCoinJoin, DoPreauthorized, GetOwnershipProof,
                    SignTx with coinjoin_request); HWI process bridge; key chains.
  src/              `sabid` binary: config, Tor bootstrap, JSON-RPC server (axum),
                    CLI subcommands (`sabid rpc …`, `sabid status`, …), MCP server (rmcp, stdio).
  vendor/           libwabisabi (MIT, NWabiSabi@295eb9f) and secp256k1 v0.7.1 sources.
```

Key crates: `bitcoin` 0.32 (tx, script, bip158, psbt, taproot), `secp256k1` (signing),
`bip32`, `bip39`, `tokio`, `reqwest` (socks feature), `axum`, `serde_json`, `rusqlite`,
`clap`, `rmcp`, `strobe-rs` (RoundHasher only), `cc` (build).

## 3. Show-stoppers found and how each is resolved

1. **KVAC + ZK proof system port (the big one).** NWabiSabi ships `libwabisabi`, a stateless
   C implementation that is byte-for-byte wire-compatible with the managed C# library
   (interop suite in its CI, fixed 2026-06-29 "C<->C# proofs now wire-compatible"). sabid
   links it via FFI (sources vendored, built with `cc`). The C issuer entry points double as a
   local test oracle. A pure-Rust port (k256 + strobe-rs) is a later phase with the C lib as
   the oracle, not a precondition for a real round.
2. **Blob <-> JSON mapping.** The C API speaks fixed byte layouts; the coordinator speaks JSON
   (`Delta`, `Presented[]`, `Requested[]{Ma,BitCommitments}`, `Proofs[]{PublicNonces,Responses}`,
   hex upper-case 33/32-byte elements). Sizes are fixed and counted, so the mapping is
   mechanical; verified against a live `/status` response and the C issuer.
3. **Round-id verification (anti-tagging).** Wasabi recomputes the round id from the round
   parameters with a Strobe128 transcript (`RoundHasher`). Needed to refuse a tagged round
   (GingerWallet CVE class). Port with `strobe-rs`; test vector = any live round from
   coinjoin.nl (`id == hash(params)`).
4. **Tor circuit isolation.** Wasabi uses one Tor identity per alice/bob request stream.
   reqwest + SOCKS5 proxy with a per-identity username gives Tor stream isolation
   (`IsolateSOCKSAuth`, on by default). One reqwest client per identity. Tor itself: reuse a
   running SOCKS (Wasabi's 37150 or system 9050) or spawn Wasabi's bundled `tor` binary;
   `arti` later.
5. **Wallet sync without Wasabi's backend.** Same as Wasabi 2.6+: bitcoind RPC
   `getblockcount/getblockhash/getblockfilter` (needs `blockfilterindex=1`), `getblock` for
   matches, `getrawtransaction` for prev txs (Trezor needs them). The user's nodes are onion
   endpoints, so RPC goes through the same SOCKS proxy. P2P BIP157 is optional later.
6. **Anonymity score parity.** sabi.py shows `anonymityScore` and the coin selector depends on
   it. Port `BlockchainAnalyzer` (443 lines) in M2; M1 uses a stub (score 1 for non-coinjoin
   outputs, equal-output count for own coinjoin outputs) so a first round can run.
7. **Trezor coinjoin signing flow.** The device demands: SLIP-25 taproot account, prev-tx
   streaming for every non-taproot input, ownership proofs + commitment data for every foreign
   input (both come from the round state `InputAdded` events), `coinjoin_request`
   (fee_rate, no_fee_threshold, min_registrable_amount) and one SignTx per authorized round.
   Port `TrezorDevice.RunSigningFlowAsync` one-to-one; test against the user's Model T through
   pytrezord. Sign-first-then-post scheduling as in Preview 8 (`SigningTakesTime`).
8. **Shared wallet file with the GUI.** Both apps rewrite `Wallets/<name>.json`. sabid writes
   only on key/label/state changes and never while the GUI holds the wallet (documented; a
   lock file is a later nicety). sabid never deletes unknown fields: unknown JSON keys are kept
   verbatim on rewrite.
9. **Coordinator bans on client mistakes.** A misbehaving client gets its inputs banned for
   hours. First live rounds use a dedicated small test wallet; unit tests exercise every
   request against the C issuer oracle before touching coinjoin.nl.

## 4. Milestones

- **M0 (POC, this session):** workspace builds; `wabisabi-sys` compiles libwabisabi +
  secp256k1; zero -> issue -> real -> issue roundtrip against the C issuer in Rust tests;
  live `/status` decoded; round id recomputed and matches.
- **M1:** wallet JSON load, bitcoind BIP158 sync, coin list, `getstatus`, `listwallets`,
  `loadwallet`, `getwalletinfo`, `listunspentcoins`, `gethistory`, `getnewaddress`,
  `getfeerates` — sabi.py dashboard/wallet tabs work read-only.
- **M2:** soft-wallet coinjoin end to end (`startcoinjoin`/`stopcoinjoin`, `coinjoinStatus`,
  `excludefromcoinjoin`, `setcoinjoinlimits`), analyzer port, blame rounds, bans.
  User test: one real round with a small hot test wallet.
- **M3:** Trezor: `enumeratedevices`, `importhardwarewallet`, `enablecoinjoin`,
  `displayaddress`, device key chain, authorization, full round signed on device.
  User test: hardware wallet round (Preview 8 parity).
- **M4:** rest of RPC (`send`, `build`, `broadcast`, `speeduptransaction`, `canceltransaction`,
  `payincoinjoin` family, `startcoinjoinsweep`, `listkeys`, `recoverwallet`, `createwallet`),
  MCP server, CLI polish, Coldcard/Passport/Krux key chains, pure-Rust crypto port.

## 5. Open decisions (defaults chosen, change if you disagree)

- Project name `sabid`, data dir `~/.sabid/` (store, logs); wallet files stay in
  `~/.walletwasabi/client/Wallets/` so the GUI and sabi.py see the same wallets.
- Crypto core via C FFI first, pure Rust later (the user asked for Rust; this is the one
  non-Rust piece and is isolated in `wabisabi-sys`).
- Tor: reuse an existing SOCKS proxy if one answers; otherwise spawn Wasabi's bundled tor.

## 6. Experimental directions (design notes, not started)

### 6.1 Hybrid liquidity: JoinMarket makers inside the WabiSabi denomination world

Kruw's "Four Horsemen" idea (https://delvingbitcoin.org/t/the-four-horsemen/2728): one client that
uses WabiSabi to consolidate and to create ZeroLink-style standard denominations, JoinMarket for
on-demand liquidity, payjoin for spending. The liquidity of the three pools then overlaps instead
of fragmenting.

What sabid can contribute first, in order of effort:

1. **Denomination alignment.** `coinjoin/decomposer.rs` already produces Wasabi's standard
   denomination set (powers of two, three and ten, "lucky" amounts). A JoinMarket maker that offers
   exactly those amounts lets a WabiSabi-shaped output be remixed in a JoinMarket transaction
   without a fingerprint. Zero protocol work; a table and a selection rule.
2. **Maker side.** A `jm` crate: JoinMarket's directory-node message layer (Tor onion services,
   the JSON-over-onion v2 messaging, fidelity bond announcement), the `!orderbook`/`!fill`/
   `!auth`/`!ioauth`/`!tx`/`!sig` handshake, and a maker that signs through the existing
   `KeyChain` trait. A soft wallet signs directly; a Coldcard under the HSM policy already allows
   "self transfer >= 50 %, bounded fee", which is exactly a maker's position in a JoinMarket
   transaction (its outputs return to itself plus the coinjoin fee), so the policy covers it with
   no firmware change. Trezor needs `AuthorizeCoinJoin` with the maker's own output; SLIP-25
   forbids foreign scripts in the coinjoin account, which may need a plain account instead.
3. **Taker side.** A taker that fills a JoinMarket transaction with standard-denomination outputs
   (the decomposer, fed with the maker offers' amounts as "others' inputs") so the result looks
   like any WabiSabi output set. This is where the "hybrid" lands: a WabiSabi round for the
   many-small-participants case, a JoinMarket fill for the whale case, both producing the same
   denominations, chosen per coin by size and by the current orderbook.
4. **Coordinator-side hybrid** (Kruw's full picture: makers participating inside a WabiSabi
   round) needs a coordinator change (maker registration with a fee credential) and is out of
   sabid's scope until a coordinator implements it; keep the client interfaces (`ArenaClient`,
   credential scheduler) ready to carry an extra "liquidity fee" credential type.

Open questions: JoinMarket's directory nodes and message signing need a libsecp ECDSA path that
sabid has (`bitcoin` crate); fidelity bonds need a timelocked output type the wallet does not track
yet; privacy of mixing the two pools (a coin seen in both a WabiSabi round and a JoinMarket
transaction links two coordinators' views) must be analysed before defaulting to it.

### 6.2 Payjoin v2 (BIP 77) receive and send through Payjoin Dev Kit

The `payjoin` crate (https://github.com/payjoin/rust-payjoin, 1.0, `v2` feature on by default) does
the protocol: OHTTP to a relay, a directory holding the encrypted session, BIP 21 URIs with `pj=`
and `pjos=`, receiver and sender state machines with session persistence. sabid supplies wallet
plumbing:

- **Receive.** `getnewaddress` grows a `payjoin: true` option that creates a receiver session
  (relay + directory from `Config.json`, defaults to a public mailroom), returns the BIP 21 URI with
  the `pj` parameter and keeps the session in `~/.sabid/payjoin/<wallet>/`. A loop polls the
  directory, validates the original PSBT with the node (`gettxout`), picks one of our coins to
  contribute (segwit or taproot, same type as the sender's inputs when possible), signs it through
  the `KeyChain` (soft wallet now; Coldcard under HSM only if the policy allows the output set,
  which is the open question for devices), and posts the payjoin PSBT. The sender broadcasts.
- **Send.** Needs ordinary sending first (`build`/`broadcast`, milestone M4). Then `send` with a
  `pj` URI builds the original PSBT, drives the sender state machine through the relay, verifies
  the receiver's proposal (no change to our outputs beyond the rules, fee within tolerance), signs
  the added inputs' counterpart through the `KeyChain`, broadcasts.
- **Taproot** is only an input/output script type here; the crate is agnostic, the wallet's
  taproot account (`TaprootExtPubKey`) already derives keys and the Coldcard key chain signs
  taproot under the HSM.
- **Compatibility with Wasabi's data**: payjoin sessions are sabid-only state, nothing in the
  wallet file changes; a wallet file stays loadable by Wasabi.

Testing: PDK ships a test fixture and `payjoin-cli`; a receive round trip against `payjoin-cli
send` on regtest is the acceptance test, the same setup used for the Wasabi payjoin work.

## 7. Progress log

- 2026-10-17 M0 done: credential roundtrips against the C issuer through coordinator JSON
  (zero, real, reissue, presentation-only); round ids of live coinjoin.kruw.io rounds verify.
- 2026-10-17 M1 done: wallet files load/save, scan over Wasabi's filter index (490k filters,
  ~1300 filters/s in release), blocks from Wasabi's cache, the user's bitcoind over Tor, or P2P
  onion peers; RPC methods getstatus, listwallets, loadwallet, getwalletinfo, listunspentcoins,
  listcoins, gethistory, getnewaddress, listkeys, excludefromcoinjoin, getfeerates, startcoinjoin,
  stopcoinjoin; sabi.py's own RPC client drives it. Scans release the wallet between batches.
- 2026-10-17 M2 code complete, not yet exercised in a live round: coin selector, decomposer,
  dependency graph + scheduler, Alice/Bob flow, signing, blame rounds, bans (PrisonedCoins.json),
  soft key chain (BIP38 master key). First live test must use a dedicated small wallet.
- 2026-10-17 M3 code complete, not yet tested on a device: Trezor over pytrezord/trezord
  (authorize, ownership proofs, preauthorized SignTx), wired into startcoinjoin for wallets with a
  SLIP-25 account and CoinJoinVendor = Trezor.
- 2026-10-18: BlockchainAnalyzer ported (26 of 28 coins of the synced Trezor wallet score private, as a 98-coinjoin wallet should); Trezor bridge enumerate/display/limits RPCs; MCP stdio server; bitcoind input verifier.
- Open: mempool scanning (only the
  daemon's own coinjoins are tracked unconfirmed), remaining RPC (send/build/broadcast/payincoinjoin/
  sweep/recover/create/import/enable/displayaddress/setcoinjoinlimits), MCP server, Coldcard/
  Passport/Krux, input verification via bitcoind gettxout, pure-Rust crypto.

- 2026-10-18: Coldcard device timing measured through `crates/hw/tests/coldcard_timing.rs` (ignored test, needs the device in HSM mode): a kruw-shaped 331-input / 403-output round is a 41 KB PSBT and takes the Mk4 (coinjoin-fw-2, 6.6.1X) 175 s end to end, 4.25 ms/byte; kruw.io gives 57 s to sign, so kruw rounds are out of reach for a Coldcard. coinjoin.nl (max 100 inputs, 129 s) fits. The same test found that the 6.6.1X firmware fails ("Signing failed late") when a foreign input has no witness UTXO, so `ColdcardKeyChain::create_psbt` now attaches every input's UTXO. `sabid status` prints the phase timeouts.
- 2026-10-18 10:43 UTC: first complete live coinjoin through sabid with the Coldcard Mk4 on coinjoin.nl: two inputs registered, five outputs registered, device signed under the HSM policy, both signatures posted, coordinator broadcast the transaction. Three bugs fixed on the way, each in a path unit tests never reached: credential slots filled before anyone subscribed were dropped (watch `send` -> `send_replace`), the presentation-only validation state serialized unset points (C abort), and the 6.6.1X firmware needs every input's witness UTXO. Two coins were banned on coinjoin.nl by the first two failures (DoS prison, hours).
- 2026-10-18 (review pass after the live round): fixed the crash and hang candidates a code review found in paths the live rounds had not reached: empty signer list with a device key chain (`alices[0]`), rounds without a RoundCreated event (updater panic), wire-sized `Vec::with_capacity` in ownership proofs, filters/wallet lock-order inversion on reorg, reorg into Wasabi's read-only filter store (infinite loop), `reduce_nodes` with a zero target, selector/decomposer `expect`s on round parameters, `TimeSpan` parse on non-ASCII text and time overflows, connection-confirmation retry without pacing, per-Alice vsize budget mis-pairing, blocking Coldcard proof I/O on async workers, Trezor session probe without a timeout, dropped final progress events, and the FFI now requires exactly two presented credentials with zeroed request structs. Hand-rolled join helpers replaced by futures-util (already in the tree).
- 2026-10-18 (secrets): soft wallets are unlocked on the daemon host (`sabid unlock`, RPC `unlockwallet`/`lockwallet`, master key cached with a time to live, `getwalletinfo.unlocked`), the MCP has no password argument anywhere and its passthrough refuses password-carrying calls, and every RPC/MCP answer passes a key-material guard (`src/secrets.rs`).
- 2026-10-18 (coexistence with Wasabi): sabid refuses to start beside a running Wasabi GUI/daemon (process scan, `src/wasabi_guard.rs`) and shuts down after critical phases when one appears; all writes moved under the data directory (wallet copies bootstrapped from Wasabi's `Wallets/`, per-coordinator `PrisonedCoins.json` likewise), Wasabi's files are read-only. Open: a way to hand labels/key states back to Wasabi (an explicit export, never automatic).
- 2026-10-18 (easy features first): review leftovers closed (`sabid status` id slicing, fee rates refreshed every ~10 min, tor child killed on bootstrap timeout, constant-time Basic-auth compare, proof counts bounded in `wabisabi_verify`); `startcoinjoinsweep [password, outputWalletName]` (consolidation mode: every coin, outputs from the other wallet, both wallets' stores updated); `sabid export-wallet` hands sabid's wallet copy back to Wasabi with a backup, refusing while either program runs. Next in order: `recoverwallet`/`createwallet` (Wasabi wallet file from a BIP 39 mnemonic), `enablecoinjoin`/`importhardwarewallet`, mempool scanning via the node, `build`/`send`/`broadcast` for soft wallets, payments in coinjoin.
- 2026-10-18 (wallet files): `createwallet` / `recoverwallet` write a Wasabi-format wallet file from a BIP 39 mnemonic (`crates/wallet/src/create.rs`: password is both the BIP 39 passphrase and the BIP 38 key, Wasabi's field order and defaults, gap of 21 keys derived on creation; verified against the BIP 84 test vector), CLI `sabid create-wallet` / `recover-wallet` keep words and passwords out of shell history. Neither method is reachable through the MCP.

