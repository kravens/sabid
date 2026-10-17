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

## 6. Progress log

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
