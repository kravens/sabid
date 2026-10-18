# sabid

A Rust re-implementation of the Wasabi Wallet daemon: the WabiSabi coinjoin client, a
Wasabi-compatible JSON-RPC server (so [sabi.py](https://github.com/kravens/coinjoin.nl/tree/main/scripts)
and `wcli.sh` work unchanged), hardware-wallet coinjoins through the device (Trezor, as in the
Wasabi hardware-wallet previews), a CLI and (planned) an MCP server for agents.

Status and design notes: [PLAN.md](PLAN.md).

## Build

```sh
cargo build --release          # builds the vendored libwabisabi + secp256k1 with cc, no cmake needed
cargo test --workspace
```

## Run

sabid reads Wasabi's own `~/.walletwasabi/client/Config.json` (coordinator, RPC credentials and
port, bitcoind endpoint) and the wallet files in `~/.walletwasabi/client/Wallets/`. It reuses
Wasabi's local block-filter index read-only and keeps its own state under `~/.sabid/`.

```sh
# Tor: reuses a SOCKS proxy on 127.0.0.1:37150 (Wasabi) or :9050, else starts Wasabi's bundled tor.
sabid daemon --wallet MyWallet                     # JSON-RPC on the Config.json prefix (127.0.0.1:37128)
sabid daemon --wallet MyWallet --rpc-bind 127.0.0.1:37129 --wallet-dir /tmp/wallets --datadir /tmp/sabid

sabid status                                       # coordinator rounds, with round-id verification
sabid rpc getstatus
sabid rpc getwalletinfo --wallet MyWallet
sabid rpc startcoinjoin '["password", true, true]' --wallet MyWallet
sabid rpc stopcoinjoin --wallet MyWallet
```

Do not run sabid and the Wasabi GUI on the same wallet file at the same time: both rewrite it.

## Hardware wallets

A Trezor wallet imported with a coinjoin account (SLIP-25, `TaprootAccountKeyPath` starting with
`10025'`) coinjoins through the classic bridge API on `127.0.0.1:21325` (pytrezord) or `:21328`.
`startcoinjoin` asks the device to authorize `CoinJoinDeviceMaxRounds` rounds at
`CoinJoinDeviceMaxMiningFeeRate` sat/vB (hold to confirm on the device); ownership proofs and
signatures then come from the device without further interaction, one round per authorized round.

A Coldcard Mk4 on the `coinjoin-fw-2` firmware (6.6.1X) is driven over hidraw (`/dev/hidraw*`
must be readable). `startcoinjoin` installs the HSM policy built from the wallet's
`ColdcardMaxSatsLeaving`, `ColdcardMaxTransactionsPerPeriod`, `ColdcardPeriodMinutes`,
`ColdcardMinInputs`, `CoinJoinDeviceMaxRounds` and `CoinJoinDeviceMaxMiningFeeRate` (approve it on
the device, or it reuses the policy recorded in `ColdcardActivePolicyHash` when that one is already
running). Ownership proofs come from `slp9`; the round is signed as a PSBT under the policy. The
device needs about 4.3 ms per PSBT byte (41 KB, 331 inputs: 175 s), so it can only finish rounds
whose transaction-signing phase is long enough; coinjoin.nl (100 inputs max, 129 s) fits, kruw.io
(500 inputs, 57 s) does not. `cargo test -p hw --release --test coldcard_timing -- --ignored
--nocapture` with `SABID_WALLET_JSON` set times a synthetic round on the connected device.

## Layout

| crate | what |
|---|---|
| `wabisabi-sys` | FFI to the vendored C `libwabisabi` (zkSNACKs/NWabiSabi) + secp256k1 |
| `wabisabi` | credential client, coordinator JSON <-> blob mapping, Strobe round-id hasher |
| `wasabi-proto` | coordinator models in Wasabi's JSON dialect, HTTP client with per-identity Tor circuits |
| `wallet` | Wasabi wallet files, BIP158 scan, block sources (cache, bitcoind, P2P onion peers), coins/history |
| `coinjoin` | coin selector, amount decomposer, dependency graph, round client, ownership proofs, soft key chain |
| `hw` | Trezor bridge transport, protobuf codec, device flows, Trezor key chain; Coldcard hidraw link, HSM policy, key chain |
| `sabid` | daemon: Tor, sync loop, JSON-RPC, coinjoin manager, CLI |
