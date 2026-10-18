# Benchmarks

Measured 2026-10-18 on one machine (32 cores, btrfs, Tor), sabid against Wasabi Wallet 2.8.4
(Preview 8 build of `wassabeed`), same wallet files, same filter index, same 20000 filters.
Both daemons produced the identical wallet view for the test wallet (37 unspent coins, same
outpoints and amounts, 164 history entries). Reproduce with `sabid bench` and
`bench/wasabi-filter` (a C# program using Wasabi's own matcher, NBitcoin `GolombRiceFilter`).

| what | Wasabi | sabid | notes |
|---|---|---|---|
| filter matching, 1 thread | 3355 filters/s | 4701 filters/s | 20000 BIP 158 filters from 481824, 1290 scripts |
| filter matching, all cores | 48333 filters/s (`Parallel.ForEach`) | 63784 filters/s | sabid matches on up to 8 threads in the daemon |
| wallet load (keys, store, coin view) | n/a over RPC | 324 ms | 1290 keys, 160 transactions |
| RPC latency `getstatus` | p50 41 ms | p50 1.7 ms | 30 calls, loopback |
| RPC latency `listunspentcoins` | p50 46 ms | p50 0.3 ms | |
| RPC latency `gethistory` | p50 42 ms | p50 0.4 ms | |
| RSS, one wallet loaded, idle | 819 MB | 72 MB | after the scan below: 990 MB vs ~1 GB before the allocator trim (see below) |
| first scan of a fresh wallet, 481824 to tip | 736 s | 229 s | 490k filters; Wasabi over clearnet P2P, sabid over Tor to an onion node (0.3 MB/s) |
| block fetch through an onion node, 1 / 4 / 8 streams | | 0.12 / 0.32 / 0.27 MB/s | the node's Tor upload is the ceiling; 16 streams were slower than 4 |

What the numbers say:

- Matching is not the bottleneck for either daemon once it runs on several cores. sabid spends
  ~8 s of a full scan matching; everything else is fetching the blocks the filters flag.
- Those are mostly false positives: BIP 158 flags about `scripts / 784931` of the blocks, so a
  wallet with 1300 keys downloads ~800 blocks (over 1 GB) for a scan from 2017. Wasabi has the
  same burden; it is the cost of the filter format, not of either implementation. The remedy is
  bandwidth: a node reachable directly (LAN, Tailscale) instead of through Tor, which sabid now
  uses without a proxy.
- Fixed on the way, each measured: the synced-height marker was written per filter row with an
  fsync (90 s per 2000 filters, now 0.5 s); keys were found by linear scan per output (now a
  hash map); the outpoint set was rebuilt from the store per batch; filters were copied before
  matching; wallet scans ran one after the other inside the filter loop and starved filter,
  fee and mempool updates (now separate tasks, two scans at a time); the pipeline matches ahead
  and fetches on separate Tor circuits; glibc arenas are capped and trimmed after a scan.
