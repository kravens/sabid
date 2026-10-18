#!/usr/bin/env bash
# Regtest smoke test: a local Bitcoin Core node, two sabid wallets, mining, sync, send, RBF speed-up
# and cancel, mempool pickup of a foreign payment, recovery from the words. Nothing touches
# ~/.walletwasabi or ~/.sabid. Needs bitcoind and bitcoin-cli (BITCOIND / BITCOIN_CLI env).
set -euo pipefail
BITCOIND=${BITCOIND:-bitcoind}
BITCOIN_CLI=${BITCOIN_CLI:-bitcoin-cli}
SABID=${SABID:-$(dirname "$0")/../target/release/sabid}
ROOT=${ROOT:-/tmp/sabid-regtest}
RPCPORT=${RPCPORT:-18443}
SABID_RPC=${SABID_RPC:-127.0.0.1:37140}

rm -rf "$ROOT"; mkdir -p "$ROOT/node" "$ROOT/sabid"
bcli() { "$BITCOIN_CLI" -regtest -datadir="$ROOT/node" -rpcuser=sabid -rpcpassword=sabid -rpcport="$RPCPORT" "$@"; }
rpc() { "$SABID" --config "$ROOT/Config.json" --datadir "$ROOT/sabid" --network regtest rpc "$@" --url "http://$SABID_RPC/"; }
field() { python3 -c 'import json,sys; v=json.load(sys.stdin); exec(sys.argv[1])' "$1"; }
cleanup() { kill "${SABID_PID:-0}" 2>/dev/null || true; bcli stop >/dev/null 2>&1 || true; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; echo "--- sabid log tail"; tail -20 "$ROOT/sabid.log"; exit 1; }
wait_for() { local n=$1; shift; for _ in $(seq 1 "$n"); do if "$@" 2>/dev/null; then return 0; fi; sleep 2; done; return 1; }

"$BITCOIND" -regtest -datadir="$ROOT/node" -blockfilterindex=1 -txindex=1 -fallbackfee=0.0001 -rpcuser=sabid -rpcpassword=sabid -rpcport="$RPCPORT" -listen=0 -daemon >/dev/null
wait_for 30 bcli getblockchaininfo >/dev/null || fail "bitcoind did not start"
bcli createwallet miner >/dev/null
MINER=$(bcli getnewaddress)

cat > "$ROOT/Config.json" <<JSON
{"Network":"RegTest","CoordinatorUri":"http://127.0.0.1:37127/","UseTor":"Disabled","JsonRpcServerEnabled":true,"JsonRpcUser":"","JsonRpcPassword":"","JsonRpcServerPrefixes":["http://$SABID_RPC/"],"BitcoinRpcEndPoint":"127.0.0.1:$RPCPORT","BitcoinRpcCredentialString":"sabid:sabid","DustThreshold":"0.00001"}
JSON
RUST_LOG=info "$SABID" --config "$ROOT/Config.json" --datadir "$ROOT/sabid" --network regtest daemon --no-tor --rpc-bind "$SABID_RPC" > "$ROOT/sabid.log" 2>&1 &
SABID_PID=$!
wait_for 30 sh -c "$SABID --config $ROOT/Config.json --datadir $ROOT/sabid --network regtest rpc getstatus --url http://$SABID_RPC/ | grep -q result" || fail "sabid did not start"

echo "1. wallets"
WORDS_A=$(rpc createwallet '["A","pw"]' | field 'print(v["result"])')
rpc createwallet '["B","pw"]' >/dev/null
rpc loadwallet '["A"]' >/dev/null; rpc loadwallet '["B"]' >/dev/null
ADDR_A=$(rpc getnewaddress '["mining", false]' --wallet A | field 'print(v["result"]["address"])')
ADDR_B=$(rpc getnewaddress '["from A", false]' --wallet B | field 'print(v["result"]["address"])')
[[ $ADDR_A == bcrt1* ]] || fail "regtest address expected, got $ADDR_A"

echo "2. mine 101 blocks to A and 101 to the miner, wait for sync"
bcli generatetoaddress 101 "$ADDR_A" >/dev/null
bcli generatetoaddress 101 "$MINER" >/dev/null
balance() { rpc getwalletinfo --wallet "$1" | field 'print(v["result"].get("balance", 0))'; }
wait_for 90 sh -c "[ \$($SABID --config $ROOT/Config.json --datadir $ROOT/sabid --network regtest rpc getwalletinfo --wallet A --url http://$SABID_RPC/ | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"result\"].get(\"balance\",0))') -ge 500000000000 ]" || fail "A did not see its 101 coinbases (balance $(balance A))"
echo "   A balance $(balance A) sat"

echo "3. send 1 BTC from A to B (unlocked key, no password in the call)"
printf 'pw\n' | "$SABID" --config "$ROOT/Config.json" --datadir "$ROOT/sabid" --network regtest unlock --wallet A --ttl 900 --url "http://$SABID_RPC/" >/dev/null
COIN=$(rpc listunspentcoins --wallet A | field 'c=[c for c in v["result"] if c["confirmations"]>=100][0]; print(c["txid"], c["index"])')
read -r TXID_IN VOUT_IN <<<"$COIN"
TX1=$(rpc send "{\"payments\":[{\"sendto\":\"$ADDR_B\",\"amount\":100000000,\"label\":\"test\"}],\"coins\":[{\"transactionid\":\"$TXID_IN\",\"index\":$VOUT_IN}],\"feeRate\":2}" --wallet A | field 'print(v["result"]["txid"])')
[[ ${#TX1} -eq 64 ]] || fail "send returned no txid"
rpc listunspentcoins --wallet B | field 'c=[c for c in v["result"] if not c["confirmed"]]; assert len(c)==1 and c[0]["amount"]==100000000, c' || fail "B does not show the unconfirmed 1 BTC"
echo "   sent $TX1"

echo "4. speed it up (RBF), broadcast the replacement"
HEX=$(rpc speeduptransaction "[\"$TX1\", \"\"]" --wallet A | field 'print(v["result"])')
TX2=$(rpc broadcast "[\"$HEX\"]" | field 'print(v["result"]["txid"])')
[[ $TX2 != "$TX1" ]] || fail "replacement has the same txid"
bcli getmempoolentry "$TX2" >/dev/null || fail "replacement not in the node's mempool"
rpc listunspentcoins --wallet B | field "c=[c for c in v['result'] if not c['confirmed']]; assert len(c)==1 and c[0]['txid']=='$TX2', c" || fail "B still shows the replaced transaction"
bcli generatetoaddress 1 "$MINER" >/dev/null
wait_for 60 sh -c "$SABID --config $ROOT/Config.json --datadir $ROOT/sabid --network regtest rpc listunspentcoins --wallet B --url http://$SABID_RPC/ | python3 -c \"import json,sys; c=json.load(sys.stdin)['result']; assert any(x['txid']=='$TX2' and x['confirmed'] for x in c)\"" || fail "B's coin did not confirm"
echo "   replaced by $TX2, confirmed"

echo "5. send again and cancel it"
COIN=$(rpc listunspentcoins --wallet A | field 'c=[c for c in v["result"] if c["confirmations"]>=100][0]; print(c["txid"], c["index"])')
read -r TXID_IN VOUT_IN <<<"$COIN"
TX3=$(rpc send "{\"payments\":[{\"sendto\":\"$ADDR_B\",\"amount\":50000000}],\"coins\":[{\"transactionid\":\"$TXID_IN\",\"index\":$VOUT_IN}],\"feeRate\":2}" --wallet A | field 'print(v["result"]["txid"])')
HEX=$(rpc canceltransaction "[\"$TX3\", \"\"]" --wallet A | field 'print(v["result"])')
TX4=$(rpc broadcast "[\"$HEX\"]" | field 'print(v["result"]["txid"])')
bcli getmempoolentry "$TX4" >/dev/null || fail "cancel not in the node's mempool"
rpc listunspentcoins --wallet B | field 'c=[c for c in v["result"] if not c["confirmed"]]; assert len(c)==0, c' || fail "B still shows the cancelled payment"
rpc listunspentcoins --wallet A | field "c=[c for c in v['result'] if c['txid']=='$TX4']; assert len(c)==1 and c[0]['amount']>4990000000, c" || fail "A did not get the cancelled coins back"
echo "   cancelled by $TX4"

echo "6. a foreign payment appears through the mempool scan (up to 3 min)"
ADDR_B2=$(rpc getnewaddress '["from the miner", false]' --wallet B | field 'print(v["result"]["address"])')
TX5=$(bcli sendtoaddress "$ADDR_B2" 0.3)
wait_for 100 sh -c "$SABID --config $ROOT/Config.json --datadir $ROOT/sabid --network regtest rpc listunspentcoins --wallet B --url http://$SABID_RPC/ | python3 -c \"import json,sys; c=json.load(sys.stdin)['result']; assert any(x['txid']=='$TX5' for x in c)\"" || fail "B never saw the miner's unconfirmed payment $TX5"
echo "   seen $TX5"

echo "7. recover A from its words as A2"
rpc recoverwallet "[\"A2\", \"$WORDS_A\", \"pw\", 0]" >/dev/null
rpc loadwallet '["A2"]' >/dev/null
wait_for 90 sh -c "[ \$($SABID --config $ROOT/Config.json --datadir $ROOT/sabid --network regtest rpc getwalletinfo --wallet A2 --url http://$SABID_RPC/ | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"result\"].get(\"balance\",0))') -ge 500000000000 ]" || fail "A2 did not recover A's balance"
echo "   A2 balance $(balance A2) sat"
echo "PASS"
