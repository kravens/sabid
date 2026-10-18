// Usage: dotnet run -c Release -- <IndexStore.sqlite> <wallet.json> [from] [count]
// Matches `count` BIP 158 filters from the Wasabi index against the wallet's scripts the way
// Wasabi's WalletFilterProcessor does (one filter at a time, GolombRiceFilter.MatchAny with the
// block hash as key), then the same work with Parallel.ForEach. Prints filters/s and matches.
using System.Diagnostics;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using NBitcoin;

var index = args[0];
var walletJson = args[1];
var from = args.Length > 2 ? int.Parse(args[2]) : 481824;
var count = args.Length > 3 ? int.Parse(args[3]) : 20000;

// Scripts: P2WPKH for 84' keys, BIP 86 taproot for 86' and SLIP-25 keys, like Wasabi's HdPubKey.
var scripts = new List<byte[]>();
using (var doc = JsonDocument.Parse(File.ReadAllText(walletJson)))
{
    foreach (var k in doc.RootElement.GetProperty("HdPubKeys").EnumerateArray())
    {
        var pub = new PubKey(k.GetProperty("PubKey").GetString()!);
        var path = k.GetProperty("FullKeyPath").GetString()!;
        var type = path.StartsWith("84'") ? ScriptPubKeyType.Segwit : ScriptPubKeyType.TaprootBIP86;
        scripts.Add(pub.GetScriptPubKey(type).ToBytes());
    }
}

var filters = new List<(byte[] key, byte[] data)>();
using (var conn = new SqliteConnection($"Data Source={index};Mode=ReadOnly"))
{
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "SELECT block_hash, filter_data FROM filter WHERE block_height >= $from ORDER BY block_height LIMIT $count";
    cmd.Parameters.AddWithValue("$from", from);
    cmd.Parameters.AddWithValue("$count", count);
    using var r = cmd.ExecuteReader();
    while (r.Read())
    {
        var hash = (byte[])r[0];
        filters.Add((hash[..16], (byte[])r[1]));
    }
}
Console.WriteLine($"{filters.Count} filters, {scripts.Count} scripts, {Environment.ProcessorCount} cores");

var sw = Stopwatch.StartNew();
int matches = 0;
foreach (var (key, data) in filters)
{
    if (new GolombRiceFilter(data).MatchAny(scripts, key)) matches++;
}
sw.Stop();
Console.WriteLine($"| filters matched (Wasabi/NBitcoin, 1 thread) | {filters.Count} filters, {scripts.Count} scripts | {filters.Count / sw.Elapsed.TotalSeconds:F0} filters/s, {matches} matches |");

sw.Restart();
int pmatches = 0;
Parallel.ForEach(filters, f => { if (new GolombRiceFilter(f.data).MatchAny(scripts, f.key)) Interlocked.Increment(ref pmatches); });
sw.Stop();
Console.WriteLine($"| filters matched (Wasabi/NBitcoin, Parallel.ForEach) | {filters.Count} filters, {scripts.Count} scripts, {Environment.ProcessorCount} cores | {filters.Count / sw.Elapsed.TotalSeconds:F0} filters/s, {pmatches} matches |");
