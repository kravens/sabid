//! Times a Coldcard Mk4 signing a coinjoin-shaped PSBT over sabid's own transport, with no
//! coordinator involved. The inputs do not exist, so the result can never be broadcast; it does
//! spend one transaction of the device's HSM policy budget. Needs the wallet file of the connected
//! device (its keys and master fingerprint) and an active HSM policy:
//!
//!   SABID_WALLET_JSON=/tmp/sabid-wallets/ColdCardTest.json SABID_BENCH_FOREIGN=330 SABID_BENCH_OUTPUTS=403 \
//!   cargo test -p hw --release --test coldcard_timing -- --ignored --nocapture

use bitcoin::absolute::LockTime;
use bitcoin::hashes::{hash160, sha256, Hash};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use coinjoin::keychain::UnsignedCoinJoin;
use coinjoin::units::FeeRate;
use hw::{ColdcardDevice, ColdcardKeyChain, ColdcardKeyInfo};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

/// Foreign scripts as a live round has them: two P2WPKH for every P2TR.
fn foreign_script(i: usize, tag: &str) -> ScriptBuf {
    let seed = sha256::Hash::hash(format!("{tag}-{i}").as_bytes()).to_byte_array();
    let mut b = if i % 3 == 0 { vec![0x51, 0x20] } else { vec![0x00, 0x14] };
    if i % 3 == 0 {
        b.extend_from_slice(&seed);
    } else {
        b.extend_from_slice(&hash160::Hash::hash(&seed).to_byte_array());
    }
    ScriptBuf::from_bytes(b)
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|s| s.parse().ok()).unwrap_or(default)
}

#[test]
#[ignore]
fn coldcard_signs_a_coinjoin_sized_psbt() {
    let wallet = std::env::var("SABID_WALLET_JSON").expect("SABID_WALLET_JSON=<wallet file of the connected Coldcard>");
    let foreign = env_usize("SABID_BENCH_FOREIGN", 330);
    let n_outputs = env_usize("SABID_BENCH_OUTPUTS", foreign * 12 / 10).max(2);
    let our_value = 1_000_000u64;
    let our_loss = 300u64; // ~4,400 sat/kvB of our own vsize, under the default 5 sat/vB cap

    let text = std::fs::read_to_string(&wallet).unwrap();
    let v: serde_json::Value = serde_json::from_str(text.trim_start_matches('\u{feff}')).unwrap();
    let fingerprint = v["MasterFingerprint"].as_str().unwrap().to_string();
    let mut keys = HashMap::new();
    let mut ours: Vec<ScriptBuf> = vec![];
    for k in v["HdPubKeys"].as_array().unwrap() {
        let path = k["FullKeyPath"].as_str().unwrap().to_string();
        if !path.starts_with("84'") {
            continue;
        }
        let pk: PublicKey = k["PubKey"].as_str().unwrap().parse().unwrap();
        let spk = ScriptBuf::new_p2wpkh(&pk.wpubkey_hash().unwrap());
        keys.insert(spk.clone(), ColdcardKeyInfo { path, pubkey: pk.inner });
        if ours.len() < 2 {
            ours.push(spk);
        }
    }
    assert!(ours.len() == 2, "need two P2WPKH keys in the wallet file");

    let mut tx = Transaction { version: Version::ONE, lock_time: LockTime::ZERO, input: vec![], output: vec![] };
    let mut prevouts = vec![];
    for i in 0..=foreign {
        let txid = Txid::from_slice(&sha256::Hash::hash(format!("bench-in-{i}").as_bytes()).to_byte_array()).unwrap();
        tx.input.push(TxIn { previous_output: OutPoint { txid, vout: (i % 4) as u32 }, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() });
        let (spk, value) = if i == 0 { (ours[0].clone(), our_value) } else { (foreign_script(i, "in"), 500_000 + (i as u64) * 137) };
        prevouts.push(TxOut { value: Amount::from_sat(value), script_pubkey: spk });
    }
    let total_in: u64 = prevouts.iter().map(|o| o.value.to_sat()).sum();
    let fee = ((foreign + 1) * 68 + n_outputs * 31) as u64;
    let pot = total_in - (our_value - our_loss) - fee;
    let per_out = pot / (n_outputs as u64 - 1);
    tx.output.push(TxOut { value: Amount::from_sat(our_value - our_loss), script_pubkey: ours[1].clone() });
    let mut remaining = pot;
    for i in 1..n_outputs {
        let value = if i + 1 < n_outputs { per_out } else { remaining };
        remaining -= value;
        tx.output.push(TxOut { value: Amount::from_sat(value), script_pubkey: foreign_script(i, "out") });
    }
    let our_outpoint = tx.input[0].previous_output;
    let unsigned = UnsignedCoinJoin { tx, prevouts, ownership_proofs: HashMap::new() };

    let device = Arc::new(ColdcardDevice::open().expect("Coldcard over USB"));
    assert_eq!(device.master_fingerprint, fingerprint.to_lowercase(), "connected device is not the wallet's");
    let kc = ColdcardKeyChain::new(device.clone(), &fingerprint, keys, 50, FeeRate::from_sat_per_vb(5.0), 21).unwrap();
    let (psbt, _) = kc.create_psbt(&unsigned).unwrap();
    let raw = psbt.serialize();
    std::fs::write("/tmp/sabid-bench-last.psbt", &raw).unwrap();
    let bytes = raw.len();
    println!("PSBT: {bytes} bytes, {} inputs, {} outputs", foreign + 1, n_outputs);

    assert!(device.hsm_status().unwrap().active, "the Coldcard must be in HSM mode (approve the coinjoin policy first)");
    let started = Instant::now();
    let signed = device.sign_psbt(&raw, Instant::now() + std::time::Duration::from_secs(360)).expect("device signature");
    let secs = started.elapsed().as_secs_f64();
    println!("signed in {secs:.1}s ({:.2} ms/byte, upload included)", secs * 1000.0 / bytes as f64);
    let signed = bitcoin::psbt::Psbt::deserialize(&signed).unwrap();
    let ours_in = signed.inputs.iter().zip(&signed.unsigned_tx.input).find(|(_, i)| i.previous_output == our_outpoint).unwrap().0;
    assert!(ours_in.final_script_witness.is_some() || !ours_in.partial_sigs.is_empty(), "no signature for our input");
    let _ = &kc;
}
