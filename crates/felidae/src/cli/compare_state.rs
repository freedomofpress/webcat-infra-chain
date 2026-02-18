//! Compare felidae JMT state between two storage directories.
//!
//! Use after a chain halt to find where validator state diverges. Reads each
//! storage via cnidarium (same RocksDB/JMT as the node) and diffs key-value
//! pairs in the internal and canonical substores.

use cnidarium::{StateRead, Storage};
use color_eyre::{Report, eyre::eyre};
use futures::StreamExt;
use std::collections::BTreeMap;
use std::path::PathBuf;

const SUBSTORES: [&str; 2] = ["internal", "canonical"];

#[derive(clap::Args)]
pub struct CompareState {
    /// First felidae storage directory (e.g. validator-1 .../opt/felidae/storage).
    #[arg(value_name = "PATH_A")]
    pub path_a: PathBuf,

    /// Second felidae storage directory (e.g. validator-2 .../opt/felidae/storage).
    #[arg(value_name = "PATH_B")]
    pub path_b: PathBuf,

    /// Write a detailed diff to this file (key + value hex for differing keys).
    #[arg(long, value_name = "FILE")]
    pub output_diff: Option<PathBuf>,

    /// Show first N bytes of value in summary for differing keys (0 = none).
    #[arg(long, default_value = "32")]
    pub value_preview_bytes: usize,
}

struct StorageDump {
    version: u64,
    internal_root: String,
    canonical_root: String,
    keys: BTreeMap<String, Vec<u8>>,
}

async fn load_and_dump(path: PathBuf, label: &str) -> Result<StorageDump, Report> {
    let storage = Storage::load(path.clone(), SUBSTORES.map(String::from).to_vec())
        .await
        .map_err(|e| {
            eyre!(
                "failed to load storage at {} ({}): {}",
                path.display(),
                label,
                e
            )
        })?;

    let snapshot = storage.latest_snapshot();
    let version = storage.latest_version();
    let internal_root = snapshot
        .prefix_root_hash("internal")
        .await
        .map(|h| hex::encode(h.0.as_slice()))
        .unwrap_or_else(|e| format!("error: {}", e));
    let canonical_root = snapshot
        .prefix_root_hash("canonical")
        .await
        .map(|h| hex::encode(h.0.as_slice()))
        .unwrap_or_else(|e| format!("error: {}", e));

    let mut keys: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for prefix in ["internal/", "canonical/"] {
        let mut stream = Box::pin(snapshot.prefix_raw(prefix));
        while let Some(res) = stream.next().await {
            let (key, value) =
                res.map_err(|e| eyre!("prefix_raw {} ({}): {}", prefix, label, e))?;
            keys.insert(key, value);
        }
    }

    Ok(StorageDump {
        version,
        internal_root,
        canonical_root,
        keys,
    })
}

fn hex_preview(bytes: &[u8], max_len: usize) -> String {
    if bytes.is_empty() {
        return "()".to_string();
    }
    let len = bytes.len().min(max_len);
    let hex = hex::encode(&bytes[..len]);
    if bytes.len() > max_len {
        format!("{}… ({} bytes)", hex, bytes.len())
    } else {
        format!("{} ({} bytes)", hex, bytes.len())
    }
}

use super::Run;

impl Run for CompareState {
    async fn run(self) -> color_eyre::Result<()> {
        run_impl(self).await
    }
}

async fn run_impl(cmd: CompareState) -> color_eyre::Result<()> {
    let CompareState {
        path_a,
        path_b,
        output_diff,
        value_preview_bytes,
    } = cmd;

    println!("Loading storage A: {}", path_a.display());
    let dump_a = load_and_dump(path_a.clone(), "A").await?;
    println!("Loading storage B: {}", path_b.display());
    let dump_b = load_and_dump(path_b.clone(), "B").await?;

    println!();
    println!("=== Version (block height) ===");
    println!("  A: {} (0x{:x})", dump_a.version, dump_a.version);
    println!("  B: {} (0x{:x})", dump_b.version, dump_b.version);
    if dump_a.version != dump_b.version {
        println!("  -> MISMATCH");
    }

    println!();
    println!("=== Internal substore root hash ===");
    println!("  A: {}", dump_a.internal_root);
    println!("  B: {}", dump_b.internal_root);
    if dump_a.internal_root != dump_b.internal_root {
        println!("  -> MISMATCH");
    }

    println!();
    println!("=== Canonical substore root hash ===");
    println!("  A: {}", dump_a.canonical_root);
    println!("  B: {}", dump_b.canonical_root);
    if dump_a.canonical_root != dump_b.canonical_root {
        println!("  -> MISMATCH");
    }

    let only_a: Vec<_> = dump_a
        .keys
        .keys()
        .filter(|k| !dump_b.keys.contains_key(*k))
        .collect();
    let only_b: Vec<_> = dump_b
        .keys
        .keys()
        .filter(|k| !dump_a.keys.contains_key(*k))
        .collect();
    let value_mismatch: Vec<_> = dump_a
        .keys
        .keys()
        .filter(|k| dump_b.keys.contains_key(*k) && dump_a.keys.get(*k) != dump_b.keys.get(*k))
        .collect();

    println!();
    println!("=== Key-level diff ===");
    println!("  Keys only in A: {}", only_a.len());
    println!("  Keys only in B: {}", only_b.len());
    println!(
        "  Keys in both with different value: {}",
        value_mismatch.len()
    );
    println!(
        "  Total keys A: {}, B: {}",
        dump_a.keys.len(),
        dump_b.keys.len()
    );

    if !only_a.is_empty() {
        println!();
        println!("--- Keys only in A (all {}) ---", only_a.len());
        for k in &only_a {
            println!("  {}", k);
        }
    }

    if !only_b.is_empty() {
        println!();
        println!("--- Keys only in B (all {}) ---", only_b.len());
        for k in &only_b {
            println!("  {}", k);
        }
    }

    if !value_mismatch.is_empty() {
        println!();
        println!(
            "--- Keys with different value (all {}, preview {} bytes) ---",
            value_mismatch.len(),
            value_preview_bytes
        );
        for k in &value_mismatch {
            let va = dump_a.keys.get(*k).unwrap();
            let vb = dump_b.keys.get(*k).unwrap();
            println!("  {}", k);
            println!("    A: {}", hex_preview(va, value_preview_bytes));
            println!("    B: {}", hex_preview(vb, value_preview_bytes));
        }
    }

    if let Some(ref out_path) = output_diff {
        let mut f = std::io::BufWriter::new(std::fs::File::create(out_path)?);
        use std::io::Write;
        writeln!(f, "# Felidae JMT state diff")?;
        writeln!(f, "# A: {}", path_a.display())?;
        writeln!(f, "# B: {}", path_b.display())?;
        writeln!(f, "# version A={} B={}", dump_a.version, dump_b.version)?;
        writeln!(
            f,
            "# internal_root A={} B={}",
            dump_a.internal_root, dump_b.internal_root
        )?;
        writeln!(
            f,
            "# canonical_root A={} B={}",
            dump_a.canonical_root, dump_b.canonical_root
        )?;
        writeln!(
            f,
            "# keys_only_in_A={} keys_only_in_B={} value_mismatch={}",
            only_a.len(),
            only_b.len(),
            value_mismatch.len()
        )?;
        writeln!(f)?;

        writeln!(f, "## Keys only in A")?;
        for k in &only_a {
            writeln!(f, "{}", k)?;
        }
        writeln!(f)?;
        writeln!(f, "## Keys only in B")?;
        for k in &only_b {
            writeln!(f, "{}", k)?;
        }
        writeln!(f)?;
        writeln!(f, "## Value mismatch (key -> hex A | hex B)")?;
        for k in &value_mismatch {
            let va = dump_a.keys.get(*k).unwrap();
            let vb = dump_b.keys.get(*k).unwrap();
            writeln!(f, "{}", k)?;
            writeln!(f, "  A: {}", hex::encode(va))?;
            writeln!(f, "  B: {}", hex::encode(vb))?;
        }
        println!();
        println!("Wrote detailed diff to {}", out_path.display());
    }

    Ok(())
}
