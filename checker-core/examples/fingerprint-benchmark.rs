//! Read-only measurements of the production fingerprint implementation.
use checker_core::fingerprint::{FingerprintOptions, fingerprint};
use std::{path::PathBuf, time::Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let root = PathBuf::from(args.next().ok_or("root required")?);
    let samples: usize = args.next().ok_or("sample count required")?.parse()?;
    if args.next().is_some() || !(1..=20).contains(&samples) {
        return Err("expected root and 1..20 samples".into());
    }
    let mut observations = Vec::new();
    for _ in 0..samples {
        let start = Instant::now();
        let report = fingerprint(&root, &FingerprintOptions::default())?;
        observations.push(serde_json::json!({
            "elapsed_ms":start.elapsed().as_secs_f64()*1000.0,
            "input_count":report.input_count,"digest":report.digest
        }));
    }
    println!(
        "{}",
        serde_json::json!({"version":env!("CARGO_PKG_VERSION"),"samples":observations})
    );
    Ok(())
}
