#![forbid(unsafe_code)]
#![doc = "Offline verifier for Keel audit streams."]

use keel_audit::{RunKey, verify_file};
use std::{env, fs, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os().skip(1);
    let audit_path = arguments
        .next()
        .ok_or("usage: keel-audit-verify AUDIT.ndjson RUN_KEY_FILE")?;
    let key_path = arguments
        .next()
        .ok_or("usage: keel-audit-verify AUDIT.ndjson RUN_KEY_FILE")?;
    if arguments.next().is_some() {
        return Err("usage: keel-audit-verify AUDIT.ndjson RUN_KEY_FILE".into());
    }
    let key = RunKey::from_hex(&fs::read_to_string(key_path)?)?;
    let records = verify_file(Path::new(&audit_path), &key)?;
    println!("verified {records} audit records");
    Ok(())
}
