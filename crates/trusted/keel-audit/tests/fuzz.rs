#![doc = "Randomized tampering of a sealed audit chain (D103)."]

use keel_audit::{AuditPayload, AuditWriter, Redactor, RunKey, read_verified_file};
use std::{collections::BTreeMap, fs};

/// However a sealed chain is edited, it either fails verification or reads
/// back as exactly the records that were written.
#[test]
fn an_edited_chain_never_verifies_as_different_records() {
    let root = std::env::temp_dir().join(format!("keel-audit-fuzz-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    let path = root.join("audit.ndjson");
    let key = || RunKey::new([47; 32]);
    let writer = AuditWriter::spawn(
        &path,
        "fuzz",
        key(),
        Redactor::new(Vec::<String>::new()).unwrap(),
    )
    .unwrap();
    for sequence in 0..5_u64 {
        writer
            .record(AuditPayload {
                timestamp_ms: sequence,
                event: "kernel.action".to_owned(),
                action_id: Some(sequence),
                fields: BTreeMap::from([("decision".to_owned(), "allow".into())]),
            })
            .unwrap();
    }
    writer.shutdown().unwrap();
    let sealed = fs::read(&path).unwrap();
    let written = read_verified_file(&path, &key()).unwrap();
    assert_eq!(written.len(), 5);

    let lines = sealed
        .split_inclusive(|byte| *byte == b'\n')
        .collect::<Vec<_>>();
    let edited = root.join("edited.ndjson");
    let mut rng = Rng(0x4b45_454c_0301);
    // Each iteration writes and reads a file, so run a tenth as many.
    for iteration in 0..iterations() / 10 {
        let bytes = match rng.below(4) {
            // Drop, repeat, or swap whole records, which keeps every line
            // individually authentic.
            0 => {
                let skip = rng.below(lines.len());
                lines
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| *index != skip)
                    .flat_map(|(_, line)| line.iter().copied())
                    .collect()
            }
            1 => {
                let mut order = lines.clone();
                let (a, b) = (rng.below(order.len()), rng.below(order.len()));
                if a == b {
                    order.insert(a, lines[a]);
                } else {
                    order.swap(a, b);
                }
                order.concat()
            }
            _ => mutate(
                &mut rng,
                &sealed,
                &[b"\n", b"allow", b"deny", b"\"seq\":0", b" "],
            ),
        };
        if bytes == sealed {
            continue;
        }
        fs::write(&edited, &bytes).unwrap();
        if let Ok(records) = read_verified_file(&edited, &key()) {
            // The hex of a hash or signature may change case and still
            // decode to the same bytes; what was recorded may not change.
            let content = |records: &[keel_audit::AuditRecord]| {
                records
                    .iter()
                    .map(|record| (record.seq, record.run_id.clone(), record.payload.clone()))
                    .collect::<Vec<_>>()
            };
            assert_eq!(
                content(&records),
                content(&written),
                "iteration {iteration}: an edited chain verified as other records"
            );
        }
    }
    fs::remove_dir_all(&root).unwrap();
}

/// xorshift64*, seeded, so a failure names an iteration that reproduces.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(bound.max(1)).unwrap()).unwrap()
    }
}

fn iterations() -> usize {
    std::env::var("KEEL_FUZZ_ITERATIONS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(20_000)
}

/// One or more random edits: a flipped bit, a cut, a copied run, a
/// truncation, an inserted byte, or an inserted token.
fn mutate(rng: &mut Rng, seed: &[u8], tokens: &[&[u8]]) -> Vec<u8> {
    let mut bytes = seed.to_vec();
    for _ in 0..=rng.below(4) {
        let at = rng.below(bytes.len() + 1);
        match rng.below(6) {
            0 if !bytes.is_empty() => {
                let index = rng.below(bytes.len());
                bytes[index] ^= 1 << rng.below(8);
            }
            1 if !bytes.is_empty() => {
                let end = (at + rng.below(8)).min(bytes.len());
                bytes.drain(at.min(end)..end);
            }
            2 if !tokens.is_empty() => {
                let token = tokens[rng.below(tokens.len())];
                bytes.splice(at..at, token.iter().copied());
            }
            3 if !bytes.is_empty() => {
                let start = rng.below(bytes.len());
                let end = (start + rng.below(16)).min(bytes.len());
                let copy = bytes[start..end].to_vec();
                bytes.splice(at..at, copy);
            }
            4 => bytes.truncate(at),
            _ => {
                let byte = u8::try_from(rng.below(256)).unwrap();
                bytes.insert(at, byte);
            }
        }
    }
    bytes
}
