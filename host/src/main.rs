use anyhow::Result;
use clap::{Arg, Command};
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use methods::{METHOD_ELF, METHOD_ID};
use zerocopy::IntoBytes;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DiffInput {
    file_a_hash: [u8; 32],
    file_b_hash: [u8; 32],
    file_a_content: String,
    file_b_content: String,
    redaction_ranges: Vec<RedactionRange>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct RedactionRange {
    start_line: usize,
    end_line: usize,
    operation: DiffOperation,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
enum DiffOperation {
    Insert,
    Delete,
    Replace,
}

#[derive(Serialize, Deserialize, Debug)]
struct DiffOutput {
    file_a_hash: [u8; 32],
    file_b_hash: [u8; 32],
    diff_lines: Vec<DiffLine>,
    proof_hash: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DiffLine {
    line_number_a: Option<usize>,
    line_number_b: Option<usize>,
    operation: DiffOperation,
    content: Option<String>,
    redacted_length: Option<usize>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ProofFile {
    verified: bool,
    output: DiffOutput,
    method_id: String,
    proof_generated: bool,
    receipt: Option<serde_json::Value>,
}

fn hash_content(content: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hasher.finalize().into()
}

fn main() -> Result<()> {
    let matches = Command::new("zkdiff")
        .about("Zero-knowledge diff implementation using Myers algorithm")
        .subcommand_required(true)
        .subcommand(
            Command::new("generate")
                .about("Generate a zero-knowledge diff proof")
                .arg(
                    Arg::new("file_a")
                        .short('a')
                        .long("file-a")
                        .value_name("FILE")
                        .help("First file to compare")
                        .required(true),
                )
                .arg(
                    Arg::new("file_b")
                        .short('b')
                        .long("file-b")
                        .value_name("FILE")
                        .help("Second file to compare")
                        .required(true),
                )
                .arg(
                    Arg::new("redact")
                        .short('r')
                        .long("redact")
                        .value_name("RANGES")
                        .help("Redaction ranges in format: operation:start-end,operation:start-end")
                        .default_value(""),
                )
                .arg(
                    Arg::new("output")
                        .short('o')
                        .long("output")
                        .value_name("FILE")
                        .help("Output file for the proof")
                        .default_value("zkdiff.proof"),
                ),
        )
        .subcommand(
            Command::new("verify")
                .about("Verify a zero-knowledge diff proof")
                .arg(
                    Arg::new("proof_file")
                        .value_name("PROOF_FILE")
                        .help("Proof file to verify")
                        .required(true),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("generate", sub_matches)) => {
            generate_proof(sub_matches)?;
        }
        Some(("verify", sub_matches)) => {
            verify_proof(sub_matches)?;
        }
        _ => unreachable!(),
    }

    Ok(())
}

fn generate_proof(matches: &clap::ArgMatches) -> Result<()> {
    let file_a_path = matches.get_one::<String>("file_a").unwrap();
    let file_b_path = matches.get_one::<String>("file_b").unwrap();
    let redact_str = matches.get_one::<String>("redact").unwrap();
    let output_path = matches.get_one::<String>("output").unwrap();

    let file_a_content = fs::read_to_string(file_a_path)?;
    let file_b_content = fs::read_to_string(file_b_path)?;

    let file_a_hash = hash_content(&file_a_content);
    let file_b_hash = hash_content(&file_b_content);

    let redaction_ranges = parse_redaction_ranges(redact_str)?;

    let input = DiffInput {
        file_a_hash,
        file_b_hash,
        file_a_content,
        file_b_content,
        redaction_ranges,
    };

    println!("Generating zero-knowledge proof for diff...");
    println!("File A hash: {}", hex::encode(file_a_hash));
    println!("File B hash: {}", hex::encode(file_b_hash));

    let env = ExecutorEnv::builder()
        .write(&input)?
        .build()?;

    let prover = default_prover();
    let prove_info = prover.prove(env, METHOD_ELF)?;

    prove_info.receipt.verify(METHOD_ID)?;

    let output: DiffOutput = prove_info.receipt.journal.decode()?;

    println!("✅ Proof generated and verified successfully!");
    println!("Diff contains {} lines", output.diff_lines.len());
    
    let mut inserts = 0;
    let mut deletes = 0;
    let mut redacted = 0;
    
    for line in &output.diff_lines {
        match line.operation {
            DiffOperation::Insert => inserts += 1,
            DiffOperation::Delete => deletes += 1,
            DiffOperation::Replace => {
                inserts += 1;
                deletes += 1;
            }
        }
        if line.content.is_none() {
            redacted += 1;
        }
    }
    
    println!("Summary: +{} -{} lines, {} redacted", inserts, deletes, redacted);

    let method_id_bytes = METHOD_ID.as_bytes();
    let proof_file = ProofFile {
        verified: true,
        output,
        method_id: hex::encode(method_id_bytes),
        proof_generated: true,
        receipt: Some(serde_json::to_value(&prove_info.receipt)?),
    };
    
    let proof_data = serde_json::to_string_pretty(&proof_file)?;
    fs::write(output_path, proof_data)?;
    println!("Proof saved to: {}", output_path);

    Ok(())
}

fn verify_proof(matches: &clap::ArgMatches) -> Result<()> {
    let proof_file_path = matches.get_one::<String>("proof_file").unwrap();
    
    println!("Verifying proof from: {}", proof_file_path);
    
    let proof_data = fs::read_to_string(proof_file_path)?;
    let proof_file: ProofFile = serde_json::from_str(&proof_data)?;
    
    let expected_method_id = hex::encode(METHOD_ID.as_bytes());
    if proof_file.method_id != expected_method_id {
        println!("❌ Method ID mismatch!");
        println!("Expected: {}", expected_method_id);
        println!("Found: {}", proof_file.method_id);
        return Ok(());
    }

    if let Some(receipt_value) = proof_file.receipt {
        let receipt: Receipt = serde_json::from_value(receipt_value)?;
        
        match receipt.verify(METHOD_ID) {
            Ok(_) => {
                println!("✅ Proof verification successful!");
                
                println!("\nProof Details:");
                println!("File A hash: {}", hex::encode(proof_file.output.file_a_hash));
                println!("File B hash: {}", hex::encode(proof_file.output.file_b_hash));
                println!("Diff lines: {}", proof_file.output.diff_lines.len());
                
                let mut inserts = 0;
                let mut deletes = 0;
                let mut redacted = 0;
                
                for line in &proof_file.output.diff_lines {
                    match line.operation {
                        DiffOperation::Insert => inserts += 1,
                        DiffOperation::Delete => deletes += 1,
                        DiffOperation::Replace => {
                            inserts += 1;
                            deletes += 1;
                        }
                    }
                    if line.content.is_none() {
                        redacted += 1;
                    }
                }
                
                println!("Summary: +{} -{} lines, {} redacted", inserts, deletes, redacted);
            }
            Err(e) => {
                println!("❌ Proof verification failed: {}", e);
            }
        }
    } else {
        println!("⚠️  No receipt found in proof file - cannot verify cryptographically");
        println!("Proof metadata indicates: {}", if proof_file.verified { "verified" } else { "not verified" });
    }
    
    Ok(())
}

fn parse_redaction_ranges(redact_str: &str) -> Result<Vec<RedactionRange>> {
    if redact_str.is_empty() {
        return Ok(vec![]);
    }

    let mut ranges = Vec::new();
    for range_str in redact_str.split(',') {
        let parts: Vec<&str> = range_str.split(':').collect();
        if parts.len() != 2 {
            continue;
        }

        let operation = match parts[0] {
            "insert" | "i" => DiffOperation::Insert,
            "delete" | "d" => DiffOperation::Delete,
            "replace" | "r" => DiffOperation::Replace,
            _ => continue,
        };

        let range_parts: Vec<&str> = parts[1].split('-').collect();
        if range_parts.len() != 2 {
            continue;
        }

        let start_line = range_parts[0].parse::<usize>()?;
        let end_line = range_parts[1].parse::<usize>()?;

        ranges.push(RedactionRange {
            start_line,
            end_line,
            operation,
        });
    }

    Ok(ranges)
}