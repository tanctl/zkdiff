# zkdiff
`zkdiff` is a zero-knowledge implementation of the myers diff algorithm designed to prove that two files were compared correctly, and optionally, that a specific set of line-level changes were computed, without exposing full file contents.
### Features
- **Zero-Knowledge Proofs**: Generate verifiable proofs without revealing file contents
- **Selective Redaction**: Hide sensitive portions while proving diff structure
- **Myers Algorithm**: Efficient diff computation with optimal edit distance
- **Cryptographic Integrity**: SHA256 hashing ensures file authenticity
- **Tamper-Proof**: Proofs are cryptographically verifiable and cannot be forged
- **Privacy-Preserving**: Redacted content never leaves the secure computation environment
## Installation

### Prerequisites

- **Rust toolchain** (1.70 or later)
- **RISC Zero zkVM** dependencies (automatically handled by cargo)
### Install from Git [Recommended]
```
cargo install --git https://github.com/tanctl/zkdiff
```
### Build from Source
```bash
git clone https://github.com/yourusername/zkdiff.git
cd zkdiff
cargo build --release
```

The binary will be available at `target/release/zkdiff`.

## Quick Start
### Generate a Proof
Compare two files and generate a zero-knowledge proof:
```bash
zkdiff generate -a file1.txt -b file2.txt -o proof.json
```
### Generate a Proof with Redaction
Hide specific lines while proving the diff structure:
```bash
zkdiff generate -a file1.txt -b file2.txt -r "delete:5-10,insert:15-20" -o proof.json
```
### Verify a Proof
Cryptographically verify a proof file:
```bash
zkdiff verify proof.json
```

## Usage
### Command Line Interface
```
zkdiff <COMMAND>

Commands:
  generate  Generate a zero-knowledge diff proof
  verify    Verify a zero-knowledge diff proof
  help      Print this message or the help of the given subcommand(s)
```
### Generate Command
```bash
zkdiff generate [OPTIONS] --file-a <FILE> --file-b <FILE>

Options:
  -a, --file-a <FILE>     First file to compare
  -b, --file-b <FILE>     Second file to compare
  -r, --redact <RANGES>   Redaction ranges [default: ""]
  -o, --output <FILE>     Output file for the proof [default: zkdiff.proof]
```
### Verify Command
```bash
zkdiff verify <PROOF_FILE>

Arguments:
  <PROOF_FILE>  Proof file to verify
```
## Redaction Syntax
Redaction ranges specify which lines to hide based on operation type:
```
operation:start-end,operation:start-end
```
### Operations
- `delete` or `d`: Redact deleted lines
- `insert` or `i`: Redact inserted lines  
- `replace` or `r`: Redact replaced lines
### Examples
```bash
# Redact deleted lines 5-10 and inserted lines 15-20
zkdiff generate -a file1.txt -b file2.txt -r "delete:5-10,insert:15-20" -o proof.json

# Short form syntax
zkdiff generate -a file1.txt -b file2.txt -r "d:1-3,i:7-9,r:12-15" -o proof.json

# Single line redaction
zkdiff generate -a file1.txt -b file2.txt -r "d:5-5" -o proof.json
```

## How It Works
### Architecture
zkdiff uses a **host-guest architecture** with the RISC Zero zkVM to provide zero-knowledge file comparison:
```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                                   zkdiff System                                     │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  ┌─────────────────────────────────┐          ┌─────────────────────────────────┐  │
│  │          Host Program           │          │         RISC Zero zkVM          │  │
│  │        (host/src/main.rs)       │          │                                 │  │
│  │                                 │          │  ┌───────────────────────────┐  │  │
│  │  ┌─────────────────────────┐   │          │  │      Guest Program        │  │  │
│  │  │     CLI Interface       │   │          │  │  (methods/guest/main.rs)  │  │  │
│  │  │  • generate command     │   │          │  │                           │  │  │
│  │  │  • verify command       │   │          │  │  ┌─────────────────────┐  │  │  │
│  │  │  • argument parsing     │   │          │  │  │   Myers Algorithm   │  │  │  │
│  │  └─────────────────────────┘   │          │  │  │  • diff computation │  │  │  │
│  │                                 │          │  │  │  • edit sequence    │  │  │  │
│  │  ┌─────────────────────────┐   │ Input    │  │  └─────────────────────┘  │  │  │
│  │  │    File Operations      │   │────────▶ │  │                           │  │  │
│  │  │  • read files A & B     │   │          │  │  ┌─────────────────────┐  │  │  │
│  │  │  • SHA256 hashing       │   │          │  │  │   Redaction Logic   │  │  │  │
│  │  │  • proof serialization  │   │          │  │  │  • selective hiding │  │  │  │
│  │  └─────────────────────────┘   │          │  │  │  • range filtering  │  │  │  │
│  │                                 │          │  │  └─────────────────────┘  │  │  │
│  │  ┌─────────────────────────┐   │ Output   │  │                           │  │  │
│  │  │   Proof Verification    │   │◀──────── │  │  ┌─────────────────────┐  │  │  │
│  │  │  • cryptographic check  │   │          │  │  │   Proof Generation  │  │  │  │
│  │  │  • method ID validation │   │          │  │  │  • integrity hash   │  │  │  │
│  │  │  • receipt validation   │   │          │  │  │  • structured output│  │  │  │
│  │  └─────────────────────────┘   │          │  │  └─────────────────────┘  │  │  │
│  └─────────────────────────────────┘          │  └───────────────────────────┘  │  │
│                                                │                                 │  │
│                                                └─────────────────────────────────┘  │
│                                                                                     │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                 Data Flow                                           │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  Input Files ──┐                                             ┌── Cryptographic     │
│               │                                             │    Proof Output     │
│  file_a.txt   ├── SHA256 ──┐                     ┌─────────┴─────────────────────  │
│  file_b.txt   │   Hashing  │                     │                               │  │
│               │            │                     │   ┌─────────────────────────┐ │  │
│  Redaction ───┘            │                     │   │     Proof Structure     │ │  │
│  Ranges                    ▼                     │   │  • file_a_hash          │ │  │
│                    ┌───────────────┐             │   │  • file_b_hash          │ │  │
│                    │  DiffInput    │             │   │  • diff_lines[]         │ │  │
│                    │  Structure    │────────────▶│   │  • proof_hash           │ │  │
│                    │               │             │   │  • method_id            │ │  │
│                    └───────────────┘             │   │  • receipt (zkProof)    │ │  │
│                                                  │   └─────────────────────────┘ │  │
│                                                  └───────────────────────────────┘  │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘
```
#### Component Breakdown
1. **Host Program** (`host/src/main.rs:1-301`) - Untrusted execution environment:
   - **CLI Interface**: Command parsing and user interaction
   - **File Operations**: Reading input files and generating SHA256 hashes  
   - **Proof Management**: Serialization/deserialization of proof data
   - **Verification Engine**: Cryptographic validation of zkVM receipts

2. **Guest Program** (`methods/guest/src/main.rs:1-293`) - Trusted execution inside zkVM:
   - **Myers Algorithm**: Optimal diff computation with O((N+M)D) complexity
   - **Redaction Engine**: Selective content hiding based on operation ranges
   - **Integrity Verification**: Hash validation and proof generation

3. **Methods Bridge** (`methods/src/lib.rs:1`) - Interface layer:
   - **METHOD_ELF**: Compiled guest program bytecode
   - **METHOD_ID**: Cryptographic identifier for guest program version

4. **RISC Zero zkVM** - Zero-knowledge execution environment:
   - **Deterministic Execution**: Guarantees reproducible computation
   - **Privacy Preservation**: Redacted content never leaves secure environment  
   - **Cryptographic Proofs**: STARK-based verification without re-execution

### Process Flow
```
Input Files → Hash Verification → Myers Diff → Redaction → ZK Proof → Verification
```
1. **File Processing**: Files are read and hashed for integrity
2. **Diff Computation**: Myers algorithm calculates optimal edit sequence
3. **Redaction Applied**: Specified ranges are hidden from output
4. **Proof Generation**: zkVM creates cryptographic proof of computation
5. **Verification**: Proof can be verified without access to original files

### Security Model
- **Computational Integrity**: RISC Zero zkVM ensures correct execution
- **Privacy Preservation**: Redacted content never leaves the secure environment
- **Tamper Resistance**: Proofs are cryptographically bound to inputs
- **Hash Verification**: SHA256 prevents input tampering

## Proof Format
Proofs are stored as JSON files containing:
```json
{
  "verified": true,
  "output": {
    "file_a_hash": "sha256_hash_of_file_a",
    "file_b_hash": "sha256_hash_of_file_b", 
    "diff_lines": [
      {
        "line_number_a": 1,
        "line_number_b": null,
        "operation": "Delete",
        "content": null,
        "redacted_length": 42
      }
    ],
    "proof_hash": "integrity_hash"
  },
  "method_id": "guest_program_identifier",
  "proof_generated": true,
  "receipt": "cryptographic_proof_data"
}
```

### Proof Contents
- **File Hashes**: SHA256 hashes of original files
- **Diff Lines**: Structured diff output with redactions
- **Proof Hash**: Integrity hash of the entire proof
- **Receipt**: Cryptographic proof from RISC Zero zkVM
- **Method ID**: Identifier for the guest program version

## Examples
### Basic File Comparison
```bash
# Create test files
echo -e "line1\nline2\nline3" > file1.txt
echo -e "line1\nmodified\nline3\nline4" > file2.txt

# Generate proof
zkdiff generate -a file1.txt -b file2.txt -o example.proof

# Verify proof
zkdiff verify example.proof
```

### Code Review with Redaction
```bash
# Compare code files, hiding sensitive function implementations
zkdiff generate \
  -a old_code.rs \
  -b new_code.rs \
  -r "insert:50-75,delete:20-30" \
  -o code_review.proof

# Reviewer can verify changes without seeing redacted sections
zkdiff verify code_review.proof
```

### Security Audit
```bash
# Prove vulnerability was fixed without revealing details
zkdiff generate \
  -a vulnerable.c \
  -b patched.c \
  -r "d:123-145,i:150-175" \
  -o security_fix.proof

# Verify the fix without seeing sensitive code
zkdiff verify security_fix.proof
```

## Development
### Building
```bash
# Debug build
cargo build

# Release build  
cargo build --release

# Run tests
cargo test

# Format code
cargo fmt

# Check for linting issues
cargo clippy
```

### Project Structure
```
zkdiff/
├── Cargo.toml          # Workspace configuration
├── host/               # Host program (CLI interface)
│   ├── Cargo.toml
│   └── src/
│       └── main.rs
├── methods/            # Guest program compilation
│   ├── Cargo.toml
│   ├── build.rs
│   ├── src/
│   │   └── lib.rs
│   └── guest/          # Guest program (runs in zkVM)
│       ├── Cargo.toml
│       └── src/
│           └── main.rs
├── target/             # Build artifacts
└── rust-toolchain.toml
```

## Technical Details
## What zkdiff Proves
Given two files `A` and `B`, and a set of redaction rules, `zkdiff` proves the following inside a zero-knowledge virtual machine:
- The SHA-256 hashes of `file_a_content` and `file_b_content` match the claimed `file_a_hash` and `file_b_hash`.
- The Myers diff was run on the files line-by-line and the correct edit trace was produced.
- The output diff contains the correct line differences, where some lines may be redacted in accordance with user-specified ranges.
- The output includes a `proof_hash` that cryptographically commits to all revealed + redacted edits, making verification of redacted diffs possible without revealing the redacted lines.
## Diff Semantics
The diff output is based on a variant of the **O(ND)** Myers algorithm which computes the shortest edit script to convert lines from file A to file B.
Each edit operation is tracked as:
- `Insert` — A new line appears in B but not A
- `Delete` — A line is removed in B that was present in A
- `Keep` (internal use) — A line that exists in both A and B (not included in final diff)
- `Replace` — Not explicitly emitted; encoded via Delete+Insert pairs on adjacent lines
### Zero-Knowledge Virtual Machine
RISC Zero zkVM provides:
- **Deterministic Execution**: Same inputs always produce same proofs
- **Computational Integrity**: Proofs guarantee correct execution
- **Privacy**: Intermediate values never leave the secure environment
- **Verifiability**: Proofs can be verified without re-execution

## Performance
### Computational Complexity
- **Diff Algorithm**: O((N+M)D) where N, M are file sizes, D is edit distance
- **Proof Generation**: ~1000x slower than native execution (zkVM overhead)
- **Verification**: O(1) - constant time regardless of file size
### Benchmarks

| File Size | Lines | Proof Generation | Verification |
|-----------|-------|------------------|--------------|
| 1KB       | 50    | ~2 seconds       | ~0.1 seconds |
| 10KB      | 500   | ~15 seconds      | ~0.1 seconds |
| 100KB     | 5000  | ~2 minutes       | ~0.1 seconds |
Performance varies by system configuration.*

## Security Considerations
### Threat Model
- **Malicious Prover**: Cannot generate false proofs
- **Untrusted Verifier**: Cannot access redacted content
- **Network Adversary**: Proofs are self-contained and verifiable
- **Quantum Resistance**: STARK proofs are post-quantum secure

### Limitations
- **Proof Size**: Proofs are larger than original diffs
- **Generation Time**: Significant computational overhead
- **Trust Assumptions**: Requires trust in RISC Zero zkVM
- **Side Channels**: Timing attacks may reveal information

## License
This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments
- [RISC Zero](https://github.com/risc0/risc0) for the zero-knowledge virtual machine
- Eugene Myers for the optimal diff algorithm
---

_zkdiff - Trustless diffing with zero-knowledge proofs_