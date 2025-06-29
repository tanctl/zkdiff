use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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

#[derive(Debug, Clone)]
struct Edit {
    operation: EditOp,
    old_index: usize,
    new_index: usize,
}

#[derive(Debug, Clone, PartialEq)]
enum EditOp {
    Insert,
    Delete,
    Keep,
}

fn main() {
    let input: DiffInput = env::read();

    let computed_hash_a = hash_content(&input.file_a_content);
    let computed_hash_b = hash_content(&input.file_b_content);
    
    assert_eq!(input.file_a_hash, computed_hash_a, "File A hash mismatch");
    assert_eq!(input.file_b_hash, computed_hash_b, "File B hash mismatch");

    let lines_a: Vec<&str> = input.file_a_content.lines().collect();
    let lines_b: Vec<&str> = input.file_b_content.lines().collect();

    let edits = myers_diff(&lines_a, &lines_b);

    let diff_lines = create_diff_lines(&edits, &lines_a, &lines_b, &input.redaction_ranges);

    let proof_hash = create_proof_hash(&input, &diff_lines);

    let output = DiffOutput {
        file_a_hash: input.file_a_hash,
        file_b_hash: input.file_b_hash,
        diff_lines,
        proof_hash,
    };

    env::commit(&output);
}

fn hash_content(content: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hasher.finalize().into()
}

fn myers_diff(a: &[&str], b: &[&str]) -> Vec<Edit> {
    let n = a.len();
    let m = b.len();
    let max_d = n + m;
    
    let mut v = vec![0i32; 2 * max_d + 1];
    let offset = max_d as i32;
    
    let mut trace = Vec::new();
    
    for d in 0..=max_d {
        trace.push(v.clone());
        
        let start_k = -(d as i32);
        let end_k = d as i32;
        
        for k in (start_k..=end_k).step_by(2) {
            let idx = (k + offset) as usize;
            
            let x = if k == start_k || (k != end_k && v[idx - 1] < v[idx + 1]) {
                v[idx + 1]
            } else {
                v[idx - 1] + 1
            };
            
            let mut x_cur = x;
            let mut y_cur = x - k;
            
            while (x_cur as usize) < n && (y_cur as usize) < m && 
                  a[x_cur as usize] == b[y_cur as usize] {
                x_cur += 1;
                y_cur += 1;
            }
            
            v[idx] = x_cur;
            
            if (x_cur as usize) >= n && (y_cur as usize) >= m {
                return backtrack(&trace, a, b, d);
            }
        }
    }
    
    Vec::new()
}

fn backtrack(trace: &[Vec<i32>], a: &[&str], b: &[&str], d: usize) -> Vec<Edit> {
    let mut edits = Vec::new();
    let mut x = a.len() as i32;
    let mut y = b.len() as i32;
    let max_d = a.len() + b.len();
    let offset = max_d as i32;
    
    for trace_d in (0..=d).rev() {
        let v = &trace[trace_d];
        let k = x - y;
        let idx = (k + offset) as usize;
        
        let prev_k = if k == -(trace_d as i32) || 
                        (k != trace_d as i32 && v[idx - 1] < v[idx + 1]) {
            k + 1
        } else {
            k - 1
        };
        
        let prev_idx = (prev_k + offset) as usize;
        let prev_x = if trace_d > 0 { v[prev_idx] } else { 0 };
        let prev_y = prev_x - prev_k;
        
        while x > prev_x && y > prev_y {
            x -= 1;
            y -= 1;
            edits.push(Edit {
                operation: EditOp::Keep,
                old_index: x as usize,
                new_index: y as usize,
            });
        }
        
        if trace_d > 0 {
            if x > prev_x {
                x -= 1;
                edits.push(Edit {
                    operation: EditOp::Delete,
                    old_index: x as usize,
                    new_index: y as usize,
                });
            } else if y > prev_y {
                y -= 1;
                edits.push(Edit {
                    operation: EditOp::Insert,
                    old_index: x as usize,
                    new_index: y as usize,
                });
            }
        }
    }
    
    edits.reverse();
    edits
}

fn create_diff_lines(
    edits: &[Edit],
    lines_a: &[&str],
    lines_b: &[&str],
    redaction_ranges: &[RedactionRange],
) -> Vec<DiffLine> {
    let mut diff_lines = Vec::new();
    
    for edit in edits {
        match edit.operation {
            EditOp::Keep => {
                continue;
            }
            EditOp::Delete => {
                let line_content = lines_a[edit.old_index];
                let should_redact = should_redact_line(
                    edit.old_index,
                    &DiffOperation::Delete,
                    redaction_ranges,
                );
                
                diff_lines.push(DiffLine {
                    line_number_a: Some(edit.old_index + 1),
                    line_number_b: None,
                    operation: DiffOperation::Delete,
                    content: if should_redact { None } else { Some(line_content.to_string()) },
                    redacted_length: if should_redact { Some(line_content.len()) } else { None },
                });
            }
            EditOp::Insert => {
                let line_content = lines_b[edit.new_index];
                let should_redact = should_redact_line(
                    edit.new_index,
                    &DiffOperation::Insert,
                    redaction_ranges,
                );
                
                diff_lines.push(DiffLine {
                    line_number_a: None,
                    line_number_b: Some(edit.new_index + 1),
                    operation: DiffOperation::Insert,
                    content: if should_redact { None } else { Some(line_content.to_string()) },
                    redacted_length: if should_redact { Some(line_content.len()) } else { None },
                });
            }
        }
    }
    
    diff_lines
}

fn should_redact_line(
    line_number: usize,
    operation: &DiffOperation,
    redaction_ranges: &[RedactionRange],
) -> bool {
    for range in redaction_ranges {
        if range.operation == *operation &&
           line_number >= range.start_line.saturating_sub(1) &&
           line_number < range.end_line {
            return true;
        }
    }
    false
}

fn create_proof_hash(input: &DiffInput, diff_lines: &[DiffLine]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&input.file_a_hash);
    hasher.update(&input.file_b_hash);
    
    for line in diff_lines {
        hasher.update([match line.operation {
            DiffOperation::Insert => 1u8,
            DiffOperation::Delete => 2u8,
            DiffOperation::Replace => 3u8,
        }]);
        
        if let Some(line_a) = line.line_number_a {
            hasher.update(&line_a.to_le_bytes());
        }
        if let Some(line_b) = line.line_number_b {
            hasher.update(&line_b.to_le_bytes());
        }
        
        match (&line.content, line.redacted_length) {
            (Some(content), _) => {
                hasher.update(b"content:");
                hasher.update(content.as_bytes());
            }
            (None, Some(length)) => {
                hasher.update(b"redacted:");
                hasher.update(&length.to_le_bytes());
            }
            _ => {}
        }
    }
    
    hasher.finalize().into()
}