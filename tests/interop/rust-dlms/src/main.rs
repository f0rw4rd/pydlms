//! Oracle adapters for the Rust DLMS crates (tests/interop/PROTOCOL.md).
//!
//! rust-dlms-oracle                    dlms-cosem-rs 0.1.0 (hupe1980), line protocol
//! rust-dlms-oracle push-parser        dlms_cosem 0.2.0 (reitermarkus), line protocol
//! rust-dlms-oracle server [--ciphered] [--port N]
//!                                     dlms-cosem-rs Server on the TCP wrapper
//! rust-dlms-oracle client HOST:PORT [--ciphered]
//!                                     dlms-cosem-rs ClientSession against a meter,
//!                                     one JSON report line on stdout
//!
//! Only JSON goes to stdout; diagnostics go to stderr.

mod client;
mod cosemrs;
mod reiter;
mod server;

use std::io::{BufRead, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};

use serde_json::{Value, json};

/// What one request line produced.
pub enum Reply {
    /// The `hello` line: emitted as is, with `"ok": true` added.
    Hello(Value),
    Ok(Value),
    Reject(String),
    Unsupported(String),
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd-length hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("bad hex: {e}")))
        .collect()
}

fn reply_json(r: Reply) -> Value {
    match r {
        Reply::Hello(mut v) => {
            v["ok"] = json!(true);
            v
        }
        Reply::Ok(v) => json!({"ok": true, "result": v}),
        Reply::Reject(e) => json!({"ok": false, "error": e}),
        Reply::Unsupported(e) => json!({"ok": false, "unsupported": true, "error": e}),
    }
}

/// Serve the line protocol with `answer`, catching panics from the library under test.
fn serve_lines(answer: fn(&str, &[&str], &str) -> Reply, on_panic: fn(String) -> Reply) {
    std::panic::set_hook(Box::new(|_| {}));
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (op, rest) = line.split_once(' ').unwrap_or((line, ""));
        // A key or system-title argument of `-` means "absent" (PROTOCOL.md).
        let args: Vec<&str> =
            rest.split_whitespace().map(|a| if a == "-" { "" } else { a }).collect();
        let reply = match catch_unwind(AssertUnwindSafe(|| answer(op, &args, rest))) {
            Ok(r) => r,
            Err(p) => {
                let msg = p
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_else(|| "panic".into());
                on_panic(msg)
            }
        };
        let _ = writeln!(out, "{}", reply_json(reply));
        let _ = out.flush();
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("oracle") => serve_lines(cosemrs::answer, |m| Reply::Reject(format!("panic: {m}"))),
        Some("push-parser") => serve_lines(reiter::answer, reiter::on_panic),
        Some("server") => server::main(&args[1..]),
        Some("client") => client::main(&args[1..]),
        Some(other) => {
            eprintln!("unknown mode {other}");
            std::process::exit(2);
        }
    }
}
