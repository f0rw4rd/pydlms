//! dlms_cosem 0.2.0 (reitermarkus) as an oracle: a push/message parser only.
//!
//! The crate keeps most fields `pub(crate)`: date, time and date-time values, the
//! data-notification's date-time and body, and the raw long-invoke-id are not readable.
//! What is reported:
//! - `data`: the public `Data` enum; date/time values as `{"t": ...}` with no `"v"`
//!   (the compare checks only the keys an oracle returns).
//! - `push`: `Apdu::parse` / `Apdu::parse_encrypted` must accept the frame; the
//!   long-invoke-id is rebuilt from the crate's accessors (bits 24-27, reserved, are
//!   not readable and are reported as zero); the body is `Data::parse` at the offset the
//!   crate's own data-notification grammar puts it (tag, 4 octets, length-prefixed
//!   date-time).
//! - `decrypt`: `general-glo-ciphering` only, through the crate's own decrypt.
//!
//! The crate panics (`unimplemented!`) on APDU tags and data types it does not know;
//! those panics are reported as `unsupported`.

use aes::Aes128;
use cipher::Key;
use dlms_cosem::{Apdu, Data};
use serde_json::{Value, json};

use crate::{Reply, hex, unhex};

pub fn on_panic(msg: String) -> Reply {
    if msg.starts_with("not implemented") {
        Reply::Unsupported(format!("dlms_cosem panics: {msg}"))
    } else {
        Reply::Reject(format!("panic: {msg}"))
    }
}

pub fn answer(op: &str, args: &[&str], _rest: &str) -> Reply {
    let r = match op {
        "hello" => {
            return Reply::Hello(json!({
                "library": "dlms_cosem (reitermarkus)",
                "version": "0.2.0",
                "ops": ["data", "push", "decrypt"],
            }));
        }
        "data" => op_data(args),
        "push" => op_push(args),
        "decrypt" => op_decrypt(args),
        _ => return Reply::Unsupported(format!("no {op} in dlms_cosem")),
    };
    match r {
        Ok(v) => Reply::Ok(v),
        Err(e) => Reply::Reject(e),
    }
}

type R<T> = Result<T, String>;

fn arg<'a>(args: &[&'a str], i: usize) -> R<&'a str> {
    args.get(i).copied().ok_or_else(|| format!("missing argument {i}"))
}

fn parse_data(raw: &[u8]) -> R<Value> {
    let (rest, d) = Data::parse(raw).map_err(|e| format!("{e:?}"))?;
    if !rest.is_empty() {
        return Err(format!("{} trailing octets", rest.len()));
    }
    data_json(&d)
}

fn op_data(args: &[&str]) -> R<Value> {
    parse_data(&unhex(arg(args, 0)?)?)
}

fn tv(t: &str, v: Value) -> Value {
    json!({"t": t, "v": v})
}

fn data_json(d: &Data) -> R<Value> {
    Ok(match d {
        Data::Null => tv("null-data", Value::Null),
        Data::OctetString(b) => tv("octet-string", json!(hex(b))),
        Data::Utf8String(s) => tv("utf8-string", json!(s)),
        Data::Integer(v) => tv("integer", json!(v)),
        Data::Unsigned(v) => tv("unsigned", json!(v)),
        Data::Long(v) => tv("long", json!(v)),
        Data::LongUnsigned(v) => tv("long-unsigned", json!(v)),
        Data::DoubleLong(v) => tv("double-long", json!(v)),
        Data::DoubleLongUnsigned(v) => tv("double-long-unsigned", json!(v)),
        Data::Long64(v) => tv("long64", json!(v)),
        Data::Long64Unsigned(v) => tv("long64-unsigned", json!(v)),
        Data::Float32(v) => tv("float32", json!(hex(&v.to_bits().to_be_bytes()))),
        Data::Float64(v) => tv("float64", json!(hex(&v.to_bits().to_be_bytes()))),
        // Fields are pub(crate): the type is known, the octets are not.
        Data::DateTime(_) => json!({"t": "date-time"}),
        Data::Date(_) => json!({"t": "date"}),
        Data::Time(_) => json!({"t": "time"}),
        Data::Structure(v) => tv("structure", Value::Array(v.iter().map(data_json).collect::<R<_>>()?)),
        Data::Enum(v) => tv("enum", json!(v)),
        other => return Err(format!("unmapped variant {other:?}")),
    })
}

fn aes_key(hex_: &str) -> R<Key<Aes128>> {
    let b: [u8; 16] = unhex(hex_)?.try_into().map_err(|_| "dlms_cosem takes AES-128 keys only".to_string())?;
    Ok(b.into())
}

/// The plaintext of a general-glo-ciphering APDU, through the crate's own decrypt.
fn decipher(raw: &[u8], ek: &str) -> R<Vec<u8>> {
    let (_, apdu) = Apdu::parse(raw).map_err(|e| format!("{e:?}"))?;
    match apdu {
        Apdu::GeneralGloCiphering(g) => g.decrypt(&aes_key(ek)?).map_err(|e| format!("{e:?}")),
        _ => Err("not general-glo-ciphering".into()),
    }
}

fn op_decrypt(args: &[&str]) -> R<Value> {
    // <ek> <ak> <system-title> <hex>: the crate takes no AK and no external title.
    let raw = unhex(arg(args, 3)?)?;
    Ok(json!({"plaintext": hex(&decipher(&raw, arg(args, 0)?)?)}))
}

fn op_push(args: &[&str]) -> R<Value> {
    let raw = unhex(arg(args, 0)?)?;
    let ek = args.get(1).copied().unwrap_or("");
    let plain = if raw.first() == Some(&0xDB) {
        if ek.is_empty() {
            return Err("ciphered push and no key".into());
        }
        // The crate's own entry point must accept it; it also requires the plaintext
        // to be exactly one APDU (all_consuming).
        Apdu::parse_encrypted(&raw, &aes_key(ek)?).map_err(|e| format!("{e:?}"))?;
        decipher(&raw, ek)?
    } else {
        raw
    };
    let (rest, apdu) = Apdu::parse(&plain).map_err(|e| format!("{e:?}"))?;
    if !rest.is_empty() {
        return Err(format!("{} trailing octets after the APDU", rest.len()));
    }
    let Apdu::DataNotification(n) = apdu else { return Err("not a data-notification".into()) };
    let bit = |set: bool, b: u32| if set { 1u32 << b } else { 0 };
    let long_invoke_id = n.invoke_id()
        | bit(format!("{:?}", n.priority()) == "High", 31)
        | bit(format!("{:?}", n.service_class()) == "Confirmed", 30)
        | bit(format!("{:?}", n.processing_option()) == "BreakOnError", 29)
        | bit(n.self_descriptive(), 28);
    // Grammar as in data_notification.rs: tag, long-invoke-id, length-prefixed date-time.
    let dt_len = usize::from(*plain.get(5).ok_or("short")?);
    let body = parse_data(plain.get(6 + dt_len..).ok_or("short")?)?;
    Ok(json!({"long_invoke_id": long_invoke_id, "body": body}))
}
