//! dlms-cosem-rs 0.1.0 as an oracle: every op goes through the crate's own decoder,
//! encoder or security engine; this file only maps its types onto the JSON model.

use dlms_cosem_rs::acse::{Aare, Aarq, Diagnostic, Rlre, Rlrq};
use dlms_cosem_rs::axdr::{Data, DataBuf, Date, DateTime, Time, TypeDesc};
use dlms_cosem_rs::client::{NotificationListener, SingleMeterKeys};
use dlms_cosem_rs::codec::{Decode, Encode, ErrorKind, Reader};
use dlms_cosem_rs::obis::Obis;
use dlms_cosem_rs::security::{
    Key, KeyRing, KeySet, KeyUsage, Protector, RustCryptoProvider, SecurityPolicy, SecuritySuite, SystemTitle,
};
use dlms_cosem_rs::xdlms::{
    AccessRequestSpecification, AccessResponseSpecification, ActionRequest, ActionResponse, ActionResponseWithOptionalData, Apdu, AttributeDescriptor,
    AttributeDescriptorWithSelection, CipheredService, GetDataResult, GetRequest, GetResponse, MethodDescriptor,
    Protection, ReadResult, SelectiveAccess, SetRequest, SetResponse, VariableAccess, WriteResult,
};
use serde_json::{Value, json};

use crate::{Reply, hex, unhex};

type R<T> = Result<T, String>;

fn err(e: dlms_cosem_rs::Error) -> String {
    e.to_string()
}

pub fn answer(op: &str, args: &[&str], rest: &str) -> Reply {
    let result = match op {
        "hello" => {
            return Reply::Hello(json!({
                "library": "dlms-cosem-rs",
                "version": "0.1.0",
                "ops": ["data", "encode-data", "apdu", "push", "decrypt"],
            }));
        }
        "data" => op_data(args),
        "encode-data" => op_encode(rest),
        "apdu" => op_apdu(args),
        "push" => op_push(args),
        "decrypt" => op_decrypt(args),
        _ => return Reply::Unsupported(format!("unknown op {op}")),
    };
    match result {
        Ok(v) => Reply::Ok(v),
        Err(Fail::Reject(e)) => Reply::Reject(e),
        Err(Fail::Unsupported(e)) => Reply::Unsupported(e),
    }
}

pub enum Fail {
    Reject(String),
    Unsupported(String),
}

impl From<String> for Fail {
    fn from(s: String) -> Self {
        Fail::Reject(s)
    }
}

impl From<&str> for Fail {
    fn from(s: &str) -> Self {
        Fail::Reject(s.into())
    }
}

impl From<dlms_cosem_rs::Error> for Fail {
    fn from(e: dlms_cosem_rs::Error) -> Self {
        if e.kind == ErrorKind::Unsupported {
            Fail::Unsupported(format!("library refuses by name: {e}"))
        } else {
            Fail::Reject(e.to_string())
        }
    }
}

fn arg<'a>(args: &[&'a str], i: usize) -> R<&'a str> {
    args.get(i).copied().ok_or_else(|| format!("missing argument {i}"))
}

// --- data ---------------------------------------------------------------------------------

fn op_data(args: &[&str]) -> Result<Value, Fail> {
    let raw = unhex(arg(args, 0)?)?;
    let d = Data::from_bytes(&raw)?;
    Ok(data_json(&d)?)
}

fn bits(len: usize, bit: impl Fn(usize) -> bool) -> String {
    (0..len).map(|i| if bit(i) { '1' } else { '0' }).collect()
}

/// ISO 646 bytes as text, one char per octet (the same lossless mapping pydlms uses).
fn latin1(b: &[u8]) -> String {
    b.iter().map(|&c| c as char).collect()
}

fn tv(t: &str, v: Value) -> Value {
    json!({"t": t, "v": v})
}

pub fn data_json(d: &Data<'_>) -> R<Value> {
    Ok(match *d {
        Data::Null => tv("null-data", Value::Null),
        Data::Array(s) => tv("array", Value::Array(s.iter().map(|e| data_json(&e.map_err(err)?)).collect::<R<_>>()?)),
        Data::Structure(s) => {
            tv("structure", Value::Array(s.iter().map(|e| data_json(&e.map_err(err)?)).collect::<R<_>>()?))
        }
        Data::Boolean(v) => tv("boolean", json!(v)),
        Data::BitString(b) => tv("bit-string", json!(bits(b.len(), |i| b.bit(i)))),
        Data::DoubleLong(v) => tv("double-long", json!(v)),
        Data::DoubleLongUnsigned(v) => tv("double-long-unsigned", json!(v)),
        Data::OctetString(b) => tv("octet-string", json!(hex(b))),
        Data::VisibleString(b) => tv("visible-string", json!(latin1(b))),
        Data::Utf8String(b) => {
            tv("utf8-string", json!(std::str::from_utf8(b).map_err(|e| format!("utf8-string: {e}"))?))
        }
        // The crate keeps the octet as i8; the protocol carries the octet's value.
        Data::Bcd(v) => tv("bcd", json!(v as u8)),
        Data::Integer(v) => tv("integer", json!(v)),
        Data::Long(v) => tv("long", json!(v)),
        Data::Unsigned(v) => tv("unsigned", json!(v)),
        Data::LongUnsigned(v) => tv("long-unsigned", json!(v)),
        Data::CompactArray(c) => {
            let desc = desc_json(&c.description().map_err(err)?)?;
            let rows = c.to_rows().map_err(err)?;
            tv(
                "compact-array",
                json!({"description": desc, "items": rows.iter().map(buf_json).collect::<R<Vec<_>>>()?}),
            )
        }
        Data::Long64(v) => tv("long64", json!(v)),
        Data::Long64Unsigned(v) => tv("long64-unsigned", json!(v)),
        Data::Enum(v) => tv("enum", json!(v)),
        Data::Float32(v) => tv("float32", json!(hex(&v.to_bits().to_be_bytes()))),
        Data::Float64(v) => tv("float64", json!(hex(&v.to_bits().to_be_bytes()))),
        Data::DateTime(v) => tv("date-time", json!(hex(&v.to_bytes()))),
        Data::Date(v) => tv("date", json!(hex(&v.to_bytes()))),
        Data::Time(v) => tv("time", json!(hex(&v.to_bytes()))),
        // Green Book ed. 10 delta types and dont-care (tag 255): not in the protocol's
        // type list, reported under their ASN.1 names.
        Data::DeltaInteger(v) => tv("delta-integer", json!(v)),
        Data::DeltaLong(v) => tv("delta-long", json!(v)),
        Data::DeltaDoubleLong(v) => tv("delta-double-long", json!(v)),
        Data::DeltaUnsigned(v) => tv("delta-unsigned", json!(v)),
        Data::DeltaLongUnsigned(v) => tv("delta-long-unsigned", json!(v)),
        Data::DeltaDoubleLongUnsigned(v) => tv("delta-double-long-unsigned", json!(v)),
        Data::DontCare => tv("dont-care", Value::Null),
    })
}

fn buf_json(d: &DataBuf) -> R<Value> {
    // Round-trip the owned row through the crate's encoder and borrowed decoder, so one
    // mapping (data_json) serves both.
    let mut raw = Vec::new();
    d.encode(&mut raw).map_err(err)?;
    data_json(&Data::from_bytes(&raw).map_err(err)?)
}

fn tag_name(tag: u8) -> R<&'static str> {
    // Reuse data_json's names: encode a zero value of the tag is not possible for every
    // tag, so name them directly.
    Ok(match tag {
        0 => "null-data",
        1 => "array",
        2 => "structure",
        3 => "boolean",
        4 => "bit-string",
        5 => "double-long",
        6 => "double-long-unsigned",
        9 => "octet-string",
        10 => "visible-string",
        12 => "utf8-string",
        13 => "bcd",
        15 => "integer",
        16 => "long",
        17 => "unsigned",
        18 => "long-unsigned",
        19 => "compact-array",
        20 => "long64",
        21 => "long64-unsigned",
        22 => "enum",
        23 => "float32",
        24 => "float64",
        25 => "date-time",
        26 => "date",
        27 => "time",
        28 => "delta-integer",
        29 => "delta-long",
        30 => "delta-double-long",
        31 => "delta-unsigned",
        32 => "delta-long-unsigned",
        33 => "delta-double-long-unsigned",
        255 => "dont-care",
        t => return Err(format!("tag {t}")),
    })
}

fn desc_json(d: &TypeDesc<'_>) -> R<Value> {
    Ok(match *d {
        TypeDesc::Scalar(tag) => json!({"t": tag_name(tag.as_u8())?}),
        TypeDesc::Array { len, elem } => {
            let inner = TypeDesc::parse(&mut Reader::new(elem)).map_err(err)?;
            json!({"t": "array", "count": len, "of": desc_json(&inner)?})
        }
        TypeDesc::Structure { count, fields } => {
            let mut r = Reader::new(fields);
            let mut members = Vec::new();
            for _ in 0..count {
                members.push(desc_json(&TypeDesc::parse(&mut r).map_err(err)?)?);
            }
            json!({"t": "structure", "members": members})
        }
    })
}

// --- encode-data ----------------------------------------------------------------------------

fn op_encode(rest: &str) -> Result<Value, Fail> {
    let tree: Value = serde_json::from_str(rest).map_err(|e| format!("json: {e}"))?;
    let buf = json_buf(&tree)?;
    let mut out = Vec::new();
    buf.encode(&mut out)?;
    Ok(json!({"hex": hex(&out)}))
}

fn json_buf(v: &Value) -> Result<DataBuf, Fail> {
    let t = v["t"].as_str().ok_or("no t")?;
    let x = &v["v"];
    let int = || x.as_i64().ok_or_else(|| Fail::Reject(format!("{t}: not an integer")));
    let uint = || x.as_u64().ok_or_else(|| Fail::Reject(format!("{t}: not an integer")));
    let rng = |e| Fail::Reject(format!("{t}: out of range: {e}"));
    let bytes = || -> Result<Vec<u8>, Fail> { Ok(unhex(x.as_str().ok_or("not hex")?)?) };
    let list = || -> Result<Vec<DataBuf>, Fail> {
        x.as_array().ok_or("not a list")?.iter().map(json_buf).collect()
    };
    Ok(match t {
        "null-data" => DataBuf::Null,
        "array" => DataBuf::Array(list()?),
        "structure" => DataBuf::Structure(list()?),
        "boolean" => DataBuf::Boolean(x.as_bool().ok_or("not a bool")?),
        "bit-string" => {
            let s = x.as_str().ok_or("not a bit string")?;
            let mut bytes = vec![0u8; s.len().div_ceil(8)];
            for (i, c) in s.chars().enumerate() {
                if c == '1' {
                    bytes[i / 8] |= 0x80 >> (i % 8);
                }
            }
            DataBuf::BitString { bits: s.len(), bytes }
        }
        "double-long" => DataBuf::DoubleLong(i32::try_from(int()?).map_err(rng)?),
        "double-long-unsigned" => DataBuf::DoubleLongUnsigned(u32::try_from(uint()?).map_err(rng)?),
        "octet-string" => DataBuf::OctetString(bytes()?),
        "visible-string" => DataBuf::VisibleString(
            x.as_str()
                .ok_or("not a string")?
                .chars()
                .map(|c| u8::try_from(u32::from(c)).map_err(|_| Fail::Reject("not latin-1".into())))
                .collect::<Result<_, _>>()?,
        ),
        "utf8-string" => DataBuf::Utf8String(x.as_str().ok_or("not a string")?.as_bytes().to_vec()),
        "bcd" => DataBuf::Bcd(u8::try_from(uint()?).map_err(rng)? as i8),
        "integer" => DataBuf::Integer(i8::try_from(int()?).map_err(rng)?),
        "long" => DataBuf::Long(i16::try_from(int()?).map_err(rng)?),
        "unsigned" => DataBuf::Unsigned(u8::try_from(uint()?).map_err(rng)?),
        "long-unsigned" => DataBuf::LongUnsigned(u16::try_from(uint()?).map_err(rng)?),
        "long64" => DataBuf::Long64(int()?),
        "long64-unsigned" => DataBuf::Long64Unsigned(uint()?),
        "enum" => DataBuf::Enum(u8::try_from(uint()?).map_err(rng)?),
        "float32" => {
            let b: [u8; 4] = bytes()?.try_into().map_err(|_| Fail::Reject("float32 needs 4 octets".into()))?;
            DataBuf::Float32(f32::from_bits(u32::from_be_bytes(b)))
        }
        "float64" => {
            let b: [u8; 8] = bytes()?.try_into().map_err(|_| Fail::Reject("float64 needs 8 octets".into()))?;
            DataBuf::Float64(f64::from_bits(u64::from_be_bytes(b)))
        }
        "date-time" => DataBuf::DateTime(DateTime::from_bytes(
            bytes()?.try_into().map_err(|_| Fail::Reject("date-time needs 12 octets".into()))?,
        )),
        "date" => DataBuf::Date(Date::from_bytes(
            bytes()?.try_into().map_err(|_| Fail::Reject("date needs 5 octets".into()))?,
        )),
        "time" => DataBuf::Time(Time::from_bytes(
            bytes()?.try_into().map_err(|_| Fail::Reject("time needs 4 octets".into()))?,
        )),
        // DataBuf has no compact-array variant (from_data expands one into an array) and
        // the crate has no encoder from values to a compact array.
        "compact-array" => return Err(Fail::Unsupported("no compact-array encoder in dlms-cosem-rs".into())),
        other => return Err(Fail::Reject(format!("unknown type {other}"))),
    })
}

// --- apdu -----------------------------------------------------------------------------------

fn op_apdu(args: &[&str]) -> Result<Value, Fail> {
    let raw = unhex(arg(args, 0)?)?;
    let apdu = Apdu::from_bytes(&raw)?;
    Ok(apdu_json(&apdu)?)
}

fn obis(o: &Obis) -> String {
    let b = o.as_bytes();
    format!("{}.{}.{}.{}.{}.{}", b[0], b[1], b[2], b[3], b[4], b[5])
}

fn attr(d: &AttributeDescriptor) -> Value {
    json!({"kind": "attribute-descriptor", "class_id": d.class_id, "instance_id": obis(&d.instance_id),
           "attribute_id": d.attribute_id})
}

fn method(d: &MethodDescriptor) -> Value {
    json!({"kind": "method-descriptor", "class_id": d.class_id, "instance_id": obis(&d.instance_id),
           "method_id": d.method_id})
}

fn access(a: &Option<SelectiveAccess<'_>>) -> R<Value> {
    Ok(match a {
        None => Value::Null,
        Some(s) => json!({"kind": "selective-access", "selector": s.selector, "parameters": data_json(&s.parameters)?}),
    })
}

fn gdr(r: &GetDataResult<'_>) -> R<Value> {
    Ok(match r {
        GetDataResult::Data(d) => json!({"kind": "get-data-result", "data": data_json(d)?, "error": null}),
        GetDataResult::Error(e) => json!({"kind": "get-data-result", "data": null, "error": e.as_u8()}),
    })
}

fn opt_hex(b: Option<&[u8]>) -> Value {
    b.map_or(Value::Null, |b| json!(hex(b)))
}

/// pydlms models an absent user-information as empty octets.
fn ui(b: Option<&[u8]>) -> Value {
    json!(hex(b.unwrap_or(&[])))
}

fn obj(kind: &str, fields: Value) -> Value {
    let mut m = serde_json::Map::new();
    m.insert("kind".into(), json!(kind));
    if let Value::Object(f) = fields {
        m.extend(f);
    }
    Value::Object(m)
}

fn conformance(c: dlms_cosem_rs::xdlms::Conformance) -> u32 {
    let b = c.to_bytes();
    u32::from_be_bytes([0, b[0], b[1], b[2]])
}

fn list<'a, T: Decode<'a>>(l: &dlms_cosem_rs::xdlms::List<'a, T>) -> R<Vec<T>> {
    l.iter().map(|x| x.map_err(err)).collect()
}

fn sel_item(d: &AttributeDescriptorWithSelection<'_>) -> R<Value> {
    Ok(json!([attr(&d.descriptor), access(&d.access)?]))
}

fn action_item(r: &ActionResponseWithOptionalData<'_>) -> R<Value> {
    Ok(json!([r.result.as_u8(), r.return_parameters.as_ref().map(gdr).transpose()?]))
}

fn variable(v: &VariableAccess<'_>) -> R<Value> {
    Ok(match *v {
        VariableAccess::VariableName(n) => json!({"kind": "variable-name", "name": n}),
        VariableAccess::Parameterized { name, selector, parameter } => {
            json!({"kind": "parameterized-access", "name": name, "selector": selector,
                   "parameter": data_json(&parameter)?})
        }
        VariableAccess::BlockNumber(n) => json!({"kind": "block-number-access", "block_number": n}),
        VariableAccess::ReadDataBlock { last_block, block_number, raw_data } => {
            json!({"kind": "read-data-block-access", "last_block": last_block, "block_number": block_number,
                   "raw_data": hex(raw_data)})
        }
        VariableAccess::WriteDataBlock { last_block, block_number } => {
            json!({"kind": "write-data-block-access", "last_block": last_block, "block_number": block_number})
        }
    })
}

fn access_specs(l: &dlms_cosem_rs::xdlms::List<'_, AccessRequestSpecification<'_>>) -> R<Value> {
    let mut out = Vec::new();
    for s in list(l)? {
        out.push(match s {
            AccessRequestSpecification::Get(d) => json!({"kind": "access-request-get", "attribute": attr(&d)}),
            AccessRequestSpecification::Set(d) => json!({"kind": "access-request-set", "attribute": attr(&d)}),
            AccessRequestSpecification::Action(d) => json!({"kind": "access-request-action", "method": method(&d)}),
            AccessRequestSpecification::GetWithSelection(d) => json!({"kind": "access-request-get-with-selection",
                "attribute": attr(&d.descriptor), "access": access(&d.access)?}),
            AccessRequestSpecification::SetWithSelection(d) => json!({"kind": "access-request-set-with-selection",
                "attribute": attr(&d.descriptor), "access": access(&d.access)?}),
        });
    }
    Ok(Value::Array(out))
}

fn access_result(r: &AccessResponseSpecification) -> Value {
    match r {
        AccessResponseSpecification::Get(v) => json!({"kind": "access-response-get", "result": v.as_u8()}),
        AccessResponseSpecification::Set(v) => json!({"kind": "access-response-set", "result": v.as_u8()}),
        AccessResponseSpecification::Action(v) => json!({"kind": "access-response-action", "result": v.as_u8()}),
    }
}

fn datas(l: &dlms_cosem_rs::xdlms::List<'_, Data<'_>>) -> R<Value> {
    Ok(Value::Array(list(l)?.iter().map(data_json).collect::<R<_>>()?))
}

pub fn apdu_json(apdu: &Apdu<'_>) -> R<Value> {
    Ok(match apdu {
        Apdu::Aarq(a) => aarq(a),
        Apdu::Aare(a) => aare(a),
        Apdu::Rlrq(Rlrq { reason, user_information }) | Apdu::Rlre(Rlre { reason, user_information }) => obj(
            if matches!(apdu, Apdu::Rlrq(_)) { "rlrq" } else { "rlre" },
            json!({"reason": reason.map(|r| r.as_u8()), "user_information": ui(*user_information)}),
        ),
        Apdu::InitiateRequest(i) => {
            let mut v = obj(
                "initiate-request",
                json!({"conformance": conformance(i.proposed_conformance),
                       "max_receive_pdu_size": i.client_max_receive_pdu_size,
                       "dlms_version": i.proposed_dlms_version,
                       "dedicated_key": opt_hex(i.dedicated_key),
                       "quality_of_service": i.proposed_quality_of_service}),
            );
            // Absent means the ASN.1 DEFAULT (TRUE); only report what was decoded.
            if let Some(r) = i.response_allowed {
                v["response_allowed"] = json!(r);
            }
            v
        }
        Apdu::InitiateResponse(i) => obj(
            "initiate-response",
            json!({"conformance": conformance(i.negotiated_conformance),
                   "max_receive_pdu_size": i.server_max_receive_pdu_size,
                   "dlms_version": i.negotiated_dlms_version, "vaa_name": i.vaa_name,
                   "quality_of_service": i.negotiated_quality_of_service}),
        ),
        Apdu::GetRequest(g) => match g {
            GetRequest::Normal { invoke_id, descriptor, access: a } => obj(
                "get-request-normal",
                json!({"invoke_id": invoke_id.0, "attribute": attr(descriptor), "access": access(a)?}),
            ),
            GetRequest::Next { invoke_id, block_number } => {
                obj("get-request-next", json!({"invoke_id": invoke_id.0, "block_number": block_number}))
            }
            GetRequest::WithList { invoke_id, list: l } => obj(
                "get-request-with-list",
                json!({"invoke_id": invoke_id.0,
                       "items": list(l)?.iter().map(sel_item).collect::<R<Vec<_>>>()?}),
            ),
        },
        Apdu::GetResponse(g) => match g {
            GetResponse::Normal { invoke_id, result } => {
                obj("get-response-normal", json!({"invoke_id": invoke_id.0, "result": gdr(result)?}))
            }
            GetResponse::WithDataBlock { invoke_id, block } => {
                let (raw, error) = match block.result {
                    Ok(b) => (json!(hex(b)), Value::Null),
                    Err(e) => (Value::Null, json!(e.as_u8())),
                };
                obj(
                    "get-response-with-datablock",
                    json!({"invoke_id": invoke_id.0, "last_block": block.last_block,
                           "block_number": block.block_number, "raw_data": raw, "error": error}),
                )
            }
            GetResponse::WithList { invoke_id, results } => obj(
                "get-response-with-list",
                json!({"invoke_id": invoke_id.0, "results": list(results)?.iter().map(gdr).collect::<R<Vec<_>>>()?}),
            ),
        },
        Apdu::SetRequest(s) => match s {
            SetRequest::Normal { invoke_id, descriptor, access: a, value } => obj(
                "set-request-normal",
                json!({"invoke_id": invoke_id.0, "attribute": attr(descriptor), "value": data_json(value)?,
                       "access": access(a)?}),
            ),
            SetRequest::WithFirstDataBlock { invoke_id, descriptor, access: a, block } => obj(
                "set-request-with-first-datablock",
                json!({"invoke_id": invoke_id.0, "attribute": attr(descriptor), "last_block": block.last_block,
                       "block_number": block.block_number, "raw_data": hex(block.raw_data),
                       "access": access(a)?}),
            ),
            SetRequest::WithDataBlock { invoke_id, block } => obj(
                "set-request-with-datablock",
                json!({"invoke_id": invoke_id.0, "last_block": block.last_block,
                       "block_number": block.block_number, "raw_data": hex(block.raw_data)}),
            ),
            SetRequest::WithList { invoke_id, descriptors, values } => {
                let d = list(descriptors)?;
                let v = list(values)?;
                if d.len() != v.len() {
                    return Err(format!("{} descriptors, {} values", d.len(), v.len()));
                }
                let items = d
                    .iter()
                    .zip(v.iter())
                    .map(|(d, v)| Ok(json!([attr(&d.descriptor), access(&d.access)?, data_json(v)?])))
                    .collect::<R<Vec<_>>>()?;
                obj("set-request-with-list", json!({"invoke_id": invoke_id.0, "items": items}))
            }
            SetRequest::WithListAndFirstDataBlock { invoke_id, descriptors, block } => obj(
                "set-request-with-list-and-first-datablock",
                json!({"invoke_id": invoke_id.0,
                       "items": list(descriptors)?.iter().map(sel_item).collect::<R<Vec<_>>>()?,
                       "last_block": block.last_block, "block_number": block.block_number,
                       "raw_data": hex(block.raw_data)}),
            ),
        },
        Apdu::SetResponse(s) => match s {
            SetResponse::Normal { invoke_id, result } => {
                obj("set-response-normal", json!({"invoke_id": invoke_id.0, "result": result.as_u8()}))
            }
            SetResponse::DataBlock { invoke_id, block_number } => {
                obj("set-response-datablock", json!({"invoke_id": invoke_id.0, "block_number": block_number}))
            }
            SetResponse::LastDataBlock { invoke_id, result, block_number } => obj(
                "set-response-last-datablock",
                json!({"invoke_id": invoke_id.0, "result": result.as_u8(), "block_number": block_number}),
            ),
            SetResponse::LastDataBlockWithList { invoke_id, results, block_number } => obj(
                "set-response-last-datablock-with-list",
                json!({"invoke_id": invoke_id.0,
                       "results": list(results)?.iter().map(|r| r.as_u8()).collect::<Vec<_>>(),
                       "block_number": block_number}),
            ),
            SetResponse::WithList { invoke_id, results } => obj(
                "set-response-with-list",
                json!({"invoke_id": invoke_id.0,
                       "results": list(results)?.iter().map(|r| r.as_u8()).collect::<Vec<_>>()}),
            ),
        },
        Apdu::ActionRequest(a) => match a {
            ActionRequest::Normal { invoke_id, descriptor, parameters } => obj(
                "action-request-normal",
                json!({"invoke_id": invoke_id.0, "method": method(descriptor),
                       "parameters": parameters.as_ref().map(data_json).transpose()?}),
            ),
            ActionRequest::NextPblock { invoke_id, block_number } => {
                obj("action-request-next-pblock", json!({"invoke_id": invoke_id.0, "block_number": block_number}))
            }
            ActionRequest::WithList { invoke_id, descriptors, parameters } => {
                let d = list(descriptors)?;
                let p = list(parameters)?;
                if d.len() != p.len() {
                    return Err(format!("{} methods, {} parameters", d.len(), p.len()));
                }
                let items = d
                    .iter()
                    .zip(p.iter())
                    .map(|(d, p)| Ok(json!([method(d), data_json(p)?])))
                    .collect::<R<Vec<_>>>()?;
                obj("action-request-with-list", json!({"invoke_id": invoke_id.0, "items": items}))
            }
            ActionRequest::WithFirstPblock { invoke_id, descriptor, block } => obj(
                "action-request-with-first-pblock",
                json!({"invoke_id": invoke_id.0, "method": method(descriptor), "last_block": block.last_block,
                       "block_number": block.block_number, "raw_data": hex(block.raw_data)}),
            ),
            ActionRequest::WithListAndFirstPblock { invoke_id, descriptors, block } => obj(
                "action-request-with-list-and-first-pblock",
                json!({"invoke_id": invoke_id.0, "methods": list(descriptors)?.iter().map(method).collect::<Vec<_>>(),
                       "last_block": block.last_block, "block_number": block.block_number,
                       "raw_data": hex(block.raw_data)}),
            ),
            ActionRequest::WithPblock { invoke_id, block } => obj(
                "action-request-with-pblock",
                json!({"invoke_id": invoke_id.0, "last_block": block.last_block,
                       "block_number": block.block_number, "raw_data": hex(block.raw_data)}),
            ),
        },
        Apdu::ActionResponse(a) => match a {
            ActionResponse::Normal { invoke_id, response } => obj(
                "action-response-normal",
                json!({"invoke_id": invoke_id.0, "result": response.result.as_u8(),
                       "return_data": response.return_parameters.as_ref().map(gdr).transpose()?}),
            ),
            ActionResponse::WithPblock { invoke_id, block } => obj(
                "action-response-with-pblock",
                json!({"invoke_id": invoke_id.0, "last_block": block.last_block,
                       "block_number": block.block_number, "raw_data": hex(block.raw_data)}),
            ),
            ActionResponse::WithList { invoke_id, responses } => obj(
                "action-response-with-list",
                json!({"invoke_id": invoke_id.0,
                       "results": list(responses)?.iter().map(action_item).collect::<R<Vec<_>>>()?}),
            ),
            ActionResponse::NextPblock { invoke_id, block_number } => {
                obj("action-response-next-pblock", json!({"invoke_id": invoke_id.0, "block_number": block_number}))
            }
        },
        Apdu::AccessRequest(a) => obj(
            "access-request",
            json!({"long_invoke_id": a.long_invoke_id.0, "date_time": a.date_time.0.map(|d| hex(&d.to_bytes())),
                   "specifications": access_specs(&a.specification)?, "data": datas(&a.data)?}),
        ),
        Apdu::AccessResponse(a) => obj(
            "access-response",
            json!({"long_invoke_id": a.long_invoke_id.0, "date_time": a.date_time.0.map(|d| hex(&d.to_bytes())),
                   "specifications": a.request_specification.as_ref().map(access_specs).transpose()?,
                   "data": datas(&a.data)?,
                   "results": list(&a.response_specification)?.iter().map(access_result).collect::<Vec<_>>()}),
        ),
        Apdu::DataNotification(n) => obj(
            "data-notification",
            json!({"long_invoke_id": n.long_invoke_id.0, "date_time": n.date_time.0.map(|d| hex(&d.to_bytes())),
                   "body": data_json(&n.body)?}),
        ),
        Apdu::EventNotification(e) => obj(
            "event-notification-request",
            json!({"attribute": attr(&e.descriptor), "value": data_json(&e.value)?,
                   "time": e.time.map(|d| hex(&d.to_bytes()))}),
        ),
        Apdu::ReadRequest(r) => obj(
            "read-request",
            json!({"items": list(&r.specification)?.iter().map(variable).collect::<R<Vec<_>>>()?}),
        ),
        Apdu::ReadResponse(r) => {
            let results = list(&r.results)?
                .iter()
                .map(|x| {
                    Ok(match *x {
                        ReadResult::Data(d) => json!({"kind": "read-result", "data": data_json(&d)?, "error": null,
                                                       "block_last": null, "block_number": null, "raw_data": null}),
                        ReadResult::Error(e) => json!({"kind": "read-result", "data": null, "error": e.as_u8(),
                                                        "block_last": null, "block_number": null, "raw_data": null}),
                        ReadResult::Block { last_block, block_number, raw_data } => {
                            json!({"kind": "read-result", "data": null, "error": null, "block_last": last_block,
                                   "block_number": block_number, "raw_data": hex(raw_data)})
                        }
                        // Read-Response choice [3] block-number: no pydlms field for it.
                        ReadResult::BlockNumber(n) => json!({"kind": "read-result-block-number", "block_number": n}),
                    })
                })
                .collect::<R<Vec<_>>>()?;
            obj("read-response", json!({"results": results}))
        }
        Apdu::WriteRequest(w) => obj(
            "write-request",
            json!({"items": list(&w.specification)?.iter().map(variable).collect::<R<Vec<_>>>()?,
                   "values": datas(&w.values)?}),
        ),
        Apdu::UnconfirmedWriteRequest(w) => obj(
            "unconfirmed-write-request",
            json!({"items": list(&w.specification)?.iter().map(variable).collect::<R<Vec<_>>>()?,
                   "values": datas(&w.values)?}),
        ),
        Apdu::WriteResponse(w) => {
            let results = list(&w.results)?
                .iter()
                .map(|r| match *r {
                    WriteResult::Success => json!(0),
                    WriteResult::Error(e) => json!(e.as_u8()),
                    WriteResult::BlockNumber(n) => json!({"block_number": n}),
                })
                .collect::<Vec<_>>();
            obj("write-response", json!({"results": results}))
        }
        Apdu::InformationReportRequest(i) => {
            let names = list(&i.specification)?
                .iter()
                .map(|v| match *v {
                    VariableAccess::VariableName(n) => Ok(json!(n)),
                    _ => Err("information-report with a non-name variable access".to_string()),
                })
                .collect::<R<Vec<_>>>()?;
            obj(
                "information-report-request",
                json!({"current_time": opt_hex(i.current_time), "names": names, "values": datas(&i.values)?}),
            )
        }
        Apdu::ExceptionResponse(e) => obj(
            "exception-response",
            json!({"state_error": e.state_error.as_u8(), "service_error": e.service_error.as_u8(),
                   "invocation_counter": e.expected_invocation_counter}),
        ),
        Apdu::ConfirmedServiceError(e) => obj(
            "confirmed-service-error",
            json!({"service": e.service, "error_type": e.error_class, "value": e.error_code}),
        ),
        Apdu::GeneralBlockTransfer(g) => obj(
            "gbt-block",
            json!({"last": g.control.last_block(), "streaming": g.control.streaming(), "window": g.control.window(),
                   "block_number": g.block_number, "block_number_ack": g.block_number_ack,
                   "data": hex(g.block_data)}),
        ),
        Apdu::Ciphered { protection, service, body } => obj(
            "ciphered",
            json!({"protection": format!("{protection:?}"), "service": service.as_u8(),
                   "security_control": body.security_control.0, "invocation_counter": body.invocation_counter}),
        ),
        Apdu::GeneralCiphered { protection, body } => obj(
            "general-ciphered",
            json!({"protection": format!("{protection:?}"), "system_title": hex(body.system_title),
                   "security_control": body.ciphered.security_control.0,
                   "invocation_counter": body.ciphered.invocation_counter}),
        ),
        Apdu::GeneralCiphering(_) => obj("general-ciphering", json!({})),
        Apdu::GeneralSigning(_) => obj("general-signing", json!({})),
        Apdu::Gateway { response, network_id, physical_device_address, payload } => obj(
            if *response { "gateway-response" } else { "gateway-request" },
            json!({"network_id": network_id, "physical_device_address": hex(physical_device_address),
                   "payload": hex(payload)}),
        ),
        _ => return Err("an Apdu variant this adapter does not map".into()),
    })
}

fn aarq(a: &Aarq<'_>) -> Value {
    let mut v = obj(
        "aarq",
        json!({"mechanism": a.mechanism_name.map(|m| m.arc()),
               "calling_authentication_value": opt_hex(a.calling_authentication_value),
               "calling_ap_title": opt_hex(a.calling_ap_title),
               "calling_ae_qualifier": opt_hex(a.calling_ae_qualifier),
               "user_information": ui(a.user_information)}),
    );
    if let Some(c) = a.application_context {
        v["application_context"] = json!(c.arc());
    }
    v
}

fn aare(a: &Aare<'_>) -> Value {
    let (source, diagnostic) = match a.diagnostic {
        Diagnostic::User(d) => (1, d.as_u8()),
        Diagnostic::Provider(d) => (2, d),
    };
    let mut v = obj(
        "aare",
        json!({"result": a.result.as_u8(), "diagnostic_source": source, "diagnostic": diagnostic,
               "responding_ap_title": opt_hex(a.responding_ap_title),
               "mechanism": a.mechanism_name.map(|m| m.arc()),
               "responding_authentication_value": opt_hex(a.responding_authentication_value),
               "user_information": ui(a.user_information)}),
    );
    if let Some(c) = a.application_context {
        v["application_context"] = json!(c.arc());
    }
    v
}

// --- security -------------------------------------------------------------------------------

fn key(hex_: &str) -> Result<Option<Key>, Fail> {
    if hex_.is_empty() {
        return Ok(None);
    }
    Ok(Some(Key::from_slice(&unhex(hex_)?)?))
}

/// A key ring holding `ek` for every encryption usage (global unicast, broadcast and
/// dedicated) and `ak` (or zeros) as the authentication key.
fn ring(ek: &str, ak: &str) -> Result<KeyRing, Fail> {
    let ek = key(ek)?.ok_or("no encryption key")?;
    let ak = key(ak)?;
    let mut keys = KeyRing::default();
    let zeros = Key::from_slice(&vec![0u8; ek.len()])?;
    keys.set(KeyUsage::GlobalUnicastEncryption, Key::from_slice(ek.expose())?);
    keys.set(KeyUsage::GlobalBroadcastEncryption, Key::from_slice(ek.expose())?);
    keys.set(KeyUsage::Dedicated, Key::from_slice(ek.expose())?);
    keys.set(KeyUsage::Authentication, ak.unwrap_or(zeros));
    Ok(keys)
}

/// The policy a ciphered frame claims. An oracle opens what it is handed; the crate's own
/// listener and server demand a policy instead (see the findings document).
fn claimed(control: dlms_cosem_rs::xdlms::SecurityControl, dedicated: bool) -> Result<SecurityPolicy, Fail> {
    Ok(SecurityPolicy {
        suite: SecuritySuite::from_id(control.suite())?,
        authenticated: control.authenticated(),
        encrypted: control.encrypted(),
        key_set: if dedicated {
            KeySet::Dedicated
        } else if control.broadcast_key() {
            KeySet::GlobalBroadcast
        } else {
            KeySet::GlobalUnicast
        },
    })
}

fn open(keys: KeyRing, title: &[u8], c: &CipheredService<'_>, dedicated: bool) -> Result<Vec<u8>, Fail> {
    let title = SystemTitle::from_slice(title)?;
    let policy = claimed(c.security_control, dedicated)?;
    let ak = keys.get(KeyUsage::Authentication).map(<[u8]>::to_vec).unwrap_or_default();
    let protector = Protector::new(RustCryptoProvider::new(keys), policy);
    let mut payload = c.payload.to_vec();
    let plain = protector.unprotect(c.security_control, &title, c.invocation_counter, &ak, &mut payload)?;
    Ok(plain.to_vec())
}

fn decipher(ek: &str, ak: &str, title: Option<&str>, raw: &[u8]) -> Result<Vec<u8>, Fail> {
    let keys = ring(ek, ak)?;
    match Apdu::from_bytes(raw)? {
        Apdu::Ciphered { protection, body, .. } => {
            let title = unhex(title.ok_or("glo-/ded- APDU needs the sender's system title")?)?;
            open(keys, &title, &body, protection == Protection::Dedicated)
        }
        Apdu::GeneralCiphered { protection, body } => {
            open(keys, body.system_title, &body.ciphered, protection == Protection::Dedicated)
        }
        Apdu::GeneralCiphering(_) | Apdu::GeneralSigning(_) => {
            Err(Fail::Unsupported("general-ciphering/general-signing: refused by the crate".into()))
        }
        other => Err(Fail::Reject(format!("not a ciphered APDU: {:?}", other.tag()))),
    }
}

fn op_decrypt(args: &[&str]) -> Result<Value, Fail> {
    let plain = decipher(arg(args, 0)?, arg(args, 1)?, Some(arg(args, 2)?), &unhex(arg(args, 3)?)?)?;
    Ok(json!({"plaintext": hex(&plain)}))
}

/// `push <hex> [<ek> [<ak>]]`: the crate's `NotificationListener` decodes the frame
/// (body and date-time come from it); the long-invoke-id, which the listener does not
/// return, comes from decoding the same plaintext as an `Apdu`.
fn op_push(args: &[&str]) -> Result<Value, Fail> {
    let raw = unhex(arg(args, 0)?)?;
    let ek = args.get(1).copied().unwrap_or("");
    let ak = args.get(2).copied().unwrap_or("");
    let first = Apdu::from_bytes(&raw)?;
    let (title, policy, plain) = match first {
        Apdu::DataNotification(_) => (SystemTitle::new([0; 8]), SecurityPolicy::NONE, raw.clone()),
        Apdu::GeneralCiphered { protection, body } => {
            if ek.is_empty() {
                return Err(Fail::Reject("ciphered push and no key".into()));
            }
            let plain = decipher(ek, ak, None, &raw)?;
            let policy = claimed(body.ciphered.security_control, protection == Protection::Dedicated)?;
            (SystemTitle::from_slice(body.system_title)?, policy, plain)
        }
        other => return Err(Fail::Reject(format!("not a push: {:?}", other.tag()))),
    };
    let keys = if ek.is_empty() { KeyRing::default() } else { ring(ek, ak)? };
    let mut listener = NotificationListener::new(
        RustCryptoProvider::new(KeyRing::default()),
        SingleMeterKeys::new(title, keys),
        policy,
    );
    let mut buf = vec![0u8; raw.len() + 64];
    let got = listener.handle(&raw, &mut buf)?;
    let long_invoke_id = match Apdu::from_bytes(&plain)? {
        Apdu::DataNotification(n) => n.long_invoke_id.0,
        other => return Err(Fail::Reject(format!("plaintext is not a data-notification: {:?}", other.tag()))),
    };
    Ok(json!({
        "long_invoke_id": long_invoke_id,
        "date_time": got.captured_at.map(|d| hex(&d.to_bytes())),
        "body": data_json(&got.body)?,
    }))
}
