//! A dlms-cosem-rs `ClientSession` reading a meter over the TCP wrapper (phase 4).
//!
//! rust-dlms-oracle client HOST:PORT [--ciphered] [--sap N]
//!
//! Prints one JSON object: every step's outcome, values as data trees. Steps continue
//! after a failure where that makes sense, so one report shows everything that broke.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use dlms_cosem_rs::acse::AuthMechanism;
use dlms_cosem_rs::axdr::Data;
use dlms_cosem_rs::client::{AssociationStep, BlockCollector, ClientConfig, ClientSession, Response};
use dlms_cosem_rs::cosem::EntryDescriptor;
use dlms_cosem_rs::obis::Obis;
use dlms_cosem_rs::security::{KeyRing, RandomSource, RustCryptoProvider, SecurityPolicy, SecuritySuite, SystemTitle};
use dlms_cosem_rs::transport::wrapper::{StreamReassembler, Wpdu};
use dlms_cosem_rs::xdlms::{AttributeDescriptor, AttributeDescriptorWithSelection, MethodDescriptor, SelectiveAccess};
use serde_json::{Map, Value, json};

use crate::cosemrs::data_json;
use crate::server::{GAK, GUEK};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

struct Link {
    stream: TcpStream,
    reassembler: StreamReassembler,
    buffered: Vec<u8>,
    sap: u16,
}

impl Link {
    fn exchange(&mut self, apdu: &[u8]) -> Res<Vec<u8>> {
        let mut framed = Vec::new();
        Wpdu::new(self.sap, 1, apdu)?.encode(&mut framed)?;
        eprintln!("-> {}", crate::hex(apdu));
        self.stream.write_all(&framed)?;
        let mut chunk = [0u8; 2048];
        loop {
            if let Some((wpdu, used)) = self.reassembler.next_pdu(&self.buffered)? {
                let answer = wpdu.apdu.to_vec();
                self.buffered.drain(..used);
                eprintln!("<- {}", crate::hex(&answer));
                return Ok(answer);
            }
            let n = self.stream.read(&mut chunk)?;
            if n == 0 {
                return Err("the meter closed the connection".into());
            }
            self.buffered.extend_from_slice(&chunk[..n]);
        }
    }
}

use dlms_cosem_rs::codec::Encode;

struct Rng;

impl RandomSource for Rng {
    fn fill(&self, out: &mut [u8]) -> dlms_cosem_rs::codec::Result<()> {
        for (i, b) in out.iter_mut().enumerate() {
            *b = 0xA0u8.wrapping_add(i as u8);
        }
        Ok(())
    }
}

type Session = ClientSession<RustCryptoProvider<Rng>>;

/// GET one attribute, following block transfer; the value as a data tree.
fn get(s: &mut Session, link: &mut Link, d: AttributeDescriptor, access: Option<SelectiveAccess<'_>>) -> Res<Value> {
    let mut request = [0u8; 2048];
    let mut plain = vec![0u8; 16384];
    let n = s.get_request(d, access, &mut request)?;
    let answer = link.exchange(&request[..n])?;
    let mut response = s.handle_response(&answer, &mut plain)?;
    let mut storage = vec![0u8; 65536];
    let mut blocks = BlockCollector::new(&mut storage);
    let mut count = 0u32;
    loop {
        match response {
            Response::Data(v) => return Ok(data_json(&v)?),
            Response::DataError(e) => return Ok(json!({"error": e.as_u8()})),
            Response::Block { last, number, data } => {
                blocks.push(number, data)?;
                count += 1;
                if last {
                    let v = blocks.value()?;
                    let mut tree = data_json(&v)?;
                    tree["blocks"] = json!(count);
                    return Ok(tree);
                }
                let n = s.get_next_block_request(number, &mut request)?;
                let answer = link.exchange(&request[..n])?;
                response = s.handle_response(&answer, &mut plain)?;
            }
            other => return Err(format!("unexpected response {other:?}").into()),
        }
    }
}

fn key(class_id: u16, name: Obis, attribute: i8) -> String {
    let b = name.as_bytes();
    format!("{}.{}.{}.{}.{}.{}/{class_id}/{attribute}", b[0], b[1], b[2], b[3], b[4], b[5])
}

pub fn main(args: &[String]) {
    let report = match run(args) {
        Ok(r) => r,
        Err(e) => json!({"fatal": e.to_string()}),
    };
    println!("{report}");
}

fn run(args: &[String]) -> Res<Value> {
    let addr = args.iter().find(|a| !a.starts_with("--")).ok_or("HOST:PORT")?.clone();
    let ciphered = args.iter().any(|a| a == "--ciphered");
    let sap: u8 = args
        .iter()
        .position(|a| a == "--sap")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(if ciphered { 1 } else { 16 });
    let stream = TcpStream::connect(&addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut link = Link { stream, reassembler: StreamReassembler::new(65535), buffered: Vec::new(), sap: u16::from(sap) };
    let mut report = Map::new();

    let mut s: Session = ClientSession::new(
        ClientConfig {
            client_sap: sap,
            system_title: ciphered.then_some(SystemTitle::new(*b"RSTCLI01")),
            mechanism: if ciphered { AuthMechanism::HighGmac } else { AuthMechanism::None },
            security: if ciphered {
                SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0)
            } else {
                SecurityPolicy::NONE
            },
            max_pdu_size: 1024,
            invocation_counter: 0,
            ..Default::default()
        },
        RustCryptoProvider::with_rng(if ciphered { KeyRing::new(GUEK, GAK) } else { KeyRing::default() }, Rng),
    );

    // ---- associate
    let mut request = [0u8; 2048];
    let n = s.associate_request(&mut request)?;
    let answer = link.exchange(&request[..n])?;
    let step = match s.handle_associate_response(&answer)? {
        AssociationStep::HlsReplyRequired => {
            let n = s.hls_reply_request(&mut request)?;
            let answer = link.exchange(&request[..n])?;
            s.handle_hls_reply_response(&answer)?
        }
        other => other,
    };
    report.insert("associate".into(), json!(format!("{step:?}")));
    if step != AssociationStep::Established {
        return Ok(Value::Object(report));
    }
    if let Some(neg) = s.negotiated() {
        let c = neg.negotiated_conformance.to_bytes();
        report.insert(
            "negotiated".into(),
            json!({"max_pdu": neg.server_max_receive_pdu_size, "conformance": crate::hex(&c),
                   "dlms_version": neg.negotiated_dlms_version}),
        );
    }
    if let Some(t) = s.server_system_title() {
        report.insert("server_system_title".into(), json!(crate::hex(t.as_bytes())));
    }

    // ---- object list, then every listed attribute 1..=3 plus selected others
    let mut reads = Map::new();
    let assoc = AttributeDescriptor::new(15, Obis::new(0, 0, 40, 0, 0, 255), 2);
    let list = get(&mut s, &mut link, assoc, None);
    let mut objects = Vec::new();
    match &list {
        Ok(v) => {
            for entry in v["v"].as_array().into_iter().flatten() {
                let f = &entry["v"];
                let ln = crate::unhex(f[2]["v"].as_str().unwrap_or(""))?;
                if ln.len() == 6 {
                    objects.push((f[0]["v"].as_u64().unwrap_or(0) as u16, Obis::from_bytes(ln.try_into().unwrap())));
                }
            }
            report.insert("object_list".into(), json!(objects.iter().map(|(c, o)| key(*c, *o, 0)).collect::<Vec<_>>()));
        }
        Err(e) => {
            report.insert("object_list".into(), json!({"failed": e.to_string()}));
        }
    }
    for &(class_id, name) in &objects {
        for attribute in 1..=3i8 {
            if class_id == 15 && attribute == 2 {
                continue;
            }
            let v = get(&mut s, &mut link, AttributeDescriptor::new(class_id, name, attribute), None)
                .unwrap_or_else(|e| json!({"failed": e.to_string()}));
            reads.insert(key(class_id, name, attribute), v);
        }
    }
    report.insert("reads".into(), Value::Object(reads));

    // ---- three registers in one GET-with-list
    let regs = [Obis::new(1, 0, 1, 8, 0, 255), Obis::new(1, 0, 2, 8, 0, 255), Obis::new(1, 0, 1, 7, 0, 255)];
    let items: Vec<_> = regs
        .iter()
        .map(|o| AttributeDescriptorWithSelection { descriptor: AttributeDescriptor::new(3, *o, 2), access: None })
        .collect();
    let with_list = (|| -> Res<Value> {
        let n = s.get_request_with_list(&items, &mut request)?;
        let answer = link.exchange(&request[..n])?;
        let mut plain = vec![0u8; 4096];
        match s.handle_response(&answer, &mut plain)? {
            Response::DataList(results) => {
                let mut out = Vec::new();
                for r in results.iter() {
                    out.push(match r?.value() {
                        Ok(v) => data_json(&v)?,
                        Err(e) => json!({"error": e.as_u8()}),
                    });
                }
                Ok(Value::Array(out))
            }
            other => Err(format!("unexpected {other:?}").into()),
        }
    })()
    .unwrap_or_else(|e| json!({"failed": e.to_string()}));
    report.insert("get_with_list".into(), with_list);

    // ---- profile: the whole buffer (blocks), then entries 1..10 by selective access
    let profile = AttributeDescriptor::new(7, Obis::new(1, 0, 99, 1, 0, 255), 2);
    let whole = get(&mut s, &mut link, profile, None).unwrap_or_else(|e| json!({"failed": e.to_string()}));
    report.insert(
        "profile_all".into(),
        json!({"rows": whole["v"].as_array().map(Vec::len), "blocks": whole.get("blocks"),
               "first": whole["v"].get(0), "failed": whole.get("failed")}),
    );
    let mut params = [0u8; 64];
    let sel = EntryDescriptor::entries(1, 10).to_selective_access(&mut params)?;
    let some = get(&mut s, &mut link, profile, Some(sel)).unwrap_or_else(|e| json!({"failed": e.to_string()}));
    report.insert(
        "profile_entries_1_10".into(),
        json!({"rows": some["v"].as_array().map(Vec::len), "first": some["v"].get(0), "last": some["v"].get(9),
               "failed": some.get("failed"), "error": some.get("error")}),
    );

    // ---- ACTION: disconnect control remote_disconnect, then read its state back
    let breaker = Obis::new(0, 0, 96, 3, 10, 255);
    let action = (|| -> Res<Value> {
        let n = s.action_request(MethodDescriptor::new(70, breaker, 1), Some(Data::Integer(0)), &mut request)?;
        let answer = link.exchange(&request[..n])?;
        let mut plain = vec![0u8; 1024];
        Ok(json!(format!("{:?}", s.handle_response(&answer, &mut plain)?)))
    })()
    .unwrap_or_else(|e| json!({"failed": e.to_string()}));
    report.insert("action".into(), action);
    report.insert(
        "breaker_after".into(),
        get(&mut s, &mut link, AttributeDescriptor::new(70, breaker, 2), None)
            .unwrap_or_else(|e| json!({"failed": e.to_string()})),
    );

    // ---- release
    let release = (|| -> Res<Value> {
        let n = s.release_request(&mut request)?;
        let answer = link.exchange(&request[..n])?;
        let mut plain = vec![0u8; 1024];
        Ok(json!(format!("{:?}", s.handle_response(&answer, &mut plain)?)))
    })()
    .unwrap_or_else(|e| json!({"failed": e.to_string()}));
    report.insert("release".into(), release);
    Ok(Value::Object(report))
}
