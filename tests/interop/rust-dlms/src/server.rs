//! A dlms-cosem-rs `Server` on the TCP wrapper (port 4059), with a handful of objects:
//! Association LN, two Data, two Registers, a Clock and a Profile Generic.
//!
//! `server` serves no-security associations (any client SAP; the crate's server has no
//! per-SAP configuration). `server --ciphered` demands HLS-GMAC (mechanism 5) and
//! authenticated+encrypted suite-0 APDUs with the Gurux test keys.
//!
//! The objects and their encodings are this file's: the crate deliberately leaves the
//! object model, Association LN included, to the store.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use dlms_cosem_rs::acse::AuthMechanism;
use dlms_cosem_rs::axdr::DataBuf;
use dlms_cosem_rs::codec::{Encode, Writer};
use dlms_cosem_rs::cosem::{AttributeAccess, MethodAccess};
use dlms_cosem_rs::obis::Obis;
use dlms_cosem_rs::security::{KeyRing, RandomSource, RustCryptoProvider, SecurityPolicy, SecuritySuite, SystemTitle};
use dlms_cosem_rs::server::{ObjectStore, Server, ServerConfig, StoreResult};
use dlms_cosem_rs::transport::wrapper::{StreamReassembler, Wpdu};
use dlms_cosem_rs::xdlms::{DataAccessResult, SelectiveAccess};

pub const GUEK: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
pub const GAK: [u8; 16] = [
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
];
const TITLE: [u8; 8] = *b"RST\x00\x00\x00\x00\x01";

const ASSOCIATION: Obis = Obis::new(0, 0, 40, 0, 0, 255);
const DEVICE_ID: Obis = Obis::new(0, 0, 96, 1, 0, 255);
const LDN: Obis = Obis::new(0, 0, 42, 0, 0, 255);
const ENERGY: Obis = Obis::new(1, 0, 1, 8, 0, 255);
const POWER: Obis = Obis::new(1, 0, 1, 7, 0, 255);
const CLOCK: Obis = Obis::new(0, 0, 1, 0, 0, 255);
const PROFILE: Obis = Obis::new(1, 0, 99, 1, 0, 255);

/// (class, version, logical name, attribute count, method count).
const OBJECTS: &[(u16, u8, Obis, i8, i8)] = &[
    (15, 1, ASSOCIATION, 9, 4),
    (1, 0, DEVICE_ID, 2, 0),
    (1, 0, LDN, 2, 0),
    (3, 0, ENERGY, 3, 1),
    (3, 0, POWER, 3, 1),
    (8, 0, CLOCK, 9, 6),
    (7, 1, PROFILE, 8, 2),
];

const ROWS: u32 = 96;
/// 2024-05-01 00:00:00, deviation 0, status 0 (COSEM date-time, Blue Book 4.1.6.1).
fn stamp(minutes: u32) -> [u8; 12] {
    let (h, m) = ((minutes / 60) as u8, (minutes % 60) as u8);
    [0x07, 0xE8, 5, 1, 3, h, m, 0, 0, 0x00, 0x00, 0x00]
}

fn octets(b: &[u8]) -> DataBuf {
    DataBuf::OctetString(b.to_vec())
}

struct Meter {
    mechanism: AuthMechanism,
}

impl Meter {
    fn value(&self, class_id: u16, name: Obis, attribute: i8) -> Option<DataBuf> {
        use DataBuf as D;
        let ln = || octets(name.as_bytes());
        Some(match (class_id, name, attribute) {
            (_, _, 1) if OBJECTS.iter().any(|o| o.0 == class_id && o.2 == name) => ln(),
            (15, ASSOCIATION, 2) => D::Array(OBJECTS.iter().map(object_list_entry).collect()),
            // associated_partners_id: structure { client SAP, server SAP }
            (15, ASSOCIATION, 3) => D::Structure(vec![D::Integer(0x10), D::LongUnsigned(1)]),
            // application_context_name / authentication_mechanism_name as OBJECT
            // IDENTIFIER encodings in an octet-string (one of the two shapes the Blue Book
            // allows for class 15).
            (15, ASSOCIATION, 4) => octets(&[0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01]),
            (15, ASSOCIATION, 5) => D::Structure(vec![
                D::BitString { bits: 24, bytes: vec![0x00, 0x7E, 0x1F] },
                D::LongUnsigned(1024),
                D::LongUnsigned(1024),
                D::Unsigned(6),
                D::Integer(0),
                octets(&[]),
            ]),
            (15, ASSOCIATION, 6) => octets(&[0x60, 0x85, 0x74, 0x05, 0x08, 0x02, self.mechanism.arc()]),
            (15, ASSOCIATION, 8) => D::Enum(2), // associated
            (1, DEVICE_ID, 2) => D::VisibleString(b"RST0000000001".to_vec()),
            (1, LDN, 2) => octets(b"RST1000000000001"),
            (3, ENERGY, 2) => D::DoubleLongUnsigned(12_345_678),
            (3, ENERGY, 3) => D::Structure(vec![D::Integer(0), D::Enum(30)]),
            (3, POWER, 2) => D::LongUnsigned(1520),
            (3, POWER, 3) => D::Structure(vec![D::Integer(0), D::Enum(27)]),
            // Blue Book 4.5.1: time is an octet-string holding a COSEM date-time.
            (8, CLOCK, 2) => octets(&[0x07, 0xE8, 5, 1, 3, 12, 0, 0, 0, 0xFF, 0x88, 0x80]),
            (8, CLOCK, 3) => D::Long(-120),
            (8, CLOCK, 4) => D::Unsigned(0x80),
            (8, CLOCK, 5) => octets(&[0xFF, 0xFF, 3, 0xFE, 7, 2, 0, 0, 0, 0x80, 0, 0]),
            (8, CLOCK, 6) => octets(&[0xFF, 0xFF, 10, 0xFE, 7, 3, 0, 0, 0, 0x80, 0, 0]),
            (8, CLOCK, 7) => D::Integer(60),
            (8, CLOCK, 8) => D::Boolean(true),
            (8, CLOCK, 9) => D::Enum(1),
            (7, PROFILE, 2) => D::Array((0..ROWS).map(row).collect()),
            (7, PROFILE, 3) => D::Array(vec![
                capture_object(8, CLOCK, 2),
                capture_object(3, ENERGY, 2),
            ]),
            (7, PROFILE, 4) => D::DoubleLongUnsigned(900),
            (7, PROFILE, 5) => D::Enum(1),
            (7, PROFILE, 6) => capture_object(0, Obis::new(0, 0, 0, 0, 0, 0), 0),
            (7, PROFILE, 7) | (7, PROFILE, 8) => D::DoubleLongUnsigned(ROWS),
            _ => return None,
        })
    }
}

fn row(i: u32) -> DataBuf {
    DataBuf::Structure(vec![octets(&stamp(15 * i)), DataBuf::DoubleLongUnsigned(1000 + 7 * i)])
}

fn capture_object(class_id: u16, name: Obis, attribute: i8) -> DataBuf {
    DataBuf::Structure(vec![
        DataBuf::LongUnsigned(class_id),
        octets(name.as_bytes()),
        DataBuf::Integer(attribute),
        DataBuf::LongUnsigned(0),
    ])
}

/// object_list_element for Association LN version 1: access modes as enum (attributes,
/// 1 = read-only) and boolean (methods), access_selectors null-data.
fn object_list_entry(&(class_id, version, name, attributes, methods): &(u16, u8, Obis, i8, i8)) -> DataBuf {
    use DataBuf as D;
    let attrs = (1..=attributes)
        .map(|a| D::Structure(vec![D::Integer(a), D::Enum(1), D::Null]))
        .collect();
    let meths = (1..=methods).map(|m| D::Structure(vec![D::Integer(m), D::Boolean(false)])).collect();
    D::Structure(vec![
        D::LongUnsigned(class_id),
        D::Unsigned(version),
        octets(name.as_bytes()),
        D::Structure(vec![D::Array(attrs), D::Array(meths)]),
    ])
}

impl ObjectStore for Meter {
    fn get_attribute(
        &self,
        class_id: u16,
        logical_name: Obis,
        attribute_id: i8,
        selective_access: Option<SelectiveAccess<'_>>,
        w: &mut dyn Writer,
    ) -> StoreResult<()> {
        let value = self.value(class_id, logical_name, attribute_id).ok_or(DataAccessResult::ObjectUndefined)?;
        let value = match (selective_access, value) {
            (None, v) => v,
            // Selector 2 (entry descriptor) on the profile buffer; anything else refused.
            (Some(sa), DataBuf::Array(rows)) if sa.selector == 2 && (class_id, logical_name) == (7, PROFILE) => {
                let s = sa.parameters.as_structure().ok_or(DataAccessResult::TypeUnmatched)?;
                let n = |i| -> StoreResult<usize> {
                    s.get(i).ok().and_then(|d| d.as_u64()).map(|v| v as usize).ok_or(DataAccessResult::TypeUnmatched)
                };
                let (from, to) = (n(0)?, n(1)?);
                let to = if to == 0 { rows.len() } else { to.min(rows.len()) };
                if from == 0 || from > to + 1 {
                    return Err(DataAccessResult::TypeUnmatched);
                }
                DataBuf::Array(rows[from - 1..to].to_vec())
            }
            (Some(_), _) => return Err(DataAccessResult::ScopeOfAccessViolated),
        };
        value.encode(w).map_err(|_| DataAccessResult::OtherReason)
    }

    fn attribute_access(&self, class_id: u16, logical_name: Obis, _: i8) -> AttributeAccess {
        if OBJECTS.iter().any(|o| o.0 == class_id && o.2 == logical_name) {
            AttributeAccess::READ
        } else {
            AttributeAccess::empty()
        }
    }

    fn method_access(&self, _: u16, _: Obis, _: i8) -> MethodAccess {
        MethodAccess::empty()
    }
}

/// A counter, not a generator: loopback test server only.
struct Rng;

impl RandomSource for Rng {
    fn fill(&self, out: &mut [u8]) -> dlms_cosem_rs::codec::Result<()> {
        for (i, b) in out.iter_mut().enumerate() {
            *b = 0xB0u8.wrapping_add(i as u8);
        }
        Ok(())
    }
}

type Sim = Server<Meter, RustCryptoProvider<Rng>, 8192>;

pub fn main(args: &[String]) {
    let ciphered = args.iter().any(|a| a == "--ciphered");
    let port = args
        .iter()
        .position(|a| a == "--port")
        .and_then(|i| args.get(i + 1))
        .and_then(|p| p.parse().ok())
        .unwrap_or(4059u16);
    let mechanism = if ciphered { AuthMechanism::HighGmac } else { AuthMechanism::None };
    let mut server: Sim = Server::new(
        ServerConfig {
            system_title: Some(SystemTitle::new(TITLE)),
            mechanism,
            security: if ciphered {
                SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0)
            } else {
                SecurityPolicy::NONE
            },
            max_pdu_size: 1024,
            ..Default::default()
        },
        Meter { mechanism },
        RustCryptoProvider::with_rng(if ciphered { KeyRing::new(GUEK, GAK) } else { KeyRing::default() }, Rng),
    );
    let listener = TcpListener::bind(("0.0.0.0", port)).expect("bind");
    eprintln!("rust-dlms server listening on {port} ({})", if ciphered { "HLS-GMAC, suite 0" } else { "no security" });
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        if let Err(e) = serve(&mut server, &mut stream) {
            eprintln!("link closed: {e}");
        }
        server.reset();
    }
}

fn serve(server: &mut Sim, stream: &mut TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let reassembler = StreamReassembler::new(4096);
    let mut buffered = Vec::new();
    let mut chunk = [0u8; 2048];
    let mut out = vec![0u8; 4096];
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok(());
        }
        buffered.extend_from_slice(&chunk[..n]);
        while let Some((wpdu, used)) = reassembler.next_pdu(&buffered)? {
            eprintln!("<- {}", crate::hex(wpdu.apdu));
            let reply = match server.handle(wpdu.apdu, &mut out) {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("   server refused: {e}");
                    return Err(Box::new(e));
                }
            };
            eprintln!("-> {}", crate::hex(&out[..reply]));
            let mut framed = Vec::new();
            Wpdu::new(wpdu.header.destination, wpdu.header.source, &out[..reply])?.encode(&mut framed)?;
            stream.write_all(&framed)?;
            buffered.drain(..used);
        }
    }
}
