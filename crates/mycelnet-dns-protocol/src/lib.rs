use std::fmt::{Display, Formatter, Result};

pub trait DnsPacketData {
    fn from_bytes(data: &[u8]) -> Self;
    fn to_bytes(&self) -> Vec<u8>;
}

#[derive(Debug, Default)]
pub struct DnsRequest {
    pub header: DnsHeader,
    pub question: DnsQuestion,
}

impl DnsPacketData for DnsRequest {
    fn from_bytes(data: &[u8]) -> DnsRequest {
        DnsRequest {
            header: DnsHeader::from_bytes(&data[0..12]),
            question: DnsQuestion::from_bytes(&data[12..]),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.header.to_bytes());
        data.extend_from_slice(&self.question.to_bytes());
        data
    }
}

#[derive(Debug, Default)]
pub struct DnsResponse {
    pub header: DnsHeader,
    pub answer: DnsAnswer,
}

#[derive(Debug, Default)]
pub struct DnsHeader {
    /// A 16 bit identifier assigned by the program that generates any kind of query.
    pub id: u16,
    pub flags: DnsFlags,
    /// An unsigned 16 bit integer specifying the number of entries in the question section.
    pub qdcount: u16,
    /// An unsigned 16 bit integer specifying the number of resource records in the answer section.
    pub ancount: u16,
    /// An unsigned 16 bit integer specifying the number of name server resource records in the authority records section.
    pub nscount: u16,
    /// An unsigned 16 bit integer specifying the number of resource records in the additional records section.
    pub arcount: u16,
}

impl DnsPacketData for DnsHeader {
    fn from_bytes(data: &[u8]) -> DnsHeader {
        // Output the binary representation of first 12 bytes
        // println!(
        //     "{:0>8b}{:0>8b} {:0>8b}{:0>8b}",
        //     data[0], data[1], data[2], data[3]
        // );
        // println!(
        //     "{:0>8b}{:0>8b} {:0>8b}{:0>8b}",
        //     data[4], data[5], data[6], data[7]
        // );
        // println!(
        //     "{:0>8b}{:0>8b} {:0>8b}{:0>8b}",
        //     data[8], data[9], data[10], data[11]
        // );

        // Output the binary representation of id (16 bits)
        // println!(
        //     "id: {:0>16b} : {}",
        //     ((data[0] as u16) << 8) | data[1] as u16,
        //     ((data[0] as u16) << 8) | data[1] as u16
        // );

        // Output the binary representation of flags (16 bits)
        // println!("flags: {:0>16b}", ((data[2] as u16) << 8) | data[3] as u16);

        // Output the binary representation of qdcount (16 bits)
        // println!(
        //     "qd: {:0>16b} : {}",
        //     ((data[4] as u16) << 8) | data[5] as u16,
        //     ((data[4] as u16) << 8) | data[5] as u16
        // );

        // Output the binary representation of ancount (16 bits)
        // println!(
        //     "an: {:0>16b} : {}",
        //     ((data[6] as u16) << 8) | data[7] as u16,
        //     ((data[6] as u16) << 8) | data[7] as u16
        // );

        // Output the binary representation of nscount (16 bits)
        // println!(
        //     "ns: {:0>16b} : {}",
        //     ((data[8] as u16) << 8) | data[9] as u16,
        //     ((data[8] as u16) << 8) | data[9] as u16
        // );

        // Output the binary representation of arcount (16 bits)
        // println!(
        //     "ar: {:0>16b} : {}",
        //     ((data[10] as u16) << 8) | data[11] as u16,
        //     ((data[10] as u16) << 8) | data[11] as u16
        // );

        DnsHeader {
            id: ((data[0] as u16) << 8) | data[1] as u16,
            flags: DnsFlags::from_bytes(&data[2..4] as &[u8]),
            qdcount: ((data[4] as u16) << 8) | data[5] as u16,
            ancount: ((data[6] as u16) << 8) | data[7] as u16,
            nscount: ((data[8] as u16) << 8) | data[9] as u16,
            arcount: ((data[10] as u16) << 8) | data[11] as u16,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.push((self.id >> 8) as u8);
        data.push(self.id as u8);
        let flags = self.flags.to_bytes();
        data.push(flags[0]);
        data.push(flags[1]);
        data.push((self.qdcount >> 8) as u8);
        data.push(self.qdcount as u8);
        data.push((self.ancount >> 8) as u8);
        data.push(self.ancount as u8);
        data.push((self.nscount >> 8) as u8);
        data.push(self.nscount as u8);
        data.push((self.arcount >> 8) as u8);
        data.push(self.arcount as u8);
        data
    }
}

#[derive(Debug)]
pub struct DnsFlags {
    /// A one bit field that specifies whether this message is a query (0), or a response (1).
    pub qr: u8,
    /// A four bit field that specifies kind of query in this message.
    pub opcode: DnsOpcode,
    /// Authoritative Answer - this bit is valid in responses, and specifies that the responding name server is an authority for the domain name in question section.
    pub aa: u8,
    /// TrunCation - specifies that this message was truncated due to length greater than that permitted on the transmission channel.
    pub tc: u8,
    /// Recursion Desired - this bit may be set in a query and is copied into the response.
    pub rd: u8,
    /// Recursion Available - this be is set or cleared in a response, and denotes whether recursive query support is available in the name server.
    pub ra: u8,
    /// Reserved for future use. Must be zero in all queries and responses.
    pub z: u8,
    /// Authentic Data - this bit is only set in responses. When set, it signifies that the responding name server was an authority for the data in question section.
    pub ad: u8,
    /// Checking Disabled - this bit is only set in queries. When set, it signifies that the querier desires some form of checking in the answer.
    pub cd: u8,
    /// Response code - this 4 bit field is set as part of responses.
    pub rcode: DnsRcode,
}

impl Default for DnsFlags {
    fn default() -> DnsFlags {
        DnsFlags {
            qr: 0,
            opcode: DnsOpcode::Query,
            aa: 0,
            tc: 0,
            rd: 1,
            ra: 0,
            z: 0,
            ad: 0,
            cd: 0,
            rcode: DnsRcode::NoError,
        }
    }
}

impl DnsPacketData for DnsFlags {
    fn from_bytes(data: &[u8]) -> DnsFlags {
        // println!("{:0>8b}{:0>8b}", data[0], data[1]);
        // println!("{:0>8b}", data[0]);
        // println!("qr: {:0>8b}", data[0] >> 7);
        // println!("op: {:0>8b}", (data[0] >> 3) & 0b00001111);
        // println!("aa: {:0>8b}", (data[0] >> 2) & 0b00000001);
        // println!("tc: {:0>8b}", (data[0] >> 1) & 0b00000001);
        // println!("rd: {:0>8b}", data[0] & 0b00000001);
        // println!("{:0>8b}", data[1]);
        // println!("ra: {:0>8b}", data[1] >> 7);
        // println!(" z: {:0>8b}", (data[1] >> 6) & 0b00000001);
        // println!("ad: {:0>8b}", (data[1] >> 5) & 0b00000001);
        // println!("cd: {:0>8b}", (data[1] >> 4) & 0b00000001);
        // println!("rc: {:0>8b}", data[1] & 0b00001111);

        DnsFlags {
            qr: data[0] >> 7,
            opcode: DnsOpcode::from_u8((data[0] >> 3) & 0b00001111),
            aa: (data[0] >> 2) & 0b00000001,
            tc: (data[0] >> 1) & 0b00000001,
            rd: data[0] & 0b00000001,
            ra: data[1] >> 7,
            z: (data[1] >> 4) & 0b00000001,
            ad: (data[1] >> 3) & 0b00000001,
            cd: (data[1] >> 2) & 0b00000001,
            rcode: DnsRcode::from_u8(data[1] & 0b00001111),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut flags = [0; 2];
        flags[0] =
            (self.qr << 7) | (self.opcode.to_u8() << 3) | (self.aa << 2) | (self.tc << 1) | self.rd;
        flags[1] =
            (self.ra << 7) | (self.z << 4) | (self.ad << 3) | (self.cd << 2) | self.rcode.to_u8();
        flags.to_vec()
    }
}

#[derive(Debug, Default, PartialEq)]
pub enum DnsOpcode {
    #[default]
    /// A standard query (QUERY)
    Query,
    /// An inverse query (IQUERY)
    IQuery,
    /// A server status request (STATUS)
    Status,
    /// Reserved for future use
    Reserved,
    /// A request for a transfer of an entire zone (NOTIFY)
    Notify,
    /// Dynamic update request (UPDATE)
    Update,
    /// DNS Stateful Operations (DSO)
    DynamicStatefulOperations,
    /// Unassigned
    Unassigned,
}

impl DnsOpcode {
    pub fn from_u8(opcode: u8) -> DnsOpcode {
        match opcode {
            0 => DnsOpcode::Query,
            1 => DnsOpcode::IQuery,
            2 => DnsOpcode::Status,
            3 => DnsOpcode::Reserved,
            4 => DnsOpcode::Notify,
            5 => DnsOpcode::Update,
            6 => DnsOpcode::DynamicStatefulOperations,
            _ => DnsOpcode::Unassigned,
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            DnsOpcode::Query => 0,
            DnsOpcode::IQuery => 1,
            DnsOpcode::Status => 2,
            DnsOpcode::Reserved => 3,
            DnsOpcode::Notify => 4,
            DnsOpcode::Update => 5,
            DnsOpcode::DynamicStatefulOperations => 6,
            DnsOpcode::Unassigned => 7,
        }
    }
}

#[derive(Debug, Default, PartialEq)]
pub enum DnsRcode {
    #[default]
    /// No error condition
    NoError,
    /// Format error - The name server was unable to interpret the query.
    FormatError,
    /// Server failure - The name server was unable to process this query due to a problem with the name server.
    ServerFailure,
    /// Name Error - Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist.
    NameError,
    /// Not Implemented - The name server does not support the requested kind of query.
    NotImplemented,
    /// Refused - The name server refuses to perform the specified operation for policy reasons.
    Refused,
    /// YXDomain - Name Exists when it should not.
    YXDomain,
    /// YXRRSet - RR Set Exists when it should not.
    YXRRSet,
    /// NXRRSet - RR Set that should exist does not.
    NXRRSet,
    /// NotAuth - Server Not Authoritative for zone.
    NotAuth,
    /// NotZone - Name not contained in zone.
    NotZone,
    /// Bad OPT Version - TSIG Signature Failure
    BadOptVersion,
    /// Bad Signature - Key not recognized
    BadSignature,
    /// Bad Key - Signature out of time window
    BadKey,
    /// Bad Timestamp - Bad TKEY Mode
    BadTimestamp,
    /// Bad Mode - Duplicate key name
    BadMode,
    /// Bad Name - Algorithm not supported
    BadName,
    /// Bad Alg - Bad truncation
    BadAlg,
    /// Bad Truncation - Bad/missing Server Cookie
    BadTruncation,
    /// Unassigned
    Unassigned,
    /// Reserved
    Reserved,
}

impl DnsRcode {
    pub fn from_u8(rcode: u8) -> DnsRcode {
        // Per rfc6895 section 2.3 4 bits are used in the header
        let rcode = rcode & 0b00001111;

        match rcode {
            0 => DnsRcode::NoError,
            1 => DnsRcode::FormatError,
            2 => DnsRcode::ServerFailure,
            3 => DnsRcode::NameError,
            4 => DnsRcode::NotImplemented,
            5 => DnsRcode::Refused,
            6 => DnsRcode::YXDomain,
            7 => DnsRcode::YXRRSet,
            8 => DnsRcode::NXRRSet,
            9 => DnsRcode::NotAuth,
            10 => DnsRcode::NotZone,
            16 => DnsRcode::BadOptVersion,
            _ => DnsRcode::Unassigned,
        }
    }

    pub fn from_u16(rcode: u16) -> DnsRcode {
        // Per rfc6895 section 2.3 4 bits are used in the header and 8 bits are used in the OPT record
        let rcode = rcode & 0b0000111111111111;
        match rcode {
            0 => DnsRcode::NoError,
            1 => DnsRcode::FormatError,
            2 => DnsRcode::ServerFailure,
            3 => DnsRcode::NameError,
            4 => DnsRcode::NotImplemented,
            5 => DnsRcode::Refused,
            6 => DnsRcode::YXDomain,
            7 => DnsRcode::YXRRSet,
            8 => DnsRcode::NXRRSet,
            9 => DnsRcode::NotAuth,
            10 => DnsRcode::NotZone,
            11..=15 => DnsRcode::Unassigned,
            16 => DnsRcode::BadSignature,
            17 => DnsRcode::BadKey,
            18 => DnsRcode::BadTimestamp,
            19 => DnsRcode::BadMode,
            20 => DnsRcode::BadName,
            21 => DnsRcode::BadAlg,
            22 => DnsRcode::BadTruncation,
            23..=3840 => DnsRcode::Unassigned,
            3841..=4095 => DnsRcode::Reserved,
            4096..=65534 => DnsRcode::Unassigned,
            65535 => DnsRcode::Reserved,
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            DnsRcode::NoError => 0,
            DnsRcode::FormatError => 1,
            DnsRcode::ServerFailure => 2,
            DnsRcode::NameError => 3,
            DnsRcode::NotImplemented => 4,
            DnsRcode::Refused => 5,
            DnsRcode::YXDomain => 6,
            DnsRcode::YXRRSet => 7,
            DnsRcode::NXRRSet => 8,
            DnsRcode::NotAuth => 9,
            DnsRcode::NotZone => 10,
            DnsRcode::BadOptVersion => 16,
            _ => 0,
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            DnsRcode::NoError => 0,
            DnsRcode::FormatError => 1,
            DnsRcode::ServerFailure => 2,
            DnsRcode::NameError => 3,
            DnsRcode::NotImplemented => 4,
            DnsRcode::Refused => 5,
            DnsRcode::YXDomain => 6,
            DnsRcode::YXRRSet => 7,
            DnsRcode::NXRRSet => 8,
            DnsRcode::NotAuth => 9,
            DnsRcode::NotZone => 10,
            DnsRcode::BadSignature => 16,
            DnsRcode::BadKey => 17,
            DnsRcode::BadTimestamp => 18,
            DnsRcode::BadMode => 19,
            DnsRcode::BadName => 20,
            DnsRcode::BadAlg => 21,
            DnsRcode::BadTruncation => 22,
            _ => 0,
        }
    }
}

#[derive(Debug, Default)]
pub struct DnsQuestion {
    /// A domain name represented as a sequence of labels, where each label consists of a length octet followed by that number of octets.
    pub qname: DnsName,
    /// A two octet code which specifies the type of the query.
    pub qtype: DnsQType,
    /// A two octet code that specifies the class of the query.
    pub qclass: DnsClass,
    /// Raw bytes of the question
    pub raw: Vec<u8>,
}

impl DnsPacketData for DnsQuestion {
    fn from_bytes(data: &[u8]) -> DnsQuestion {
        let name = DnsName::from_bytes(data);

        let index = name.name.len();
        let qtype = ((data[index] as u16) << 8) | data[index + 1] as u16;
        let qclass = ((data[index + 2] as u16) << 8) | data[index + 3] as u16;

        DnsQuestion {
            qname: name,
            qtype: DnsQType::from_u16(qtype),
            qclass: DnsClass::from_u16(qclass),
            // qtype: ((data[index + 1] as u16) << 8) | data[index + 2] as u16,
            // qclass: ((data[index + 3] as u16) << 8) | data[index + 4] as u16,
            raw: data[..index + 4].to_vec(),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.qname.to_bytes());
        // data.push(0); // TODO: do we still need this?
        // data.push((self.qtype >> 8) as u8);
        data.extend(self.qtype.to_bytes());
        // data.push((self.qclass >> 8) as u8);
        data.extend(self.qclass.to_bytes());
        data
    }
}

#[derive(Debug)]
pub struct DnsAnswer {
    /// A domain name to which this resource record pertains.
    pub name: Vec<u8>,
    /// A two octet code which specifies the type of the query.
    pub rtype: DnsQType,
    /// A two octet code that specifies the class of the query.
    pub rclass: u16,
    /// A 32 bit unsigned integer that specifies the time interval (in seconds) that the resource record may be cached before it should be discarded.
    pub ttl: u32,
    /// An unsigned 16 bit integer that specifies the length in octets of the RDATA field.
    pub rdlength: u16,
    /// A variable length string of octets that describes the resource.
    pub rdata: Vec<u8>,
}

impl Default for DnsAnswer {
    fn default() -> DnsAnswer {
        DnsAnswer {
            name: Vec::new(),
            rtype: DnsQType::A,
            rclass: 0,
            ttl: 0,
            rdlength: 0,
            rdata: Vec::new(),
        }
    }
}

#[derive(Debug, Default)]
pub struct DnsName {
    pub name: Vec<u8>,
    pub labels: Vec<String>,
}

impl DnsName {
    pub fn count(&self) -> u8 {
        self.labels.len() as u8
    }
}

impl DnsPacketData for DnsName {
    fn from_bytes(data: &[u8]) -> DnsName {
        let mut name = DnsName::default();

        // Loop through bytes reading label length and then label then add to qname
        let mut index = 0;
        loop {
            let label_length = data[index];
            if label_length == 0 {
                name.name.push(0);
                break;
            }
            index += 1;
            let label = String::from_utf8(data[index..index + label_length as usize].to_vec())
                .unwrap_or_else(|_| "".to_string());
            name.labels.push(label);
            name.name
                .extend_from_slice(&data[index - 1..index + label_length as usize]);
            index += label_length as usize;
        }

        name
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.name);
        data.push(0);
        data
    }
}

impl Display for DnsName {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "{}", self.labels.join("."))
    }
}

#[derive(Debug, Default, PartialEq)]
pub enum DnsQType {
    #[default]
    A,
    NS,
    MD,
    MF,
    CNAME,
    SOA,
    MB,
    MG,
    MR,
    NULL,
    WKS,
    PTR,
    HINFO,
    MINFO,
    MX,
    TXT,
    RP,
    AFSDB,
    X25,
    ISDN,
    RT,
    NSAP,
    NsapPtr,
    SIG,
    KEY,
    PX,
    GPOS,
    AAAA,
    LOC,
    NXT,
    EID,
    NIMLOC,
    SRV,
    ATMA,
    NAPTR,
    KX,
    CERT,
    A6,
    DNAME,
    SINK,
    OPT,
    APL,
    DS,
    SSHFP,
    IPSECKEY,
    RRSIG,
    NSEC,
    DNSKEY,
    DHCID,
    NSEC3,
    NSEC3PARAM,
    TLSA,
    SMIMEA,
    HIP,
    NINFO,
    RKEY,
    TALINK,
    CDS,
    CDNSKEY,
    OPENPGPKEY,
    CSYNC,
    ZONEMD,
    SVCB,
    HTTPS,
    SPF,
    UINFO,
    UID,
    GID,
    UNSPEC,
    NID,
    L32,
    L64,
    LP,
    EUI48,
    EUI64,
    TKEY,
    TSIG,
    IXFR,
    AXFR,
    MAILB,
    MAILA,
    ALL,
    URI,
    CAA,
    AVC,
    DOA,
    AMTRELAY,
    TA,
    DLV,
    Unassigned,
}

impl DnsQType {
    pub fn from_u16(qtype: u16) -> DnsQType {
        match qtype {
            1 => DnsQType::A,
            2 => DnsQType::NS,
            3 => DnsQType::MD,
            4 => DnsQType::MF,
            5 => DnsQType::CNAME,
            6 => DnsQType::SOA,
            7 => DnsQType::MB,
            8 => DnsQType::MG,
            9 => DnsQType::MR,
            10 => DnsQType::NULL,
            11 => DnsQType::WKS,
            12 => DnsQType::PTR,
            13 => DnsQType::HINFO,
            14 => DnsQType::MINFO,
            15 => DnsQType::MX,
            16 => DnsQType::TXT,
            17 => DnsQType::RP,
            18 => DnsQType::AFSDB,
            19 => DnsQType::X25,
            20 => DnsQType::ISDN,
            21 => DnsQType::RT,
            22 => DnsQType::NSAP,
            23 => DnsQType::NsapPtr,
            24 => DnsQType::SIG,
            25 => DnsQType::KEY,
            26 => DnsQType::PX,
            27 => DnsQType::GPOS,
            28 => DnsQType::AAAA,
            29 => DnsQType::LOC,
            30 => DnsQType::NXT,
            31 => DnsQType::EID,
            32 => DnsQType::NIMLOC,
            33 => DnsQType::SRV,
            34 => DnsQType::ATMA,
            35 => DnsQType::NAPTR,
            36 => DnsQType::KX,
            37 => DnsQType::CERT,
            38 => DnsQType::A6,
            39 => DnsQType::DNAME,
            40 => DnsQType::SINK,
            41 => DnsQType::OPT,
            42 => DnsQType::APL,
            43 => DnsQType::DS,
            44 => DnsQType::SSHFP,
            45 => DnsQType::IPSECKEY,
            46 => DnsQType::RRSIG,
            47 => DnsQType::NSEC,
            48 => DnsQType::DNSKEY,
            49 => DnsQType::DHCID,
            50 => DnsQType::NSEC3,
            51 => DnsQType::NSEC3PARAM,
            52 => DnsQType::TLSA,
            53 => DnsQType::SMIMEA,
            55 => DnsQType::HIP,
            56 => DnsQType::NINFO,
            57 => DnsQType::RKEY,
            58 => DnsQType::TALINK,
            59 => DnsQType::CDS,
            60 => DnsQType::CDNSKEY,
            61 => DnsQType::OPENPGPKEY,
            62 => DnsQType::CSYNC,
            63 => DnsQType::ZONEMD,
            64 => DnsQType::SVCB,
            65 => DnsQType::HTTPS,
            99 => DnsQType::SPF,
            100 => DnsQType::UINFO,
            101 => DnsQType::UID,
            102 => DnsQType::GID,
            103 => DnsQType::UNSPEC,
            104 => DnsQType::NID,
            105 => DnsQType::L32,
            106 => DnsQType::L64,
            107 => DnsQType::LP,
            108 => DnsQType::EUI48,
            109 => DnsQType::EUI64,
            249 => DnsQType::TKEY,
            250 => DnsQType::TSIG,
            251 => DnsQType::IXFR,
            252 => DnsQType::AXFR,
            253 => DnsQType::MAILB,
            254 => DnsQType::MAILA,
            255 => DnsQType::ALL,
            256 => DnsQType::URI,
            257 => DnsQType::CAA,
            258 => DnsQType::AVC,
            259 => DnsQType::DOA,
            260 => DnsQType::AMTRELAY,
            32768 => DnsQType::TA,
            32769 => DnsQType::DLV,
            _ => DnsQType::Unassigned,
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            DnsQType::A => 1,
            DnsQType::NS => 2,
            DnsQType::MD => 3,
            DnsQType::MF => 4,
            DnsQType::CNAME => 5,
            DnsQType::SOA => 6,
            DnsQType::MB => 7,
            DnsQType::MG => 8,
            DnsQType::MR => 9,
            DnsQType::NULL => 10,
            DnsQType::WKS => 11,
            DnsQType::PTR => 12,
            DnsQType::HINFO => 13,
            DnsQType::MINFO => 14,
            DnsQType::MX => 15,
            DnsQType::TXT => 16,
            DnsQType::RP => 17,
            DnsQType::AFSDB => 18,
            DnsQType::X25 => 19,
            DnsQType::ISDN => 20,
            DnsQType::RT => 21,
            DnsQType::NSAP => 22,
            DnsQType::NsapPtr => 23,
            DnsQType::SIG => 24,
            DnsQType::KEY => 25,
            DnsQType::PX => 26,
            DnsQType::GPOS => 27,
            DnsQType::AAAA => 28,
            DnsQType::LOC => 29,
            DnsQType::NXT => 30,
            DnsQType::EID => 31,
            DnsQType::NIMLOC => 32,
            DnsQType::SRV => 33,
            DnsQType::ATMA => 34,
            DnsQType::NAPTR => 35,
            DnsQType::KX => 36,
            DnsQType::CERT => 37,
            DnsQType::A6 => 38,
            DnsQType::DNAME => 39,
            DnsQType::SINK => 40,
            DnsQType::OPT => 41,
            DnsQType::APL => 42,
            DnsQType::DS => 43,
            DnsQType::SSHFP => 44,
            DnsQType::IPSECKEY => 45,
            DnsQType::RRSIG => 46,
            DnsQType::NSEC => 47,
            DnsQType::DNSKEY => 48,
            DnsQType::DHCID => 49,
            DnsQType::NSEC3 => 50,
            DnsQType::NSEC3PARAM => 51,
            DnsQType::TLSA => 52,
            DnsQType::SMIMEA => 53,
            DnsQType::HIP => 55,
            DnsQType::NINFO => 56,
            DnsQType::RKEY => 57,
            DnsQType::TALINK => 58,
            DnsQType::CDS => 59,
            DnsQType::CDNSKEY => 60,
            DnsQType::OPENPGPKEY => 61,
            DnsQType::CSYNC => 62,
            DnsQType::ZONEMD => 63,
            DnsQType::SVCB => 64,
            DnsQType::HTTPS => 65,
            DnsQType::SPF => 99,
            DnsQType::UINFO => 100,
            DnsQType::UID => 101,
            DnsQType::GID => 102,
            DnsQType::UNSPEC => 103,
            DnsQType::NID => 104,
            DnsQType::L32 => 105,
            DnsQType::L64 => 106,
            DnsQType::LP => 107,
            DnsQType::EUI48 => 108,
            DnsQType::EUI64 => 109,
            DnsQType::TKEY => 249,
            DnsQType::TSIG => 250,
            DnsQType::IXFR => 251,
            DnsQType::AXFR => 252,
            DnsQType::MAILB => 253,
            DnsQType::MAILA => 254,
            DnsQType::ALL => 255,
            DnsQType::URI => 256,
            DnsQType::CAA => 257,
            DnsQType::AVC => 258,
            DnsQType::DOA => 259,
            DnsQType::AMTRELAY => 260,
            DnsQType::TA => 32768,
            DnsQType::DLV => 32769,
            DnsQType::Unassigned => 0,
        }
    }
}

impl DnsPacketData for DnsQType {
    fn from_bytes(data: &[u8]) -> DnsQType {
        let qtype = ((data[0] as u16) << 8) | data[1] as u16;
        DnsQType::from_u16(qtype)
    }

    fn to_bytes(&self) -> Vec<u8> {
        let qtype = self.to_u16();
        Vec::from([(qtype >> 8) as u8, qtype as u8])
    }
}

#[derive(Debug, Default, PartialEq)]
pub enum DnsClass {
    #[default]
    IN,
    CS,
    CH,
    HS,
    NONE,
    ANY,
    Unassigned,
    Reserved,
}

impl DnsClass {
    pub fn from_u16(rclass: u16) -> DnsClass {
        match rclass {
            1 => DnsClass::IN,
            2 => DnsClass::CS,
            3 => DnsClass::CH,
            4 => DnsClass::HS,
            254 => DnsClass::NONE,
            255 => DnsClass::ANY,
            0 => DnsClass::Reserved,
            5..=253 => DnsClass::Unassigned,
            65280..=65534 => DnsClass::Reserved,
            65535 => DnsClass::Reserved,
            _ => DnsClass::Unassigned,
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            DnsClass::IN => 1,
            DnsClass::CS => 2,
            DnsClass::CH => 3,
            DnsClass::HS => 4,
            DnsClass::NONE => 254,
            DnsClass::ANY => 255,
            DnsClass::Reserved => 0,
            DnsClass::Unassigned => 0,
        }
    }
}

impl DnsPacketData for DnsClass {
    fn from_bytes(data: &[u8]) -> DnsClass {
        let rclass = ((data[0] as u16) << 8) | data[1] as u16;
        DnsClass::from_u16(rclass)
    }

    fn to_bytes(&self) -> Vec<u8> {
        let rclass = self.to_u16();
        Vec::from([(rclass >> 8) as u8, rclass as u8])
    }
}

#[derive(Debug, Default)]
pub struct DnsResourceRecord {
    /// A domain name to which this resource record pertains.
    pub name: Vec<u8>,
    /// A two octet code which specifies the type of the query.
    pub rtype: DnsQType,
    /// A two octet code that specifies the class of the query.
    pub rclass: u16,
    /// A 32 bit unsigned integer that specifies the time interval (in seconds) that the resource record may be cached before it should be discarded.
    pub ttl: u32,
    /// An unsigned 16 bit integer that specifies the length in octets of the RDATA field.
    pub rdlength: u16,
    /// A variable length string of octets that describes the resource.
    pub rdata: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_request() {
        // Create a DNS request from the following byte array

        let data = vec![
            0x41, 0x46, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x6d,
            0x79, 0x63, 0x65, 0x6c, 0x6e, 0x65, 0x74, 0x04, 0x74, 0x65, 0x63, 0x68, 0x00, 0x00,
            0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c,
            0x00, 0x0a, 0x00, 0x08, 0x31, 0xb9, 0xb2, 0x38, 0x01, 0xba, 0x1a, 0xfe,
        ];

        let request = DnsRequest::from_bytes(&data);

        assert_eq!(request.header.id, 16710);
        assert_eq!(request.header.flags.qr, 0);
        assert_eq!(request.header.flags.opcode, DnsOpcode::Query);
        assert_eq!(request.header.flags.aa, 0);
        assert_eq!(request.header.flags.tc, 0);
        assert_eq!(request.header.flags.rd, 1);
        assert_eq!(request.header.flags.ra, 0);
        assert_eq!(request.header.flags.z, 0);
        assert_eq!(request.header.flags.ad, 0);
        assert_eq!(request.header.flags.cd, 0);
        assert_eq!(request.header.flags.rcode, DnsRcode::NoError);
        assert_eq!(request.header.qdcount, 1);
        assert_eq!(request.header.ancount, 0);
        assert_eq!(request.header.nscount, 0);
        assert_eq!(request.header.arcount, 1);
        assert_eq!(
            request.question.qname.name,
            vec![
                0x08, 0x6d, 0x79, 0x63, 0x65, 0x6c, 0x6e, 0x65, 0x74, 0x04, 0x74, 0x65, 0x63, 0x68,
                0x00,
            ]
        );
        assert_eq!(request.question.qname.labels.len(), 2);
        assert_eq!(
            request.question.qname.labels,
            vec!["mycelnet".to_string(), "tech".to_string()]
        );
        assert_eq!(request.question.qtype, DnsQType::A);
        assert_eq!(request.question.qclass, DnsClass::IN);
    }
}
