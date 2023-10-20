use std::fmt::{Debug, Display, Formatter};

use anyhow::{anyhow, Context, Result};

pub trait DnsPacketData: Sized {
    fn from_bytes(data: &[u8], offset: usize) -> Result<Self>;
    fn to_bytes(&self) -> Result<Vec<u8>>;
}

#[derive(Debug, Default)]
pub struct DnsRequest {
    pub header: DnsHeader,
    pub question: DnsQuestion,
    pub additional: Option<Vec<DnsResourceRecord>>,
}

impl DnsPacketData for DnsRequest {
    fn from_bytes(data: &[u8], offset: usize) -> Result<DnsRequest> {
        let mut request = DnsRequest {
            header: DnsHeader::from_bytes(data, offset)
                .with_context(|| "Failed to parse DNS header".to_string())?,
            question: DnsQuestion::from_bytes(data, offset + 12).with_context(|| {
                format!("Failed to parse DNS question at offset {}", offset + 12)
            })?,
            additional: None,
        };

        // Parse additional records if they exist
        if request.header.arcount > 0 {
            let mut additional = Vec::new();
            let mut index = offset + 12 + request.question.qname.length() + 4;

            for _ in 0..request.header.arcount {
                let record = DnsResourceRecord::from_bytes(data, index).with_context(|| {
                    format!("Failed to parse DNS additional record at offset {}", index)
                })?;

                index += record.name.length() + 10 + record.rdlength as usize;
                additional.push(record);
            }

            request.additional = Some(additional);
        }

        Ok(request)
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut data = Vec::new();

        data.extend_from_slice(
            &self
                .header
                .to_bytes()
                .with_context(|| format!("Failed to serialize DNS header {:?}", self.header))?,
        );

        data.extend_from_slice(
            &self
                .question
                .to_bytes()
                .with_context(|| format!("Failed to serialize DNS question {:?}", self.question))?,
        );

        if let Some(additional) = &self.additional {
            for record in additional {
                data.extend_from_slice(&record.to_bytes().with_context(|| {
                    format!("Failed to serialize DNS additional record {:?}", record)
                })?);
            }
        }

        Ok(data)
    }
}

#[derive(Debug, Default)]
pub struct DnsResponse {
    pub header: DnsHeader,
    pub question: DnsQuestion,
    pub answers: Option<Vec<DnsResourceRecord>>,
}

impl DnsResponse {
    pub fn new() -> DnsResponse {
        DnsResponse {
            header: DnsHeader::default(),
            question: DnsQuestion::default(),
            answers: None,
        }
    }

    pub fn from_request(request: &DnsRequest) -> DnsResponse {
        let mut response = DnsResponse::new();

        response.header.id = request.header.id;
        response.header.flags.qr = 1;
        response.header.flags.rd = request.header.flags.rd;
        response.header.flags.ra = 1;
        response.header.qdcount = request.header.qdcount;
        response.header.ancount = 1;
        response.header.nscount = 0;
        response.header.arcount = 0;
        response.question = request.question.clone();
        response.answers = Some(vec![DnsResourceRecord {
            name: request.question.qname.clone(),
            rtype: request.question.qtype,
            rclass: request.question.qclass,
            ttl: 300,
            rdlength: 4,
            rdata: vec![127, 0, 0, 1],
        }]);

        response
    }
}

impl DnsPacketData for DnsResponse {
    fn from_bytes(data: &[u8], offset: usize) -> Result<DnsResponse> {
        let mut response = DnsResponse::new();

        response.header = DnsHeader::from_bytes(data, offset)
            .with_context(|| "Failed to parse DNS header".to_string())?;
        response.question = DnsQuestion::from_bytes(data, offset + 12)
            .with_context(|| format!("Failed to parse DNS question at offset {}", offset + 12))?;

        let mut index = offset + 12 + response.question.qname.length() + 4;
        for _ in 0..response.header.ancount {
            let record = DnsResourceRecord::from_bytes(data, index).with_context(|| {
                format!("Failed to parse DNS resource record at offset {}", index)
            })?;
            index += record.name.length() + 10 + record.rdlength as usize;
            if response.answers.is_none() {
                response.answers = Some(Vec::new());
            }
            response.answers.as_mut().unwrap().push(record);
        }

        Ok(response)
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut data = Vec::new();

        data.extend_from_slice(
            &self
                .header
                .to_bytes()
                .with_context(|| format!("Failed to serialize DNS header {:?}", self.header))?,
        );

        data.extend_from_slice(
            &self
                .question
                .to_bytes()
                .with_context(|| format!("Failed to serialize DNS question {:?}", self.question))?,
        );

        if let Some(answers) = &self.answers {
            for record in answers {
                data.extend_from_slice(&record.to_bytes().with_context(|| {
                    format!("Failed to serialize DNS resource record {:?}", record)
                })?);
            }
        }

        Ok(data)
    }
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
    fn from_bytes(data: &[u8], offset: usize) -> Result<DnsHeader> {
        let header = DnsHeader {
            id: ((data[offset] as u16) << 8) | data[offset + 1] as u16,
            flags: DnsFlags::from_bytes(data, 2)
                .with_context(|| "Failed to parse DNS flags".to_string())?,
            qdcount: ((data[offset + 4] as u16) << 8) | data[offset + 5] as u16,
            ancount: ((data[offset + 6] as u16) << 8) | data[offset + 7] as u16,
            nscount: ((data[offset + 8] as u16) << 8) | data[offset + 9] as u16,
            arcount: ((data[offset + 10] as u16) << 8) | data[offset + 11] as u16,
        };

        Ok(header)
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        data.push((self.id >> 8) as u8);
        data.push(self.id as u8);

        let flags = self
            .flags
            .to_bytes()
            .with_context(|| "Failed to serialize DNS flags".to_string())?;
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

        Ok(data)
    }
}

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
    fn from_bytes(data: &[u8], offset: usize) -> Result<DnsFlags> {
        let flags = DnsFlags {
            qr: data[offset] >> 7,
            opcode: DnsOpcode::from_u8((data[offset] >> 3) & 0b00001111),
            aa: (data[offset] >> 2) & 0b00000001,
            tc: (data[offset] >> 1) & 0b00000001,
            rd: data[offset] & 0b00000001,
            ra: data[offset + 1] >> 7,
            z: (data[offset + 1] >> 6) & 0b00000001,
            ad: (data[offset + 1] >> 5) & 0b00000001,
            cd: (data[offset + 1] >> 4) & 0b00000001,
            rcode: DnsRcode::from_u8(data[offset + 1] & 0b00001111),
        };

        Ok(flags)
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut flags = [0; 2];
        flags[0] =
            (self.qr << 7) | (self.opcode.to_u8() << 3) | (self.aa << 2) | (self.tc << 1) | self.rd;
        flags[1] =
            (self.ra << 7) | (self.z << 6) | (self.ad << 5) | (self.cd << 4) | self.rcode.to_u8();

        Ok(flags.to_vec())
    }
}

impl Debug for DnsFlags {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        // Output flags as binary
        let qr_result = writeln!(
            f,
            "{:0>4b} {:0>4b} {:0>4b} {:0>4b} = Response code: {:?}",
            self.qr << 3,
            0x0,
            0x0,
            0x0,
            self.qr >> 7
        );

        let opcode_result = writeln!(
            f,
            "{:0>4b} {:0>4b} {:0>4b} {:0>4b} = Opcode: {:?}",
            self.opcode.to_u8() >> 1,
            self.opcode.to_u8() << 3 & 0b1000,
            0x0,
            0x0,
            self.opcode
        );

        let aa_result = writeln!(
            f,
            "{:0>4b} {:0>4b} {:0>4b} {:0>4b} = Authoritative Answer: {}",
            0x0,
            self.aa << 2,
            0x0,
            0x0,
            self.aa
        );

        let tc_result = writeln!(
            f,
            "{:0>4b} {:0>4b} {:0>4b} {:0>4b} = TrunCation: {}",
            0x0,
            self.tc << 1,
            0x0,
            0x0,
            self.tc
        );

        let rd_result = writeln!(
            f,
            "{:0>4b} {:0>4b} {:0>4b} {:0>4b} = Recursion Desired: {}",
            0x0, self.rd, 0x0, 0x0, self.rd
        );

        let ra_result = writeln!(
            f,
            "{:0>4b} {:0>4b} {:0>4b} {:0>4b} = Recursion Available: {}",
            0x0,
            0x0,
            self.ra << 3,
            0x0,
            self.ra
        );

        let z_result = writeln!(
            f,
            "{:0>4b} {:0>4b} {:0>4b} {:0>4b} = Reserved: {}",
            0x0,
            0x0,
            self.z << 2,
            0x0,
            self.z
        );

        let ad_result = writeln!(
            f,
            "{:0>4b} {:0>4b} {:0>4b} {:0>4b} = Authentication Data: {}",
            0x0,
            0x0,
            self.ad << 1,
            0x0,
            self.ad
        );

        let cd_result = writeln!(
            f,
            "{:0>4b} {:0>4b} {:0>4b} {:0>4b} = Checking Disabled: {}",
            0x0, 0x0, self.cd, 0x0, self.cd
        );

        let rcode_result = writeln!(
            f,
            "{:0>4b} {:0>4b} {:0>4b} {:0>4b} = Response code: {:?}",
            0x0,
            0x0,
            0x0,
            self.rcode.to_u8(),
            self.rcode
        );

        qr_result
            .and(opcode_result)
            .and(aa_result)
            .and(tc_result)
            .and(rd_result)
            .and(ra_result)
            .and(z_result)
            .and(ad_result)
            .and(cd_result)
            .and(rcode_result)
    }
}

#[derive(Debug, Default, PartialEq, Clone, Copy)]
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

#[derive(Debug, Default, PartialEq, Clone, Copy)]
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

#[derive(Debug, Default, Clone)]
pub struct DnsQuestion {
    /// A domain name represented as a sequence of labels, where each label consists of a length octet followed by that number of octets.
    pub qname: DnsName,
    /// A two octet code which specifies the type of the query.
    pub qtype: DnsQType,
    /// A two octet code that specifies the class of the query.
    pub qclass: DnsClass,
}

impl DnsPacketData for DnsQuestion {
    fn from_bytes(data: &[u8], offset: usize) -> Result<DnsQuestion> {
        let name = DnsName::from_bytes(data, offset)
            .with_context(|| format!("Failed to parse DNS question name at offset {}", offset))?;

        let index = offset + name.length();
        let qtype = ((data[index] as u16) << 8) | data[index + 1] as u16;
        let qclass = ((data[index + 2] as u16) << 8) | data[index + 3] as u16;

        let question = DnsQuestion {
            qname: name,
            qtype: DnsQType::from_u16(qtype),
            qclass: DnsClass::from_u16(qclass),
        };

        Ok(question)
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut data = Vec::new();

        data.extend_from_slice(
            &self.qname.to_bytes().with_context(|| {
                format!("Failed to serialize DNS question name {:?}", self.qname)
            })?,
        );

        // data.push(0); // TODO: do we still need this?
        // data.push((self.qtype >> 8) as u8);
        data.extend(
            self.qtype.to_bytes().with_context(|| {
                format!("Failed to serialize DNS question type {:?}", self.qtype)
            })?,
        );

        // data.push((self.qclass >> 8) as u8);
        data.extend(self.qclass.to_bytes().with_context(|| {
            format!("Failed to serialize DNS question class {:?}", self.qclass)
        })?);

        Ok(data)
    }
}

#[derive(Debug)]
pub struct DnsResourceRecord {
    /// A domain name to which this resource record pertains.
    pub name: DnsName,
    /// A two octet code which specifies the type of the query.
    pub rtype: DnsQType,
    /// A two octet code that specifies the class of the query.
    pub rclass: DnsClass,
    /// A 32 bit unsigned integer that specifies the time interval (in seconds) that the resource record may be cached before it should be discarded.
    pub ttl: u32,
    /// An unsigned 16 bit integer that specifies the length in octets of the RDATA field.
    pub rdlength: u16,
    /// A variable length string of octets that describes the resource.
    pub rdata: Vec<u8>,
}

impl Default for DnsResourceRecord {
    fn default() -> DnsResourceRecord {
        DnsResourceRecord {
            name: DnsName::default(),
            rtype: DnsQType::A,
            rclass: DnsClass::IN,
            ttl: 300,
            rdlength: 0,
            rdata: Vec::new(),
        }
    }
}

impl DnsPacketData for DnsResourceRecord {
    fn from_bytes(data: &[u8], offset: usize) -> Result<DnsResourceRecord> {
        let name = DnsName::from_bytes(data, offset).with_context(|| {
            format!(
                "Failed to parse DNS resource record name at offset {}",
                offset
            )
        })?;

        let index = offset + name.length();
        let rtype = ((data[index] as u16) << 8) | data[index + 1] as u16;

        // If rtype is 41 then this is an OPT extension request not a standard resource record
        // We need to additional information to properly process the request
        if rtype == 41 {
            // TODO: parse OPT extension request
            let rr = DnsResourceRecord {
                name,
                rtype: DnsQType::from_u16(rtype),
                rclass: DnsClass::IN,
                ttl: 0,
                rdlength: data.len() as u16 - index as u16 - 2,
                rdata: data[index + 2..].to_vec(),
            };

            return Ok(rr);
        }

        let rclass = ((data[index + 2] as u16) << 8) | data[index + 3] as u16;
        let ttl = ((data[index + 4] as u32) << 24)
            | ((data[index + 5] as u32) << 16)
            | ((data[index + 6] as u32) << 8)
            | data[index + 7] as u32;
        let rdlength = ((data[index + 8] as u16) << 8) | data[index + 9] as u16;
        let rdata = data[index + 10..index + 10 + rdlength as usize].to_vec();

        let rr = DnsResourceRecord {
            name,
            rtype: DnsQType::from_u16(rtype),
            rclass: DnsClass::from_u16(rclass),
            ttl,
            rdlength,
            rdata,
        };

        Ok(rr)
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.name.to_bytes().with_context(|| {
            format!(
                "Failed to serialize DNS resource record name {:?}",
                self.name
            )
        })?);

        data.extend(self.rtype.to_bytes().with_context(|| {
            format!(
                "Failed to serialize DNS resource record type {:?}",
                self.rtype
            )
        })?);

        if self.rtype == DnsQType::OPT {
            data.extend_from_slice(&self.rdata);
        } else {
            data.extend(self.rclass.to_bytes().with_context(|| {
                format!(
                    "Failed to serialize DNS resource record class {:?}",
                    self.rclass
                )
            })?);
            data.push((self.ttl >> 24) as u8);
            data.push((self.ttl >> 16) as u8);
            data.push((self.ttl >> 8) as u8);
            data.push(self.ttl as u8);
            data.push((self.rdlength >> 8) as u8);
            data.push(self.rdlength as u8);
            data.extend_from_slice(&self.rdata);
        }

        Ok(data)
    }
}

#[derive(Debug, Default)]
pub struct DnsRDataCname {
    pub cname: DnsName,
}

#[derive(Debug, Default, Clone)]
pub struct DnsName {
    pub labels: Vec<String>,
    pub offset: u16,
    pub pointer: u16,
}

impl DnsName {
    pub fn count(&self) -> usize {
        self.labels.len()
    }

    pub fn length(&self) -> usize {
        // If pointer is set then return 2 bytes for pointer
        if self.pointer != 0 {
            return 2;
        }

        // Loop through labels and add length of each label
        let mut length = 0;
        for label in &self.labels {
            // Add 1 byte for label length
            length += label.len() + 1; // Add 1 byte for label length
        }

        length + 1 // Add 1 byte for null byte
    }
}

impl DnsPacketData for DnsName {
    fn from_bytes(data: &[u8], offset: usize) -> Result<DnsName> {
        let mut name = DnsName::default();

        // Loop through bytes reading label length and then label then add to qname
        let mut index = offset;

        loop {
            let label_length = data[index];

            // Check if label is null byte and break loop
            if label_length == 0 {
                break;
            }

            // Check if label is a pointer to another label
            if label_length & 0b11000000 == 0b11000000 {
                let pointer = ((label_length & 0b00111111) as u16) << 8 | data[index + 1] as u16;

                // Else reference start of data to get label from question section
                // Dirty hackery to get this to work
                let question = DnsQuestion::from_bytes(data, 12).with_context(|| {
                    format!("Failed to parse DNS question at offset {}", offset + 12)
                })?;

                // Check if pointer matches question section
                if question.qname.offset == pointer {
                    name.labels = question.qname.labels;
                    name.pointer = pointer;

                    return Ok(name);
                }

                // Pointer found byt no matching question section
                Err(anyhow!(
                    "Failed to locate name pointer reference at offset {}",
                    offset
                ))?;
            }

            let label_index = index + 1;
            let label_bytes = &data[label_index..label_index + label_length as usize];
            let label = String::from_utf8(label_bytes.to_vec()).unwrap_or_else(|_| "".to_string());

            // Add label to name
            name.labels.push(label.to_owned());
            name.offset = offset as u16;

            // Update index to end of label
            index = label_index + label_length as usize;
        }

        Ok(name)
    }

    /// Convert a domain name to bytes using the format specified in RFC 1035 section 4.1.4
    /// Use name compression if possible
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut data = Vec::<u8>::new();

        // Add pointer reference if label has already been added
        if self.pointer != 0 {
            data.push(0b11000000 | (self.pointer >> 8) as u8);
            data.push(self.pointer as u8);

            return Ok(data);
        }

        // Loop through labels and add to data
        for label in &self.labels {
            // Add label length and label to data
            data.push(label.len() as u8);
            data.extend_from_slice(label.as_bytes());
        }

        // Add null byte to end of name
        data.push(0);

        Ok(data)
    }
}

impl Display for DnsName {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", self.labels.join("."))
    }
}

#[derive(Debug, Default, PartialEq, Clone, Copy)]
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
    fn from_bytes(data: &[u8], offset: usize) -> Result<DnsQType> {
        let qtype = ((data[offset] as u16) << 8) | data[offset + 1] as u16;
        Ok(DnsQType::from_u16(qtype))
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        let qtype = self.to_u16();
        Ok(Vec::from([(qtype >> 8) as u8, qtype as u8]))
    }
}

#[derive(Debug, Default, PartialEq, Clone, Copy)]
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
    fn from_bytes(data: &[u8], offset: usize) -> Result<DnsClass> {
        let rclass = ((data[offset] as u16) << 8) | data[offset + 1] as u16;
        Ok(DnsClass::from_u16(rclass))
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        let rclass = self.to_u16();
        Ok(Vec::from([(rclass >> 8) as u8, rclass as u8]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_request() -> Result<()> {
        // Create a DNS request from the following byte array

        let data = vec![
            0x41, 0x46, // ID
            0x01, 0x20, // Flags
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x01, // ARCOUNT
            0x08, 0x6d, 0x79, 0x63, 0x65, 0x6c, 0x6e, 0x65, 0x74, 0x04, 0x74, 0x65, 0x63, 0x68,
            0x00, 0x00, 0x01, 0x00, 0x01, // QNAME
            0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00,
            0x08, 0x31, 0xb9, 0xb2, 0x38, 0x01, 0xba, 0x1a, 0xfe, // ARs
        ];

        let request = DnsRequest::from_bytes(&data, 0).with_context(|| {
            format!(
                "Failed to parse DNS request from bytes {:?} at offset {}",
                data, 0
            )
        })?;

        assert_eq!(request.header.id, 16710);
        assert_eq!(request.header.flags.qr, 0);
        assert_eq!(request.header.flags.opcode, DnsOpcode::Query);
        assert_eq!(request.header.flags.aa, 0);
        assert_eq!(request.header.flags.tc, 0);
        assert_eq!(request.header.flags.rd, 1);
        assert_eq!(request.header.flags.ra, 0);
        assert_eq!(request.header.flags.z, 0);
        assert_eq!(request.header.flags.ad, 1);
        assert_eq!(request.header.flags.cd, 0);
        assert_eq!(request.header.flags.rcode, DnsRcode::NoError);
        assert_eq!(request.header.qdcount, 1);
        assert_eq!(request.header.ancount, 0);
        assert_eq!(request.header.nscount, 0);
        assert_eq!(request.header.arcount, 1);
        assert_eq!(
            request.question.qname.labels,
            vec!["mycelnet".to_string(), "tech".to_string()]
        );
        assert_eq!(request.question.qtype, DnsQType::A);
        assert_eq!(request.question.qclass, DnsClass::IN);

        assert_eq!(
            data,
            request.to_bytes().with_context(|| {
                format!(
                    "Failed to serialize DNS request {:?} at offset {}",
                    request, 0
                )
            })?
        );

        Ok(())
    }

    #[test]
    fn decode_response() -> Result<()> {
        let data = vec![
            0x44, 0x6f, // ID
            0x81, 0x80, // Flags
            0x00, 0x01, // QDCOUNT
            0x00, 0x02, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x01, // ARCOUNT
            0x08, 0x6d, 0x79, 0x63, 0x65, 0x6c, 0x6e, 0x65, 0x74, 0x04, 0x74, 0x65, 0x63, 0x68,
            0x00, // QNAME
            0x00, 0x01, // QTYPE
            0x00, 0x01, // QCLASS
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x04, 0x68, 0x15,
            0x23, 0x92, // RRs
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x04, 0xac, 0x43,
            0xb0,
            0xb6, // RRs
                  //0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ARs
        ];

        let response = DnsResponse::from_bytes(&data, 0).with_context(|| {
            format!(
                "Failed to parse DNS response from bytes {:?} at offset {}",
                data, 0
            )
        })?;

        assert_eq!(response.header.id, 17519);
        assert_eq!(response.header.flags.qr, 1);
        assert_eq!(response.header.flags.opcode, DnsOpcode::Query);
        assert_eq!(response.header.flags.aa, 0);
        assert_eq!(response.header.flags.tc, 0);
        assert_eq!(response.header.flags.rd, 1);
        assert_eq!(response.header.flags.ra, 1);
        assert_eq!(response.header.flags.z, 0);
        assert_eq!(response.header.flags.ad, 0);
        assert_eq!(response.header.flags.cd, 0);
        assert_eq!(response.header.flags.rcode, DnsRcode::NoError);
        assert_eq!(response.header.qdcount, 1);
        assert_eq!(response.header.ancount, 2);
        assert_eq!(response.header.nscount, 0);
        assert_eq!(response.header.arcount, 1);
        assert_eq!(response.question.qtype, DnsQType::A);
        assert_eq!(response.question.qclass, DnsClass::IN);

        assert_eq!(
            response.question.qname.labels,
            vec!["mycelnet".to_string(), "tech".to_string()]
        );

        assert_eq!(
            response
                .to_bytes()
                .with_context(|| "Failed to serialize DNS response".to_string())?,
            data
        );

        Ok(())
    }

    #[test]
    fn decode_flags() -> Result<()> {
        let data = vec![0x81, 0x80];

        let flags = DnsFlags::from_bytes(&data, 0).with_context(|| {
            format!(
                "Failed to parse DNS flags from bytes {:?} at offset {}",
                data, 0
            )
        })?;

        println!("{:?}", flags);

        assert_eq!(flags.qr, 1);
        assert_eq!(flags.opcode, DnsOpcode::Query);
        assert_eq!(flags.aa, 0);
        assert_eq!(flags.tc, 0);
        assert_eq!(flags.rd, 1);
        assert_eq!(flags.ra, 1);
        assert_eq!(flags.z, 0);
        assert_eq!(flags.ad, 0);
        assert_eq!(flags.cd, 0);
        assert_eq!(flags.rcode, DnsRcode::NoError);

        Ok(())
    }

    #[test]
    fn decode_header() -> Result<()> {
        let data = vec![
            0x44, 0x6f, // ID
            0x81, 0x80, // Flags
            0x00, 0x01, // QDCOUNT
            0x00, 0x02, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x01, // ARCOUNT
        ];

        let header = DnsHeader::from_bytes(&data, 0).with_context(|| {
            format!(
                "Failed to parse DNS header from bytes {:?} at offset {}",
                data, 0
            )
        })?;

        assert_eq!(header.id, 17519);
        assert_eq!(header.flags.qr, 1);
        assert_eq!(header.flags.opcode, DnsOpcode::Query);
        assert_eq!(header.flags.aa, 0);
        assert_eq!(header.flags.tc, 0);
        assert_eq!(header.flags.rd, 1);
        assert_eq!(header.flags.ra, 1);
        assert_eq!(header.flags.z, 0);
        assert_eq!(header.flags.ad, 0);
        assert_eq!(header.flags.cd, 0);
        assert_eq!(header.flags.rcode, DnsRcode::NoError);
        assert_eq!(header.qdcount, 1);
        assert_eq!(header.ancount, 2);
        assert_eq!(header.nscount, 0);
        assert_eq!(header.arcount, 1);

        Ok(())
    }

    #[test]
    fn decode_question() -> Result<()> {
        let data = vec![
            0x08, 0x6d, 0x79, 0x63, 0x65, 0x6c, 0x6e, 0x65, 0x74, 0x04, 0x74, 0x65, 0x63, 0x68,
            0x00, // QNAME
            0x00, 0x01, // QTYPE
            0x00, 0x01, // QCLASS
        ];

        let question = DnsQuestion::from_bytes(&data, 0).with_context(|| {
            format!(
                "Failed to parse DNS question from bytes {:?} at offset {}",
                data, 0
            )
        })?;

        assert_eq!(
            question.qname.labels,
            vec!["mycelnet".to_string(), "tech".to_string()]
        );
        assert_eq!(question.qtype, DnsQType::A);
        assert_eq!(question.qclass, DnsClass::IN);

        assert_eq!(
            question
                .to_bytes()
                .with_context(|| "Failed to serialize DNS question".to_string())?,
            data
        );

        Ok(())
    }

    #[test]
    fn decode_qname() -> Result<()> {
        let data = [
            0x08, 0x6d, 0x79, 0x63, 0x65, 0x6c, 0x6e, 0x65, 0x74, 0x04, 0x74, 0x65, 0x63, 0x68,
            0x00, // mycelnet.tech
        ];

        let qname = DnsName::from_bytes(&data, 0).with_context(|| {
            format!(
                "Failed to parse DNS name from bytes {:?} at offset {}",
                data, 0
            )
        })?;

        assert_eq!(
            qname.labels,
            vec!["mycelnet".to_string(), "tech".to_string()]
        );

        assert_eq!(
            qname
                .to_bytes()
                .with_context(|| "Failed to serialize DNS name".to_string())?,
            data.to_vec()
        );

        Ok(())
    }
}
