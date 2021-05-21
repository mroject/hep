/*!
 # hep

 use HEP3 Network Protocol Specification

 HEP3 (Homer Encapsulation Protocol Version 3) transmits packets over UDP/TCP/SCTP connections.

 Supprot HEPv1 HEPv2 HEP v3.

 HEPv2 Just Support IPv4

 author: MROJECT(ZhangLianJun z0413@outlook.com)

## Examples

```
use hep::{Chunk,CapProtoType,parse_packet};
use std::net::UdpSocket;

fn main() -> std::io::Result<()> {

    let socket = UdpSocket::bind("169.254.165.11:9060").expect("couldn't bind to address");
    loop {
        let mut buffer = [0x0; 0xdbba0];
        let (number_of_bytes, src_addr) =
            socket.recv_from(&mut buffer).expect("Didn't receive data");
        let filled_buf = &mut buffer[..number_of_bytes];
        let data = hep::parse_packet(&filled_buf);
        
        match data {
            Ok(chunk) => {
                println!("Message length:{}", &chunk.packet_payload.len());
                if chunk.packet_payload.len() > 6 {
                    println!(
                        "Received Hep(sip) Message from IP:{}, CaptureId:{}\n{}",
                        src_addr, 
                        chunk.capture_agent_id, 
                        chunk.packet_payload
                    );
                } else {
                    println!(
                        "Received Hep(Keepalive) Message from IP:{}, CaptureId:{}.\n",
                        src_addr, 
                        chunk.capture_agent_id
                    );
                }
            }
            Err(_) => {
                println!(
                    "Received Hep Message from IP:{}\n ignore data.\r\n\r\n",
                    src_addr
                );
            }
        }
    }
}

```
*/
use byteorder::{ByteOrder, NetworkEndian};
use log::{debug, error, trace};
use std::net::{Ipv4Addr, Ipv6Addr};

/// CHUNK_PAYLOAD_START with HEPv3
/// 
/// 0..4 HEP Version
///
/// 4..6 Packet Size
const CHUNK_PAYLOAD_START: usize = 6;

/// Hep Version enum
#[derive(Debug, PartialEq)]
pub enum HepVersion {
    HepV1,
    HepV2,
    HepV3,
    Unknown,
}

/// match hep packet 0..4
/// 
/// convert to Version
/// 
/// [1, _, _, _] -> HepV1
/// 
/// [2, _, _, _] -> HepV2
/// 
/// [72, 69, 80, 51] -> HepV3
/// 
impl std::convert::From<&[u8]> for HepVersion {
    fn from(b: &[u8]) -> Self {
        match b {
            [1, _, _, _] => HepVersion::HepV1,
            [2, _, _, _] => HepVersion::HepV2,
            [72, 69, 80, 51] => HepVersion::HepV3,
            _ => HepVersion::Unknown,
        }
    }
}

/// Vendor Id enum
#[warn(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq)]
pub enum Vendor {
    Generic,
    FreeSwitch,
    Kamailio,
    OpenSips,
    Asterisk,
    Homer,
    SipXecs,
    YetiSwitch,
    Genesys,
}

/// Vendor id defined
impl std::convert::From<u16> for Vendor {
    fn from(b: u16) -> Self {
        match b {
            0 => Vendor::Generic,
            1 => Vendor::FreeSwitch,
            2 => Vendor::Kamailio,
            3 => Vendor::OpenSips,
            4 => Vendor::Asterisk,
            5 => Vendor::Homer,
            6 => Vendor::SipXecs,
            7 => Vendor::YetiSwitch,
            8 => Vendor::Genesys,
            _ => Vendor::Generic,
        }
    }
}

/// Hep Capture Protocol Type
///
/// Support list as below
///
/// but this project just suppport sip
///
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum CapProtoType {
    Reserved,
    Sip,
    Xmpp,
    Sdp,
    Rtp,
    Rtcp,
    Mgcp,
    Megaco,
    Mtp2,
    Mtp3,
    Iax,
    H3222,
    H321,
    M2Pa,
    MosFull,
    MosShort,
    SipJson,
    DnsJson,
    M3UaJson,
    Rtsp,
    Diameter,
    GsmMap,
}

/// Print Capture Protocol Type
impl std::fmt::Display for CapProtoType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use CapProtoType::*;
        match &self {
            Reserved => write!(f, "Reserved"),
            Sip => write!(f, "SIP"),
            Xmpp => write!(f, "XMPP"),
            Sdp => write!(f, "SDP"),
            Rtp => write!(f, "RTP"),
            Rtcp => write!(f, "RTCP"),
            Mgcp => write!(f, "MGCP"),
            Megaco => write!(f, "Megaco"),
            Mtp2 => write!(f, "MTP2"),
            Mtp3 => write!(f, "MTP3"),
            Iax => write!(f, "IAX"),
            H3222 => write!(f, "H322"),
            H321 => write!(f, "H321"),
            M2Pa => write!(f, "M2PA"),
            MosFull => write!(f, "MOS Full"),
            MosShort => write!(f, "MOS Short"),
            SipJson => write!(f, "SIP JSON"),
            DnsJson => write!(f, "DNS JSON"),
            M3UaJson => write!(f, "M3UA JSON"),
            Rtsp => write!(f, "RTSP"),
            Diameter => write!(f, "Diameter"),
            GsmMap => write!(f, "GSM map"),
        }
    }
}

/// match Capture id
///
/// Convert to Capture Protocol Type
impl std::convert::From<u8> for CapProtoType {
    fn from(b: u8) -> Self {
        match b {
            0 => CapProtoType::Reserved,
            1 => CapProtoType::Sip,
            2 => CapProtoType::Xmpp,
            3 => CapProtoType::Sdp,
            4 => CapProtoType::Rtp,
            5 => CapProtoType::Rtcp,
            6 => CapProtoType::Mgcp,
            7 => CapProtoType::Megaco,
            8 => CapProtoType::Mtp2,
            9 => CapProtoType::Mtp3,
            10 => CapProtoType::Iax,
            11 => CapProtoType::H3222,
            12 => CapProtoType::H321,
            13 => CapProtoType::M2Pa,
            34 => CapProtoType::MosFull,
            35 => CapProtoType::MosShort,
            50 => CapProtoType::SipJson,
            51 => CapProtoType::Reserved,
            52 => CapProtoType::Reserved,
            53 => CapProtoType::DnsJson,
            54 => CapProtoType::M3UaJson,
            55 => CapProtoType::Rtsp,
            56 => CapProtoType::Diameter,
            57 => CapProtoType::GsmMap,
            _ => CapProtoType::Reserved,
        }
    }
}

/// Chunk types with chunk vendor ID 0x0000 are called generic chunk types. The following
///
/// generic chunk types are defined:
/// 1 uint8 IP protocol family
///
/// 2 uint8 IP protocol ID
///
/// 3 inet4-addr IPv4 source address
///
/// 4 inet4-addr IPv4 destination address
///
/// 5 inet6-addr IPv6 source address
///
/// 6 inet6-addr IPv6 destination address
///
/// 7 uint16 protocol source port (UDP, TCP, SCTP)
///
/// 8 uint16 protocol destination port (UDP, TCP, SCTP)
///
/// 9 uint32 timestamp, seconds since 01/01/1970 (epoch)
///
/// 10 uint32 timestamp microseconds offset (added to timestamp)
///
/// 11 uint8 protocol type (SIP/H323/RTP/MGCP/M2UA)
///
/// 12 uint32 capture agent ID (202, 1201, 2033...)
///
/// 13 uint16 keep alive timer (sec)Capture protocol types (0x00b)
///
/// 14 octet-string authenticate key (plain text / TLS connection)
///
/// 15 octet-string captured packet payload
///
/// 16 octet-string captured compressed payload (gzip/inflate)
///
/// 17 octet-string Internal correlation id
///
/// 18 uint16 Vlan ID
///
/// 19 octet-string Group ID
///
/// 20 uint64 Source MAC
///
/// 21 uint64 Destination MAC
///
/// 22 uint16 Ethernet Type
///
/// 23 uint8 TCP Flag [SYN.PUSH...]
///
/// 24 uint8 IP TOS
/// ….. ….. …...
/// 31 Reserved
///
/// 32 uint16 MOS value
///
/// 33 uint16 R-Factor
///
/// 34 octet-string GEO Location
///
/// 35 uint32 Jitter
///
/// 36 octet-string Transaction type [call, registration]
///
/// 37 octet-string Payload JSON Keys
///
/// 38 octet-string Tags’ values
///
/// 39 uint16 Type of tag
#[derive(Debug, Clone, PartialEq)]
pub struct Chunk {
    pub ip_protocol_family: u8,              //1
    pub ip_protocol_id: u8,                  //2
    pub ipv4_src_address: Ipv4Addr,          //3
    pub ipv4_dst_address: Ipv4Addr,          //4
    pub ipv6_src_address: Ipv6Addr,          //5
    pub ipv6_dst_address: Ipv6Addr,          //6
    pub proto_src_port: u16,                 //7
    pub proto_dst_port: u16,                 //8
    pub timestamp_seconds: u32,              //9
    pub timestamp_micro_seconds_offset: u32, //10
    pub proto_type: CapProtoType,            //11
    pub capture_agent_id: u32,               //12
    pub keep_alive_timer: u16,               //13
    pub authenticate_key: String,            //14
    pub packet_payload: String,              //15
    pub compressed_payload: String,          //16
    pub internal_correlation_id: String,     //17
    pub vlan_id: u16,                        //18
    pub group_id: String,                    //19
    pub src_mac: u64,                        //20
    pub dst_mac: u64,                        //21
    pub ethernet_type: u16,                  //22
    pub tcp_flag: u8,                        //23
    pub ip_tos: u8,                          //24
    pub mos_value: u16,                      //32
    pub rfactor: u16,                        //33
    pub geo_location: String,                //34
    pub jitter: u32,                         //35
    pub translation_type: String,            //36
    pub payload_json_keys: String,           //37
    pub tags_values: String,                 //38
    pub type_of_tag: String,                 //39
}

impl Chunk {
    pub fn new() -> Chunk {
        Chunk {
            ip_protocol_family: 0,
            ip_protocol_id: 0,
            ipv4_src_address: Ipv4Addr::new(0, 0, 0, 0),
            ipv4_dst_address: Ipv4Addr::new(0, 0, 0, 0),
            ipv6_src_address: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
            ipv6_dst_address: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
            proto_src_port: 5060,
            proto_dst_port: 9060,
            timestamp_seconds: 0,
            timestamp_micro_seconds_offset: 0,
            proto_type: CapProtoType::Sip,
            capture_agent_id: 0,
            keep_alive_timer: 1500,
            authenticate_key: String::new(),
            packet_payload: String::new(),
            compressed_payload: String::new(),
            internal_correlation_id: String::new(),
            vlan_id: 0,
            group_id: String::new(),
            src_mac: 0,
            dst_mac: 0,
            ethernet_type: 0,
            tcp_flag: 0,
            ip_tos: 0,
            mos_value: 0,
            rfactor: 0,
            geo_location: String::new(),
            jitter: 0,
            translation_type: String::new(),
            payload_json_keys: String::new(),
            tags_values: String::new(),
            type_of_tag: String::new(),
        }
    }
}

impl Chunk {
    /// set Chunk types of IpProtocolFamily
    /// ```
    /// use hep::Chunk;
    /// 
    /// let mut chunks = Chunk::new();
    /// chunks.set_ip_protocol_family(1);
    ///
    /// println!("{:?}",chunks);
    /// ```
    pub fn set_ip_protocol_family(&mut self, ip_protocol_family: u8) -> &mut Chunk {
        self.ip_protocol_family = ip_protocol_family;
        self
    }

    /// set Chunk types of IpProtocolId
    pub fn set_ip_protocol_id(&mut self, ip_protocol_id: u8) -> &mut Chunk {
        self.ip_protocol_id = ip_protocol_id;
        self
    }

    /// set Chunk types of Ipv4SrcAddress
    pub fn set_ipv4_src_address(&mut self, ipv4_src_address: Ipv4Addr) -> &mut Chunk {
        self.ipv4_src_address = ipv4_src_address;
        self
    }

    /// set Chunk types of Ipv4DstAddress
    pub fn set_ipv4_dst_address(&mut self, ipv4_dst_address: Ipv4Addr) -> &mut Chunk {
        self.ipv4_dst_address = ipv4_dst_address;
        self
    }

    /// set Chunk types of Ipv6SrcAddress
    pub fn set_ipv6_src_address(&mut self, ipv6_src_address: Ipv6Addr) -> &mut Chunk {
        self.ipv6_src_address = ipv6_src_address;
        self
    }

    /// set Chunk types of Ipv6DstAddress
    pub fn set_ipv6_dst_address(&mut self, ipv6_dst_address: Ipv6Addr) -> &mut Chunk {
        self.ipv6_dst_address = ipv6_dst_address;
        self
    }

    /// set Chunk types of ProtoSrcPort
    pub fn set_proto_src_port(&mut self, proto_src_port: u16) -> &mut Chunk {
        self.proto_src_port = proto_src_port;
        self
    }

    /// set Chunk types of ProtoDstPort
    pub fn set_proto_dst_port(&mut self, proto_dst_port: u16) -> &mut Chunk {
        self.proto_dst_port = proto_dst_port;
        self
    }

    /// set Chunk types of Timestamp_Seconds
    pub fn set_timestamp_seconds(&mut self, timestamp_seconds: u32) -> &mut Chunk {
        self.timestamp_seconds = timestamp_seconds;
        self
    }

    /// set Chunk types of TimestampMicroSecondsOffset
    pub fn set_timestamp_micro_seconds_offset(
        &mut self,
        timestamp_micro_seconds_offset: u32,
    ) -> &mut Chunk {
        self.timestamp_micro_seconds_offset = timestamp_micro_seconds_offset;
        self
    }

    /// set Chunk types of ProtoType
    pub fn set_proto_type(&mut self, proto_type: CapProtoType) -> &mut Chunk {
        self.proto_type = proto_type;
        self
    }

    /// set Chunk types of CaptureAgentId
    pub fn set_capture_agent_id(&mut self, capture_agent_id: u32) -> &mut Chunk {
        self.capture_agent_id = capture_agent_id;
        self
    }

    /// set Chunk types of KeepAliveTimer
    pub fn set_keep_alive_timer(&mut self, keep_alive_timer: u16) -> &mut Chunk {
        self.keep_alive_timer = keep_alive_timer;
        self
    }

    /// set Chunk types of AuthenticateKey
    pub fn set_authenticate_key(&mut self, authenticate_key: String) -> &mut Chunk {
        self.authenticate_key = authenticate_key;
        self
    }

    /// set Chunk types of PacketPayload
    ///
    /// Valid Data in PacketPayload
    pub fn set_packet_payload(&mut self, packet_payload: String) -> &mut Chunk {
        self.packet_payload = packet_payload;
        self
    }

    /// set Chunk types of CompressedPayload
    pub fn set_compressed_payload(&mut self, compressed_payload: String) -> &mut Chunk {
        self.compressed_payload = compressed_payload;
        self
    }

    /// set Chunk types of InternalCorrelationId
    pub fn set_set_internal_correlation_id(&mut self, internal_correlation_id: String) -> &mut Chunk {
        self.internal_correlation_id = internal_correlation_id;
        self
    }

    /// set Chunk types of VlanId
    pub fn set_vlan_id(&mut self, vlan_id: u16) -> &mut Chunk {
        self.vlan_id = vlan_id;
        self
    }

    /// set Chunk types of GroupId
    pub fn set_group_id(&mut self, group_id: String) -> &mut Chunk {
        self.group_id = group_id;
        self
    }

    /// set Chunk types of SrcMac
    pub fn set_src_mac(&mut self, src_mac: u64) -> &mut Chunk {
        self.src_mac = src_mac;
        self
    }

    /// set Chunk types of DstMac
    pub fn set_dst_mac(&mut self, dst_mac: u64) -> &mut Chunk {
        self.dst_mac = dst_mac;
        self
    }

    /// set Chunk types of EthernetType
    pub fn set_ethernet_type(&mut self, ethernet_type: u16) -> &mut Chunk {
        self.ethernet_type = ethernet_type;
        self
    }

    /// set Chunk types of TcpFlag
    pub fn set_tcp_flag(&mut self, tcp_flag: u8) -> &mut Chunk {
        self.tcp_flag = tcp_flag;
        self
    }

    /// set Chunk types of IpTos
    pub fn set_ip_tos(&mut self, ip_tos: u8) -> &mut Chunk {
        self.ip_tos = ip_tos;
        self
    }

    /// set Chunk types of MosValue
    pub fn set_mos_value(&mut self, mos_value: u16) -> &mut Chunk {
        self.mos_value = mos_value;
        self
    }

    /// set Chunk types of RFactor
    pub fn set_rfactor(&mut self, rfactor: u16) -> &mut Chunk {
        self.rfactor = rfactor;
        self
    }

    /// set Chunk types of GeoLocation
    pub fn set_geo_location(&mut self, geo_location: String) -> &mut Chunk {
        self.geo_location = geo_location;
        self
    }

    /// set Chunk types of Jitter
    pub fn set_jitter(&mut self, jitter: u32) -> &mut Chunk {
        self.jitter = jitter;
        self
    }

    /// set Chunk types of TranslationType
    pub fn set_translation_type(&mut self, translation_type: String) -> &mut Chunk {
        self.translation_type = translation_type;
        self
    }

    /// set Chunk types of PlayloadJsonKeys
    pub fn set_payload_json_keys(&mut self, payload_json_keys: String) -> &mut Chunk {
        self.payload_json_keys = payload_json_keys;
        self
    }

    /// set Chunk types of TagsValues
    pub fn set_tags_values(&mut self, tags_values: String) -> &mut Chunk {
        self.tags_values = tags_values;
        self
    }

    /// set Chunk types of TypeOfTag
    pub fn set_type_of_tag(&mut self, type_of_tag: String) -> &mut Chunk {
        self.type_of_tag = type_of_tag;
        self
    }
}

/// Entry Function
///
/// input params: hep packet data
///
/// return data:
///
/// 1. ();
///
/// 2. Ok(Chunk);// Chunk defined see pub Struct Chunk
///
pub fn parse_packet(packet: &[u8]) -> Result<Chunk, ()> {
    let version = HepVersion::from(&packet[..4]);

    match version {
        HepVersion::HepV1 => {
            debug!("HEP Version 1");
            parse_hep_v1(packet)
        }
        HepVersion::HepV2 => {
            debug!("HEP Version 2");
            parse_hep_v2(packet)
        }
        HepVersion::HepV3 => {
            debug!("HEP version 3");
            parse_hep_v3(packet)
        }
        _ => {
            error!("Not matched HEP/EEP.");
            parse_hep_v1(packet)
        }
    }
}

/// Hep v1
/// 
/// Hep v1 Header is exist
/// 
/// [0]: Hep Version, static value: 1
/// 
/// [1..]: Payload Data
///
/// return Ok([Chunk](./struct.Chunk.html)),
///
/// but PacketPayload is null
fn parse_hep_v1(_packet: &[u8]) -> Result<Chunk, ()> {
    trace!("Parse HEPV2/EEPV2 Start.");
    let mut chunks = Chunk::new();

    trace!("Ignore Chunk Data, hep v1 exist chunk.");

    chunks.set_packet_payload(
        String::from_utf8(_packet[1..].to_vec()).unwrap_or_else(|_| "".to_owned()),
    );

    trace!("Parse HEPV2/EEPV2 Completed.");
    
    if chunks.packet_payload.len() > 2 {
        Ok(chunks)
    } else {
        Err(())
    }
}

/// Hepv2 used
///
/// hep v2 header format:
/// 
/// [0]: hep 2, value is 2
/// 
/// [1]: header length, static value: 28
/// 
/// [2]: ip_protocol_family: static value: 2
/// 
/// [3]: transport type:17 is UDP, 06 is TCP, STCP Unknown
/// 
/// [4..6]: Src Port
/// 
/// [6..8]: Dst Port
/// 
/// [8..12]: Src IP
/// 
/// [12..16]: Dst IP
/// 
/// [16..20]: Unix Timestamp
/// 
/// [20..24]: Timestamp Micro Seconds Offset
/// 
/// [24..28]: Capture Agent Id
/// 
/// [28]: Meaningless
/// 
/// [28..]: Payload Data
/// 
fn parse_hep_v2(_packet: &[u8]) -> Result<Chunk, ()> {
    trace!("Parse HEPV2/EEPV2 Start.");

    let mut chunks = Chunk::new();
    trace!("Match Chunk Data.");

    let payload_start = _packet[1] as usize;

    chunks.set_ip_protocol_family(_packet[2]);

    chunks.set_translation_type(match _packet[3] {
        17 => String::from("UDP"),
        6 => String::from("TCP"),
        _ => String::from("Unknown")

    });

    chunks.set_proto_src_port(NetworkEndian::read_u16(&_packet[4..6]));

    chunks.set_proto_dst_port(NetworkEndian::read_u16(&_packet[6..8]));

    let src_ip_chunk = &_packet[8..12];
    chunks.set_ipv4_src_address(Ipv4Addr::new(
        src_ip_chunk[0],
        src_ip_chunk[1],
        src_ip_chunk[2],
        src_ip_chunk[3],
    ));

    let dst_ip_chunk = &_packet[12..16];
    chunks.set_ipv4_dst_address(Ipv4Addr::new(
        dst_ip_chunk[0],
        dst_ip_chunk[1],
        dst_ip_chunk[2],
        dst_ip_chunk[3],
    ));

    let tmso = &_packet[16..20];
    let tmso_clone = <&[u8]>::clone(&tmso);
    let tmso_clone:Vec<u8> =  tmso_clone.iter().rev().copied().collect();
    chunks.set_timestamp_seconds(NetworkEndian::read_u32(tmso_clone.as_slice()));

    let tm = &_packet[20..24];
    let tm_clone = <&[u8]>::clone(&tm);
    let tm_clone:Vec<u8> =  tm_clone.iter().rev().copied().collect();
    chunks.set_timestamp_micro_seconds_offset(NetworkEndian::read_u32(tm_clone.as_slice()));

    let agent_id_byte = &_packet[24..28];
    let agent_clone = <&[u8]>::clone(&agent_id_byte);
    let agent_clone: Vec<u8> = agent_clone.iter().rev().copied().collect();
    chunks.set_capture_agent_id(NetworkEndian::read_u32(agent_clone.as_slice()));

    trace!("Read Payload Data.");

    chunks.set_packet_payload(
        String::from_utf8(_packet[payload_start..].to_vec()).unwrap_or_else(|_| "".to_owned()),
    );

    trace!("Parse HEPV2/EEPV2 Completed.");

    if chunks.packet_payload.len() > 2 {
        Ok(chunks)
    } else {
        Err(())
    }
}


fn parse_hep_v3(packet: &[u8]) -> Result<Chunk, ()> {
    trace!("Parse HEPV3/EEPV3 Start.");
    let mut current_byte = CHUNK_PAYLOAD_START;
    let total_len = NetworkEndian::read_u16(&packet[4..6]) as usize;
    trace!("HEPV3/EEPV3 Packet Size: {}", &total_len);

    let mut chunks = Chunk::new();

    while current_byte < total_len {
        let chunk = &packet[current_byte as usize..];

        let vendor = Vendor::from(NetworkEndian::read_u16(&chunk[0..2]));
        trace!("Vendor Chunk Id: {:?}", &vendor);

        let chunk_type = NetworkEndian::read_u16(&chunk[2..4]);
        trace!("Chunk Type: {}", &chunk_type);

        let chunk_len = NetworkEndian::read_u16(&chunk[4..6]) as usize;
        trace!("Chunk Length: {}", &chunk_len);

        let chunk_payload = &chunk[CHUNK_PAYLOAD_START..chunk_len];

        match chunk_type {
            1 => chunks.set_ip_protocol_family(chunk_payload[0]),
            2 => chunks.set_ip_protocol_id(chunk_payload[0]),
            3 => chunks.set_ipv4_src_address(Ipv4Addr::new(
                chunk_payload[0],
                chunk_payload[1],
                chunk_payload[2],
                chunk_payload[3],
            )),
            4 => chunks.set_ipv4_dst_address(Ipv4Addr::new(
                chunk_payload[0],
                chunk_payload[1],
                chunk_payload[2],
                chunk_payload[3],
            )),
            5 => chunks
                .set_ipv6_src_address(Ipv6Addr::from(NetworkEndian::read_u128(&chunk_payload))),
            6 => chunks
                .set_ipv6_dst_address(Ipv6Addr::from(NetworkEndian::read_u128(&chunk_payload))),
            7 => chunks.set_proto_src_port(NetworkEndian::read_u16(&chunk_payload)),
            8 => chunks.set_proto_dst_port(NetworkEndian::read_u16(&chunk_payload)),
            9 => chunks.set_timestamp_seconds(NetworkEndian::read_u32(&chunk_payload)),
            10 => {
                chunks.set_timestamp_micro_seconds_offset(NetworkEndian::read_u32(&chunk_payload))
            }

            11 => chunks.set_proto_type(CapProtoType::from(chunk_payload[0])),
            12 => chunks.set_capture_agent_id(NetworkEndian::read_u32(&chunk_payload)),
            13 => chunks.set_keep_alive_timer(NetworkEndian::read_u16(&chunk_payload)),
            14 => chunks.set_authenticate_key(
                String::from_utf8(chunk_payload.to_vec()).unwrap_or_else(|_| "".to_owned()),
            ),
            15 => chunks.set_packet_payload(
                String::from_utf8(chunk_payload.to_vec()).unwrap_or_else(|_| "".to_owned()),
            ),
            16 => chunks.set_compressed_payload(
                String::from_utf8(chunk_payload.to_vec()).unwrap_or_else(|_| "".to_owned()),
            ),
            17 => chunks.set_set_internal_correlation_id(
                String::from_utf8(chunk_payload.to_vec()).unwrap_or_else(|_| "".to_owned()),
            ),
            18 => chunks.set_vlan_id(NetworkEndian::read_u16(&chunk_payload)),
            19 => {
                chunks.set_group_id(String::from_utf8(chunk_payload.to_vec()).unwrap_or_default())
            }
            20 => chunks.set_src_mac(NetworkEndian::read_u64(&chunk_payload)),
            21 => chunks.set_dst_mac(NetworkEndian::read_u64(&chunk_payload)),
            22 => chunks.set_ethernet_type(NetworkEndian::read_u16(&chunk_payload)),
            23 => chunks.set_tcp_flag(chunk_payload[0]),
            24 => chunks.set_ip_tos(chunk_payload[0]),
            32 => chunks.set_mos_value(NetworkEndian::read_u16(&chunk_payload)),
            33 => chunks.set_rfactor(NetworkEndian::read_u16(&chunk_payload)),
            34 => chunks
                .set_geo_location(String::from_utf8(chunk_payload.to_vec()).unwrap_or_default()),
            35 => chunks.set_jitter(NetworkEndian::read_u32(&chunk_payload)),
            36 => chunks.set_translation_type(
                String::from_utf8(chunk_payload.to_vec()).unwrap_or_default(),
            ),
            37 => chunks.set_payload_json_keys(
                String::from_utf8(chunk_payload.to_vec()).unwrap_or_default(),
            ),
            38 => chunks
                .set_tags_values(String::from_utf8(chunk_payload.to_vec()).unwrap_or_default()),
            39 => chunks
                .set_type_of_tag(String::from_utf8(chunk_payload.to_vec()).unwrap_or_default()),
            _ => &mut chunks,
        };

        current_byte += chunk_len;
        trace!("Chunk Data Length: {}", &current_byte);
    }
    trace!("Parse HEPV3/EEPV3 Completed.");

    if chunks.packet_payload.len() > 2 {
        Ok(chunks)
    } else {
        Err(())
    }
}


#[cfg(test)]
mod tests {

    #[test]
    fn hep() {
        assert_eq!(true, true)
    }

    #[test]
    fn parse_hep_version_1() {
        let packet = &[
            1, 82, 69, 71, 73, 83, 84, 69, 82, 32, 115, 105, 112,
            58, 49, 54, 57, 46, 50, 53, 52, 46, 49, 54, 53, 46, 49, 48, 48, 32, 83, 73, 80, 47, 50,
            46, 48, 13, 10, 86, 105, 97, 58, 32, 83, 73, 80, 47, 50, 46, 48, 47, 85, 68, 80, 32,
            49, 54, 57, 46, 50, 53, 52, 46, 49, 54, 53, 46, 49, 49, 58, 53, 48, 54, 48, 59, 98,
            114, 97, 110, 99, 104, 61, 122, 57, 104, 71, 52, 98, 75, 46, 51, 76, 106, 69, 126, 83,
            97, 106, 70, 59, 114, 112, 111, 114, 116, 13, 10, 70, 114, 111, 109, 58, 32, 60, 115,
            105, 112, 58, 49, 48, 48, 48, 64, 49, 54, 57, 46, 50, 53, 52, 46, 49, 54, 53, 46, 49,
            48, 48, 62, 59, 116, 97, 103, 61, 67, 88, 76, 112, 109, 106, 74, 120, 77, 13, 10, 84,
            111, 58, 32, 115, 105, 112, 58, 49, 48, 48, 48, 64, 49, 54, 57, 46, 50, 53, 52, 46, 49,
            54, 53, 46, 49, 48, 48, 13, 10, 67, 83, 101, 113, 58, 32, 50, 48, 32, 82, 69, 71, 73,
            83, 84, 69, 82, 13, 10, 67, 97, 108, 108, 45, 73, 68, 58, 32, 71, 119, 67, 103, 48, 85,
            100, 88, 49, 98, 13, 10, 77, 97, 120, 45, 70, 111, 114, 119, 97, 114, 100, 115, 58, 32,
            55, 48, 13, 10, 83, 117, 112, 112, 111, 114, 116, 101, 100, 58, 32, 111, 117, 116, 98,
            111, 117, 110, 100, 13, 10, 65, 99, 99, 101, 112, 116, 58, 32, 97, 112, 112, 108, 105,
            99, 97, 116, 105, 111, 110, 47, 115, 100, 112, 44, 32, 116, 101, 120, 116, 47, 112,
            108, 97, 105, 110, 44, 32, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 118,
            110, 100, 46, 103, 115, 109, 97, 46, 114, 99, 115, 45, 102, 116, 45, 104, 116, 116,
            112, 43, 120, 109, 108, 13, 10, 67, 111, 110, 116, 97, 99, 116, 58, 32, 60, 115, 105,
            112, 58, 49, 48, 48, 48, 64, 49, 54, 57, 46, 50, 53, 52, 46, 49, 54, 53, 46, 49, 49,
            62, 59, 43, 115, 105, 112, 46, 105, 110, 115, 116, 97, 110, 99, 101, 61, 34, 60, 117,
            114, 110, 58, 117, 117, 105, 100, 58, 54, 102, 98, 98, 102, 101, 48, 51, 45, 54, 99,
            54, 57, 45, 52, 101, 50, 99, 45, 57, 99, 51, 97, 45, 57, 52, 49, 54, 52, 57, 54, 56,
            99, 54, 97, 48, 62, 34, 13, 10, 69, 120, 112, 105, 114, 101, 115, 58, 32, 51, 54, 48,
            48, 13, 10, 85, 115, 101, 114, 45, 65, 103, 101, 110, 116, 58, 32, 76, 105, 110, 112,
            104, 111, 110, 101, 47, 51, 46, 56, 46, 49, 32, 40, 98, 101, 108, 108, 101, 45, 115,
            105, 112, 47, 49, 46, 52, 46, 48, 41, 13, 10, 13, 10,
        ];

        use super::*;

        let mut check = Chunk::new();
        check.set_packet_payload("REGISTER sip:169.254.165.100 SIP/2.0\r\nVia: SIP/2.0/UDP 169.254.165.11:5060;branch=z9hG4bK.3LjE~SajF;rport\r\nFrom: <sip:1000@169.254.165.100>;tag=CXLpmjJxM\r\nTo: sip:1000@169.254.165.100\r\nCSeq: 20 REGISTER\r\nCall-ID: GwCg0UdX1b\r\nMax-Forwards: 70\r\nSupported: outbound\r\nAccept: application/sdp, text/plain, application/vnd.gsma.rcs-ft-http+xml\r\nContact: <sip:1000@169.254.165.11>;+sip.instance=\"<urn:uuid:6fbbfe03-6c69-4e2c-9c3a-94164968c6a0>\"\r\nExpires: 3600\r\nUser-Agent: Linphone/3.8.1 (belle-sip/1.4.0)\r\n\r\n".parse().unwrap());

        assert_eq!(parse_hep_v1(packet).unwrap(), check);
    }

    #[test]
    fn parse_hep_version_2() {
        let packet = &[
            2, 28, 2, 17, 19, 196, 19, 196, 169, 254, 165, 11, 169, 254, 165, 100, 113, 223, 164,
            96, 51, 111, 3, 0, 255, 255, 0, 0, 82, 69, 71, 73, 83, 84, 69, 82, 32, 115, 105, 112,
            58, 49, 54, 57, 46, 50, 53, 52, 46, 49, 54, 53, 46, 49, 48, 48, 32, 83, 73, 80, 47, 50,
            46, 48, 13, 10, 86, 105, 97, 58, 32, 83, 73, 80, 47, 50, 46, 48, 47, 85, 68, 80, 32,
            49, 54, 57, 46, 50, 53, 52, 46, 49, 54, 53, 46, 49, 49, 58, 53, 48, 54, 48, 59, 98,
            114, 97, 110, 99, 104, 61, 122, 57, 104, 71, 52, 98, 75, 46, 51, 76, 106, 69, 126, 83,
            97, 106, 70, 59, 114, 112, 111, 114, 116, 13, 10, 70, 114, 111, 109, 58, 32, 60, 115,
            105, 112, 58, 49, 48, 48, 48, 64, 49, 54, 57, 46, 50, 53, 52, 46, 49, 54, 53, 46, 49,
            48, 48, 62, 59, 116, 97, 103, 61, 67, 88, 76, 112, 109, 106, 74, 120, 77, 13, 10, 84,
            111, 58, 32, 115, 105, 112, 58, 49, 48, 48, 48, 64, 49, 54, 57, 46, 50, 53, 52, 46, 49,
            54, 53, 46, 49, 48, 48, 13, 10, 67, 83, 101, 113, 58, 32, 50, 48, 32, 82, 69, 71, 73,
            83, 84, 69, 82, 13, 10, 67, 97, 108, 108, 45, 73, 68, 58, 32, 71, 119, 67, 103, 48, 85,
            100, 88, 49, 98, 13, 10, 77, 97, 120, 45, 70, 111, 114, 119, 97, 114, 100, 115, 58, 32,
            55, 48, 13, 10, 83, 117, 112, 112, 111, 114, 116, 101, 100, 58, 32, 111, 117, 116, 98,
            111, 117, 110, 100, 13, 10, 65, 99, 99, 101, 112, 116, 58, 32, 97, 112, 112, 108, 105,
            99, 97, 116, 105, 111, 110, 47, 115, 100, 112, 44, 32, 116, 101, 120, 116, 47, 112,
            108, 97, 105, 110, 44, 32, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 118,
            110, 100, 46, 103, 115, 109, 97, 46, 114, 99, 115, 45, 102, 116, 45, 104, 116, 116,
            112, 43, 120, 109, 108, 13, 10, 67, 111, 110, 116, 97, 99, 116, 58, 32, 60, 115, 105,
            112, 58, 49, 48, 48, 48, 64, 49, 54, 57, 46, 50, 53, 52, 46, 49, 54, 53, 46, 49, 49,
            62, 59, 43, 115, 105, 112, 46, 105, 110, 115, 116, 97, 110, 99, 101, 61, 34, 60, 117,
            114, 110, 58, 117, 117, 105, 100, 58, 54, 102, 98, 98, 102, 101, 48, 51, 45, 54, 99,
            54, 57, 45, 52, 101, 50, 99, 45, 57, 99, 51, 97, 45, 57, 52, 49, 54, 52, 57, 54, 56,
            99, 54, 97, 48, 62, 34, 13, 10, 69, 120, 112, 105, 114, 101, 115, 58, 32, 51, 54, 48,
            48, 13, 10, 85, 115, 101, 114, 45, 65, 103, 101, 110, 116, 58, 32, 76, 105, 110, 112,
            104, 111, 110, 101, 47, 51, 46, 56, 46, 49, 32, 40, 98, 101, 108, 108, 101, 45, 115,
            105, 112, 47, 49, 46, 52, 46, 48, 41, 13, 10, 13, 10,
        ];

        use super::*;

        let mut check = Chunk::new();
        check.set_ip_protocol_family(2)
             .set_proto_src_port(5060)
             .set_proto_dst_port(5060)
             .set_ipv4_src_address("169.254.165.11".parse().unwrap())
             .set_ipv4_dst_address("169.254.165.100".parse().unwrap())
             .set_capture_agent_id(65535)
             .set_timestamp_seconds("1621417841".parse().unwrap())
             .set_timestamp_micro_seconds_offset("225075".parse().unwrap())
             .set_translation_type(String::from("UDP"))
             .set_packet_payload("REGISTER sip:169.254.165.100 SIP/2.0\r\nVia: SIP/2.0/UDP 169.254.165.11:5060;branch=z9hG4bK.3LjE~SajF;rport\r\nFrom: <sip:1000@169.254.165.100>;tag=CXLpmjJxM\r\nTo: sip:1000@169.254.165.100\r\nCSeq: 20 REGISTER\r\nCall-ID: GwCg0UdX1b\r\nMax-Forwards: 70\r\nSupported: outbound\r\nAccept: application/sdp, text/plain, application/vnd.gsma.rcs-ft-http+xml\r\nContact: <sip:1000@169.254.165.11>;+sip.instance=\"<urn:uuid:6fbbfe03-6c69-4e2c-9c3a-94164968c6a0>\"\r\nExpires: 3600\r\nUser-Agent: Linphone/3.8.1 (belle-sip/1.4.0)\r\n\r\n".parse().unwrap());

        assert_eq!(parse_hep_v2(packet).unwrap(), check);
    }

    #[test]
    fn parse_hep_version_3() {
        let packet = &[
            72, 69, 80, 51, 2, 89, 0, 0, 0, 1, 0, 7, 2, 0, 0, 0, 2, 0, 7, 17, 0, 0, 0, 7, 0, 8, 19,
            196, 0, 0, 0, 8, 0, 8, 19, 196, 0, 0, 0, 9, 0, 10, 96, 163, 125, 225, 0, 0, 0, 10, 0,
            10, 0, 12, 37, 96, 0, 0, 0, 11, 0, 7, 1, 0, 0, 0, 12, 0, 10, 0, 0, 0, 100, 0, 0, 0, 3,
            0, 10, 169, 254, 165, 11, 0, 0, 0, 4, 0, 10, 169, 254, 165, 100, 0, 0, 0, 15, 1, 252,
            82, 69, 71, 73, 83, 84, 69, 82, 32, 115, 105, 112, 58, 49, 54, 57, 46, 50, 53, 52, 46,
            49, 54, 53, 46, 49, 48, 48, 32, 83, 73, 80, 47, 50, 46, 48, 13, 10, 86, 105, 97, 58,
            32, 83, 73, 80, 47, 50, 46, 48, 47, 85, 68, 80, 32, 49, 54, 57, 46, 50, 53, 52, 46, 49,
            54, 53, 46, 49, 49, 58, 53, 48, 54, 48, 59, 98, 114, 97, 110, 99, 104, 61, 122, 57,
            104, 71, 52, 98, 75, 46, 83, 122, 118, 80, 120, 103, 80, 76, 98, 59, 114, 112, 111,
            114, 116, 13, 10, 70, 114, 111, 109, 58, 32, 60, 115, 105, 112, 58, 49, 48, 48, 48, 64,
            49, 54, 57, 46, 50, 53, 52, 46, 49, 54, 53, 46, 49, 48, 48, 62, 59, 116, 97, 103, 61,
            116, 78, 76, 84, 55, 87, 69, 114, 80, 13, 10, 84, 111, 58, 32, 115, 105, 112, 58, 49,
            48, 48, 48, 64, 49, 54, 57, 46, 50, 53, 52, 46, 49, 54, 53, 46, 49, 48, 48, 13, 10, 67,
            83, 101, 113, 58, 32, 50, 48, 32, 82, 69, 71, 73, 83, 84, 69, 82, 13, 10, 67, 97, 108,
            108, 45, 73, 68, 58, 32, 101, 71, 66, 55, 97, 103, 98, 118, 69, 73, 13, 10, 77, 97,
            120, 45, 70, 111, 114, 119, 97, 114, 100, 115, 58, 32, 55, 48, 13, 10, 83, 117, 112,
            112, 111, 114, 116, 101, 100, 58, 32, 111, 117, 116, 98, 111, 117, 110, 100, 13, 10,
            65, 99, 99, 101, 112, 116, 58, 32, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110,
            47, 115, 100, 112, 44, 32, 116, 101, 120, 116, 47, 112, 108, 97, 105, 110, 44, 32, 97,
            112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 118, 110, 100, 46, 103, 115, 109,
            97, 46, 114, 99, 115, 45, 102, 116, 45, 104, 116, 116, 112, 43, 120, 109, 108, 13, 10,
            67, 111, 110, 116, 97, 99, 116, 58, 32, 60, 115, 105, 112, 58, 49, 48, 48, 48, 64, 49,
            54, 57, 46, 50, 53, 52, 46, 49, 54, 53, 46, 49, 49, 62, 59, 43, 115, 105, 112, 46, 105,
            110, 115, 116, 97, 110, 99, 101, 61, 34, 60, 117, 114, 110, 58, 117, 117, 105, 100, 58,
            54, 102, 98, 98, 102, 101, 48, 51, 45, 54, 99, 54, 57, 45, 52, 101, 50, 99, 45, 57, 99,
            51, 97, 45, 57, 52, 49, 54, 52, 57, 54, 56, 99, 54, 97, 48, 62, 34, 13, 10, 69, 120,
            112, 105, 114, 101, 115, 58, 32, 51, 54, 48, 48, 13, 10, 85, 115, 101, 114, 45, 65,
            103, 101, 110, 116, 58, 32, 76, 105, 110, 112, 104, 111, 110, 101, 47, 51, 46, 56, 46,
            49, 32, 40, 98, 101, 108, 108, 101, 45, 115, 105, 112, 47, 49, 46, 52, 46, 48, 41, 13,
            10, 13, 10,
        ];

        use super::*;

        let mut check = Chunk::new();
        check.set_ip_protocol_family(2)
             .set_ip_protocol_id(17)
             .set_proto_src_port(5060)
             .set_proto_dst_port(5060)
             .set_timestamp_seconds(1621327329)
             .set_timestamp_micro_seconds_offset(796000)
             .set_proto_type(CapProtoType::Sip)
             .set_capture_agent_id(100)
             .set_ipv4_src_address("169.254.165.11".parse().unwrap())
             .set_ipv4_dst_address("169.254.165.100".parse().unwrap())
             .set_packet_payload("REGISTER sip:169.254.165.100 SIP/2.0\r\nVia: SIP/2.0/UDP 169.254.165.11:5060;branch=z9hG4bK.SzvPxgPLb;rport\r\nFrom: <sip:1000@169.254.165.100>;tag=tNLT7WErP\r\nTo: sip:1000@169.254.165.100\r\nCSeq: 20 REGISTER\r\nCall-ID: eGB7agbvEI\r\nMax-Forwards: 70\r\nSupported: outbound\r\nAccept: application/sdp, text/plain, application/vnd.gsma.rcs-ft-http+xml\r\nContact: <sip:1000@169.254.165.11>;+sip.instance=\"<urn:uuid:6fbbfe03-6c69-4e2c-9c3a-94164968c6a0>\"\r\nExpires: 3600\r\nUser-Agent: Linphone/3.8.1 (belle-sip/1.4.0)\r\n\r\n".parse().unwrap());

        assert_eq!(parse_hep_v3(packet).unwrap(), check)
    }

    #[test]
    fn parse_packet_version_1() {
        let packet = &[
            1, 82, 69, 71, 73, 83, 84, 69, 82, 32, 115, 105, 112,
            58, 49, 54, 57, 46, 50, 53, 52, 46, 49, 54, 53, 46, 49, 48, 48, 32, 83, 73, 80, 47, 50,
            46, 48, 13, 10, 86, 105, 97, 58, 32, 83, 73, 80, 47, 50, 46, 48, 47, 85, 68, 80, 32,
            49, 54, 57, 46, 50, 53, 52, 46, 49, 54, 53, 46, 49, 49, 58, 53, 48, 54, 48, 59, 98,
            114, 97, 110, 99, 104, 61, 122, 57, 104, 71, 52, 98, 75, 46, 51, 76, 106, 69, 126, 83,
            97, 106, 70, 59, 114, 112, 111, 114, 116, 13, 10, 70, 114, 111, 109, 58, 32, 60, 115,
            105, 112, 58, 49, 48, 48, 48, 64, 49, 54, 57, 46, 50, 53, 52, 46, 49, 54, 53, 46, 49,
            48, 48, 62, 59, 116, 97, 103, 61, 67, 88, 76, 112, 109, 106, 74, 120, 77, 13, 10, 84,
            111, 58, 32, 115, 105, 112, 58, 49, 48, 48, 48, 64, 49, 54, 57, 46, 50, 53, 52, 46, 49,
            54, 53, 46, 49, 48, 48, 13, 10, 67, 83, 101, 113, 58, 32, 50, 48, 32, 82, 69, 71, 73,
            83, 84, 69, 82, 13, 10, 67, 97, 108, 108, 45, 73, 68, 58, 32, 71, 119, 67, 103, 48, 85,
            100, 88, 49, 98, 13, 10, 77, 97, 120, 45, 70, 111, 114, 119, 97, 114, 100, 115, 58, 32,
            55, 48, 13, 10, 83, 117, 112, 112, 111, 114, 116, 101, 100, 58, 32, 111, 117, 116, 98,
            111, 117, 110, 100, 13, 10, 65, 99, 99, 101, 112, 116, 58, 32, 97, 112, 112, 108, 105,
            99, 97, 116, 105, 111, 110, 47, 115, 100, 112, 44, 32, 116, 101, 120, 116, 47, 112,
            108, 97, 105, 110, 44, 32, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 118,
            110, 100, 46, 103, 115, 109, 97, 46, 114, 99, 115, 45, 102, 116, 45, 104, 116, 116,
            112, 43, 120, 109, 108, 13, 10, 67, 111, 110, 116, 97, 99, 116, 58, 32, 60, 115, 105,
            112, 58, 49, 48, 48, 48, 64, 49, 54, 57, 46, 50, 53, 52, 46, 49, 54, 53, 46, 49, 49,
            62, 59, 43, 115, 105, 112, 46, 105, 110, 115, 116, 97, 110, 99, 101, 61, 34, 60, 117,
            114, 110, 58, 117, 117, 105, 100, 58, 54, 102, 98, 98, 102, 101, 48, 51, 45, 54, 99,
            54, 57, 45, 52, 101, 50, 99, 45, 57, 99, 51, 97, 45, 57, 52, 49, 54, 52, 57, 54, 56,
            99, 54, 97, 48, 62, 34, 13, 10, 69, 120, 112, 105, 114, 101, 115, 58, 32, 51, 54, 48,
            48, 13, 10, 85, 115, 101, 114, 45, 65, 103, 101, 110, 116, 58, 32, 76, 105, 110, 112,
            104, 111, 110, 101, 47, 51, 46, 56, 46, 49, 32, 40, 98, 101, 108, 108, 101, 45, 115,
            105, 112, 47, 49, 46, 52, 46, 48, 41, 13, 10, 13, 10,
        ];

        use super::*;

        let mut check = Chunk::new();
        check.set_packet_payload("REGISTER sip:169.254.165.100 SIP/2.0\r\nVia: SIP/2.0/UDP 169.254.165.11:5060;branch=z9hG4bK.3LjE~SajF;rport\r\nFrom: <sip:1000@169.254.165.100>;tag=CXLpmjJxM\r\nTo: sip:1000@169.254.165.100\r\nCSeq: 20 REGISTER\r\nCall-ID: GwCg0UdX1b\r\nMax-Forwards: 70\r\nSupported: outbound\r\nAccept: application/sdp, text/plain, application/vnd.gsma.rcs-ft-http+xml\r\nContact: <sip:1000@169.254.165.11>;+sip.instance=\"<urn:uuid:6fbbfe03-6c69-4e2c-9c3a-94164968c6a0>\"\r\nExpires: 3600\r\nUser-Agent: Linphone/3.8.1 (belle-sip/1.4.0)\r\n\r\n".parse().unwrap());

        assert_eq!(parse_packet(packet).unwrap(), check);
    }

    #[test]
    fn parse_packet_version_2() {
        let packet = &[
            2, 28, 2, 17, 19, 196, 19, 196, 169, 254, 165, 11, 169, 254, 165, 100, 113, 223, 164,
            96, 51, 111, 3, 0, 255, 255, 0, 0, 82, 69, 71, 73, 83, 84, 69, 82, 32, 115, 105, 112,
            58, 49, 54, 57, 46, 50, 53, 52, 46, 49, 54, 53, 46, 49, 48, 48, 32, 83, 73, 80, 47, 50,
            46, 48, 13, 10, 86, 105, 97, 58, 32, 83, 73, 80, 47, 50, 46, 48, 47, 85, 68, 80, 32,
            49, 54, 57, 46, 50, 53, 52, 46, 49, 54, 53, 46, 49, 49, 58, 53, 48, 54, 48, 59, 98,
            114, 97, 110, 99, 104, 61, 122, 57, 104, 71, 52, 98, 75, 46, 51, 76, 106, 69, 126, 83,
            97, 106, 70, 59, 114, 112, 111, 114, 116, 13, 10, 70, 114, 111, 109, 58, 32, 60, 115,
            105, 112, 58, 49, 48, 48, 48, 64, 49, 54, 57, 46, 50, 53, 52, 46, 49, 54, 53, 46, 49,
            48, 48, 62, 59, 116, 97, 103, 61, 67, 88, 76, 112, 109, 106, 74, 120, 77, 13, 10, 84,
            111, 58, 32, 115, 105, 112, 58, 49, 48, 48, 48, 64, 49, 54, 57, 46, 50, 53, 52, 46, 49,
            54, 53, 46, 49, 48, 48, 13, 10, 67, 83, 101, 113, 58, 32, 50, 48, 32, 82, 69, 71, 73,
            83, 84, 69, 82, 13, 10, 67, 97, 108, 108, 45, 73, 68, 58, 32, 71, 119, 67, 103, 48, 85,
            100, 88, 49, 98, 13, 10, 77, 97, 120, 45, 70, 111, 114, 119, 97, 114, 100, 115, 58, 32,
            55, 48, 13, 10, 83, 117, 112, 112, 111, 114, 116, 101, 100, 58, 32, 111, 117, 116, 98,
            111, 117, 110, 100, 13, 10, 65, 99, 99, 101, 112, 116, 58, 32, 97, 112, 112, 108, 105,
            99, 97, 116, 105, 111, 110, 47, 115, 100, 112, 44, 32, 116, 101, 120, 116, 47, 112,
            108, 97, 105, 110, 44, 32, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 118,
            110, 100, 46, 103, 115, 109, 97, 46, 114, 99, 115, 45, 102, 116, 45, 104, 116, 116,
            112, 43, 120, 109, 108, 13, 10, 67, 111, 110, 116, 97, 99, 116, 58, 32, 60, 115, 105,
            112, 58, 49, 48, 48, 48, 64, 49, 54, 57, 46, 50, 53, 52, 46, 49, 54, 53, 46, 49, 49,
            62, 59, 43, 115, 105, 112, 46, 105, 110, 115, 116, 97, 110, 99, 101, 61, 34, 60, 117,
            114, 110, 58, 117, 117, 105, 100, 58, 54, 102, 98, 98, 102, 101, 48, 51, 45, 54, 99,
            54, 57, 45, 52, 101, 50, 99, 45, 57, 99, 51, 97, 45, 57, 52, 49, 54, 52, 57, 54, 56,
            99, 54, 97, 48, 62, 34, 13, 10, 69, 120, 112, 105, 114, 101, 115, 58, 32, 51, 54, 48,
            48, 13, 10, 85, 115, 101, 114, 45, 65, 103, 101, 110, 116, 58, 32, 76, 105, 110, 112,
            104, 111, 110, 101, 47, 51, 46, 56, 46, 49, 32, 40, 98, 101, 108, 108, 101, 45, 115,
            105, 112, 47, 49, 46, 52, 46, 48, 41, 13, 10, 13, 10,
        ];

        use super::*;

        let mut check = Chunk::new();
        check.set_ip_protocol_family(2)
             .set_proto_src_port(5060)
             .set_proto_dst_port(5060)
             .set_ipv4_src_address("169.254.165.11".parse().unwrap())
             .set_ipv4_dst_address("169.254.165.100".parse().unwrap())
             .set_capture_agent_id(65535)
             .set_timestamp_seconds("1621417841".parse().unwrap())
             .set_timestamp_micro_seconds_offset("225075".parse().unwrap())
             .set_translation_type(String::from("UDP"))
             .set_packet_payload("REGISTER sip:169.254.165.100 SIP/2.0\r\nVia: SIP/2.0/UDP 169.254.165.11:5060;branch=z9hG4bK.3LjE~SajF;rport\r\nFrom: <sip:1000@169.254.165.100>;tag=CXLpmjJxM\r\nTo: sip:1000@169.254.165.100\r\nCSeq: 20 REGISTER\r\nCall-ID: GwCg0UdX1b\r\nMax-Forwards: 70\r\nSupported: outbound\r\nAccept: application/sdp, text/plain, application/vnd.gsma.rcs-ft-http+xml\r\nContact: <sip:1000@169.254.165.11>;+sip.instance=\"<urn:uuid:6fbbfe03-6c69-4e2c-9c3a-94164968c6a0>\"\r\nExpires: 3600\r\nUser-Agent: Linphone/3.8.1 (belle-sip/1.4.0)\r\n\r\n".parse().unwrap());

        assert_eq!(parse_packet(packet).unwrap(), check);
    }

    #[test]
    fn parse_packet_version_3() {
        let packet = &[
            72, 69, 80, 51, 2, 89, 0, 0, 0, 1, 0, 7, 2, 0, 0, 0, 2, 0, 7, 17, 0, 0, 0, 7, 0, 8, 19,
            196, 0, 0, 0, 8, 0, 8, 19, 196, 0, 0, 0, 9, 0, 10, 96, 163, 125, 225, 0, 0, 0, 10, 0,
            10, 0, 12, 37, 96, 0, 0, 0, 11, 0, 7, 1, 0, 0, 0, 12, 0, 10, 0, 0, 0, 100, 0, 0, 0, 3,
            0, 10, 169, 254, 165, 11, 0, 0, 0, 4, 0, 10, 169, 254, 165, 100, 0, 0, 0, 15, 1, 252,
            82, 69, 71, 73, 83, 84, 69, 82, 32, 115, 105, 112, 58, 49, 54, 57, 46, 50, 53, 52, 46,
            49, 54, 53, 46, 49, 48, 48, 32, 83, 73, 80, 47, 50, 46, 48, 13, 10, 86, 105, 97, 58,
            32, 83, 73, 80, 47, 50, 46, 48, 47, 85, 68, 80, 32, 49, 54, 57, 46, 50, 53, 52, 46, 49,
            54, 53, 46, 49, 49, 58, 53, 48, 54, 48, 59, 98, 114, 97, 110, 99, 104, 61, 122, 57,
            104, 71, 52, 98, 75, 46, 83, 122, 118, 80, 120, 103, 80, 76, 98, 59, 114, 112, 111,
            114, 116, 13, 10, 70, 114, 111, 109, 58, 32, 60, 115, 105, 112, 58, 49, 48, 48, 48, 64,
            49, 54, 57, 46, 50, 53, 52, 46, 49, 54, 53, 46, 49, 48, 48, 62, 59, 116, 97, 103, 61,
            116, 78, 76, 84, 55, 87, 69, 114, 80, 13, 10, 84, 111, 58, 32, 115, 105, 112, 58, 49,
            48, 48, 48, 64, 49, 54, 57, 46, 50, 53, 52, 46, 49, 54, 53, 46, 49, 48, 48, 13, 10, 67,
            83, 101, 113, 58, 32, 50, 48, 32, 82, 69, 71, 73, 83, 84, 69, 82, 13, 10, 67, 97, 108,
            108, 45, 73, 68, 58, 32, 101, 71, 66, 55, 97, 103, 98, 118, 69, 73, 13, 10, 77, 97,
            120, 45, 70, 111, 114, 119, 97, 114, 100, 115, 58, 32, 55, 48, 13, 10, 83, 117, 112,
            112, 111, 114, 116, 101, 100, 58, 32, 111, 117, 116, 98, 111, 117, 110, 100, 13, 10,
            65, 99, 99, 101, 112, 116, 58, 32, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110,
            47, 115, 100, 112, 44, 32, 116, 101, 120, 116, 47, 112, 108, 97, 105, 110, 44, 32, 97,
            112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 118, 110, 100, 46, 103, 115, 109,
            97, 46, 114, 99, 115, 45, 102, 116, 45, 104, 116, 116, 112, 43, 120, 109, 108, 13, 10,
            67, 111, 110, 116, 97, 99, 116, 58, 32, 60, 115, 105, 112, 58, 49, 48, 48, 48, 64, 49,
            54, 57, 46, 50, 53, 52, 46, 49, 54, 53, 46, 49, 49, 62, 59, 43, 115, 105, 112, 46, 105,
            110, 115, 116, 97, 110, 99, 101, 61, 34, 60, 117, 114, 110, 58, 117, 117, 105, 100, 58,
            54, 102, 98, 98, 102, 101, 48, 51, 45, 54, 99, 54, 57, 45, 52, 101, 50, 99, 45, 57, 99,
            51, 97, 45, 57, 52, 49, 54, 52, 57, 54, 56, 99, 54, 97, 48, 62, 34, 13, 10, 69, 120,
            112, 105, 114, 101, 115, 58, 32, 51, 54, 48, 48, 13, 10, 85, 115, 101, 114, 45, 65,
            103, 101, 110, 116, 58, 32, 76, 105, 110, 112, 104, 111, 110, 101, 47, 51, 46, 56, 46,
            49, 32, 40, 98, 101, 108, 108, 101, 45, 115, 105, 112, 47, 49, 46, 52, 46, 48, 41, 13,
            10, 13, 10,
        ];

        use super::*;

        let mut check = Chunk::new();
        check.set_ip_protocol_family(2)
             .set_ip_protocol_id(17)
             .set_proto_src_port(5060)
             .set_proto_dst_port(5060)
             .set_timestamp_seconds(1621327329)
             .set_timestamp_micro_seconds_offset(796000)
             .set_proto_type(CapProtoType::Sip)
             .set_capture_agent_id(100)
             .set_ipv4_src_address("169.254.165.11".parse().unwrap())
             .set_ipv4_dst_address("169.254.165.100".parse().unwrap())
             .set_packet_payload("REGISTER sip:169.254.165.100 SIP/2.0\r\nVia: SIP/2.0/UDP 169.254.165.11:5060;branch=z9hG4bK.SzvPxgPLb;rport\r\nFrom: <sip:1000@169.254.165.100>;tag=tNLT7WErP\r\nTo: sip:1000@169.254.165.100\r\nCSeq: 20 REGISTER\r\nCall-ID: eGB7agbvEI\r\nMax-Forwards: 70\r\nSupported: outbound\r\nAccept: application/sdp, text/plain, application/vnd.gsma.rcs-ft-http+xml\r\nContact: <sip:1000@169.254.165.11>;+sip.instance=\"<urn:uuid:6fbbfe03-6c69-4e2c-9c3a-94164968c6a0>\"\r\nExpires: 3600\r\nUser-Agent: Linphone/3.8.1 (belle-sip/1.4.0)\r\n\r\n".parse().unwrap());

        assert_eq!(parse_packet(packet).unwrap(), check)
    }
}
