# hep
hep protocol parsing,support hep v1/v2/v3

Usage:

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
