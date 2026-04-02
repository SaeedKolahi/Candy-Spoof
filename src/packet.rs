//! Candy-Spoof wire protocol – the application-level packet that rides inside
//! spoofed UDP (data channel) or ICMP Echo (control channel) payloads.

use anyhow::{bail, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// 4-byte magic number at the start of every CandyPacket.
pub const MAGIC: u32 = 0xCA_FE_5F_00;
/// Current protocol version.
pub const VERSION: u8 = 1;
/// Minimum wire size of a CandyPacket (no payload).
pub const HEADER_SIZE: usize = 18;

/// Type of a CandyPacket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketKind {
    /// Application data.
    Data = 0,
    /// Cumulative acknowledgement.
    Ack = 1,
    /// Negative acknowledgement (request retransmission).
    Nack = 2,
    /// Tunnel open request (client → server).
    Syn = 3,
    /// Tunnel open acknowledgement (server → client).
    SynAck = 4,
    /// Tunnel teardown.
    Fin = 5,
    /// Keepalive ping.
    Heartbeat = 6,
    /// Keepalive pong.
    HeartbeatAck = 7,
}

impl TryFrom<u8> for PacketKind {
    type Error = anyhow::Error;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::Data),
            1 => Ok(Self::Ack),
            2 => Ok(Self::Nack),
            3 => Ok(Self::Syn),
            4 => Ok(Self::SynAck),
            5 => Ok(Self::Fin),
            6 => Ok(Self::Heartbeat),
            7 => Ok(Self::HeartbeatAck),
            _ => bail!("unknown packet kind {}", v),
        }
    }
}

/// An application-level Candy-Spoof packet.
///
/// Wire format (big-endian):
/// ```text
/// [magic:4][version:1][kind:1][tunnel_id:4][seq:4][ack:4][window:2][payload…]
/// ```
#[derive(Debug, Clone)]
pub struct CandyPacket {
    pub kind:      PacketKind,
    pub tunnel_id: u32,
    /// Sequence number of this packet (data) or highest received seq + 1 (ack).
    pub seq:       u32,
    /// Cumulative ACK – next seq the sender expects to receive.
    pub ack:       u32,
    /// Receiver window in packets.
    pub window:    u16,
    /// Payload bytes (may be empty for control packets).
    pub payload:   Bytes,
}

impl CandyPacket {
    // ── Constructors ──────────────────────────────────────────────────────────

    pub fn new_syn(tunnel_id: u32, seq: u32) -> Self {
        Self {
            kind:      PacketKind::Syn,
            tunnel_id,
            seq,
            ack:       0,
            window:    64,
            payload:   Bytes::new(),
        }
    }

    pub fn new_syn_ack(tunnel_id: u32, peer_seq: u32, our_seq: u32) -> Self {
        Self {
            kind:      PacketKind::SynAck,
            tunnel_id,
            seq:       our_seq,
            ack:       peer_seq.wrapping_add(1),
            window:    64,
            payload:   Bytes::new(),
        }
    }

    pub fn new_ack(tunnel_id: u32, ack: u32, window: u16) -> Self {
        Self {
            kind:      PacketKind::Ack,
            tunnel_id,
            seq:       0,
            ack,
            window,
            payload:   Bytes::new(),
        }
    }

    pub fn new_nack(tunnel_id: u32, missing_seq: u32) -> Self {
        Self {
            kind:      PacketKind::Nack,
            tunnel_id,
            seq:       missing_seq,
            ack:       0,
            window:    0,
            payload:   Bytes::new(),
        }
    }

    pub fn new_data(tunnel_id: u32, seq: u32, ack: u32, window: u16, payload: Bytes) -> Self {
        Self { kind: PacketKind::Data, tunnel_id, seq, ack, window, payload }
    }

    pub fn new_heartbeat(tunnel_id: u32, seq: u32) -> Self {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            kind:      PacketKind::Heartbeat,
            tunnel_id,
            seq,
            ack:       0,
            window:    0,
            payload:   Bytes::copy_from_slice(&ts.to_be_bytes()),
        }
    }

    pub fn new_fin(tunnel_id: u32) -> Self {
        Self {
            kind:      PacketKind::Fin,
            tunnel_id,
            seq:       0,
            ack:       0,
            window:    0,
            payload:   Bytes::new(),
        }
    }

    // ── Serialisation ─────────────────────────────────────────────────────────

    /// Encode the packet to bytes.
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(HEADER_SIZE + self.payload.len());
        buf.put_u32(MAGIC);
        buf.put_u8(VERSION);
        buf.put_u8(self.kind as u8);
        buf.put_u32(self.tunnel_id);
        buf.put_u32(self.seq);
        buf.put_u32(self.ack);
        buf.put_u16(self.window);
        buf.put(self.payload.clone());
        buf.freeze()
    }

    /// Decode a packet from bytes. Returns an error on invalid input.
    pub fn decode(mut data: Bytes) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            bail!("packet too short: {} bytes (min {})", data.len(), HEADER_SIZE);
        }
        let magic = data.get_u32();
        if magic != MAGIC {
            bail!("bad magic 0x{:08x}", magic);
        }
        let version = data.get_u8();
        if version != VERSION {
            bail!("unsupported version {}", version);
        }
        let kind      = PacketKind::try_from(data.get_u8())?;
        let tunnel_id = data.get_u32();
        let seq       = data.get_u32();
        let ack       = data.get_u32();
        let window    = data.get_u16();
        let payload   = data; // remaining bytes
        Ok(CandyPacket { kind, tunnel_id, seq, ack, window, payload })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syn_uses_provided_sequence() {
        let pkt = CandyPacket::new_syn(42, 12345);
        assert_eq!(pkt.kind, PacketKind::Syn);
        assert_eq!(pkt.tunnel_id, 42);
        assert_eq!(pkt.seq, 12345);
    }
}
