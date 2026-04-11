use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Mutex};

use crate::config::Config;
use crate::packet::CandyPacket;
use crate::tunnel::TunnelManager;

const SMUX_MAGIC: u32 = 0x53_4d_55_58;
const SMUX_VERSION: u8 = 1;
const SMUX_HEADER_LEN: usize = 14;
const MAX_FRAME_PAYLOAD: usize = 1024 * 1024;
static NEXT_STREAM_ID: AtomicU32 = AtomicU32::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum FrameKind {
    Open = 1,
    OpenAck = 2,
    Data = 3,
    Close = 4,
    Reset = 5,
}

impl TryFrom<u8> for FrameKind {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Open),
            2 => Ok(Self::OpenAck),
            3 => Ok(Self::Data),
            4 => Ok(Self::Close),
            5 => Ok(Self::Reset),
            _ => bail!("unknown smux frame kind {}", value),
        }
    }
}

#[derive(Clone, Debug)]
struct Frame {
    kind: FrameKind,
    stream_id: u32,
    payload: Bytes,
}

impl Frame {
    fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(SMUX_HEADER_LEN + self.payload.len());
        buf.put_u32(SMUX_MAGIC);
        buf.put_u8(SMUX_VERSION);
        buf.put_u8(self.kind as u8);
        buf.put_u32(self.stream_id);
        buf.put_u32(self.payload.len() as u32);
        buf.extend_from_slice(&self.payload);
        buf.freeze()
    }
}

#[derive(Default)]
struct FrameDecoder {
    buf: BytesMut,
}

impl FrameDecoder {
    fn feed(&mut self, chunk: Bytes) -> Result<Vec<Frame>> {
        self.buf.extend_from_slice(&chunk);
        let mut out = Vec::new();

        loop {
            if self.buf.len() < SMUX_HEADER_LEN {
                break;
            }

            let mut header = &self.buf[..SMUX_HEADER_LEN];
            let magic = header.get_u32();
            if magic != SMUX_MAGIC {
                bail!("invalid smux magic 0x{:08x}", magic);
            }

            let version = header.get_u8();
            if version != SMUX_VERSION {
                bail!("unsupported smux version {}", version);
            }

            let kind = FrameKind::try_from(header.get_u8())?;
            let stream_id = header.get_u32();
            let payload_len = header.get_u32() as usize;

            if payload_len > MAX_FRAME_PAYLOAD {
                bail!("smux payload too large: {}", payload_len);
            }

            let full_len = SMUX_HEADER_LEN + payload_len;
            if self.buf.len() < full_len {
                break;
            }

            let mut frame_bytes = self.buf.split_to(full_len);
            frame_bytes.advance(SMUX_HEADER_LEN);

            out.push(Frame {
                kind,
                stream_id,
                payload: frame_bytes.freeze(),
            });
        }

        Ok(out)
    }
}

#[derive(Clone)]
struct Lane {
    tunnel_id: u32,
    tx: mpsc::Sender<Bytes>,
}

async fn send_on_lane(
    lanes: &Mutex<Vec<Lane>>,
    rr: &AtomicUsize,
    payload: Bytes,
    lane_hint: Option<u32>,
) -> Result<()> {
    if let Some(tunnel_id) = lane_hint {
        let lane = {
            let lanes_guard = lanes.lock().await;
            lanes_guard
                .iter()
                .find(|l| l.tunnel_id == tunnel_id)
                .cloned()
        };

        if let Some(lane) = lane {
            if lane.tx.send(payload).await.is_ok() {
                return Ok(());
            }

            let mut lanes_guard = lanes.lock().await;
            if let Some(pos) = lanes_guard.iter().position(|l| l.tunnel_id == tunnel_id) {
                lanes_guard.remove(pos);
            }
            return Err(anyhow!("tunnel lane {} unavailable", tunnel_id));
        }

        return Err(anyhow!("tunnel lane {} not found", tunnel_id));
    }

    for _ in 0..8 {
        let lane = {
            let lanes_guard = lanes.lock().await;
            if lanes_guard.is_empty() {
                return Err(anyhow!("no active tunnel lanes"));
            }
            let index = rr.fetch_add(1, Ordering::Relaxed) % lanes_guard.len();
            lanes_guard[index].clone()
        };

        if lane.tx.send(payload.clone()).await.is_ok() {
            return Ok(());
        }

        let mut lanes_guard = lanes.lock().await;
        if let Some(pos) = lanes_guard.iter().position(|l| l.tunnel_id == lane.tunnel_id) {
            lanes_guard.remove(pos);
        }
    }

    Err(anyhow!("all tunnel lanes are unavailable"))
}

struct ClientStream {
    app_tx: mpsc::Sender<Bytes>,
    lane_tunnel_id: u32,
}

struct ClientInner {
    cfg: Arc<Config>,
    manager: TunnelManager,
    lanes: Mutex<Vec<Lane>>,
    rr: AtomicUsize,
    streams: Mutex<HashMap<u32, ClientStream>>,
    pending_open: Mutex<HashMap<u32, oneshot::Sender<Result<()>>>>,
}

#[derive(Clone)]
pub struct SmuxClient {
    inner: Arc<ClientInner>,
}

impl SmuxClient {
    pub async fn new(cfg: Arc<Config>, manager: TunnelManager) -> Result<Self> {
        let inner = Arc::new(ClientInner {
            cfg,
            manager,
            lanes: Mutex::new(Vec::new()),
            rr: AtomicUsize::new(0),
            streams: Mutex::new(HashMap::new()),
            pending_open: Mutex::new(HashMap::new()),
        });

        Ok(Self { inner })
    }

    pub async fn open_stream(
        &self,
        target_host: String,
        target_port: u16,
    ) -> Result<(u32, mpsc::Receiver<Bytes>, mpsc::Sender<Bytes>)> {
        let stream_id = NEXT_STREAM_ID
            .fetch_add(1, Ordering::Relaxed)
            .max(1);

        let (app_tx, app_rx) = mpsc::channel::<Bytes>(2048);
        let (pending_tx, pending_rx) = oneshot::channel::<Result<()>>();

        self.inner
            .streams
            .lock()
            .await
            .insert(
                stream_id,
                ClientStream {
                    app_tx,
                    lane_tunnel_id: 0,
                },
            );
        self.inner
            .pending_open
            .lock()
            .await
            .insert(stream_id, pending_tx);

        let active_streams = self.inner.streams.lock().await.len().max(1);
        let desired_lanes = active_streams.min(self.inner.cfg.tunnel_count.max(1));
        if let Err(e) = self.ensure_lane_count(desired_lanes).await {
            self.inner.streams.lock().await.remove(&stream_id);
            self.inner.pending_open.lock().await.remove(&stream_id);
            return Err(e);
        }

        let lane_tunnel_id = {
            let lanes = self.inner.lanes.lock().await;
            if lanes.is_empty() {
                self.inner.streams.lock().await.remove(&stream_id);
                self.inner.pending_open.lock().await.remove(&stream_id);
                return Err(anyhow!("no active tunnel lanes"));
            }
            let index = (stream_id as usize) % lanes.len();
            lanes[index].tunnel_id
        };

        {
            let mut streams = self.inner.streams.lock().await;
            if let Some(s) = streams.get_mut(&stream_id) {
                s.lane_tunnel_id = lane_tunnel_id;
            }
        }

        let target = format!("{}:{}", target_host, target_port);
        self.send_frame(Frame {
            kind: FrameKind::Open,
            stream_id,
            payload: Bytes::from(target),
        })
        .await?;

        match tokio::time::timeout(Duration::from_secs(15), pending_rx).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(e))) => {
                self.inner.streams.lock().await.remove(&stream_id);
                return Err(e);
            }
            Ok(Err(_)) => {
                self.inner.streams.lock().await.remove(&stream_id);
                return Err(anyhow!("smux open waiter dropped"));
            }
            Err(_) => {
                self.inner.streams.lock().await.remove(&stream_id);
                self.inner.pending_open.lock().await.remove(&stream_id);
                return Err(anyhow!("smux open timeout"));
            }
        }

        let (to_mux_tx, mut to_mux_rx) = mpsc::channel::<Bytes>(2048);
        let this = self.clone();
        tokio::spawn(async move {
            while let Some(chunk) = to_mux_rx.recv().await {
                if this
                    .send_frame(Frame {
                        kind: FrameKind::Data,
                        stream_id,
                        payload: chunk,
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }

            let _ = this
                .send_frame(Frame {
                    kind: FrameKind::Close,
                    stream_id,
                    payload: Bytes::new(),
                })
                .await;
            this.inner.streams.lock().await.remove(&stream_id);
        });

        Ok((stream_id, app_rx, to_mux_tx))
    }

    pub async fn close_stream(&self, stream_id: u32) {
        let lane_hint = {
            let streams = self.inner.streams.lock().await;
            streams.get(&stream_id).map(|s| s.lane_tunnel_id)
        };
        self.inner.pending_open.lock().await.remove(&stream_id);
        let _ = self
            .send_frame_with_hint(
                Frame {
                    kind: FrameKind::Close,
                    stream_id,
                    payload: Bytes::new(),
                },
                lane_hint,
            )
            .await;
        self.inner.streams.lock().await.remove(&stream_id);
    }

    async fn send_frame(&self, frame: Frame) -> Result<()> {
        let lane_hint = if frame.stream_id == 0 {
            None
        } else {
            let streams = self.inner.streams.lock().await;
            streams.get(&frame.stream_id).map(|s| s.lane_tunnel_id)
        };
        self.send_frame_with_hint(frame, lane_hint).await
    }

    async fn send_frame_with_hint(&self, frame: Frame, lane_hint: Option<u32>) -> Result<()> {
        send_on_lane(
            &self.inner.lanes,
            &self.inner.rr,
            frame.encode(),
            lane_hint,
        )
        .await
    }

    async fn ensure_lane_count(&self, desired: usize) -> Result<()> {
        let desired = desired.max(1);

        loop {
            let current = self.inner.lanes.lock().await.len();
            if current >= desired {
                return Ok(());
            }

            let (tunnel_id, mut app_rx, net_tx) = self.inner.manager.open_tunnel().await?;
            if !self
                .inner
                .manager
                .wait_established(tunnel_id, Duration::from_secs(15))
                .await
            {
                self.inner.manager.close_tunnel(tunnel_id).await;
                return Err(anyhow!("lane tunnel {} handshake timeout", tunnel_id));
            }

            self.inner
                .lanes
                .lock()
                .await
                .push(Lane { tunnel_id, tx: net_tx });

            let this = self.clone();
            tokio::spawn(async move {
                let mut decoder = FrameDecoder::default();
                while let Some(chunk) = app_rx.recv().await {
                    match decoder.feed(chunk) {
                        Ok(frames) => {
                            for frame in frames {
                                if let Err(e) = this.handle_frame(frame).await {
                                    log::warn!("smux client frame error: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            log::warn!("smux client decode error: {}", e);
                            break;
                        }
                    }
                }
                this.remove_lane(tunnel_id).await;
            });
        }
    }

    async fn remove_lane(&self, tunnel_id: u32) {
        let mut lanes = self.inner.lanes.lock().await;
        if let Some(pos) = lanes.iter().position(|l| l.tunnel_id == tunnel_id) {
            lanes.remove(pos);
        }
    }

    async fn handle_frame(&self, frame: Frame) -> Result<()> {
        match frame.kind {
            FrameKind::Open => {}
            FrameKind::OpenAck => {
                if let Some(waiter) = self.inner.pending_open.lock().await.remove(&frame.stream_id) {
                    let _ = waiter.send(Ok(()));
                }
            }
            FrameKind::Data => {
                let tx = {
                    let streams = self.inner.streams.lock().await;
                    streams.get(&frame.stream_id).map(|s| s.app_tx.clone())
                };
                if let Some(tx) = tx {
                    if tx.send(frame.payload).await.is_err() {
                        self.inner.streams.lock().await.remove(&frame.stream_id);
                    }
                }
            }
            FrameKind::Close => {
                self.inner.streams.lock().await.remove(&frame.stream_id);
                self.inner.pending_open.lock().await.remove(&frame.stream_id);
            }
            FrameKind::Reset => {
                let message = String::from_utf8_lossy(&frame.payload).into_owned();
                if let Some(waiter) = self.inner.pending_open.lock().await.remove(&frame.stream_id) {
                    let _ = waiter.send(Err(anyhow!("{}", message)));
                }
                self.inner.streams.lock().await.remove(&frame.stream_id);
            }
        }
        Ok(())
    }
}

struct ServerInner {
    cfg: Arc<Config>,
    manager: TunnelManager,
    lanes: Mutex<Vec<Lane>>,
    rr: AtomicUsize,
    streams: Mutex<HashMap<u32, ServerStream>>,
}

struct ServerStream {
    to_tcp_tx: mpsc::Sender<Bytes>,
    lane_tunnel_id: u32,
}

#[derive(Clone)]
pub struct SmuxServer {
    inner: Arc<ServerInner>,
}

impl SmuxServer {
    pub async fn new(cfg: Arc<Config>, manager: TunnelManager) -> Result<Self> {
        let inner = Arc::new(ServerInner {
            cfg,
            manager,
            lanes: Mutex::new(Vec::new()),
            rr: AtomicUsize::new(0),
            streams: Mutex::new(HashMap::new()),
        });

        Ok(Self { inner })
    }

    pub async fn attach_syn(&self, syn: CandyPacket, src_ip: Ipv4Addr) -> Result<()> {
        let (tunnel_id, mut app_rx, net_tx) = self
            .inner
            .manager
            .accept_syn(syn, src_ip)
            .await
            .context("accept syn for smux lane")?;

        self.inner
            .lanes
            .lock()
            .await
            .push(Lane { tunnel_id, tx: net_tx });

        let this = self.clone();
        tokio::spawn(async move {
            let mut decoder = FrameDecoder::default();
            while let Some(chunk) = app_rx.recv().await {
                match decoder.feed(chunk) {
                    Ok(frames) => {
                        for frame in frames {
                            if let Err(e) = this.handle_frame(frame, tunnel_id).await {
                                log::warn!("smux server frame error: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("smux server decode error: {}", e);
                        break;
                    }
                }
            }
            this.remove_lane(tunnel_id).await;
        });

        Ok(())
    }

    async fn send_frame(&self, frame: Frame) -> Result<()> {
        let lane_hint = if frame.stream_id == 0 {
            None
        } else {
            let streams = self.inner.streams.lock().await;
            streams.get(&frame.stream_id).map(|s| s.lane_tunnel_id)
        };
        self.send_frame_with_hint(frame, lane_hint).await
    }

    async fn send_frame_with_hint(&self, frame: Frame, lane_hint: Option<u32>) -> Result<()> {
        send_on_lane(
            &self.inner.lanes,
            &self.inner.rr,
            frame.encode(),
            lane_hint,
        )
        .await
    }

    async fn remove_lane(&self, tunnel_id: u32) {
        let mut lanes = self.inner.lanes.lock().await;
        if let Some(pos) = lanes.iter().position(|l| l.tunnel_id == tunnel_id) {
            lanes.remove(pos);
        }
    }

    async fn handle_frame(&self, frame: Frame, incoming_tunnel_id: u32) -> Result<()> {
        match frame.kind {
            FrameKind::Open => {
                let target = String::from_utf8(frame.payload.to_vec())
                    .context("invalid stream OPEN target bytes")?;
                let this = self.clone();
                tokio::spawn(async move {
                    if let Err(e) = this
                        .handle_open(frame.stream_id, target, incoming_tunnel_id)
                        .await
                    {
                        let _ = this
                            .send_frame_with_hint(
                                Frame {
                                    kind: FrameKind::Reset,
                                    stream_id: frame.stream_id,
                                    payload: Bytes::from(e.to_string()),
                                },
                                Some(incoming_tunnel_id),
                            )
                            .await;
                    }
                });
            }
            FrameKind::OpenAck => {}
            FrameKind::Data => {
                let tx = {
                    let streams = self.inner.streams.lock().await;
                    streams.get(&frame.stream_id).map(|s| s.to_tcp_tx.clone())
                };
                if let Some(tx) = tx {
                    if tx.send(frame.payload).await.is_err() {
                        self.inner.streams.lock().await.remove(&frame.stream_id);
                    }
                }
            }
            FrameKind::Close | FrameKind::Reset => {
                self.inner.streams.lock().await.remove(&frame.stream_id);
            }
        }
        Ok(())
    }

    async fn handle_open(&self, stream_id: u32, target: String, lane_tunnel_id: u32) -> Result<()> {
        let tcp = TcpStream::connect(&target)
            .await
            .with_context(|| format!("connect to {}", target))?;
        let (mut tcp_r, mut tcp_w) = tcp.into_split();

        let (to_tcp_tx, mut to_tcp_rx) = mpsc::channel::<Bytes>(2048);
        self.inner.streams.lock().await.insert(
            stream_id,
            ServerStream {
                to_tcp_tx,
                lane_tunnel_id,
            },
        );

        self.send_frame(Frame {
            kind: FrameKind::OpenAck,
            stream_id,
            payload: Bytes::new(),
        })
        .await?;

        let writer = tokio::spawn(async move {
            while let Some(data) = to_tcp_rx.recv().await {
                if tcp_w.write_all(&data).await.is_err() {
                    break;
                }
            }
        });

        let this = self.clone();
        let mtu = self.inner.cfg.mtu;
        let reader = tokio::spawn(async move {
            let mut buf = vec![0u8; mtu.max(512)];
            loop {
                match tcp_r.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if this
                            .send_frame(Frame {
                                kind: FrameKind::Data,
                                stream_id,
                                payload: Bytes::copy_from_slice(&buf[..n]),
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        tokio::select! {
            _ = writer => {}
            _ = reader => {}
        }

        self.inner.streams.lock().await.remove(&stream_id);
        let _ = self
            .send_frame(Frame {
                kind: FrameKind::Close,
                stream_id,
                payload: Bytes::new(),
            })
            .await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_codec_roundtrip() {
        let frame = Frame {
            kind: FrameKind::Data,
            stream_id: 42,
            payload: Bytes::from_static(b"hello"),
        };

        let mut decoder = FrameDecoder::default();
        let out = decoder.feed(frame.encode()).expect("decode");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, FrameKind::Data);
        assert_eq!(out[0].stream_id, 42);
        assert_eq!(out[0].payload, Bytes::from_static(b"hello"));
    }

    #[test]
    fn frame_codec_handles_fragmented_input() {
        let frame = Frame {
            kind: FrameKind::Open,
            stream_id: 7,
            payload: Bytes::from_static(b"example.com:443"),
        }
        .encode();

        let left = frame.slice(..5);
        let right = frame.slice(5..);
        let mut decoder = FrameDecoder::default();
        assert!(decoder.feed(left).expect("left").is_empty());
        let out = decoder.feed(right).expect("right");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].stream_id, 7);
    }
}