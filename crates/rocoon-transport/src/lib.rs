//! Cocoon proxy transport stack.
//!
//! This crate owns the reusable transport layers needed to talk to a Cocoon
//! proxy: TCP proof-of-work, RA-TLS setup, and the Cocoon frame/session protocol.
//! The session layer provides two request styles: classic `tcp.query` for
//! metadata/auth and raw `tcp.packet` streaming for `client.runQueryEx`.

use std::io::{Read, Write};

use anyhow::{Context, Result};
use rand::Rng;
use rand::RngCore;
use rocoon_protocol::{self as cocoon, RunQueryOptions};
use tl_proto::{TlRead, TlWrite};

pub mod pow;
pub mod ratls;

const MAX_FRAME_SIZE: u32 = 1 << 20;

/// TL packet that opens a logical Cocoon TCP session.
#[derive(TlWrite)]
#[tl(boxed, id = 0xa57c4261)]
struct TcpConnect {
    id: i64,
}

/// TL response confirming the logical session id.
#[derive(Debug, TlRead)]
#[tl(boxed, id = 0x636d41d6)]
struct TcpConnectedPacket {
    id: i64,
}

/// TL wrapper for request/response-style proxy calls.
#[derive(TlWrite)]
#[tl(boxed, id = 0x3af51908)]
struct TcpQuery<'a> {
    id: i64,
    data: &'a [u8],
}

/// TL keepalive response.
#[derive(TlWrite)]
#[tl(boxed, id = 0x0bd4302c)]
struct TcpPong {
    id: i64,
}

/// TL wrapper for streaming packets such as `client.runQueryEx`.
#[derive(TlWrite)]
#[tl(boxed, id = 0x9c17baf8)]
struct TcpPacketOut<'a> {
    data: &'a [u8],
}

/// Incoming TL packet variants inside Cocoon session frames.
#[derive(Debug, TlRead)]
#[tl(boxed)]
enum TcpPacket<'tl> {
    #[tl(id = 0xbbe9627c)]
    Ping { id: i64 },
    #[tl(id = 0x0bd4302c)]
    Pong { id: i64 },
    #[tl(id = 0x9c17baf8)]
    Packet { data: &'tl [u8] },
    #[tl(id = 0xc048c311)]
    QueryAnswer { id: i64, data: &'tl [u8] },
    #[tl(id = 0x4cd2f602)]
    QueryError {
        id: i64,
        code: i32,
        message: &'tl [u8],
    },
}

/// Stateful frame reader/writer over an already-secure transport.
///
/// `RW` is generic so the framing logic can be tested or reused with any
/// `Read + Write` stream. In production it is `RatlsStream`.
pub struct Session<RW> {
    io: RW,
    send_seqno: u32,
    recv_seqno: u32,
}

/// Result of the initial `tcp.connect` handshake.
pub struct TcpConnected {
    /// Random session id acknowledged by the proxy.
    pub id: i64,
}

/// Owned token counters copied from Cocoon `client.queryFinalInfo`.
#[derive(Clone, Copy, Debug, Default)]
#[allow(clippy::struct_field_names)]
pub struct TokenUsage {
    pub prompt_tokens_used: i64,
    pub cached_tokens_used: i64,
    pub completion_tokens_used: i64,
    pub reasoning_tokens_used: i64,
    pub total_tokens_used: i64,
}

/// Owned final metadata attached to the terminal `client.runQueryEx` packet.
#[derive(Clone, Debug)]
pub struct QueryFinalInfo {
    pub tokens_used: TokenUsage,
    pub worker_debug: Option<String>,
    pub proxy_debug: Option<String>,
    pub proxy_start_time: Option<f64>,
    pub proxy_end_time: Option<f64>,
    pub worker_start_time: Option<f64>,
    pub worker_end_time: Option<f64>,
}

/// Aggregated result of one `client.runQueryEx` call.
pub struct RunQueryOutput {
    /// First answer packet containing the encoded HTTP response head.
    pub response_head: Vec<u8>,
    /// Additional body chunks from subsequent answer part packets.
    pub payload_parts: Vec<Vec<u8>>,
    /// Terminal packet metadata with token counters and optional debug strings.
    pub final_info: Option<QueryFinalInfo>,
}

impl<RW: Read + Write> Session<RW> {
    /// Starts a logical Cocoon session over the supplied transport.
    ///
    /// # Errors
    ///
    /// Returns an error if the initial `tcp.connect` frame cannot be written,
    /// the response frame cannot be read, the response is not `tcp.connected`,
    /// or the acknowledged session id does not match the requested one.
    pub fn connect(io: RW) -> Result<(Self, TcpConnected)> {
        let mut session = Self {
            io,
            send_seqno: 0,
            recv_seqno: 0,
        };

        let id = rand::thread_rng().gen_range(0..i64::MAX);
        let payload = tl_proto::serialize(TcpConnect { id });

        session
            .send_frame(&payload)
            .context("send tcp.connect frame")?;
        let response = session
            .recv_frame()
            .context("receive tcp.connected frame")?;
        let connected = tl_proto::deserialize::<TcpConnectedPacket>(&response)
            .context("decode tcp.connected")?;

        if connected.id != id {
            anyhow::bail!(
                "tcp.connected id mismatch: got {}, expected {id}",
                connected.id
            );
        }

        Ok((session, TcpConnected { id }))
    }

    /// Sends a one-shot `tcp.query` and waits for its matching answer.
    ///
    /// This is used for metadata and authorization calls where the proxy returns
    /// a single `tcp.queryAnswer` or `tcp.queryError`.
    ///
    /// # Errors
    ///
    /// Returns an error if frame IO fails, the proxy returns a matching
    /// `tcp.queryError`, or a matching response cannot be decoded.
    pub fn make_request(&mut self, request_payload: &[u8]) -> Result<Vec<u8>> {
        let query_id = rand::thread_rng().gen_range(0..i64::MAX);
        let packet = tl_proto::serialize(TcpQuery {
            id: query_id,
            data: request_payload,
        });
        self.send_frame(&packet).context("send tcp.query frame")?;

        loop {
            let payload = self
                .recv_frame()
                .context("receive tcp.query response frame")?;
            let packet = tl_proto::deserialize::<TcpPacket>(&payload)
                .context("decode tcp packet while waiting for query answer")?;

            match packet {
                TcpPacket::QueryAnswer { id, data } if id == query_id => return Ok(data.to_vec()),
                TcpPacket::QueryError { id, code, message } if id == query_id => {
                    let message = std::str::from_utf8(message).unwrap_or("<non-utf8>");
                    anyhow::bail!("tcp.queryError code={code}: {message}");
                }
                TcpPacket::Ping { id } => {
                    let pong = tl_proto::serialize(TcpPong { id });
                    self.send_frame(&pong).context("send tcp.pong")?;
                }
                TcpPacket::Pong { id } => {
                    let _ = id;
                }
                TcpPacket::Packet { .. }
                | TcpPacket::QueryAnswer { .. }
                | TcpPacket::QueryError { .. } => {}
            }
        }
    }

    /// Sends `client.runQueryEx` and aggregates its streamed answer packets.
    ///
    /// The first matching `Answer` packet contains the encoded HTTP response.
    /// Later `Part` packets contain more response body bytes. The optional
    /// `final_info` flag marks the terminal packet.
    ///
    /// # Errors
    ///
    /// Returns an error if frame IO fails, the proxy returns a matching query
    /// error, answer packets arrive in an invalid order, or sequence/frame
    /// validation fails.
    pub fn run_client_query_ex(
        &mut self,
        model: &str,
        http_request_payload: &[u8],
        options: RunQueryOptions,
    ) -> Result<RunQueryOutput> {
        let mut request_id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut request_id);

        let request =
            cocoon::encode_run_query_ex(model, http_request_payload, &request_id, options);
        let packet = tl_proto::serialize(TcpPacketOut { data: &request });
        self.send_frame(&packet)
            .context("send client.runQueryEx tcp.packet")?;

        let mut response_head = None;
        let mut payload_parts = Vec::new();

        loop {
            let payload = self.recv_frame().context("receive tcp.packet response")?;
            let packet = tl_proto::deserialize::<TcpPacket>(&payload)
                .context("decode tcp packet while waiting for client.runQueryEx")?;

            match packet {
                TcpPacket::Packet { data } => {
                    let Ok(answer) = cocoon::decode_query_answer_ex(data) else {
                        continue;
                    };
                    match answer {
                        cocoon::QueryAnswerEx::Answer {
                            request_id: got_id,
                            answer,
                            final_info,
                            ..
                        } if got_id == &request_id => {
                            if response_head.is_some() {
                                anyhow::bail!("duplicate client.queryAnswerEx");
                            }
                            let answer = answer.to_vec();
                            let final_info = final_info.as_ref().map(query_final_info_from_tl);
                            if final_info.is_some() {
                                return Ok(RunQueryOutput {
                                    response_head: answer,
                                    payload_parts,
                                    final_info,
                                });
                            }
                            response_head = Some(answer);
                        }
                        cocoon::QueryAnswerEx::Part {
                            request_id: got_id,
                            answer,
                            final_info,
                            ..
                        } if got_id == &request_id => {
                            if response_head.is_none() {
                                anyhow::bail!(
                                    "received client.queryAnswerPartEx before response head"
                                );
                            }
                            payload_parts.push(answer.to_vec());
                            let final_info = final_info.as_ref().map(query_final_info_from_tl);
                            if final_info.is_some() {
                                let response_head =
                                    response_head.context("missing client.queryAnswerEx")?;
                                return Ok(RunQueryOutput {
                                    response_head,
                                    payload_parts,
                                    final_info,
                                });
                            }
                        }
                        cocoon::QueryAnswerEx::Error {
                            request_id: got_id,
                            error_code,
                            error,
                            ..
                        } if got_id == &request_id => {
                            let error = std::str::from_utf8(error).unwrap_or("<non-utf8>");
                            anyhow::bail!("client.queryAnswerErrorEx code={error_code}: {error}");
                        }
                        _ => {}
                    }
                }
                TcpPacket::Ping { id } => {
                    let pong = tl_proto::serialize(TcpPong { id });
                    self.send_frame(&pong).context("send tcp.pong")?;
                }
                TcpPacket::Pong { id } => {
                    let _ = id;
                }
                TcpPacket::QueryAnswer { .. } | TcpPacket::QueryError { .. } => {}
            }
        }
    }

    /// Writes one length/seqno-prefixed Cocoon frame.
    fn send_frame(&mut self, payload: &[u8]) -> Result<()> {
        let len = u32::try_from(payload.len()).context("payload too large")?;
        let mut header = [0u8; 8];
        header[0..4].copy_from_slice(&len.to_le_bytes());
        header[4..8].copy_from_slice(&self.send_seqno.to_le_bytes());
        self.send_seqno = self
            .send_seqno
            .checked_add(1)
            .context("send seqno overflow")?;

        self.io.write_all(&header).context("write frame header")?;
        self.io.write_all(payload).context("write frame payload")?;
        self.io.flush().context("flush frame")
    }

    /// Reads one Cocoon frame and validates the receive sequence number.
    fn recv_frame(&mut self) -> Result<Vec<u8>> {
        let mut header = [0u8; 8];
        self.io
            .read_exact(&mut header)
            .context("read frame header")?;

        let size = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let seqno = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);

        if seqno != self.recv_seqno {
            anyhow::bail!(
                "unexpected frame seqno {seqno}, expected {}",
                self.recv_seqno
            );
        }
        self.recv_seqno = self
            .recv_seqno
            .checked_add(1)
            .context("recv seqno overflow")?;

        if size > MAX_FRAME_SIZE {
            anyhow::bail!("frame too large: {size} bytes");
        }

        let mut payload = vec![0u8; size as usize];
        self.io
            .read_exact(&mut payload)
            .context("read frame payload")?;
        Ok(payload)
    }
}

/// Copies borrowed TL final metadata out of the frame buffer.
fn query_final_info_from_tl(value: &cocoon::QueryFinalInfo<'_>) -> QueryFinalInfo {
    QueryFinalInfo {
        tokens_used: TokenUsage {
            prompt_tokens_used: value.tokens_used.prompt_tokens_used,
            cached_tokens_used: value.tokens_used.cached_tokens_used,
            completion_tokens_used: value.tokens_used.completion_tokens_used,
            reasoning_tokens_used: value.tokens_used.reasoning_tokens_used,
            total_tokens_used: value.tokens_used.total_tokens_used,
        },
        worker_debug: value.worker_debug.map(bytes_to_lossy_string),
        proxy_debug: value.proxy_debug.map(bytes_to_lossy_string),
        proxy_start_time: value.proxy_start_time,
        proxy_end_time: value.proxy_end_time,
        worker_start_time: value.worker_start_time,
        worker_end_time: value.worker_end_time,
    }
}

/// Debug strings are proxy-provided; keep them readable even if they are not UTF-8.
fn bytes_to_lossy_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}
