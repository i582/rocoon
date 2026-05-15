//! Cocoon TCP session framing.
//!
//! After `PoW` and RA-TLS, Cocoon uses a compact frame protocol with send/receive
//! sequence numbers and TL packets inside each frame. This module owns that
//! framing layer and provides two request styles: classic `tcp.query` for
//! metadata/auth and raw `tcp.packet` streaming for `client.runQueryEx`.

use std::io::{Read, Write};

use anyhow::{Context, Result};
use rand::Rng;
use rand::RngCore;
use tl_proto::{TlRead, TlWrite};

use crate::cocoon::{self, RunQueryOptions};
use crate::debug_log::{escaped_preview, short_request_id};

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
#[allow(dead_code)]
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

/// Aggregated result of one `client.runQueryEx` call.
pub struct RunQueryOutput {
    /// First answer packet containing the encoded HTTP response head.
    pub response_head: Vec<u8>,
    /// Additional body chunks from subsequent answer part packets.
    pub payload_parts: Vec<Vec<u8>>,
}

/// One streamed `client.runQueryEx` event from Cocoon.
pub enum RunQueryEvent<'a> {
    /// First packet containing the encoded HTTP response head.
    ResponseHead(&'a [u8]),
    /// Additional body bytes from a subsequent answer part packet.
    PayloadPart(&'a [u8]),
}

impl<RW: Read + Write> Session<RW> {
    /// Starts a logical Cocoon session over the supplied transport.
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
                TcpPacket::Pong { .. }
                | TcpPacket::Packet { .. }
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
    pub fn run_client_query_ex(
        &mut self,
        model: &str,
        http_request_payload: &[u8],
        options: RunQueryOptions,
    ) -> Result<RunQueryOutput> {
        let mut response_head = None;
        let mut payload_parts = Vec::new();

        self.run_client_query_ex_stream(model, http_request_payload, options, |event| {
            match event {
                RunQueryEvent::ResponseHead(data) => {
                    response_head = Some(data.to_vec());
                }
                RunQueryEvent::PayloadPart(data) => {
                    payload_parts.push(data.to_vec());
                }
            }
            Ok(())
        })?;

        let response_head = response_head.context("missing client.queryAnswerEx")?;
        Ok(RunQueryOutput {
            response_head,
            payload_parts,
        })
    }

    /// Sends `client.runQueryEx` and forwards answer packets as they arrive.
    ///
    /// Callers receive the first encoded HTTP response head and every
    /// subsequent payload chunk before this method reads the next frame.
    pub fn run_client_query_ex_stream<F>(
        &mut self,
        model: &str,
        http_request_payload: &[u8],
        options: RunQueryOptions,
        mut on_event: F,
    ) -> Result<()>
    where
        F: for<'a> FnMut(RunQueryEvent<'a>) -> Result<()>,
    {
        let mut request_id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut request_id);

        let request =
            cocoon::encode_run_query_ex(model, http_request_payload, &request_id, options);
        let packet = tl_proto::serialize(TcpPacketOut { data: &request });
        let request_id_log = short_request_id(&request_id);
        eprintln!(
            "[rocoon][runQueryEx:{request_id_log}] send model={model} http_request_len={} max_coefficient={} max_tokens={} timeout={:.3}",
            http_request_payload.len(),
            options.max_coefficient,
            options.max_tokens,
            options.timeout,
        );
        self.send_frame(&packet)
            .context("send client.runQueryEx tcp.packet")?;

        let mut seen_response_head = false;

        loop {
            let payload = self.recv_frame().context("receive tcp.packet response")?;
            let packet = tl_proto::deserialize::<TcpPacket>(&payload)
                .context("decode tcp packet while waiting for client.runQueryEx")?;
            if self.handle_run_query_packet(
                &packet,
                &request_id,
                &request_id_log,
                &mut seen_response_head,
                &mut on_event,
            )? {
                return Ok(());
            }
        }
    }

    fn handle_run_query_packet<F>(
        &mut self,
        packet: &TcpPacket<'_>,
        request_id: &[u8; 32],
        request_id_log: &str,
        seen_response_head: &mut bool,
        on_event: &mut F,
    ) -> Result<bool>
    where
        F: for<'a> FnMut(RunQueryEvent<'a>) -> Result<()>,
    {
        match packet {
            TcpPacket::Packet { data } => handle_run_query_answer(
                data,
                request_id,
                request_id_log,
                seen_response_head,
                on_event,
            ),
            TcpPacket::Ping { id } => {
                let pong = tl_proto::serialize(TcpPong { id: *id });
                self.send_frame(&pong).context("send tcp.pong")?;
                Ok(false)
            }
            TcpPacket::Pong { .. }
            | TcpPacket::QueryAnswer { .. }
            | TcpPacket::QueryError { .. } => Ok(false),
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

fn handle_run_query_answer<F>(
    data: &[u8],
    request_id: &[u8; 32],
    request_id_log: &str,
    seen_response_head: &mut bool,
    on_event: &mut F,
) -> Result<bool>
where
    F: for<'a> FnMut(RunQueryEvent<'a>) -> Result<()>,
{
    let Ok(answer) = cocoon::decode_query_answer_ex(data) else {
        eprintln!(
            "[rocoon][runQueryEx:{request_id_log}] ignored tcp.packet data_len={} decode=not_query_answer preview=\"{}\"",
            data.len(),
            escaped_preview(data),
        );
        return Ok(false);
    };
    match answer {
        cocoon::QueryAnswerEx::Answer {
            request_id: got_id,
            answer,
            final_info,
            ..
        } if got_id == request_id => {
            if *seen_response_head {
                anyhow::bail!("duplicate client.queryAnswerEx");
            }
            *seen_response_head = true;
            log_query_answer(
                "client.queryAnswerEx",
                request_id_log,
                answer,
                final_info.as_ref(),
            );
            on_event(RunQueryEvent::ResponseHead(answer)).context("handle client.queryAnswerEx")?;
            Ok(final_info.is_some())
        }
        cocoon::QueryAnswerEx::Part {
            request_id: got_id,
            answer,
            final_info,
            ..
        } if got_id == request_id => {
            if !*seen_response_head {
                anyhow::bail!("received client.queryAnswerPartEx before response head");
            }
            log_query_answer(
                "client.queryAnswerPartEx",
                request_id_log,
                answer,
                final_info.as_ref(),
            );
            on_event(RunQueryEvent::PayloadPart(answer))
                .context("handle client.queryAnswerPartEx")?;
            Ok(final_info.is_some())
        }
        cocoon::QueryAnswerEx::Error {
            request_id: got_id,
            error_code,
            error,
            final_info,
            ..
        } if got_id == request_id => {
            let error = std::str::from_utf8(error).unwrap_or("<non-utf8>");
            log_final_info(
                "client.queryAnswerErrorEx",
                request_id_log,
                final_info.as_ref(),
            );
            anyhow::bail!("client.queryAnswerErrorEx code={error_code}: {error}");
        }
        _ => Ok(false),
    }
}

fn log_query_answer(
    kind: &str,
    request_id: &str,
    answer: &[u8],
    final_info: Option<&cocoon::QueryFinalInfo<'_>>,
) {
    eprintln!(
        "[rocoon][runQueryEx:{request_id}] recv {kind} answer_len={} final={} preview=\"{}\"",
        answer.len(),
        final_info.is_some(),
        escaped_preview(answer),
    );
    log_final_info(kind, request_id, final_info);
}

fn log_final_info(kind: &str, request_id: &str, final_info: Option<&cocoon::QueryFinalInfo<'_>>) {
    let Some(final_info) = final_info else {
        return;
    };
    let tokens = final_info.tokens_used;
    eprintln!(
        "[rocoon][runQueryEx:{request_id}] {kind} final_info prompt={} cached={} completion={} reasoning={} total={}",
        tokens.prompt_tokens_used,
        tokens.cached_tokens_used,
        tokens.completion_tokens_used,
        tokens.reasoning_tokens_used,
        tokens.total_tokens_used,
    );
}
