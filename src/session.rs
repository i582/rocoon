use std::io::{Read, Write};

use anyhow::{Context, Result, anyhow};
use rand::Rng;
use rand::RngCore;
use tl_proto::{TlRead, TlWrite};

use crate::cocoon::{self, OwnedFinalInfo, RunQueryOptions};

const MAX_FRAME_SIZE: u32 = 1 << 20;

#[derive(TlWrite)]
#[tl(boxed, id = 0xa57c4261)]
struct TcpConnect {
    id: i64,
}

#[derive(Debug, TlRead)]
#[tl(boxed, id = 0x636d41d6)]
struct TcpConnectedPacket {
    id: i64,
}

#[derive(TlWrite)]
#[tl(boxed, id = 0x3af51908)]
struct TcpQuery<'a> {
    id: i64,
    data: &'a [u8],
}

#[derive(TlWrite)]
#[tl(boxed, id = 0x0bd4302c)]
struct TcpPong {
    id: i64,
}

#[derive(TlWrite)]
#[tl(boxed, id = 0x9c17baf8)]
struct TcpPacketOut<'a> {
    data: &'a [u8],
}

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

pub struct Session<RW> {
    io: RW,
    send_seqno: u32,
    recv_seqno: u32,
}

pub struct TcpConnected {
    pub id: i64,
}

pub struct RunQueryOutput {
    pub response_head: Vec<u8>,
    pub payload_parts: Vec<Vec<u8>>,
    pub final_info: Option<OwnedFinalInfo>,
}

impl<RW: Read + Write> Session<RW> {
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
            return Err(anyhow!(
                "tcp.connected id mismatch: got {}, expected {id}",
                connected.id
            ));
        }

        Ok((session, TcpConnected { id }))
    }

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
                    return Err(anyhow!("tcp.queryError code={code}: {message}"));
                }
                TcpPacket::Ping { id } => {
                    let pong = tl_proto::serialize(TcpPong { id });
                    self.send_frame(&pong).context("send tcp.pong")?;
                }
                TcpPacket::Pong { .. } => {}
                TcpPacket::Packet { .. } => {}
                TcpPacket::QueryAnswer { .. } | TcpPacket::QueryError { .. } => {}
            }
        }
    }

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
        if std::env::var("ROCOON_DUMP_TL").is_ok() {
            eprintln!("rocoon client.runQueryEx tl: {}", hex::encode(&request));
        }
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
                                return Err(anyhow!("duplicate client.queryAnswerEx"));
                            }
                            response_head = Some(answer.to_vec());
                            if let Some(final_info) = final_info {
                                return Ok(RunQueryOutput {
                                    response_head: response_head.unwrap(),
                                    payload_parts,
                                    final_info: Some(final_info.to_owned()),
                                });
                            }
                        }
                        cocoon::QueryAnswerEx::Part {
                            request_id: got_id,
                            answer,
                            final_info,
                            ..
                        } if got_id == &request_id => {
                            if response_head.is_none() {
                                return Err(anyhow!(
                                    "received client.queryAnswerPartEx before response head"
                                ));
                            }
                            payload_parts.push(answer.to_vec());
                            if let Some(final_info) = final_info {
                                return Ok(RunQueryOutput {
                                    response_head: response_head.unwrap(),
                                    payload_parts,
                                    final_info: Some(final_info.to_owned()),
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
                            return Err(anyhow!(
                                "client.queryAnswerErrorEx code={error_code}: {error}"
                            ));
                        }
                        _ => {}
                    }
                }
                TcpPacket::Ping { id } => {
                    let pong = tl_proto::serialize(TcpPong { id });
                    self.send_frame(&pong).context("send tcp.pong")?;
                }
                TcpPacket::Pong { .. } => {}
                TcpPacket::QueryAnswer { .. } | TcpPacket::QueryError { .. } => {}
            }
        }
    }

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

    fn recv_frame(&mut self) -> Result<Vec<u8>> {
        let mut header = [0u8; 8];
        self.io
            .read_exact(&mut header)
            .context("read frame header")?;

        let size = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let seqno = u32::from_le_bytes(header[4..8].try_into().unwrap());

        if seqno != self.recv_seqno {
            return Err(anyhow!(
                "unexpected frame seqno {seqno}, expected {}",
                self.recv_seqno
            ));
        }
        self.recv_seqno = self
            .recv_seqno
            .checked_add(1)
            .context("recv seqno overflow")?;

        if size > MAX_FRAME_SIZE {
            return Err(anyhow!("frame too large: {size} bytes"));
        }

        let mut payload = vec![0u8; size as usize];
        self.io
            .read_exact(&mut payload)
            .context("read frame payload")?;
        Ok(payload)
    }
}
