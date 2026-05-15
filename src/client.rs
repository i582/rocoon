//! High-level Cocoon client orchestration.
//!
//! This module ties the lower protocol layers together: TCP connect, `PoW`,
//! RA-TLS, Cocoon session framing, proxy authorization, model discovery, and
//! inference requests. It exposes domain-level methods used by the local HTTP
//! server instead of leaking TL objects or frame handling into the API layer.

use std::net::{TcpStream, ToSocketAddrs};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::cocoon::{self, RunQueryOptions, WorkerInstanceV2, WorkerTypeV2};
use crate::config::RuntimeConfig;
use crate::debug_log::{escaped_preview, headers_summary};
use crate::pow;
use crate::ratls;
use crate::session::{RunQueryEvent, RunQueryOutput, Session};

/// Authenticated Cocoon proxy client.
///
/// A `CocoonClient` owns one live session to a selected proxy. If selected
/// calls fail, it can reconnect using the stored `RuntimeConfig`.
pub struct CocoonClient {
    session: Session<ratls::RatlsStream>,
    request_options: RunQueryOptions,
    proto_version: i32,
    config: RuntimeConfig,
}

/// OpenAI-style model metadata derived from `client.getWorkerTypesV2`.
pub struct ModelInfo {
    /// Model identifier, for example `Qwen/Qwen3-32B`.
    pub id: String,
    /// Available workers currently advertising this model.
    pub workers: Vec<WorkerInfo>,
}

/// Worker capacity and price metadata for one model.
pub struct WorkerInfo {
    /// Cocoon price coefficient advertised by the worker.
    pub coefficient: i32,
    /// Number of requests the worker reports as currently active.
    pub active_requests: i32,
    /// Worker-side concurrency limit.
    pub max_active_requests: i32,
}

/// HTTP response returned by Cocoon after an inference request.
///
/// Cocoon wraps the model API as an HTTP request/response transported inside
/// TL messages. This struct is the decoded response that the local server can
/// write back to OpenAI-compatible clients.
pub struct HttpExchange {
    /// Upstream HTTP status code.
    pub status_code: i32,
    /// Upstream HTTP reason phrase.
    pub reason: String,
    /// Upstream headers after TL decoding.
    pub headers: Vec<(String, String)>,
    /// Full response body assembled from head and streamed parts.
    pub payload: Vec<u8>,
}

/// Parameters for one Cocoon-backed completion request.
pub struct CompletionRun<'a> {
    /// Model name used by Cocoon to select worker type.
    pub model: &'a str,
    /// OpenAI-compatible path forwarded inside Cocoon's HTTP wrapper.
    pub path: &'a str,
    /// Sanitized JSON body forwarded to the worker.
    pub body: &'a [u8],
    /// Maximum accepted Cocoon worker price coefficient.
    pub max_coefficient: i32,
    /// Maximum tokens the worker may spend for this request.
    pub max_tokens: i32,
    /// Cocoon request timeout in seconds.
    pub timeout: f64,
}

/// HTTP response metadata returned before a streamed Cocoon response body.
pub struct HttpResponseHead {
    /// Upstream HTTP status code.
    pub status_code: i32,
    /// Upstream HTTP reason phrase.
    pub reason: String,
    /// Upstream headers after TL decoding.
    pub headers: Vec<(String, String)>,
}

/// One HTTP-level streaming event decoded from Cocoon answer packets.
pub enum HttpStreamEvent<'a> {
    /// Upstream HTTP status line and headers from the first answer packet.
    ResponseHead(HttpResponseHead),
    /// Upstream response body bytes from the head payload or later part packets.
    PayloadPart(&'a [u8]),
}

impl CocoonClient {
    /// Opens and authorizes a full Cocoon proxy connection.
    ///
    /// The handshake sequence is:
    /// TCP connect -> Cocoon `PoW` -> RA-TLS -> `tcp.connect` session ->
    /// `client.connectToProxy` -> `client.authorizeWithProxyShort`.
    pub fn connect(config: &RuntimeConfig) -> Result<Self> {
        let addr = &config.proxy_addr;
        println!("connecting to Cocoon proxy at {addr}");
        let socket_addr = addr
            .to_socket_addrs()
            .with_context(|| format!("resolve {addr}"))?
            .next()
            .with_context(|| format!("no socket addresses for {addr}"))?;

        let mut tcp = TcpStream::connect_timeout(&socket_addr, config.connect_timeout)
            .with_context(|| format!("connect TCP to {socket_addr} (from {addr})"))?;
        tcp.set_nodelay(true).context("set TCP_NODELAY")?;

        let pow = pow::handshake(&mut tcp).context("Cocoon TCP PoW handshake")?;
        println!(
            "pow solved: difficulty={} nonce={} elapsed_ms={}",
            pow.difficulty,
            pow.nonce,
            pow.elapsed.as_millis()
        );

        let tls = ratls::connect(tcp).context("Cocoon RA-TLS handshake")?;
        println!(
            "tls connected: server_cert_der_len={}",
            tls.server_cert_der_len()
        );

        let (mut session, connected) =
            Session::connect(tls).context("Cocoon tcp.connect session handshake")?;
        println!("session connected: id={}", connected.id);

        let proto_version = authorize(&mut session, config)?;

        Ok(Self {
            session,
            request_options: RunQueryOptions {
                max_coefficient: config.max_coefficient,
                max_tokens: config.max_tokens,
                timeout: config.request_timeout * 0.95,
                min_config_version: config.min_config_version,
                public_key: None,
            },
            proto_version,
            config: config.clone(),
        })
    }

    /// Returns the current model/worker list from the proxy.
    ///
    /// This powers `/v1/models`. A reconnect is attempted once because metadata
    /// calls are cheap and stale sessions are common after proxy-side closes.
    pub fn get_worker_types_v2(&mut self) -> Result<Vec<ModelInfo>> {
        let request = cocoon::encode_get_worker_types_v2();
        let response = match self.session.make_request(&request) {
            Ok(response) => response,
            Err(error) => {
                eprintln!("client.getWorkerTypesV2 failed, reconnecting: {error:#}");
                self.reconnect()
                    .context("reconnect after getWorkerTypesV2 failure")?;
                self.session
                    .make_request(&request)
                    .context("client.getWorkerTypesV2 after reconnect")?
            }
        };
        let response = cocoon::decode_worker_types_v2(&response)?;
        Ok(response.types.iter().map(model_info_from_tl).collect())
    }

    /// Runs an OpenAI-compatible completion request through Cocoon.
    ///
    /// `body` is already sanitized JSON from the local HTTP layer. The method
    /// wraps it into Cocoon's internal `http.request`, sends `client.runQueryEx`,
    /// gathers all answer parts, and decodes Cocoon's `http.response`.
    pub fn run_chat_completion(&mut self, request: &CompletionRun<'_>) -> Result<HttpExchange> {
        let options =
            self.query_options(request.max_coefficient, request.max_tokens, request.timeout);

        let headers = json_request_headers(request.body.len());
        let http_request =
            cocoon::encode_http_request("POST", request.path, &headers, request.body);
        eprintln!(
            "[rocoon][completion] send model={} path={} body_len={} max_coefficient={} max_tokens={} timeout={:.3} body_preview=\"{}\"",
            request.model,
            request.path,
            request.body.len(),
            request.max_coefficient,
            request.max_tokens,
            request.timeout,
            escaped_preview(request.body),
        );
        let output = match self
            .session
            .run_client_query_ex(request.model, &http_request, options)
        {
            Ok(output) => output,
            Err(error) => {
                eprintln!("client.runQueryEx failed, reconnecting for next request: {error:#}");
                if let Err(reconnect_error) = self.reconnect() {
                    eprintln!("reconnect after runQueryEx failure failed: {reconnect_error:#}");
                }
                return Err(error).context("client.runQueryEx");
            }
        };
        http_exchange_from_output(output)
    }

    /// Runs a completion request and forwards Cocoon body parts as they arrive.
    pub fn run_chat_completion_stream<F>(
        &mut self,
        request: &CompletionRun<'_>,
        mut on_event: F,
    ) -> Result<()>
    where
        F: for<'a> FnMut(HttpStreamEvent<'a>) -> Result<()>,
    {
        let options =
            self.query_options(request.max_coefficient, request.max_tokens, request.timeout);
        let headers = json_request_headers(request.body.len());
        let http_request =
            cocoon::encode_http_request("POST", request.path, &headers, request.body);
        log_completion_request(request);

        let result = self.session.run_client_query_ex_stream(
            request.model,
            &http_request,
            options,
            |event| {
                match event {
                    RunQueryEvent::ResponseHead(data) => {
                        forward_response_head(data, &mut on_event)?;
                    }
                    RunQueryEvent::PayloadPart(data) => {
                        on_event(HttpStreamEvent::PayloadPart(data))?;
                    }
                }
                Ok(())
            },
        );
        if let Err(error) = result {
            eprintln!("client.runQueryEx stream failed, reconnecting for next request: {error:#}");
            if let Err(reconnect_error) = self.reconnect() {
                eprintln!(
                    "reconnect after streaming runQueryEx failure failed: {reconnect_error:#}"
                );
            }
            return Err(error).context("client.runQueryEx stream");
        }
        Ok(())
    }

    /// Builds `client.runQueryEx` options for one completion request.
    fn query_options(
        &self,
        max_coefficient: i32,
        max_tokens: i32,
        timeout: f64,
    ) -> RunQueryOptions {
        let mut options = self.request_options;
        options.max_coefficient = max_coefficient;
        options.max_tokens = max_tokens;
        options.timeout = timeout * 0.95;
        // C++ sets flag bit 1 for proto >= 3 even when the request is not
        // encrypted. The zero key preserves that wire shape.
        options.public_key = (self.proto_version >= 3).then_some([0u8; 32]);
        options
    }

    /// Replaces the current live session with a fresh authorized connection.
    fn reconnect(&mut self) -> Result<()> {
        let replacement = Self::connect(&self.config)?;
        *self = replacement;
        Ok(())
    }
}

fn log_completion_request(request: &CompletionRun<'_>) {
    eprintln!(
        "[rocoon][completion] send model={} path={} body_len={} max_coefficient={} max_tokens={} timeout={:.3} body_preview=\"{}\"",
        request.model,
        request.path,
        request.body.len(),
        request.max_coefficient,
        request.max_tokens,
        request.timeout,
        escaped_preview(request.body),
    );
}

fn forward_response_head<F>(data: &[u8], on_event: &mut F) -> Result<()>
where
    F: for<'a> FnMut(HttpStreamEvent<'a>) -> Result<()>,
{
    let response = cocoon::decode_http_response(data)?;
    let head = http_response_head_from_response(&response)?;
    eprintln!(
        "[rocoon][http.stream.response] status={} reason=\"{}\" headers=\"{}\" head_payload_len={} head_payload_preview=\"{}\"",
        head.status_code,
        head.reason,
        headers_summary(&head.headers),
        response.payload.len(),
        escaped_preview(response.payload),
    );
    on_event(HttpStreamEvent::ResponseHead(head))?;
    if !response.payload.is_empty() {
        on_event(HttpStreamEvent::PayloadPart(response.payload))?;
    }
    Ok(())
}

/// Minimal HTTP headers required by Cocoon's internal HTTP request wrapper.
///
/// User-agent, auth, and other local UI headers are intentionally not forwarded
/// because the Cocoon worker only needs the JSON payload and its length.
fn json_request_headers(body_len: usize) -> Vec<(&'static str, String)> {
    vec![
        ("Content-Type", "application/json".to_string()),
        ("Content-Length", body_len.to_string()),
    ]
}

/// Performs Cocoon proxy authorization and returns the negotiated protocol version.
///
/// The current prototype supports short authorization with a local secret. Long
/// authorization requires on-chain registration/top-up and is intentionally not
/// implemented here.
fn authorize(session: &mut Session<ratls::RatlsStream>, config: &RuntimeConfig) -> Result<i32> {
    println!("authenticating as {}", config.owner_address);
    let request = cocoon::encode_connect_to_proxy(&config.owner_address, config.min_config_version);
    let response = session
        .make_request(&request)
        .context("client.connectToProxy")?;
    let connected_to_proxy = cocoon::decode_connected_to_proxy(&response)?;

    match connected_to_proxy.auth {
        cocoon::ProxyAuth::Short { secret_hash, .. } => {
            let Some(secret) = config.client_secret.as_deref() else {
                anyhow::bail!("short auth requires client.secret in TOML or COCOON_CLIENT_SECRET");
            };
            verify_secret_hash(secret, secret_hash)?;

            let request = cocoon::encode_authorize_with_proxy_short(secret);
            let response = session
                .make_request(&request)
                .context("client.authorizeWithProxyShort")?;
            let auth = cocoon::decode_authorization_with_proxy(&response)?;
            print_authorization_result(&auth)?;
        }
        cocoon::ProxyAuth::Long { nonce } => {
            anyhow::bail!(
                "auth: long nonce={nonce}; on-chain register is required before Rust can serve requests"
            );
        }
    }

    Ok(connected_to_proxy.params.proto_version.unwrap_or(0))
}

/// Checks that the configured secret matches the proxy-provided challenge hash.
fn verify_secret_hash(secret: &str, expected: &[u8; 32]) -> Result<()> {
    let digest = Sha256::digest(secret.as_bytes());
    if digest.as_slice() != expected {
        anyhow::bail!("client secret hash does not match proxy challenge");
    }
    Ok(())
}

/// Converts the proxy authorization result into either a concise log or error.
fn print_authorization_result(auth: &cocoon::AuthorizationWithProxy<'_>) -> Result<()> {
    match auth {
        cocoon::AuthorizationWithProxy::Success {
            signed_payment: _,
            tokens_committed_to_db,
            max_tokens,
        } => {
            println!(
                "auth success: tokens_committed_to_db={tokens_committed_to_db} max_tokens={max_tokens}"
            );
            Ok(())
        }
        cocoon::AuthorizationWithProxy::Failed { error_code, error } => {
            anyhow::bail!("auth failed: code={error_code} error={}", utf8(error)?)
        }
    }
}

/// Converts Cocoon's framed response into a local HTTP exchange.
///
/// The first `client.queryAnswerEx` carries the HTTP response head. Subsequent
/// `client.queryAnswerPartEx` packets carry additional response body bytes.
fn http_exchange_from_output(output: RunQueryOutput) -> Result<HttpExchange> {
    let response = cocoon::decode_http_response(&output.response_head)?;
    let head = http_response_head_from_response(&response)?;
    let part_count = output.payload_parts.len();
    let part_bytes = output.payload_parts.iter().map(Vec::len).sum::<usize>();
    eprintln!(
        "[rocoon][http.response] status={} reason=\"{}\" headers=\"{}\" head_payload_len={} part_count={} part_bytes={} head_payload_preview=\"{}\"",
        head.status_code,
        head.reason,
        headers_summary(&head.headers),
        response.payload.len(),
        part_count,
        part_bytes,
        escaped_preview(response.payload),
    );
    let mut payload = response.payload.to_vec();
    for part in output.payload_parts {
        payload.extend(part);
    }

    Ok(HttpExchange {
        status_code: head.status_code,
        reason: head.reason,
        headers: head.headers,
        payload,
    })
}

/// Converts a decoded Cocoon `http.response` into owned response metadata.
fn http_response_head_from_response(
    response: &cocoon::HttpResponse<'_>,
) -> Result<HttpResponseHead> {
    Ok(HttpResponseHead {
        status_code: response.status_code,
        reason: utf8(response.reason)?.to_string(),
        headers: response
            .headers
            .iter()
            .map(|header| {
                Ok((
                    utf8(header.name)?.to_string(),
                    utf8(header.value)?.to_string(),
                ))
            })
            .collect::<Result<_>>()?,
    })
}

/// Converts one TL worker type entry into API-facing model metadata.
fn model_info_from_tl(value: &WorkerTypeV2<'_>) -> ModelInfo {
    ModelInfo {
        id: String::from_utf8_lossy(value.name).into_owned(),
        workers: value.workers.iter().map(worker_info_from_tl).collect(),
    }
}

/// Converts one TL worker entry into API-facing worker metadata.
const fn worker_info_from_tl(value: &WorkerInstanceV2) -> WorkerInfo {
    WorkerInfo {
        coefficient: value.coefficient,
        active_requests: value.active_requests,
        max_active_requests: value.max_active_requests,
    }
}

/// Decodes a TL byte string that must contain UTF-8 text.
fn utf8(bytes: &[u8]) -> Result<&str> {
    std::str::from_utf8(bytes).context("decode TL string as UTF-8")
}
