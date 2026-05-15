use std::net::{TcpStream, ToSocketAddrs};

use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};

use crate::cocoon::{self, RunQueryOptions, WorkerInstanceV2, WorkerTypeV2};
use crate::config::RuntimeConfig;
use crate::pow;
use crate::ratls;
use crate::session::{RunQueryOutput, Session};

pub struct CocoonClient {
    session: Session<ratls::RatlsStream>,
    request_options: RunQueryOptions,
    proto_version: i32,
    config: RuntimeConfig,
}

pub struct ModelInfo {
    pub id: String,
    pub workers: Vec<WorkerInfo>,
}

pub struct WorkerInfo {
    pub coefficient: i32,
    pub active_requests: i32,
    pub max_active_requests: i32,
}

pub struct HttpExchange {
    pub status_code: i32,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub payload: Vec<u8>,
}

impl CocoonClient {
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

    pub fn run_chat_completion(
        &mut self,
        model: &str,
        path: &str,
        body: &[u8],
        max_coefficient: i32,
        max_tokens: i32,
        timeout: f64,
    ) -> Result<HttpExchange> {
        let mut options = self.request_options;
        options.max_coefficient = max_coefficient;
        options.max_tokens = max_tokens;
        options.timeout = timeout * 0.95;
        options.public_key = (self.proto_version >= 3).then_some([0u8; 32]);

        let http_request =
            cocoon::encode_http_request("POST", path, json_request_headers(body.len()), body);
        let output = match self
            .session
            .run_client_query_ex(model, &http_request, options)
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

    fn reconnect(&mut self) -> Result<()> {
        let replacement = Self::connect(&self.config)?;
        *self = replacement;
        Ok(())
    }
}

fn json_request_headers(body_len: usize) -> Vec<(&'static str, String)> {
    vec![
        ("Content-Type", "application/json".to_string()),
        ("Content-Length", body_len.to_string()),
    ]
}

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
                bail!("short auth requires client.secret in TOML or COCOON_CLIENT_SECRET");
            };
            verify_secret_hash(secret, secret_hash)?;

            let request = cocoon::encode_authorize_with_proxy_short(secret);
            let response = session
                .make_request(&request)
                .context("client.authorizeWithProxyShort")?;
            let auth = cocoon::decode_authorization_with_proxy(&response)?;
            print_authorization_result(auth)?;
        }
        cocoon::ProxyAuth::Long { nonce } => {
            bail!(
                "auth: long nonce={nonce}; on-chain register is required before Rust can serve requests"
            );
        }
    }

    Ok(connected_to_proxy.params.proto_version.unwrap_or(0))
}

fn verify_secret_hash(secret: &str, expected: &[u8; 32]) -> Result<()> {
    let digest = Sha256::digest(secret.as_bytes());
    if digest.as_slice() == expected {
        Ok(())
    } else {
        Err(anyhow!("client secret hash does not match proxy challenge"))
    }
}

fn print_authorization_result(auth: cocoon::AuthorizationWithProxy<'_>) -> Result<()> {
    match auth {
        cocoon::AuthorizationWithProxy::Success {
            signed_payment: _,
            tokens_committed_to_db,
            max_tokens,
        } => {
            println!(
                "auth success: tokens_committed_to_db={} max_tokens={}",
                tokens_committed_to_db, max_tokens
            );
            Ok(())
        }
        cocoon::AuthorizationWithProxy::Failed { error_code, error } => {
            bail!("auth failed: code={} error={}", error_code, utf8(error)?)
        }
    }
}

fn http_exchange_from_output(output: RunQueryOutput) -> Result<HttpExchange> {
    let response = cocoon::decode_http_response(&output.response_head)?;
    let mut payload = response.payload.to_vec();
    for part in output.payload_parts {
        payload.extend(part);
    }

    Ok(HttpExchange {
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
        payload,
    })
}

fn model_info_from_tl(value: &WorkerTypeV2<'_>) -> ModelInfo {
    ModelInfo {
        id: String::from_utf8_lossy(value.name).into_owned(),
        workers: value.workers.iter().map(worker_info_from_tl).collect(),
    }
}

fn worker_info_from_tl(value: &WorkerInstanceV2) -> WorkerInfo {
    WorkerInfo {
        coefficient: value.coefficient,
        active_requests: value.active_requests,
        max_active_requests: value.max_active_requests,
    }
}

fn utf8(bytes: &[u8]) -> Result<&str> {
    std::str::from_utf8(bytes).context("decode TL string as UTF-8")
}
