//! RA-TLS transport setup.
//!
//! Cocoon proxies speak TLS with a TEE/RA-TLS-oriented certificate flow. This
//! prototype creates an ephemeral Ed25519 client certificate and deliberately
//! skips server certificate verification because full TEE quote validation is
//! outside the current scope. The resulting `RatlsStream` is still encrypted and
//! is used as the transport for Cocoon session frames.

use std::fmt;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use rcgen::{CertificateParams, KeyPair};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error, SignatureScheme, StreamOwned,
};

/// TLS stream plus small metadata useful for startup logging.
pub struct RatlsStream {
    inner: StreamOwned<ClientConnection, TcpStream>,
    server_cert_der_len: usize,
}

impl RatlsStream {
    /// Returns the DER length of the first server certificate, or zero if none.
    #[must_use]
    pub const fn server_cert_der_len(&self) -> usize {
        self.server_cert_der_len
    }

    pub(crate) fn read_timeout(&self) -> std::io::Result<Option<Duration>> {
        self.inner.sock.read_timeout()
    }

    pub(crate) fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.inner.sock.set_read_timeout(timeout)
    }
}

impl std::io::Read for RatlsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl std::io::Write for RatlsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Opens the RA-TLS-like client connection over an already connected TCP stream.
///
/// # Errors
///
/// Returns an error if the ephemeral client certificate cannot be generated, the
/// rustls client configuration cannot be built, or the TLS handshake fails.
pub fn connect(stream: TcpStream) -> Result<RatlsStream> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (cert, key) = generate_ephemeral_ed25519_cert()?;

    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoServerCertVerification))
        .with_client_auth_cert(vec![cert], key)
        .context("build rustls client config with client cert")?;
    config.enable_sni = false;

    let server_name = ServerName::try_from("cocoon.local").context("build server name")?;
    let conn = ClientConnection::new(Arc::new(config), server_name).context("create TLS client")?;
    let mut inner = StreamOwned::new(conn, stream);

    while inner.conn.is_handshaking() {
        inner
            .conn
            .complete_io(&mut inner.sock)
            .context("complete TLS handshake")?;
    }

    let server_cert_der_len = inner
        .conn
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map_or(0, |cert| cert.len());

    Ok(RatlsStream {
        inner,
        server_cert_der_len,
    })
}

/// Generates the short-lived self-signed client certificate used for this run.
fn generate_ephemeral_ed25519_cert() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .context("generate ephemeral Ed25519 key pair")?;
    let params = CertificateParams::new(vec!["rocoon.local".to_string()])
        .context("build self-signed cert params")?;
    let cert = params
        .self_signed(&key_pair)
        .context("create self-signed client cert")?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    Ok((cert_der, key_der))
}

/// Placeholder verifier used until real RA-TLS quote verification is implemented.
#[derive(Clone)]
struct NoServerCertVerification;

impl fmt::Debug for NoServerCertVerification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NoServerCertVerification")
    }
}

impl ServerCertVerifier for NoServerCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}
