//! Cocoon TCP proof-of-work handshake.
//!
//! Before the RA-TLS handshake, the proxy sends a small challenge containing a
//! salt and target difficulty. The client must find a nonce whose SHA-256 hash
//! has enough leading zero bits and send that nonce back. This is a lightweight
//! anti-abuse gate before the expensive secure session setup.

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

const POW_SIMPLE_MAGIC: u32 = 0x418e_1291;
const POW_SIMPLE_RESPONSE_MAGIC: u32 = 0x0182_7319;

/// Timing and difficulty information for a solved `PoW` challenge.
pub struct PowStats {
    /// Difficulty requested by the proxy, measured in leading zero bits.
    pub difficulty: i32,
    /// Nonce that satisfied the challenge.
    pub nonce: u64,
    /// Local time spent solving the challenge.
    pub elapsed: Duration,
}

/// Parsed proxy challenge.
struct Challenge {
    difficulty: i32,
    salt: [u8; 16],
}

/// Completes the proxy `PoW` exchange on an open TCP stream.
///
/// # Errors
///
/// Returns an error if the proxy challenge cannot be read, contains an
/// unexpected magic/difficulty, or the solved nonce cannot be written back.
pub fn handshake<RW: Read + Write>(io: &mut RW) -> Result<PowStats> {
    let challenge = read_challenge(io)?;
    let start = Instant::now();
    let nonce = solve(&challenge);
    let elapsed = start.elapsed();
    send_response(io, nonce)?;

    Ok(PowStats {
        difficulty: challenge.difficulty,
        nonce,
        elapsed,
    })
}

/// Reads and validates the fixed-size `PoW` challenge.
fn read_challenge<R: Read>(reader: &mut R) -> Result<Challenge> {
    let mut buf = [0u8; 24];
    reader
        .read_exact(&mut buf)
        .context("read 24-byte PoW challenge")?;

    let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if magic != POW_SIMPLE_MAGIC {
        anyhow::bail!("unexpected PoW magic 0x{magic:08x}, expected 0x{POW_SIMPLE_MAGIC:08x}");
    }

    let difficulty = i32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if difficulty < 0 {
        anyhow::bail!("negative PoW difficulty {difficulty}");
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&buf[8..24]);

    Ok(Challenge { difficulty, salt })
}

/// Sends the solved nonce back to the proxy.
fn send_response<W: Write>(writer: &mut W, nonce: u64) -> Result<()> {
    let mut buf = [0u8; 12];
    buf[0..4].copy_from_slice(&POW_SIMPLE_RESPONSE_MAGIC.to_le_bytes());
    buf[4..12].copy_from_slice(&nonce.to_le_bytes());
    writer.write_all(&buf).context("send PoW response")
}

/// Brute-forces a nonce that satisfies the challenge difficulty.
fn solve(challenge: &Challenge) -> u64 {
    let mut data = [0u8; 24];
    data[0..16].copy_from_slice(&challenge.salt);
    let difficulty =
        u32::try_from(challenge.difficulty).expect("validated non-negative PoW difficulty");

    let mut nonce = 0u64;
    loop {
        data[16..24].copy_from_slice(&nonce.to_le_bytes());
        let hash = Sha256::digest(data);
        if leading_zero_bits(&hash[..]) >= difficulty {
            return nonce;
        }
        nonce += 1;
    }
}

/// Counts leading zero bits in the first 64 bits of the SHA-256 digest.
fn leading_zero_bits(hash: &[u8]) -> u32 {
    let mut first = [0u8; 8];
    first.copy_from_slice(&hash[..8]);
    u64::from_le_bytes(first).leading_zeros()
}
