//! Small helpers for bounded wire-level debug logs.
//!
//! Completion requests can contain large prompts and binary TL objects. These
//! helpers keep logs readable by escaping non-printable bytes and truncating
//! previews before they can flood the terminal.

const PREVIEW_BYTES: usize = 512;

/// Returns a printable, bounded preview of raw bytes.
pub fn escaped_preview(bytes: &[u8]) -> String {
    let mut preview = String::new();
    for escaped in bytes
        .iter()
        .take(PREVIEW_BYTES)
        .flat_map(|byte| byte.escape_ascii())
    {
        preview.push(char::from(escaped));
    }
    if bytes.len() > PREVIEW_BYTES {
        preview.push_str("...");
    }
    preview
}

/// Returns a short hex prefix for a 32-byte Cocoon request id.
pub fn short_request_id(request_id: &[u8; 32]) -> String {
    let mut out = String::with_capacity(16);
    for byte in request_id.iter().take(8).copied() {
        push_hex_byte(&mut out, byte);
    }
    out
}

/// Formats HTTP headers as a compact one-line summary.
pub fn headers_summary(headers: &[(String, String)]) -> String {
    let mut summary = String::new();
    for (index, (name, value)) in headers.iter().enumerate() {
        if index > 0 {
            summary.push_str("; ");
        }
        summary.push_str(name);
        summary.push('=');
        summary.push_str(value);
    }
    summary
}

fn push_hex_byte(out: &mut String, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(char::from(HEX[usize::from(byte >> 4)]));
    out.push(char::from(HEX[usize::from(byte & 0x0f)]));
}
