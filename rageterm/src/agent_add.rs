use std::io::{self, Read, Write};

use ssh_key::{Algorithm, EcdsaCurve, PrivateKey};
use thiserror::Error;
use zeroize::Zeroizing;

const SSH_AGENTC_ADD_IDENTITY: u8 = 17;
const SSH_AGENTC_ADD_ID_CONSTRAINED: u8 = 25;
const SSH_AGENT_SUCCESS: u8 = 6;
const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENT_CONSTRAIN_LIFETIME: u8 = 1;

const MAX_AGENT_REPLY: usize = 256 * 1024;

#[derive(Debug, Error)]
pub enum AgentAddError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[cfg_attr(windows, allow(dead_code))]
    #[error("$SSH_AUTH_SOCK is not set; start a real ssh-agent first")]
    NoAuthSock,
    #[error("not an OpenSSH private key: {0}")]
    NotOpenSsh(String),
    #[error("private key is encrypted; decrypt before storing in ragewarden")]
    EncryptedKey,
    #[error("unsupported key algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("ssh-agent rejected the request (code {0})")]
    AgentRejected(u8),
    #[error("agent: malformed reply ({0})")]
    BadReply(String),
    #[error("agent connection only supported on unix; named-pipe path TBD")]
    #[allow(dead_code)]
    UnsupportedPlatform,
}

pub struct AddOptions<'a> {
    pub plaintext: &'a Zeroizing<Vec<u8>>,

    pub comment: &'a str,

    pub lifetime_secs: Option<u32>,
}

pub struct AddOutcome {
    pub fingerprint: String,

    pub algorithm: String,

    pub lifetime_secs: Option<u32>,
}

pub fn add_to_agent(opts: AddOptions<'_>) -> Result<AddOutcome, AgentAddError> {
    let key = parse_openssh(opts.plaintext)?;
    let comment = if opts.comment.is_empty() {
        key.comment().to_string()
    } else {
        opts.comment.to_string()
    };

    let payload = encode_add_identity(&key, &comment, opts.lifetime_secs)?;
    let reply = send_to_agent(&payload)?;
    interpret_reply(&reply)?;

    let fingerprint = key
        .public_key()
        .fingerprint(ssh_key::HashAlg::Sha256)
        .to_string();
    let algorithm = key.algorithm().as_str().to_string();
    Ok(AddOutcome {
        fingerprint,
        algorithm,
        lifetime_secs: opts.lifetime_secs,
    })
}

fn parse_openssh(plaintext: &Zeroizing<Vec<u8>>) -> Result<PrivateKey, AgentAddError> {
    let s = std::str::from_utf8(plaintext)
        .map_err(|e| AgentAddError::NotOpenSsh(format!("plaintext is not utf-8: {e}")))?;
    let key = PrivateKey::from_openssh(s).map_err(|e| AgentAddError::NotOpenSsh(e.to_string()))?;
    if key.is_encrypted() {
        return Err(AgentAddError::EncryptedKey);
    }
    Ok(key)
}

/// The returned buffer holds `d`/`p`/`q` (RSA), the ed25519 seed, or the ECDSA
/// scalar in the clear -- it is the private key, byte for byte. It used to be a
/// bare `Vec<u8>` whose heap block was freed unwiped once the agent had it,
/// leaving a full copy of an SSH private key in whatever allocation reused the
/// page. `Zeroizing` wipes it on drop, including on every `?` return below.
fn encode_add_identity(
    key: &PrivateKey,
    comment: &str,
    lifetime_secs: Option<u32>,
) -> Result<Zeroizing<Vec<u8>>, AgentAddError> {
    let mut payload: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(8192));
    payload.push(if lifetime_secs.is_some() {
        SSH_AGENTC_ADD_ID_CONSTRAINED
    } else {
        SSH_AGENTC_ADD_IDENTITY
    });

    write_key_fields(&mut payload, key)?;
    write_string(&mut payload, comment.as_bytes());

    if let Some(secs) = lifetime_secs {
        payload.push(SSH_AGENT_CONSTRAIN_LIFETIME);
        payload.extend_from_slice(&secs.to_be_bytes());
    }

    Ok(payload)
}

fn write_key_fields(out: &mut Vec<u8>, key: &PrivateKey) -> Result<(), AgentAddError> {
    use ssh_key::private::KeypairData;

    let algo = key.algorithm();
    let kp = key.key_data();

    match (algo, kp) {
        (Algorithm::Ed25519, KeypairData::Ed25519(pair)) => {
            write_string(out, b"ssh-ed25519");
            write_string(out, pair.public.as_ref());

            let mut priv64: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(64));
            priv64.extend_from_slice(pair.private.as_ref());
            priv64.extend_from_slice(pair.public.as_ref());
            write_string(out, &priv64);
        }
        (Algorithm::Rsa { .. }, KeypairData::Rsa(rsa)) => {
            write_string(out, b"ssh-rsa");
            write_string(out, rsa.public.n.as_bytes());
            write_string(out, rsa.public.e.as_bytes());
            write_string(out, rsa.private.d.as_bytes());
            write_string(out, rsa.private.iqmp.as_bytes());
            write_string(out, rsa.private.p.as_bytes());
            write_string(out, rsa.private.q.as_bytes());
        }
        (Algorithm::Ecdsa { curve }, KeypairData::Ecdsa(ec)) => {
            let (name, ident) = match curve {
                EcdsaCurve::NistP256 => ("ecdsa-sha2-nistp256", "nistp256"),
                EcdsaCurve::NistP384 => ("ecdsa-sha2-nistp384", "nistp384"),
                EcdsaCurve::NistP521 => ("ecdsa-sha2-nistp521", "nistp521"),
            };
            write_string(out, name.as_bytes());
            write_string(out, ident.as_bytes());
            write_string(out, ec.public_key_bytes());
            write_mpint(out, ec.private_key_bytes());
        }
        (other, _) => {
            return Err(AgentAddError::UnsupportedAlgorithm(
                other.as_str().to_string(),
            ));
        }
    }
    Ok(())
}

fn write_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

fn write_mpint(out: &mut Vec<u8>, raw: &[u8]) {
    let mut start = 0usize;
    while start < raw.len() && raw[start] == 0 {
        start += 1;
    }
    let trimmed = &raw[start..];
    if trimmed.is_empty() {
        out.extend_from_slice(&0u32.to_be_bytes());
        return;
    }
    if trimmed[0] & 0x80 != 0 {
        let len = (trimmed.len() + 1) as u32;
        out.extend_from_slice(&len.to_be_bytes());
        out.push(0);
        out.extend_from_slice(trimmed);
    } else {
        out.extend_from_slice(&(trimmed.len() as u32).to_be_bytes());
        out.extend_from_slice(trimmed);
    }
}

fn interpret_reply(reply: &[u8]) -> Result<(), AgentAddError> {
    match reply.first().copied() {
        Some(SSH_AGENT_SUCCESS) => Ok(()),
        Some(SSH_AGENT_FAILURE) => Err(AgentAddError::AgentRejected(SSH_AGENT_FAILURE)),
        Some(other) => Err(AgentAddError::AgentRejected(other)),
        None => Err(AgentAddError::BadReply("empty body".into())),
    }
}

fn send_to_agent(payload: &[u8]) -> Result<Vec<u8>, AgentAddError> {
    let path = std::env::var("SSH_AUTH_SOCK").ok();
    send_via_socket(path.as_deref(), payload)
}

/// One request/reply in the ssh-agent framing (u32 big-endian length + body).
fn exchange<S: Read + Write>(sock: &mut S, payload: &[u8]) -> Result<Vec<u8>, AgentAddError> {
    let len = (payload.len() as u32).to_be_bytes();
    sock.write_all(&len)?;
    sock.write_all(payload)?;
    sock.flush()?;

    let mut len_buf = [0u8; 4];
    sock.read_exact(&mut len_buf)?;
    let reply_len = u32::from_be_bytes(len_buf) as usize;
    if reply_len == 0 || reply_len > MAX_AGENT_REPLY {
        return Err(AgentAddError::BadReply(format!(
            "reply length {reply_len} out of range"
        )));
    }
    let mut body = vec![0u8; reply_len];
    sock.read_exact(&mut body)?;
    Ok(body)
}

#[cfg(unix)]
fn send_via_socket(path: Option<&str>, payload: &[u8]) -> Result<Vec<u8>, AgentAddError> {
    use std::os::unix::net::UnixStream;
    use std::time::Duration;
    let path = path.ok_or(AgentAddError::NoAuthSock)?;
    let mut sock = UnixStream::connect(path)?;
    sock.set_read_timeout(Some(Duration::from_secs(10)))?;
    sock.set_write_timeout(Some(Duration::from_secs(10)))?;
    exchange(&mut sock, payload)
}

/// Windows OpenSSH's agent listens on a named pipe, which opens as a file.
#[cfg(windows)]
fn send_via_socket(path: Option<&str>, payload: &[u8]) -> Result<Vec<u8>, AgentAddError> {
    let path = path.unwrap_or(r"\\.\pipe\openssh-ssh-agent");
    let mut pipe = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?;
    exchange(&mut pipe, payload)
}

#[cfg(not(any(unix, windows)))]
fn send_via_socket(_path: Option<&str>, _payload: &[u8]) -> Result<Vec<u8>, AgentAddError> {
    Err(AgentAddError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_agent_exchange_frames_the_request_and_reads_one_reply() {
        let mut io = std::io::Cursor::new(Vec::new());
        io.get_mut().extend_from_slice(&[0, 0, 0, 1, 6]);
        struct Duplex {
            reply: std::io::Cursor<Vec<u8>>,
            sent: Vec<u8>,
        }
        impl Read for Duplex {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                self.reply.read(b)
            }
        }
        impl Write for Duplex {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                self.sent.extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut d = Duplex {
            reply: io,
            sent: Vec::new(),
        };
        assert_eq!(exchange(&mut d, &[17, 1]).unwrap(), vec![6]);
        assert_eq!(d.sent, vec![0, 0, 0, 2, 17, 1]);
    }

    #[test]
    fn write_string_prefixes_length() {
        let mut out = Vec::new();
        write_string(&mut out, b"abc");
        assert_eq!(out, vec![0, 0, 0, 3, b'a', b'b', b'c']);
    }

    #[test]
    fn write_string_empty() {
        let mut out = Vec::new();
        write_string(&mut out, b"");
        assert_eq!(out, vec![0, 0, 0, 0]);
    }

    #[test]
    fn write_mpint_zero() {
        let mut out = Vec::new();
        write_mpint(&mut out, &[0, 0, 0]);
        assert_eq!(out, vec![0, 0, 0, 0]);
    }

    #[test]
    fn write_mpint_high_bit_pads_with_zero() {
        let mut out = Vec::new();
        write_mpint(&mut out, &[0x80, 0x01]);
        assert_eq!(out, vec![0, 0, 0, 3, 0, 0x80, 0x01]);
    }

    #[test]
    fn write_mpint_low_bit_does_not_pad() {
        let mut out = Vec::new();
        write_mpint(&mut out, &[0x00, 0x40, 0x00]);
        assert_eq!(out, vec![0, 0, 0, 2, 0x40, 0x00]);
    }

    #[test]
    fn unsupported_algorithm_rejected() {
        let openssh = include_str!("agent_add_test_data/ed25519").to_string();
        let pt = Zeroizing::new(openssh.into_bytes());
        let key = parse_openssh(&pt).expect("parse");
        assert_eq!(key.algorithm().as_str(), "ssh-ed25519");
    }

    #[test]
    fn encode_ed25519_starts_with_add_identity_byte() {
        let openssh = include_str!("agent_add_test_data/ed25519").to_string();
        let pt = Zeroizing::new(openssh.into_bytes());
        let key = parse_openssh(&pt).expect("parse");
        let payload = encode_add_identity(&key, "test-comment", None).expect("encode");
        assert_eq!(payload[0], SSH_AGENTC_ADD_IDENTITY);

        let algo_len =
            u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]) as usize;
        assert_eq!(&payload[5..5 + algo_len], b"ssh-ed25519");
    }

    #[test]
    fn encode_with_lifetime_uses_constrained_opcode() {
        let openssh = include_str!("agent_add_test_data/ed25519").to_string();
        let pt = Zeroizing::new(openssh.into_bytes());
        let key = parse_openssh(&pt).expect("parse");
        let payload = encode_add_identity(&key, "test-comment", Some(60)).expect("encode");
        assert_eq!(payload[0], SSH_AGENTC_ADD_ID_CONSTRAINED);
        let last_five = &payload[payload.len() - 5..];
        assert_eq!(last_five[0], SSH_AGENT_CONSTRAIN_LIFETIME);
        assert_eq!(
            u32::from_be_bytes([last_five[1], last_five[2], last_five[3], last_five[4]]),
            60
        );
    }
}
