use std::io::{self, Write};
use std::process::Command;
use std::thread;
use std::time::Duration;

use ragewarden_core::Plaintext;
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum OutputError {
    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("clipboard: {0}")]
    Clipboard(String),

    #[error("exec child exited with status {0}")]
    #[allow(dead_code)]
    ExecFailed(i32),
}

pub const DEFAULT_CLIPBOARD_CLEAR_SECS: u64 = 30;

pub fn deliver_stdout(plaintext: Plaintext, append_newline: bool) -> Result<(), OutputError> {
    let mut out = io::stdout().lock();
    out.write_all(&plaintext)?;
    if append_newline {
        out.write_all(b"\n")?;
    }
    out.flush()?;
    drop(plaintext);
    Ok(())
}

pub fn deliver_reveal(plaintext: Plaintext) -> Result<(), OutputError> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    writeln!(out, "--- secret (press Enter to dismiss) ---")?;
    out.write_all(&plaintext)?;
    writeln!(out)?;
    writeln!(out, "----------------------------------------")?;
    out.flush()?;
    drop(plaintext);

    let mut buf = String::new();
    let _ = io::stdin().read_line(&mut buf);
    Ok(())
}

pub fn deliver_clipboard(
    plaintext: Plaintext,
    clear_after_secs: u64,
    expected_hash: &str,
) -> Result<(), OutputError> {
    let pt_str = std::str::from_utf8(&plaintext)
        .map_err(|e| OutputError::Clipboard(format!("plaintext is not utf-8: {e}")))?;

    let mut clip =
        arboard::Clipboard::new().map_err(|e| OutputError::Clipboard(format!("init: {e}")))?;
    // `set_text` takes `impl Into<Cow<'_, str>>`. Passing the borrowed `&str`
    // yields `Cow::Borrowed`, so no owned `String` of the secret is minted here;
    // the previous `pt_str.to_string()` left one on the heap with no `Drop` that
    // wiped it, outliving the `Zeroizing` plaintext it was copied from.
    clip.set_text(pt_str)
        .map_err(|e| OutputError::Clipboard(format!("set_text: {e}")))?;
    drop(plaintext);

    if clear_after_secs > 0 {
        spawn_clipboard_clear_helper(clear_after_secs, expected_hash)?;
    }
    Ok(())
}

fn spawn_clipboard_clear_helper(secs: u64, expected_hash: &str) -> Result<(), OutputError> {
    let exe = std::env::current_exe()?;
    let mut cmd = Command::new(exe);
    cmd.arg("__clipboard-clear-helper")
        .arg(secs.to_string())
        .arg(expected_hash);
    detach_stdio(&mut cmd);
    cmd.spawn()?;
    Ok(())
}

#[cfg(unix)]
fn detach_stdio(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    unsafe {
        cmd.pre_exec(|| {
            let _ = libc::setsid();
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn detach_stdio(cmd: &mut Command) {
    use std::process::Stdio;
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
}

pub fn run_clipboard_clear_helper(secs: u64, expected_hash: &str) -> Result<(), OutputError> {
    thread::sleep(Duration::from_secs(secs));
    let mut clip = match arboard::Clipboard::new() {
        Ok(c) => c,

        Err(_) => return Ok(()),
    };
    // Whatever is on the clipboard right now is very likely the secret we put
    // there; wrap it so the comparison copy is wiped when this returns.
    let cur = match clip.get_text() {
        Ok(s) => Zeroizing::new(s),
        Err(_) => return Ok(()),
    };
    if hex_sha256(cur.as_bytes()) == expected_hash {
        let _ = clip.set_text(String::new());

        let _ = clip.clear();
    }
    Ok(())
}

pub fn hex_sha256(data: &[u8]) -> String {
    use sha2_compat::Sha256;
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut s = String::with_capacity(64);
    for b in out {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

mod sha2_compat {
    pub struct Sha256 {
        state: [u32; 8],
        buf: [u8; 64],
        len: u64,
        buf_len: usize,
    }

    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    const H0: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    impl Sha256 {
        pub fn new() -> Self {
            Self {
                state: H0,
                buf: [0; 64],
                len: 0,
                buf_len: 0,
            }
        }
        pub fn update(&mut self, mut data: &[u8]) {
            self.len = self.len.wrapping_add((data.len() as u64) * 8);
            if self.buf_len > 0 {
                let take = (64 - self.buf_len).min(data.len());
                self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
                self.buf_len += take;
                data = &data[take..];
                if self.buf_len == 64 {
                    let block = self.buf;
                    Self::compress(&mut self.state, &block);
                    self.buf_len = 0;
                }
            }
            while data.len() >= 64 {
                let mut blk = [0u8; 64];
                blk.copy_from_slice(&data[..64]);
                Self::compress(&mut self.state, &blk);
                data = &data[64..];
            }
            if !data.is_empty() {
                self.buf[..data.len()].copy_from_slice(data);
                self.buf_len = data.len();
            }
        }
        pub fn finalize(mut self) -> [u8; 32] {
            self.buf[self.buf_len] = 0x80;
            self.buf_len += 1;
            if self.buf_len > 56 {
                for i in self.buf_len..64 {
                    self.buf[i] = 0;
                }
                let block = self.buf;
                Self::compress(&mut self.state, &block);
                self.buf_len = 0;
            }
            for i in self.buf_len..56 {
                self.buf[i] = 0;
            }
            self.buf[56..64].copy_from_slice(&self.len.to_be_bytes());
            let block = self.buf;
            Self::compress(&mut self.state, &block);

            let mut out = [0u8; 32];
            for (i, w) in self.state.iter().enumerate() {
                out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
            }
            out
        }
        fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
            let mut w = [0u32; 64];
            for (i, chunk) in block.chunks_exact(4).enumerate() {
                w[i] = u32::from_be_bytes(chunk.try_into().unwrap());
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let t1 = h
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let mj = (a & b) ^ (a & c) ^ (b & c);
                let t2 = s0.wrapping_add(mj);
                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }
            state[0] = state[0].wrapping_add(a);
            state[1] = state[1].wrapping_add(b);
            state[2] = state[2].wrapping_add(c);
            state[3] = state[3].wrapping_add(d);
            state[4] = state[4].wrapping_add(e);
            state[5] = state[5].wrapping_add(f);
            state[6] = state[6].wrapping_add(g);
            state[7] = state[7].wrapping_add(h);
        }
    }
}

pub fn deliver_exec(
    plaintext: Plaintext,
    argv: &[String],
    via_env: bool,
) -> Result<i32, OutputError> {
    if argv.is_empty() {
        return Err(OutputError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "exec: empty argv",
        )));
    }
    let mut cmd = Command::new(&argv[0]);
    if argv.len() > 1 {
        cmd.args(&argv[1..]);
    }
    if via_env {
        let secret_str = std::str::from_utf8(&plaintext).map_err(|e| {
            OutputError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("non-utf8 secret for --via-env: {e}"),
            ))
        })?;
        cmd.env("RAGEWARDEN_SECRET", secret_str);
        let status = cmd.spawn()?.wait()?;
        return Ok(status.code().unwrap_or(-1));
    }

    deliver_exec_fd3(plaintext, cmd)
}

#[cfg(unix)]
fn deliver_exec_fd3(plaintext: Plaintext, mut cmd: Command) -> Result<i32, OutputError> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;

    let (read_fd, write_fd): (OwnedFd, OwnedFd) = unsafe {
        let mut fds = [-1i32; 2];
        let rc = libc::pipe(fds.as_mut_ptr());
        if rc != 0 {
            return Err(OutputError::Io(io::Error::last_os_error()));
        }

        let _ = libc::fcntl(fds[1], libc::F_SETFD, libc::FD_CLOEXEC);
        let _ = libc::fcntl(fds[0], libc::F_SETFD, libc::FD_CLOEXEC);
        (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1]))
    };

    let read_raw = read_fd.as_raw_fd();

    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(read_raw, 3) == -1 {
                return Err(io::Error::last_os_error());
            }

            let flags = libc::fcntl(3, libc::F_GETFD);
            if flags == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(3, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = cmd.spawn()?;

    drop(read_fd);

    let mut writer = std::fs::File::from(write_fd);
    writer.write_all(&plaintext)?;
    drop(plaintext);
    drop(writer);

    let status = child.wait()?;
    Ok(status.code().unwrap_or(-1))
}

#[cfg(not(unix))]
fn deliver_exec_fd3(plaintext: Plaintext, _cmd: Command) -> Result<i32, OutputError> {
    drop(plaintext);
    Err(OutputError::Io(io::Error::new(
        io::ErrorKind::Unsupported,
        "exec --via-fd is unix-only; use --via-env on this platform",
    )))
}

#[allow(dead_code)]
pub type Pt = Zeroizing<Vec<u8>>;
