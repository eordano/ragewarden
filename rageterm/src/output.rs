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
    deliver_clipboard_text(pt_str, clear_after_secs, expected_hash)?;
    drop(plaintext);
    Ok(())
}

/// A detached `__clipboard-serve` child takes the plaintext on stdin and owns the clipboard
/// value until another client replaces it or the clear deadline passes, then clears it. X11 and
/// Wayland need that owner to stay alive; on every platform it keeps the plaintext out of this
/// process's clipboard library and keeps any digest of it out of argv. This process returns only
/// once the value is readable from the clipboard.
fn deliver_clipboard_text(
    text: &str,
    clear_after_secs: u64,
    expected_hash: &str,
) -> Result<(), OutputError> {
    use std::process::Stdio;
    use std::time::Instant;

    let exe = std::env::current_exe()?;
    let mut cmd = Command::new(exe);
    cmd.arg(CLIPBOARD_SERVE_SUBCOMMAND)
        .arg(clear_after_secs.to_string());
    detach_stdio(&mut cmd);
    cmd.stdin(Stdio::piped());
    let mut child = cmd.spawn()?;
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| OutputError::Clipboard("serve helper has no stdin".into()))?;
        stdin.write_all(text.as_bytes())?;
    }

    let mut clip =
        arboard::Clipboard::new().map_err(|e| OutputError::Clipboard(format!("init: {e}")))?;
    let deadline = Instant::now() + CLIPBOARD_SERVE_TIMEOUT;
    loop {
        if let Ok(cur) = clip.get_text() {
            if hex_sha256(Zeroizing::new(cur).as_bytes()) == expected_hash {
                return Ok(());
            }
        }
        if let Some(status) = child.try_wait()? {
            let landed = clip
                .get_text()
                .map(|cur| hex_sha256(Zeroizing::new(cur).as_bytes()) == expected_hash)
                .unwrap_or(false);
            if status.success() && landed {
                return Ok(());
            }
            return Err(OutputError::Clipboard(format!(
                "serve helper exited ({status}) before the value reached the clipboard"
            )));
        }
        if Instant::now() >= deadline {
            return Err(OutputError::Clipboard(format!(
                "the value did not reach the clipboard within {}s",
                CLIPBOARD_SERVE_TIMEOUT.as_secs()
            )));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

pub const CLIPBOARD_SERVE_SUBCOMMAND: &str = "__clipboard-serve";

/// Windows `exec`: the inherited pipe handle the child reads the secret from.
#[cfg_attr(not(windows), allow(dead_code))]
pub const SECRET_HANDLE_ENV: &str = "RAGEWARDEN_SECRET_HANDLE";

const CLIPBOARD_SERVE_TIMEOUT: Duration = Duration::from_secs(3);

#[cfg(unix)]
fn detach_stdio(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    // SAFETY: runs in the forked child before exec; setsid(2) is
    // async-signal-safe and touches no memory shared with the parent.
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

/// The `__clipboard-serve` child: owns the selection for `secs` (0 = until replaced), kept out of
/// clipboard-manager histories, then clears it if it still holds this value.
pub fn run_clipboard_serve(secs: u64) -> Result<(), OutputError> {
    use std::io::Read;
    use std::time::Instant;

    let mut buf = Zeroizing::new(Vec::new());
    io::stdin().read_to_end(&mut buf)?;
    let text = Zeroizing::new(
        std::str::from_utf8(&buf)
            .map_err(|e| OutputError::Clipboard(format!("plaintext is not utf-8: {e}")))?
            .to_owned(),
    );
    drop(buf);
    let expected_hash = hex_sha256(text.as_bytes());
    let deadline = (secs > 0).then(|| Instant::now() + Duration::from_secs(secs));

    let mut clip =
        arboard::Clipboard::new().map_err(|e| OutputError::Clipboard(format!("init: {e}")))?;
    let served = serve_until(&mut clip, &text, deadline);
    drop(text);
    served?;

    if let Some(deadline) = deadline {
        if let Some(left) = deadline.checked_duration_since(Instant::now()) {
            thread::sleep(left);
        }
        clear_if_unchanged(&mut clip, &expected_hash);
    }
    // arboard's own copy is released here at the latest; the global
    // allocator (zalloc) wipes it as it is freed.
    drop(clip);
    Ok(())
}

#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "android", target_os = "emscripten"))
))]
fn serve_until(
    clip: &mut arboard::Clipboard,
    text: &str,
    deadline: Option<std::time::Instant>,
) -> Result<(), OutputError> {
    use arboard::SetExtLinux;
    let set = clip.set().exclude_from_history();
    let set = match deadline {
        Some(deadline) => set.wait_until(deadline),
        None => set.wait(),
    };
    set.text(text.to_owned())
        .map_err(|e| OutputError::Clipboard(format!("set_text: {e}")))
}

#[cfg(not(all(
    unix,
    not(any(target_os = "macos", target_os = "android", target_os = "emscripten"))
)))]
fn serve_until(
    clip: &mut arboard::Clipboard,
    text: &str,
    _deadline: Option<std::time::Instant>,
) -> Result<(), OutputError> {
    clip.set_text(text)
        .map_err(|e| OutputError::Clipboard(format!("set_text: {e}")))
}

fn clear_if_unchanged(clip: &mut arboard::Clipboard, expected_hash: &str) {
    let cur = match clip.get_text() {
        Ok(s) => Zeroizing::new(s),
        Err(_) => return,
    };
    if hex_sha256(cur.as_bytes()) == expected_hash {
        let _ = clip.set_text(String::new());

        let _ = clip.clear();
    }
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

/// What the `exec` child inherits. rageterm's own `RAGEWARDEN_*` settings never
/// reach it; `clean` drops everything else too except a minimal login set.
#[derive(Debug, Clone, Default)]
pub struct ExecEnv {
    pub clean: bool,
    pub keep: Vec<String>,
}

const CLEAN_ENV_BASE: &[&str] = &["PATH", "HOME", "USER", "LOGNAME", "SHELL", "TERM", "LANG"];

/// The child's environment, computed from the parent's.
pub fn exec_environment<I>(parent: I, env: &ExecEnv) -> Vec<(String, String)>
where
    I: IntoIterator<Item = (String, String)>,
{
    parent
        .into_iter()
        .filter(|(k, _)| !k.starts_with("RAGEWARDEN_"))
        .filter(|(k, _)| {
            !env.clean
                || CLEAN_ENV_BASE.contains(&k.as_str())
                || k.starts_with("LC_")
                || env.keep.iter().any(|keep| keep == k)
        })
        .collect()
}

pub fn deliver_exec(
    plaintext: Plaintext,
    argv: &[String],
    via_env: bool,
    env: &ExecEnv,
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
    cmd.env_clear()
        .envs(exec_environment(std::env::vars(), env));
    if via_env {
        let secret_str = std::str::from_utf8(&plaintext).map_err(|e| {
            OutputError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("non-utf8 secret for --via-env: {e}"),
            ))
        })?;
        cmd.env("RAGEWARDEN_SECRET", secret_str);
        let mut child = cmd.spawn()?;
        drop(cmd);
        drop(plaintext);
        let status = child.wait()?;
        return Ok(status.code().unwrap_or(-1));
    }

    deliver_exec_fd3(plaintext, cmd)
}

#[cfg(unix)]
fn deliver_exec_fd3(plaintext: Plaintext, mut cmd: Command) -> Result<i32, OutputError> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;

    // SAFETY: pipe(2) writes two fresh descriptors into `fds`, which this
    // block owns exclusively and wraps in OwnedFd exactly once each.
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

    // SAFETY: runs in the forked child before exec and calls only dup2(2) and
    // fcntl(2), both async-signal-safe; `read_raw` stays open in the parent
    // until after spawn returns.
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

/// Windows has no FD 3: the secret goes down an anonymous pipe whose read end
/// the child inherits, named by `RAGEWARDEN_SECRET_HANDLE` (the handle value in
/// decimal). The write end is not inheritable and is closed after writing, so
/// the child reads exactly the secret and then EOF.
#[cfg(windows)]
fn deliver_exec_fd3(plaintext: Plaintext, mut cmd: Command) -> Result<i32, OutputError> {
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::{HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::System::Pipes::CreatePipe;

    let mut read: HANDLE = std::ptr::null_mut();
    let mut write: HANDLE = std::ptr::null_mut();
    let attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    // SAFETY: CreatePipe writes two fresh handles into `read`/`write`, which
    // this function owns exclusively from here on.
    if unsafe { CreatePipe(&mut read, &mut write, &attrs, 0) } == 0 {
        return Err(OutputError::Io(io::Error::last_os_error()));
    }
    // SAFETY: both handles were just created by CreatePipe and are wrapped in
    // OwnedHandle exactly once, which closes them on drop.
    let (read_end, write_end) = unsafe {
        (
            OwnedHandle::from_raw_handle(read as _),
            OwnedHandle::from_raw_handle(write as _),
        )
    };
    // SAFETY: `write` is a valid handle owned by `write_end`; clearing its
    // inherit flag keeps the child from holding the pipe open.
    if unsafe { SetHandleInformation(write, HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(OutputError::Io(io::Error::last_os_error()));
    }
    cmd.env(SECRET_HANDLE_ENV, (read as usize).to_string());
    let mut child = cmd.spawn()?;
    drop(read_end);
    let mut writer = std::fs::File::from(write_end);
    writer.write_all(&plaintext)?;
    drop(plaintext);
    drop(writer);
    let status = child.wait()?;
    Ok(status.code().unwrap_or(-1))
}

#[cfg(not(any(unix, windows)))]
fn deliver_exec_fd3(plaintext: Plaintext, _cmd: Command) -> Result<i32, OutputError> {
    drop(plaintext);
    Err(OutputError::Io(io::Error::new(
        io::ErrorKind::Unsupported,
        "exec without --via-env is not supported on this platform",
    )))
}

#[allow(dead_code)]
pub type Pt = Zeroizing<Vec<u8>>;

#[cfg(test)]
mod exec_env_tests {
    use super::*;

    fn parent() -> Vec<(String, String)> {
        [
            ("PATH", "/bin"),
            ("HOME", "/h"),
            ("LC_ALL", "C"),
            ("RAGEWARDEN_CONFIG_DIR", "/c"),
            ("RAGEWARDEN_NATIVE_HOST_ALLOW_SOFTWARE", "1"),
            ("SSH_AUTH_SOCK", "/s"),
            ("AWS_PROFILE", "p"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    fn keys(v: &[(String, String)]) -> Vec<&str> {
        v.iter().map(|(k, _)| k.as_str()).collect()
    }

    #[test]
    fn rageterm_settings_never_reach_the_child() {
        let env = exec_environment(parent(), &ExecEnv::default());
        assert!(!keys(&env).iter().any(|k| k.starts_with("RAGEWARDEN_")));
        assert!(keys(&env).contains(&"SSH_AUTH_SOCK"));
    }

    #[test]
    fn a_clean_environment_keeps_only_the_login_set_and_named_variables() {
        let env = exec_environment(
            parent(),
            &ExecEnv {
                clean: true,
                keep: vec!["AWS_PROFILE".into()],
            },
        );
        assert_eq!(keys(&env), vec!["PATH", "HOME", "LC_ALL", "AWS_PROFILE"]);
    }
}
