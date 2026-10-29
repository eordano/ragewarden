//! Where a device PIN comes from.
//!
//! A terminal when stdin is one; otherwise `pinentry` (the native host's stdin is
//! the browser pipe, so it has no terminal); otherwise refuse. Every source shows
//! the ceremony line so the PIN is never typed without knowing what it unlocks.

use std::io::{self, BufRead, BufReader, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum PinError {
    #[error(
        "this device needs a PIN, but there is no terminal and no `pinentry` program on PATH \
         to ask for it"
    )]
    NoPinSource,
    #[error("PIN entry cancelled")]
    Cancelled,
    #[error("pinentry: {0}")]
    Pinentry(String),
    #[error("pin io: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinSource {
    Tty,
    Pinentry(PathBuf),
}

/// Pick the source for this process: a terminal on stdin wins, then
/// `RAGEWARDEN_PINENTRY` or the first `pinentry` on PATH.
pub fn select_source(stdin_is_tty: bool, path_var: Option<&std::ffi::OsStr>) -> Option<PinSource> {
    if stdin_is_tty {
        return Some(PinSource::Tty);
    }
    if let Some(explicit) = std::env::var_os("RAGEWARDEN_PINENTRY") {
        let p = PathBuf::from(explicit);
        return is_executable(&p).then_some(PinSource::Pinentry(p));
    }
    let path_var = path_var?;
    std::env::split_paths(path_var)
        .map(|d| d.join("pinentry"))
        .find(|p| is_executable(p))
        .map(PinSource::Pinentry)
}

pub fn current_source() -> Option<PinSource> {
    select_source(
        io::stdin().is_terminal(),
        std::env::var_os("PATH").as_deref(),
    )
}

/// Whether a PIN could be asked for at all in this process.
pub fn available() -> bool {
    current_source().is_some()
}

pub fn read_pin(prompt: &str, description: &str) -> Result<Zeroizing<String>, PinError> {
    match current_source().ok_or(PinError::NoPinSource)? {
        PinSource::Tty => {
            crate::ceremony::announce_step(description);
            Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
        }
        PinSource::Pinentry(bin) => read_pin_from_pinentry(&bin, prompt, description),
    }
}

fn is_executable(p: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p)
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        p.is_file()
    }
}

/// Assuan percent-escaping for SETDESC/SETPROMPT arguments.
pub fn assuan_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '%' => out.push_str("%25"),
            '\n' => out.push_str("%0A"),
            '\r' => out.push_str("%0D"),
            _ => out.push(c),
        }
    }
    out
}

pub fn assuan_unescape(s: &str) -> Zeroizing<String> {
    let bytes = s.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    Zeroizing::new(String::from_utf8_lossy(&out).into_owned())
}

pub fn read_pin_from_pinentry(
    bin: &Path,
    prompt: &str,
    description: &str,
) -> Result<Zeroizing<String>, PinError> {
    let mut child = Command::new(bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut to = child
        .stdin
        .take()
        .ok_or(PinError::Pinentry("no stdin".into()))?;
    let mut from = BufReader::new(
        child
            .stdout
            .take()
            .ok_or(PinError::Pinentry("no stdout".into()))?,
    );

    let expect_ok = |from: &mut BufReader<_>| -> Result<(), PinError> {
        let mut line = String::new();
        loop {
            line.clear();
            if from.read_line(&mut line)? == 0 {
                return Err(PinError::Pinentry("pinentry exited".into()));
            }
            if line.starts_with("OK") {
                return Ok(());
            }
            if line.starts_with("ERR") {
                return Err(PinError::Pinentry(line.trim().to_string()));
            }
        }
    };

    expect_ok(&mut from)?;
    for cmd in [
        format!("SETDESC {}", assuan_escape(description)),
        format!("SETPROMPT {}", assuan_escape(prompt)),
        "SETTITLE rageterm".to_string(),
    ] {
        writeln!(to, "{cmd}")?;
        expect_ok(&mut from)?;
    }
    writeln!(to, "GETPIN")?;
    let mut pin: Option<Zeroizing<String>> = None;
    let mut line = Zeroizing::new(String::new());
    loop {
        line.clear();
        if from.read_line(&mut line)? == 0 {
            return Err(PinError::Pinentry("pinentry exited".into()));
        }
        if let Some(data) = line.strip_prefix("D ") {
            pin = Some(assuan_unescape(data.trim_end_matches(['\n', '\r'])));
        } else if line.starts_with("OK") {
            break;
        } else if line.starts_with("ERR") {
            let _ = writeln!(to, "BYE");
            let _ = child.wait();
            return Err(PinError::Cancelled);
        }
    }
    let _ = writeln!(to, "BYE");
    drop(to);
    let _ = child.wait();
    match pin {
        Some(p) if !p.is_empty() => Ok(p),
        _ => Err(PinError::Cancelled),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_pinentry(dir: &Path, getpin_reply: &str) -> PathBuf {
        let p = dir.join("pinentry");
        std::fs::write(
            &p,
            format!(
                "#!/bin/sh\necho 'OK Pleased to meet you'\nwhile read -r line; do\n  case \"$line\" in\n    GETPIN) printf '%s\\n' {getpin_reply};;\n    BYE) echo OK; exit 0;;\n    *) echo OK;;\n  esac\ndone\n"
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        p
    }

    #[test]
    fn a_terminal_wins_and_no_terminal_falls_back_to_pinentry_on_path() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(select_source(true, None), Some(PinSource::Tty));
        assert_eq!(select_source(false, Some(dir.path().as_os_str())), None);
        let bin = fake_pinentry(dir.path(), "'D 1234' OK");
        assert_eq!(
            select_source(false, Some(dir.path().as_os_str())),
            Some(PinSource::Pinentry(bin))
        );
    }

    #[test]
    fn pinentry_returns_the_unescaped_pin() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_pinentry(dir.path(), "'D 12%2534' OK");
        let pin = read_pin_from_pinentry(&bin, "PIN:", "Copy `x` -> clipboard").unwrap();
        assert_eq!(pin.as_str(), "12%34");
    }

    #[test]
    fn a_cancelled_pinentry_is_cancelled_not_empty() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_pinentry(dir.path(), "'ERR 83886179 Operation cancelled'");
        assert!(matches!(
            read_pin_from_pinentry(&bin, "PIN:", "x"),
            Err(PinError::Cancelled)
        ));
    }

    #[test]
    fn assuan_escaping_round_trips_newlines_and_percent() {
        let s = "a%b\nc";
        assert_eq!(assuan_escape(s), "a%25b%0Ac");
        assert_eq!(assuan_unescape(&assuan_escape(s)).as_str(), s);
    }
}
