#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::{io::Write, process::Stdio};

use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum FillError {
    #[error("`{tool}` not found in PATH; install it via {hint}")]
    ToolMissing {
        tool: &'static str,
        hint: &'static str,
    },

    #[error("autotype tool `{tool}` failed: {message}")]
    ToolFailed { tool: &'static str, message: String },

    #[error(
        "could not parse window spec `{0}` (expected pid:N, class:NAME, title:SUBSTR, or focused)"
    )]
    BadSpec(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("autotype not yet implemented on this platform")]
    #[allow(dead_code)]
    UnsupportedPlatform,

    #[error("the {backend} backend does not support window spec `{spec}`")]
    UnsupportedSpec { backend: &'static str, spec: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowSpec {
    Focused,
    Pid(u32),
    Class(String),
    Title(String),
}

impl WindowSpec {
    pub fn describe(&self) -> String {
        match self {
            Self::Focused => "the focused window".to_string(),
            Self::Pid(p) => format!("the focused window of process {p}"),
            Self::Class(c) => format!("a window matching class `{c}`"),
            Self::Title(t) => format!("a window with title containing `{t}`"),
        }
    }
}

pub fn parse_window_spec(s: Option<&str>) -> Result<WindowSpec, FillError> {
    let Some(s) = s else {
        return Ok(WindowSpec::Focused);
    };
    let s = s.trim();
    if s.is_empty() || s == "focused" {
        return Ok(WindowSpec::Focused);
    }
    if let Some(rest) = s.strip_prefix("pid:") {
        let pid: u32 = rest
            .parse()
            .map_err(|_| FillError::BadSpec(s.to_string()))?;
        return Ok(WindowSpec::Pid(pid));
    }
    if let Some(rest) = s.strip_prefix("class:") {
        if rest.is_empty() {
            return Err(FillError::BadSpec(s.to_string()));
        }
        return Ok(WindowSpec::Class(rest.to_string()));
    }
    if let Some(rest) = s.strip_prefix("title:") {
        if rest.is_empty() {
            return Err(FillError::BadSpec(s.to_string()));
        }
        return Ok(WindowSpec::Title(rest.to_string()));
    }
    Err(FillError::BadSpec(s.to_string()))
}

pub trait AutotypeBackend {
    fn name(&self) -> &'static str;

    fn type_into(&self, plaintext: &Zeroizing<Vec<u8>>, spec: &WindowSpec)
        -> Result<(), FillError>;
}

pub fn default_backend() -> Result<Box<dyn AutotypeBackend>, FillError> {
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(MacosCliclick))
    }
    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("WAYLAND_DISPLAY").is_some() {
            Ok(Box::new(LinuxYdotool))
        } else {
            Ok(Box::new(LinuxXdotool))
        }
    }
    #[cfg(target_os = "windows")]
    {
        Ok(Box::new(WindowsSendInput))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err(FillError::UnsupportedPlatform)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn ensure_in_path(tool: &'static str, hint: &'static str) -> Result<(), FillError> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let exe = if cfg!(windows) {
        format!("{tool}.exe")
    } else {
        tool.to_string()
    };
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(&exe);
        if candidate.exists() {
            return Ok(());
        }
    }
    Err(FillError::ToolMissing { tool, hint })
}

#[cfg(target_os = "linux")]
pub struct LinuxXdotool;

#[cfg(target_os = "linux")]
impl AutotypeBackend for LinuxXdotool {
    fn name(&self) -> &'static str {
        "xdotool"
    }
    fn type_into(
        &self,
        plaintext: &Zeroizing<Vec<u8>>,
        spec: &WindowSpec,
    ) -> Result<(), FillError> {
        ensure_in_path("xdotool", "apt-get install xdotool / dnf install xdotool")?;
        if let Some(window_id) = resolve_x11_window(spec)? {
            run_xdotool_with(
                plaintext,
                &[
                    "type",
                    "--window",
                    &window_id,
                    "--delay",
                    "12",
                    "--clearmodifiers",
                    "--file",
                    "-",
                ],
            )
        } else {
            run_xdotool_with(
                plaintext,
                &["type", "--delay", "12", "--clearmodifiers", "--file", "-"],
            )
        }
    }
}

#[cfg(target_os = "linux")]
fn run_xdotool_with(plaintext: &Zeroizing<Vec<u8>>, args: &[&str]) -> Result<(), FillError> {
    let mut child = Command::new("xdotool")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(plaintext)?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(FillError::ToolFailed {
            tool: "xdotool",
            message: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn resolve_x11_window(spec: &WindowSpec) -> Result<Option<String>, FillError> {
    match spec {
        WindowSpec::Focused => Ok(None),
        WindowSpec::Pid(pid) => xdotool_search(&["--pid", &pid.to_string()]),
        WindowSpec::Class(c) => xdotool_search(&["--class", c]),
        WindowSpec::Title(t) => xdotool_search(&["--name", t]),
    }
}

#[cfg(target_os = "linux")]
fn xdotool_search(extra: &[&str]) -> Result<Option<String>, FillError> {
    let mut args = vec!["search"];
    args.extend_from_slice(extra);
    args.push("--limit");
    args.push("1");
    let out = Command::new("xdotool").args(&args).output()?;
    if !out.status.success() {
        return Ok(None);
    }
    let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if id.is_empty() {
        Ok(None)
    } else {
        Ok(Some(id))
    }
}

#[cfg(target_os = "linux")]
pub struct LinuxYdotool;

#[cfg(target_os = "linux")]
impl AutotypeBackend for LinuxYdotool {
    fn name(&self) -> &'static str {
        "ydotool"
    }
    fn type_into(
        &self,
        plaintext: &Zeroizing<Vec<u8>>,
        spec: &WindowSpec,
    ) -> Result<(), FillError> {
        ensure_in_path(
            "ydotool",
            "apt-get install ydotool -- Wayland sessions need ydotoold running",
        )?;
        match spec {
            WindowSpec::Focused | WindowSpec::Title(_) => {}
            other => {
                return Err(FillError::UnsupportedSpec {
                    backend: "ydotool",
                    spec: format!("{other:?}"),
                });
            }
        }
        let mut child = Command::new("ydotool")
            .args(["type", "--file", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(plaintext)?;
        }
        let out = child.wait_with_output()?;
        if !out.status.success() {
            return Err(FillError::ToolFailed {
                tool: "ydotool",
                message: String::from_utf8_lossy(&out.stderr).trim().to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
pub struct MacosCliclick;

/// Characters `-[NSCharacterSet newlineCharacterSet]` matches. cliclick splits
/// its command stream on exactly these, so a secret containing one would be cut
/// into two "commands" and the tail interpreted as an action shortcut.
#[cfg(any(target_os = "macos", test))]
const CLICLICK_LINE_BREAKS: &[char] = &[
    '\u{000a}', '\u{000b}', '\u{000c}', '\u{000d}', '\u{0085}', '\u{2028}', '\u{2029}',
];

/// Builds the byte stream handed to `cliclick -f -`.
///
/// The secret used to be `format!("t:{s}")` passed as an ARGV element, which put
/// it in `/proc/PID/cmdline` (and `ps`) for the lifetime of the child -- readable
/// by any process of the same user, and on some systems by any user at all.
/// `DESIGN.md` promises the plaintext "never appears in any process's argv".
///
/// `cliclick -f <file>` reads its commands from a file, or from stdin when the
/// filename is `-`, so the same stdin pipe the xdotool/ydotool backends use
/// works here too. cliclick's parser (`parseCommandsFile` in `cliclick.m`) does
/// no shell-style quote handling: it splits the input on newlines, trims
/// leading/trailing whitespace from each line, drops blank and `#`-prefixed
/// lines, and hands the rest to `ActionExecutor`, which splits at the *first*
/// colon and rejoins the remainder with `:`. So `t:<secret>` on one line carries
/// the secret verbatim, including spaces and colons -- with two limits that this
/// function refuses rather than silently corrupting:
///
/// * a line break would split the command;
/// * trailing whitespace would be trimmed off the typed text.
#[cfg(any(target_os = "macos", test))]
fn cliclick_type_script(plaintext: &Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, FillError> {
    let s = std::str::from_utf8(plaintext).map_err(|_| FillError::ToolFailed {
        tool: "cliclick",
        message: "plaintext is not utf-8; cliclick types text, not bytes".into(),
    })?;
    if s.is_empty() {
        return Err(FillError::ToolFailed {
            tool: "cliclick",
            message: "refusing to autotype an empty secret".into(),
        });
    }
    if s.contains(CLICLICK_LINE_BREAKS) {
        return Err(FillError::ToolFailed {
            tool: "cliclick",
            message: "secret contains a line break; cliclick's command stream is \
                      line-oriented and would type only the first line. Use \
                      `rageterm copy` or `rageterm exec` for this item."
                .into(),
        });
    }
    if s.ends_with(char::is_whitespace) {
        return Err(FillError::ToolFailed {
            tool: "cliclick",
            message: "secret ends in whitespace; cliclick trims it off every command \
                      line, so the typed text would silently differ from the stored \
                      secret. Use `rageterm copy` or `rageterm exec` for this item."
                .into(),
        });
    }

    let mut script = Zeroizing::new(Vec::with_capacity(plaintext.len() + 3));
    script.extend_from_slice(b"t:");
    script.extend_from_slice(plaintext);
    script.push(b'\n');
    Ok(script)
}

#[cfg(target_os = "macos")]
impl AutotypeBackend for MacosCliclick {
    fn name(&self) -> &'static str {
        "cliclick"
    }
    fn type_into(
        &self,
        plaintext: &Zeroizing<Vec<u8>>,
        spec: &WindowSpec,
    ) -> Result<(), FillError> {
        ensure_in_path(
            "cliclick",
            "brew install cliclick -- grant Accessibility permission once after install",
        )?;
        if !matches!(
            spec,
            WindowSpec::Focused | WindowSpec::Pid(_) | WindowSpec::Title(_)
        ) {
            return Err(FillError::UnsupportedSpec {
                backend: "cliclick",
                spec: format!("{spec:?}"),
            });
        }
        let script = cliclick_type_script(plaintext)?;

        let mut child = Command::new("cliclick")
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(&script)?;
            // cliclick blocks in `readDataToEndOfFile`; dropping the handle here
            // closes the pipe so it can proceed.
        }
        let out = child.wait_with_output()?;
        if !out.status.success() {
            return Err(FillError::ToolFailed {
                tool: "cliclick",
                message: String::from_utf8_lossy(&out.stderr).trim().to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
pub struct WindowsSendInput;

#[cfg(target_os = "windows")]
impl AutotypeBackend for WindowsSendInput {
    fn name(&self) -> &'static str {
        "SendInput"
    }
    fn type_into(
        &self,
        _plaintext: &Zeroizing<Vec<u8>>,
        _spec: &WindowSpec,
    ) -> Result<(), FillError> {
        Err(FillError::ToolFailed {
            tool: "SendInput",
            message: "Windows autotype is stubbed; build with `--features fill-windows` after the windows-rs wiring lands.".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_window_spec_variants() {
        assert_eq!(parse_window_spec(None).unwrap(), WindowSpec::Focused);
        assert_eq!(
            parse_window_spec(Some("focused")).unwrap(),
            WindowSpec::Focused
        );
        assert_eq!(
            parse_window_spec(Some("pid:42")).unwrap(),
            WindowSpec::Pid(42)
        );
        assert_eq!(
            parse_window_spec(Some("class:Firefox")).unwrap(),
            WindowSpec::Class("Firefox".into())
        );
        assert_eq!(
            parse_window_spec(Some("title:foo bar")).unwrap(),
            WindowSpec::Title("foo bar".into())
        );
        assert!(matches!(
            parse_window_spec(Some("garbage")),
            Err(FillError::BadSpec(_))
        ));
        assert!(matches!(
            parse_window_spec(Some("pid:nope")),
            Err(FillError::BadSpec(_))
        ));
        assert!(matches!(
            parse_window_spec(Some("class:")),
            Err(FillError::BadSpec(_))
        ));
    }

    #[test]
    fn window_spec_describe_names_target() {
        assert!(WindowSpec::Focused.describe().contains("focused"));
        assert!(WindowSpec::Pid(7).describe().contains("7"));
        assert!(WindowSpec::Class("X".into()).describe().contains("X"));
        assert!(WindowSpec::Title("hi".into()).describe().contains("hi"));
    }

    pub struct RecordingBackend {
        pub calls: std::sync::Mutex<Vec<(WindowSpec, Vec<u8>)>>,
    }

    impl AutotypeBackend for RecordingBackend {
        fn name(&self) -> &'static str {
            "recording"
        }
        fn type_into(
            &self,
            plaintext: &Zeroizing<Vec<u8>>,
            spec: &WindowSpec,
        ) -> Result<(), FillError> {
            self.calls
                .lock()
                .unwrap()
                .push((spec.clone(), plaintext.to_vec()));
            Ok(())
        }
    }

    #[test]
    fn cliclick_script_is_one_line_and_keeps_spaces_and_colons() {
        let pt = Zeroizing::new(b"p a s s:w0rd!".to_vec());
        let script = cliclick_type_script(&pt).expect("encodes");
        assert_eq!(&script[..], b"t:p a s s:w0rd!\n");
        assert_eq!(script.iter().filter(|b| **b == b'\n').count(), 1);
    }

    #[test]
    fn cliclick_script_never_puts_the_secret_where_argv_could_see_it() {
        // The only argv cliclick gets is `-f -`; everything else is the pipe.
        let pt = Zeroizing::new(b"hunter2".to_vec());
        let script = cliclick_type_script(&pt).expect("encodes");
        assert!(script.starts_with(b"t:"));
        assert!(script.ends_with(b"\n"));
    }

    #[test]
    fn cliclick_script_refuses_line_breaks() {
        for bad in ["a\nb", "a\rb", "a\u{2028}b", "a\u{0085}b"] {
            let pt = Zeroizing::new(bad.as_bytes().to_vec());
            let err = cliclick_type_script(&pt).expect_err("must refuse");
            assert!(
                matches!(&err, FillError::ToolFailed { message, .. } if message.contains("line break")),
                "{bad:?} gave {err}"
            );
        }
    }

    #[test]
    fn cliclick_script_refuses_trailing_whitespace_it_cannot_carry() {
        for bad in ["secret ", "secret\t"] {
            let pt = Zeroizing::new(bad.as_bytes().to_vec());
            let err = cliclick_type_script(&pt).expect_err("must refuse");
            assert!(
                matches!(&err, FillError::ToolFailed { message, .. } if message.contains("whitespace")),
                "{bad:?} gave {err}"
            );
        }
        // Leading whitespace survives: the line starts with `t`, so cliclick's
        // trim never reaches it.
        let pt = Zeroizing::new(b" leading".to_vec());
        assert_eq!(&cliclick_type_script(&pt).unwrap()[..], b"t: leading\n");
    }

    #[test]
    fn cliclick_script_refuses_empty_and_non_utf8() {
        let empty = Zeroizing::new(Vec::new());
        assert!(cliclick_type_script(&empty).is_err());
        let non_utf8 = Zeroizing::new(vec![0xff, 0xfe]);
        assert!(cliclick_type_script(&non_utf8).is_err());
    }

    #[test]
    fn recording_backend_observes_plaintext_and_spec() {
        let backend = RecordingBackend {
            calls: std::sync::Mutex::new(Vec::new()),
        };
        let pt = Zeroizing::new(b"hunter2".to_vec());
        backend
            .type_into(&pt, &WindowSpec::Title("github".into()))
            .expect("backend ok");
        let calls = backend.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, WindowSpec::Title("github".into()));
        assert_eq!(calls[0].1, b"hunter2");
    }
}
