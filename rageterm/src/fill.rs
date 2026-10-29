use std::io::Write;
use std::process::{Command, Stdio};

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
        Ok(Box::new(MacosKeyEvents))
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
        Ok(Box::new(WindowsSendKeys))
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

/// macOS: rageterm types the secret itself through CoreGraphics -- keyboard
/// events that carry the text as Unicode (`CGEventKeyboardSetUnicodeString`),
/// at most [`MAX_EVENT_UTF16`] UTF-16 units each, posted to the focused app or
/// to one process. Every character goes through as stored, line breaks and
/// trailing whitespace included, and the plaintext never leaves this process:
/// no argv, no pipe, no helper. Posting needs the Accessibility permission of
/// the app rageterm runs in; without it the events would be dropped silently,
/// so rageterm checks first and falls back to cliclick (which has its own
/// grant and its own limits) when it is installed.
#[cfg(target_os = "macos")]
pub struct MacosKeyEvents;

/// The longest string one keyboard event carries; the window server truncates
/// past it.
#[cfg(any(target_os = "macos", test))]
const MAX_EVENT_UTF16: usize = 20;

/// `s` as UTF-16 chunks of at most `max` units, never splitting a surrogate
/// pair.
#[cfg(any(target_os = "macos", test))]
fn utf16_chunks(s: &str, max: usize) -> Vec<Zeroizing<Vec<u16>>> {
    let mut chunks = Vec::new();
    let mut current = Zeroizing::new(Vec::with_capacity(max));
    let mut buf = [0u16; 2];
    for c in s.chars() {
        let units = c.encode_utf16(&mut buf);
        if current.len() + units.len() > max {
            chunks.push(std::mem::replace(
                &mut current,
                Zeroizing::new(Vec::with_capacity(max)),
            ));
        }
        current.extend_from_slice(units);
    }
    buf.fill(0);
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

#[cfg(target_os = "macos")]
mod cg {
    use std::ffi::{c_ulong, c_void};

    pub type EventSource = *mut c_void;
    pub type Event = *mut c_void;

    /// `kCGEventSourceStateHIDSystemState`.
    pub const HID_SYSTEM_STATE: i32 = 1;
    /// `kCGHIDEventTap`.
    pub const HID_EVENT_TAP: u32 = 0;

    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        pub fn CGEventSourceCreate(state: i32) -> EventSource;
        pub fn CGEventCreateKeyboardEvent(source: EventSource, key: u16, down: bool) -> Event;
        pub fn CGEventKeyboardSetUnicodeString(event: Event, length: c_ulong, text: *const u16);
        pub fn CGEventSetFlags(event: Event, flags: u64);
        pub fn CGEventPost(tap: u32, event: Event);
        pub fn CGEventPostToPid(pid: i32, event: Event);
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        pub fn CFRelease(cf: *const c_void);
    }

    #[link(name = "ApplicationServices", kind = "framework")]
    unsafe extern "C" {
        pub fn AXIsProcessTrusted() -> u8;
    }
}

#[cfg(target_os = "macos")]
impl MacosKeyEvents {
    fn post(chunks: &[Zeroizing<Vec<u16>>], pid: Option<i32>) -> Result<(), FillError> {
        let failed = |message: &str| FillError::ToolFailed {
            tool: "CoreGraphics",
            message: message.into(),
        };
        // SAFETY: plain CoreGraphics calls. The source and each event are
        // checked for null before use and released exactly once; every text
        // pointer is a live chunk of `chunk.len()` UTF-16 units.
        unsafe {
            let source = cg::CGEventSourceCreate(cg::HID_SYSTEM_STATE);
            if source.is_null() {
                return Err(failed("could not create a keyboard event source"));
            }
            for chunk in chunks {
                for down in [true, false] {
                    let event = cg::CGEventCreateKeyboardEvent(source, 0, down);
                    if event.is_null() {
                        cg::CFRelease(source);
                        return Err(failed("could not create a keyboard event"));
                    }
                    cg::CGEventSetFlags(event, 0);
                    cg::CGEventKeyboardSetUnicodeString(
                        event,
                        chunk.len() as std::ffi::c_ulong,
                        chunk.as_ptr(),
                    );
                    match pid {
                        Some(pid) => cg::CGEventPostToPid(pid, event),
                        None => cg::CGEventPost(cg::HID_EVENT_TAP, event),
                    }
                    cg::CFRelease(event);
                }
                std::thread::sleep(std::time::Duration::from_millis(4));
            }
            cg::CFRelease(source);
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
impl AutotypeBackend for MacosKeyEvents {
    fn name(&self) -> &'static str {
        "macOS keyboard events"
    }

    fn type_into(
        &self,
        plaintext: &Zeroizing<Vec<u8>>,
        spec: &WindowSpec,
    ) -> Result<(), FillError> {
        let pid = match spec {
            WindowSpec::Focused => None,
            WindowSpec::Pid(p) => {
                Some(i32::try_from(*p).map_err(|_| FillError::BadSpec(format!("pid:{p}")))?)
            }
            other => {
                return Err(FillError::UnsupportedSpec {
                    backend: "macOS keyboard events",
                    spec: format!("{other:?}"),
                });
            }
        };
        let text = std::str::from_utf8(plaintext).map_err(|_| FillError::ToolFailed {
            tool: "CoreGraphics",
            message: "plaintext is not utf-8; only text can be typed".into(),
        })?;
        if text.is_empty() {
            return Err(FillError::ToolFailed {
                tool: "CoreGraphics",
                message: "refusing to autotype an empty secret".into(),
            });
        }
        // SAFETY: a side-effect-free query of this process's Accessibility grant.
        let trusted = unsafe { cg::AXIsProcessTrusted() } != 0;
        if trusted {
            return Self::post(&utf16_chunks(text, MAX_EVENT_UTF16), pid);
        }
        if ensure_in_path("cliclick", "").is_ok() {
            eprintln!(
                "rageterm: this terminal may not post keyboard events (System Settings -> \
                 Privacy & Security -> Accessibility); typing through cliclick instead"
            );
            return MacosCliclick.type_into(plaintext, spec);
        }
        Err(FillError::ToolFailed {
            tool: "CoreGraphics",
            message: "this terminal may not post keyboard events: allow it under System \
                      Settings -> Privacy & Security -> Accessibility, then run `fill` again"
                .into(),
        })
    }
}

/// The fallback when this process may not post keyboard events itself.
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

/// Windows: PowerShell's `SendKeys` after `AppActivate`. The secret goes over
/// the child's stdin, never argv; the script escapes SendKeys' metacharacters.
/// Compiled on every platform so the logic is type-checked and tested off
/// Windows; `default_backend` selects it only there.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub struct WindowsSendKeys;

/// Reads the plaintext from stdin, activates the target window when one is
/// named, and types it. `{`, `}`, `+`, `^`, `%`, `~`, `(`, `)`, `[`, `]` are
/// wrapped in braces, which is how SendKeys takes them literally.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn sendkeys_script(spec: &WindowSpec) -> Result<String, FillError> {
    let activate = match spec {
        WindowSpec::Focused => String::new(),
        WindowSpec::Pid(pid) => format!(
            "if (-not (New-Object -ComObject WScript.Shell).AppActivate({pid})) {{ exit 3 }}\n"
        ),
        WindowSpec::Title(t) => format!(
            "if (-not (New-Object -ComObject WScript.Shell).AppActivate('{}')) {{ exit 3 }}\n",
            t.replace('\'', "''")
        ),
        WindowSpec::Class(_) => {
            return Err(FillError::UnsupportedSpec {
                backend: "SendKeys",
                spec: format!("{spec:?}"),
            });
        }
    };
    Ok(format!(
        "$ErrorActionPreference = 'Stop'\n\
         Add-Type -AssemblyName System.Windows.Forms\n\
         $s = [Console]::In.ReadToEnd()\n\
         {activate}\
         $e = [regex]::Replace($s, '[+^%~(){{}}\\[\\]]', '{{$0}}')\n\
         [System.Windows.Forms.SendKeys]::SendWait($e)\n"
    ))
}

impl AutotypeBackend for WindowsSendKeys {
    fn name(&self) -> &'static str {
        "SendKeys"
    }
    fn type_into(
        &self,
        plaintext: &Zeroizing<Vec<u8>>,
        spec: &WindowSpec,
    ) -> Result<(), FillError> {
        let script = sendkeys_script(spec)?;
        let mut child = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => FillError::ToolMissing {
                    tool: "powershell.exe",
                    hint: "Windows PowerShell (part of every supported Windows)",
                },
                _ => FillError::from(e),
            })?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(plaintext)?;
        }
        let out = child.wait_with_output()?;
        match out.status.code() {
            Some(0) => Ok(()),
            Some(3) => Err(FillError::ToolFailed {
                tool: "SendKeys",
                message: format!("could not activate {}", spec.describe()),
            }),
            _ => Err(FillError::ToolFailed {
                tool: "SendKeys",
                message: String::from_utf8_lossy(&out.stderr).trim().to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sendkeys_script_activates_the_named_window_and_escapes_metacharacters() {
        let s = sendkeys_script(&WindowSpec::Title("it's me".into())).unwrap();
        assert!(s.contains("AppActivate('it''s me')"));
        assert!(s.contains("[regex]::Replace($s, '[+^%~(){}\\[\\]]', '{$0}')"));
        assert!(
            !sendkeys_script(&WindowSpec::Focused)
                .unwrap()
                .contains("AppActivate")
        );
        assert!(sendkeys_script(&WindowSpec::Class("x".into())).is_err());
    }

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
    fn unicode_chunks_keep_every_character_and_never_split_a_surrogate_pair() {
        let secret = "line one\nline two \u{1F512}\u{1F511}\tend  ";
        let chunks = utf16_chunks(secret, MAX_EVENT_UTF16);
        assert!(chunks.iter().all(|c| c.len() <= MAX_EVENT_UTF16));
        let joined: Vec<u16> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
        assert_eq!(String::from_utf16(&joined).unwrap(), secret);
        for c in &chunks {
            assert!(
                String::from_utf16(c).is_ok(),
                "a chunk ends inside a surrogate pair"
            );
        }
        let emoji = "\u{1F512}".repeat(11);
        let chunks = utf16_chunks(&emoji, MAX_EVENT_UTF16);
        assert_eq!(chunks.iter().map(|c| c.len()).collect::<Vec<_>>(), [20, 2]);
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
