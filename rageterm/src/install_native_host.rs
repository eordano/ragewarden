use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;
use thiserror::Error;

pub const HOST_NAME: &str = "com.ragewarden.host";

pub const DEFAULT_FIREFOX_EXTENSION_ID: &str = "ragewarden@ragewarden";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Browser {
    Chromium,
    Firefox,
    Safari,
}

impl Browser {
    pub fn parse(s: &str) -> Result<Self, InstallError> {
        match s.to_ascii_lowercase().as_str() {
            "chromium" | "chrome" => Ok(Browser::Chromium),
            "firefox" => Ok(Browser::Firefox),
            "safari" => Ok(Browser::Safari),
            other => Err(InstallError::UnsupportedBrowser(other.to_string())),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Browser::Chromium => "chromium",
            Browser::Firefox => "firefox",
            Browser::Safari => "safari",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    User,
    System,
}

#[derive(Debug, Error)]
pub enum InstallError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported browser `{0}` (expected chromium|firefox|safari)")]
    UnsupportedBrowser(String),
    #[error("{browser} on {os} is not supported")]
    UnsupportedCombination {
        browser: &'static str,
        os: &'static str,
    },
    #[error("could not resolve home directory")]
    NoHomeDir,
    #[error("manifest already exists at {0}; pass --yes to overwrite")]
    WouldOverwrite(PathBuf),
    #[error("not installed at {0}")]
    NotInstalled(PathBuf),
    #[error("registry: {0}")]
    #[allow(dead_code)]
    Registry(String),
    #[error(
        "`{0}` is not a Chrome extension id -- expected exactly 32 characters, each a lowercase \
         letter a-p (copy the id from chrome://extensions with the Ragewarden extension loaded)"
    )]
    InvalidExtensionId(String),
}

/// Chrome extension ids are the mpdecimal encoding of a SHA-256 prefix: exactly
/// 32 characters, each in `a`-`p`. Anything else in `allowed_origins` makes
/// Chrome silently refuse to start the host, so an invalid id is never written.
pub fn validate_chromium_extension_id(id: &str) -> Result<(), InstallError> {
    if id.len() == 32 && id.bytes().all(|b| b.is_ascii_lowercase() && b <= b'p') {
        Ok(())
    } else {
        Err(InstallError::InvalidExtensionId(id.to_string()))
    }
}

#[derive(Debug, Serialize)]
struct ChromiumManifest<'a> {
    name: &'a str,
    description: &'a str,
    path: String,
    #[serde(rename = "type")]
    transport: &'a str,
    allowed_origins: Vec<String>,
}

#[derive(Debug, Serialize)]
struct FirefoxManifest<'a> {
    name: &'a str,
    description: &'a str,
    path: String,
    #[serde(rename = "type")]
    transport: &'a str,
    allowed_extensions: Vec<String>,
}

/// Safari has no native-messaging manifest: the Ragewarden Safari app's
/// extension relays each request to rageterm itself
/// (`ragemanifest/safari-host-app/Extension/SafariWebExtensionHandler.swift`,
/// `ragetermURL()`). It runs the rageterm bundled into the app, else the first
/// of these that is executable -- in this order; `~` is the user's home and
/// `{user}` their login name.
pub const SAFARI_RELAY_PATHS: &[&str] = &[
    "/opt/homebrew/bin/rageterm",
    "/usr/local/bin/rageterm",
    "~/.nix-profile/bin/rageterm",
    "/etc/profiles/per-user/{user}/bin/rageterm",
    "/run/current-system/sw/bin/rageterm",
];

pub fn safari_relay_paths(home: &Path, user: &str) -> Vec<PathBuf> {
    SAFARI_RELAY_PATHS
        .iter()
        .map(|p| match p.strip_prefix("~/") {
            Some(rest) => home.join(rest),
            None => PathBuf::from(p.replace("{user}", user)),
        })
        .collect()
}

/// The rageterm the Safari app runs when it does not bundle one.
pub fn safari_relay_target() -> Result<Option<PathBuf>, InstallError> {
    let user = std::env::var("USER").unwrap_or_default();
    Ok(safari_relay_paths(&home()?, &user)
        .into_iter()
        .find(|p| is_executable(p)))
}

fn is_executable(p: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(p)
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        p.is_file()
    }
}

/// The metadata file older rageterm versions wrote for Safari, which nothing
/// read; install and uninstall remove it.
pub fn legacy_safari_metadata() -> Result<PathBuf, InstallError> {
    Ok(home()?
        .join("Library/Application Support/Ragewarden")
        .join(format!("{HOST_NAME}.json")))
}

pub fn manifest_dir(browser: Browser, scope: Scope) -> Result<PathBuf, InstallError> {
    let os = current_os();
    match (os, browser, scope) {
        (Os::Macos, Browser::Chromium, Scope::User) => {
            home().map(|h| h.join("Library/Application Support/Google/Chrome/NativeMessagingHosts"))
        }
        (Os::Macos, Browser::Chromium, Scope::System) => {
            Ok(PathBuf::from("/Library/Google/Chrome/NativeMessagingHosts"))
        }
        (Os::Macos, Browser::Firefox, Scope::User) => {
            home().map(|h| h.join("Library/Application Support/Mozilla/NativeMessagingHosts"))
        }
        (Os::Macos, Browser::Firefox, Scope::System) => Ok(PathBuf::from(
            "/Library/Application Support/Mozilla/NativeMessagingHosts",
        )),
        (Os::Macos, Browser::Safari, _) => Err(InstallError::UnsupportedCombination {
            browser: "safari",
            os: "macos (Safari has no native-messaging manifest; the Ragewarden app relays)",
        }),
        (Os::Linux, Browser::Chromium, Scope::User) => {
            home().map(|h| h.join(".config/google-chrome/NativeMessagingHosts"))
        }
        (Os::Linux, Browser::Chromium, Scope::System) => {
            Ok(PathBuf::from("/etc/opt/chrome/native-messaging-hosts"))
        }
        (Os::Linux, Browser::Firefox, Scope::User) => {
            home().map(|h| h.join(".mozilla/native-messaging-hosts"))
        }
        (Os::Linux, Browser::Firefox, Scope::System) => {
            Ok(PathBuf::from("/usr/lib/mozilla/native-messaging-hosts"))
        }
        (Os::Linux, Browser::Safari, _) => Err(InstallError::UnsupportedCombination {
            browser: "safari",
            os: "linux",
        }),
        (Os::Windows, Browser::Safari, _) => Err(InstallError::UnsupportedCombination {
            browser: "safari",
            os: "windows",
        }),
        (Os::Windows, _, _) => Ok(PathBuf::from("__windows_uses_registry__")),
        (Os::Other, _, _) => Err(InstallError::UnsupportedCombination {
            browser: browser.as_str_static(),
            os: "unknown",
        }),
    }
}

pub fn manifest_path(browser: Browser, scope: Scope) -> Result<PathBuf, InstallError> {
    let dir = manifest_dir(browser, scope)?;
    Ok(dir.join(format!("{HOST_NAME}.json")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Os {
    Macos,
    Linux,
    Windows,
    Other,
}

fn current_os() -> Os {
    if cfg!(target_os = "macos") {
        Os::Macos
    } else if cfg!(target_os = "linux") {
        Os::Linux
    } else if cfg!(target_os = "windows") {
        Os::Windows
    } else {
        Os::Other
    }
}

fn home() -> Result<PathBuf, InstallError> {
    dirs::home_dir().ok_or(InstallError::NoHomeDir)
}

impl Browser {
    fn as_str_static(self) -> &'static str {
        self.as_str()
    }
}

pub fn build_manifest_json(
    browser: Browser,
    binary_path: &str,
    extension_id: &str,
) -> Result<String, InstallError> {
    let description = "Ragewarden native messaging host";
    match browser {
        Browser::Chromium => {
            validate_chromium_extension_id(extension_id)?;
            let m = ChromiumManifest {
                name: HOST_NAME,
                description,
                path: binary_path.to_string(),
                transport: "stdio",
                allowed_origins: vec![format!("chrome-extension://{extension_id}/")],
            };
            Ok(serde_json::to_string_pretty(&m)?)
        }
        Browser::Firefox => {
            let m = FirefoxManifest {
                name: HOST_NAME,
                description,
                path: binary_path.to_string(),
                transport: "stdio",
                allowed_extensions: vec![extension_id.to_string()],
            };
            Ok(serde_json::to_string_pretty(&m)?)
        }
        Browser::Safari => Err(InstallError::UnsupportedCombination {
            browser: "safari",
            os: "any OS (Safari has no native-messaging manifest)",
        }),
    }
}

#[derive(Debug)]
pub struct InstallOutcome {
    pub path: PathBuf,
    pub already_present: bool,
}

pub fn install(
    browser: Browser,
    scope: Scope,
    extension_id: &str,
    yes: bool,
) -> Result<InstallOutcome, InstallError> {
    let binary = stable_binary_path(&std::env::current_exe()?, &stable_candidates());
    if binary.starts_with("/nix/store") {
        eprintln!(
            "rageterm: the manifest points at {} -- a Nix store path that disappears after \
             garbage collection. Install rageterm into a profile (home-manager, \
             environment.systemPackages or `nix profile install`) and re-run this command.",
            binary.display()
        );
    }
    let binary_str = binary.to_string_lossy().to_string();
    let manifest = build_manifest_json(browser, &binary_str, extension_id)?;

    if cfg!(target_os = "windows") {
        return install_windows_registry(browser, scope, &manifest, yes);
    }

    let path = manifest_path(browser, scope)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let already_present = path.exists();
    if already_present && !yes {
        return Err(InstallError::WouldOverwrite(path));
    }
    let mut f = fs::File::create(&path)?;
    f.write_all(manifest.as_bytes())?;
    f.flush()?;
    Ok(InstallOutcome {
        path,
        already_present,
    })
}

pub fn uninstall(browser: Browser, scope: Scope) -> Result<PathBuf, InstallError> {
    if cfg!(target_os = "windows") {
        return uninstall_windows_registry(browser, scope);
    }
    let path = manifest_path(browser, scope)?;
    if !path.exists() {
        return Err(InstallError::NotInstalled(path));
    }
    fs::remove_file(&path)?;
    Ok(path)
}

/// Where a Windows install puts things: the manifest file, and the registry
/// keys (under HKCU for `--user`, HKLM for `--system`) whose default value
/// names it. Every Chromium-family browser reads its own key, so `chromium`
/// registers Chrome, Chromium and Edge alike.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsRegistration {
    pub manifest_path: PathBuf,
    pub machine_wide: bool,
    pub subkeys: Vec<String>,
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn windows_registration(
    browser: Browser,
    scope: Scope,
    user_config_dir: &Path,
    program_data: &Path,
) -> Result<WindowsRegistration, InstallError> {
    let prefixes: &[&str] = match browser {
        Browser::Chromium => &[
            r"Software\Google\Chrome\NativeMessagingHosts",
            r"Software\Chromium\NativeMessagingHosts",
            r"Software\Microsoft\Edge\NativeMessagingHosts",
        ],
        Browser::Firefox => &[r"Software\Mozilla\NativeMessagingHosts"],
        Browser::Safari => {
            return Err(InstallError::UnsupportedCombination {
                browser: browser.as_str_static(),
                os: "windows",
            });
        }
    };
    let dir = match scope {
        Scope::User => user_config_dir.join("ragewarden"),
        Scope::System => program_data.join("ragewarden"),
    };
    Ok(WindowsRegistration {
        manifest_path: dir.join(format!("{HOST_NAME}.{}.json", browser.as_str())),
        machine_wide: scope == Scope::System,
        subkeys: prefixes
            .iter()
            .map(|p| format!("{p}\\{HOST_NAME}"))
            .collect(),
    })
}

#[cfg(target_os = "windows")]
fn windows_dirs() -> Result<(PathBuf, PathBuf), InstallError> {
    let user = dirs::config_dir().ok_or(InstallError::NoHomeDir)?;
    let program_data = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    Ok((user, program_data))
}

#[cfg(target_os = "windows")]
fn install_windows_registry(
    browser: Browser,
    scope: Scope,
    manifest_json: &str,
    yes: bool,
) -> Result<InstallOutcome, InstallError> {
    use winreg::RegKey;
    use winreg::enums::*;

    let (user, program_data) = windows_dirs()?;
    let plan = windows_registration(browser, scope, &user, &program_data)?;
    let path = plan.manifest_path.clone();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let already_present = path.exists();
    if already_present && !yes {
        return Err(InstallError::WouldOverwrite(path));
    }
    fs::write(&path, manifest_json)?;

    let root = RegKey::predef(if plan.machine_wide {
        HKEY_LOCAL_MACHINE
    } else {
        HKEY_CURRENT_USER
    });
    for subkey in &plan.subkeys {
        let (key, _) = root
            .create_subkey(subkey)
            .map_err(|e| InstallError::Registry(e.to_string()))?;
        key.set_value("", &path.to_string_lossy().to_string())
            .map_err(|e| InstallError::Registry(e.to_string()))?;
    }
    Ok(InstallOutcome {
        path,
        already_present,
    })
}

#[cfg(not(target_os = "windows"))]
fn install_windows_registry(
    _browser: Browser,
    _scope: Scope,
    _manifest_json: &str,
    _yes: bool,
) -> Result<InstallOutcome, InstallError> {
    unreachable!("install_windows_registry called on non-Windows target")
}

#[cfg(target_os = "windows")]
fn uninstall_windows_registry(browser: Browser, scope: Scope) -> Result<PathBuf, InstallError> {
    use winreg::RegKey;
    use winreg::enums::*;

    let (user, program_data) = windows_dirs()?;
    let plan = windows_registration(browser, scope, &user, &program_data)?;
    let root = RegKey::predef(if plan.machine_wide {
        HKEY_LOCAL_MACHINE
    } else {
        HKEY_CURRENT_USER
    });
    let mut removed_any = false;
    for subkey in &plan.subkeys {
        removed_any |= root.delete_subkey_all(subkey).is_ok();
    }
    let existed = plan.manifest_path.exists();
    if existed {
        fs::remove_file(&plan.manifest_path)?;
    }
    if !removed_any && !existed {
        return Err(InstallError::NotInstalled(plan.manifest_path));
    }
    Ok(plan.manifest_path)
}

#[cfg(not(target_os = "windows"))]
fn uninstall_windows_registry(_browser: Browser, _scope: Scope) -> Result<PathBuf, InstallError> {
    unreachable!("uninstall_windows_registry called on non-Windows target")
}

/// Profile symlinks that outlive a garbage-collected store path, most specific first.
fn stable_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(home) = dirs::home_dir() {
        out.push(home.join(".nix-profile/bin/rageterm"));
        out.push(home.join(".local/state/nix/profile/bin/rageterm"));
    }
    if let Ok(user) = std::env::var("USER") {
        out.push(PathBuf::from(format!(
            "/etc/profiles/per-user/{user}/bin/rageterm"
        )));
    }
    out.push(PathBuf::from("/run/current-system/sw/bin/rageterm"));
    out
}

/// The path to write into the manifest: `current` unless it is a store path
/// and a profile link to a rageterm binary exists.
pub fn stable_binary_path(current: &Path, candidates: &[PathBuf]) -> PathBuf {
    if !current.starts_with("/nix/store") {
        return current.to_path_buf();
    }
    candidates
        .iter()
        .find(|c| c.exists())
        .cloned()
        .unwrap_or_else(|| current.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_windows_chromium_install_registers_every_chromium_family_key() {
        let plan = windows_registration(
            Browser::Chromium,
            Scope::User,
            Path::new(r"C:\Users\u\AppData\Roaming"),
            Path::new(r"C:\ProgramData"),
        )
        .unwrap();
        assert!(!plan.machine_wide);
        assert_eq!(
            plan.subkeys,
            vec![
                format!(r"Software\Google\Chrome\NativeMessagingHosts\{HOST_NAME}"),
                format!(r"Software\Chromium\NativeMessagingHosts\{HOST_NAME}"),
                format!(r"Software\Microsoft\Edge\NativeMessagingHosts\{HOST_NAME}"),
            ]
        );
        assert!(
            plan.manifest_path
                .starts_with(Path::new(r"C:\Users\u\AppData\Roaming").join("ragewarden"))
        );
    }

    #[test]
    fn a_windows_system_install_writes_under_program_data_and_hklm() {
        let plan = windows_registration(
            Browser::Firefox,
            Scope::System,
            Path::new("user"),
            Path::new(r"C:\ProgramData"),
        )
        .unwrap();
        assert!(plan.machine_wide);
        assert!(
            plan.manifest_path
                .starts_with(Path::new(r"C:\ProgramData").join("ragewarden"))
        );
        assert_eq!(
            plan.subkeys,
            vec![format!(
                r"Software\Mozilla\NativeMessagingHosts\{HOST_NAME}"
            )]
        );
    }

    #[test]
    fn safari_on_windows_is_refused_instead_of_panicking() {
        assert!(matches!(
            windows_registration(Browser::Safari, Scope::User, Path::new("u"), Path::new("p")),
            Err(InstallError::UnsupportedCombination { .. })
        ));
    }

    #[test]
    fn a_windows_manifest_escapes_the_exe_path_as_json() {
        let json = build_manifest_json(
            Browser::Chromium,
            r"C:\Program Files\rageterm\rageterm.exe",
            "abcdefghijklmnopabcdefghijklmnop",
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["path"], r"C:\Program Files\rageterm\rageterm.exe");
        assert_eq!(v["type"], "stdio");
        assert_eq!(
            v["allowed_origins"][0],
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop/"
        );
    }

    #[test]
    fn parse_browser_accepts_aliases() {
        assert_eq!(Browser::parse("chromium").unwrap(), Browser::Chromium);
        assert_eq!(Browser::parse("Chrome").unwrap(), Browser::Chromium);
        assert_eq!(Browser::parse("FIREFOX").unwrap(), Browser::Firefox);
        assert_eq!(Browser::parse("safari").unwrap(), Browser::Safari);
        assert!(matches!(
            Browser::parse("opera").unwrap_err(),
            InstallError::UnsupportedBrowser(_)
        ));
    }

    const VALID_CHROMIUM_ID: &str = "abcdefghijklmnopabcdefghijklmnop";

    #[test]
    fn chromium_manifest_uses_allowed_origins() {
        let json =
            build_manifest_json(Browser::Chromium, "/bin/rageterm", VALID_CHROMIUM_ID).unwrap();
        assert!(json.contains("\"allowed_origins\""));
        assert!(json.contains(&format!("chrome-extension://{VALID_CHROMIUM_ID}/")));
        assert!(json.contains("\"name\": \"com.ragewarden.host\""));
        assert!(json.contains("\"path\": \"/bin/rageterm\""));
        assert!(json.contains("\"type\": \"stdio\""));
    }

    #[test]
    fn chromium_extension_id_validation() {
        validate_chromium_extension_id(VALID_CHROMIUM_ID).unwrap();
        for bad in [
            "",
            "ragewardenchrome",
            "abcdefghijklmnopabcdefghijklmno",
            "abcdefghijklmnopabcdefghijklmnopq",
            "abcdefghijklmnopabcdefghijklmnoq",
            "Abcdefghijklmnopabcdefghijklmnop",
            "abcdefghijklmnopabcdefghijklmno1",
        ] {
            assert!(
                matches!(
                    validate_chromium_extension_id(bad),
                    Err(InstallError::InvalidExtensionId(_))
                ),
                "`{bad}` should be rejected"
            );
        }
    }

    #[test]
    fn chromium_manifest_refuses_invalid_extension_id() {
        let err = build_manifest_json(Browser::Chromium, "/bin/rageterm", "ragewardenchrome")
            .unwrap_err();
        assert!(matches!(err, InstallError::InvalidExtensionId(_)));
    }

    #[test]
    fn firefox_manifest_uses_allowed_extensions() {
        let json = build_manifest_json(Browser::Firefox, "/bin/rageterm", "ragewarden@ragewarden")
            .unwrap();
        assert!(json.contains("\"allowed_extensions\""));
        assert!(json.contains("ragewarden@ragewarden"));
        assert!(!json.contains("allowed_origins"));
    }

    #[test]
    fn safari_writes_no_manifest() {
        assert!(build_manifest_json(Browser::Safari, "/bin/rageterm", "x").is_err());
        assert!(manifest_path(Browser::Safari, Scope::User).is_err());
    }

    #[test]
    fn the_safari_relay_paths_are_the_ones_the_app_tries_in_its_order() {
        let swift = include_str!(
            "../../ragemanifest/safari-host-app/Extension/SafariWebExtensionHandler.swift"
        );
        let start = swift
            .find("let candidates = [")
            .expect("ragetermURL() candidates");
        let block = &swift[start..start + swift[start..].find(']').unwrap()];
        let from_swift: Vec<String> = block
            .lines()
            .skip(1)
            .map(|l| {
                l.trim()
                    .trim_end_matches(',')
                    .replace("realHome() + \"", "\"~")
                    .replace("\" + NSUserName() + \"", "{user}")
                    .trim_matches('"')
                    .to_string()
            })
            .filter(|l| !l.is_empty())
            .collect();
        assert_eq!(from_swift, SAFARI_RELAY_PATHS);
        let paths = safari_relay_paths(Path::new("/home/u"), "u");
        assert_eq!(paths[2], Path::new("/home/u/.nix-profile/bin/rageterm"));
        assert_eq!(paths[3], Path::new("/etc/profiles/per-user/u/bin/rageterm"));
    }

    #[test]
    fn manifest_path_resolves_per_os() {
        if cfg!(target_os = "macos") {
            let p = manifest_path(Browser::Chromium, Scope::User).unwrap();
            assert!(
                p.to_string_lossy()
                    .contains("Google/Chrome/NativeMessagingHosts")
            );
            assert!(p.to_string_lossy().ends_with("com.ragewarden.host.json"));
            let p = manifest_path(Browser::Firefox, Scope::User).unwrap();
            assert!(p.to_string_lossy().contains("Mozilla/NativeMessagingHosts"));
            let p = manifest_path(Browser::Chromium, Scope::System).unwrap();
            assert!(p.starts_with("/Library/Google"));
        } else if cfg!(target_os = "linux") {
            let p = manifest_path(Browser::Chromium, Scope::User).unwrap();
            assert!(
                p.to_string_lossy()
                    .contains(".config/google-chrome/NativeMessagingHosts")
            );
            let p = manifest_path(Browser::Firefox, Scope::User).unwrap();
            assert!(
                p.to_string_lossy()
                    .contains(".mozilla/native-messaging-hosts")
            );
            let p = manifest_path(Browser::Chromium, Scope::System).unwrap();
            assert!(p.starts_with("/etc/opt/chrome"));
            let p = manifest_path(Browser::Firefox, Scope::System).unwrap();
            assert!(p.starts_with("/usr/lib/mozilla"));

            let err = manifest_path(Browser::Safari, Scope::User).unwrap_err();
            assert!(matches!(err, InstallError::UnsupportedCombination { .. }));
        }
    }
}
