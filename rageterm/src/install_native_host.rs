use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

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

#[derive(Debug, Serialize)]
struct SafariMetadata<'a> {
    name: &'a str,
    description: &'a str,
    path: String,
    bundle_id: &'a str,
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
        (Os::Macos, Browser::Safari, Scope::User) => {
            home().map(|h| h.join("Library/Application Support/Ragewarden"))
        }
        (Os::Macos, Browser::Safari, Scope::System) => Err(InstallError::UnsupportedCombination {
            browser: "safari",
            os: "macos (system scope)",
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
        Browser::Safari => {
            let m = SafariMetadata {
                name: HOST_NAME,
                description,
                path: binary_path.to_string(),
                bundle_id: extension_id,
            };
            Ok(serde_json::to_string_pretty(&m)?)
        }
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
    let binary = std::env::current_exe()?;
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

#[cfg(target_os = "windows")]
fn install_windows_registry(
    browser: Browser,
    scope: Scope,
    manifest_json: &str,
    yes: bool,
) -> Result<InstallOutcome, InstallError> {
    use winreg::enums::*;
    use winreg::RegKey;

    let manifest_dir = home()?.join(".config").join("ragewarden");
    fs::create_dir_all(&manifest_dir)?;
    let path = manifest_dir.join(format!("{HOST_NAME}.json"));
    let already_present = path.exists();
    if already_present && !yes {
        return Err(InstallError::WouldOverwrite(path));
    }
    fs::write(&path, manifest_json)?;

    let key_path = registry_subkey(browser);
    let root_hkey = match scope {
        Scope::User => HKEY_CURRENT_USER,
        Scope::System => HKEY_LOCAL_MACHINE,
    };
    let root = RegKey::predef(root_hkey);
    let (key, _) = root
        .create_subkey(&key_path)
        .map_err(|e| InstallError::Registry(e.to_string()))?;
    key.set_value("", &path.to_string_lossy().to_string())
        .map_err(|e| InstallError::Registry(e.to_string()))?;
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
    use winreg::enums::*;
    use winreg::RegKey;

    let key_path = registry_subkey(browser);
    let root_hkey = match scope {
        Scope::User => HKEY_CURRENT_USER,
        Scope::System => HKEY_LOCAL_MACHINE,
    };
    let root = RegKey::predef(root_hkey);
    let manifest_path = root
        .open_subkey(&key_path)
        .ok()
        .and_then(|k| k.get_value::<String, _>("").ok());
    root.delete_subkey_all(&key_path)
        .map_err(|e| InstallError::Registry(e.to_string()))?;
    if let Some(p) = manifest_path {
        let pb = PathBuf::from(&p);
        if pb.exists() {
            let _ = fs::remove_file(&pb);
        }
        return Ok(pb);
    }
    Ok(PathBuf::from(key_path))
}

#[cfg(not(target_os = "windows"))]
fn uninstall_windows_registry(_browser: Browser, _scope: Scope) -> Result<PathBuf, InstallError> {
    unreachable!("uninstall_windows_registry called on non-Windows target")
}

#[cfg(target_os = "windows")]
fn registry_subkey(browser: Browser) -> String {
    let prefix = match browser {
        Browser::Chromium => r"Software\Google\Chrome\NativeMessagingHosts",
        Browser::Firefox => r"Software\Mozilla\NativeMessagingHosts",
        Browser::Safari => unreachable!("safari + windows guarded earlier"),
    };
    format!("{prefix}\\{HOST_NAME}")
}

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
fn registry_subkey(_browser: Browser) -> String {
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

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
            "ragewardenchrome",                  // the old placeholder: 16 chars
            "abcdefghijklmnopabcdefghijklmno",   // 31 chars
            "abcdefghijklmnopabcdefghijklmnopq", // 33 chars
            "abcdefghijklmnopabcdefghijklmnoq",  // `q` is out of range
            "Abcdefghijklmnopabcdefghijklmnop",  // uppercase
            "abcdefghijklmnopabcdefghijklmno1",  // digit
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
    fn safari_metadata_records_bundle_id() {
        let json =
            build_manifest_json(Browser::Safari, "/bin/rageterm", "com.ragewarden.safari").unwrap();
        assert!(json.contains("\"bundle_id\": \"com.ragewarden.safari\""));
    }

    #[test]
    fn manifest_path_resolves_per_os() {
        if cfg!(target_os = "macos") {
            let p = manifest_path(Browser::Chromium, Scope::User).unwrap();
            assert!(p
                .to_string_lossy()
                .contains("Google/Chrome/NativeMessagingHosts"));
            assert!(p.to_string_lossy().ends_with("com.ragewarden.host.json"));
            let p = manifest_path(Browser::Firefox, Scope::User).unwrap();
            assert!(p.to_string_lossy().contains("Mozilla/NativeMessagingHosts"));
            let p = manifest_path(Browser::Chromium, Scope::System).unwrap();
            assert!(p.starts_with("/Library/Google"));
        } else if cfg!(target_os = "linux") {
            let p = manifest_path(Browser::Chromium, Scope::User).unwrap();
            assert!(p
                .to_string_lossy()
                .contains(".config/google-chrome/NativeMessagingHosts"));
            let p = manifest_path(Browser::Firefox, Scope::User).unwrap();
            assert!(p
                .to_string_lossy()
                .contains(".mozilla/native-messaging-hosts"));
            let p = manifest_path(Browser::Chromium, Scope::System).unwrap();
            assert!(p.starts_with("/etc/opt/chrome"));
            let p = manifest_path(Browser::Firefox, Scope::System).unwrap();
            assert!(p.starts_with("/usr/lib/mozilla"));

            let err = manifest_path(Browser::Safari, Scope::User).unwrap_err();
            assert!(matches!(err, InstallError::UnsupportedCombination { .. }));
        }
    }
}
