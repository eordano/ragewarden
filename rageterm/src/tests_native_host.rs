use std::io::Cursor;

use crate::install_native_host::{self, build_manifest_json, manifest_path, Browser, Scope};
use crate::native_host::{read_frame, write_frame, RequestContext};
use crate::tests_lock::ENV_LOCK;

#[test]
fn frame_length_prefix_is_little_endian() {
    let mut out = Vec::new();
    write_frame(&mut out, b"abc").unwrap();
    assert_eq!(out[0], 3);
    assert_eq!(out[1], 0);
    assert_eq!(out[2], 0);
    assert_eq!(out[3], 0);
    assert_eq!(&out[4..], b"abc");
}

#[test]
fn frame_round_trip_preserves_payload() {
    let payloads: &[&[u8]] = &[
        b"",
        b"x",
        b"hello world",
        br#"{"method":"unwrap_stanza","stanza":{"tag":"piv-p256","args":[],"body":"AAA="}}"#,
    ];
    for payload in payloads {
        let mut out = Vec::new();
        write_frame(&mut out, payload).unwrap();
        let mut cur = Cursor::new(out);
        let read = read_frame(&mut cur).unwrap().unwrap();
        assert_eq!(read.as_slice(), *payload);
    }
}

#[test]
fn frame_eof_at_start_returns_none() {
    let mut cur = Cursor::new(Vec::<u8>::new());
    assert!(read_frame(&mut cur).unwrap().is_none());
}

#[test]
fn frame_truncated_length_prefix_returns_none() {
    let cur = Cursor::new(vec![0x05, 0x00]);
    let mut cur = cur;
    assert!(read_frame(&mut cur).unwrap().is_none());
}

#[test]
fn install_native_host_path_per_os() {
    if cfg!(target_os = "macos") {
        let p = manifest_path(Browser::Chromium, Scope::User).unwrap();
        let s = p.to_string_lossy();
        assert!(s.contains("Library/Application Support/Google/Chrome/NativeMessagingHosts"));
        assert!(s.ends_with("com.ragewarden.host.json"));

        let p = manifest_path(Browser::Firefox, Scope::User).unwrap();
        assert!(p
            .to_string_lossy()
            .contains("Library/Application Support/Mozilla/NativeMessagingHosts"));

        let p = manifest_path(Browser::Safari, Scope::User).unwrap();
        assert!(p
            .to_string_lossy()
            .contains("Library/Application Support/Ragewarden"));

        let p = manifest_path(Browser::Chromium, Scope::System).unwrap();
        assert!(p.starts_with("/Library/Google/Chrome"));
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
    }
}

#[test]
fn manifest_json_chromium_uses_allowed_origins_list() {
    let id = "abcdefghijklmnopabcdefghijklmnop";
    let json = build_manifest_json(Browser::Chromium, "/usr/local/bin/rageterm", id).unwrap();
    assert!(json.contains("\"allowed_origins\""));
    assert!(json.contains(&format!("chrome-extension://{id}/")));
    assert!(json.contains("\"path\": \"/usr/local/bin/rageterm\""));
    assert!(json.contains("\"name\": \"com.ragewarden.host\""));
    assert!(json.contains("\"type\": \"stdio\""));
}

#[test]
fn manifest_json_chromium_refuses_non_extension_ids() {
    for bad in ["ragewardenchrome", "abcdef", ""] {
        let err = build_manifest_json(Browser::Chromium, "/usr/local/bin/rageterm", bad)
            .unwrap_err();
        assert!(matches!(
            err,
            install_native_host::InstallError::InvalidExtensionId(_)
        ));
    }
}

#[test]
fn manifest_json_firefox_uses_allowed_extensions_list() {
    let json = build_manifest_json(
        Browser::Firefox,
        "/usr/local/bin/rageterm",
        "ragewarden@ragewarden",
    )
    .unwrap();
    assert!(json.contains("\"allowed_extensions\""));
    assert!(json.contains("ragewarden@ragewarden"));
    assert!(!json.contains("allowed_origins"));
}

#[test]
fn install_then_uninstall_round_trip_unix_isolated_home() {
    if cfg!(target_os = "windows") {
        return;
    }
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::TempDir::new().unwrap();
    let prev = std::env::var_os("HOME");
    std::env::set_var("HOME", tmp.path());

    let res = install_native_host::install(
        Browser::Firefox,
        Scope::User,
        install_native_host::DEFAULT_FIREFOX_EXTENSION_ID,
        true,
    );
    let outcome = res.expect("install should succeed");
    assert!(outcome.path.exists());
    assert!(!outcome.already_present);

    let again = install_native_host::install(
        Browser::Firefox,
        Scope::User,
        install_native_host::DEFAULT_FIREFOX_EXTENSION_ID,
        true,
    )
    .expect("second install with --yes should succeed");
    assert!(again.already_present);

    let removed = install_native_host::uninstall(Browser::Firefox, Scope::User).expect("uninstall");
    assert!(!removed.exists());

    let err = install_native_host::uninstall(Browser::Firefox, Scope::User);
    assert!(matches!(
        err.unwrap_err(),
        install_native_host::InstallError::NotInstalled(_)
    ));

    if let Some(p) = prev {
        std::env::set_var("HOME", p);
    } else {
        std::env::remove_var("HOME");
    }
}

#[test]
fn install_refuses_overwrite_without_yes() {
    if cfg!(target_os = "windows") {
        return;
    }
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::TempDir::new().unwrap();
    let prev = std::env::var_os("HOME");
    std::env::set_var("HOME", tmp.path());

    let _first = install_native_host::install(
        Browser::Firefox,
        Scope::User,
        install_native_host::DEFAULT_FIREFOX_EXTENSION_ID,
        true,
    )
    .expect("first install");
    let second = install_native_host::install(
        Browser::Firefox,
        Scope::User,
        install_native_host::DEFAULT_FIREFOX_EXTENSION_ID,
        false,
    );

    if let Some(p) = prev {
        std::env::set_var("HOME", p);
    } else {
        std::env::remove_var("HOME");
    }
    assert!(matches!(
        second.unwrap_err(),
        install_native_host::InstallError::WouldOverwrite(_)
    ));
}

#[test]
fn action_prompt_includes_action_and_domain() {
    let ctx = RequestContext {
        action: "autofill".into(),
        domain: "github.com".into(),
    };
    let prompt = crate::native_host::action_prompt(&ctx);
    assert!(prompt.contains("github.com"));
    assert!(prompt.contains("Autofill"));
}
