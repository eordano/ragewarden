use std::fs;
use std::path::PathBuf;

use crate::pass_import::{
    PassImportError, item_name_from_relative, plan_import, resolve_store_dir,
    split_password_and_notes,
};
use crate::tests_lock::ENV_LOCK;
use tempfile::TempDir;

fn touch_gpg(root: &std::path::Path, rel: &str) {
    let p = root.join(rel);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&p, b"placeholder").unwrap();
}

#[test]
fn name_strips_dot_gpg_and_uses_forward_slash() {
    use std::path::Path;
    let rel = Path::new("github.com.gpg");
    assert_eq!(item_name_from_relative(rel, None).unwrap(), "github.com");
    let rel = Path::new("work").join("aws").join("prod-key.gpg");
    assert_eq!(
        item_name_from_relative(&rel, None).unwrap(),
        "work/aws/prod-key"
    );
}

#[test]
fn name_with_folder_arg_prepends_subfolder() {
    use std::path::Path;
    assert_eq!(
        item_name_from_relative(Path::new("github.com.gpg"), Some("imported")).unwrap(),
        "imported/github.com"
    );
    assert_eq!(
        item_name_from_relative(Path::new("github.com.gpg"), Some("/imported/")).unwrap(),
        "imported/github.com"
    );
}

#[test]
fn plan_skips_non_gpg_files() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    touch_gpg(root, "github.com.gpg");
    fs::write(root.join("README.txt"), b"hi").unwrap();
    fs::write(root.join(".gpg-id"), b"key").unwrap();
    fs::create_dir_all(root.join(".git")).unwrap();
    fs::write(root.join(".git/config"), b"git").unwrap();

    let plan = plan_import(root, None).unwrap();
    let names: Vec<String> = plan.items.iter().map(|i| i.name.clone()).collect();
    assert_eq!(names, vec!["github.com".to_string()]);
}

#[test]
fn plan_recursively_walks_subfolders_with_correct_names() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    touch_gpg(root, "alpha.gpg");
    touch_gpg(root, "work/aws/prod.gpg");
    touch_gpg(root, "work/aws/staging.gpg");
    touch_gpg(root, "personal/mail/imap.gpg");

    let plan = plan_import(root, None).unwrap();
    let names: Vec<String> = plan.items.iter().map(|i| i.name.clone()).collect();
    assert_eq!(
        names,
        vec![
            "alpha".to_string(),
            "personal/mail/imap".to_string(),
            "work/aws/prod".to_string(),
            "work/aws/staging".to_string(),
        ]
    );
}

#[test]
fn plan_with_folder_arg_prefixes_every_item() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    touch_gpg(root, "alpha.gpg");
    touch_gpg(root, "nested/beta.gpg");

    let plan = plan_import(root, Some("imported-2026")).unwrap();
    let names: Vec<String> = plan.items.iter().map(|i| i.name.clone()).collect();
    assert_eq!(
        names,
        vec![
            "imported-2026/alpha".to_string(),
            "imported-2026/nested/beta".to_string(),
        ]
    );
}

#[test]
fn plan_errors_when_source_missing() {
    let tmp = TempDir::new().unwrap();
    let nope = tmp.path().join("does-not-exist");
    let err = plan_import(&nope, None).unwrap_err();
    assert!(matches!(err, PassImportError::StoreNotFound(_)));
}

#[test]
fn split_keeps_first_line_as_password_rest_as_notes() {
    let pt = b"hunter2\nuser: alice\nurl: https://github.com\n";
    let (pw, notes) = split_password_and_notes(pt);
    assert_eq!(pw.as_slice(), b"hunter2");
    assert_eq!(notes.unwrap(), "user: alice\nurl: https://github.com");
}

#[test]
fn split_handles_password_only_no_notes() {
    let pt = b"hunter2";
    let (pw, notes) = split_password_and_notes(pt);
    assert_eq!(pw.as_slice(), b"hunter2");
    assert!(notes.is_none());
}

#[test]
fn split_password_with_carriage_returns_preserved() {
    let pt = b"pw\nline1\nline2";
    let (pw, notes) = split_password_and_notes(pt);
    assert_eq!(pw.as_slice(), b"pw");
    assert_eq!(notes.as_deref(), Some("line1\nline2"));
}

#[test]
fn resolve_store_dir_explicit_overrides_env() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prev = std::env::var_os("PASSWORD_STORE_DIR");
    crate::tests_lock::set_var("PASSWORD_STORE_DIR", "/from/env");

    let explicit = std::path::Path::new("/from/cli");
    assert_eq!(
        resolve_store_dir(Some(explicit)).unwrap(),
        explicit.to_path_buf()
    );

    if let Some(p) = prev {
        crate::tests_lock::set_var("PASSWORD_STORE_DIR", p);
    } else {
        crate::tests_lock::remove_var("PASSWORD_STORE_DIR");
    }
}

#[test]
fn resolve_store_dir_falls_back_to_home_default() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prev_pw = std::env::var_os("PASSWORD_STORE_DIR");
    let prev_home = std::env::var_os("HOME");
    crate::tests_lock::remove_var("PASSWORD_STORE_DIR");
    let tmp = TempDir::new().unwrap();
    crate::tests_lock::set_var("HOME", tmp.path());

    let got = resolve_store_dir(None).unwrap();
    assert_eq!(got, PathBuf::from(tmp.path()).join(".password-store"));

    if let Some(p) = prev_pw {
        crate::tests_lock::set_var("PASSWORD_STORE_DIR", p);
    }
    if let Some(p) = prev_home {
        crate::tests_lock::set_var("HOME", p);
    } else {
        crate::tests_lock::remove_var("HOME");
    }
}
