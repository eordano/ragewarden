use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use chrono::Utc;
use ragewarden_core::{PrfEntry, Recipient, encrypt_with_prf};
use thiserror::Error;
use walkdir::WalkDir;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum PassImportError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("password store not found at {0}")]
    StoreNotFound(PathBuf),
    #[error("gpg subprocess: {0}")]
    Gpg(String),
    #[error("walk: {0}")]
    Walk(String),
    #[error("encrypt: {0}")]
    Encrypt(String),
    #[error("decoded plaintext is empty for {0}")]
    EmptyPlaintext(PathBuf),
    #[error("no recipients enrolled")]
    NoRecipients,
    #[error("invalid name `{0}`: {1}")]
    InvalidName(String, String),
}

#[derive(Debug, Clone)]
pub struct ImportPlan {
    #[allow(dead_code)]
    pub source: PathBuf,
    pub items: Vec<PlannedItem>,
}

#[derive(Debug, Clone)]
pub struct PlannedItem {
    pub source: PathBuf,
    pub name: String,
}

pub fn resolve_store_dir(explicit: Option<&Path>) -> Result<PathBuf, PassImportError> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    if let Ok(dir) = std::env::var("PASSWORD_STORE_DIR") {
        if !dir.is_empty() {
            return Ok(PathBuf::from(dir));
        }
    }
    let home = dirs::home_dir().ok_or_else(|| {
        PassImportError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "could not resolve home directory",
        ))
    })?;
    Ok(home.join(".password-store"))
}

pub fn plan_import(source: &Path, folder: Option<&str>) -> Result<ImportPlan, PassImportError> {
    if !source.exists() {
        return Err(PassImportError::StoreNotFound(source.to_path_buf()));
    }
    let mut items = Vec::new();
    for entry in WalkDir::new(source).into_iter() {
        let entry = entry.map_err(|e| PassImportError::Walk(e.to_string()))?;
        let path = entry.path();
        if !entry.file_type().is_file() {
            continue;
        }
        let Some(ext) = path.extension() else {
            continue;
        };
        if ext != "gpg" {
            continue;
        }
        let rel = path
            .strip_prefix(source)
            .map_err(|e| PassImportError::Walk(format!("strip_prefix: {e}")))?;
        let name = item_name_from_relative(rel, folder)?;
        items.push(PlannedItem {
            source: path.to_path_buf(),
            name,
        });
    }
    items.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(ImportPlan {
        source: source.to_path_buf(),
        items,
    })
}

pub fn item_name_from_relative(
    rel: &Path,
    folder: Option<&str>,
) -> Result<String, PassImportError> {
    let s = rel.to_str().ok_or_else(|| {
        PassImportError::InvalidName(rel.display().to_string(), "non-utf8".into())
    })?;
    let trimmed = s
        .strip_suffix(".gpg")
        .ok_or_else(|| PassImportError::InvalidName(s.into(), "missing .gpg suffix".into()))?;
    let normalized = trimmed.replace(std::path::MAIN_SEPARATOR, "/");
    if normalized.is_empty() {
        return Err(PassImportError::InvalidName(
            s.into(),
            "empty after suffix strip".into(),
        ));
    }
    Ok(match folder {
        Some(f) if !f.is_empty() => format!("{}/{}", f.trim_matches('/'), normalized),
        _ => normalized,
    })
}

pub fn gpg_decrypt(file: &Path) -> Result<Zeroizing<Vec<u8>>, PassImportError> {
    let mut child = Command::new("gpg")
        .arg("--decrypt")
        .arg("--quiet")
        .arg("--batch")
        .arg(file)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| PassImportError::Gpg(format!("spawn gpg: {e}")))?;

    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| PassImportError::Gpg("gpg child has no stdout".into()))?;
    let mut buf: Vec<u8> = Vec::new();
    stdout
        .read_to_end(&mut buf)
        .map_err(|e| PassImportError::Gpg(format!("read stdout: {e}")))?;
    let buf = Zeroizing::new(buf);

    let status = child
        .wait()
        .map_err(|e| PassImportError::Gpg(format!("wait: {e}")))?;
    if !status.success() {
        let mut stderr = String::new();
        if let Some(mut e) = child.stderr.take() {
            let _ = e.read_to_string(&mut stderr);
        }
        return Err(PassImportError::Gpg(format!(
            "gpg --decrypt exited {}: {stderr}",
            status.code().unwrap_or(-1)
        )));
    }
    Ok(buf)
}

pub fn split_password_and_notes(plaintext: &[u8]) -> (Zeroizing<Vec<u8>>, Option<String>) {
    let split = plaintext.iter().position(|&b| b == b'\n');
    match split {
        Some(idx) => {
            let mut pw = Vec::with_capacity(idx);
            pw.extend_from_slice(&plaintext[..idx]);
            let pw = Zeroizing::new(pw);
            let rest = &plaintext[idx + 1..];
            let notes = if rest.is_empty() {
                None
            } else {
                Some(String::from_utf8_lossy(rest).trim_end().to_string())
            };
            (pw, notes)
        }
        None => {
            let pw = Zeroizing::new(plaintext.to_vec());
            (pw, None)
        }
    }
}

pub fn encrypt_password_to_recipients(
    password: &[u8],
    recipients: &[Recipient],
    prf_table: &[PrfEntry<'_>],
) -> Result<String, PassImportError> {
    let blob = encrypt_with_prf(password, recipients, prf_table)
        .map_err(|e| PassImportError::Encrypt(e.to_string()))?;
    String::from_utf8(blob.0).map_err(|e| PassImportError::Encrypt(format!("utf-8: {e}")))
}

pub fn write_log(items: &[ImportedItem]) -> Result<PathBuf, PassImportError> {
    let dir = dirs::home_dir()
        .ok_or_else(|| PassImportError::Io(io::Error::new(io::ErrorKind::NotFound, "no home")))?
        .join(".config")
        .join("ragewarden");
    fs::create_dir_all(&dir)?;
    let path = dir.join("pass-import.log");
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    let stamp = Utc::now().to_rfc3339();
    for it in items {
        writeln!(f, "{stamp}\t{}\t{}", it.name, it.source.display())?;
    }
    f.flush()?;
    Ok(path)
}

#[derive(Debug, Clone)]
pub struct ImportedItem {
    pub name: String,
    pub source: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::TempDir;

    fn touch_gpg(root: &Path, rel: &str) {
        let p = root.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&p, b"placeholder ciphertext").unwrap();
    }

    #[test]
    fn item_name_from_relative_strips_extension_and_normalizes() {
        let rel = Path::new("github.com.gpg");
        assert_eq!(item_name_from_relative(rel, None).unwrap(), "github.com");

        let rel = Path::new("work").join("aws").join("prod-key.gpg");
        assert_eq!(
            item_name_from_relative(&rel, None).unwrap(),
            "work/aws/prod-key"
        );

        let rel = Path::new("github.com.gpg");
        assert_eq!(
            item_name_from_relative(rel, Some("imported")).unwrap(),
            "imported/github.com"
        );

        let rel = Path::new("github.com.gpg");
        assert_eq!(
            item_name_from_relative(rel, Some("/imported/")).unwrap(),
            "imported/github.com"
        );
    }

    #[test]
    fn item_name_from_relative_rejects_non_gpg() {
        let rel = Path::new("notes.txt");
        let err = item_name_from_relative(rel, None).unwrap_err();
        assert!(matches!(err, PassImportError::InvalidName(_, _)));
    }

    #[test]
    fn plan_import_walks_only_gpg_files() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        touch_gpg(root, "github.com.gpg");
        touch_gpg(root, "gitlab.com.gpg");
        touch_gpg(root, "work/aws.gpg");
        fs::write(root.join("README"), b"plain readme").unwrap();
        fs::write(root.join(".gpg-id"), b"id").unwrap();

        let plan = plan_import(root, None).unwrap();
        let names: Vec<String> = plan.items.iter().map(|i| i.name.clone()).collect();
        assert_eq!(
            names,
            vec![
                "github.com".to_string(),
                "gitlab.com".to_string(),
                "work/aws".to_string(),
            ]
        );
    }

    #[test]
    fn plan_import_with_folder_prefixes_each_name() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        touch_gpg(root, "github.com.gpg");
        touch_gpg(root, "work/aws.gpg");

        let plan = plan_import(root, Some("imported")).unwrap();
        let names: Vec<String> = plan.items.iter().map(|i| i.name.clone()).collect();
        assert_eq!(
            names,
            vec![
                "imported/github.com".to_string(),
                "imported/work/aws".to_string(),
            ]
        );
    }

    #[test]
    fn plan_import_errors_when_store_missing() {
        let tmp = TempDir::new().unwrap();
        let nope = tmp.path().join("does-not-exist");
        let err = plan_import(&nope, None).unwrap_err();
        assert!(matches!(err, PassImportError::StoreNotFound(_)));
    }

    #[test]
    fn split_password_and_notes_separates_first_line() {
        let pt = b"hunter2\nuser: alice\nurl: https://github.com\n";
        let (pw, notes) = split_password_and_notes(pt);
        assert_eq!(pw.as_slice(), b"hunter2");
        assert_eq!(notes.unwrap(), "user: alice\nurl: https://github.com");
    }

    #[test]
    fn split_password_and_notes_handles_password_only() {
        let pt = b"hunter2";
        let (pw, notes) = split_password_and_notes(pt);
        assert_eq!(pw.as_slice(), b"hunter2");
        assert!(notes.is_none());
    }

    #[test]
    fn split_password_and_notes_with_password_and_blank_lines() {
        let pt = b"hunter2\n\n";
        let (pw, notes) = split_password_and_notes(pt);
        assert_eq!(pw.as_slice(), b"hunter2");
        assert_eq!(notes.as_deref(), Some(""));
    }

    #[test]
    fn resolve_store_dir_honors_explicit_path() {
        let explicit = Path::new("/tmp/some-other-store");
        assert_eq!(resolve_store_dir(Some(explicit)).unwrap(), explicit);
    }

    /// Same lock as `tests_pass_import`, which sets and clears
    /// `PASSWORD_STORE_DIR` for its own assertions: without it the two modules
    /// clobber each other's value in the shared process environment.
    #[test]
    fn resolve_store_dir_honors_env_var() {
        let _guard = crate::tests_lock::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var_os("PASSWORD_STORE_DIR");
        crate::tests_lock::set_var("PASSWORD_STORE_DIR", "/tmp/from-env-store");
        let got = resolve_store_dir(None).unwrap();
        if let Some(p) = prev {
            crate::tests_lock::set_var("PASSWORD_STORE_DIR", p);
        } else {
            crate::tests_lock::remove_var("PASSWORD_STORE_DIR");
        }
        assert_eq!(got, PathBuf::from("/tmp/from-env-store"));
    }
}
