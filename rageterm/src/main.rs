#![deny(clippy::undocumented_unsafe_blocks)]

use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod agent_add;
mod audit_helper;
mod ceremony;
mod commands;
mod config;
mod consent;
mod fido;
mod fido_ctap;
mod fill;
mod history_helper;
mod http;
mod hw;
mod identities;
mod idfile;
mod install_native_host;
mod keyring_id;
mod lock;
mod native_host;
mod native_proof;
mod output;
mod pass_import;
mod pin;
mod piv;
mod piv_apdu;
mod piv_pcsc;
mod recipients;
mod recovery;
mod session;
mod store;
mod tui;
mod vault;
mod zalloc;

#[global_allocator]
static ALLOCATOR: zalloc::WipeOnFree<std::alloc::System> = zalloc::WipeOnFree(std::alloc::System);

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_agent_add;
#[cfg(test)]
mod tests_consent;
#[cfg(test)]
mod tests_fill;
#[cfg(test)]
mod tests_lock;
#[cfg(test)]
mod tests_native_host;
#[cfg(test)]
mod tests_pass_import;
#[cfg(test)]
mod tests_piv;

#[derive(Parser, Debug)]
#[command(
    name = "rageterm",
    version,
    about = "Ragewarden terminal client -- Bitwarden/Vaultwarden vault with software, PIV, FIDO2, and keyring identities",
    long_about = None
)]
struct Cli {
    /// Skip the y/N confirmation on a read from a software-only vault.
    ///
    /// It cannot skip a hardware tap, it is refused outright on any vault with
    /// a device enrolled, and it never answers a destructive prompt -- `delete`,
    /// `folders remove` and `recipients remove` ask at the terminal regardless.
    #[arg(long, short = 'y', global = true)]
    yes: bool,

    /// Run the full-screen interface instead of a subcommand.
    #[arg(long)]
    tui: bool,

    /// Fail instead of waiting when another rageterm holds the vault lock.
    #[arg(long, global = true)]
    no_wait: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create an account on a Bitwarden/Vaultwarden server.
    Register {
        #[arg(long)]
        server: String,

        #[arg(long)]
        email: String,

        #[arg(long, default_value = "Ragewarden user")]
        name: String,

        /// Key derivation for the new account: `pbkdf2` (with
        /// `--kdf-iterations`) or `argon2id`.
        #[arg(long, default_value = "pbkdf2", value_parser = ["pbkdf2", "argon2id"])]
        kdf: String,

        #[arg(long, default_value_t = 600_000)]
        kdf_iterations: u32,

        /// Read the master password from the first line of stdin instead of
        /// prompting on the terminal.
        #[arg(long)]
        password_stdin: bool,
    },

    /// Unlock a server session and cache it for later commands.
    Login {
        #[arg(long)]
        server: String,

        #[arg(long)]
        email: String,

        /// Read the master password from the first line of stdin instead of
        /// prompting on the terminal.
        #[arg(long)]
        password_stdin: bool,

        /// Accept an account whose PBKDF2 count is below the minimum, then
        /// raise it to the current default on the server.
        #[arg(long)]
        allow_weak_kdf: bool,
    },

    /// Move every item from an X25519 PIV slot to a P-256 slot (which also
    /// signs the browser's per-unwrap proof) and retire the X25519 one. Without
    /// --public-key it prints the steps.
    MigratePiv {
        /// The P-256 slot to move to, e.g. 0x9d.
        #[arg(long, value_parser = parse_piv_slot)]
        slot: Option<u8>,

        /// That slot's public key (PEM, hex or a file), as for enroll-yubikey.
        #[arg(long)]
        public_key: Option<String>,

        #[arg(long)]
        label: Option<String>,

        /// The X25519 identity to migrate when more than one is enrolled.
        #[arg(long)]
        from: Option<String>,

        /// As for enroll-yubikey: record a slot that needs no touch.
        #[arg(long = "i-accept-this-slot-needs-no-touch")]
        allow_untouched_slot: bool,
    },

    /// Recover a FIDO2 credential's public key with one touch, for a credential
    /// enrolled before rageterm kept it, so the browser can verify its
    /// native-host unwraps. Without an id: every credential missing one.
    AttestFido2 { id: Option<String> },

    /// Print a new random password (or a BIP39 passphrase with --words).
    Generate {
        #[command(flatten)]
        gen_args: GenerateArgs,
    },

    /// Move an item into a folder; without `--folder` it leaves every folder.
    Mv {
        name: String,

        #[arg(long)]
        folder: Option<String>,
    },

    /// Show the newest audit events (and how many log lines were unreadable).
    Audit {
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },

    /// Drop the cached session and vault.
    Logout,

    /// Refresh the cached vault from the server.
    Sync,

    /// Generate this machine's software identity (identity.age).
    EnrollSoftwareIdentity {
        /// Keep identity.age as a bare secret key instead of protecting it
        /// with a passphrase. Implied when there is no terminal to ask on.
        #[arg(long)]
        plaintext: bool,
    },

    /// Put a passphrase on an existing plaintext identity.age.
    ProtectIdentity,

    /// Store or replace an item, wrapped to every recipient this machine covers.
    #[command(alias = "insert")]
    Set {
        name: String,

        #[arg(long, value_parser = parse_set_type)]
        r#type: Option<SetType>,

        #[arg(long)]
        from_stdin: bool,

        #[arg(long)]
        folder: Option<String>,

        /// Keep the item in this machine's local store instead of the server.
        /// Required when not logged in; `login` uploads local items.
        #[arg(long)]
        offline: bool,

        /// Store a newly generated password instead of reading one (see
        /// `rageterm generate` for the options); `copy` it afterwards.
        #[arg(long)]
        generate: bool,

        #[command(flatten)]
        gen_args: GenerateArgs,

        /// With `--type login`: the login's username.
        #[arg(long)]
        username: Option<String>,

        /// With `--type login`: a site the login belongs to (repeatable). This is
        /// what browser and Android autofill match on.
        #[arg(long = "url", value_name = "URL")]
        urls: Vec<String>,

        /// Write one protected field of an existing item (`code`, `notes`,
        /// `passphrase`, ...) and keep its others; default: the primary secret.
        #[arg(long, value_name = "FIELD")]
        field: Option<String>,

        /// For a new item: the fields the blob holds (default: the type's
        /// primary one). With more than one, each is prompted for, or stdin is
        /// a JSON object of them.
        #[arg(long, value_name = "FIELD,...", value_delimiter = ',')]
        protect: Vec<String>,

        /// An unprotected card, identity or SSH key field (repeatable), e.g.
        /// `--with brand=Visa --with expMonth=12`.
        #[arg(long = "with", value_name = "FIELD=VALUE", value_parser = parse_field_value)]
        with: Vec<(String, String)>,
    },

    /// List item names (never their contents).
    List {
        #[arg(long)]
        filter: Option<String>,

        #[arg(long)]
        json: bool,
    },

    /// Write an item's plaintext to stdout, for a pipe.
    #[command(alias = "pipe")]
    Get {
        name: String,

        /// A field of a multi-field item (`notes`, `code`, `passphrase`, ...);
        /// default: the item's primary secret.
        #[arg(long)]
        field: Option<String>,

        #[arg(long)]
        newline: bool,
    },

    /// Copy an item to the clipboard and clear it again.
    #[command(alias = "c")]
    Copy {
        name: String,

        #[arg(long, default_value_t = output::DEFAULT_CLIPBOARD_CLEAR_SECS)]
        clear: u64,
    },

    /// Print an item's plaintext to a terminal, refusing a pipe unless --force.
    #[command(alias = "show")]
    Reveal {
        name: String,

        #[arg(long)]
        force: bool,
    },

    /// Load a secret into the ssh-agent for a bounded lifetime.
    #[command(subcommand)]
    Agent(AgentCmd),

    /// Type an item into another window, never touching the clipboard.
    Fill {
        name: String,

        #[arg(long)]
        to: Option<String>,
    },

    /// Run a command with an item on FD 3, or in $RAGEWARDEN_SECRET.
    Exec {
        name: String,

        #[arg(long)]
        via_env: bool,

        /// Start the child with only PATH, HOME, USER, LOGNAME, SHELL, TERM,
        /// LANG and LC_* (plus `--keep`) instead of rageterm's environment.
        #[arg(long)]
        clean_env: bool,

        /// With `--clean-env`, also pass this variable through (repeatable).
        #[arg(long, value_name = "VAR", requires = "clean_env")]
        keep: Vec<String>,

        #[arg(trailing_var_arg = true, required = true)]
        argv: Vec<String>,
    },

    /// Enroll a YubiKey PIV slot as a recipient, proving possession first.
    EnrollYubikey {
        #[arg(long, default_value = "0x95", value_parser = parse_piv_slot)]
        slot: u8,

        #[arg(long)]
        label: Option<String>,

        /// The slot's public key, as a PEM file path, a literal PEM, or hex (66
        /// or 130 characters for P-256, 64 for X25519). Produce it with
        /// `ykman piv keys generate --algorithm ECCP256 <slot> pub.pem`.
        /// Enrollment runs one live ECDH against the card to prove it holds the
        /// matching private key before recording anything.
        #[arg(long, value_name = "PEM|HEX|PATH")]
        public_key: Option<String>,

        /// Enrol a slot that the card says needs no touch.
        ///
        /// Enrollment reads the slot's touch policy (YubiKey GET METADATA) and
        /// refuses when a touch is not required, because every later prompt
        /// would be claiming a physical confirmation that never happens. This
        /// flag records the slot anyway, and rageterm then says so on each use
        /// instead of announcing a touch. The name is deliberately unpleasant:
        /// the resulting recipient is protected by the PIN alone.
        #[arg(long = "i-accept-this-slot-needs-no-touch")]
        allow_untouched_slot: bool,

        /// Publish this X25519 slot with `stanzaVersion: 2` (the
        /// recipient-bound `piv-x25519-v2` stanza). Only once every client
        /// that opens your items reads v2; until then items stay v1.
        #[arg(long)]
        stanza_v2: bool,

        /// Accept an X25519 slot (YubiKey firmware 5.7+). New slots are P-256,
        /// which also sign the browser's per-unwrap proof; an X25519 slot
        /// cannot, and `migrate-piv` later moves its items to a P-256 one.
        #[arg(long)]
        x25519: bool,
    },

    /// Enroll a FIDO2 authenticator (hmac-secret) as a recipient.
    EnrollFido2 {
        #[arg(long, default_value = crate::fido::FIDO2_RP_ID)]
        rp: String,

        #[arg(long)]
        label: Option<String>,
    },

    /// Enroll a key held in the OS keyring as a recipient.
    EnrollKeyring {
        #[arg(long)]
        user: Option<String>,

        #[arg(long)]
        label: Option<String>,
    },

    /// Enroll a 24-word paper recovery identity as a recipient.
    EnrollRecovery {
        #[arg(long, default_value = "recovery")]
        label: String,

        #[arg(long, hide = true)]
        no_confirm: bool,
    },

    /// Rebuild the recovery identity from its 24 words.
    Recover {
        #[arg(long)]
        save: bool,
    },

    /// Delete an item from the server. There is no trash: this is permanent.
    Delete { name: String },

    /// List, create, rename and remove folders.
    #[command(subcommand)]
    Folders(FoldersCmd),

    /// List enrolled recipients, and which of them this machine wraps to.
    #[command(subcommand)]
    Recipients(RecipientsCmd),

    /// Re-encrypt items to your CURRENT recipient set -- the way to fold a
    /// newly-enrolled recipient into secrets that were stored before it
    /// existed. Name one item, or use --all (optionally --folder) or --only.
    #[command(alias = "rotate")]
    Reencrypt {
        /// The item to re-encrypt. Omit and pass --all or --only for many.
        name: Option<String>,

        /// Re-encrypt every protected item to the current recipient set.
        #[arg(long)]
        all: bool,

        /// Re-encrypt only the items `list` marks `[legacy-wrap]`.
        #[arg(long)]
        legacy: bool,

        /// With --all, limit to items in this folder.
        #[arg(long)]
        folder: Option<String>,

        /// Re-encrypt exactly this comma-separated list of item names.
        #[arg(long, value_name = "NAME[,NAME...]")]
        only: Option<String>,

        /// Proceed under --yes even when re-encrypting would DROP a recipient
        /// this machine cannot wrap to (a browser passkey, an unattached
        /// authenticator), revoking their access. Without this, --yes refuses
        /// such a run so a revocation can never happen unattended.
        #[arg(long)]
        allow_revoke: bool,
    },

    /// Restrict an item to a named subset of recipients, dropping the rest --
    /// the narrow/revoke operation. Refused when no named recipient can be
    /// opened on this machine; run `rageterm recipients list` for the ids.
    Restrict {
        name: String,

        /// Comma-separated recipient ids to wrap to *instead of* the current
        /// set -- this replaces it, it does not extend it.
        #[arg(long, value_name = "ID[,ID...]", required = true)]
        to: String,
    },

    /// Print (or copy) the current TOTP code for an item.
    Totp {
        name: String,

        #[arg(long)]
        copy: bool,
    },

    #[command(name = output::CLIPBOARD_SERVE_SUBCOMMAND, hide = true)]
    ClipboardServe { secs: u64 },

    /// Install the browser native-messaging manifest for ragemanifest.
    InstallNativeHost {
        #[arg(long, default_value = "chromium")]
        browser: String,

        /// Per-user manifest (the default).
        #[arg(long, conflicts_with = "system")]
        user: bool,

        /// System-wide manifest.
        #[arg(long)]
        system: bool,

        /// The extension the manifest allows to start the host. For chromium
        /// this is the 32-character id (letters a-p) shown at
        /// chrome://extensions and is required -- prompted for at a terminal
        /// when omitted, never defaulted. Firefox defaults to
        /// `ragewarden@ragewarden`. Safari has no manifest: `--browser safari`
        /// reports which rageterm the Ragewarden Safari app will run.
        #[arg(long, value_name = "ID")]
        extension_id: Option<String>,
    },

    /// Remove that manifest again.
    UninstallNativeHost {
        #[arg(long, default_value = "chromium")]
        browser: String,

        /// Per-user manifest (the default).
        #[arg(long, conflicts_with = "system")]
        user: bool,

        /// System-wide manifest.
        #[arg(long)]
        system: bool,
    },

    /// Serve the native-messaging protocol on stdio (the browser starts this).
    NativeHost,

    /// Import a `pass` store, re-wrapping each entry to this vault.
    PassImport {
        #[arg(long)]
        from: Option<std::path::PathBuf>,

        #[arg(long)]
        folder: Option<String>,

        #[arg(long)]
        default_recipient: Option<String>,

        #[arg(long)]
        dry_run: bool,

        #[arg(long)]
        also_export: bool,
    },
}

#[derive(Subcommand, Debug)]
enum RecipientsCmd {
    /// Show every enrolled recipient, and the ones writes from here skip.
    List,

    /// Forget a recipient here and unpublish it from the registry.
    Remove { id: String },
}

#[derive(Subcommand, Debug)]
enum FoldersCmd {
    /// Show folders and how many items each holds.
    List,

    /// Create a folder.
    Create { name: String },

    /// Rename a folder by id.
    Rename { id: String, name: String },

    /// Delete a folder by id.
    Remove { id: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SetType {
    SecureNote,
    Login,
    Card,
    Identity,
    SshKey,
}

fn parse_set_type(s: &str) -> Result<SetType, String> {
    match s {
        "secure-note" | "secure_note" | "note" => Ok(SetType::SecureNote),
        "login" => Ok(SetType::Login),
        "card" => Ok(SetType::Card),
        "identity" => Ok(SetType::Identity),
        "ssh-key" | "ssh_key" => Ok(SetType::SshKey),
        other => Err(format!(
            "unknown --type `{other}`; expected `secure-note`, `login`, `card`, `identity` \
             or `ssh-key`"
        )),
    }
}

fn parse_field_value(s: &str) -> Result<(String, String), String> {
    let (k, v) = s
        .split_once('=')
        .ok_or_else(|| format!("`{s}` is not FIELD=VALUE"))?;
    if k.is_empty() {
        return Err(format!("`{s}` has no field name"));
    }
    Ok((k.to_string(), v.to_string()))
}

#[derive(Subcommand, Debug)]
enum AgentCmd {
    /// Add an item's SSH key to the running ssh-agent.
    Add {
        name: String,

        #[arg(long)]
        lifetime: Option<u32>,
    },
}

#[derive(clap::Args, Debug, Clone)]
struct GenerateArgs {
    /// Password length.
    #[arg(long, default_value_t = 20)]
    length: usize,

    /// Letters and digits only.
    #[arg(long)]
    no_symbols: bool,

    /// A passphrase of this many words instead of a password.
    #[arg(long)]
    words: Option<usize>,
}

impl GenerateArgs {
    fn to_generate(&self) -> commands::Generate {
        commands::Generate {
            length: self.length,
            no_symbols: self.no_symbols,
            words: self.words,
        }
    }
}

/// Browsers start the host with their own argv and no subcommand: Chromium
/// passes the caller origin (`chrome-extension://<id>/`, plus
/// `--parent-window=<hwnd>` on Windows), Firefox the manifest path and the
/// add-on id.
fn launched_by_browser(args: &[std::ffi::OsString]) -> bool {
    let Some(first) = args.get(1).and_then(|a| a.to_str()) else {
        return false;
    };
    first.starts_with("chrome-extension://")
        || first.starts_with("--parent-window=")
        || (args.len() == 3 && first.ends_with(".json"))
}

fn main() -> ExitCode {
    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if launched_by_browser(&argv) {
        return match commands::cmd_native_host() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("rageterm native-host: {e}");
                ExitCode::from(1)
            }
        };
    }
    let cli = Cli::parse_from(argv);

    if hw::mock_requested_but_unavailable() {
        eprintln!(
            "rageterm: {}=1 is set but this build has no software stand-ins compiled in \
             (they are only available in `cargo test` and in builds made with \
             `--features mock-hardware`, which cannot be release builds). Hardware \
             ceremonies will use real devices.",
            hw::MOCK_ENV
        );
    }
    hw::warn_banner_once();

    if cli.tui {
        if cli.command.is_some() {
            eprintln!("rageterm: --tui cannot be combined with a subcommand.");
            return ExitCode::from(2);
        }
        return match tui::run() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("rageterm: {e}");
                ExitCode::from(1)
            }
        };
    }

    let Some(cmd) = cli.command else {
        eprintln!("rageterm: pass a subcommand or `--tui`. See `rageterm --help`.");
        return ExitCode::from(2);
    };

    match run_command(cmd, cli.yes, cli.no_wait) {
        Ok(code) => ExitCode::from(code as u8),
        Err(commands::CmdError::Cancelled) => {
            eprintln!("cancelled");
            ExitCode::from(130)
        }
        Err(e) => {
            eprintln!("rageterm: {e}");
            ExitCode::from(1)
        }
    }
}

fn run_command(cmd: Command, yes: bool, no_wait: bool) -> Result<i32, commands::CmdError> {
    match cmd {
        Command::Register {
            server,
            email,
            name,
            kdf,
            kdf_iterations,
            password_stdin,
        } => {
            commands::set_password_stdin(password_stdin);
            let kdf = if kdf == "argon2id" {
                ragewarden_core::sync::KdfParams::argon2id_default()
            } else {
                ragewarden_core::sync::KdfParams::pbkdf2(kdf_iterations)
            };
            run_async(commands::cmd_register(&server, &email, &name, kdf))?;
            Ok(0)
        }
        Command::Login {
            server,
            email,
            password_stdin,
            allow_weak_kdf,
        } => {
            commands::set_password_stdin(password_stdin);
            run_async(commands::cmd_login(&server, &email, allow_weak_kdf))?;
            Ok(0)
        }
        Command::MigratePiv {
            slot,
            public_key,
            label,
            from,
            allow_untouched_slot,
        } => {
            run_async(commands::cmd_migrate_piv(
                slot,
                public_key.as_deref(),
                label.as_deref(),
                from.as_deref(),
                allow_untouched_slot,
                yes,
                no_wait,
            ))?;
            Ok(0)
        }
        Command::AttestFido2 { id } => {
            run_async(commands::cmd_attest_fido2(id.as_deref(), no_wait))?;
            Ok(0)
        }
        Command::Generate { gen_args } => {
            commands::cmd_generate(&gen_args.to_generate())?;
            Ok(0)
        }
        Command::Mv { name, folder } => {
            run_async(commands::cmd_mv(&name, folder.as_deref()))?;
            Ok(0)
        }
        Command::Audit { limit } => {
            commands::cmd_audit(limit)?;
            Ok(0)
        }
        Command::Logout => {
            commands::cmd_logout()?;
            Ok(0)
        }
        Command::Sync => {
            run_async(commands::cmd_sync())?;
            Ok(0)
        }
        Command::EnrollSoftwareIdentity { plaintext } => {
            commands::cmd_enroll_software_identity(plaintext)?;
            Ok(0)
        }
        Command::ProtectIdentity => {
            commands::cmd_protect_identity()?;
            Ok(0)
        }
        Command::Set {
            name,
            r#type,
            from_stdin,
            folder,
            offline,
            username,
            urls,
            generate,
            gen_args,
            field,
            protect,
            with,
        } => {
            let spec = generate.then(|| gen_args.to_generate());
            let login_args = username.is_some() || !urls.is_empty();
            let cipher_type = match r#type {
                Some(SetType::Login) => Some(commands::SetCipherType::Login { username, urls }),
                None if login_args => Some(commands::SetCipherType::Login { username, urls }),
                Some(_) if login_args => {
                    return Err(commands::CmdError::InvalidArg(
                        "--username and --url need `--type login`".into(),
                    ));
                }
                Some(SetType::SecureNote) => Some(commands::SetCipherType::SecureNote),
                Some(SetType::Card) => Some(commands::SetCipherType::Card),
                Some(SetType::Identity) => Some(commands::SetCipherType::Identity),
                Some(SetType::SshKey) => Some(commands::SetCipherType::SshKey),
                None => None,
            };
            run_async(commands::cmd_set(commands::SetArgs {
                name: &name,
                cipher_type,
                from_stdin,
                folder: folder.as_deref(),
                offline,
                generate: spec.as_ref(),
                field: field.as_deref(),
                protect,
                with,
                yes,
                no_wait,
            }))?;
            Ok(0)
        }
        Command::List { filter, json } => {
            run_async(commands::cmd_list(filter.as_deref(), json))?;
            Ok(0)
        }
        Command::Get {
            name,
            field,
            newline,
        } => {
            run_async(commands::cmd_get(
                &name,
                field.as_deref(),
                newline,
                yes,
                no_wait,
            ))?;
            Ok(0)
        }
        Command::Copy { name, clear } => {
            run_async(commands::cmd_copy(&name, clear, yes, no_wait))?;
            Ok(0)
        }
        Command::Reveal { name, force } => {
            run_async(commands::cmd_reveal(&name, yes, no_wait, force))?;
            Ok(0)
        }
        Command::Agent(AgentCmd::Add { name, lifetime }) => {
            run_async(commands::cmd_agent_add(&name, lifetime, yes, no_wait))?;
            Ok(0)
        }
        Command::Fill { name, to } => {
            run_async(commands::cmd_fill(&name, to.as_deref(), yes, no_wait))?;
            Ok(0)
        }
        Command::Exec {
            name,
            via_env,
            clean_env,
            keep,
            argv,
        } => {
            let env = output::ExecEnv {
                clean: clean_env,
                keep,
            };
            run_async(commands::cmd_exec(
                &name, &argv, via_env, &env, yes, no_wait,
            ))
        }
        Command::EnrollYubikey {
            slot,
            label,
            public_key,
            allow_untouched_slot,
            stanza_v2,
            x25519,
        } => {
            run_async(commands::cmd_enroll_yubikey(
                slot,
                label.as_deref(),
                public_key.as_deref(),
                no_wait,
                allow_untouched_slot,
                stanza_v2,
                x25519,
            ))?;
            Ok(0)
        }
        Command::EnrollFido2 { rp, label } => {
            run_async(commands::cmd_enroll_fido2(&rp, label.as_deref(), no_wait))?;
            Ok(0)
        }
        Command::EnrollKeyring { user, label } => {
            run_async(commands::cmd_enroll_keyring(
                user.as_deref(),
                label.as_deref(),
            ))?;
            Ok(0)
        }
        Command::EnrollRecovery { label, no_confirm } => {
            run_async(commands::cmd_enroll_recovery(&label, no_confirm))?;
            Ok(0)
        }
        Command::Recover { save } => {
            commands::cmd_recover(save)?;
            Ok(0)
        }
        Command::Delete { name } => {
            run_async(commands::cmd_delete(&name))?;
            Ok(0)
        }
        Command::Folders(FoldersCmd::List) => {
            run_async(commands::cmd_folders_list())?;
            Ok(0)
        }
        Command::Folders(FoldersCmd::Create { name }) => {
            run_async(commands::cmd_folders_create(&name))?;
            Ok(0)
        }
        Command::Folders(FoldersCmd::Rename { id, name }) => {
            run_async(commands::cmd_folders_rename(&id, &name))?;
            Ok(0)
        }
        Command::Folders(FoldersCmd::Remove { id }) => {
            run_async(commands::cmd_folders_delete(&id))?;
            Ok(0)
        }
        Command::Recipients(RecipientsCmd::List) => {
            run_async(commands::cmd_recipients_list())?;
            Ok(0)
        }
        Command::Recipients(RecipientsCmd::Remove { id }) => {
            run_async(commands::cmd_recipients_remove(&id))?;
            Ok(0)
        }
        Command::Reencrypt {
            name,
            all,
            legacy,
            folder,
            only,
            allow_revoke,
        } => {
            run_async(commands::cmd_reencrypt(
                name.as_deref(),
                all,
                legacy,
                folder.as_deref(),
                only.as_deref(),
                allow_revoke,
                yes,
                no_wait,
            ))?;
            Ok(0)
        }
        Command::Restrict { name, to } => {
            run_async(commands::cmd_restrict(&name, &to, yes, no_wait))?;
            Ok(0)
        }
        Command::Totp { name, copy } => {
            run_async(commands::cmd_totp(&name, copy, yes, no_wait))?;
            Ok(0)
        }
        Command::ClipboardServe { secs } => {
            output::run_clipboard_serve(secs)?;
            Ok(0)
        }
        Command::InstallNativeHost {
            browser,
            user,
            system,
            extension_id,
        } => {
            let system = system && !user;
            commands::cmd_install_native_host(&browser, system, extension_id.as_deref(), yes)?;
            Ok(0)
        }
        Command::UninstallNativeHost {
            browser,
            user,
            system,
        } => {
            let system = system && !user;
            commands::cmd_uninstall_native_host(&browser, system)?;
            Ok(0)
        }
        Command::NativeHost => {
            commands::cmd_native_host()?;
            Ok(0)
        }
        Command::PassImport {
            from,
            folder,
            default_recipient,
            dry_run,
            also_export,
        } => {
            run_async(commands::cmd_pass_import(commands::PassImportOpts {
                source: from.as_deref(),
                folder: folder.as_deref(),
                default_recipient: default_recipient.as_deref(),
                dry_run,
                also_export,
                yes,
            }))?;
            Ok(0)
        }
    }
}

fn parse_piv_slot(s: &str) -> Result<u8, String> {
    let stripped = s.trim_start_matches("0x").trim_start_matches("0X");
    let parsed = if stripped.chars().all(|c| c.is_ascii_hexdigit()) {
        u8::from_str_radix(stripped, 16)
    } else {
        s.parse::<u8>()
    };
    let v = parsed.map_err(|e| format!("could not parse `{s}` as u8: {e}"))?;
    let valid = matches!(
        v,
        0x82..=0x95 | 0x9a | 0x9c..=0x9e,
    );
    if !valid {
        return Err(format!(
            "slot {v:#04x} is not a valid PIV slot (must be 0x82..=0x95, 0x9a, or 0x9c..=0x9e)"
        ));
    }
    Ok(v)
}

fn run_async<F, T>(fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime should always build");
    rt.block_on(fut)
}
