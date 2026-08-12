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
mod hw;
mod history_helper;
mod http;
mod identities;
mod idfile;
mod install_native_host;
mod keyring_id;
mod lock;
mod native_host;
mod output;
mod pass_import;
mod piv;
mod piv_apdu;
mod piv_pcsc;
mod recipients;
mod recovery;
mod session;
mod store;
mod tui;
mod vault;

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

        #[arg(long, default_value_t = 600_000)]
        kdf_iterations: u32,
    },

    /// Unlock a server session and cache it for later commands.
    Login {
        #[arg(long)]
        server: String,

        #[arg(long)]
        email: String,
    },

    /// Drop the cached session and vault.
    Logout,

    /// Refresh the cached vault from the server.
    Sync,

    /// Generate this machine's software identity (identity.age).
    EnrollSoftwareIdentity,

    /// Store or replace an item, wrapped to every recipient this machine covers.
    #[command(alias = "insert")]
    Set {
        name: String,

        #[arg(long, default_value = "secure-note", value_parser = parse_set_type)]
        r#type: SetType,

        #[arg(long)]
        from_stdin: bool,

        #[arg(long)]
        folder: Option<String>,
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

        #[arg(trailing_var_arg = true, required = true)]
        argv: Vec<String>,
    },

    /// Enroll a YubiKey PIV slot as a recipient, proving possession first.
    EnrollYubikey {
        #[arg(long, default_value = "0x95", value_parser = parse_piv_slot)]
        slot: u8,

        #[arg(long)]
        label: Option<String>,

        /// The slot's X25519 public key, as a PEM file path, a literal PEM, or
        /// 64 hex characters. Produce it with
        /// `ykman piv keys generate --algorithm X25519 <slot> pub.pem`.
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
    Delete {
        name: String,
    },

    /// List, create, rename and remove folders.
    #[command(subcommand)]
    Folders(FoldersCmd),

    /// List enrolled recipients, and which of them this machine wraps to.
    #[command(subcommand)]
    Recipients(RecipientsCmd),

    /// Re-encrypt items to your CURRENT recipient set -- the way to fold a
    /// newly-enrolled recipient into secrets that were stored before it
    /// existed. Name one item, or use --all (optionally --folder) or --only.
    Reencrypt {
        /// The item to re-encrypt. Omit and pass --all or --only for many.
        name: Option<String>,

        /// Re-encrypt every protected item to the current recipient set.
        #[arg(long)]
        all: bool,

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

    #[command(name = "__clipboard-clear-helper", hide = true)]
    ClipboardClearHelper {
        secs: u64,

        expected_hash: String,
    },

    /// Install the browser native-messaging manifest for ragemanifest.
    InstallNativeHost {
        #[arg(long, default_value = "chromium")]
        browser: String,

        #[arg(long, group = "scope")]
        user: bool,

        #[arg(long, group = "scope")]
        system: bool,

        /// The extension the manifest allows to start the host. For chromium
        /// this is the 32-character id (letters a-p) shown at
        /// chrome://extensions and is required -- prompted for at a terminal
        /// when omitted, never defaulted. Firefox defaults to
        /// `ragewarden@ragewarden`, Safari to `com.ragewarden.safari`.
        #[arg(long, value_name = "ID")]
        extension_id: Option<String>,
    },

    /// Remove that manifest again.
    UninstallNativeHost {
        #[arg(long, default_value = "chromium")]
        browser: String,

        #[arg(long, group = "scope")]
        user: bool,

        #[arg(long, group = "scope")]
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
}

fn parse_set_type(s: &str) -> Result<SetType, String> {
    match s {
        "secure-note" | "secure_note" | "note" => Ok(SetType::SecureNote),
        "login" => Ok(SetType::Login),
        other => Err(format!(
            "unknown --type `{other}`; expected `secure-note` or `login`"
        )),
    }
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

fn main() -> ExitCode {
    let cli = Cli::parse();

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
            kdf_iterations,
        } => {
            run_async(commands::cmd_register(
                &server,
                &email,
                &name,
                kdf_iterations,
            ))?;
            Ok(0)
        }
        Command::Login { server, email } => {
            run_async(commands::cmd_login(&server, &email))?;
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
        Command::EnrollSoftwareIdentity => {
            commands::cmd_enroll_software_identity()?;
            Ok(0)
        }
        Command::Set {
            name,
            r#type,
            from_stdin,
            folder,
        } => {
            let cipher_type = match r#type {
                SetType::SecureNote => commands::SetCipherType::SecureNote,
                SetType::Login => commands::SetCipherType::Login,
            };
            run_async(commands::cmd_set(
                &name,
                cipher_type,
                from_stdin,
                folder.as_deref(),
            ))?;
            Ok(0)
        }
        Command::List { filter, json } => {
            run_async(commands::cmd_list(filter.as_deref(), json))?;
            Ok(0)
        }
        Command::Get { name, newline } => {
            run_async(commands::cmd_get(&name, newline, yes, no_wait))?;
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
            argv,
        } => run_async(commands::cmd_exec(&name, &argv, via_env, yes, no_wait)),
        Command::EnrollYubikey {
            slot,
            label,
            public_key,
            allow_untouched_slot,
        } => {
            run_async(commands::cmd_enroll_yubikey(
                slot,
                label.as_deref(),
                public_key.as_deref(),
                no_wait,
                allow_untouched_slot,
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
            folder,
            only,
            allow_revoke,
        } => {
            run_async(commands::cmd_reencrypt(
                name.as_deref(),
                all,
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
        Command::ClipboardClearHelper {
            secs,
            expected_hash,
        } => {
            output::run_clipboard_clear_helper(secs, &expected_hash)?;
            Ok(0)
        }
        Command::InstallNativeHost {
            browser,
            user: _,
            system,
            extension_id,
        } => {
            commands::cmd_install_native_host(&browser, system, extension_id.as_deref(), yes)?;
            Ok(0)
        }
        Command::UninstallNativeHost {
            browser,
            user: _,
            system,
        } => {
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
