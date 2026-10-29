#![allow(dead_code)]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{ContainerPort, IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};

const VAULTWARDEN_IMAGE: &str = "vaultwarden/server";
const VAULTWARDEN_TAG: &str = "1.32.7";
const HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(60);

const RELAXED_RATE_LIMITS: [(&str, &str); 4] = [
    ("LOGIN_RATELIMIT_MAX_BURST", "1000"),
    ("LOGIN_RATELIMIT_SECONDS", "1"),
    ("ADMIN_RATELIMIT_MAX_BURST", "1000"),
    ("ADMIN_RATELIMIT_SECONDS", "1"),
];

enum Guard {
    Native { child: Child, data: PathBuf },
    Docker(Box<ContainerAsync<GenericImage>>),
}

/// A throwaway Vaultwarden: the binary named by RAGEWARDEN_VAULTWARDEN_BIN
/// (which the #ragewarden devshell exports) when set, otherwise a Docker
/// container when RAGEWARDEN_E2E=1. Stopped and its data removed on drop.
pub struct Vaultwarden {
    pub url: String,
    guard: Guard,
}

impl Drop for Vaultwarden {
    fn drop(&mut self) {
        if let Guard::Native { child, data } = &mut self.guard {
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_dir_all(&*data);
        }
    }
}

/// `None` when neither a native binary nor Docker was offered: the caller
/// skips with a note.
pub async fn start() -> Option<Vaultwarden> {
    if let Ok(bin) = std::env::var("RAGEWARDEN_VAULTWARDEN_BIN") {
        return Some(start_native(&bin).await);
    }
    if matches!(std::env::var("RAGEWARDEN_E2E").as_deref(), Ok("1")) {
        return Some(start_docker().await);
    }
    eprintln!(
        "no Vaultwarden: set RAGEWARDEN_VAULTWARDEN_BIN (the #ragewarden devshell does) or \
         RAGEWARDEN_E2E=1 for Docker; skipping"
    );
    None
}

async fn start_native(bin: &str) -> Vaultwarden {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("free port")
        .port();
    let data = std::env::temp_dir().join(format!("ragewarden-vw-{}-{port}", random_suffix()));
    std::fs::create_dir_all(&data).expect("vaultwarden data dir");
    let log = std::fs::File::create(data.join("vaultwarden.log")).expect("log file");
    let url = format!("http://127.0.0.1:{port}");
    let mut cmd = Command::new(bin);
    cmd.env("DATA_FOLDER", &data)
        .env("ROCKET_ADDRESS", "127.0.0.1")
        .env("ROCKET_PORT", port.to_string())
        .env("SIGNUPS_ALLOWED", "true")
        .env("WEB_VAULT_ENABLED", "false")
        .env("DOMAIN", &url)
        .stdout(Stdio::from(log.try_clone().expect("log fd")))
        .stderr(Stdio::from(log));
    for (k, v) in RELAXED_RATE_LIMITS {
        cmd.env(k, v);
    }
    let child = cmd.spawn().expect("spawn vaultwarden");
    let vw = Vaultwarden {
        url,
        guard: Guard::Native { child, data },
    };
    wait_for_alive(&vw.url).await;
    vw
}

async fn start_docker() -> Vaultwarden {
    let mut image = GenericImage::new(VAULTWARDEN_IMAGE, VAULTWARDEN_TAG)
        .with_exposed_port(ContainerPort::Tcp(80))
        .with_wait_for(WaitFor::message_on_stdout("Rocket has launched"))
        .with_env_var("SIGNUPS_ALLOWED", "true")
        .with_env_var("WEB_VAULT_ENABLED", "false")
        .with_env_var("ROCKET_PORT", "80")
        .with_env_var("DOMAIN", "http://localhost");
    for (k, v) in RELAXED_RATE_LIMITS {
        image = image.with_env_var(k, v);
    }
    let container = image.start().await.expect("start vaultwarden");
    let port = container
        .get_host_port_ipv4(80.tcp())
        .await
        .expect("vaultwarden host port");
    let vw = Vaultwarden {
        url: format!("http://localhost:{port}"),
        guard: Guard::Docker(Box::new(container)),
    };
    wait_for_alive(&vw.url).await;
    vw
}

pub async fn wait_for_alive(server_url: &str) {
    let alive = format!("{server_url}/alive");
    let client = reqwest::Client::new();
    let deadline = std::time::Instant::now() + HEALTHCHECK_TIMEOUT;
    loop {
        if let Ok(r) = client.get(&alive).send().await {
            if r.status().is_success() {
                return;
            }
        }
        if std::time::Instant::now() >= deadline {
            panic!("vaultwarden /alive never returned 2xx within {HEALTHCHECK_TIMEOUT:?}");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

pub fn random_suffix() -> String {
    use rand::Rng;
    let mut b = [0u8; 4];
    rand::rng().fill_bytes(&mut b);
    hex::encode(b)
}

pub fn client() -> ragewarden_core::http_reqwest::ReqwestClient {
    ragewarden_core::http_reqwest::ReqwestClient::new("rageterm-e2e-test/0.1")
        .expect("rustls client should always build")
}

pub fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}
