use ragewarden_core::http_reqwest::ReqwestClient;
use ragewarden_core::sync::HttpError;

pub fn run_async<F: std::future::Future>(f: F) -> F::Output {
    use std::sync::OnceLock;
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    let rt = RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("ragedroid-jni")
            .build()
            .expect("tokio multi-thread runtime")
    });
    rt.block_on(f)
}

pub fn shared_client() -> Result<ReqwestClient, HttpError> {
    use std::sync::OnceLock;
    static CLIENT: OnceLock<ReqwestClient> = OnceLock::new();
    if let Some(c) = CLIENT.get() {
        return Ok(c.clone());
    }
    let c = ReqwestClient::new(&format!("ragedroid-jni/{}", env!("CARGO_PKG_VERSION")))?;
    let _ = CLIENT.set(c.clone());
    Ok(c)
}
